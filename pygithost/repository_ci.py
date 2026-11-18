"""Read repository-owned CI definitions without checking out or executing code."""

import json
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .runner_types import JsonObject

CONFIG_FILE = "ci/config.json"
MAX_CONFIG_BYTES = 262144

_INVALID_DOCUMENT = "Repository CI configuration is invalid."
_INVALID_SCHEMA = (
    "Repository CI configuration is invalid: it does not match the supported pipeline schema."
)
_INVALID_REFERENCE = (
    "Repository CI configuration is invalid: a referenced ci/ pipeline file does not "
    "match the supported pipeline schema."
)

_SAFE_PIPELINE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_SAFE_REFERENCE = re.compile(r"ci/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]{1,128}\.json")
_DUPLICATE_JSON_KEY = "Duplicate JSON key in repository CI configuration."
_JSON_OBJECT = "Repository CI configuration must be a JSON object."
_OVERSIZED = "Repository CI configuration exceeds 256 KiB."
_NOT_REGULAR_PREFIX = "Missing regular "
_GIT_READ_FAILURE = "Cannot read repository CI configuration at the recorded revision."


class GitReadError(ValueError):
    """Git could not be queried, so repository policy state is unverified."""


class _ReferenceError(ValueError):
    """A safe, reference-specific diagnostic that may name the file and pipeline."""


def _json_position(exc: Exception) -> str:
    if isinstance(exc, json.JSONDecodeError):
        return f" at line {exc.lineno} column {exc.colno}"
    return ""


def _read_detail(exc: Exception) -> str:
    """Describe a read failure without echoing JSON, paths or Git diagnostics."""
    if isinstance(exc, json.JSONDecodeError):
        return "is not valid JSON" + _json_position(exc) + "."
    if isinstance(exc, UnicodeError):
        return "is not valid UTF-8 JSON."
    if isinstance(exc, RecursionError):
        return "has JSON nesting that is too deep."
    if isinstance(exc, OSError):
        return "could not be read."
    message = str(exc)
    if message == _DUPLICATE_JSON_KEY:
        return "contains a duplicate JSON key."
    if message == _JSON_OBJECT:
        return "must contain a JSON object."
    if message == _OVERSIZED:
        return "exceeds 256 KiB."
    if message.startswith(_NOT_REGULAR_PREFIX):
        return "must be a regular file under ci/."
    if message == _GIT_READ_FAILURE:
        return "could not be read from the repository."
    return "is not a valid ci/ configuration file."


def _reference_subject(filename: str, pipeline_id: object) -> str:
    """Build a label only from values that already passed their own validation."""
    parts: list[str] = []
    if isinstance(pipeline_id, str) and _SAFE_PIPELINE.fullmatch(pipeline_id):
        parts.append(f"pipeline {pipeline_id!r}")
    if _SAFE_REFERENCE.fullmatch(filename):
        parts.append(f"file {filename!r}")
    if parts:
        return " ".join(parts)
    return "a referenced ci/ file"


def _reference_message(filename: str, pipeline_id: object, detail: str) -> str:
    return f"{_INVALID_DOCUMENT} {_reference_subject(filename, pipeline_id)} {detail}"


@dataclass(frozen=True)
class ConfigurationInspection:
    """Safe, read-only result of validating repository-owned CI configuration.

    ``commit`` is ``None`` when the revision cannot be resolved. When ``commit`` is
    set but ``document`` and ``config`` are both ``None`` with no ``error``, the
    repository simply has no ``ci/config.json``. An ``error`` means the file, or one
    of the pipeline files it references, is present but invalid.

    ``git_error`` distinguishes a failed Git lookup from a verified empty
    repository or a missing revision. Mutation paths must fail closed when this is
    set because any stored policy cannot be verified.
    """

    commit: str | None
    document: JsonObject | None
    config: JsonObject | None
    error: str | None
    git_error: bool = False


def configuration_path(filename: str) -> str:
    """Configuration references must be regular files strictly inside ci/."""
    path = PurePosixPath(filename)
    if (
        not filename.startswith("ci/")
        or "\\" in filename
        or any(char in filename for char in "\0\r\n\t")
        or any(part in ("", ".", "..") for part in filename.split("/"))
        or path.is_absolute()
    ):
        raise ValueError("Repository CI configuration files must be inside ci/.")
    return filename


def _run_git(bare: str, *args: str) -> subprocess.CompletedProcess[bytes]:
    from .ci import runner_environment

    try:
        return subprocess.run(
            ["git", "--git-dir", bare, *args],
            capture_output=True,
            timeout=10,
            check=False,
            env=runner_environment(tempfile.gettempdir()),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GitReadError(
            "Cannot read repository CI configuration at the recorded revision."
        ) from exc


def git(bare: str, *args: str) -> bytes:
    result = _run_git(bare, *args)
    if result.returncode:
        raise GitReadError("Cannot read repository CI configuration at the recorded revision.")
    return result.stdout


def _verified_unborn(bare: str) -> bool:
    """Return True only when Git confirms that the repository has no commits."""
    head = _run_git(bare, "symbolic-ref", "--quiet", "HEAD")
    if head.returncode:
        return False
    branch = head.stdout.decode("ascii", "replace").strip()
    if not branch.startswith("refs/heads/") or any(char in branch for char in "\0\r\n\t"):
        return False
    exists = _run_git(bare, "rev-parse", "--verify", "--quiet", branch)
    if exists.returncode != 1:
        return False
    commits = _run_git(bare, "rev-list", "--all", "--count")
    if commits.returncode:
        return False
    return commits.stdout.decode("ascii", "replace").strip() == "0"


def resolve_commit(bare: str, revision: str = "HEAD") -> str | None:
    # Only server-generated refs or immutable object IDs may reach Git.
    if revision != "HEAD" and not (
        revision.startswith("refs/heads/")
        or re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", revision)
    ):
        raise ValueError("Repository CI requires an exact commit or branch reference.")
    result = _run_git(
        bare,
        "rev-parse",
        "--verify",
        "--end-of-options",
        revision + "^{commit}",
    )
    if result.returncode == 0:
        commit = result.stdout.decode("ascii", "replace").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit):
            raise GitReadError("Cannot read repository CI configuration at the recorded revision.")
        return commit
    if revision == "HEAD":
        if _verified_unborn(bare):
            return None
        raise GitReadError("Cannot read repository CI configuration at the recorded revision.")
    return None


def _parse_document(data: bytes) -> JsonObject:
    """Use one JSON parser for the entry point and every referenced pipeline file."""

    def unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key in repository CI configuration.")
            result[key] = value
        return result

    document = json.loads(data, object_pairs_hook=unique_keys)
    if not isinstance(document, dict):
        raise ValueError("Repository CI configuration must be a JSON object.")
    return document


def read_document(bare: str, commit: str, filename: str = CONFIG_FILE) -> JsonObject | None:
    configuration_path(filename)
    if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit):
        raise ValueError("Repository CI requires an exact commit SHA.")
    entry = git(bare, "ls-tree", "-z", "--full-tree", commit, "--", filename)
    if not entry:
        return None
    metadata, found = entry.rstrip(b"\0").split(b"\t", 1)
    mode, kind, oid = metadata.split()
    if found.decode("utf-8") != filename or mode not in (b"100644", b"100755") or kind != b"blob":
        raise ValueError(f"Missing regular {filename} file.")
    if int(git(bare, "cat-file", "-s", oid.decode("ascii"))) > MAX_CONFIG_BYTES:
        raise ValueError("Repository CI configuration exceeds 256 KiB.")
    return _parse_document(git(bare, "cat-file", "blob", oid.decode("ascii")))


def read_working_document(
    root: str | os.PathLike[str], filename: str = CONFIG_FILE
) -> JsonObject | None:
    """Read one configuration file from a checkout, without following symlinks."""
    configuration_path(filename)
    path = Path(root).joinpath(*filename.split("/"))
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Missing regular {filename} file.")
    if info.st_size > MAX_CONFIG_BYTES:
        raise ValueError("Repository CI configuration exceeds 256 KiB.")
    return _parse_document(path.read_bytes())


def compile_repository_document(document: JsonObject) -> JsonObject:
    from .ci import pipeline_config, unconfigured_repository_config
    from .ci_config import compile_document

    if "pipelines" in document:
        config = compile_document(document)
    elif "file" in document:
        # The entry point itself is the definition, not a server-side reference.
        raise ValueError("ci/config.json must define pipelines or steps, not a file reference.")
    else:
        config = pipeline_config(document, unconfigured_repository_config(), enforce_timeout=False)
        config["repository_config"] = False
        config.pop("_autodetect_repository_config", None)
    for item in [config, *config.get("pipelines", [])]:
        if item.get("repository_config"):
            filename = configuration_path(item["repository_file"])
            if filename == CONFIG_FILE:
                raise ValueError("A pipeline cannot reference ci/config.json recursively.")
    return config


def _validate_references(read: Callable[[str], JsonObject | None], config: JsonObject) -> None:
    """Validate every referenced pipeline file with the runtime's own parser."""
    from .ci import pipeline_config

    for item in [config, *config.get("pipelines", [])]:
        if not item.get("repository_config"):
            continue
        filename = configuration_path(item["repository_file"])
        if filename == CONFIG_FILE:
            raise _ReferenceError(
                _reference_message(
                    filename,
                    item.get("pipeline_id"),
                    "cannot be referenced recursively.",
                )
            )
        try:
            raw = read(filename)
        except (
            ValueError,
            TypeError,
            KeyError,
            OverflowError,
            UnicodeError,
            OSError,
            RecursionError,
            subprocess.SubprocessError,
        ) as exc:
            raise _ReferenceError(
                _reference_message(filename, item.get("pipeline_id"), _read_detail(exc))
            ) from None
        if raw is None:
            raise _ReferenceError(
                _reference_message(filename, item.get("pipeline_id"), "is missing.")
            )
        try:
            pipeline_config(raw, item)
        except ValueError, TypeError, KeyError, OverflowError, UnicodeError, RecursionError:
            raise _ReferenceError(
                _reference_message(
                    filename,
                    item.get("pipeline_id"),
                    "does not match the supported pipeline schema.",
                )
            ) from None


def _inspect(
    *,
    commit: str | None,
    read: Callable[[str], JsonObject | None],
) -> ConfigurationInspection:
    failures = (
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        UnicodeError,
        OSError,
        RecursionError,
        subprocess.SubprocessError,
    )
    try:
        document = read(CONFIG_FILE)
    except GitReadError:
        return ConfigurationInspection(commit, None, None, _GIT_READ_FAILURE, True)
    except failures as exc:
        return ConfigurationInspection(
            commit,
            None,
            None,
            f"{_INVALID_DOCUMENT} ci/config.json {_read_detail(exc)}",
        )
    if document is None:
        return ConfigurationInspection(commit, None, None, None)
    try:
        config = compile_repository_document(document)
    except failures:
        return ConfigurationInspection(commit, document, None, _INVALID_SCHEMA)
    try:
        _validate_references(read, config)
    except failures as exc:
        # A malformed secondary file must not discard the root policy that was
        # already parsed successfully. The error keeps the caller from running it.
        error = str(exc) if isinstance(exc, _ReferenceError) else _INVALID_REFERENCE
        return ConfigurationInspection(commit, document, config, error)
    return ConfigurationInspection(commit, document, config, None)


def inspect_configuration(bare: str, revision: str = "HEAD") -> ConfigurationInspection:
    """Validate the committed CI definition at ``revision`` without executing it.

    The returned messages are fixed diagnostics and never include repository
    contents, environment values or Git output, so they are safe to display in the
    web UI.
    """
    try:
        commit = resolve_commit(bare, revision)
    except GitReadError:
        return ConfigurationInspection(None, None, None, None, True)
    except ValueError, UnicodeError, OSError, subprocess.SubprocessError:
        return ConfigurationInspection(None, None, None, None)
    if commit is None:
        return ConfigurationInspection(None, None, None, None)
    return _inspect(
        commit=commit,
        read=lambda filename: read_document(bare, commit, filename),
    )


def inspect_working_configuration(root: str | os.PathLike[str]) -> ConfigurationInspection:
    """Validate a checkout's current files, including uncommitted CI changes."""
    return _inspect(
        commit=None,
        read=lambda filename: read_working_document(root, filename),
    )


__all__ = [
    "CONFIG_FILE",
    "MAX_CONFIG_BYTES",
    "ConfigurationInspection",
    "GitReadError",
    "compile_repository_document",
    "configuration_path",
    "inspect_configuration",
    "inspect_working_configuration",
    "read_document",
    "read_working_document",
    "resolve_commit",
]
