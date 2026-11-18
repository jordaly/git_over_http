"""Helpers for repository-owned CI configuration in tests.

Runtime CI configuration lives at ``ci/config.json`` in the repository.  Tests
that used to save a configuration in SQLite must commit the equivalent
document instead.  These helpers use Git plumbing so they work with bare
repositories without disturbing an existing working tree.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping
from unittest import mock

from pygithost import database
from pygithost.ci import validate_config
from pygithost.ci_config import export_document


def _git_environment(git_dir: Path) -> dict[str, str]:
    environment = {
        **os.environ,
        "GIT_DIR": str(git_dir),
        "GIT_AUTHOR_NAME": "CI fixture",
        "GIT_AUTHOR_EMAIL": "ci@example.invalid",
        "GIT_COMMITTER_NAME": "CI fixture",
        "GIT_COMMITTER_EMAIL": "ci@example.invalid",
    }
    return environment


def _git_dir(repository: os.PathLike[str] | str) -> Path:
    path = Path(repository)
    if (path / ".git").is_dir():
        return path / ".git"
    return path


def _git(
    git_dir: Path,
    *args: str,
    input: bytes | None = None,
    environment: Mapping[str, str] | None = None,
) -> str:
    result = subprocess.run(
        ["git", "--git-dir", str(git_dir), *args],
        input=input,
        capture_output=True,
        check=False,
        env=dict(environment or _git_environment(git_dir)),
    )
    if result.returncode:
        raise RuntimeError(
            f"git {' '.join(args)} failed: {result.stderr.decode('utf-8', 'replace').strip()}"
        )
    return result.stdout.decode("utf-8").strip()


def _resolve_parent(git_dir: Path, branch: str) -> str:
    result = subprocess.run(
        ["git", "--git-dir", str(git_dir), "rev-parse", "--verify", branch + "^{commit}"],
        capture_output=True,
        check=False,
        env=_git_environment(git_dir),
    )
    if result.returncode:
        return ""
    return result.stdout.decode("ascii").strip()


def commit_file(
    repository: os.PathLike[str] | str,
    filename: str,
    content: bytes | str,
    *,
    branch: str = "main",
    message: str = "CI fixture",
) -> str:
    """Commit one file to ``branch`` in a bare or working repository.

    The existing tree is preserved.  Returns the new commit SHA.
    """
    git_dir = _git_dir(repository)
    parent = _resolve_parent(git_dir, branch)
    data = content.encode("utf-8") if isinstance(content, str) else content

    with tempfile.TemporaryDirectory(prefix="ci-fixture-index-") as directory:
        index = str(Path(directory) / "index")
        environment = {**_git_environment(git_dir), "GIT_INDEX_FILE": index}
        if parent:
            _git(git_dir, "read-tree", parent, environment=environment)
        else:
            _git(git_dir, "read-tree", "--empty", environment=environment)
        blob = _git(
            git_dir,
            "hash-object",
            "-w",
            "--stdin",
            input=data,
            environment=environment,
        )
        _git(
            git_dir,
            "update-index",
            "--add",
            "--cacheinfo",
            f"100644,{blob},{filename}",
            environment=environment,
        )
        tree = _git(git_dir, "write-tree", environment=environment)

    arguments = ["commit-tree", tree]
    if parent:
        arguments.extend(("-p", parent))
    arguments.extend(("-m", message))
    commit = _git(git_dir, *arguments)
    update = ["update-ref", f"refs/heads/{branch}", commit]
    if parent:
        update.append(parent)
    _git(git_dir, *update)
    return commit


def commit_ci_config(
    repository: os.PathLike[str] | str,
    document: Mapping[str, Any] | None = None,
    *,
    filename: str = "ci/config.json",
    branch: str = "main",
    raw: str | None = None,
    message: str = "CI fixture",
) -> str:
    """Commit a full or simple repository CI document and return its SHA."""
    if raw is None:
        if document is None:
            raise ValueError("A CI document or raw JSON text is required.")
        raw = json.dumps(document)
    return commit_file(repository, filename, raw, branch=branch, message=message)


def legacy_document(config: Mapping[str, Any]) -> dict[str, Any]:
    """Convert a legacy validated/flat config into an editable CI document."""
    validated = validate_config(config)
    if not validated.get("command") and not validated.get("steps"):
        # A full repository pipeline still needs a runnable definition even when
        # the legacy fixture only exercised deployment behavior.
        validated = {**validated, "command": "true"}
    document = copy.deepcopy(export_document(validated))
    for pipeline in document.get("pipelines", {}).values():
        steps = pipeline.get("steps")
        if not pipeline.get("command") and (
            not steps or any(not step.get("run") for step in steps)
        ):
            pipeline["steps"] = [{"name": "Run", "run": "true"}]
    return document


def commit_legacy_config(
    repository: os.PathLike[str] | str,
    config: Mapping[str, Any],
    *,
    filename: str = "ci/config.json",
    branch: str = "main",
    message: str = "CI fixture",
) -> str:
    """Commit the document equivalent of a legacy saved configuration."""
    return commit_ci_config(
        repository,
        legacy_document(config),
        filename=filename,
        branch=branch,
        message=message,
    )


@contextmanager
def trusted_ci_repositories(*repositories: str) -> Iterator[None]:
    """Authorize exact fixture repositories for host execution and deployments."""
    with mock.patch.dict(
        os.environ,
        {"PYGITHOST_CI_TRUSTED_REPOSITORIES": "\n".join(repositories)},
    ):
        yield


def seed_verified_retention(commit: str, *repositories: tuple[str, str], **values: object) -> None:
    """Write verified cache rows without reading Git.

    Tests that expect cleanup to delete records must not rely on an absent row:
    absence deliberately pauses deletion. Pass an empty policy to exercise the
    live server defaults.
    """
    for owner, repo in repositories:
        database.db_ci_retention_policy_set(owner, repo, dict(values), commit=commit)


@contextmanager
def verified_retention(
    commit: str, *repositories: tuple[str, str], **values: object
) -> Iterator[None]:
    """Treat the given repositories as verified at ``commit`` for one test."""
    previous = database._retention_head_resolver
    database.configure_retention_head_resolver(lambda _owner, _repo: commit)
    try:
        seed_verified_retention(commit, *repositories, **values)
        yield
    finally:
        database.configure_retention_head_resolver(previous)
