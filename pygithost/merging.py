"""Server-side pull request merging through Git plumbing.

Every operation works on a bare repository without a working tree: trees are
produced by ``git merge-tree --write-tree`` or a temporary index, commits by
``git commit-tree`` and refs are moved in a single ``git update-ref --stdin``
transaction that verifies the commits the caller decided on. Functions are
synchronous; async callers wrap them in ``asyncio.to_thread``.
"""

import os
import re
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, TypedDict

from .webide import _identity

GIT_TIMEOUT = 30
MERGE_TIMEOUT = 120
# A rebase simulation for the mergeability badge is skipped for longer ranges.
MAX_REBASE_PREVIEW = 250
MAX_REPLACE_FILE = 1 << 20
MAX_TITLE = 1000
MAX_MESSAGE = 65536
REGULAR_MODES = ("100644", "100755")
_SHA = re.compile(r"[0-9a-f]{40}([0-9a-f]{24})?")
_HUNK = re.compile(rb"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_IDENTITY_BAD = re.compile(r"[<>\r\n\x00]")

MergeMethod = Literal["merge", "squash", "rebase", "ff"]


class MergeError(Exception):
    """User-presentable merge failure with a machine-readable ``code``.

    Codes: ``conflict``, ``stale``, ``not_found``, ``unsupported``, ``invalid``,
    ``up_to_date`` and ``failed`` (unexpected Git failure).
    """

    def __init__(self, code: str, message: str, conflicts: Sequence[str] = ()) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.conflicts: list[str] = list(conflicts)


@dataclass(frozen=True)
class Identity:
    name: str
    email: str


class Mergeability(TypedDict):
    fast_forward: bool
    clean: bool
    conflicts: list[str]
    up_to_date: bool
    rebase_clean: bool | None


def identity_for(username: str | None) -> Identity:
    """Identity for a server user, using the browser editor's sanitising rules."""
    values = _identity(username)
    return Identity(values["GIT_AUTHOR_NAME"], values["GIT_AUTHOR_EMAIL"])


# --------------------------------------------------------------------------- #
# Git plumbing helpers
# --------------------------------------------------------------------------- #


def _env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_LITERAL_PATHSPECS"] = "1"
    if extra:
        env.update(extra)
    return env


def _run(
    repo: str,
    *args: str,
    data: bytes | None = None,
    env: Mapping[str, str] | None = None,
    timeout: int = GIT_TIMEOUT,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["git", "--git-dir=" + repo, *args],
            input=data,
            capture_output=True,
            env=_env(env),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise MergeError("failed", "The Git operation timed out.") from None
    except OSError:
        raise MergeError("failed", "Git could not be started on the server.") from None


def _git(
    repo: str,
    *args: str,
    data: bytes | None = None,
    env: Mapping[str, str] | None = None,
    timeout: int = GIT_TIMEOUT,
) -> bytes:
    result = _run(repo, *args, data=data, env=env, timeout=timeout)
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()[:500]
        raise MergeError("failed", "Git operation failed: " + detail)
    return result.stdout


def _identity_env(committer: Identity, author: Identity | None = None) -> dict[str, str]:
    author = author or committer
    return {
        "GIT_AUTHOR_NAME": author.name,
        "GIT_AUTHOR_EMAIL": author.email,
        "GIT_COMMITTER_NAME": committer.name,
        "GIT_COMMITTER_EMAIL": committer.email,
    }


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def _branch(repo: str, name: object) -> str:
    if (
        not isinstance(name, str)
        or not name
        or name.startswith("-")
        or "@{" in name
        or len(name.encode("utf-8")) > 255
        or any(ord(c) < 32 for c in name)
    ):
        raise MergeError("invalid", "Invalid branch name.")
    result = _run(repo, "check-ref-format", "--branch", name)
    if result.returncode or result.stdout.decode("utf-8", "replace").strip() != name:
        raise MergeError("invalid", "Invalid branch name.")
    return name


def _sha(value: object, what: str = "commit") -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise MergeError("invalid", f"Invalid {what} id.")
    return value


def _path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 4096
        or any(ord(c) < 32 for c in value)
        or "\\" in value
        or value.startswith("/")
        or any(p in ("", ".", "..") or p.lower() == ".git" for p in value.split("/"))
    ):
        raise MergeError("invalid", "Invalid repository file path.")
    return value


def _identity_ok(identity: Identity) -> Identity:
    if (
        not isinstance(identity, Identity)
        or not identity.name.strip()
        or not identity.email.strip()
        or _IDENTITY_BAD.search(identity.name)
        or _IDENTITY_BAD.search(identity.email)
    ):
        raise MergeError("invalid", "Invalid commit identity.")
    return identity


def _text(value: object, what: str, limit: int, *, required: bool) -> str:
    if not isinstance(value, str) or "\0" in value or len(value) > limit:
        raise MergeError("invalid", f"Invalid {what}.")
    value = value.strip()
    if required and not value:
        raise MergeError("invalid", f"Enter a {what}.")
    return value


def _commit_message(title: str, message: str) -> bytes:
    head = _text(title, "commit title", MAX_TITLE, required=True)
    body = _text(message, "commit message", MAX_MESSAGE, required=False)
    return (head + ("\n\n" + body if body else "") + "\n").encode("utf-8")


# --------------------------------------------------------------------------- #
# Read-only queries
# --------------------------------------------------------------------------- #


def resolve(repo: str, ref: str) -> str | None:
    """Commit SHA for a branch name, a full ``refs/...`` name or a commit SHA."""
    if not isinstance(ref, str) or not ref or ref.startswith("-") or "\0" in ref:
        raise MergeError("invalid", "Invalid branch or commit.")
    if _SHA.fullmatch(ref):
        candidate = ref
    elif ref.startswith("refs/"):
        if _run(repo, "check-ref-format", ref).returncode:
            raise MergeError("invalid", "Invalid branch or commit.")
        candidate = ref
    else:
        candidate = "refs/heads/" + _branch(repo, ref)
    result = _run(
        repo, "rev-parse", "--verify", "--quiet", "--end-of-options", candidate + "^{commit}"
    )
    if result.returncode:
        return None
    return result.stdout.decode().strip() or None


def _is_ancestor(repo: str, ancestor: str, descendant: str) -> bool:
    result = _run(repo, "merge-base", "--is-ancestor", ancestor, descendant)
    if result.returncode not in (0, 1):
        raise MergeError("failed", "Could not compare branch histories.")
    return result.returncode == 0


def merge_base(repo: str, a: str, b: str) -> str | None:
    result = _run(repo, "merge-base", _sha(a), _sha(b))
    if result.returncode:
        return None
    return result.stdout.decode().strip() or None


def _tree_of(repo: str, commit: str) -> str:
    return _git(repo, "rev-parse", "--verify", commit + "^{tree}").decode().strip()


def merge_tree(
    repo: str, ours: str, theirs: str, *, merge_base: str | None = None
) -> tuple[str | None, list[str]]:
    """Merge two commits in memory; ``(tree, [])`` when clean, ``(None, paths)`` otherwise."""
    args = ["merge-tree", "--write-tree", "-z", "--name-only", "--no-messages"]
    if merge_base is not None:
        args.append("--merge-base=" + _sha(merge_base))
    args += ["--end-of-options", _sha(ours), _sha(theirs)]
    result = _run(repo, *args, timeout=MERGE_TIMEOUT)
    fields = result.stdout.split(b"\0")
    if result.returncode == 0 and fields and _SHA.fullmatch(fields[0].decode("ascii", "replace")):
        return fields[0].decode(), []
    if result.returncode == 1:
        conflicts: list[str] = []
        for raw in fields[1:]:
            name = raw.decode("utf-8", "replace")
            if name and name not in conflicts:
                conflicts.append(name)
        return None, conflicts
    error = result.stderr.decode("utf-8", "replace")
    if "unrelated histories" in error:
        raise MergeError("unsupported", "The branches do not share any history.")
    raise MergeError("failed", "Git could not merge the branches: " + error.strip()[:500])


def commits_to_replay(repo: str, base: str, head: str) -> list[str]:
    """Commits in ``base..head``, oldest first; merge commits are not supported."""
    out = _git(
        repo, "rev-list", "--reverse", "--topo-order", "--parents", _sha(base) + ".." + _sha(head)
    )
    commits: list[str] = []
    for line in out.decode().splitlines():
        parts = line.split()
        if not parts:
            continue
        if len(parts) != 2:
            raise MergeError(
                "unsupported",
                "Rebase merging is not available for branches containing merge commits.",
            )
        commits.append(parts[0])
    return commits


def _parse_commit(raw: bytes) -> tuple[dict[bytes, bytes], bytes]:
    """Split a raw commit object into single-line headers and the exact message."""
    header, sep, message = raw.partition(b"\n\n")
    if not sep:
        header, message = raw.rstrip(b"\n"), b""
    headers: dict[bytes, bytes] = {}
    for line in header.split(b"\n"):
        if line.startswith(b" "):  # Continuation of a multi-line header (gpgsig).
            continue
        key, _, value = line.partition(b" ")
        headers.setdefault(key, value)
    return headers, message


def _author_env(raw_author: bytes) -> dict[str, str]:
    match = re.fullmatch(rb"(.*?) ?<([^<>]*)> (\d+) ([+-]\d{4})", raw_author)
    if not match:
        raise MergeError("unsupported", "A commit has a malformed author and cannot be rebased.")
    name, email, stamp, zone = (g.decode("utf-8", "replace") for g in match.groups())
    return {
        "GIT_AUTHOR_NAME": name,
        "GIT_AUTHOR_EMAIL": email,
        "GIT_AUTHOR_DATE": "@" + stamp + " " + zone,
    }


def _replay(
    repo: str, onto: str, commits: Sequence[str], committer: Identity | None
) -> tuple[str, list[str]]:
    """Cherry-pick ``commits`` onto ``onto``.

    Returns ``(new_tip, [])`` or ``(onto, conflicts)``. With ``committer`` None
    only trees are computed (a dry run for mergeability).
    """
    current = onto
    current_tree = _tree_of(repo, onto)
    for commit in commits:
        raw = _git(repo, "cat-file", "commit", commit)
        headers, message = _parse_commit(raw)
        parent = headers.get(b"parent", b"").decode()
        tree, conflicts = merge_tree(repo, current, commit, merge_base=parent)
        if tree is None:
            return onto, conflicts
        if tree == current_tree:
            continue  # Already applied upstream; the commit became empty.
        if committer is None:
            # merge-tree accepts trees when an explicit merge base is given, so
            # a dry run needs no throwaway commit objects.
            current = current_tree = tree
            continue
        env = _identity_env(committer)
        env.update(_author_env(headers.get(b"author", b"")))
        options: list[str] = []
        encoding = headers.get(b"encoding")
        if encoding and re.fullmatch(rb"[A-Za-z0-9_.:-]{1,40}", encoding):
            options = ["-c", "i18n.commitEncoding=" + encoding.decode()]
        current = (
            _git(repo, *options, "commit-tree", tree, "-p", current, data=message, env=env)
            .decode()
            .strip()
        )
        current_tree = tree
    return current, []


def mergeability(repo: str, target: str, source: str) -> Mergeability:
    """How (and whether) ``source`` can be merged into ``target``.

    ``target`` and ``source`` are branch names, full refs or commit SHAs.
    ``rebase_clean`` is None when rebasing is unsupported (merge commits) or
    too expensive to preview.
    """
    tgt = resolve(repo, target)
    src = resolve(repo, source)
    if tgt is None or src is None:
        raise MergeError("not_found", "The branch no longer exists.")
    result: Mergeability = {
        "fast_forward": False,
        "clean": True,
        "conflicts": [],
        "up_to_date": False,
        "rebase_clean": None,
    }
    if tgt == src or _is_ancestor(repo, src, tgt):
        result["up_to_date"] = True
        return result
    result["fast_forward"] = _is_ancestor(repo, tgt, src)
    tree, conflicts = merge_tree(repo, tgt, src)
    result["clean"] = tree is not None
    result["conflicts"] = conflicts
    try:
        commits = commits_to_replay(repo, tgt, src)
    except MergeError as error:
        if error.code != "unsupported":
            raise
        return result
    if len(commits) <= MAX_REBASE_PREVIEW:
        _tip, rebase_conflicts = _replay(repo, tgt, commits, None)
        result["rebase_clean"] = not rebase_conflicts
    return result


# --------------------------------------------------------------------------- #
# Ref updates and merging
# --------------------------------------------------------------------------- #


def _update_refs(repo: str, update: tuple[str, str, str], verify: tuple[str, str] | None) -> None:
    """Atomically ``verify`` one ref and move another; raise "stale" on any mismatch."""
    ref, new, old = update
    lines = ["start"]
    if verify is not None:
        lines.append(f"verify {verify[0]} {verify[1]}")
    lines += [f"update {ref} {new} {old}", "prepare", "commit", ""]
    result = _run(repo, "update-ref", "--stdin", data="\n".join(lines).encode())
    if result.returncode:
        raise MergeError("stale", "The branch changed while merging; refresh and try again.")


def _current(repo: str, branch: str, expected: str) -> str:
    tip = resolve(repo, "refs/heads/" + branch)
    if tip is None:
        raise MergeError("not_found", f"Branch '{branch}' no longer exists.")
    if tip != expected:
        raise MergeError("stale", f"Branch '{branch}' changed; refresh and try again.")
    return tip


def _merge_commit(
    repo: str, tree: str, parents: Sequence[str], message: bytes, env: Mapping[str, str]
) -> str:
    args = ["commit-tree", tree]
    for parent in parents:
        args += ["-p", parent]
    return _git(repo, *args, data=message, env=env).decode().strip()


def merge_pull(
    repo: str,
    *,
    target_branch: str,
    source_branch: str,
    expected_target: str,
    expected_source: str,
    method: MergeMethod,
    committer: Identity,
    title: str,
    message: str = "",
    squash_author: Identity | None = None,
) -> str:
    """Merge ``source_branch`` into ``target_branch``; returns the new target tip."""
    _branch(repo, target_branch)
    _branch(repo, source_branch)
    if target_branch == source_branch:
        raise MergeError("invalid", "Choose two different branches.")
    _sha(expected_target)
    _sha(expected_source)
    if method not in ("merge", "squash", "rebase", "ff"):
        raise MergeError("invalid", "Unknown merge method.")
    _identity_ok(committer)
    if squash_author is not None:
        _identity_ok(squash_author)
    commit_message = _commit_message(title, message) if method in ("merge", "squash") else b""

    tgt = _current(repo, target_branch, expected_target)
    src = _current(repo, source_branch, expected_source)
    if tgt == src or _is_ancestor(repo, src, tgt):
        raise MergeError("up_to_date", "The target branch already contains these changes.")

    if method == "ff":
        if not _is_ancestor(repo, tgt, src):
            raise MergeError(
                "unsupported",
                "The branches have diverged; a fast-forward merge is not possible.",
            )
        new = src
    elif method == "rebase":
        commits = commits_to_replay(repo, tgt, src)
        new, conflicts = _replay(repo, tgt, commits, committer)
        if conflicts:
            raise MergeError(
                "conflict", "The commits cannot be rebased cleanly onto the target.", conflicts
            )
        if new == tgt:
            raise MergeError("up_to_date", "The target branch already contains these changes.")
    else:
        tree, conflicts = merge_tree(repo, tgt, src)
        if tree is None:
            raise MergeError("conflict", "The branches have conflicting changes.", conflicts)
        if method == "merge":
            env = _identity_env(committer)
            new = _merge_commit(repo, tree, (tgt, src), commit_message, env)
        else:
            env = _identity_env(committer, squash_author)
            new = _merge_commit(repo, tree, (tgt,), commit_message, env)

    _update_refs(
        repo,
        ("refs/heads/" + target_branch, new, tgt),
        ("refs/heads/" + source_branch, src),
    )
    return new


def update_branch(
    repo: str,
    *,
    head_branch: str,
    base_branch: str,
    expected_head: str,
    expected_base: str,
    committer: Identity,
    message: str,
) -> str:
    """Merge ``base_branch`` into ``head_branch`` (GitHub's "Update branch")."""
    _branch(repo, head_branch)
    _branch(repo, base_branch)
    if head_branch == base_branch:
        raise MergeError("invalid", "Choose two different branches.")
    _sha(expected_head)
    _sha(expected_base)
    _identity_ok(committer)
    commit_message = _commit_message(message, "")
    head = _current(repo, head_branch, expected_head)
    base = _current(repo, base_branch, expected_base)
    if head == base or _is_ancestor(repo, base, head):
        raise MergeError("up_to_date", "This branch is already up to date with the base branch.")
    tree, conflicts = merge_tree(repo, head, base)
    if tree is None:
        raise MergeError("conflict", "The base branch has conflicting changes.", conflicts)
    new = _merge_commit(repo, tree, (head, base), commit_message, _identity_env(committer))
    _update_refs(
        repo, ("refs/heads/" + head_branch, new, head), ("refs/heads/" + base_branch, base)
    )
    return new


# --------------------------------------------------------------------------- #
# Files, review suggestions and line mapping
# --------------------------------------------------------------------------- #


def _entry(repo: str, commit: str, path: str) -> tuple[str, str, str] | None:
    """``(mode, type, oid)`` of ``path`` at ``commit``, or None."""
    out = _git(repo, "ls-tree", "-z", "--full-tree", _sha(commit), "--", _path(path))
    for record in out.split(b"\0"):
        meta, tab, name = record.partition(b"\t")
        if not tab or name.decode("utf-8", "replace") != path:
            continue
        parts = meta.decode().split()
        if len(parts) == 3:
            return parts[0], parts[1], parts[2]
    return None


def blob_id(repo: str, commit: str, path: str) -> str | None:
    found = _entry(repo, commit, path)
    if found is None or found[1] != "blob":
        return None
    return found[2]


def path_changed(repo: str, old_commit: str, new_commit: str, path: str) -> bool:
    return blob_id(repo, old_commit, path) != blob_id(repo, new_commit, path)


def _split_lines(data: bytes) -> list[tuple[bytes, bytes]]:
    """``(content, terminator)`` pairs; the terminator is ``\\r\\n``, ``\\n`` or empty."""
    lines: list[tuple[bytes, bytes]] = []
    pieces = data.split(b"\n")
    for index, piece in enumerate(pieces):
        last = index == len(pieces) - 1
        if last:
            if piece:
                lines.append((piece, b""))
        elif piece.endswith(b"\r"):
            lines.append((piece[:-1], b"\r\n"))
        else:
            lines.append((piece, b"\n"))
    return lines


def _regular_blob(repo: str, commit: str, path: str) -> tuple[str, str, bytes] | None:
    found = _entry(repo, commit, path)
    if found is None or found[1] != "blob" or found[0] not in REGULAR_MODES:
        return None
    data = _git(repo, "cat-file", "blob", found[2])
    if b"\0" in data:
        return None
    return found[0], found[2], data


def file_lines(repo: str, commit: str, path: str) -> list[str] | None:
    """Text lines (without terminators) of a regular file, None if missing or binary."""
    found = _regular_blob(repo, commit, path)
    if found is None:
        return None
    return [content.decode("utf-8", "replace") for content, _term in _split_lines(found[2])]


def replace_lines(
    repo: str,
    *,
    branch: str,
    expected_head: str,
    path: str,
    start_line: int,
    end_line: int,
    expected_lines: Sequence[str],
    new_text: str,
    message: str,
    author: Identity,
) -> str:
    """Apply a review suggestion replacing lines ``start_line..end_line`` (1-based)."""
    _branch(repo, branch)
    _sha(expected_head)
    _path(path)
    _identity_ok(author)
    commit_message = _commit_message(message, "")
    if (
        not isinstance(start_line, int)
        or not isinstance(end_line, int)
        or not 1 <= start_line <= end_line
    ):
        raise MergeError("invalid", "Invalid line range.")
    if not isinstance(new_text, str) or "\0" in new_text or len(new_text) > MAX_REPLACE_FILE:
        raise MergeError("invalid", "Invalid suggested change.")
    expected = list(expected_lines)
    if len(expected) != end_line - start_line + 1:
        raise MergeError("invalid", "The line range does not match the original lines.")

    head = _current(repo, branch, expected_head)
    found = _regular_blob(repo, head, path)
    if found is None:
        raise MergeError("stale", "The file no longer exists or is not a text file.")
    mode, _oid, data = found
    lines = _split_lines(data)
    if end_line > len(lines):
        raise MergeError("stale", "The file changed since this suggestion was made.")
    current = [c.decode("utf-8", "replace") for c, _t in lines[start_line - 1 : end_line]]
    if current != expected:
        raise MergeError("stale", "The file changed since this suggestion was made.")

    crlf = sum(1 for _c, t in lines if t == b"\r\n")
    lf = sum(1 for _c, t in lines if t == b"\n")
    eol = b"\r\n" if crlf > lf else b"\n"
    trailing_newline = not lines or lines[-1][1] != b""
    text = new_text[:-2] if new_text.endswith("\r\n") else new_text.removesuffix("\n")
    replacement = [(line.encode("utf-8"), eol) for line in re.split(r"\r\n|\r|\n", text)]
    if not new_text:
        replacement = []
    result = lines[: start_line - 1] + replacement + lines[end_line:]
    if result:
        content, term = result[-1]
        if not trailing_newline:
            result[-1] = (content, b"")
        elif not term:
            result[-1] = (content, eol)
    new_data = b"".join(content + term for content, term in result)
    if len(new_data) > MAX_REPLACE_FILE:
        raise MergeError("invalid", "The changed file is too large.")
    if new_data == data:
        raise MergeError("invalid", "The suggestion does not change the file.")

    env = _identity_env(author)
    oid = _git(repo, "hash-object", "-w", "--stdin", data=new_data, env=env).decode().strip()
    with tempfile.TemporaryDirectory(prefix="pygithost-suggest-") as directory:
        index_env = dict(env, GIT_INDEX_FILE=os.path.join(directory, "index"))
        _git(repo, "read-tree", head, env=index_env)
        record = f"{mode} {oid}\t{path}".encode() + b"\0"
        _git(repo, "update-index", "-z", "--index-info", data=record, env=index_env)
        tree = _git(repo, "write-tree", env=index_env).decode().strip()
    new = _merge_commit(repo, tree, (head,), commit_message, env)
    _update_refs(repo, ("refs/heads/" + branch, new, head), None)
    return new


def map_line(repo: str, old_commit: str, new_commit: str, path: str, line: int) -> int | None:
    """Position of ``path``'s line ``line`` at ``old_commit`` within ``new_commit``.

    None when the line was changed or removed, the file was deleted (renames are
    not followed) or the file is binary.
    """
    _sha(old_commit)
    _sha(new_commit)
    _path(path)
    if not isinstance(line, int) or line < 1:
        raise MergeError("invalid", "Invalid line number.")
    old_blob = blob_id(repo, old_commit, path)
    new_blob = blob_id(repo, new_commit, path)
    if old_blob is None or new_blob is None:
        return None
    if old_blob == new_blob:
        return line
    out = _git(
        repo,
        "diff",
        "-U0",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        old_commit,
        new_commit,
        "--",
        path,
    )
    delta = 0
    hunks = 0
    for raw in out.split(b"\n"):
        match = _HUNK.match(raw)
        if not match:
            continue
        hunks += 1
        old_start = int(match.group(1))
        old_count = int(match.group(2)) if match.group(2) is not None else 1
        new_count = int(match.group(4)) if match.group(4) is not None else 1
        if old_count:
            if old_start <= line <= old_start + old_count - 1:
                return None
            if old_start > line:
                break
        elif old_start >= line:  # Pure insertion after line ``old_start``.
            break
        delta += new_count - old_count
    if not hunks:
        return None  # Binary or otherwise unparseable change.
    return line + delta


def run_git(repo: str, *args: str) -> str:
    """Run a read-only Git command with the sanitised environment; return stdout text."""
    return _git(repo, *args).decode("utf-8", "replace")


def is_ancestor(repo: str, ancestor: str, descendant: str) -> bool:
    return _is_ancestor(repo, _sha(ancestor), _sha(descendant))


def delete_branch(repo: str, branch: str, expected: str) -> None:
    """Delete ``refs/heads/<branch>`` only if it still points at ``expected``."""
    name = _branch(repo, branch)
    _update_refs(repo, ("refs/heads/" + name, "0" * len(_sha(expected)), expected), None)


def create_branch(repo: str, branch: str, sha: str) -> None:
    """Create ``refs/heads/<branch>`` at ``sha``; fails if the branch already exists."""
    name = _branch(repo, branch)
    commit = _sha(sha)
    if resolve(repo, commit) is None:
        raise MergeError("not_found", "That commit is no longer in the repository.")
    _update_refs(repo, ("refs/heads/" + name, commit, "0" * len(commit)), None)
