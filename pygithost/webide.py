"""Bounded, worktree-free Git operations for the browser editor."""

import os
import re
import subprocess
import tempfile
import threading
from collections.abc import Iterable, Mapping
from typing import TypedDict

MAX_FILE = 1024 * 1024
MAX_REQUEST = 5 * MAX_FILE
# The Explorer loads directories on demand; this bounds the optional whole-repo
# index used by "Go to file" and the filename filter.
MAX_INDEX_FILES = 200_000
# A single directory response is truncated at this size; the client shows a note
# and users can fall back to the index/picker for huge listings.
MAX_DIR_ENTRIES = 20_000
REGULAR_MODES = ("100644", "100755")


class IDEError(ValueError):
    pass


class TreeEntry(TypedDict):
    """Metadata for one path recorded in a Git tree."""

    path: str
    mode: str
    type: str
    oid: str


class DirectoryEntry(TypedDict):
    """One direct child of a directory listing."""

    name: str
    path: str
    type: str


class DirectoryListing(TypedDict):
    """A bounded listing of one directory."""

    path: str
    entries: list[DirectoryEntry]
    truncated: bool


class Snapshot(TypedDict):
    """Initial editor state for one branch."""

    branch: str
    commit: str
    root: list[DirectoryEntry]
    root_truncated: bool


class PathIndex(TypedDict):
    """Flat path index used by "Go to file" and the filename filter."""

    files: list[str]


class SearchHit(TypedDict):
    """One matching line from a bounded repository search."""

    path: str
    line: int
    text: str


class SearchResults(TypedDict):
    """Bounded search response."""

    results: list[SearchHit]
    truncated: bool


def git(
    repo: str,
    *args: str,
    data: bytes | None = None,
    env: Mapping[str, str] | None = None,
) -> bytes:
    result = subprocess.run(
        ["git", "--git-dir=" + repo, *args], input=data, capture_output=True, env=env, timeout=30
    )
    if result.returncode:
        raise IDEError("Git operation failed: " + result.stderr.decode("utf-8", "replace")[:500])
    return result.stdout


def _identity(username: str | None) -> dict[str, str]:
    """Author/committer variables; inherited identity must not impersonate another user."""
    name = re.sub(r"[<>\r\n\x00]", "", username or "Browser user")[:100] or "Browser user"
    email = re.sub(r"[^a-zA-Z0-9_.-]", "_", name) + "@users.pygithost.local"
    return {
        "GIT_AUTHOR_NAME": name,
        "GIT_AUTHOR_EMAIL": email,
        "GIT_COMMITTER_NAME": name,
        "GIT_COMMITTER_EMAIL": email,
    }


def initial_commit(repo: str, branch: str, files: Mapping[str, bytes], username: str | None) -> str:
    """Commit top-level files as the first commit of an empty bare repository.

    Returns the new commit SHA. The ref update only succeeds if the branch does
    not exist yet, so a concurrent first push is never overwritten.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(_identity(username))
    records = b""
    for filename, content in files.items():
        if not filename or "/" in filename or any(c in filename for c in "\t\n\0"):
            raise IDEError("Invalid initial file name.")
        oid = git(repo, "hash-object", "-w", "--stdin", data=content, env=env).strip()
        records += b"100644 blob " + oid + b"\t" + filename.encode() + b"\n"
    tree = git(repo, "mktree", data=records, env=env).decode().strip()
    commit = git(repo, "commit-tree", tree, data=b"Initial commit\n", env=env).decode().strip()
    zero = "0" * len(commit)
    git(repo, "update-ref", "refs/heads/" + branch, commit, zero, env=env)
    return commit


def path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 4096
        or any(ord(c) < 32 for c in value)
        or "\\" in value
        or any(p in ("", ".", "..") or p.lower() == ".git" for p in value.split("/"))
    ):
        raise IDEError("Invalid repository file path.")
    return value


def head(repo: str, branch: str) -> str:
    if not isinstance(branch, str) or not branch or branch.startswith("-"):
        raise IDEError("Choose an existing branch.")
    git(repo, "check-ref-format", "refs/heads/" + branch)
    return git(repo, "rev-parse", "--verify", "refs/heads/" + branch).decode().strip()


def _tree_record(record: bytes) -> tuple[str, str, str, str] | None:
    """Parse one NUL-delimited `git ls-tree` record into (mode, kind, oid, name)."""
    if not record:
        return None
    try:
        meta, raw_name = record.split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        return mode, kind, oid, raw_name.decode("utf-8")
    except ValueError, UnicodeDecodeError:
        return None


def tree(repo: str, commit: str) -> dict[str, TreeEntry]:
    entries: dict[str, TreeEntry] = {}
    for record in git(repo, "ls-tree", "-rz", "--full-tree", commit).split(b"\0"):
        parsed = _tree_record(record)
        if not parsed:
            continue
        mode, kind, oid, name = parsed
        entries[name] = {"path": name, "mode": mode, "type": kind, "oid": oid}
        if len(entries) > MAX_INDEX_FILES:
            raise IDEError(
                f"This repository exceeds the editor's {MAX_INDEX_FILES:,}-file index limit."
            )
    return entries


def paths(repo: str, commit: str) -> list[str]:
    """Every path in the commit, without building per-file metadata."""
    names: list[str] = []
    for record in git(repo, "ls-tree", "-rz", "--full-tree", commit).split(b"\0"):
        parsed = _tree_record(record)
        if not parsed:
            continue
        names.append(parsed[3])
        if len(names) > MAX_INDEX_FILES:
            raise IDEError(
                f"This repository exceeds the editor's {MAX_INDEX_FILES:,}-file index limit."
            )
    return names


def _commit_in_branch(repo: str, branch: str, commit: str) -> str:
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit or ""):
        raise IDEError("Invalid base commit.")
    git(repo, "merge-base", "--is-ancestor", commit, head(repo, branch))
    return commit


def children(repo: str, branch: str, commit: str, directory: str = "") -> DirectoryListing:
    """Direct children of one directory (a single `git ls-tree` call)."""
    _commit_in_branch(repo, branch, commit)
    if directory:
        path(directory)
        spec = commit + ":" + directory
    else:
        spec = commit + ":"
    entries: list[DirectoryEntry] = []
    for record in git(repo, "ls-tree", "-z", spec).split(b"\0"):
        parsed = _tree_record(record)
        if not parsed:
            continue
        _mode, kind, _oid, name = parsed
        entries.append(
            {
                "name": name,
                "path": (directory + "/" if directory else "") + name,
                "type": "tree" if kind == "tree" else "blob",
            }
        )
    entries.sort(key=lambda item: (0 if item["type"] == "tree" else 1, item["name"].lower()))
    truncated = len(entries) > MAX_DIR_ENTRIES
    return {"path": directory, "entries": entries[:MAX_DIR_ENTRIES], "truncated": truncated}


def index(repo: str, branch: str, commit: str) -> PathIndex:
    """Optional flat path index for "Go to file" and the filename filter."""
    _commit_in_branch(repo, branch, commit)
    return {"files": paths(repo, commit)}


def entry(repo: str, commit: str, filename: str) -> TreeEntry | None:
    """Metadata for one path, without scanning the whole repository."""
    for record in git(repo, "--literal-pathspecs", "ls-tree", "-z", commit, "--", filename).split(
        b"\0"
    ):
        parsed = _tree_record(record)
        if parsed and parsed[3] == filename:
            mode, kind, oid, _name = parsed
            return {"path": filename, "mode": mode, "type": kind, "oid": oid}
    return None


def regular_entries(repo: str, commit: str, names: Iterable[str]) -> set[str]:
    """The subset of `names` that are regular files, resolved in bounded Git calls."""
    allowed: set[str] = set()
    # Chunk pathspecs to stay well under the platform argument limit.
    unique = [name for name in dict.fromkeys(names) if name]
    for index in range(0, len(unique), 50):
        chunk = unique[index : index + 50]
        output = git(repo, "--literal-pathspecs", "ls-tree", "-rz", commit, "--", *chunk)
        for record in output.split(b"\0"):
            parsed = _tree_record(record)
            if parsed and parsed[0] in REGULAR_MODES:
                allowed.add(parsed[3])
    return allowed


def snapshot(repo: str, branch: str) -> Snapshot:
    commit = head(repo, branch)
    # Only the root listing is returned up front. The Explorer requests each
    # directory as the user opens it, so huge repositories never ship a full
    # path list on load. The optional flat index powers "Go to file" and the
    # filename filter when those are used.
    listing = children(repo, branch, commit, "")
    return {
        "branch": branch,
        "commit": commit,
        "root": listing["entries"],
        "root_truncated": listing["truncated"],
    }


def _blob(repo: str, info: TreeEntry) -> str:
    if info["mode"] not in REGULAR_MODES:
        raise IDEError("Only regular text files can be edited (not symlinks or submodules).")
    if int(git(repo, "cat-file", "-s", info["oid"])) > MAX_FILE:
        raise IDEError("Files larger than 1 MiB cannot be edited.")
    content = git(repo, "cat-file", "blob", info["oid"])
    if b"\0" in content:
        raise IDEError("Binary files cannot be edited.")
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IDEError("Only UTF-8 text files can be edited.") from exc


def read_file(repo: str, branch: str, commit: str, filename: str) -> str:
    path(filename)
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit or ""):
        raise IDEError("Invalid base commit.")
    # Only serve snapshots from this branch's history, not arbitrary objects.
    git(repo, "merge-base", "--is-ancestor", commit, head(repo, branch))
    info = entry(repo, commit, filename)
    if not info:
        raise IDEError("Only regular text files can be edited (not symlinks or submodules).")
    return _blob(repo, info)


def search(repo: str, branch: str, commit: str, query: str) -> SearchResults:
    """Literal, case-insensitive search with bounded output and runtime."""
    if (
        not isinstance(query, str)
        or not query.strip()
        or len(query) > 200
        or any(c in query for c in "\0\r\n")
    ):
        raise IDEError("Enter a single-line search term of 1–200 characters.")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise IDEError("Invalid base commit.")
    git(repo, "merge-base", "--is-ancestor", commit, head(repo, branch))
    limit = 256 * 1024
    timed_out = threading.Event()
    with subprocess.Popen(
        [
            "git",
            "--git-dir=" + repo,
            "grep",
            "--no-textconv",
            "-z",
            "-n",
            "-I",
            "-F",
            "-i",
            "-e",
            query,
            commit,
            "--",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as proc:

        def expire() -> None:
            timed_out.set()
            try:
                proc.kill()
            except ProcessLookupError:
                pass

        timer = threading.Timer(10, expire)
        timer.daemon = True
        timer.start()
        assert proc.stdout is not None
        try:
            output = proc.stdout.read(limit + 1)
            if len(output) > limit:
                proc.kill()
            proc.wait()
        finally:
            timer.cancel()
        truncated = len(output) > limit or timed_out.is_set()
        if proc.returncode not in (0, 1) and not truncated:
            raise IDEError("Repository search failed.")
    candidates: list[SearchHit] = []
    remaining = output[:limit]
    while remaining:
        fields = remaining.split(b"\0", 2)
        if len(fields) != 3 or b"\n" not in fields[2]:
            break  # Ignore the final partial record when output was limited.
        raw_name, raw_line, rest = fields
        text, remaining = rest.split(b"\n", 1)
        try:
            filename = raw_name[len(commit) + 1 :].decode("utf-8")
            path(filename)
            candidate: SearchHit = {
                "path": filename,
                "line": int(raw_line),
                "text": text.decode("utf-8")[:300],
            }
        except UnicodeError, ValueError:
            continue
        if len(candidates) == 200:
            truncated = True
            break
        candidates.append(candidate)
    # Validate modes for just the matched paths instead of scanning the whole
    # repository (which would be expensive for large monorepos).
    allowed = regular_entries(repo, commit, [item["path"] for item in candidates])
    results = [item for item in candidates if item["path"] in allowed]
    return {"results": results, "truncated": truncated}


def commit_changes(
    repo: str,
    branch: str,
    base: str,
    changes: Mapping[str, str | None],
    message: str,
    username: str | None,
) -> str:
    if head(repo, branch) != base:
        raise IDEError("The branch changed. Your edits are retained; reload before committing.")
    if (
        not isinstance(message, str)
        or not message.strip()
        or len(message) > 4000
        or "\0" in message
    ):
        raise IDEError("Enter a commit message (up to 4,000 characters).")
    if not isinstance(changes, dict) or not 1 <= len(changes) <= 100:
        raise IDEError("Commit between 1 and 100 changed files.")
    # Never desynchronize a server-side checkout, including linked worktrees.
    worktrees = git(repo, "worktree", "list", "--porcelain").decode("utf-8", "replace")
    if "branch refs/heads/" + branch + "\n" in worktrees:
        raise IDEError("This branch is checked out on the server. Use a different branch.")
    updates: list[tuple[str, str | None, str | None]] = []
    total = 0
    for filename, content in changes.items():
        path(filename)
        old = entry(repo, base, filename)
        if old and old["mode"] not in REGULAR_MODES:
            raise IDEError("Symlinks and submodules cannot be changed in the editor.")
        if content is None:
            if not old:
                raise IDEError("Cannot delete a nonexistent file.")
            updates.append((filename, None, None))
            continue
        if not isinstance(content, str) or "\0" in content:
            raise IDEError("Only UTF-8 text content is supported.")
        encoded = content.encode("utf-8")
        total += len(encoded)
        if len(encoded) > MAX_FILE or total > MAX_REQUEST:
            raise IDEError("Changes exceed the editor size limit.")
        if old:
            _blob(repo, old)  # Reject binaries and oversized existing files.
        oid = git(repo, "hash-object", "-w", "--stdin", data=encoded).decode().strip()
        updates.append((filename, old["mode"] if old else "100644", oid))
    with tempfile.TemporaryDirectory(prefix="pygithost-ide-") as directory:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = os.path.join(directory, "index")
        env.update(_identity(username))
        git(repo, "read-tree", base, env=env)
        for filename, file_mode, file_oid in updates:
            if file_oid is not None:
                assert file_mode is not None
                record = file_mode + " " + file_oid + "\t" + filename
            else:
                record = "0 " + "0" * len(base) + "\t" + filename
            git(repo, "update-index", "-z", "--index-info", data=record.encode() + b"\0", env=env)
        new_tree = git(repo, "write-tree", env=env).decode().strip()
        if new_tree == git(repo, "rev-parse", base + "^{tree}").decode().strip():
            raise IDEError("There are no changes to commit.")
        commit = (
            git(
                repo,
                "commit-tree",
                new_tree,
                "-p",
                base,
                data=(message.strip() + "\n").encode(),
                env=env,
            )
            .decode()
            .strip()
        )
        # Local receive-pack honors repository receive hooks/configuration. The
        # explicit lease protects against pushes outside the HTTP server too.
        # Objects already exist in this repository, so no checkout is necessary.
        git(
            repo,
            "push",
            "--no-verify",
            "--porcelain",
            "--force-with-lease=refs/heads/" + branch + ":" + base,
            "--",
            os.path.abspath(repo),
            commit + ":refs/heads/" + branch,
            env=env,
        )
        return commit
