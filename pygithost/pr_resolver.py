"""Web-UI pull-request conflict resolution through Git plumbing.

The resolver merges the target branch into the source branch inside a temporary
index, produces conflict-marker previews, and turns edited resolutions into a
merge commit on the source branch. It never touches the working tree of a bare
repository and validates ref updates against the commit the user started from.
"""

import os
import re
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import TypedDict

from .webide import IDEError
from .webide import git as _git


class ResolverError(ValueError):
    """Actionable resolution error shown on the resolve page."""


class ConflictInfo(TypedDict):
    """Conflicted path with the blob OID present in each merge stage."""

    path: str
    mode: str
    base: str | None
    ours: str | None
    theirs: str | None


MAX_FILE = 1 << 20
MAX_CONFLICT_FILES = 40


def _blob(repo: str, oid: str) -> bytes:
    return _git(repo, "cat-file", "blob", oid)


def _index_env(directory: str) -> dict[str, str]:
    """Environment for index-only plumbing against a bare repository.

    ``read-tree``/``update-index``/``write-tree`` need a working tree to exist,
    but never write into it without a checkout; an empty temporary directory
    satisfies that requirement while keeping the repository untouched.
    """
    env = os.environ.copy()
    env["GIT_WORK_TREE"] = directory
    env["GIT_INDEX_FILE"] = os.path.join(directory, "index")
    return env


def list_conflicts(repo: str, base: str, ours: str, theirs: str) -> list[ConflictInfo]:
    """Return conflicted paths with per-side blob OIDs using a 3-way index."""
    with tempfile.TemporaryDirectory(prefix="pygithost-merge-") as directory:
        env = _index_env(directory)
        _git(repo, "read-tree", "-m", base, ours, theirs, env=env)
        raw = _git(repo, "ls-files", "-u", "-z", env=env)
    conflicts: dict[str, ConflictInfo] = {}
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        header, _, path = entry.partition(b"\t")
        mode, oid, stage = header.split(b" ")
        decoded_path = path.decode("utf-8", "replace")
        item = conflicts.setdefault(
            decoded_path,
            {
                "path": decoded_path,
                "mode": mode.decode(),
                "base": None,
                "ours": None,
                "theirs": None,
            },
        )
        side = {b"1": "base", b"2": "ours", b"3": "theirs"}[stage]
        decoded_oid = oid.decode()
        if side == "base":
            item["base"] = decoded_oid
        elif side == "ours":
            item["ours"] = decoded_oid
        else:
            item["theirs"] = decoded_oid
    return [conflicts[path] for path in sorted(conflicts)]


def _run_merge_file(
    ours: bytes | None,
    theirs: bytes | None,
    base: bytes | None,
    names: tuple[str, str, str],
) -> tuple[int, bytes]:
    with tempfile.TemporaryDirectory(prefix="pygithost-conflict-") as directory:
        ours_path = Path(directory) / "ours"
        theirs_path = Path(directory) / "theirs"
        base_path = Path(directory) / "base"
        ours_path.write_bytes(ours or b"")
        theirs_path.write_bytes(theirs or b"")
        base_path.write_bytes(base or b"")
        process = subprocess.run(
            [
                "git",
                "merge-file",
                "-p",
                "-L",
                names[0],
                "-L",
                names[1],
                "-L",
                names[2],
                str(ours_path),
                str(base_path),
                str(theirs_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return process.returncode, process.stdout


def preview(
    repo: str, conflict: ConflictInfo, src_branch: str, tgt_branch: str
) -> tuple[bytes | None, str]:
    """Build one conflict-marker text preview for the file."""
    names = (f"HEAD ({src_branch})", "base", f"target ({tgt_branch})")
    sides: dict[str, bytes | None] = {}
    for side in ("base", "ours", "theirs"):
        oid = conflict[side]
        if not oid:
            sides[side] = None
            continue
        data = _blob(repo, oid)
        sides[side] = None if len(data) > MAX_FILE or b"\0" in data else data
    if sides["ours"] is None and conflict["ours"]:
        if sides["theirs"] is None:
            return b"", "nonmergeable"
        return sides["theirs"], "deleted-here"
    if sides["theirs"] is None:
        if conflict["theirs"]:
            return sides["ours"], "deleted-there"
        return sides["ours"], "nonmergeable"
    code, merged = _run_merge_file(sides["ours"], sides["theirs"], sides["base"], names)
    if code < 0:
        return sides["ours"], "nonmergeable"
    return merged, "conflicts"


def apply_resolution(
    repo: str,
    base: str,
    ours: str,
    theirs: str,
    src_branch: str,
    resolutions: Iterable[tuple[str, str | None, bool]],
    message: str | None,
    username: str | None,
) -> str:
    """Create a merge commit integrating resolutions; returns the new commit.

    ``ours``/``theirs`` are the source/target commit SHAs. The merge commit is
    committed onto ``src_branch`` with a compare-and-swap ref update so a push
    that lands while the user is editing invalidates the resolution safely.
    """
    if not isinstance(src_branch, str) or not src_branch or src_branch.startswith("-"):
        raise ResolverError("Invalid source branch.")
    _git(repo, "check-ref-format", "--branch", src_branch)
    message = (message or "").strip()
    if not message or len(message) > 4000 or "\0" in message:
        raise ResolverError("Enter a merge commit message (up to 4,000 characters).")
    seen: set[str] = set()
    updates: list[tuple[str, tuple[str, str] | None]] = []
    for path, content, delete in resolutions:
        if path in seen:
            raise ResolverError(f"Duplicate resolution for {path}.")
        seen.add(path)
        if not isinstance(path, str) or not path or "\0" in path:
            raise ResolverError("Invalid file path.")
        normal = os.path.normpath(path)
        if normal.startswith("../") or normal.startswith("/"):
            raise ResolverError("Invalid file path.")
        if delete:
            updates.append((path, None))
        else:
            if not isinstance(content, str) or "\0" in content:
                raise ResolverError("Only UTF-8 text content is supported.")
            encoded = content.encode("utf-8")
            if len(encoded) > MAX_FILE:
                raise ResolverError(f"Resolution for {path} exceeds the 1 MiB size limit.")
            oid = _git(repo, "hash-object", "-w", "--stdin", data=encoded).decode().strip()
            updates.append((path, ("100644", oid)))
    with tempfile.TemporaryDirectory(prefix="pygithost-resolve-") as directory:
        env = _index_env(directory)
        _git(repo, "read-tree", "-m", base, ours, theirs, env=env)
        unresolved = [
            line.split(b"\t", 1)[1].decode("utf-8", "replace")
            for line in _git(repo, "ls-files", "-u", "-z", env=env).split(b"\0")
            if line
        ]
        resolved = {path for path, _change in updates}
        for path, change in updates:
            if change is None:
                _git(repo, "update-index", "--force-remove", "--", path, env=env)
            else:
                record = change[0] + " " + change[1] + "\t" + path
                _git(
                    repo,
                    "update-index",
                    "-z",
                    "--index-info",
                    data=record.encode() + b"\0",
                    env=env,
                )
        missing = [path for path in unresolved if path not in resolved]
        if missing:
            raise ResolverError(
                "Resolve every conflicted file first: "
                + ", ".join(missing[:5])
                + ("…" if len(missing) > 5 else "")
            )
        tree_id = _git(repo, "write-tree", env=env).decode().strip()
        name = re.sub(r"[<>\r\n\x00]", "", username or "Browser user")[:100] or "Browser user"
        email = re.sub(r"[^a-zA-Z0-9_.-]", "_", name) + "@users.pygithost.local"
        env.update(
            {
                "GIT_AUTHOR_NAME": name,
                "GIT_AUTHOR_EMAIL": email,
                "GIT_COMMITTER_NAME": name,
                "GIT_COMMITTER_EMAIL": email,
            }
        )
        commit = (
            _git(
                repo,
                "commit-tree",
                tree_id,
                "-p",
                ours,
                "-p",
                theirs,
                data=(message + "\n").encode(),
                env=env,
            )
            .decode()
            .strip()
        )
        try:
            _git(repo, "update-ref", "refs/heads/" + src_branch, commit, ours)
        except IDEError:
            raise ResolverError(
                "The source branch changed while resolving. Reload the page and resolve again."
            )
    return commit
