"""Cached commit metadata for repository directory listings."""

import asyncio
import json
from collections.abc import Sequence
from typing import TypedDict, cast

from . import database


class CommitChange(TypedDict):
    """Metadata for the most recent commit touching one path."""

    hash: str
    author: str
    date: str
    subject: str


class RepositoryOverview(TypedDict):
    """Cached commit metadata for a directory listing."""

    latest: CommitChange | None
    entries: dict[str, CommitChange | None]
    commit_count: int | None
    contributors: list[dict[str, object]]


async def repository_overview(
    owner: str,
    repo: str,
    bare: str,
    commit: str | None,
    entries: Sequence[tuple[str, str]],
    subpath: str = "",
    page: int | None = None,
    page_size: int = 25,
    include_summary: bool = True,
) -> RepositoryOverview:
    """Commit metadata for directory entries.

    ``include_summary`` also resolves the directory's latest commit, the total
    commit count and its contributors. Folder (tree) pages only render the
    per-entry "last commit" columns, so they skip that extra repository-wide
    work.
    """
    if not commit:
        return {"latest": None, "entries": {}, "commit_count": 0, "contributors": []}
    cache_key = commit + ":" + subpath if subpath else commit
    if page is not None:
        cache_key += f":page={page}"
        if page_size != 25:
            cache_key += f":size={page_size}"
    if not include_summary:
        cache_key += ":entries-only"
    cached = await asyncio.to_thread(database.db_repository_overview_get, owner, repo, cache_key)
    if cached is not None:
        return cast(RepositoryOverview, json.loads(cached))
    slots = asyncio.Semaphore(4)

    async def git(*args: str) -> bytes:
        async with slots:
            process = await asyncio.create_subprocess_exec(
                "git",
                "--git-dir=" + bare,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                output, _ = await asyncio.wait_for(process.communicate(), timeout=10)
                return output if process.returncode == 0 else b""
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.communicate()

    async def last_change(path: str | None = None) -> CommitChange | None:
        args = ["--literal-pathspecs", "log", "-1", "--format=%H%x00%an%x00%aI%x00%s", commit]
        if path is not None:
            args += ["--", path]
        try:
            fields = (await git(*args)).decode("utf-8", "replace").rstrip("\n").split("\0", 3)
            if len(fields) != 4:
                return None
            hash_value, author, date, subject = fields
            return {"hash": hash_value, "author": author, "date": date, "subject": subject}
        except OSError, asyncio.TimeoutError:
            return None

    # Avoid unbounded subprocess work for unusually wide directories. Pages
    # pass at most one page of entries, so this only covers what is rendered.
    names = [name for _kind, name in entries[:200]]
    calls = [last_change(subpath + "/" + name if subpath else name) for name in names]
    if include_summary:
        calls.insert(0, last_change(subpath or None))
    try:
        results = await asyncio.wait_for(asyncio.gather(*calls), timeout=15)
    except asyncio.TimeoutError:
        return {"latest": None, "entries": {}, "commit_count": None, "contributors": []}
    latest: CommitChange | None = results[0] if include_summary else None
    if include_summary:
        results = results[1:]
    commit_count: int | None = None
    contributors: list[dict[str, object]] = []
    if include_summary:
        try:
            count, shortlog = await asyncio.gather(
                git("rev-list", "--count", commit), git("shortlog", "-sn", commit)
            )
            commit_count = int(count.strip()) if count.strip().isdigit() else None
            contributors = []
            for line in shortlog.decode("utf-8", "replace").splitlines():
                commits, separator, name = line.strip().partition("\t")
                if separator and commits.strip().isdigit():
                    contributors.append({"name": name, "commits": int(commits)})
        except OSError, asyncio.TimeoutError:
            commit_count, contributors = None, []
    result: RepositoryOverview = {
        "latest": latest,
        "entries": dict(zip(names, results)),
        "commit_count": commit_count,
        "contributors": contributors,
    }
    # Incomplete/failed scans should be retried rather than cached forever.
    complete = all(results) and (not include_summary or (latest and commit_count is not None))
    if complete:
        await asyncio.to_thread(
            database.db_repository_overview_set, owner, repo, cache_key, json.dumps(result)
        )
    return result
