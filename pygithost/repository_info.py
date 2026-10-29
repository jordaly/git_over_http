"""Cached commit metadata for repository directory listings."""

import asyncio
import json

from . import database


async def repository_overview(owner, repo, bare, commit, entries, subpath="", page=None, page_size=25):
    if not commit:
        return {"latest": None, "entries": {}, "commit_count": 0, "contributors": []}
    cache_key = commit + ":" + subpath if subpath else commit
    if page is not None:
        cache_key += f":page={page}"
        if page_size != 25:
            cache_key += f":size={page_size}"
    cached = await asyncio.to_thread(database.db_repository_overview_get, owner, repo, cache_key)
    if cached is not None:
        return json.loads(cached)
    slots = asyncio.Semaphore(4)

    async def git(*args):
        async with slots:
            process = await asyncio.create_subprocess_exec("git", "--git-dir=" + bare, *args,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            try:
                output, _ = await asyncio.wait_for(process.communicate(), timeout=10)
                return output if process.returncode == 0 else b""
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.communicate()

    async def last_change(path=None):
        args = ["--literal-pathspecs", "log", "-1", "--format=%H%x00%an%x00%aI%x00%s", commit]
        if path is not None:
            args += ["--", path]
        try:
            fields = (await git(*args)).decode("utf-8", "replace").rstrip("\n").split("\0", 3)
            return dict(zip(("hash", "author", "date", "subject"), fields)) if len(fields) == 4 else None
        except (OSError, asyncio.TimeoutError):
            return None

    # Avoid unbounded subprocess work for unusually wide root directories.
    names = [name for _kind, name in entries[:200]]
    try:
        results = await asyncio.wait_for(asyncio.gather(last_change(subpath or None), *(last_change(subpath + "/" + name if subpath else name) for name in names)), timeout=15)
    except asyncio.TimeoutError:
        return {"latest": None, "entries": {}, "commit_count": None, "contributors": []}
    try:
        count, shortlog = await asyncio.gather(git("rev-list", "--count", commit), git("shortlog", "-sn", commit))
        commit_count = int(count.strip()) if count.strip().isdigit() else None
        contributors = []
        for line in shortlog.decode("utf-8", "replace").splitlines():
            commits, separator, name = line.strip().partition("\t")
            if separator and commits.strip().isdigit():
                contributors.append({"name": name, "commits": int(commits)})
    except (OSError, asyncio.TimeoutError):
        commit_count, contributors = None, []
    result = {"latest": results[0], "entries": dict(zip(names, results[1:])),
              "commit_count": commit_count, "contributors": contributors}
    # Incomplete/failed scans should be retried rather than cached forever.
    if results[0] and all(results[1:]) and commit_count is not None:
        await asyncio.to_thread(database.db_repository_overview_set, owner, repo, cache_key, json.dumps(result))
    return result
