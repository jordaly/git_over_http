"""Read-only Git operations with bounded output and subprocess lifetime."""

import asyncio
import contextlib
from datetime import datetime, timezone
import os
import re

from .errors import APIError


MAX_OUTPUT = 1024 * 1024


async def git(path, *args, max_output=None):
    maximum = MAX_OUTPUT if max_output is None else max_output
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    process = await asyncio.create_subprocess_exec(
        "git", "--no-pager", "--git-dir=" + str(path), *args,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, env=env)
    try:
        async with asyncio.timeout(10):
            output = bytearray()
            while chunk := await process.stdout.read(65536):
                output.extend(chunk)
                if len(output) > maximum:
                    raise APIError(413, "response_too_large", "Git output exceeds the API limit.")
            await process.wait()
            return process.returncode, bytes(output)
    finally:
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
        # Drain remaining pipe data after killing a capped/cancelled process.
        # wait() alone can hang if its stdout transport is paused on a full buffer.
        await process.communicate()


async def default_branch(path):
    code, out = await git(path, "symbolic-ref", "--quiet", "--short", "HEAD")
    return out.decode("utf-8", "replace").strip() if code == 0 else None


async def branches(path, limit, offset):
    code, out = await git(path, "for-each-ref", "--sort=refname",
                          "--format=%(refname)%00%(objectname)", "refs/heads/")
    if code:
        raise APIError(503, "repository_unavailable", "Cannot read repository branches.")
    rows = []
    for line in out.decode("utf-8", "replace").splitlines():
        name, sha = line.split("\0", 1)
        rows.append({"name": name.removeprefix("refs/heads/"), "commit": {"sha": sha}})
    return rows[offset:offset + limit]


async def resolve(path, value):
    # Do not expose revision expressions, reflogs, ranges or Git options.
    if (not value or len(value) > 256 or value.startswith(("-", "/"))
            or not re.fullmatch(r"[A-Za-z0-9_./-]+", value)
            or any(part in ("", ".", "..", ".git") for part in value.split("/"))):
        raise APIError(400, "invalid_ref", "Use a branch name, tag name or full commit SHA.")
    if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
        candidates = [value]
    else:
        candidates = ["refs/heads/" + value, "refs/tags/" + value]
    for candidate in candidates:
        code, out = await git(path, "rev-parse", "--verify", "--end-of-options", candidate + "^{commit}")
        if code == 0:
            return out.decode("ascii").strip()
    raise APIError(404, "not_found", "Commit or reference not found.")


def _commit(fields):
    sha, parents, name, email, date, message = fields
    date = datetime.fromisoformat(date).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return {"sha": sha, "parents": [{"sha": p} for p in parents.split()],
            "commit": {"message": message.rstrip("\n"),
                       "author": {"name": name, "email": email, "date": date}}}


async def commits(path, sha, limit, offset, *, exclude=None):
    # NUL-separated records preserve multiline subjects/bodies and unusual names.
    code, out = await git(path, "log", "--no-show-signature", "-z",
                          "--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%B",
                          f"--max-count={limit}", f"--skip={offset}", sha,
                          *(["^" + exclude] if exclude else []), "--")
    if code:
        raise APIError(503, "repository_unavailable", "Cannot read repository commits.")
    fields = out.decode("utf-8", "replace").split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    return [_commit(fields[i:i + 6]) for i in range(0, len(fields), 6)]
