"""Bounded repository browsing and pinned-commit comparisons."""

import asyncio
import re

from .. import webide
from . import data, git
from .errors import APIError
from .responses import BinaryDownload


MAX_SOURCE_ARCHIVE_BYTES = 32 * 1024 * 1024


def query_bool(api, key, default=False):
    value = api.value(key, "true" if default else "false")
    if value not in ("true", "false"):
        raise APIError(400, "invalid_query", f"{key} must be true or false.")
    return value == "true"


def repository_path(value):
    if value:
        try:
            webide.path(value)
        except (webide.IDEError, UnicodeError):
            raise APIError(400, "invalid_path", "Use a checkout-relative path without traversal or .git components.") from None
    return value


def filename(value):
    try:
        return value.decode("utf-8")
    except UnicodeError:
        raise APIError(422, "unsupported_filename", "This response requires UTF-8 repository filenames.") from None


async def reference(api, path):
    value = api.value("ref") or await git.default_branch(path)
    if not value:
        raise APIError(404, "not_found", "Repository has no default commit.")
    return await git.resolve(path, value)


async def entries(path, commit, directory, recursive):
    tree = commit
    if directory:
        code, output = await git.git(path, "--literal-pathspecs", "ls-tree", "-z", commit, "--", directory)
        records = [r for r in output.split(b"\0") if r]
        if code or not records:
            raise APIError(404, "not_found", "Directory not found.")
        meta, found = records[0].split(b"\t", 1)
        if filename(found) != directory or meta.split()[1] != b"tree":
            raise APIError(404, "not_found", "Directory not found.")
        tree = meta.split()[2].decode("ascii")
    code, output = await git.git(path, "ls-tree", "-z", "-l", *(["-r", "-t"] if recursive else []), tree)
    if code:
        raise APIError(503, "repository_unavailable", "Cannot read the repository tree.")
    result = []
    for record in output.split(b"\0"):
        if not record:
            continue
        meta, raw_name = record.split(b"\t", 1)
        mode, kind, sha, size = meta.split()
        name = filename(raw_name)
        full_path = directory + "/" + name if directory else name
        result.append({"path": full_path, "name": name.rsplit("/", 1)[-1],
                       "mode": mode.decode("ascii"), "type": kind.decode("ascii"),
                       "sha": sha.decode("ascii"), "size": int(size) if size != b"-" else None})
    return result


async def search(path, commit, query, prefix, ignore_case):
    code, output = await git.git(
        path, "--literal-pathspecs", "grep", "--no-recurse-submodules", "--no-textconv", "--no-color", "-I", "-n", "-z", "-F",
        *(["-i"] if ignore_case else []), "-e", query, commit, "--", *([prefix] if prefix else []))
    if code == 1:
        return []
    if code:
        raise APIError(503, "repository_unavailable", "Cannot search the repository.")
    result, position = [], 0
    while position < len(output):
        end_name = output.index(b"\0", position)
        end_line = output.index(b"\0", end_name + 1)
        end_text = output.find(b"\n", end_line + 1)
        if end_text == -1:
            end_text = len(output)
        name = filename(output[position:end_name]).removeprefix(commit + ":")
        try:
            text = output[end_line + 1:end_text].decode("utf-8")
        except UnicodeError:
            position = end_text + 1
            continue
        result.append({"path": name, "line_number": int(output[end_name + 1:end_line]),
                       "text": text, "commit_sha": commit})
        position = end_text + 1
    return result


async def diff(path, base, head, *, patch=False):
    # Never execute a repository's external diff or textconv programs.
    common = ["--no-ext-diff", "--no-textconv", "--no-renames", "--no-color"]
    args = ["diff", *common, base, head] if base else [
        "diff-tree", "--root", "--no-commit-id", "-r", *common, head]
    if patch:
        code, output = await git.git(path, *args, "--patch", "--no-color", "--")
        if code:
            raise APIError(503, "repository_unavailable", "Cannot read repository diff.")
        return {"base_sha": base, "head_sha": head, "patch": output.decode("utf-8", "replace")}
    code, output = await git.git(path, *args, "--name-status", "-z", "--")
    if code:
        raise APIError(503, "repository_unavailable", "Cannot list changed files.")
    parts = output.rstrip(b"\0").split(b"\0") if output else []
    statuses = {filename(parts[i + 1]): parts[i].decode("ascii") for i in range(0, len(parts), 2)}
    code, output = await git.git(path, *args, "--numstat", "-z", "--")
    if code:
        raise APIError(503, "repository_unavailable", "Cannot read changed-file statistics.")
    result = []
    for record in output.split(b"\0"):
        if record:
            added, deleted, raw_name = record.split(b"\t", 2)
            name = filename(raw_name)
            result.append({"path": name, "status": statuses[name],
                           "additions": int(added) if added != b"-" else None,
                           "deletions": int(deleted) if deleted != b"-" else None})
    return result


async def read(api, owner, repo, path, tail):
    if tail == "tree":
        api.parameters("ref", "path", "recursive")
        commit = await reference(api, path)
        directory = repository_path(api.value("path"))
        rows = await entries(path, commit, directory, query_bool(api, "recursive"))
        api.response_headers.append(("X-Commit-SHA", commit))
        return api.listing(rows[api.offset:api.offset + api.per_page + 1])
    if tail == "search":
        api.parameters("ref", "path", "q", "ignore_case")
        query = api.value("q")
        if not query.strip() or any(c in query for c in ("\0", "\n", "\r")):
            raise APIError(400, "invalid_query", "q must be a nonempty single-line literal search string.")
        commit = await reference(api, path)
        rows = await search(path, commit, query, repository_path(api.value("path")), query_bool(api, "ignore_case"))
        api.response_headers.append(("X-Commit-SHA", commit))
        return api.listing(rows[api.offset:api.offset + api.per_page + 1])
    if tail == "archive":
        api.parameters("ref")
        commit = await reference(api, path)
        await api.handler.server.api_download_slots.acquire()
        api.download_slot = True
        prefix = repo + "-" + commit[:12]
        code, content = await git.git(
            path, "archive", "--format=zip", "--prefix=" + prefix + "/", commit,
            max_output=MAX_SOURCE_ARCHIVE_BYTES)
        if code:
            raise APIError(503, "repository_unavailable", "Cannot generate the source archive.")
        return BinaryDownload(content if api.request.method != "HEAD" else b"", len(content), prefix + ".zip")
    compare = re.fullmatch(r"compare/(files|diff)", tail)
    commit_view = re.fullmatch(r"commits/([^/]+)/(files|diff)", tail)
    pull_view = re.fullmatch(r"pulls/([0-9]{1,18})/(files|diff|commits)", tail)
    if compare:
        api.parameters("base", "head")
        base, head = await git.resolve(path, api.value("base")), await git.resolve(path, api.value("head"))
        view = compare[1]
    elif commit_view:
        from urllib.parse import unquote
        api.parameters()
        head = await git.resolve(path, unquote(commit_view[1]))
        code, parents = await git.git(path, "rev-list", "--parents", "-n", "1", head, "--")
        if code:
            raise APIError(503, "repository_unavailable", "Cannot read commit parents.")
        values = parents.decode("ascii").split()
        base = values[1] if len(values) > 1 else None
        view = commit_view[2]
    elif pull_view:
        from .writes import branch_head
        api.parameters()
        rows = await asyncio.to_thread(data.pulls, owner, repo, "all", 1, 0, int(pull_view[1]))
        if not rows:
            raise APIError(404, "not_found", "Pull request not found.")
        pull = rows[0]
        target = await branch_head(path, pull["base"]["ref"])
        head = await branch_head(path, pull["head"]["ref"])
        if pull_view[2] == "commits":
            return api.listing(await git.commits(path, head, api.per_page + 1, api.offset, exclude=target))
        code, output = await git.git(path, "merge-base", target, head)
        if code:
            raise APIError(409, "unrelated_histories", "Pull request branches have no common ancestor.")
        base, view = output.decode("ascii").strip(), pull_view[2]
    else:
        raise APIError(404, "not_found", "Repository browsing endpoint not found.")
    if view == "diff":
        return await diff(path, base, head, patch=True)
    rows = await diff(path, base, head)
    api.response_headers.extend([("X-Commit-SHA", head), ("X-Base-SHA", base or "")])
    return api.listing(rows[api.offset:api.offset + api.per_page + 1])
