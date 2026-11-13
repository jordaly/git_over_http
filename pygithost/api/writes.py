"""Safe API mutations, using the existing editor, CI and branch protections."""

import asyncio
import base64
import binascii
from pathlib import Path
import re
from urllib.parse import unquote

from .. import database, webide
from ..ci import protected_branch
from . import data, git, text_mutations
from .errors import APIError
from .validation import fields, name, sha, text


async def branch(path, value):
    if not isinstance(value, str) or not value or len(value) > 256 or value.startswith("-"):
        raise APIError(422, "validation_error", "Invalid branch name.")
    code, _ = await git.git(path, "check-ref-format", "refs/heads/" + value)
    if code:
        raise APIError(422, "validation_error", "Invalid branch name.")
    return value


async def branch_head(path, value):
    await branch(path, value)
    code, out = await git.git(path, "rev-parse", "--verify", "--end-of-options", "refs/heads/" + value + "^{commit}")
    if code:
        raise APIError(404, "not_found", "Branch not found.")
    return out.decode("ascii").strip()


async def unprotected(api, owner, repo, value):
    config = await api.handler.server.ci_manager.config(owner, repo)
    if protected_branch(config, value):
        raise APIError(403, "protected_branch", "Direct changes to this protected branch are blocked. Use a pull request.")


async def notify(api, owner, repo, before, result):
    try:
        await api.handler.server._queue_push_changes(owner, repo, before)
    except Exception as exc:
        # The Git mutation succeeded; never encourage a blind retry of it.
        api.log_failure(exc)
        result["warnings"] = ["Git changed, but CI scheduling failed. Inspect CI before proceeding."]
    return result


async def file_content(path, filename, branch_name):
    await branch(path, branch_name)
    head = await branch_head(path, branch_name)

    def read():
        try:
            webide.path(filename)
            info = webide.entry(path, head, filename)
            if not info:
                raise APIError(404, "not_found", "File not found.")
            content = webide._blob(path, info).encode("utf-8")
            return {"path": filename, "sha": info["oid"], "commit_sha": head, "branch": branch_name,
                    "encoding": "base64", "content": base64.b64encode(content).decode("ascii"),
                    "size": len(content)}
        except webide.IDEError:
            raise APIError(422, "unsupported_file", "Only regular UTF-8 text files up to 1 MiB are supported.") from None
    return await asyncio.to_thread(read)


async def authorize(api):
    """Reauthorize before looking up cached results, including after role changes."""
    if "write" not in api.identity["scopes"]:
        raise APIError(403, "insufficient_scope", "Token requires write scope.")
    if api.path == "/api/v1/user/repos" and api.request.method == "POST":
        owner = api.identity["username"]
        if (owner == api.app.FLAT_OWNER_UI or not re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", owner)
                or not api.app._safe_seg(owner) or owner in (".", ".git")):
            raise APIError(403, "forbidden", "This account cannot create an owner-namespace repository.")
        return owner, None, None, "create_repository"
    match = re.fullmatch(r"/api/v1/repos/([^/]+)/([^/]+)(?:/(.*))?", api.path)
    if not match:
        raise APIError(405, "method_not_allowed", "Mutation endpoint is not supported.")
    owner, repo, tail = unquote(match[1]), unquote(match[2]), match[3] or ""
    path = await api.repository(owner, repo)
    if tail == "ci/settings":
        from . import settings
        settings.authorize(api)
    return owner, repo, path, tail


async def route(api, target):
    owner, repo, path, tail = target
    doc, method = api.document, api.request.method
    if tail == "create_repository":
        fields(doc, {"name", "default_branch"}, {"name"})
        repo = name(doc["name"])
        lock = api.handler.server.push_locks.setdefault((owner, repo), asyncio.Lock())
        async with lock:
            return 201, await create_repository(api, owner, repo, doc)
    lock = api.handler.server.push_locks.setdefault((owner, repo), asyncio.Lock())
    async with lock:
        # Validate the current path again after waiting for the repository lock.
        path = await api.repository(owner, repo)
        if tail == "ci/settings":
            from . import settings
            return await settings.update(api, owner, repo)
        if tail == "discussions" or tail.startswith("discussions/"):
            from . import discussions
            return await asyncio.to_thread(discussions.mutate, owner, repo, tail, method, doc, api.identity)
        if method == "POST" and (tail == "ci/runs" or re.fullmatch(
                r"ci/runs/[0-9]{1,18}/(cancel|rerun)", tail)):
            from . import ci_operations
            return await ci_operations.mutate(api, owner, repo, path, tail)
        if tail == "branches" and method == "POST":
            fields(doc, {"name", "sha"}, {"name", "sha"})
            value = await branch(path, doc["name"])
            await unprotected(api, owner, repo, value)
            source = await git.resolve(path, sha(doc, "sha"))
            before = await api.handler.server._branch_refs(owner, repo)
            code, _ = await git.git(path, "update-ref", "refs/heads/" + value, source, "0" * len(source))
            if code:
                raise APIError(409, "branch_conflict", "Branch already exists or its creation was rejected.")
            result = {"name": value, "commit": {"sha": source}}
            return 201, await notify(api, owner, repo, before, result)
        if tail.startswith("branches/") and method == "DELETE":
            fields(doc, {"expected_head"}, {"expected_head"})
            value = await branch(path, unquote(tail[len("branches/"):]))
            await unprotected(api, owner, repo, value)
            if value == await git.default_branch(path):
                raise APIError(403, "protected_branch", "The default branch cannot be deleted.")
            expected = sha(doc, "expected_head")
            if await branch_head(path, value) != expected:
                raise APIError(409, "revision_conflict", "Branch changed. Fetch its current SHA.")
            await not_checked_out(path, value)
            code, _ = await git.git(path, "update-ref", "-d", "refs/heads/" + value, expected)
            if code:
                raise APIError(409, "revision_conflict", "Branch changed or deletion was rejected.")
            return 200, {"deleted": True, "name": value}
        if tail.startswith("contents/") and method in ("PUT", "DELETE"):
            return await change_file(api, owner, repo, path, unquote(tail[len("contents/"):]), doc, method)
        merge = re.fullmatch(r"pulls/([0-9]{1,18})/merge", tail)
        if merge and method == "PUT":
            return await merge_pull(api, owner, repo, path, int(merge[1]), doc)
        entity = re.fullmatch(r"(issues|pulls)(?:/([0-9]{1,18})(?:/comments(?:/([0-9]{1,18}))?)?)?", tail)
        if entity:
            kind, identity, comment_id = entity.groups()
            if identity is None and method == "POST":
                return await create_entity(api, owner, repo, path, kind, doc)
            if identity is not None:
                identity = int(identity)
                read = data.issues if kind == "issues" else data.pulls
                parents = await asyncio.to_thread(read, owner, repo, "all", 1, 0, identity)
                if not parents:
                    raise APIError(404, "not_found", "Resource not found.")
                if tail.endswith("/comments") and method == "POST":
                    fields(doc, {"body"}, {"body"})
                    body = text(doc, "body")
                    if kind == "pulls" and parents[0]["state"] != "open":
                        raise APIError(409, "state_conflict", "Comments require an open pull request.")
                    add = database.db_issue_comment_add if kind == "issues" else database.db_pr_comment_add
                    comment = await asyncio.to_thread(add, identity, api.identity["user_id"], body)
                    result = await asyncio.to_thread(data.comments, kind, owner, repo, identity, 1, 0, comment)
                    return 201, result[0]
                if (comment_id and method in ("PATCH", "DELETE")) or (
                        not comment_id and not tail.endswith("/comments") and method == "PATCH"):
                    if kind == "pulls" and doc.get("state") == "open":
                        await branch_head(path, parents[0]["head"]["ref"])
                        await branch_head(path, parents[0]["base"]["ref"])
                    result = await asyncio.to_thread(
                        text_mutations.edit, kind, owner, repo, identity, doc, api.identity,
                        comment_id=int(comment_id) if comment_id else None, delete=method == "DELETE")
                    if kind == "pulls" and not comment_id and parents[0]["state"] == "closed" and result["state"] == "open":
                        await queue_pull(api, owner, repo, path, result, "pull_request_reopened")
                    return 200, result
        raise APIError(405, "method_not_allowed", "This mutation is not supported at this endpoint.")


async def create_repository(api, owner, repo, doc):
    root = Path(api.handler.server.context.config.git_project_root).absolute()
    directory = root / owner
    # Do not create repositories underneath an existing flat worktree or aliases.
    if (directory.is_symlink() or directory.is_junction()
            or api.app._is_git_dir(directory) or api.app._is_worktree_repo_dir(directory)):
        raise APIError(409, "repository_conflict", "Owner namespace conflicts with an existing repository or alias.")
    directory.mkdir(exist_ok=True)
    target = directory / (repo + ".git")
    if (directory / repo).exists() or (directory / repo).is_symlink():
        raise APIError(409, "repository_conflict", "Repository already exists.")
    default = doc.get("default_branch", "main")
    await branch(str(directory), default)
    try:
        target.mkdir()
    except FileExistsError:
        raise APIError(409, "repository_conflict", "Repository already exists.") from None
    code, _ = await git.git(str(target), "init", "--bare", "--initial-branch=" + default, str(target))
    if code:
        raise APIError(503, "repository_unavailable", "Repository initialization failed. Inspect the owner namespace.")
    code, _ = await git.git(str(target), "config", "http.receivepack", "true")
    if code:
        raise APIError(503, "repository_unavailable", "Repository exists but push configuration failed.")
    return {**api.repo_object(owner, repo), "default_branch": default}


async def create_entity(api, owner, repo, path, kind, doc):
    required = {"title"} | ({"head", "base"} if kind == "pulls" else set())
    fields(doc, required | {"body"}, required)
    title = text(doc, "title", maximum=256)
    body = text(doc, "body", empty=True) if "body" in doc else ""
    if kind == "issues":
        identity = await asyncio.to_thread(database.db_issue_create, owner, repo, title, body, api.identity["user_id"])
        result = await asyncio.to_thread(data.issues, owner, repo, "all", 1, 0, identity)
    else:
        head, base = await branch(path, doc["head"]), await branch(path, doc["base"])
        if head == base:
            raise APIError(422, "validation_error", "Head and base branches must differ.")
        await branch_head(path, head)
        await branch_head(path, base)
        identity = await asyncio.to_thread(
            database.db_pr_create, owner, repo, title, body, head, base, api.identity["user_id"])
        result = await asyncio.to_thread(data.pulls, owner, repo, "all", 1, 0, identity)
        await queue_pull(api, owner, repo, path, result[0], "pull_request")
    return 201, result[0]


async def queue_pull(api, owner, repo, path, result, event):
    try:
        head, base = result["head"]["ref"], result["base"]["ref"]
        source, target = await branch_head(path, head), await branch_head(path, base)
        await api.handler.server.ci_manager.enqueue(owner, repo, event, base, target, {
            "pr_number": result["id"], "base_branch": base, "head_branch": head,
            "base_commit": target, "head_commit": source})
    except Exception as exc:
        api.log_failure(exc)
        result["warnings"] = ["Pull request changed, but CI scheduling failed. Inspect CI before proceeding."]


async def not_checked_out(path, value):
    code, output = await git.git(path, "worktree", "list", "--porcelain")
    if code or ("branch refs/heads/" + value + "\n").encode() in output:
        raise APIError(409, "checked_out_branch", "This branch is checked out on the server or its worktree state is unavailable.")


async def change_file(api, owner, repo, path, filename, doc, method):
    required = {"branch", "expected_head", "message"} | ({"content"} if method == "PUT" else set())
    fields(doc, required, required)
    value = await branch(path, doc["branch"])
    expected, message = sha(doc, "expected_head"), text(doc, "message", maximum=4000)
    await unprotected(api, owner, repo, value)
    if await branch_head(path, value) != expected:
        raise APIError(409, "revision_conflict", "Branch changed. Fetch its current SHA.")
    try:
        webide.path(filename)
    except webide.IDEError:
        raise APIError(422, "validation_error", "Invalid repository file path.") from None
    content = None
    if method == "PUT":
        encoded = text(doc, "content", maximum=1400000, empty=True)
        try:
            raw = base64.b64decode(encoded, validate=True)
            content = raw.decode("utf-8")
        except (ValueError, binascii.Error, UnicodeError):
            raise APIError(422, "validation_error", "Content must be base64-encoded UTF-8 text.") from None
        if len(raw) > webide.MAX_FILE or "\0" in content:
            raise APIError(422, "unsupported_file", "Only UTF-8 text up to 1 MiB is supported.")
    old = await asyncio.to_thread(webide.entry, path, expected, filename)
    before = await api.handler.server._branch_refs(owner, repo)
    try:
        commit = await asyncio.to_thread(
            webide.commit_changes, path, value, expected, {filename: content}, message, api.identity["username"])
    except webide.IDEError:
        raise APIError(409, "git_rejected", "File change was rejected. Check the branch, file type, changes and receive hooks.") from None
    result = {"commit": {"sha": commit}, "path": filename, "deleted": method == "DELETE"}
    return (201 if method == "PUT" and old is None else 200), await notify(api, owner, repo, before, result)


async def merge_pull(api, owner, repo, path, identity, doc):
    fields(doc, {"sha", "expected_base_sha"}, {"sha", "expected_base_sha"})
    expected_source, expected_target = sha(doc, "sha"), sha(doc, "expected_base_sha")
    rows = await asyncio.to_thread(data.pulls, owner, repo, "all", 1, 0, identity)
    if not rows:
        raise APIError(404, "not_found", "Pull request not found.")
    pull = rows[0]
    if pull["state"] != "open":
        raise APIError(409, "state_conflict", "Pull request is not open.")
    head, base = pull["head"]["ref"], pull["base"]["ref"]
    source, target = await branch_head(path, head), await branch_head(path, base)
    if (source, target) != (expected_source, expected_target):
        raise APIError(409, "revision_conflict", "Pull request branches changed. Refresh both SHAs.")
    await not_checked_out(path, base)
    manager = api.handler.server.ci_manager
    policy = await manager.config(owner, repo)
    if policy["require_ci"]:
        check = await manager.merge_check(owner, repo, identity, target, source, base)
        if not check or check[1] != "success":
            raise APIError(409, "ci_required", "Successful CI is required for the current source and target commits.")
    before = await api.handler.server._branch_refs(owner, repo)
    # Shared with the web UI: ff-only ancestry and both refs are checked in one
    # Git transaction, so external pushes cannot invalidate a successful CI gate.
    ok, _message, merged_sha = await api.app._git_ff_merge(path, base, head, expected=(target, source))
    if not ok or not merged_sha:
        raise APIError(409, "merge_conflict", "Only fast-forward merges are supported; branches may also have changed or the reference transaction was rejected.")
    await asyncio.to_thread(database.db_pr_mark_merged, identity, "ff-only", source)
    result = {"merged": True, "sha": source, "merge_method": "ff-only"}
    await notify(api, owner, repo, before, result)
    try:
        await manager.enqueue(owner, repo, "pull_request_merged", base, source, {
            "pr_number": identity, "base_branch": base, "head_branch": head, "base_commit": source})
    except Exception as exc:
        api.log_failure(exc)
        result["warnings"] = ["Merge succeeded, but merged-event CI scheduling failed."]
    return 200, result
