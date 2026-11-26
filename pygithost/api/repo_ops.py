"""Repository actions the web UI offers that the REST API did not cover yet.

* ``DELETE /repos/{owner}/{repo}`` — archive (delete) a repository (administrators).
* ``POST /repos/{owner}/{repo}/commits`` — commit several file changes at once (Web IDE).
* ``GET|PUT /repos/{owner}/{repo}/ci/variables`` — repository CI environment variables.
* ``GET /repos/{owner}/{repo}/pulls/{id}/conflicts`` and
  ``POST /repos/{owner}/{repo}/pulls/{id}/conflicts/resolution`` — web conflict resolution.

Each endpoint delegates to the same code as its web page.
"""

from __future__ import annotations

import asyncio
import base64
import re
from collections.abc import Mapping
from typing import Any, cast

from .. import database, pr_resolver, webide
from ..ci import protected_branch
from .errors import APIError
from .types import APIContext
from .validation import fields, text

_CONFLICTS = re.compile(r"pulls/([0-9]{1,18})/conflicts")
_RESOLUTION = re.compile(r"pulls/([0-9]{1,18})/conflicts/resolution")


def handles_mutation(tail: str, method: str) -> bool:
    return (
        (tail == "commits" and method == "POST")
        or (tail == "ci/variables" and method == "PUT")
        or (method == "POST" and _RESOLUTION.fullmatch(tail) is not None)
    )


def handles_read(tail: str) -> bool:
    return tail == "ci/variables" or _CONFLICTS.fullmatch(tail) is not None


async def mutate(
    api: APIContext, owner: str, repo: str, path: str, tail: str
) -> tuple[int, Mapping[str, object]]:
    if tail == "commits":
        return await commit_files(api, owner, repo, path)
    if tail == "ci/variables":
        return await update_variables(api, owner, repo)
    match = _RESOLUTION.fullmatch(tail)
    assert match
    return await resolve_conflicts(api, owner, repo, int(match[1]))


async def read(api: APIContext, owner: str, repo: str, path: str, tail: str) -> object:
    api.parameters()
    if tail == "ci/variables":
        return await variables(api, owner, repo)
    match = _CONFLICTS.fullmatch(tail)
    assert match
    return await conflicts(api, owner, repo, int(match[1]))


# ---------------------------------------------------------------- repository deletion


def authorize_deletion(api: APIContext) -> None:
    if not api.identity["is_admin"]:
        raise APIError(403, "forbidden", "Administrator required to delete repositories.")
    if api.identity.get("repository") is not None:
        raise APIError(403, "forbidden", "A repository-bound token cannot delete repositories.")


async def delete_repository(
    api: APIContext, owner: str, repo: str
) -> tuple[int, Mapping[str, object]]:
    from ..application import RepositoryDeleteError

    await api.repository(owner, repo)
    doc = api.document
    fields(doc, {"confirm"}, {"confirm"})
    full_name = f"{owner}/{repo}"
    if doc["confirm"] != full_name:
        raise APIError(422, "validation_error", f"confirm must be exactly {full_name}.")
    try:
        destination = await api.handler._archive_repository(owner, repo)
    except RepositoryDeleteError as exc:
        code = {404: "not_found", 409: "conflict"}.get(exc.status, "unavailable")
        raise APIError(exc.status, code, exc.message) from None
    return 200, {"deleted": True, "full_name": full_name, "archive": str(destination)}


# ---------------------------------------------------------------- multi-file commits


def _decode(value: object, filename: str) -> str:
    if not isinstance(value, str) or len(value) > webide.MAX_FILE * 2:
        raise APIError(422, "validation_error", f"Invalid content for {filename}.")
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except ValueError:
        raise APIError(
            422, "validation_error", f"Content for {filename} must be base64 UTF-8 text."
        ) from None


async def commit_files(
    api: APIContext, owner: str, repo: str, path: str
) -> tuple[int, Mapping[str, object]]:
    """Same transaction as the Web IDE commit button: protected branches, one commit."""
    doc = api.document
    required = {"branch", "expected_head", "message", "changes"}
    fields(doc, required, required)
    branch = doc["branch"]
    expected = doc["expected_head"]
    message = text(doc, "message", maximum=4000)
    raw = doc["changes"]
    if not isinstance(branch, str) or not isinstance(expected, str):
        raise APIError(422, "validation_error", "branch and expected_head must be strings.")
    if not isinstance(raw, dict) or not 1 <= len(raw) <= 100:
        raise APIError(422, "validation_error", "changes must map 1–100 paths to content or null.")
    changes: dict[str, str | None] = {
        str(name): (None if value is None else _decode(value, str(name)))
        for name, value in raw.items()
    }
    server = api.handler.server
    lock = server.push_locks.setdefault((owner, repo), asyncio.Lock())
    async with lock:
        policy = await server.ci_manager.config(owner, repo)
        if policy["block_direct_pushes"] and protected_branch(policy, branch):
            raise APIError(
                403,
                "protected_branch",
                "Direct commits to this protected branch are blocked. Open a pull request.",
            )
        before = await server._branch_refs(owner, repo)
        try:
            commit = await asyncio.to_thread(
                webide.commit_changes,
                path,
                branch,
                expected,
                changes,
                message,
                api.identity["username"],
            )
        except webide.IDEError as exc:
            status = 409 if "changed" in str(exc) else 422
            raise APIError(status, "commit_rejected", str(exc)) from None
        result: dict[str, object] = {"commit": {"sha": commit}, "branch": branch}
        try:
            await server._queue_push_changes(owner, repo, before)
        except Exception:
            result["warnings"] = ["Committed, but CI scheduling failed."]
    return 201, result


# ---------------------------------------------------------------- CI variables


def _require_admin(api: APIContext) -> None:
    if not api.identity["is_admin"]:
        raise APIError(403, "forbidden", "Administrator required for CI variables.")


async def variables(api: APIContext, owner: str, repo: str) -> object:
    _require_admin(api)
    from ..ci_preferences import DEFAULT_ENV_SCOPE

    _global, values = await asyncio.to_thread(database.db_ci_preferences_get, owner, repo)
    scopes = cast(dict[str, dict[str, str]], values.get("env_scopes") or {})
    result: list[dict[str, object]] = []
    for name, value in sorted(cast(dict[str, str], values.get("env") or {}).items()):
        result.append(
            {
                "name": name,
                "value": value,
                "pipeline": None,
                "scope": scopes.get("", {}).get(name, DEFAULT_ENV_SCOPE),
            }
        )
    pipeline_env = cast(dict[str, dict[str, str]], values.get("pipeline_env") or {})
    for pipeline, env in sorted(pipeline_env.items()):
        for name, value in sorted(env.items()):
            result.append(
                {
                    "name": name,
                    "value": value,
                    "pipeline": pipeline,
                    "scope": scopes.get(pipeline, {}).get(name, DEFAULT_ENV_SCOPE),
                }
            )
    return {"variables": result}


async def update_variables(
    api: APIContext, owner: str, repo: str
) -> tuple[int, Mapping[str, object]]:
    """Replace all repository variables, validated exactly like the settings page."""
    _require_admin(api)
    from ..settings_pages import parse_preferences

    doc = api.document
    fields(doc, {"variables"}, {"variables"})
    items = doc["variables"]
    if not isinstance(items, list) or len(items) > 256:
        raise APIError(422, "validation_error", "variables must be an array of at most 256.")
    form: dict[str, str] = {"action": "ci_environment", "env_count": str(len(items))}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise APIError(422, "validation_error", "Each variable must be an object.")
        fields(item, {"name", "value", "pipeline", "scope"}, {"name", "value"})
        name, value = item["name"], item["value"]
        pipeline, scope = item.get("pipeline"), item.get("scope", "ordinary")
        if (
            not isinstance(name, str)
            or not isinstance(value, str)
            or not (pipeline is None or isinstance(pipeline, str))
            or not isinstance(scope, str)
        ):
            raise APIError(422, "validation_error", "Invalid variable.")
        form[f"env_name_{index}"] = name
        form[f"env_value_{index}"] = value
        form[f"env_pipeline_{index}"] = pipeline or ""
        form[f"env_access_{index}"] = scope
    server = api.handler.server
    try:
        async with server.settings_lock:
            _global, values = await asyncio.to_thread(database.db_ci_preferences_get, owner, repo)
            values = parse_preferences(form, values, repository=True)
            await asyncio.to_thread(database.db_ci_preferences_set, values, owner, repo)
    except ValueError as exc:
        raise APIError(422, "validation_error", str(exc)) from None
    return 200, cast(Mapping[str, object], await variables(api, owner, repo))


# ---------------------------------------------------------------- conflict resolution


async def _state(api: APIContext, owner: str, repo: str, pr_id: int) -> tuple[str, ...]:
    state = await api.handler._ui_pull_resolve_poststate(owner, repo, pr_id)
    if not state:
        raise APIError(404, "not_found", "Open pull request not found.")
    return cast(tuple[str, ...], state)


async def conflicts(api: APIContext, owner: str, repo: str, pr_id: int) -> object:
    src_branch, tgt_branch, src, tgt, merge_base, repo_git = await _state(api, owner, repo, pr_id)
    found = await asyncio.to_thread(pr_resolver.list_conflicts, repo_git, merge_base, src, tgt)
    files: list[dict[str, Any]] = []
    for item in found[: pr_resolver.MAX_CONFLICT_FILES]:
        data, kind = await asyncio.to_thread(
            pr_resolver.preview, repo_git, item, src_branch, tgt_branch
        )
        files.append(
            {
                "path": item["path"],
                "kind": kind,
                "preview": base64.b64encode(data).decode("ascii") if data is not None else None,
            }
        )
    return {
        "head": {"ref": src_branch, "sha": src},
        "base": {"ref": tgt_branch, "sha": tgt},
        "merge_base": merge_base,
        "files": files,
    }


async def resolve_conflicts(
    api: APIContext, owner: str, repo: str, pr_id: int
) -> tuple[int, Mapping[str, object]]:
    """Merge the base into the head with the given resolutions (the web resolve page)."""
    doc = api.document
    fields(doc, {"files", "message", "expected_head", "expected_base"}, {"files"})
    items = doc["files"]
    if not isinstance(items, list) or not 1 <= len(items) <= pr_resolver.MAX_CONFLICT_FILES:
        raise APIError(
            422,
            "validation_error",
            f"files must list 1–{pr_resolver.MAX_CONFLICT_FILES} resolved files.",
        )
    resolutions: list[tuple[str, str, bool]] = []
    for item in items:
        if not isinstance(item, dict):
            raise APIError(422, "validation_error", "Each file must be an object.")
        fields(item, {"path", "content", "delete"}, {"path"})
        name = item["path"]
        if not isinstance(name, str) or not name:
            raise APIError(422, "validation_error", "Each file needs a path.")
        delete = item.get("delete", False)
        if type(delete) is not bool:
            raise APIError(422, "validation_error", "delete must be true or false.")
        content = "" if delete else _decode(item.get("content"), name)
        resolutions.append((name, content, delete))
    message = doc.get("message")
    if message is not None and (not isinstance(message, str) or len(message) > 4000):
        raise APIError(422, "validation_error", "Invalid message.")
    server = api.handler.server
    lock = server.push_locks.setdefault((owner, repo), asyncio.Lock())
    async with lock:
        src_branch, tgt_branch, src, tgt, merge_base, repo_git = await _state(
            api, owner, repo, pr_id
        )
        if doc.get("expected_head") not in (None, src) or doc.get("expected_base") not in (
            None,
            tgt,
        ):
            raise APIError(409, "stale", "The branches changed; fetch the conflicts again.")
        blocked = await api.handler._pull_resolution_policy_error(owner, repo, src_branch)
        if blocked:
            raise APIError(blocked[0], "protected_branch", blocked[1])
        try:
            commit = await asyncio.to_thread(
                pr_resolver.apply_resolution,
                repo_git,
                merge_base,
                src,
                tgt,
                src_branch,
                resolutions,
                message or f"Merge branch '{tgt_branch}' into {src_branch}",
                api.identity["username"],
            )
        except pr_resolver.ResolverError as exc:
            raise APIError(422, "resolution_rejected", str(exc)) from None
        result: dict[str, object] = {"commit": {"sha": commit}, "head": src_branch}
        warnings = []
        try:
            await asyncio.to_thread(
                database.db_pr_comment_add,
                pr_id,
                api.identity["user_id"],
                f"Resolved merge conflicts with the target branch via the API ({len(resolutions)} file(s) changed).",
            )
        except Exception:
            warnings.append("Committed, but the conversation note could not be saved.")
        try:
            await server.ci_manager.enqueue(
                owner,
                repo,
                "pull_request",
                tgt_branch,
                tgt,
                {
                    "pr_number": pr_id,
                    "base_branch": tgt_branch,
                    "head_branch": src_branch,
                    "base_commit": tgt,
                    "head_commit": commit,
                },
            )
        except Exception:
            warnings.append("Committed, but CI scheduling failed.")
        if warnings:
            result["warnings"] = warnings
    return 201, result
