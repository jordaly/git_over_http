"""Pull request operations shared by the web UI and the REST API.

Each operation checks permissions, applies repository rules and records timeline
events in one place, so a UI form and its API endpoint always behave the same.
Errors are raised as :class:`PullError` with an HTTP status, a stable code and a
user-presentable message.
"""

from __future__ import annotations

import asyncio
import fnmatch
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol, TypedDict, cast

from . import database, merging, pull_store
from .ci import MERGE_METHODS
from .diffview import extract_suggestion
from .pull_store import Review, Side, Thread

ReviewEvent = Literal["APPROVE", "REQUEST_CHANGES", "COMMENT"]
REVIEW_EVENTS: dict[str, pull_store.ReviewState] = {
    "APPROVE": "approved",
    "REQUEST_CHANGES": "changes_requested",
    "COMMENT": "commented",
}
MAX_BODY = 65536
# When several rules block a merge, the API reports the first of these codes.
BLOCKER_PRIORITY = (
    "policy_unavailable",
    "draft",
    "ci_required",
    "approvals_required",
    "changes_requested",
    "unresolved_conversations",
    "missing_branch",
    "merge_conflict",
)
MAX_TITLE = 256


class PullError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Actor:
    """Who performs an operation.

    ``known`` is False for the anonymous local user of a server running without
    web sign-in; such users can review but never count as a distinct reviewer.
    ``viewer`` keys per-person UI state (viewed files): ``u:<id>`` or ``ip:<addr>``.
    """

    user_id: int | None
    username: str | None
    is_admin: bool
    can_write: bool
    known: bool
    viewer: str


class ServerLike(Protocol):
    push_locks: dict[tuple[str, str], asyncio.Lock]

    @property
    def ci_manager(self) -> Any: ...

    async def _branch_refs(self, owner: str, repo: str) -> dict[str, str] | None: ...

    async def _queue_push_changes(
        self, owner: str, repo: str, before_refs: dict[str, str] | None
    ) -> None: ...


@dataclass(frozen=True)
class Context:
    server: ServerLike
    owner: str
    repo: str
    repo_git: str
    actor: Actor


class PullRequest(TypedDict):
    id: int
    owner: str
    repo: str
    title: str
    body: str
    head: str
    base: str
    author_user_id: int | None
    author: str | None
    state: str
    draft: bool
    created_at: str
    closed_at: str | None
    merged_at: str | None
    merge_method: str | None
    merge_commit: str | None
    head_sha: str | None
    base_sha: str | None
    merge_base: str | None
    head_deleted_sha: str | None


async def _thread(func: Any, /, *args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(func, *args, **kwargs)


def _text(value: object, field: str, *, limit: int = MAX_BODY, required: bool = True) -> str:
    if not isinstance(value, str) or "\0" in value or len(value) > limit:
        raise PullError(422, "validation_error", f"Invalid {field}.")
    if required and not value.strip():
        raise PullError(422, "validation_error", f"{field.capitalize()} cannot be empty.")
    return value


def _branch(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("-")
        or len(value) > 256
        or not re.fullmatch(r"[A-Za-z0-9._/-]+", value)
        or ".." in value
        or value.endswith((".lock", "/"))
    ):
        raise PullError(422, "validation_error", "Invalid branch name.")
    return value


# ---------------------------------------------------------------- loading


async def load(ctx: Context, pr_id: int) -> PullRequest:
    row = await _thread(database.db_pr_get, int(pr_id))
    if not row or row[1] != ctx.owner or row[2] != ctx.repo:
        raise PullError(404, "not_found", "Pull request not found.")
    draft, deleted = await _thread(pull_store.pr_flags, int(pr_id))
    author = None
    if row[7] is not None:
        user = await _thread(database.db_get_user_by_id, row[7])
        author = user[1] if user else None
    head_sha = await _thread(merging.resolve, ctx.repo_git, "refs/heads/" + row[5])
    base_sha = await _thread(merging.resolve, ctx.repo_git, "refs/heads/" + row[6])
    merge_base = (
        await _thread(merging.merge_base, ctx.repo_git, base_sha, head_sha)
        if head_sha and base_sha
        else None
    )
    return {
        "id": row[0],
        "owner": row[1],
        "repo": row[2],
        "title": row[3],
        "body": row[4] or "",
        "head": row[5],
        "base": row[6],
        "author_user_id": row[7],
        "author": author,
        "state": row[8],
        "draft": draft,
        "created_at": row[9],
        "closed_at": row[10],
        "merged_at": row[11],
        "merge_method": row[12],
        "merge_commit": row[13],
        "head_sha": head_sha,
        "base_sha": base_sha,
        "merge_base": merge_base,
        "head_deleted_sha": deleted,
    }


def _require_write(ctx: Context, what: str) -> None:
    if not ctx.actor.can_write:
        raise PullError(403, "insufficient_scope", f"Write access is required to {what}.")


def _require_open(pr: PullRequest) -> None:
    if pr["state"] != "open":
        raise PullError(409, "not_open", "The pull request is not open.")


def _is_pr_author(ctx: Context, pr: PullRequest) -> bool:
    return ctx.actor.known and pr["author_user_id"] == ctx.actor.user_id


async def _policy(ctx: Context) -> Mapping[str, Any]:
    policy = cast(Mapping[str, Any], await ctx.server.ci_manager.config(ctx.owner, ctx.repo))
    return policy


def _protected(policy: Mapping[str, Any], branch: str) -> bool:
    return any(
        fnmatch.fnmatchcase(branch, pattern.strip())
        for pattern in str(policy.get("protected_branches", "")).splitlines()
        if pattern.strip()
    )


def _event(ctx: Context, pr_id: int, kind: str, data: Mapping[str, Any] | None = None) -> None:
    pull_store.add_event(pr_id, ctx.actor.user_id if ctx.actor.known else None, kind, data)


# ---------------------------------------------------------------- merge status


class MergeStatus(TypedDict):
    state: str
    allowed_methods: list[str]
    default_method: str
    mergeable: str
    conflicts: list[str]
    fast_forward: bool
    rebase_clean: bool | None
    protected: bool
    required_approvals: int
    approvals: int
    approved_by: list[str]
    changes_requested_by: list[str]
    unresolved_threads: int
    require_conversation_resolution: bool
    block_on_changes_requested: bool
    ci: dict[str, Any]
    draft: bool
    blocked_reasons: list[str]
    blocked_codes: list[str]
    can_merge: bool


async def merge_status(ctx: Context, pr: PullRequest) -> MergeStatus:
    policy = await _policy(ctx)
    methods = [m for m in policy.get("merge_methods", list(MERGE_METHODS)) if m in MERGE_METHODS]
    protected = _protected(policy, pr["base"])
    reasons: list[str] = []
    codes: list[str] = []

    def block(code: str, message: str) -> None:
        codes.append(code)
        reasons.append(message)

    mergeable = "unknown"
    conflicts: list[str] = []
    fast_forward = False
    rebase_clean: bool | None = None
    if pr["state"] != "open":
        mergeable = pr["state"]
    elif not pr["head_sha"] or not pr["base_sha"]:
        mergeable = "missing_branch"
        block("missing_branch", "The head or base branch no longer exists.")
    else:
        info = await _thread(merging.mergeability, ctx.repo_git, pr["base_sha"], pr["head_sha"])
        fast_forward = bool(info.get("fast_forward"))
        rebase_clean = info.get("rebase_clean")
        conflicts = list(info.get("conflicts") or [])
        if info.get("up_to_date"):
            # Nothing left to merge: completing the PR just records it as merged.
            mergeable = "up_to_date"
        elif info.get("clean"):
            mergeable = "clean"
        else:
            mergeable = "conflict"
            block("merge_conflict", "This branch has conflicts that must be resolved.")
    states = await _thread(pull_store.reviewer_states, pr["id"])
    approved_by: list[str] = []
    changes_by: list[str] = []
    approvals = 0
    for reviewer, review in states.items():
        if reviewer is not None and reviewer == pr["author_user_id"]:
            continue
        name = review["author"] or "anonymous"
        if review["state"] == "approved":
            if (
                protected
                and policy.get("dismiss_stale_approvals")
                and review["commit_sha"] != pr["head_sha"]
            ):
                continue
            approved_by.append(name)
            approvals += 1
        elif review["state"] == "changes_requested":
            changes_by.append(name)
    unresolved = await _thread(pull_store.unresolved_thread_count, pr["id"])
    required = int(policy.get("required_approvals", 0)) if protected else 0
    block_changes = bool(policy.get("block_on_changes_requested")) and protected
    require_resolution = bool(policy.get("require_conversation_resolution")) and protected
    if pr["state"] == "open":
        if pr["draft"]:
            block("draft", "Draft pull requests cannot be merged.")
        if approvals < required:
            block(
                "approvals_required",
                f"At least {required} approving review{'s' if required != 1 else ''} "
                f"{'are' if required != 1 else 'is'} required ({approvals} so far).",
            )
        if block_changes and changes_by:
            block(
                "changes_requested",
                "Changes were requested by " + ", ".join(sorted(changes_by)) + ".",
            )
        if require_resolution and unresolved:
            block(
                "unresolved_conversations",
                f"{unresolved} conversation{'s' if unresolved != 1 else ''} must be resolved.",
            )
    ci: dict[str, Any] = {"required": bool(policy.get("require_ci")), "state": None, "run_id": None}
    if pr["state"] == "open" and pr["head_sha"] and pr["base_sha"]:
        check = await ctx.server.ci_manager.merge_check(
            ctx.owner, ctx.repo, pr["id"], pr["base_sha"], pr["head_sha"], pr["base"]
        )
        if check:
            ci["run_id"], ci["state"] = check[0], check[1]
        if ci["required"] and ci["state"] != "success":
            block("ci_required", "Successful CI is required for the current head and base commits.")
    if policy.get("_configuration_git_error") and pr["state"] == "open":
        block("policy_unavailable", "Repository policy cannot be verified.")
    return {
        "state": pr["state"],
        "allowed_methods": methods,
        "default_method": methods[0] if methods else "merge",
        "mergeable": mergeable,
        "conflicts": conflicts,
        "fast_forward": fast_forward,
        "rebase_clean": rebase_clean,
        "protected": protected,
        "required_approvals": required,
        "approvals": approvals,
        "approved_by": sorted(approved_by),
        "changes_requested_by": sorted(changes_by),
        "unresolved_threads": unresolved,
        "require_conversation_resolution": require_resolution,
        "block_on_changes_requested": block_changes,
        "ci": ci,
        "draft": pr["draft"],
        "blocked_reasons": reasons,
        "blocked_codes": codes,
        "can_merge": pr["state"] == "open" and not reasons and bool(methods),
    }


# ---------------------------------------------------------------- merging


def _merge_messages(pr: PullRequest, method: str, commits: Sequence[str]) -> tuple[str, str]:
    if method == "squash":
        return f"{pr['title']} (#{pr['id']})", "\n".join(f"* {subject}" for subject in commits)
    return f"Merge pull request #{pr['id']} from {pr['head']}", pr["title"]


async def _commit_subjects(repo_git: str, base: str, head: str) -> list[str]:
    process = await asyncio.create_subprocess_exec(
        "git",
        "--git-dir=" + repo_git,
        "log",
        "--reverse",
        "--format=%s",
        "--end-of-options",
        f"{base}..{head}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    out, _ = await process.communicate()
    return out.decode("utf-8", "replace").splitlines()[:200]


async def merge(
    ctx: Context,
    pr_id: int,
    *,
    method: str | None = None,
    expected_head: str | None = None,
    expected_base: str | None = None,
    title: str | None = None,
    message: str | None = None,
    delete_branch: bool = False,
) -> dict[str, Any]:
    _require_write(ctx, "merge pull requests")
    lock = ctx.server.push_locks.setdefault((ctx.owner, ctx.repo), asyncio.Lock())
    async with lock:
        pr = await load(ctx, pr_id)
        _require_open(pr)
        status = await merge_status(ctx, pr)
        chosen = method or status["default_method"]
        if chosen not in status["allowed_methods"]:
            raise PullError(
                422,
                "method_not_allowed",
                f"Merge method '{chosen}' is not allowed in this repository "
                f"(allowed: {', '.join(status['allowed_methods'])}).",
            )
        if status["blocked_reasons"]:
            order = {code: index for index, code in enumerate(BLOCKER_PRIORITY)}
            first = min(status["blocked_codes"], key=lambda code: order.get(code, len(order)))
            raise PullError(409, first, "Merge blocked: " + " ".join(status["blocked_reasons"]))
        head, base = pr["head_sha"], pr["base_sha"]
        assert head and base
        if expected_head and expected_head != head:
            raise PullError(409, "stale", "The head branch changed; review the new commits.")
        if expected_base and expected_base != base:
            raise PullError(409, "stale", "The base branch changed; refresh and try again.")
        if status["mergeable"] == "up_to_date":
            await _thread(database.db_pr_mark_merged, pr["id"], chosen, base)
            await _thread(
                _event, ctx, pr["id"], "merged", {"method": chosen, "sha": base, "base": pr["base"]}
            )
            return {"merged": True, "sha": base, "merge_method": chosen, "up_to_date": True}
        subjects = await _commit_subjects(ctx.repo_git, pr["merge_base"] or base, head)
        default_title, default_message = _merge_messages(pr, chosen, subjects)
        commit_title = _text(title, "commit title", limit=MAX_TITLE) if title else default_title
        commit_message = (
            _text(message, "commit message", limit=4000, required=False)
            if message is not None
            else default_message
        )
        squash_author = None
        if chosen == "squash" and pr["author"]:
            squash_author = merging.identity_for(pr["author"])
        before_refs = await ctx.server._branch_refs(ctx.owner, ctx.repo)
        try:
            new_sha = await _thread(
                merging.merge_pull,
                ctx.repo_git,
                target_branch=pr["base"],
                source_branch=pr["head"],
                expected_target=base,
                expected_source=head,
                method=chosen,
                committer=merging.identity_for(ctx.actor.username),
                title=commit_title,
                message=commit_message,
                squash_author=squash_author,
            )
        except merging.MergeError as exc:
            status_code = {"stale": 409, "conflict": 409, "up_to_date": 409, "not_found": 404}
            raise PullError(status_code.get(exc.code, 422), exc.code, exc.message) from None
        await _thread(database.db_pr_mark_merged, pr["id"], chosen, new_sha)
        await _thread(
            _event, ctx, pr["id"], "merged", {"method": chosen, "sha": new_sha, "base": pr["base"]}
        )
        await ctx.server._queue_push_changes(ctx.owner, ctx.repo, before_refs)
    result: dict[str, Any] = {"merged": True, "sha": new_sha, "merge_method": chosen}
    try:
        await ctx.server.ci_manager.enqueue(
            ctx.owner,
            ctx.repo,
            "pull_request_merged",
            pr["base"],
            new_sha,
            {
                "pr_number": pr["id"],
                "base_branch": pr["base"],
                "head_branch": pr["head"],
                "base_commit": new_sha,
            },
        )
    except Exception:
        result["warnings"] = ["Merged, but scheduling merged-event CI failed."]
    if delete_branch:
        try:
            await delete_head_branch(ctx, pr["id"])
            result["branch_deleted"] = True
        except PullError as exc:
            result.setdefault("warnings", []).append(f"Branch not deleted: {exc.message}")
    return result


async def update_branch(ctx: Context, pr_id: int, *, expected_head: str | None = None) -> str:
    """Merge the base branch into the head branch (GitHub's "Update branch")."""
    _require_write(ctx, "update branches")
    lock = ctx.server.push_locks.setdefault((ctx.owner, ctx.repo), asyncio.Lock())
    async with lock:
        pr = await load(ctx, pr_id)
        _require_open(pr)
        if not pr["head_sha"] or not pr["base_sha"]:
            raise PullError(409, "missing_branch", "The head or base branch no longer exists.")
        if expected_head and expected_head != pr["head_sha"]:
            raise PullError(409, "stale", "The head branch changed; refresh and try again.")
        policy = await _policy(ctx)
        if policy.get("block_direct_pushes") and _protected(policy, pr["head"]):
            raise PullError(403, "protected_branch", "The head branch is protected.")
        before_refs = await ctx.server._branch_refs(ctx.owner, ctx.repo)
        try:
            sha = await _thread(
                merging.update_branch,
                ctx.repo_git,
                head_branch=pr["head"],
                base_branch=pr["base"],
                expected_head=pr["head_sha"],
                expected_base=pr["base_sha"],
                committer=merging.identity_for(ctx.actor.username),
                message=f"Merge branch '{pr['base']}' into {pr['head']}",
            )
        except merging.MergeError as exc:
            if exc.code == "up_to_date":
                raise PullError(409, "up_to_date", "The branch is already up to date.") from None
            raise PullError(409 if exc.code != "invalid" else 422, exc.code, exc.message) from None
        await ctx.server._queue_push_changes(ctx.owner, ctx.repo, before_refs)
    return cast(str, sha)


# ---------------------------------------------------------------- lifecycle


async def set_draft(ctx: Context, pr_id: int, draft: bool) -> PullRequest:
    pr = await load(ctx, pr_id)
    if not (ctx.actor.can_write or _is_pr_author(ctx, pr)):
        raise PullError(403, "forbidden", "Only the author or a writer can change draft state.")
    _require_open(pr)
    if pr["draft"] == draft:
        return pr
    await _thread(pull_store.set_draft, pr_id, draft)
    await _thread(_event, ctx, pr_id, "converted_to_draft" if draft else "ready_for_review")
    return await load(ctx, pr_id)


async def change_base(ctx: Context, pr_id: int, base: str) -> PullRequest:
    pr = await load(ctx, pr_id)
    if not (ctx.actor.can_write or _is_pr_author(ctx, pr)):
        raise PullError(403, "forbidden", "Only the author or a writer can change the base.")
    _require_open(pr)
    base = _branch(base)
    if base == pr["base"]:
        return pr
    if base == pr["head"]:
        raise PullError(422, "validation_error", "The base must differ from the head branch.")
    if not await _thread(merging.resolve, ctx.repo_git, "refs/heads/" + base):
        raise PullError(422, "validation_error", "Base branch not found.")
    await _thread(pull_store.set_base, pr_id, base)
    await _thread(_event, ctx, pr_id, "base_changed", {"from": pr["base"], "to": base})
    return await load(ctx, pr_id)


async def delete_head_branch(ctx: Context, pr_id: int) -> None:
    _require_write(ctx, "delete branches")
    pr = await load(ctx, pr_id)
    if pr["state"] == "open":
        raise PullError(409, "open", "Close or merge the pull request before deleting its branch.")
    if not pr["head_sha"]:
        raise PullError(409, "missing_branch", "The branch was already deleted.")
    policy = await _policy(ctx)
    if policy.get("block_direct_pushes") and _protected(policy, pr["head"]):
        raise PullError(403, "protected_branch", "Protected branches cannot be deleted.")
    default = await _thread(_default_branch, ctx.repo_git)
    if pr["head"] == default:
        raise PullError(403, "protected_branch", "The default branch cannot be deleted.")
    others = [
        row
        for row in await _thread(database.db_prs_for_source, ctx.owner, ctx.repo, pr["head"])
        if int(row[0]) != pr["id"]
    ]
    if others:
        raise PullError(409, "in_use", "Another open pull request uses this branch.")
    lock = ctx.server.push_locks.setdefault((ctx.owner, ctx.repo), asyncio.Lock())
    async with lock:
        try:
            await _thread(merging.delete_branch, ctx.repo_git, pr["head"], pr["head_sha"])
        except merging.MergeError as exc:
            raise PullError(409, exc.code, exc.message) from None
    await _thread(pull_store.set_head_deleted, pr_id, pr["head_sha"])
    await _thread(_event, ctx, pr_id, "head_ref_deleted", {"branch": pr["head"]})


async def restore_head_branch(ctx: Context, pr_id: int) -> None:
    _require_write(ctx, "restore branches")
    pr = await load(ctx, pr_id)
    if not pr["head_deleted_sha"]:
        raise PullError(409, "not_deleted", "The branch was not deleted from this pull request.")
    if pr["head_sha"]:
        raise PullError(409, "exists", "A branch with that name already exists.")
    lock = ctx.server.push_locks.setdefault((ctx.owner, ctx.repo), asyncio.Lock())
    async with lock:
        try:
            await _thread(merging.create_branch, ctx.repo_git, pr["head"], pr["head_deleted_sha"])
        except merging.MergeError as exc:
            raise PullError(409, exc.code, exc.message) from None
    await _thread(pull_store.set_head_deleted, pr_id, None)
    await _thread(_event, ctx, pr_id, "head_ref_restored", {"branch": pr["head"]})


def _default_branch(repo_git: str) -> str:
    try:
        out = merging.run_git(repo_git, "symbolic-ref", "--short", "HEAD")
    except merging.MergeError:
        return ""
    return out.strip()


# ---------------------------------------------------------------- reviewers


async def request_reviewers(ctx: Context, pr_id: int, logins: Sequence[str]) -> list[str]:
    pr = await load(ctx, pr_id)
    if not (ctx.actor.can_write or _is_pr_author(ctx, pr)):
        raise PullError(403, "forbidden", "Only the author or a writer can request reviews.")
    _require_open(pr)
    if not logins or len(logins) > 20 or any(not isinstance(x, str) for x in logins):
        raise PullError(422, "validation_error", "Name between 1 and 20 reviewers.")
    ids = await _thread(pull_store.user_ids_for_logins, logins)
    missing = sorted(set(logins) - set(ids))
    if missing:
        raise PullError(422, "validation_error", "Unknown reviewers: " + ", ".join(missing))
    if pr["author_user_id"] is not None and pr["author_user_id"] in ids.values():
        raise PullError(422, "validation_error", "The author cannot review their own PR.")
    added = await _thread(pull_store.request_reviewers, pr_id, ids.values(), _uid(ctx))
    names = {user_id: login for login, user_id in ids.items()}
    for user_id in added:
        await _thread(_event, ctx, pr_id, "review_requested", {"reviewer": names[user_id]})
    return [names[user_id] for user_id in added]


async def remove_reviewer(ctx: Context, pr_id: int, login: str) -> None:
    pr = await load(ctx, pr_id)
    if not (ctx.actor.can_write or _is_pr_author(ctx, pr)):
        raise PullError(403, "forbidden", "Only the author or a writer can remove reviewers.")
    ids = await _thread(pull_store.user_ids_for_logins, [login])
    if login not in ids or not await _thread(pull_store.remove_review_request, pr_id, ids[login]):
        raise PullError(404, "not_found", "That reviewer was not requested.")
    await _thread(_event, ctx, pr_id, "review_request_removed", {"reviewer": login})


def _uid(ctx: Context) -> int | None:
    return ctx.actor.user_id if ctx.actor.known else None


# ---------------------------------------------------------------- review comments


class CommentAnchor(TypedDict):
    path: str
    side: Side
    line: int
    start_line: int | None


def _anchor(path: object, side: object, line: object, start_line: object) -> CommentAnchor:
    if (
        not isinstance(path, str)
        or not path
        or len(path) > 4096
        or "\0" in path
        or path.startswith("/")
        or ".." in path.split("/")
    ):
        raise PullError(422, "validation_error", "Invalid file path.")
    if side not in ("LEFT", "RIGHT"):
        raise PullError(422, "validation_error", "side must be LEFT or RIGHT.")
    try:
        number = int(cast(Any, line))
        start = int(cast(Any, start_line)) if start_line not in (None, "") else None
    except TypeError, ValueError:
        raise PullError(422, "validation_error", "Invalid line number.") from None
    if number < 1 or (start is not None and not 1 <= start <= number):
        raise PullError(422, "validation_error", "Invalid line range.")
    if start == number:
        start = None
    return {"path": path, "side": side, "line": number, "start_line": start}


async def _check_anchor(ctx: Context, pr: PullRequest, anchor: CommentAnchor) -> None:
    """The commented lines must exist on that side of the PR's current diff."""
    commit = pr["head_sha"] if anchor["side"] == "RIGHT" else pr["merge_base"]
    if not commit:
        raise PullError(409, "missing_branch", "The pull request branches are unavailable.")
    lines = await _thread(merging.file_lines, ctx.repo_git, commit, anchor["path"])
    if lines is None or anchor["line"] > max(len(lines), 1):
        raise PullError(422, "validation_error", "That line is not part of the file.")


async def _review_for(ctx: Context, pr: PullRequest, mode: str) -> int | None:
    if mode == "single":
        return None
    if mode != "review":
        raise PullError(422, "validation_error", "mode must be single or review.")
    pending = await _thread(pull_store.pending_review, pr["id"], _uid(ctx))
    if pending:
        return cast(int, pending["id"])
    return cast(int, await _thread(pull_store.start_review, pr["id"], _uid(ctx), pr["head_sha"]))


async def add_review_comment(
    ctx: Context,
    pr_id: int,
    *,
    path: object,
    side: object = "RIGHT",
    line: object,
    start_line: object = None,
    body: object,
    mode: str = "single",
) -> tuple[int, int]:
    pr = await load(ctx, pr_id)
    if pr["state"] == "merged" and mode == "review":
        raise PullError(409, "not_open", "Merged pull requests cannot be reviewed.")
    anchor = _anchor(path, side, line, start_line)
    text = _text(body, "comment")
    await _check_anchor(ctx, pr, anchor)
    review_id = await _review_for(ctx, pr, mode)
    thread_id, comment_id = await _thread(
        lambda: pull_store.create_thread(
            pr_id=pr["id"],
            path=anchor["path"],
            side=anchor["side"],
            line=anchor["line"],
            start_line=anchor["start_line"],
            commit_sha=pr["head_sha"] or "",
            base_sha=pr["merge_base"] or "",
            body=text,
            author_user_id=_uid(ctx),
            review_id=review_id,
        )
    )
    if review_id is None:
        # A single comment is a one-comment "commented" review, as on GitHub.
        await _thread(_event, ctx, pr["id"], "review_comment", {"thread_id": thread_id})
    return thread_id, comment_id


async def reply(
    ctx: Context, pr_id: int, thread_id: int, body: object, mode: str = "single"
) -> int:
    pr = await load(ctx, pr_id)
    threads = await _thread(
        pull_store.list_threads, pr["id"], _uid(ctx), ctx.actor.known, int(thread_id)
    )
    if not threads:
        raise PullError(404, "not_found", "Conversation not found.")
    text = _text(body, "reply")
    review_id = await _review_for(ctx, pr, mode)
    return cast(
        int,
        await _thread(pull_store.add_reply, pr["id"], int(thread_id), text, _uid(ctx), review_id),
    )


async def resolve_thread(ctx: Context, pr_id: int, thread_id: int, resolved: bool) -> None:
    pr = await load(ctx, pr_id)
    threads = await _thread(
        pull_store.list_threads, pr["id"], _uid(ctx), ctx.actor.known, int(thread_id)
    )
    if not threads:
        raise PullError(404, "not_found", "Conversation not found.")
    starter = threads[0]["comments"][0]["author_user_id"]
    if not (
        ctx.actor.can_write
        or _is_pr_author(ctx, pr)
        or (ctx.actor.known and starter == ctx.actor.user_id)
    ):
        raise PullError(403, "forbidden", "You cannot resolve this conversation.")
    await _thread(pull_store.set_resolved, pr["id"], int(thread_id), resolved, _uid(ctx))


async def edit_review_comment(ctx: Context, pr_id: int, comment_id: int, body: object) -> None:
    await load(ctx, pr_id)
    comment = await _thread(pull_store.get_comment, int(pr_id), int(comment_id))
    if not comment or (comment["pending"] and not _owns(ctx, comment["author_user_id"])):
        raise PullError(404, "not_found", "Comment not found.")
    if not (_owns(ctx, comment["author_user_id"]) or ctx.actor.is_admin):
        raise PullError(403, "forbidden", "Only the author or an administrator can edit it.")
    await _thread(pull_store.update_comment, int(comment_id), _text(body, "comment"))


async def delete_review_comment(ctx: Context, pr_id: int, comment_id: int) -> None:
    await load(ctx, pr_id)
    comment = await _thread(pull_store.get_comment, int(pr_id), int(comment_id))
    if not comment or (comment["pending"] and not _owns(ctx, comment["author_user_id"])):
        raise PullError(404, "not_found", "Comment not found.")
    if not (_owns(ctx, comment["author_user_id"]) or ctx.actor.is_admin):
        raise PullError(403, "forbidden", "Only the author or an administrator can delete it.")
    await _thread(pull_store.delete_comment, int(comment_id))


def _owns(ctx: Context, author_user_id: int | None) -> bool:
    if ctx.actor.known:
        return author_user_id == ctx.actor.user_id
    # Without sign-in every visitor is the same anonymous local user.
    return author_user_id is None


# ---------------------------------------------------------------- reviews


async def submit_review(
    ctx: Context,
    pr_id: int,
    *,
    event: str,
    body: object = "",
    comments: Sequence[Mapping[str, Any]] = (),
    commit_id: str | None = None,
) -> Review:
    pr = await load(ctx, pr_id)
    _require_open(pr)
    state = REVIEW_EVENTS.get(event)
    if state is None:
        raise PullError(
            422, "validation_error", "event must be APPROVE, REQUEST_CHANGES or COMMENT."
        )
    text = _text(body if body is not None else "", "review summary", required=False)
    if state != "approved" and _is_pr_author(ctx, pr) and state == "changes_requested":
        raise PullError(422, "validation_error", "You cannot request changes on your own PR.")
    if state == "approved" and _is_pr_author(ctx, pr):
        raise PullError(422, "validation_error", "You cannot approve your own pull request.")
    if commit_id and commit_id != pr["head_sha"]:
        raise PullError(409, "stale", "New commits were pushed; review the latest changes.")
    if len(comments) > 100:
        raise PullError(422, "validation_error", "At most 100 comments per review.")
    for item in comments:
        await add_review_comment(
            ctx,
            pr_id,
            path=item.get("path"),
            side=item.get("side", "RIGHT"),
            line=item.get("line"),
            start_line=item.get("start_line"),
            body=item.get("body"),
            mode="review",
        )
    pending = await _thread(pull_store.pending_review, pr["id"], _uid(ctx))
    if pending is None:
        if state == "commented" and not text.strip():
            raise PullError(422, "validation_error", "Write a comment or add review comments.")
        review_id = await _thread(pull_store.start_review, pr["id"], _uid(ctx), pr["head_sha"])
    else:
        review_id = pending["id"]
        if (
            state == "commented"
            and not text.strip()
            and not await _thread(pull_store.review_comment_count, review_id)
        ):
            raise PullError(422, "validation_error", "Write a comment or add review comments.")
    await _thread(pull_store.submit_review, review_id, state, text, pr["head_sha"] or "")
    if ctx.actor.known and ctx.actor.user_id is not None:
        # Submitting a review fulfils that reviewer's request.
        await _thread(pull_store.remove_review_request, pr["id"], ctx.actor.user_id)
    review = await _thread(pull_store.get_review, pr["id"], review_id)
    return cast(Review, review)


async def discard_pending_review(ctx: Context, pr_id: int) -> None:
    pr = await load(ctx, pr_id)
    pending = await _thread(pull_store.pending_review, pr["id"], _uid(ctx))
    if not pending:
        raise PullError(404, "not_found", "You have no pending review.")
    await _thread(pull_store.delete_pending_review, pending["id"])


async def dismiss_review(ctx: Context, pr_id: int, review_id: int, message: object) -> None:
    _require_write(ctx, "dismiss reviews")
    pr = await load(ctx, pr_id)
    reason = _text(message, "dismissal message", limit=1000)
    review = await _thread(pull_store.get_review, pr["id"], int(review_id))
    if not review or review["state"] not in ("approved", "changes_requested"):
        raise PullError(404, "not_found", "No approval or change request with that id.")
    await _thread(pull_store.dismiss_review, int(review_id), _uid(ctx), reason)
    await _thread(
        _event,
        ctx,
        pr["id"],
        "review_dismissed",
        {"review_id": int(review_id), "reviewer": review["author"], "reason": reason},
    )


# ---------------------------------------------------------------- suggestions


async def apply_suggestion(
    ctx: Context, pr_id: int, comment_id: int, *, expected_head: str | None = None
) -> str:
    _require_write(ctx, "apply suggestions")
    lock = ctx.server.push_locks.setdefault((ctx.owner, ctx.repo), asyncio.Lock())
    async with lock:
        pr = await load(ctx, pr_id)
        _require_open(pr)
        comment = await _thread(pull_store.get_comment, pr["id"], int(comment_id))
        if not comment or comment["pending"]:
            raise PullError(404, "not_found", "Comment not found.")
        suggestion = extract_suggestion(comment["body"])
        if suggestion is None:
            raise PullError(422, "no_suggestion", "That comment has no suggested change.")
        threads = await _thread(
            pull_store.list_threads, pr["id"], _uid(ctx), ctx.actor.known, comment["thread_id"]
        )
        if not threads:
            raise PullError(404, "not_found", "Conversation not found.")
        thread = threads[0]
        if thread["side"] != "RIGHT":
            raise PullError(422, "no_suggestion", "Suggestions apply to the new version only.")
        head = pr["head_sha"]
        if not head or (expected_head and expected_head != head):
            raise PullError(409, "stale", "The head branch changed; refresh and try again.")
        located = await locate_thread(ctx, pr, thread)
        if located["outdated"] or located["line"] is None:
            raise PullError(409, "outdated", "The lines changed since this suggestion was made.")
        end = located["line"]
        start = end - (thread["line"] - (thread["start_line"] or thread["line"]))
        current = await _thread(merging.file_lines, ctx.repo_git, head, thread["path"])
        if current is None or start < 1:
            raise PullError(409, "outdated", "The file changed since this suggestion was made.")
        policy = await _policy(ctx)
        if policy.get("block_direct_pushes") and _protected(policy, pr["head"]):
            raise PullError(403, "protected_branch", "The head branch is protected.")
        before_refs = await ctx.server._branch_refs(ctx.owner, ctx.repo)
        try:
            sha = await _thread(
                lambda: merging.replace_lines(
                    ctx.repo_git,
                    branch=pr["head"],
                    expected_head=head,
                    path=thread["path"],
                    start_line=start,
                    end_line=end,
                    expected_lines=current[start - 1 : end],
                    new_text=suggestion,
                    message=f"Apply suggestion from code review\n\n{thread['path']}:{start}-{end}",
                    author=merging.identity_for(ctx.actor.username),
                )
            )
        except merging.MergeError as exc:
            raise PullError(409 if exc.code != "invalid" else 422, exc.code, exc.message) from None
        await _thread(pull_store.set_resolved, pr["id"], thread["id"], True, _uid(ctx))
        await ctx.server._queue_push_changes(ctx.owner, ctx.repo, before_refs)
    return cast(str, sha)


# ---------------------------------------------------------------- positions, files, timeline


class Location(TypedDict):
    outdated: bool
    line: int | None
    start_line: int | None


async def locate_thread(ctx: Context, pr: PullRequest, thread: Thread) -> Location:
    """Where a thread's lines are in the current diff, or outdated if they changed."""
    span = thread["line"] - (thread["start_line"] or thread["line"])
    if thread["side"] == "RIGHT":
        if not pr["head_sha"]:
            return {"outdated": True, "line": None, "start_line": None}
        if thread["commit_sha"] == pr["head_sha"]:
            line: int | None = thread["line"]
        else:
            line = await _thread(
                merging.map_line,
                ctx.repo_git,
                thread["commit_sha"],
                pr["head_sha"],
                thread["path"],
                thread["line"],
            )
            if line is not None and span:
                first = await _thread(
                    merging.map_line,
                    ctx.repo_git,
                    thread["commit_sha"],
                    pr["head_sha"],
                    thread["path"],
                    thread["start_line"] or thread["line"],
                )
                if first is None or line - first != span:
                    line = None
    else:
        base = pr["merge_base"]
        if not base:
            return {"outdated": True, "line": None, "start_line": None}
        changed = thread["base_sha"] != base and await _thread(
            merging.path_changed, ctx.repo_git, thread["base_sha"], base, thread["path"]
        )
        line = None if changed else thread["line"]
    if line is None:
        return {"outdated": True, "line": None, "start_line": None}
    return {"outdated": False, "line": line, "start_line": line - span if span else None}


async def threads(ctx: Context, pr: PullRequest) -> list[tuple[Thread, Location]]:
    rows = await _thread(pull_store.list_threads, pr["id"], _uid(ctx), ctx.actor.known)
    return [(thread, await locate_thread(ctx, pr, thread)) for thread in rows]


async def set_file_viewed(ctx: Context, pr_id: int, path: str, viewed: bool) -> None:
    pr = await load(ctx, pr_id)
    if not isinstance(path, str) or not path or len(path) > 4096 or "\0" in path:
        raise PullError(422, "validation_error", "Invalid file path.")
    blob = None
    if viewed:
        if not pr["head_sha"]:
            raise PullError(409, "missing_branch", "The head branch no longer exists.")
        blob = await _thread(merging.blob_id, ctx.repo_git, pr["head_sha"], path)
        # Deleted files have no blob at the head; remember the deletion instead.
        blob = blob or "deleted"
    await _thread(pull_store.set_viewed, pr["id"], ctx.actor.viewer, path, blob)


async def viewed_paths(ctx: Context, pr: PullRequest, paths: Sequence[str]) -> set[str]:
    """Paths the viewer marked viewed whose content has not changed since."""
    marks = await _thread(pull_store.viewed_files, pr["id"], ctx.actor.viewer)
    result: set[str] = set()
    for path in paths:
        blob = marks.get(path)
        if blob is None or not pr["head_sha"]:
            continue
        current = await _thread(merging.blob_id, ctx.repo_git, pr["head_sha"], path) or "deleted"
        if current == blob:
            result.add(path)
    return result


async def record_head_update(
    server: ServerLike, owner: str, repo: str, repo_git: str, pr_id: int, old: str, new: str
) -> None:
    """Timeline entry and stale-approval dismissal after the head branch moved."""
    forced = bool(old) and not await _thread(merging.is_ancestor, repo_git, old, new)
    await _thread(
        pull_store.add_event,
        pr_id,
        None,
        "head_ref_force_pushed" if forced else "committed",
        {"before": old, "after": new},
    )
    policy = cast(Mapping[str, Any], await server.ci_manager.config(owner, repo))
    row = await _thread(database.db_pr_get, pr_id)
    if row and policy.get("dismiss_stale_approvals") and _protected(policy, row[6]):
        await _thread(pull_store.dismiss_stale_approvals, pr_id, new)


async def timeline(ctx: Context, pr: PullRequest) -> list[dict[str, Any]]:
    """Conversation comments, submitted reviews and events in chronological order."""
    items: list[dict[str, Any]] = []
    for comment in await _thread(database.db_pr_comment_list, pr["id"]):
        items.append(
            {
                "type": "comment",
                "id": comment[0],
                "author_user_id": comment[1],
                "author": comment[2],
                "body": comment[3],
                "created_at": comment[4],
                "edited_at": comment[5],
            }
        )
    for review in await _thread(pull_store.list_reviews, pr["id"], _uid(ctx), ctx.actor.known):
        if review["state"] == "pending":
            continue
        items.append(
            {
                "type": "review",
                **review,
                "created_at": review["submitted_at"] or review["created_at"],
            }
        )
    for event in await _thread(pull_store.list_events, pr["id"]):
        items.append({"type": "event", **event})
    items.sort(key=lambda item: (str(item.get("created_at") or ""), item["type"] != "event"))
    return items
