"""REST endpoints for pull request reviews, merging and lifecycle (thin wrappers over pulls)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, cast

from .. import pulls
from ..pull_store import Review, Thread
from .data import timestamp
from .errors import APIError
from .types import APIContext
from .validation import fields

_PR = r"pulls/([0-9]{1,18})"
_ID = r"([0-9]{1,18})"

# (method, pattern) pairs handled here, checked before the generic writes route.
MUTATIONS = (
    ("PUT", re.compile(_PR + r"/merge")),
    ("PUT", re.compile(_PR + r"/update-branch")),
    ("PATCH", re.compile(_PR)),
    ("DELETE", re.compile(_PR + r"/head-branch")),
    ("POST", re.compile(_PR + r"/head-branch/restore")),
    ("POST", re.compile(_PR + r"/requested_reviewers")),
    ("DELETE", re.compile(_PR + r"/requested_reviewers")),
    ("POST", re.compile(_PR + r"/reviews")),
    ("DELETE", re.compile(_PR + r"/reviews/pending")),
    ("PUT", re.compile(_PR + r"/reviews/" + _ID + r"/dismissals")),
    ("POST", re.compile(_PR + r"/threads")),
    ("POST", re.compile(_PR + r"/threads/" + _ID + r"/replies")),
    ("PUT", re.compile(_PR + r"/threads/" + _ID + r"/resolution")),
    ("PATCH", re.compile(_PR + r"/review-comments/" + _ID)),
    ("DELETE", re.compile(_PR + r"/review-comments/" + _ID)),
    ("POST", re.compile(_PR + r"/review-comments/" + _ID + r"/apply-suggestion")),
    ("PUT", re.compile(_PR + r"/viewed-files")),
)
READS = re.compile(
    _PR
    + r"/(merge-status|reviews|reviews/"
    + _ID
    + r"|threads|threads/"
    + _ID
    + r"|requested_reviewers|events|timeline|viewed-files)"
)
# PATCH /pulls/{id} is handled here only for these fields; title/body/state keep
# their existing revision-checked endpoint.
LIFECYCLE_FIELDS = {"draft", "base"}


def handles_mutation(tail: str, method: str, document: Mapping[str, object]) -> bool:
    for verb, pattern in MUTATIONS:
        if verb == method and pattern.fullmatch(tail):
            if verb == "PATCH" and pattern.pattern == _PR:
                keys = set(document) - {"expected_revision"}
                return bool(keys) and keys <= LIFECYCLE_FIELDS
            return True
    return False


def handles_read(tail: str) -> bool:
    return READS.fullmatch(tail) is not None


def context(api: APIContext, owner: str, repo: str, path: str) -> pulls.Context:
    identity = api.identity
    actor = pulls.Actor(
        user_id=identity["user_id"],
        username=identity["username"],
        is_admin=identity["is_admin"],
        can_write="write" in identity["scopes"],
        known=True,
        viewer="u:" + str(identity["user_id"]),
    )
    return pulls.Context(
        server=cast(pulls.ServerLike, api.handler.server),
        owner=owner,
        repo=repo,
        repo_git=path,
        actor=actor,
    )


def _error(exc: pulls.PullError) -> APIError:
    return APIError(exc.status, exc.code, exc.message)


def _bool(document: Mapping[str, object], name: str) -> bool:
    value = document.get(name)
    if type(value) is not bool:
        raise APIError(422, "validation_error", f"{name} must be true or false.")
    return value


def _optional_sha(document: Mapping[str, object], name: str) -> str | None:
    value = document.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
        raise APIError(422, "validation_error", f"{name} must be a full commit SHA.")
    return value.lower()


def _logins(document: Mapping[str, object]) -> list[str]:
    value = document.get("reviewers")
    if not isinstance(value, list) or not value or any(not isinstance(v, str) for v in value):
        raise APIError(422, "validation_error", "reviewers must be a non-empty array of logins.")
    return cast(list[str], value)


def serialize_review(review: Review) -> dict[str, Any]:
    return {
        "id": review["id"],
        "user": {"id": review["author_user_id"], "login": review["author"]}
        if review["author_user_id"] is not None
        else None,
        "state": review["state"].upper(),
        "body": review["body"],
        "commit_id": review["commit_sha"] or None,
        "submitted_at": timestamp(review["submitted_at"]),
        "dismissed_at": timestamp(review["dismissed_at"]),
        "dismissed_by": review["dismissed_by"],
        "dismissal_message": review["dismiss_reason"] or None,
    }


def serialize_thread(thread: Thread, location: pulls.Location) -> dict[str, Any]:
    return {
        "id": thread["id"],
        "path": thread["path"],
        "side": thread["side"],
        "original_line": thread["line"],
        "original_start_line": thread["start_line"],
        "original_commit_id": thread["commit_sha"],
        "line": location["line"],
        "start_line": location["start_line"],
        "outdated": location["outdated"],
        "resolved": thread["resolved"],
        "resolved_by": thread["resolved_by"],
        "resolved_at": timestamp(thread["resolved_at"]),
        "comments": [
            {
                "id": comment["id"],
                "user": {"id": comment["author_user_id"], "login": comment["author"]}
                if comment["author_user_id"] is not None
                else None,
                "body": comment["body"],
                "review_id": comment["review_id"],
                "pending": comment["pending"],
                "created_at": timestamp(comment["created_at"]),
                "edited_at": timestamp(comment["edited_at"]),
            }
            for comment in thread["comments"]
        ],
    }


async def read(api: APIContext, owner: str, repo: str, path: str, tail: str) -> object:
    api.parameters()
    match = READS.fullmatch(tail)
    assert match
    pr_id = int(match[1])
    kind = match[2]
    ctx = context(api, owner, repo, path)
    try:
        pr = await pulls.load(ctx, pr_id)
        if kind == "merge-status":
            return dict(await pulls.merge_status(ctx, pr))
        if kind == "reviews" or kind.startswith("reviews/"):
            from .. import pull_store

            reviews = [
                serialize_review(r)
                for r in await _thread(pull_store.list_reviews, pr["id"], ctx.actor.user_id, True)
            ]
            if kind == "reviews":
                return api.listing(reviews[api.offset : api.offset + api.per_page + 1])
            wanted = int(kind.split("/")[1])
            for review in reviews:
                if review["id"] == wanted:
                    return review
            raise APIError(404, "not_found", "Review not found.")
        if kind == "threads" or kind.startswith("threads/"):
            items = [serialize_thread(t, loc) for t, loc in await pulls.threads(ctx, pr)]
            if kind == "threads":
                return api.listing(items[api.offset : api.offset + api.per_page + 1])
            wanted = int(kind.split("/")[1])
            for item in items:
                if item["id"] == wanted:
                    return item
            raise APIError(404, "not_found", "Conversation not found.")
        if kind == "requested_reviewers":
            from .. import pull_store

            requests = await _thread(pull_store.list_review_requests, pr["id"])
            return {"users": [{"id": r["user_id"], "login": r["login"]} for r in requests]}
        if kind in ("events", "timeline"):
            items = await pulls.timeline(ctx, pr)
            if kind == "events":
                items = [item for item in items if item["type"] == "event"]
            for item in items:
                if item["type"] == "event":
                    item["event"] = item.pop("kind")
                item["created_at"] = timestamp(item.get("created_at"))
                for key in ("submitted_at", "edited_at", "dismissed_at"):
                    if key in item:
                        item[key] = timestamp(item[key])
            return api.listing(items[api.offset : api.offset + api.per_page + 1])
        if kind == "viewed-files":
            from .. import pull_store

            marks = await _thread(pull_store.viewed_files, pr["id"], ctx.actor.viewer)
            current = await pulls.viewed_paths(ctx, pr, sorted(marks))
            return {"paths": sorted(current)}
    except pulls.PullError as exc:
        raise _error(exc) from None
    raise APIError(404, "not_found", "API endpoint not found.")


async def _thread(func: Any, /, *args: Any) -> Any:
    import asyncio

    return await asyncio.to_thread(func, *args)


async def mutate(
    api: APIContext, owner: str, repo: str, path: str, tail: str
) -> tuple[int, Mapping[str, object]]:
    doc, method = api.document, api.request.method
    ctx = context(api, owner, repo, path)
    pr_match = re.match(_PR, tail)
    assert pr_match
    pr_id = int(pr_match[1])
    rest = tail[pr_match.end() :]
    try:
        if rest == "/merge":
            fields(
                doc,
                {
                    "merge_method",
                    "sha",
                    "expected_base_sha",
                    "commit_title",
                    "commit_message",
                    "delete_branch",
                },
            )
            method_name = doc.get("merge_method")
            if method_name is not None and not isinstance(method_name, str):
                raise APIError(422, "validation_error", "merge_method must be a string.")
            result = await pulls.merge(
                ctx,
                pr_id,
                method=method_name,
                expected_head=_optional_sha(doc, "sha"),
                expected_base=_optional_sha(doc, "expected_base_sha"),
                title=cast(str | None, doc.get("commit_title")),
                message=cast(str | None, doc.get("commit_message")),
                delete_branch=_bool(doc, "delete_branch") if "delete_branch" in doc else False,
            )
            return 200, result
        if rest == "/update-branch":
            fields(doc, {"expected_head_sha"})
            sha = await pulls.update_branch(
                ctx, pr_id, expected_head=_optional_sha(doc, "expected_head_sha")
            )
            return 202, {"message": "Updating pull request branch.", "sha": sha}
        if rest == "" and method == "PATCH":
            fields(doc, LIFECYCLE_FIELDS | {"expected_revision"})
            draft = _bool(doc, "draft") if "draft" in doc else None
            pr = None
            if "base" in doc:
                pr = await pulls.change_base(ctx, pr_id, cast(str, doc["base"]))
            if draft is not None:
                pr = await pulls.set_draft(ctx, pr_id, draft)
            assert pr is not None
            return 200, {"id": pr["id"], "draft": pr["draft"], "base": pr["base"]}
        if rest == "/head-branch":
            fields(doc, set())
            await pulls.delete_head_branch(ctx, pr_id)
            return 200, {"deleted": True}
        if rest == "/head-branch/restore":
            fields(doc, set())
            await pulls.restore_head_branch(ctx, pr_id)
            return 201, {"restored": True}
        if rest == "/requested_reviewers":
            fields(doc, {"reviewers"}, {"reviewers"})
            logins = _logins(doc)
            if method == "POST":
                added = await pulls.request_reviewers(ctx, pr_id, logins)
                return 201, {"requested": added}
            for login in logins:
                await pulls.remove_reviewer(ctx, pr_id, login)
            return 200, {"removed": logins}
        if rest == "/reviews" and method == "POST":
            fields(doc, {"event", "body", "comments", "commit_id"})
            comments = doc.get("comments", [])
            if not isinstance(comments, list) or any(not isinstance(c, dict) for c in comments):
                raise APIError(422, "validation_error", "comments must be an array of objects.")
            if len(comments) > 100:
                raise APIError(422, "validation_error", "At most 100 comments per review.")
            for comment in comments:
                fields(
                    comment,
                    {"path", "line", "side", "start_line", "body"},
                    {"path", "line", "body"},
                )
            event = doc.get("event")
            if event is None:
                # GitHub semantics: omitting the event leaves the review pending.
                for comment in comments:
                    await pulls.add_review_comment(
                        ctx,
                        pr_id,
                        path=comment.get("path"),
                        side=comment.get("side", "RIGHT"),
                        line=comment.get("line"),
                        start_line=comment.get("start_line"),
                        body=comment.get("body"),
                        mode="review",
                    )
                from .. import pull_store

                pending = await _thread(pull_store.pending_review, pr_id, ctx.actor.user_id)
                if pending is None:
                    pr = await pulls.load(ctx, pr_id)
                    review_id = await _thread(
                        pull_store.start_review, pr_id, ctx.actor.user_id, pr["head_sha"] or ""
                    )
                    pending = await _thread(pull_store.get_review, pr_id, review_id)
                return 201, serialize_review(pending)
            if not isinstance(event, str):
                raise APIError(422, "validation_error", "event must be a string.")
            review = await pulls.submit_review(
                ctx,
                pr_id,
                event=event,
                body=doc.get("body", ""),
                comments=cast(list[Mapping[str, Any]], comments),
                commit_id=_optional_sha(doc, "commit_id"),
            )
            return 201, serialize_review(review)
        if rest == "/reviews/pending":
            fields(doc, set())
            await pulls.discard_pending_review(ctx, pr_id)
            return 200, {"deleted": True}
        dismissal = re.fullmatch(r"/reviews/" + _ID + r"/dismissals", rest)
        if dismissal:
            fields(doc, {"message"}, {"message"})
            await pulls.dismiss_review(ctx, pr_id, int(dismissal[1]), doc["message"])
            return 200, {"dismissed": True}
        if rest == "/threads":
            fields(
                doc,
                {"path", "line", "side", "start_line", "body", "mode"},
                {"path", "line", "body"},
            )
            mode = doc.get("mode", "single")
            if mode not in ("single", "review"):
                raise APIError(422, "validation_error", "mode must be single or review.")
            thread_id, comment_id = await pulls.add_review_comment(
                ctx,
                pr_id,
                path=doc.get("path"),
                side=doc.get("side", "RIGHT"),
                line=doc.get("line"),
                start_line=doc.get("start_line"),
                body=doc.get("body"),
                mode=cast(str, mode),
            )
            return 201, {"thread_id": thread_id, "comment_id": comment_id}
        replies = re.fullmatch(r"/threads/" + _ID + r"/replies", rest)
        if replies:
            fields(doc, {"body", "mode"}, {"body"})
            mode = doc.get("mode", "single")
            if mode not in ("single", "review"):
                raise APIError(422, "validation_error", "mode must be single or review.")
            comment_id = await pulls.reply(
                ctx, pr_id, int(replies[1]), doc.get("body"), cast(str, mode)
            )
            return 201, {"comment_id": comment_id}
        resolution = re.fullmatch(r"/threads/" + _ID + r"/resolution", rest)
        if resolution:
            fields(doc, {"resolved"}, {"resolved"})
            await pulls.resolve_thread(ctx, pr_id, int(resolution[1]), _bool(doc, "resolved"))
            return 200, {"resolved": doc["resolved"]}
        suggestion = re.fullmatch(r"/review-comments/" + _ID + r"/apply-suggestion", rest)
        if suggestion:
            fields(doc, {"expected_head_sha"})
            sha = await pulls.apply_suggestion(
                ctx,
                pr_id,
                int(suggestion[1]),
                expected_head=_optional_sha(doc, "expected_head_sha"),
            )
            return 201, {"sha": sha}
        comment = re.fullmatch(r"/review-comments/" + _ID, rest)
        if comment and method == "PATCH":
            fields(doc, {"body"}, {"body"})
            await pulls.edit_review_comment(ctx, pr_id, int(comment[1]), doc.get("body"))
            return 200, {"id": int(comment[1]), "updated": True}
        if comment and method == "DELETE":
            fields(doc, set())
            await pulls.delete_review_comment(ctx, pr_id, int(comment[1]))
            return 200, {"deleted": True}
        if rest == "/viewed-files":
            fields(doc, {"path", "viewed"}, {"path", "viewed"})
            await pulls.set_file_viewed(ctx, pr_id, cast(str, doc["path"]), _bool(doc, "viewed"))
            return 200, {"path": doc["path"], "viewed": doc["viewed"]}
    except pulls.PullError as exc:
        raise _error(exc) from None
    raise APIError(405, "method_not_allowed", "Mutation endpoint is not supported.")
