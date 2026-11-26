"""Pull request pages: conversation, commits, checks and the reviewable Files changed view.

The web handlers here are thin: every state change goes through :mod:`pygithost.pulls`,
the same service the REST API uses.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import parse_qs, quote, urlencode, urlparse

from . import diffview, merging, pull_store, pulls
from .octicons import octicon
from .pull_store import Review, Thread
from .rendering import SafeHTML, html_t, join_html, safe_html, str_t

if TYPE_CHECKING:
    from .application import GitHTTPHandler

TABS = ("conversation", "commits", "checks", "files")
# Review and lifecycle form actions under /r/{owner}/{repo}/pulls/{id}/ (merge has its
# own route). api/parity.py maps each one to its REST endpoint.
ACTIONS = (
    "update-branch",
    "draft",
    "base",
    "viewed",
    "reviewers/add",
    "reviewers/remove",
    "head-branch/delete",
    "head-branch/restore",
    "review-comments",
    r"review-comments/\d+/edit",
    r"review-comments/\d+/delete",
    r"review-comments/\d+/apply-suggestion",
    r"threads/\d+/replies",
    r"threads/\d+/resolve",
    r"threads/\d+/unresolve",
    "reviews",
    "reviews/discard",
    r"reviews/\d+/dismiss",
)
ACTION_ROUTE = re.compile(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/(" + "|".join(ACTIONS) + r")$")
METHOD_LABELS = {
    "merge": "Create a merge commit",
    "squash": "Squash and merge",
    "rebase": "Rebase and merge",
    "ff": "Fast-forward",
}
METHOD_HELP = {
    "merge": "All commits from this branch will be added to the base branch via a merge commit.",
    "squash": "The commits from this branch will be combined into one commit in the base branch.",
    "rebase": "The commits from this branch will be rebased and added to the base branch.",
    "ff": "The base branch will be moved to the head commit; no new commit is created.",
}
MESSAGES = {
    "merged": "Pull request merged.",
    "review": "Review submitted.",
    "review_discarded": "Pending review discarded.",
    "comment": "Comment added.",
    "review_comment": "Comment added to your pending review.",
    "reply": "Reply added.",
    "resolved": "Conversation resolved.",
    "unresolved": "Conversation unresolved.",
    "comment_updated": "Comment updated.",
    "comment_deleted": "Comment deleted.",
    "suggestion": "Suggestion committed to the head branch.",
    "reviewers": "Review requested.",
    "reviewer_removed": "Review request removed.",
    "draft": "Converted to draft.",
    "ready": "Marked as ready for review.",
    "base": "Base branch changed.",
    "updated": "Branch updated with the latest base branch changes.",
    "dismissed": "Review dismissed.",
    "branch_deleted": "Branch deleted.",
    "branch_restored": "Branch restored.",
}
STATE_ICONS = {
    "approved": ("check", "review-state-approved", "Approved"),
    "changes_requested": ("x", "review-state-changes", "Changes requested"),
    "commented": ("comment", "review-state-commented", "Commented"),
    "dismissed": ("circle-slash", "review-state-dismissed", "Dismissed"),
    "pending": ("clock", "review-state-pending", "Pending"),
}


def _app() -> Any:
    from . import application

    return application


def context(h: GitHTTPHandler, owner: str, repo: str) -> pulls.Context:
    app = _app()
    known = bool(app.REQUIRE_AUTH) and h.remote_user_id is not None
    actor = pulls.Actor(
        user_id=h.remote_user_id if known else None,
        username=h.remote_user if known else None,
        # Without sign-in the IP allowlist is the boundary, as elsewhere in the UI.
        is_admin=bool(h.remote_is_admin) or not app.REQUIRE_AUTH,
        can_write=bool(app._has_write_scope(h)),
        known=known,
        viewer=("u:" + str(h.remote_user_id)) if known else ("ip:" + h._client_ip()),
    )
    return pulls.Context(
        server=cast(pulls.ServerLike, h.server),
        owner=owner,
        repo=repo,
        repo_git=app._repo_bare_path(owner, repo),
        actor=actor,
    )


_SUGGESTION_FENCE = re.compile(r"(?ms)^[ \t]*```suggestion[^\n]*\n.*?^[ \t]*```[ \t]*$\n?")


def _without_suggestion(body: str) -> str:
    """Comment text without its suggestion block (shown as a suggested-change box)."""
    return _SUGGESTION_FENCE.sub("", body, count=1).strip("\n")


def _who(name: str | None) -> str:
    # No recorded user: the anonymous local user (sign-in disabled) or a deleted account.
    return name or "anonymous"


def _when(value: object) -> SafeHTML:
    app = _app()
    text = str(value or "")
    return safe_html(html_t(t'<time title="{text}">{app._relative_time(text) or text}</time>'))


def _avatar(name: str | None) -> SafeHTML:
    app = _app()
    return safe_html(
        html_t(
            t'<span class="avatar avatar-sm" aria-hidden="true">{app._initials(_who(name))}</span>'
        )
    )


def _state_badge(state: str) -> SafeHTML:
    icon, cls, label = STATE_ICONS.get(state, STATE_ICONS["commented"])
    return safe_html(
        html_t(t'<span class="review-state {cls}" title="{label}">{octicon(icon)}</span>')
    )


def _pr_state_pill(pr: pulls.PullRequest) -> SafeHTML:
    if pr["state"] == "open" and pr["draft"]:
        return safe_html(
            html_t(t'<span class="pill pill-draft">{octicon("git-pull-request")}Draft</span>')
        )
    icon = {"open": "git-pull-request", "merged": "git-merge", "closed": "git-pull-request-closed"}
    return safe_html(
        html_t(
            t'<span class="pill pill-{pr["state"]}">{octicon(icon.get(pr["state"], "git-pull-request"))}{pr["state"].capitalize()}</span>'
        )
    )


# ---------------------------------------------------------------- threads


def _snippet(lines: Sequence[str] | None, thread: Thread) -> SafeHTML:
    """A few lines of code above the commented line, like GitHub's conversation view."""
    if not lines:
        return safe_html("")
    end = min(thread["line"], len(lines))
    start = max(1, (thread["start_line"] or end) - 3)
    rows = [
        html_t(
            t'<tr class="{"diff-selected" if n >= (thread["start_line"] or end) else ""}"><td class="diff-num">{n}</td><td class="diff-code-cell"><code class="diff-code">{lines[n - 1]}</code></td></tr>'
        )
        for n in range(start, end + 1)
    ]
    return safe_html(
        html_t(t'<table class="diff-table diff-unified thread-snippet">{join_html(rows)}</table>')
    )


def render_thread(
    ctx: pulls.Context,
    pr: pulls.PullRequest,
    base_url: str,
    thread: Thread,
    location: pulls.Location,
    *,
    pending_review: bool,
    show_path: bool,
    snippet: SafeHTML | None = None,
    current_lines: Sequence[str] | None = None,
) -> SafeHTML:
    pr_url = f"{base_url}/pulls/{pr['id']}"
    comments: list[str] = []
    for comment in thread["comments"]:
        own = (
            comment["author_user_id"] == ctx.actor.user_id
            if ctx.actor.known
            else comment["author_user_id"] is None
        )
        controls: list[str] = []
        suggestion = diffview.extract_suggestion(comment["body"])
        if suggestion is not None and current_lines is not None and not location["outdated"]:
            end = location["line"] or thread["line"]
            span = thread["line"] - (thread["start_line"] or thread["line"])
            original = list(current_lines[max(0, end - span - 1) : end])
            controls.append(str(diffview.render_suggestion(original, suggestion)))
            if (
                ctx.actor.can_write
                and pr["state"] == "open"
                and not comment["pending"]
                and thread["side"] == "RIGHT"
            ):
                controls.append(
                    html_t(
                        t'<form method="POST" action="{pr_url}/review-comments/{comment["id"]}/apply-suggestion" class="inline-form"><input type="hidden" name="expected_head" value="{pr["head_sha"] or ""}"><button type="submit" class="btn-sm">Commit suggestion</button></form>'
                    )
                )
        manage = safe_html("")
        if own or ctx.actor.is_admin:
            manage = safe_html(
                html_t(
                    t"""<details class="review-comment-menu"><summary aria-label="Comment actions">{octicon("kebab-horizontal")}</summary><div class="review-comment-menu-body">
<form method="POST" action="{pr_url}/review-comments/{comment["id"]}/edit" class="review-edit-form"><textarea name="body" required>{comment["body"]}</textarea><button type="submit" class="btn-sm">Update comment</button></form>
<form method="POST" action="{pr_url}/review-comments/{comment["id"]}/delete" onsubmit="return confirm('Delete this comment?')"><button type="submit" class="danger btn-sm">Delete</button></form></div></details>"""
                )
            )
        pending = (
            safe_html('<span class="pill pill-pending">Pending</span>')
            if comment["pending"]
            else safe_html("")
        )
        edited = safe_html(' <span class="muted">(edited)</span>') if comment["edited_at"] else ""
        comments.append(
            html_t(
                t"""<div class="review-comment" id="discussion_r{comment["id"]}"><div class="review-comment-header">{_avatar(comment["author"])}<b>{_who(comment["author"])}</b> <span class="muted">{_when(comment["created_at"])}</span>{edited} {pending}{manage}</div>
<div class="review-comment-body md-body">{_without_suggestion(comment["body"]) if suggestion is not None else comment["body"]}</div>{join_html(controls)}</div>"""
            )
        )
    outdated = (
        safe_html('<span class="thread-outdated">Outdated</span>')
        if location["outdated"]
        else safe_html("")
    )
    lines = (
        f"lines {thread['start_line']}–{thread['line']}"
        if thread["start_line"]
        else f"line {thread['line']}"
    )
    header = safe_html("")
    if show_path:
        header = safe_html(
            html_t(
                t'<div class="review-thread-header"><code>{thread["path"]}</code> <span class="muted">{lines}</span> {outdated}</div>'
            )
        )
    elif location["outdated"]:
        header = safe_html(html_t(t'<div class="review-thread-header">{outdated}</div>'))
    # Replies stay possible on closed and merged pull requests.
    reply_form = safe_html(
        html_t(
            t"""<div class="review-thread-actions"><button type="button" class="diff-reply-toggle btn-sm">Reply…</button>
<div class="diff-reply-form" hidden>{diffview.comment_form(action=pr_url + "/threads/" + str(thread["id"]) + "/replies", review_pending=pending_review, reply_to_thread=thread["id"])}</div>"""
        )
    )
    verb = "unresolve" if thread["resolved"] else "resolve"
    label = "Unresolve conversation" if thread["resolved"] else "Resolve conversation"
    resolve = safe_html(
        html_t(
            t'<form method="POST" action="{pr_url}/threads/{thread["id"]}/{verb}" class="inline-form"><button type="submit" class="btn-sm secondary">{label}</button></form></div>'
        )
    )
    resolved_note = (
        safe_html(
            html_t(
                t'<summary class="thread-resolved-summary">{octicon("check")} {_who(thread["resolved_by"])} marked this conversation as resolved. <code>{thread["path"]}</code></summary>'
            )
        )
        if thread["resolved"]
        else safe_html("")
    )
    inner = html_t(
        t"""{header}{snippet or safe_html("")}<div class="review-thread-comments">{join_html(comments)}</div>{reply_form}{resolve}"""
    )
    if thread["resolved"]:
        return safe_html(
            html_t(
                t'<details class="review-thread thread-resolved" id="thread-{thread["id"]}">{resolved_note}{safe_html(inner)}</details>'
            )
        )
    return safe_html(
        html_t(t'<div class="review-thread" id="thread-{thread["id"]}">{safe_html(inner)}</div>')
    )


# ---------------------------------------------------------------- page pieces


def _review_entry(review: Review, threads_html: Sequence[str]) -> str:
    verbs = {
        "approved": "approved these changes",
        "changes_requested": "requested changes",
        "commented": "reviewed",
        "dismissed": "reviewed (dismissed)",
    }
    body = (
        safe_html(html_t(t'<div class="md-body review-body">{review["body"]}</div>'))
        if review["body"].strip()
        else safe_html("")
    )
    dismissed = (
        safe_html(
            html_t(
                t'<p class="muted review-dismissed">Dismissed by {_who(review["dismissed_by"])}: {review["dismiss_reason"]}</p>'
            )
        )
        if review["state"] == "dismissed"
        else safe_html("")
    )
    return html_t(
        t"""<div class="timeline-item timeline-review" id="review-{review["id"]}">{_state_badge(review["state"])}
<div class="timeline-review-card"><div class="timeline-review-head">{_avatar(review["author"])}<b>{_who(review["author"])}</b> {verbs.get(review["state"], "reviewed")} <span class="muted">{_when(review["submitted_at"])}</span></div>{body}{dismissed}{join_html(threads_html)}</div></div>"""
    )


EVENT_TEXT = {
    "closed": ("git-pull-request-closed", "closed this pull request"),
    "reopened": ("git-pull-request", "reopened this pull request"),
    "merged": ("git-merge", "merged this pull request"),
    "ready_for_review": ("check", "marked this pull request as ready for review"),
    "converted_to_draft": ("git-pull-request", "converted this pull request to draft"),
    "head_ref_deleted": ("trash", "deleted the head branch"),
    "head_ref_restored": ("git-branch", "restored the head branch"),
    "head_ref_force_pushed": ("git-commit", "force-pushed the head branch"),
    "committed": ("git-commit", "pushed new commits"),
    "review_requested": ("person", "requested a review"),
    "review_request_removed": ("person", "removed a review request"),
    "review_dismissed": ("circle-slash", "dismissed a review"),
    "base_changed": ("git-branch", "changed the base branch"),
}


def _event_entry(event: Mapping[str, Any], base_url: str) -> str:
    kind = str(event["kind"])
    if kind == "review_comment":
        return ""
    icon, text = EVENT_TEXT.get(kind, ("dot-fill", kind.replace("_", " ")))
    if icon not in (
        "check",
        "git-pull-request-closed",
        "git-pull-request",
        "git-merge",
        "trash",
        "git-branch",
        "git-commit",
        "person",
        "circle-slash",
        "dot-fill",
    ):
        icon = "dot-fill"
    data = event.get("data") or {}
    detail = ""
    if kind == "base_changed":
        detail = f" from {data.get('from', '')} to {data.get('to', '')}"
    elif kind in ("review_requested", "review_request_removed"):
        detail = f" from {data.get('reviewer', '')}"
    elif kind == "merged":
        detail = f" into {data.get('base', '')} ({data.get('method', '')})"
    elif kind == "review_dismissed":
        detail = f" by {data.get('reviewer') or 'Local user'}: {data.get('reason', '')}"
    commit = safe_html("")
    sha = str(data.get("sha") or data.get("after") or "")
    if sha:
        commit = safe_html(
            html_t(t' <a href="{base_url}/commit/{quote(sha)}"><code>{sha[:7]}</code></a>')
        )
    return html_t(
        t'<div class="timeline-item timeline-event"><span class="timeline-badge">{octicon(icon)}</span><span>{_avatar(event.get("actor"))}<b>{_who(event.get("actor"))}</b> {text}{detail}{commit} <span class="muted">{_when(event.get("created_at"))}</span></span></div>'
    )


def _merge_box(
    ctx: pulls.Context,
    pr: pulls.PullRequest,
    base_url: str,
    status: pulls.MergeStatus,
    behind: bool,
) -> SafeHTML:
    pr_url = f"{base_url}/pulls/{pr['id']}"
    if pr["state"] == "merged":
        delete = safe_html("")
        if ctx.actor.can_write and pr["head_sha"]:
            delete = safe_html(
                html_t(
                    t'<form method="POST" action="{pr_url}/head-branch/delete" class="inline-form"><button type="submit" class="secondary btn-sm">Delete branch</button></form>'
                )
            )
        elif ctx.actor.can_write and pr["head_deleted_sha"]:
            delete = safe_html(
                html_t(
                    t'<form method="POST" action="{pr_url}/head-branch/restore" class="inline-form"><button type="submit" class="secondary btn-sm">Restore branch</button></form>'
                )
            )
        return safe_html(
            html_t(
                t'<section class="merge-box merge-box-merged"><div class="merge-box-row">{octicon("git-merge")}<div><b>Pull request successfully merged and closed</b><p class="muted">Merged with <code>{pr["merge_method"] or ""}</code> as <code>{(pr["merge_commit"] or "")[:8]}</code>. You can safely delete the <code>{pr["head"]}</code> branch.</p></div>{delete}</div></section>'
            )
        )
    if pr["state"] == "closed":
        reopen = safe_html("")
        if ctx.actor.can_write:
            reopen = safe_html(
                html_t(
                    t'<form method="POST" action="{pr_url}/reopen" class="inline-form"><button class="secondary" type="submit">Reopen pull request</button></form>'
                )
            )
        delete = safe_html("")
        if ctx.actor.can_write and pr["head_sha"]:
            delete = safe_html(
                html_t(
                    t'<form method="POST" action="{pr_url}/head-branch/delete" class="inline-form"><button type="submit" class="secondary btn-sm">Delete branch</button></form>'
                )
            )
        return safe_html(
            html_t(
                t'<section class="merge-box merge-box-closed"><div class="merge-box-row">{octicon("git-pull-request-closed")}<div><b>Closed with unmerged commits</b></div>{reopen}{delete}</div></section>'
            )
        )
    checks: list[str] = []

    def row(ok: bool | None, title: str, detail: str | SafeHTML = "") -> None:
        icon = "check-circle-fill" if ok else ("x-circle-fill" if ok is False else "dot-fill")
        cls = "ok" if ok else ("bad" if ok is False else "neutral")
        checks.append(
            html_t(
                t'<div class="merge-check merge-check-{cls}">{octicon(icon)}<div><b>{title}</b><div class="muted">{detail}</div></div></div>'
            )
        )

    if status["required_approvals"]:
        row(
            status["approvals"] >= status["required_approvals"],
            f"{status['approvals']} of {status['required_approvals']} required approvals",
            ("Approved by " + ", ".join(status["approved_by"])) if status["approved_by"] else "",
        )
    elif status["approved_by"]:
        row(True, "Approved", "Approved by " + ", ".join(status["approved_by"]))
    else:
        row(None, "No approving reviews", "Reviews are optional for this branch.")
    if status["changes_requested_by"]:
        row(
            False if status["block_on_changes_requested"] else None,
            "Changes requested",
            "By " + ", ".join(status["changes_requested_by"]),
        )
    if status["unresolved_threads"] or status["require_conversation_resolution"]:
        row(
            not status["unresolved_threads"]
            if status["require_conversation_resolution"]
            else (None if status["unresolved_threads"] else True),
            f"{status['unresolved_threads']} unresolved conversation"
            + ("s" if status["unresolved_threads"] != 1 else ""),
            "Resolving conversations is required."
            if status["require_conversation_resolution"]
            else "",
        )
    ci = status["ci"]
    ci_state = ci.get("state")
    ci_link = (
        safe_html(html_t(t'<a href="{base_url}/ci/runs/{ci["run_id"]}">Details</a>'))
        if ci.get("run_id")
        else safe_html(html_t(t'<a href="{base_url}/ci">CI runs</a>'))
    )
    row(
        True if ci_state == "success" else (False if ci["required"] else None),
        "CI "
        + (str(ci_state).replace("_", " ") if ci_state else "not run for these commits")
        + (" (required)" if ci["required"] else ""),
        ci_link,
    )
    if status["mergeable"] == "conflict":
        detail: str | SafeHTML = safe_html(
            html_t(
                t'Conflicting files: <code>{", ".join(status["conflicts"][:10])}</code>. <a href="{pr_url}/resolve/ide">Resolve conflicts in the web IDE</a>'
            )
        )
        row(False, "Merge conflict: this branch has conflicts that must be resolved", detail)
    elif status["mergeable"] == "clean":
        row(True, "No conflicts with the base branch", "Merging can be performed automatically.")
    elif status["mergeable"] == "up_to_date":
        row(
            True,
            "This branch is already part of the base branch",
            "Merging records the pull request as merged.",
        )
    elif status["mergeable"] == "missing_branch":
        row(False, "A branch is missing", "Restore the head or base branch to merge.")
    update = safe_html("")
    if behind and ctx.actor.can_write and status["mergeable"] != "conflict":
        update = safe_html(
            html_t(
                t'<form method="POST" action="{pr_url}/update-branch" class="inline-form merge-update"><input type="hidden" name="expected_head" value="{pr["head_sha"] or ""}"><span class="muted">This branch is out-of-date with the base branch.</span> <button type="submit" class="secondary btn-sm">Update branch</button></form>'
            )
        )
    actions = safe_html("")
    if pr["draft"]:
        ready = safe_html("")
        if ctx.actor.can_write or (ctx.actor.known and pr["author_user_id"] == ctx.actor.user_id):
            ready = safe_html(
                html_t(
                    t'<form method="POST" action="{pr_url}/draft" class="inline-form"><input type="hidden" name="draft" value="0"><button type="submit">Ready for review</button></form>'
                )
            )
        actions = safe_html(
            html_t(
                t'<div class="merge-actions"><p><b>This pull request is still a work in progress.</b> Draft pull requests cannot be merged.</p>{ready}</div>'
            )
        )
    elif ctx.actor.can_write:
        options = join_html(
            [
                html_t(
                    t'<label class="merge-method"><input type="radio" name="merge_method" value="{m}"{" checked" if m == status["default_method"] else ""}><span><b>{METHOD_LABELS[m]}</b><small class="muted">{METHOD_HELP[m]}</small></span></label>'
                )
                for m in status["allowed_methods"]
            ]
        )
        disabled = "" if status["can_merge"] else " disabled"
        blocked = (
            safe_html(
                html_t(
                    t'<ul class="merge-blocked">{join_html([html_t(t"<li>{r}</li>") for r in status["blocked_reasons"]])}</ul>'
                )
            )
            if status["blocked_reasons"]
            else safe_html("")
        )
        actions = safe_html(
            html_t(
                t"""<form method="POST" action="{pr_url}/merge" class="merge-actions" id="merge-form">
<input type="hidden" name="expected_head" value="{pr["head_sha"] or ""}"><input type="hidden" name="expected_base" value="{pr["base_sha"] or ""}">
{blocked}<fieldset class="merge-methods"><legend>Merge method</legend>{options}</fieldset>
<details class="merge-message"><summary>Edit commit message</summary><label>Commit title (merge and squash)</label><input name="commit_title" maxlength="256" placeholder="Default title"><label>Extended description</label><textarea name="commit_message" maxlength="4000" placeholder="Default description"></textarea></details>
<label class="merge-delete"><input type="checkbox" name="delete_branch" value="1"> Delete <code>{pr["head"]}</code> after merging</label>
<div class="merge-buttons"><button type="submit" class="merge-button"{disabled}>{octicon("git-merge")}Confirm merge</button></div></form>"""
            )
        )
    else:
        actions = safe_html('<p class="muted">Only people with write access can merge.</p>')
    close = safe_html("")
    if ctx.actor.can_write:
        close = safe_html(
            html_t(
                t'<form method="POST" action="{pr_url}/close" class="inline-form merge-close"><button class="secondary btn-sm" type="submit">{octicon("git-pull-request-closed")}Close pull request</button></form>'
            )
        )
    tone = "ok" if status["can_merge"] else ("draft" if pr["draft"] else "blocked")
    return safe_html(
        html_t(
            t'<section class="merge-box merge-box-{tone}" id="merge-box"><div class="merge-checks">{join_html(checks)}</div>{update}{actions}{close}</section>'
        )
    )


def _sidebar(
    ctx: pulls.Context,
    pr: pulls.PullRequest,
    base_url: str,
    reviewers: Sequence[pull_store.ReviewRequest],
    states: Mapping[int | None, Review],
    users: Sequence[tuple[int, str]],
    branches: Sequence[str],
    totals: tuple[int, int, int],
) -> SafeHTML:
    pr_url = f"{base_url}/pulls/{pr['id']}"
    can_manage = ctx.actor.can_write or (
        ctx.actor.known and pr["author_user_id"] == ctx.actor.user_id
    )
    rows: list[str] = []
    requested_ids = {r["user_id"] for r in reviewers}
    for request in reviewers:
        remove = safe_html("")
        if can_manage and pr["state"] == "open":
            remove = safe_html(
                html_t(
                    t'<form method="POST" action="{pr_url}/reviewers/remove" class="inline-form"><input type="hidden" name="reviewer" value="{request["login"]}"><button type="submit" class="link-button" aria-label="Remove {request["login"]}">{octicon("x")}</button></form>'
                )
            )
        rows.append(
            html_t(
                t"<li>{_avatar(request['login'])}<span>{request['login']}</span>{_state_badge('pending')}{remove}</li>"
            )
        )
    for reviewer, review in states.items():
        if reviewer in requested_ids:
            continue
        rows.append(
            html_t(
                t"<li>{_avatar(review['author'])}<span>{_who(review['author'])}</span>{_state_badge(review['state'])}</li>"
            )
        )
    picker = safe_html("")
    if can_manage and pr["state"] == "open":
        options = join_html(
            [
                html_t(t'<option value="{login}">{login}</option>')
                for uid, login in users
                if uid != pr["author_user_id"] and uid not in requested_ids
            ]
        )
        picker = safe_html(
            html_t(
                t'<form method="POST" action="{pr_url}/reviewers/add" class="sidebar-form"><select name="reviewer" aria-label="Request a reviewer" required><option value="">Request a review…</option>{options}</select><button type="submit" class="btn-sm">Request</button></form>'
            )
        )
    reviewers_html = (
        safe_html(html_t(t'<ul class="sidebar-reviewers">{join_html(rows)}</ul>'))
        if rows
        else safe_html('<p class="muted">No reviews</p>')
    )
    draft_form = safe_html("")
    base_form = safe_html("")
    if can_manage and pr["state"] == "open":
        if not pr["draft"]:
            draft_form = safe_html(
                html_t(
                    t'<form method="POST" action="{pr_url}/draft" class="sidebar-form"><input type="hidden" name="draft" value="1"><button type="submit" class="link-button">Convert to draft</button></form>'
                )
            )
        base_options = join_html(
            [
                html_t(t'<option value="{b}"{" selected" if b == pr["base"] else ""}>{b}</option>')
                for b in branches
                if b != pr["head"]
            ]
        )
        base_form = safe_html(
            html_t(
                t'<details class="sidebar-edit"><summary>Edit</summary><form method="POST" action="{pr_url}/base" class="sidebar-form"><select name="base" aria-label="Base branch">{base_options}</select><button type="submit" class="btn-sm">Change base</button></form></details>'
            )
        )
    commits, adds, dels = totals
    return safe_html(
        html_t(
            t"""<aside class="review-sidebar pr-sidebar" aria-label="Pull request details">
<section><h3>Reviewers</h3>{reviewers_html}{picker}</section>
<section><h3>Branches</h3><p><code>{pr["head"]}</code> → <code>{pr["base"]}</code></p>{base_form}<p class="muted"><code>{(pr["head_sha"] or "")[:8]}</code> · <code>{(pr["base_sha"] or "")[:8]}</code></p></section>
<section><h3>Changes</h3><p>{commits} commits · <span class="add">+{adds}</span> <span class="del">−{dels}</span></p></section>
{draft_form}</aside>"""
        )
    )


async def _thread_html_by_location(
    ctx: pulls.Context,
    pr: pulls.PullRequest,
    base_url: str,
    items: Sequence[tuple[Thread, pulls.Location]],
    pending_review: bool,
) -> dict[str, dict[tuple[str, int], SafeHTML]]:
    """Current (not outdated) threads per file, keyed by (side, line) for the diff."""
    result: dict[str, dict[tuple[str, int], list[str]]] = {}
    lines_cache: dict[str, list[str] | None] = {}
    for thread, location in items:
        if location["outdated"] or location["line"] is None:
            continue
        current = None
        if thread["side"] == "RIGHT" and pr["head_sha"]:
            if thread["path"] not in lines_cache:
                lines_cache[thread["path"]] = await asyncio.to_thread(
                    merging.file_lines, ctx.repo_git, pr["head_sha"], thread["path"]
                )
            current = lines_cache[thread["path"]]
        html = render_thread(
            ctx,
            pr,
            base_url,
            thread,
            location,
            pending_review=pending_review,
            show_path=False,
            current_lines=current,
        )
        result.setdefault(thread["path"], {}).setdefault(
            (thread["side"], location["line"]), []
        ).append(str(html))
    return {
        path: {key: join_html(value) for key, value in by_line.items()}
        for path, by_line in result.items()
    }


async def _diff_text(repo_git: str, base: str, head: str, ignore_ws: bool) -> tuple[str, bool]:
    app = _app()
    args = ["diff", "--no-color", "-M", "--no-ext-diff", "--no-textconv"]
    if ignore_ws:
        args.append("-w")
    args += [base + ".." + head]
    code, out, err = await app._run_git(repo_git, args)
    if code != 0:
        return "", False
    limit = int(app.PR_PATCH_MAX_BYTES)
    if len(out) > limit:
        return out[:limit].decode("utf-8", "replace"), True
    return out.decode("utf-8", "replace"), False


# ---------------------------------------------------------------- the page


async def render(
    h: GitHTTPHandler,
    owner: str,
    repo: str,
    pr_id: int,
    notice: str = "",
    notice_kind: str = "ok",
    status_code: int = 200,
) -> None:
    app = _app()
    ctx = context(h, owner, repo)
    try:
        pr = await pulls.load(ctx, pr_id)
    except pulls.PullError:
        return await h._not_found()
    base_url = str_t(t"/r/{quote(owner, safe='')}/{quote(repo, safe='')}")
    pr_url = f"{base_url}/pulls/{pr_id}"
    params = parse_qs(urlparse(h.path).query or "")
    view = (params.get("tab") or [""])[0]
    if view not in TABS:
        view = "files" if "file" in params else "commits" if "page" in params else "conversation"
    message = MESSAGES.get((params.get("msg") or [""])[0], "")
    if message and not notice:
        notice, notice_kind = message, "ok"
    head, base_sha, merge_base = pr["head_sha"], pr["base_sha"], pr["merge_base"]
    commit_total: int | None = 0
    if head and base_sha and head != base_sha:
        commit_total = await app._git_commit_count(ctx.repo_git, base_sha + ".." + head)
    changed = (
        await app._git_diff_files(ctx.repo_git, merge_base, head)
        if merge_base and head and merge_base != head
        else []
    )
    adds = sum(f["added"] for f in changed)
    dels = sum(f["deleted"] for f in changed)
    pending = await asyncio.to_thread(pull_store.pending_review, pr_id, ctx.actor.user_id)
    pending_count = (
        await asyncio.to_thread(pull_store.review_comment_count, pending["id"]) if pending else 0
    )
    thread_items = await pulls.threads(ctx, pr)
    comment_count = await asyncio.to_thread(database_comment_count, pr_id) + sum(
        len(t["comments"]) for t, _loc in thread_items
    )

    if view == "conversation":
        panel = await _conversation(
            h, ctx, pr, base_url, thread_items, pending is not None, (commit_total or 0, adds, dels)
        )
    elif view == "commits":
        panel = await _commits(h, ctx, pr, base_url, params, commit_total)
    elif view == "checks":
        status = await pulls.merge_status(ctx, pr)
        ci = status["ci"]
        link = (
            safe_html(html_t(t'<a href="{base_url}/ci/runs/{ci["run_id"]}">View check run</a>'))
            if ci.get("run_id")
            else safe_html(html_t(t'<a href="{base_url}/ci">View CI runs</a>'))
        )
        panel = html_t(
            t'<section class="box pr-check-panel"><h2>CI checks</h2><p>CI is {"required" if ci["required"] else "informational"}: {str(ci.get("state") or "not run for current commits").replace("_", " ")}.</p>{link}</section>'
        )
    else:
        panel = await _files(h, ctx, pr, base_url, params, thread_items, pending, pending_count)

    notice_html = (
        safe_html(
            html_t(
                t'<div class="{"ok" if notice_kind == "ok" else "warn"}" role="status" style="margin-bottom:12px">{notice}</div>'
            )
        )
        if notice
        else safe_html("")
    )
    review_banner = safe_html("")
    if pending:
        review_banner = safe_html(
            html_t(
                t'<div class="review-pending-banner">{octicon("clock")} You have a pending review with {pending_count} comment{"s" if pending_count != 1 else ""}. <a href="{pr_url}?tab=files#review-submit">Finish your review</a></div>'
            )
        )
    tabs = join_html(
        html_t(
            t'''<a href="{pr_url + ("?tab=" + key if key != "conversation" else "")}"{safe_html(' aria-current="page"' if view == key else "")}>{label}{safe_html(html_t(t"<span>{count}</span>")) if count is not None else safe_html("")}</a>'''
        )
        for key, label, count in (
            ("conversation", "Conversation", comment_count),
            ("commits", "Commits", commit_total),
            ("checks", "Checks", None),
            ("files", "Files changed", len(changed)),
        )
    )
    title_edit = safe_html("")
    if pr["state"] == "open" and ctx.actor.can_write:
        title_edit = safe_html(
            html_t(
                t'<details class="pr-title-edit"><summary class="btn btn-sm">Edit</summary><form method="POST" action="{pr_url}/update" class="pr-update-form"><input name="title" value="{pr["title"]}" required maxlength="256" aria-label="Title"><input type="hidden" name="body" value="{pr["body"]}"><button type="submit" class="btn-sm">Save</button></form></details>'
            )
        )
    verb = "merged" if pr["state"] == "merged" else "wants to merge"
    can_edit = ctx.actor.can_write and bool(head)
    body_html = html_t(
        t"""{app._repo_tabs(base_url, "pulls")}<div class="review-breadcrumb"><a href="{base_url}/pulls">Pull requests</a> <span>/</span> #{pr_id}</div>
<header class="pr-detail-header"><div><h2>{pr["title"]} <span>#{pr_id}</span></h2>
<div class="pr-detail-meta">{_pr_state_pill(pr)} <strong>{_who(pr["author"])}</strong> {verb} {commit_total if commit_total is not None else "?"} commit{"s" if commit_total != 1 else ""} into <code>{pr["base"]}</code> from <code>{pr["head"]}</code></div></div>
<div class="pr-header-actions">{title_edit}{app._repo_code_menu(owner, repo, pr["head"], can_edit=can_edit)}</div></header>
{notice_html}{review_banner}<nav class="review-section-nav pr-detail-tabs" aria-label="Pull request views">{tabs}</nav>{safe_html(panel)}"""
    )
    assets = safe_html(
        '<link rel="stylesheet" href="/static/pulls.css"><script src="/static/pulls.js" defer></script>'
    )
    editor = h._issue_editor_assets() if view in ("conversation", "files") else safe_html("")
    await app._send_html(
        h.request,
        status_code,
        app._html_page(
            str_t(t"PR #{pr_id} · {owner}/{repo}"),
            safe_html(
                html_t(
                    t'<main class="repo-page review-page review-detail">{safe_html(body_html)}{assets}{editor}</main>'
                )
            ),
            wide=view == "files",
        ),
    )


def database_comment_count(pr_id: int) -> int:
    from .database import db_pr_comment_count

    return int(db_pr_comment_count(pr_id))


async def _conversation(
    h: GitHTTPHandler,
    ctx: pulls.Context,
    pr: pulls.PullRequest,
    base_url: str,
    thread_items: Sequence[tuple[Thread, pulls.Location]],
    pending_review: bool,
    totals: tuple[int, int, int],
) -> str:
    app = _app()
    pr_url = f"{base_url}/pulls/{pr['id']}"
    items = await pulls.timeline(ctx, pr)
    by_review: dict[int | None, list[tuple[Thread, pulls.Location]]] = {}
    for thread, location in thread_items:
        review_id = thread["comments"][0]["review_id"] if thread["comments"] else None
        by_review.setdefault(review_id, []).append((thread, location))
    snippet_cache: dict[tuple[str, str], list[str] | None] = {}

    async def thread_block(thread: Thread, location: pulls.Location) -> str:
        commit = thread["commit_sha"] if thread["side"] == "RIGHT" else thread["base_sha"]
        key = (commit, thread["path"])
        if key not in snippet_cache:
            snippet_cache[key] = (
                await asyncio.to_thread(merging.file_lines, ctx.repo_git, commit, thread["path"])
                if commit
                else None
            )
        current = None
        if thread["side"] == "RIGHT" and pr["head_sha"] and not location["outdated"]:
            current = await asyncio.to_thread(
                merging.file_lines, ctx.repo_git, pr["head_sha"], thread["path"]
            )
        return str(
            render_thread(
                ctx,
                pr,
                base_url,
                thread,
                location,
                pending_review=pending_review,
                show_path=True,
                snippet=_snippet(snippet_cache[key], thread),
                current_lines=current,
            )
        )

    entries: list[str] = []
    viewer_admin = ctx.actor.is_admin
    for item in items:
        if item["type"] == "comment":
            own = (
                item["author_user_id"] == ctx.actor.user_id
                if ctx.actor.known
                else ctx.actor.can_write
            )
            controls = safe_html("")
            if own or viewer_admin:
                controls = safe_html(
                    html_t(
                        t'<form method="POST" action="{pr_url}/comments/{item["id"]}/delete" class="pr-comment-actions" onsubmit="return confirm(\'Delete this comment?\')"><button class="danger btn-sm" type="submit">Delete</button></form>'
                    )
                )
            edited = " (edited)" if item.get("edited_at") else ""
            entries.append(
                html_t(
                    t'<div class="timeline-item timeline-comment" id="issuecomment-{item["id"]}"><div class="pr-comment"><div class="pr-comment-head">{_avatar(item["author"])}<b>{_who(item["author"])}</b> <span class="muted">commented {_when(item["created_at"])}{edited}</span>{controls}</div><div class="pr-comment-body md-body">{item["body"]}</div></div></div>'
                )
            )
        elif item["type"] == "review":
            blocks = [await thread_block(t, loc) for t, loc in by_review.get(item["id"], [])]
            entries.append(_review_entry(cast(Review, item), blocks))
        else:
            if item["kind"] == "review_comment":
                thread_id = (item.get("data") or {}).get("thread_id")
                for thread, location in by_review.get(None, []):
                    if thread["id"] == thread_id:
                        entries.append(
                            html_t(
                                t'<div class="timeline-item timeline-review">{_state_badge("commented")}<div class="timeline-review-card"><div class="timeline-review-head">{_avatar(thread["comments"][0]["author"])}<b>{_who(thread["comments"][0]["author"])}</b> commented on <code>{thread["path"]}</code> <span class="muted">{_when(item["created_at"])}</span></div>{safe_html(await thread_block(thread, location))}</div></div>'
                            )
                        )
                continue
            entries.append(_event_entry(item, base_url))
    status = await pulls.merge_status(ctx, pr)
    behind = bool(
        pr["state"] == "open"
        and pr["base_sha"]
        and pr["merge_base"]
        and pr["merge_base"] != pr["base_sha"]
    )
    merge_box = _merge_box(ctx, pr, base_url, status, behind)
    reviewers = await asyncio.to_thread(pull_store.list_review_requests, pr["id"])
    states = await asyncio.to_thread(pull_store.reviewer_states, pr["id"])
    users = await asyncio.to_thread(pull_store.active_users)
    branches = await _branches(ctx.repo_git)
    description = (
        safe_html(html_t(t'<div class="md-body">{pr["body"]}</div>'))
        if pr["body"].strip()
        else safe_html('<p class="muted">No description provided.</p>')
    )
    desc_edit = safe_html("")
    if pr["state"] == "open" and ctx.actor.can_write:
        desc_edit = safe_html(
            html_t(
                t'<details class="pr-desc-edit"><summary>Edit description</summary><form method="POST" action="{pr_url}/update" class="pr-update-form pr-md-form"><input type="hidden" name="title" value="{pr["title"]}"><textarea name="body" data-markdown maxlength="{app.MARKDOWN_BODY_LIMIT}">{pr["body"]}</textarea><button type="submit" class="btn-sm">Save</button></form></details>'
            )
        )
    comment_form = safe_html('<p class="muted">Write scope is required to comment.</p>')
    if pr["state"] == "open" and ctx.actor.can_write:
        comment_form = safe_html(
            html_t(
                t'<form method="POST" action="{pr_url}/comments" class="pr-comment-form pr-md-form"><label>Add a comment</label><textarea name="body" data-markdown required maxlength="{app.MARKDOWN_BODY_LIMIT}" placeholder="Leave a comment… Markdown and image uploads supported"></textarea><button type="submit">Comment</button></form>'
            )
        )
    sidebar = _sidebar(ctx, pr, base_url, reviewers, states, users, branches, totals)
    return html_t(
        t"""<div class="review-layout pr-conversation-layout"><div class="review-main"><div class="timeline" id="discussion">
<div class="timeline-item timeline-comment"><article class="pr-comment pr-description"><div class="pr-comment-head">{_avatar(pr["author"])}<b>{_who(pr["author"])}</b> <span class="muted">opened this pull request {_when(pr["created_at"])}</span></div><div class="pr-comment-body">{description}{desc_edit}</div></article></div>
{join_html(entries) if entries else safe_html('<p class="muted timeline-empty">No comments yet.</p>')}</div>{merge_box}{comment_form}</div>{sidebar}</div>"""
    )


async def _branches(repo_git: str) -> list[str]:
    app = _app()
    code, out, _ = await app._run_git(
        repo_git, ["for-each-ref", "--format=%(refname:short)", "refs/heads"]
    )
    return sorted(out.decode("utf-8", "replace").split()) if code == 0 else []


async def _commits(
    h: GitHTTPHandler,
    ctx: pulls.Context,
    pr: pulls.PullRequest,
    base_url: str,
    params: Mapping[str, list[str]],
    total: int | None,
) -> str:
    app = _app()
    pr_url = f"{base_url}/pulls/{pr['id']}"
    page, size = app._page_number(params), app._page_size(params)
    commits: list[dict[str, str]] = []
    if pr["head_sha"] and pr["base_sha"] and pr["head_sha"] != pr["base_sha"]:
        if total is not None:
            page = app._clamp_page(page, total, size)
        commits = await app._git_list_commits(
            ctx.repo_git,
            pr["base_sha"] + ".." + pr["head_sha"],
            limit=size + 1,
            skip=(page - 1) * size,
        )
    pagination = app._pagination(
        pr_url, {"tab": "commits"}, page, len(commits) > size, total=total, per_page=size
    )
    rows = [
        html_t(
            t'<tr><td style="width:110px"><a href="{base_url}/commit/{quote(c["hash"])}"><code>{c["hash"][:8]}</code></a></td><td>{c["subject"]}</td><td class="muted">{c["author_name"]}</td><td class="muted"><small>{c["date"]}</small></td></tr>'
        )
        for c in commits[:size]
    ]
    table = (
        join_html(rows)
        if rows
        else safe_html('<tr><td class="muted">No commits (or branches not resolvable).</td></tr>')
    )
    return html_t(
        t'<section class="box pr-tab-panel" id="pr-commits"><h2>Commits</h2><div class="pr-commit-scroll"><table>{table}</table></div>{pagination}</section>'
    )


async def _files(
    h: GitHTTPHandler,
    ctx: pulls.Context,
    pr: pulls.PullRequest,
    base_url: str,
    params: Mapping[str, list[str]],
    thread_items: Sequence[tuple[Thread, pulls.Location]],
    pending: Review | None,
    pending_count: int,
) -> str:
    pr_url = f"{base_url}/pulls/{pr['id']}"
    mode = "split" if (params.get("diff") or [""])[0] == "split" else "unified"
    ignore_ws = (params.get("w") or [""])[0] == "1"
    head, merge_base = pr["head_sha"], pr["merge_base"]
    if not head or not merge_base:
        return '<section class="box" id="diff"><p class="muted">The head or base branch is unavailable.</p></section>'
    if head == merge_base:
        return '<section class="box" id="diff"><p class="muted">No changes: the branches point to the same commit.</p></section>'
    text, truncated = await _diff_text(ctx.repo_git, merge_base, head, ignore_ws)
    files = diffview.parse_unified_diff(text)
    selected = (params.get("file") or [""])[0]
    file_filter = safe_html("")
    if selected and any(f.path == selected for f in files):
        files = [f for f in files if f.path == selected]
        file_filter = safe_html(
            html_t(
                t'<p class="pr-file-filter">Showing <code>{selected}</code> only. <a class="pill" href="{pr_url}?tab=files">All files</a></p>'
            )
        )
    viewed = await pulls.viewed_paths(ctx, pr, [f.path for f in files])
    anchors = {f.path: diffview.file_anchor(f.path) for f in files}
    threads_by_file = await _thread_html_by_location(
        ctx, pr, base_url, thread_items, pending is not None
    )
    # Commenting is open to anyone who can see the PR, as on GitHub; merged PRs
    # accept single comments only (handled by the service).
    can_comment = pr["state"] != "closed"
    rendered = [
        str(
            diffview.render_file(
                f,
                anchor=anchors[f.path],
                mode=cast(Any, mode),
                threads=threads_by_file.get(f.path, {}),
                can_comment=can_comment,
                viewed=f.path in viewed,
            )
        )
        for f in files
    ]
    tree = diffview.render_file_tree(files, anchors=anchors, viewed=viewed)

    def link(**changes: str) -> str:
        query = {"tab": "files", "diff": mode, **({"w": "1"} if ignore_ws else {})}
        query.update(changes)
        query = {k: v for k, v in query.items() if v}
        return pr_url + "?" + urlencode(query)

    toolbar = html_t(
        t"""<div class="pr-files-toolbar"><div class="pr-files-stats"><b>{len(files)}</b> files · <span id="pr-viewed-count">{len(viewed)} / {len(files)} files viewed</span></div>
<div class="pr-files-controls"><a class="btn btn-sm diff-mode-link{" active" if mode == "unified" else ""}" href="{link(diff="unified")}">Unified</a><a class="btn btn-sm diff-mode-link{" active" if mode == "split" else ""}" href="{link(diff="split")}">Split</a>
<a class="btn btn-sm{" active" if ignore_ws else ""}" href="{link(w="" if ignore_ws else "1")}">{"Show whitespace" if ignore_ws else "Hide whitespace"}</a>
<button type="button" class="btn btn-sm" id="pr-expand-all">Expand all</button><button type="button" class="btn btn-sm" id="pr-collapse-all">Collapse all</button></div>
{_review_popover(ctx, pr, pr_url, pending, pending_count)}</div>"""
    )
    note = (
        safe_html('<p class="warn">The diff is too large to show completely.</p>')
        if truncated
        else safe_html("")
    )
    csrf = _app()._csrf_token.get()
    return html_t(
        t"""<div id="diff"></div><div id="pr-files" data-csrf="{csrf}" data-viewed-url="{pr_url}/viewed" data-comment-url="{pr_url}/review-comments" data-mode="{mode}">
{safe_html(toolbar)}{file_filter}{note}<div class="pr-files-layout"><nav class="pr-files-tree" aria-label="Changed files">{tree}</nav><div class="pr-files-list">{join_html(rendered)}</div></div>
{diffview.comment_form_template(action=pr_url + "/review-comments", review_pending=pending is not None)}</div>"""
    )


def _review_popover(
    ctx: pulls.Context,
    pr: pulls.PullRequest,
    pr_url: str,
    pending: Review | None,
    pending_count: int,
) -> SafeHTML:
    if pr["state"] != "open":
        return safe_html("")
    own = ctx.actor.known and pr["author_user_id"] == ctx.actor.user_id
    disabled = " disabled" if own else ""
    label = f"Finish your review ({pending_count})" if pending else "Review changes"
    discard = safe_html("")
    if pending:
        discard = safe_html(
            html_t(
                t'<form method="POST" action="{pr_url}/reviews/discard" class="inline-form" onsubmit="return confirm(\'Discard your pending review and its comments?\')"><button type="submit" class="link-button">Discard review</button></form>'
            )
        )
    return safe_html(
        html_t(
            t"""<details class="review-submit" id="review-submit"><summary class="btn btn-sm btn-primary">{label}</summary>
<div class="review-submit-body"><form method="POST" action="{pr_url}/reviews"><input type="hidden" name="commit_id" value="{pr["head_sha"] or ""}">
<label for="review-body">Leave a comment</label><textarea id="review-body" name="body" placeholder="Summary of your review"></textarea>
<label class="review-choice"><input type="radio" name="event" value="COMMENT" checked><span><b>Comment</b><small class="muted">Submit general feedback without explicit approval.</small></span></label>
<label class="review-choice"><input type="radio" name="event" value="APPROVE"{disabled}><span><b>Approve</b><small class="muted">Give your approval to merge these changes.</small></span></label>
<label class="review-choice"><input type="radio" name="event" value="REQUEST_CHANGES"{disabled}><span><b>Request changes</b><small class="muted">Submit feedback that must be addressed before merging.</small></span></label>
<button type="submit" class="btn-primary">Submit review</button></form>{discard}</div></details>"""
        )
    )


# ---------------------------------------------------------------- POST actions


async def handle_post(h: GitHTTPHandler, owner: str, repo: str, pr_id: int, action: str) -> None:
    """One dispatcher for the PR review/lifecycle forms (CSRF already verified)."""
    app = _app()
    ctx = context(h, owner, repo)
    form = await h._read_form_urlencoded()
    pr_url = f"/r/{quote(owner, safe='')}/{quote(repo, safe='')}/pulls/{pr_id}"
    tab = "conversation"
    anchor = ""
    try:
        parts = action.strip("/").split("/")
        if action == "merge":
            await pulls.merge(
                ctx,
                pr_id,
                method=form.get("merge_method") or None,
                expected_head=form.get("expected_head") or None,
                expected_base=form.get("expected_base") or None,
                title=form.get("commit_title") or None,
                message=form.get("commit_message") or None,
                delete_branch=form.get("delete_branch") == "1",
            )
            msg = "merged"
        elif action == "update-branch":
            await pulls.update_branch(ctx, pr_id, expected_head=form.get("expected_head") or None)
            msg = "updated"
        elif action == "draft":
            draft = form.get("draft") == "1"
            await pulls.set_draft(ctx, pr_id, draft)
            msg = "draft" if draft else "ready"
        elif action == "base":
            await pulls.change_base(ctx, pr_id, form.get("base", ""))
            msg = "base"
        elif action == "head-branch/delete":
            await pulls.delete_head_branch(ctx, pr_id)
            msg = "branch_deleted"
        elif action == "head-branch/restore":
            await pulls.restore_head_branch(ctx, pr_id)
            msg = "branch_restored"
        elif action == "reviewers/add":
            await pulls.request_reviewers(ctx, pr_id, [form.get("reviewer", "")])
            msg = "reviewers"
        elif action == "reviewers/remove":
            await pulls.remove_reviewer(ctx, pr_id, form.get("reviewer", ""))
            msg = "reviewer_removed"
        elif action == "review-comments":
            mode = form.get("mode") or "single"
            thread_id, _ = await pulls.add_review_comment(
                ctx,
                pr_id,
                path=form.get("path"),
                side=form.get("side") or "RIGHT",
                line=form.get("line"),
                start_line=form.get("start_line") or None,
                body=form.get("body"),
                mode=mode,
            )
            msg, tab, anchor = (
                "review_comment" if mode == "review" else "comment",
                "files",
                f"thread-{thread_id}",
            )
        elif len(parts) == 3 and parts[0] == "threads" and parts[2] == "replies":
            await pulls.reply(
                ctx, pr_id, int(parts[1]), form.get("body"), form.get("mode") or "single"
            )
            msg, anchor = "reply", f"thread-{parts[1]}"
            tab = form.get("tab") or _referrer_tab(h)
        elif len(parts) == 3 and parts[0] == "threads" and parts[2] in ("resolve", "unresolve"):
            await pulls.resolve_thread(ctx, pr_id, int(parts[1]), parts[2] == "resolve")
            msg, anchor = (
                ("resolved" if parts[2] == "resolve" else "unresolved"),
                f"thread-{parts[1]}",
            )
            tab = _referrer_tab(h)
        elif len(parts) == 3 and parts[0] == "review-comments" and parts[2] == "edit":
            await pulls.edit_review_comment(ctx, pr_id, int(parts[1]), form.get("body"))
            msg, anchor = "comment_updated", f"discussion_r{parts[1]}"
            tab = _referrer_tab(h)
        elif len(parts) == 3 and parts[0] == "review-comments" and parts[2] == "delete":
            await pulls.delete_review_comment(ctx, pr_id, int(parts[1]))
            msg = "comment_deleted"
            tab = _referrer_tab(h)
        elif len(parts) == 3 and parts[0] == "review-comments" and parts[2] == "apply-suggestion":
            await pulls.apply_suggestion(
                ctx, pr_id, int(parts[1]), expected_head=form.get("expected_head") or None
            )
            msg = "suggestion"
            tab = _referrer_tab(h)
        elif action == "reviews":
            await pulls.submit_review(
                ctx,
                pr_id,
                event=form.get("event") or "COMMENT",
                body=form.get("body", ""),
                commit_id=form.get("commit_id") or None,
            )
            msg = "review"
        elif action == "reviews/discard":
            await pulls.discard_pending_review(ctx, pr_id)
            msg, tab = "review_discarded", "files"
        elif len(parts) == 3 and parts[0] == "reviews" and parts[2] == "dismiss":
            await pulls.dismiss_review(ctx, pr_id, int(parts[1]), form.get("message", ""))
            msg = "dismissed"
        elif action == "viewed":
            await pulls.set_file_viewed(ctx, pr_id, form.get("path", ""), form.get("viewed") == "1")
            await app._send_response(
                h.request,
                200,
                json.dumps({"ok": True}).encode(),
                [
                    ("Content-Type", "application/json; charset=utf-8"),
                    ("Cache-Control", "no-store"),
                ],
            )
            return
        else:
            return await h._not_found()
    except pulls.PullError as exc:
        if action == "viewed":
            await app._send_response(
                h.request,
                exc.status,
                json.dumps({"error": exc.message}).encode(),
                [("Content-Type", "application/json; charset=utf-8")],
            )
            return
        if exc.status == 404 and exc.code == "not_found" and "Pull request" in exc.message:
            return await h._not_found()
        return await render(h, owner, repo, pr_id, exc.message, "warn", min(exc.status, 499))
    except ValueError:
        return await render(h, owner, repo, pr_id, "Invalid request.", "warn", 422)
    query = {"msg": msg}
    if tab != "conversation":
        query["tab"] = tab
    location = pr_url + "?" + urlencode(query) + (f"#{anchor}" if anchor else "")
    await app._send_redirect(h.request, location)


def _referrer_tab(h: GitHTTPHandler) -> str:
    referrer = h.headers.get("Referer") or ""
    tab = (parse_qs(urlparse(referrer).query).get("tab") or [""])[0]
    return tab if tab in TABS else "conversation"
