"""State-changing web forms and their REST equivalents.

tests/test_api_parity.py fails when a POST route is added to the web UI without an
entry here, or when an entry points at an endpoint the API does not document.
Paths are relative to ``/api/v1``. A reason string identifies a web-only route.
"""

from __future__ import annotations

Endpoint = tuple[str, str]  # (HTTP method, OpenAPI path)

_R = "/repos/{owner}/{repo}"
_P = _R + "/pulls/{id}"

# Keys are the literal path or the regex text used in GitHTTPHandler.do_POST.
UI_ROUTES: dict[str, list[Endpoint] | str] = {
    # ---- not repository actions (decided: no API for these)
    "LOGIN_PATH": "sign-in is a browser session flow",
    "/logout": "sign-out is a browser session flow",
    "/admin/settings/favicon": "server administration is web-only",
    "/admin/users/create": "server administration is web-only",
    "/admin/email": "server administration is web-only",
    "/admin/settings": "server administration is web-only",
    "/admin/email/test": "server administration is web-only",
    "/admin/users/reset": "server administration is web-only",
    "/admin/users/toggle": "server administration is web-only",
    "/tokens/create": "tokens cannot mint tokens",
    "/admin/token": "tokens cannot mint tokens",
    "/tokens/revoke": "tokens cannot manage tokens",
    r"^/r/([^/]+)/([^/]+)/ci/config$": "retired form: CI configuration lives in ci/config.json",
    # ---- repositories, files and branches
    "/create-repo": [("post", "/user/repos")],
    r"^/r/([^/]+)/([^/]+)/settings/delete$": [("delete", _R)],
    r"^/r/([^/]+)/([^/]+)/ide/commit$": [("post", _R + "/commits")],
    r"^/r/([^/]+)/([^/]+)/branches/create$": [("post", _R + "/branches")],
    r"^/r/([^/]+)/([^/]+)/branches/delete$": [("delete", _R + "/branches/{branch}")],
    # ---- issues
    r"^/r/([^/]+)/([^/]+)/issues/create$": [("post", _R + "/issues")],
    r"^/r/([^/]+)/([^/]+)/issues/(\d+)/comments$": [("post", _R + "/issues/{id}/comments")],
    r"^/r/([^/]+)/([^/]+)/issues/(\d+)/comments/(\d+)/delete$": [
        ("delete", _R + "/issues/{id}/comments/{comment_id}")
    ],
    r"^/r/([^/]+)/([^/]+)/issues/(\d+)/comments/(\d+)/edit$": [
        ("patch", _R + "/issues/{id}/comments/{comment_id}")
    ],
    r"^/r/([^/]+)/([^/]+)/issues/(\d+)/close$": [("patch", _R + "/issues/{id}")],
    r"^/r/([^/]+)/([^/]+)/issues/(\d+)/reopen$": [("patch", _R + "/issues/{id}")],
    r"^/r/([^/]+)/([^/]+)/issues/(\d+)/update$": [("patch", _R + "/issues/{id}")],
    # ---- discussions
    r"^/r/([^/]+)/([^/]+)/discussions/create$": [("post", _R + "/discussions")],
    r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/comments$": [
        ("post", _R + "/discussions/{id}/comments")
    ],
    r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/comments/(\d+)/delete$": [
        ("delete", _R + "/discussions/{id}/comments/{comment_id}")
    ],
    r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/comments/(\d+)/edit$": [
        ("patch", _R + "/discussions/{id}/comments/{comment_id}")
    ],
    r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/lock$": [("patch", _R + "/discussions/{id}")],
    r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/unlock$": [("patch", _R + "/discussions/{id}")],
    r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/answer/(\d+)$": [("patch", _R + "/discussions/{id}")],
    r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/unanswer/(\d+)$": [("patch", _R + "/discussions/{id}")],
    r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/update$": [("patch", _R + "/discussions/{id}")],
    # ---- pull requests
    r"^/r/([^/]+)/([^/]+)/pulls/create$": [("post", _R + "/pulls")],
    r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/close$": [("patch", _P)],
    r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/reopen$": [("patch", _P)],
    r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/update$": [("patch", _P)],
    r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/merge$": [("put", _P + "/merge")],
    r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/resolve$": [("post", _P + "/conflicts/resolution")],
    r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/resolve/ide/commit$": [
        ("post", _P + "/conflicts/resolution")
    ],
    r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/comments$": [("post", _P + "/comments")],
    r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/comments/(\d+)/delete$": [
        ("delete", _P + "/comments/{comment_id}")
    ],
    r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/comments/(\d+)/edit$": [
        ("patch", _P + "/comments/{comment_id}")
    ],
    # ---- CI
    r"^/r/([^/]+)/([^/]+)/ci/preferences$": [("put", _R + "/ci/variables")],
    r"^/r/([^/]+)/([^/]+)/ci/run$": [("post", _R + "/ci/runs")],
    r"^/r/([^/]+)/([^/]+)/ci/runs/(\d+)/(cancel|rerun|notify)$": [
        ("post", _R + "/ci/runs/{id}/cancel"),
        ("post", _R + "/ci/runs/{id}/rerun"),
        ("post", _R + "/ci/runs/{id}/notify"),
    ],
}

# pull_pages.ACTIONS (review and lifecycle forms) and their endpoints.
PULL_ACTIONS: dict[str, list[Endpoint]] = {
    "update-branch": [("put", _P + "/update-branch")],
    "draft": [("patch", _P)],
    "base": [("patch", _P)],
    "viewed": [("put", _P + "/viewed-files")],
    "reviewers/add": [("post", _P + "/requested_reviewers")],
    "reviewers/remove": [("delete", _P + "/requested_reviewers")],
    "head-branch/delete": [("delete", _P + "/head-branch")],
    "head-branch/restore": [("post", _P + "/head-branch/restore")],
    "review-comments": [("post", _P + "/threads")],
    r"review-comments/\d+/edit": [("patch", _P + "/review-comments/{comment_id}")],
    r"review-comments/\d+/delete": [("delete", _P + "/review-comments/{comment_id}")],
    r"review-comments/\d+/apply-suggestion": [
        ("post", _P + "/review-comments/{comment_id}/apply-suggestion")
    ],
    r"threads/\d+/replies": [("post", _P + "/threads/{thread_id}/replies")],
    r"threads/\d+/resolve": [("put", _P + "/threads/{thread_id}/resolution")],
    r"threads/\d+/unresolve": [("put", _P + "/threads/{thread_id}/resolution")],
    "reviews": [("post", _P + "/reviews")],
    "reviews/discard": [("delete", _P + "/reviews/pending")],
    r"reviews/\d+/dismiss": [("put", _P + "/reviews/{review_id}/dismissals")],
}
