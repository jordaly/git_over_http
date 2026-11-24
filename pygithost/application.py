import argparse
import asyncio
import base64
import contextlib
import gzip
import hashlib
import ipaddress
import json
import logging
import mimetypes
import os
import platform
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections.abc import Awaitable, Callable, Collection, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import formatdate
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, BinaryIO, ParamSpec, TypedDict, TypeVar, cast, overload
from urllib.parse import parse_qs, unquote, urlencode, urlparse

from hl_mappings import PRISM_LANGUAGE_BY_EXTENSION

from . import pr_resolver
from .ci import CIManager, protected_branch
from .ci import default_config as ci_default_config
from .ci_documentation import ci_configuration_guide
from .ci_email import load_settings as load_email_settings
from .ci_email import send_notification, validate_recipients
from .ci_email import validate_settings as validate_email_settings
from .ci_protection import prepare_hooks
from .config import AppConfig
from .context import AppContext
from .database import (
    _db_init,
    _ensure_dir,
    configure_retention_head_resolver,
    db_audit_append,
    db_ci_artifact_get,
    db_ci_artifacts_list,
    db_ci_config_get,
    db_ci_latest_run,
    db_ci_merge_check,
    db_ci_run_get,
    db_ci_run_metadata,
    db_ci_runs_list,
    db_ci_steps_get,
    db_create_session,
    db_create_token,
    db_create_user,
    db_discussion_comment_add,
    db_discussion_comment_count,
    db_discussion_comment_counts,
    db_discussion_comment_delete,
    db_discussion_comment_get,
    db_discussion_comment_list,
    db_discussion_comment_update,
    db_discussion_count,
    db_discussion_create,
    db_discussion_get,
    db_discussion_list,
    db_discussion_set_answer,
    db_discussion_set_locked,
    db_discussion_update_text,
    db_email_settings_set,
    db_ensure_default_admin,
    db_favicon_clear,
    db_favicon_get,
    db_favicon_set,
    db_get_user_by_id,
    db_issue_close,
    db_issue_comment_add,
    db_issue_comment_count,
    db_issue_comment_delete,
    db_issue_comment_get,
    db_issue_comment_list,
    db_issue_comment_update,
    db_issue_count,
    db_issue_create,
    db_issue_get,
    db_issue_list,
    db_issue_reopen,
    db_issue_update_text,
    db_list_tokens_for_user,
    db_list_users,
    db_pr_close,
    db_pr_comment_add,
    db_pr_comment_count,
    db_pr_comment_delete,
    db_pr_comment_get,
    db_pr_comment_list,
    db_pr_comment_update,
    db_pr_create,
    db_pr_get,
    db_pr_list,
    db_pr_mark_merged,
    db_pr_reopen,
    db_pr_update_text,
    db_prs_for_source,
    db_prs_for_target,
    db_reset_password,
    db_revoke_session,
    db_revoke_token,
    db_set_user_active,
    db_verify_password,
    db_verify_session,
    db_verify_token,
    db_verify_token_any_user,
)
from .database import (
    configure as configure_database,
)
from .database_types import CommentIdentityRow, DiscussionRow, IssueRow
from .languages import LanguageStat, repository_languages
from .logging_setup import access as log_access
from .logging_setup import configure_logging, safe_target
from .octicons import octicon
from .readme import render_readme
from .repo_templates import GITIGNORE_TEMPLATES, LICENSES, initial_files
from .repository_info import RepositoryOverview, repository_overview

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    # Compatibility globals populated by ``apply_config`` at import time.  They
    # mirror ``CONFIG_GLOBAL_MAP`` and are declared here so the rest of the
    # module can be checked without ``Any``-typed lookups.
    HOST: str
    PORT: int
    GIT_PROJECT_ROOT: str
    GIT_HTTP_BACKEND: str
    TRACE_LOG: str | None
    DB_PATH: str
    URL_PREFIX: str
    REQUIRE_AUTH: bool
    FILTER_IPS: bool
    REALM: str
    FLAT_OWNER_UI: str
    PR_PATCH_MAX_BYTES: int
    PRISM_DIFF_HIGHLIGHT_MAX_BYTES: int
    MAX_HEADER_BYTES: int
    READ_CHUNK: int
    SESSION_COOKIE_NAME: str
    SESSION_TTL_SECONDS: int
    SESSION_COOKIE_SECURE: bool
    LOGIN_PATH: str
    STATIC_URL_PREFIX: str
    STATIC_ROOT: str
    STATIC_CACHE_SECONDS: int
    STATIC_REQUIRES_AUTH: bool
    LOG_LEVEL: str
    LOG_FORMAT: str
    LOG_FILE: str | None
    LOG_MAX_BYTES: int
    LOG_BACKUP_COUNT: int
    ACCESS_LOG: bool
    AUDIT_LOG: bool
    ALLOWED_CLIENT_IPS: set[str]


_display_name = ContextVar("display_name", default="pygithost")
# Per-request view state used by the shared page shell (header menus and context).
_request_path: ContextVar[str] = ContextVar("request_path", default="")
_viewer: ContextVar[tuple[str | None, bool]] = ContextVar("viewer", default=(None, False))

_P = ParamSpec("_P")
_T = TypeVar("_T")


class CommitInfo(TypedDict):
    """Metadata for one commit produced by :func:`pygithost.repository_info.repository_overview`."""

    hash: str
    author: str
    date: str
    subject: str


class ChangedFile(TypedDict):
    """One entry from :func:`_git_diff_files`."""

    path: str
    added: int
    deleted: int
    kind: str


def _thread_call(func: Callable[_P, _T], /, *args: _P.args, **kwargs: _P.kwargs) -> tuple[_T]:
    """Keep executor results non-None, including database misses and void writes."""
    return (func(*args, **kwargs),)


def _ci_elapsed(start: str | None, end: str | None = None) -> str:
    if not start:
        return "—"
    try:
        begin = datetime.fromisoformat(start).replace(tzinfo=timezone.utc)
        finish = (
            datetime.fromisoformat(end).replace(tzinfo=timezone.utc)
            if end
            else datetime.now(timezone.utc)
        )
        seconds = max(0, int((finish - begin).total_seconds()))
        return f"{seconds // 60}m {seconds % 60}s"
    except ValueError:
        return "—"


def _relative_time(value: object) -> str:
    """Humanize Git ISO-8601 or SQLite UTC timestamps."""
    try:
        # Git emits 2026-11-02T14:59:40-04:00; SQLite emits 2026-11-02 14:59:40.
        stamp = datetime.fromisoformat(str(value).strip().replace(" ", "T", 1))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        seconds = max(0, int((datetime.now(timezone.utc) - stamp).total_seconds()))
    except ValueError, TypeError:
        return str(value) if value else "—"
    for unit, length in (
        ("year", 31536000),
        ("month", 2592000),
        ("week", 604800),
        ("day", 86400),
        ("hour", 3600),
        ("minute", 60),
    ):
        if seconds >= length:
            count = seconds // length
            return f"{count} {unit}{'s' if count != 1 else ''} ago"
    return "just now"


def _page_number(params: Mapping[str, list[str]]) -> int:
    value = (params.get("page") or ["1"])[0]
    return (
        max(1, min(1000000, int(value)))
        if value.isascii() and value.isdecimal() and len(value) <= 7
        else 1
    )


def _page_size(params: Mapping[str, list[str]], default: int = 25) -> int:
    value = (params.get("per_page") or [str(default)])[0]
    return int(value) if value in ("10", "25", "50", "100") else default


def _clamp_page(page: int, total: int, size: int) -> int:
    return min(page, max(1, (total + size - 1) // size))


def _pagination(
    base: str,
    params: Mapping[str, str | list[str]],
    page: int,
    has_next: bool,
    *,
    total: int | None = None,
    per_page: int = 25,
) -> SafeHTML:
    if total is not None:
        page = _clamp_page(page, total, per_page)
        has_next = page * per_page < total
    params = {
        key: value
        for key, value in params.items()
        if key not in ("page", "partial", "skip", "per_page")
    }
    pages = max(1, (total + per_page - 1) // per_page) if total is not None else None
    links: list[str] = []

    def control(
        label: str,
        destination: int,
        enabled: bool,
        *,
        rel: str = "",
        aria: str = "",
        numbered: bool = False,
    ) -> str:
        cls = "pagination-number" if numbered else "pagination-control"
        if enabled:
            href = (
                base
                + "?"
                + urlencode({**params, "page": str(destination), "per_page": str(per_page)})
            )
            relationship = safe_html(html_t(t' rel="{rel}"')) if rel else safe_html("")
            return html_t(
                t'<a class="{cls}"{relationship} href="{href}" aria-label="{aria or label}">{label}</a>'
            )
        return html_t(t'<span class="{cls} is-disabled" aria-disabled="true">{label}</span>')

    links.append(control("« First", 1, page > 1, aria="Go to first page"))
    links.append(control("← Previous", page - 1, page > 1, rel="prev"))
    numbers = {1, page, *range(max(1, page - 1), page + 2 if has_next else page + 1)}
    if pages is not None:
        numbers.add(pages)
        numbers = {number for number in numbers if number <= pages}
    previous = 0
    for number in sorted(numbers):
        if previous and number - previous > 1:
            links.append(safe_html('<span class="pagination-ellipsis" aria-hidden="true">…</span>'))
        if number == page:
            links.append(
                html_t(t'<span class="pagination-current" aria-current="page">Page {page}</span>')
            )
        else:
            links.append(
                control(str(number), number, True, aria=f"Go to page {number}", numbered=True)
            )
        previous = number
    links.append(control("Next →", page + 1, has_next, rel="next"))
    if pages is not None:
        links.append(control("Last »", pages, page < pages, aria="Go to last page"))
    summary = (
        f"{total:,} results · Page {page:,} of {pages:,}" if total is not None else f"Page {page:,}"
    )
    if total:
        summary = f"Showing {(page - 1) * per_page + 1:,}–{min(page * per_page, total):,} of {total:,} · Page {page:,} of {pages:,}"
    return safe_html(
        html_t(t"""<nav class="pagination" aria-label="Pagination">
<p class="pagination-summary" role="status">{summary}</p><div class="pagination-links">{join_html(links)}</div></nav>""")
    )


def _paginate_items(
    items: list[_T], url: str, base: str | None = None
) -> tuple[list[_T], SafeHTML, int]:
    parsed = urlparse(url)
    params = parse_qs(parsed.query or "")
    size = _page_size(params)
    page = _clamp_page(_page_number(params), len(items), size)
    query = {key: values[0] for key, values in params.items() if key not in ("page", "partial")}
    return (
        items[(page - 1) * size : page * size],
        _pagination(
            base or parsed.path,
            query,
            page,
            page * size < len(items),
            total=len(items),
            per_page=size,
        ),
        page,
    )


def _ci_tabs(base: str, active: str) -> SafeHTML:
    links: list[str] = []
    for key, suffix, label in (
        ("runs", "/ci", "Runs"),
        ("run", "/ci/run", "Run pipeline"),
        ("deployments", "/ci/deployments", "Deployments"),
        ("settings", "/ci/config", "Settings"),
        ("docs", "/ci/docs", "Documentation"),
    ):
        current = safe_html(' aria-current="page"' if key == active else "")
        links.append(html_t(t'<a href="{base}{suffix}"{current}>{label}</a>'))
    return safe_html(
        html_t(
            t'<div class="repo-ci-navigation">{_repo_tabs(base, "ci")}<nav class="ci-tabs" aria-label="CI navigation">{join_html(links)}</nav></div>'
        )
    )


def _pr_create_form_html(base: str, opt_src: str, opt_tgt: str, warn_merge: str) -> SafeHTML:
    """The pull-request creation form, shared by the dedicated page and any embeds."""
    return safe_html(
        html_t(
            t'''<form method="POST" action="{base}/pulls/create">
<div class="row"><div style="min-width:220px"><label>Source branch</label><select name="source_branch" required>{opt_src}</select></div>
<div style="min-width:220px"><label>Target branch</label><select name="target_branch" required>{opt_tgt}</select></div></div>
<div class="row" style="margin-top:10px"><div style="flex:1;min-width:260px"><label>Title</label><input name="title" placeholder="Add feature X" required style="width:100%"/></div></div>
<div style="margin-top:10px"><label>Description</label><textarea name="body" data-markdown placeholder="What does this change?"></textarea></div>
<div style="margin-top:10px"><button type="submit">Create PR</button></div></form>{warn_merge}'''
        )
    )


def _repo_tabs(base: str, active: str) -> SafeHTML:
    owner, repo = [unquote(part) for part in base.rstrip("/").split("/")[-2:]]
    links: list[str] = []
    for key, suffix, icon, label in (
        ("code", "", "code", "Code"),
        ("issues", "/issues", "issue-opened", "Issues"),
        ("pulls", "/pulls", "git-pull-request", "Pull requests"),
        ("discussions", "/discussions", "comment-discussion", "Discussions"),
        ("ci", "/ci", "play", "CI"),
        ("artifacts", "/artifacts", "package", "Artifacts"),
        ("branches", "/branches", "git-branch", "Branches"),
        ("settings", "/settings", "gear", "Settings"),
    ):
        current = safe_html(' aria-current="page"' if key == active else "")
        links.append(
            html_t(t'<a href="{base}{suffix}"{current}>{octicon(icon)}<span>{label}</span></a>')
        )
    owner_href = "/?" + urlencode({"q": owner})
    return safe_html(
        html_t(
            t'<div class="repo-navigation"><header class="repo-header"><h1>{octicon("repo", cls="repo-header-icon")}<a class="repo-header-owner" href="{owner_href}">{owner}</a><span class="repo-header-sep">/</span><strong><a href="{base}">{repo}</a></strong></h1></header><nav class="ci-tabs repo-tabs" aria-label="Repository navigation">{join_html(links)}</nav></div>'
        )
    )


def _repo_breadcrumbs(
    owner: str, repo: str, ref: str, path: str = "", *, is_file: bool = False
) -> SafeHTML:
    base = str_t(t"/r/{q(owner)}/{q(repo)}")
    crumbs: list[str] = [
        html_t(t'<a href="{base}/tree/{q(ref)}/">{repo}</a>')
        if path
        else html_t(t"<strong>{repo}</strong>")
    ]
    parts = path.split("/") if path else []
    for index, part in enumerate(parts):
        if index < len(parts) - 1:
            folder = "/".join(parts[: index + 1])
            crumbs.append(
                html_t(t'<a href="{base}/tree/{q(ref)}/{q(folder, safe="/")}/">{part}</a>')
            )
        else:
            crumbs.append(html_t(t'<strong aria-current="page">{part}</strong>'))
    result: list[str] = []
    for crumb in crumbs:
        if result:
            result.append(safe_html('<span aria-hidden="true">/</span>'))
        result.append(crumb)
    label = "File path" if is_file else "Folder path"
    return safe_html(
        html_t(t'<nav class="repo-file-breadcrumbs" aria-label="{label}">{join_html(result)}</nav>')
    )


def _language_panel(languages: Sequence[LanguageStat] | None, branch: str) -> SafeHTML:
    if languages is None:
        content = safe_html('<p class="muted">Language statistics are temporarily unavailable.</p>')
    elif not languages:
        content = safe_html('<p class="muted">No recognized source files found.</p>')
    else:
        segments = join_html(
            [
                html_t(
                    t'<span style="width:{item["percentage"]:.6f}%;background:{item["color"]}" title="{item["name"]}: {item["percentage"]:.1f}%"></span>'
                )
                for item in languages
            ]
        )
        entries: list[str] = []
        for item in languages:
            percentage = "<0.1%" if item["percentage"] < 0.1 else f"{item['percentage']:.1f}%"
            entries.append(
                html_t(
                    t'<li><span class="repo-language-dot" style="background:{item["color"]}" aria-hidden="true"></span><strong>{item["name"]}</strong><span class="muted">{percentage}</span></li>'
                )
            )
        content = safe_html(
            html_t(
                t'<div class="repo-language-bar" aria-hidden="true">{segments}</div><ul class="repo-language-list">{join_html(entries)}</ul>'
            )
        )
    return safe_html(
        html_t(
            t'<section class="box repo-language-panel" aria-labelledby="repo-languages-title"><h2 id="repo-languages-title">Languages</h2>{content}<p class="muted repo-language-note">Estimated from tracked source bytes on <code>{branch}</code>. Common generated files and dependencies are excluded.</p></section>'
        )
    )


def _repo_code_menu(
    owner: str,
    repo: str,
    ref: str,
    *,
    can_edit: bool = False,
    path: str = "",
    is_file: bool = False,
) -> SafeHTML:
    base = str_t(t"/r/{q(owner)}/{q(repo)}")
    ide_query = urlencode({"branch": ref, "path" if is_file else "folder": path})
    ide_link = (
        safe_html(
            html_t(
                t'<a class="repo-zip-link repo-open-ide" href="{base}/ide?{ide_query}"><strong>Open in Web IDE</strong><small>Edit multiple files in a browser workspace <kbd>.</kbd></small></a>'
            )
        )
        if can_edit
        else safe_html("")
    )
    clone_path = (
        str_t(t"{URL_PREFIX}/{q(repo)}.git")
        if owner == FLAT_OWNER_UI
        else str_t(t"{URL_PREFIX}/{q(owner)}/{q(repo)}.git")
    )
    return safe_html(
        html_t(t'''<details class="repo-code-menu"><summary>{octicon("code")}Code{octicon("triangle-down")}</summary><div class="repo-code-popover">
<div class="repo-panel-heading"><strong>Clone repository</strong><span class="repo-clone-protocol">HTTP(S)</span></div><div class="repo-clone-body">
<label>Clone URL</label><div class="repo-copy-row"><input class="repo-clone-url" data-path="{clone_path}" value="{clone_path}" readonly aria-label="Repository clone URL"><button class="repo-copy-button" type="button">Copy</button></div><p class="muted repo-copy-status" role="status" aria-live="polite">Use Git to clone the full repository and its history.</p><p class="muted">If authentication is enabled, enter your username and password or access token when Git asks. Never share a URL containing credentials.</p></div>
{ide_link}<a class="repo-zip-link" href="{base}/archive.zip?{urlencode({"ref": ref})}"><strong>↓ Download ZIP</strong><small>Source snapshot of <code>{ref}</code>; no Git history.</small></a></div></details>
<script>(function() {{
 const script = document.currentScript; const menu = script.previousElementSibling;
 const input = menu.querySelector(".repo-clone-url");
  input.value = window.location.origin + input.dataset.path;
  const ideLink = menu.querySelector(".repo-open-ide");
  if (ideLink) document.addEventListener("keydown", event => {{
    if (event.key === "." && !event.ctrlKey && !event.metaKey && !event.altKey && !event.shiftKey &&
        !event.target.closest("input, textarea, select, [contenteditable=true]") && !event.defaultPrevented) {{
      event.preventDefault(); window.location.assign(ideLink.href);
    }}
  }});
 menu.querySelector(".repo-clone-protocol").textContent = window.location.protocol === "https:" ? "HTTPS" : "HTTP";
 input.addEventListener("click", () => input.select());
 menu.querySelector(".repo-copy-button").addEventListener("click", async function() {{
   const status = menu.querySelector(".repo-copy-status");
   try {{
     if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(input.value);
     else {{ input.focus(); input.select(); if (!document.execCommand("copy")) throw new Error("copy unavailable"); }}
     status.textContent = "Clone URL copied.";
   }} catch (_error) {{ input.focus(); input.select(); status.textContent = "Press Ctrl+C or Command+C to copy the selected URL."; }}
 }});
 document.addEventListener("click", event => {{ if (!menu.contains(event.target)) menu.open = false; }});
 menu.addEventListener("keydown", event => {{ if (event.key === "Escape") {{ menu.open = false; menu.querySelector("summary").focus(); }} }});
}})();</script>''')
    )


async def _call_in_thread(func: Callable[_P, _T], /, *args: _P.args, **kwargs: _P.kwargs) -> _T:
    def invoke() -> tuple[_T]:
        return _thread_call(func, *args, **kwargs)

    (result,) = await asyncio.to_thread(invoke)
    return result


from .rendering import SafeHTML, html_t, join_html, q, safe_html, str_t

# ============================================================
# CONFIG
# ============================================================
CONFIG_SCHEMA_VERSION = 1
DEFAULT_CONFIG_FILENAME = "pygithost.config.json"
CURRENT_PLATFORM = platform.system()

# Markdown bodies (issues, discussions, PR descriptions/comments) can embed
# images as data URLs. Base64 inflates a file by ~4/3, so the editor's 512 KiB
# inline-image budget becomes ~700k characters of Markdown. The stored-body cap
# must stay above that: truncating a data URL midway leaves an unterminated
# `![alt](data:…)` and the viewer renders the raw base64 text instead of the
# image (the editor preview still looked fine because it had the full value).
MARKDOWN_BODY_LIMIT = 1_000_000

# Repository file listings show every entry in normal folders, but very wide
# directories are paged (with last-commit metadata only for the visible page)
# so opening a folder with thousands of files stays fast.
REPO_FILES_PAGE_SIZE = 100


CONFIG_GLOBAL_MAP = {
    "host": "HOST",
    "port": "PORT",
    "git_project_root": "GIT_PROJECT_ROOT",
    "git_http_backend": "GIT_HTTP_BACKEND",
    "trace_log": "TRACE_LOG",
    "db_path": "DB_PATH",
    "url_prefix": "URL_PREFIX",
    "require_auth": "REQUIRE_AUTH",
    "filter_ips": "FILTER_IPS",
    "realm": "REALM",
    "flat_owner_ui": "FLAT_OWNER_UI",
    "pr_patch_max_bytes": "PR_PATCH_MAX_BYTES",
    "prism_diff_highlight_max_bytes": "PRISM_DIFF_HIGHLIGHT_MAX_BYTES",
    "max_header_bytes": "MAX_HEADER_BYTES",
    "read_chunk": "READ_CHUNK",
    "session_cookie_name": "SESSION_COOKIE_NAME",
    "session_ttl_seconds": "SESSION_TTL_SECONDS",
    "session_cookie_secure": "SESSION_COOKIE_SECURE",
    "login_path": "LOGIN_PATH",
    "static_url_prefix": "STATIC_URL_PREFIX",
    "static_root": "STATIC_ROOT",
    "static_cache_seconds": "STATIC_CACHE_SECONDS",
    "static_requires_auth": "STATIC_REQUIRES_AUTH",
    "log_level": "LOG_LEVEL",
    "log_format": "LOG_FORMAT",
    "log_file": "LOG_FILE",
    "log_max_bytes": "LOG_MAX_BYTES",
    "log_backup_count": "LOG_BACKUP_COUNT",
    "access_log": "ACCESS_LOG",
    "audit_log": "AUDIT_LOG",
}


def _default_config_path() -> Path:
    return Path(__file__).resolve().parent.parent / DEFAULT_CONFIG_FILENAME


def default_config_for_platform(target_platform: str | None = None) -> dict[str, object]:
    """Create a complete JSON-serializable configuration dictionary."""
    return AppConfig.default_for_platform(target_platform).to_dict()


def _normalize_config(raw_config: dict[str, object]) -> dict[str, object]:
    """Merge a loaded JSON config with defaults."""
    return AppConfig.from_mapping(raw_config).to_dict()


def load_config(path: str | os.PathLike[str]) -> dict[str, object]:
    return AppConfig.from_file(path).to_dict()


def apply_config(config: dict[str, object] | AppConfig) -> None:
    """
    Apply JSON config values to the existing module-level names used by the server.
    Keeping these globals avoids changing the rest of the server code.
    """
    global CURRENT_PLATFORM, ALLOWED_CLIENT_IPS

    if isinstance(config, AppConfig):
        config_model = config
        config = config.to_dict()
    else:
        config_model = AppConfig.from_mapping(config)

    CURRENT_PLATFORM = str(config.get("platform") or platform.system())

    for json_key, global_name in CONFIG_GLOBAL_MAP.items():
        globals()[global_name] = config[json_key]

    ALLOWED_CLIENT_IPS = set(config_model.allowed_client_ips)
    configure_database(config_model)


def write_config_file(
    path: str | os.PathLike[str], target_platform: str | None = None, overwrite: bool = False
) -> Path:
    return AppConfig.default_for_platform(target_platform).write(path, overwrite=overwrite)


# Initialize module globals with platform defaults. The CLI `run` command replaces
# these values with the JSON file values before the server starts.
apply_config(default_config_for_platform())

TREE_FOLDER_ICON = safe_html(
    f'<span class="tree-icon folder" aria-hidden="true">{octicon("file-directory-fill")}</span>'
)

TREE_FILE_ICON = safe_html(
    f'<span class="tree-icon file" aria-hidden="true">{octicon("file")}</span>'
)


_PULL_STATE_ICONS = {
    "open": octicon("git-pull-request", label="Open"),
    "merged": octicon("git-merge", label="Merged"),
    "closed": octicon("git-pull-request-closed", label="Closed"),
}
_ISSUE_STATE_ICONS = {
    "open": octicon("issue-opened", label="Open"),
    "closed": octicon("issue-closed", label="Closed"),
}


def _clean_repo_path(value: str | None) -> str:
    """
    Normalize a path inside a Git tree.

    This fixes URLs like /tree/master/Principal/ producing paths like
    Principal//Fbase.cs when a file link is built from a directory URL that
    already ends with /.
    """
    raw = unquote(value or "")
    raw = raw.replace("\\", "/")

    if "\0" in raw:
        return ""

    parts: list[str] = []
    for part in raw.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            # Git tree paths should never need parent traversal.
            return ""
        parts.append(part)

    return "/".join(parts)


def _join_repo_path(base: str, name: str) -> str:
    base = _clean_repo_path(base)
    name = _clean_repo_path(name)
    if base and name:
        return base + "/" + name
    return base or name


# ============================================================
# HELPERS: validation / permissions
# ============================================================
SAFE_SEG = re.compile(r"^[A-Za-z0-9._-]+$")


def _safe_seg(s: str) -> bool:
    return (
        bool(s)
        and SAFE_SEG.match(s) is not None
        and ".." not in s
        and "/" not in s
        and "\\" not in s
    )


def _safe_branch_name(name: str) -> bool:
    if not name:
        return False
    if name.startswith("/") or name.endswith("/"):
        return False
    if name.startswith("-"):
        return False
    if "\\" in name:
        return False
    if any(c in name for c in [" ", "\t", "\n", "\r"]):
        return False
    if ".." in name or "//" in name:
        return False
    if name.endswith(".lock"):
        return False
    for ch in name:
        ok = ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9") or ch in "._-/"
        if not ok:
            return False
    return True


def _has_write_scope(handler: object) -> bool:
    # When authentication is disabled, IP allowlist becomes the security boundary.
    # The request has already passed ALLOWED_CLIENT_IPS in do_GET/do_POST before
    # this function is reached, so Git push/write operations should be allowed.
    if not REQUIRE_AUTH:
        return True

    scopes = getattr(handler, "remote_scopes", None) or set()
    if not isinstance(scopes, (set, frozenset, list, tuple)):
        scopes = set()
    if getattr(handler, "remote_is_admin", False):
        return True
    return "write" in {str(s).lower() for s in scopes}


def _require_admin(handler: object) -> bool:
    return bool(getattr(handler, "remote_is_admin", False))


# ============================================================
# HELPERS: repos + git + HTTP
# ============================================================
def _is_git_dir(p: Path) -> bool:
    """
    Return True for a real Git directory.

    This supports:
      - bare repo folders with .git suffix: repo.git/
      - bare repo folders without .git suffix: repo/
      - normal repo Git dirs: repo/.git/
    """
    return (
        p.is_dir()
        and (p / "HEAD").is_file()
        and (p / "objects").is_dir()
        and ((p / "refs").is_dir() or (p / "packed-refs").is_file())
    )


def _is_bare_repo_dir(p: Path) -> bool:
    """Return True for a bare repository directory, with or without a .git suffix."""
    return _is_git_dir(p)


def _is_worktree_repo_dir(p: Path) -> bool:
    """Return True for a normal/non-bare repository, for example repo/.git/."""
    return p.is_dir() and _is_git_dir(p / ".git")


def _repo_name_from_git_dir_name(folder_name: str) -> str:
    """
    Convert a Git directory folder name to the public repo name.

    Examples:
      repo.git -> repo
      repo     -> repo
    """
    if folder_name.endswith(".git"):
        return folder_name[:-4]
    return folder_name


def _scan_repos(project_root: str) -> list[tuple[str, str, str]]:
    """
    Scan GIT_PROJECT_ROOT and return repositories for the web UI.

    Supported layouts:
      Flat bare with suffix:       GIT_PROJECT_ROOT/repo.git
      Flat bare without suffix:    GIT_PROJECT_ROOT/repo
      Flat non-bare:               GIT_PROJECT_ROOT/repo/.git
      Owner bare with suffix:      GIT_PROJECT_ROOT/owner/repo.git
      Owner bare without suffix:   GIT_PROJECT_ROOT/owner/repo
      Owner non-bare:              GIT_PROJECT_ROOT/owner/repo/.git
    """
    root = Path(project_root)
    results: list[tuple[str, str, str]] = []

    if not root.exists():
        return results

    root_dirs = sorted([x for x in root.iterdir() if x.is_dir()], key=lambda x: x.name.lower())

    # Flat repos directly under GIT_PROJECT_ROOT.
    for p in root_dirs:
        if p.name == ".git":
            continue

        if _is_bare_repo_dir(p):
            repo = _repo_name_from_git_dir_name(p.name)
            if _safe_seg(repo):
                results.append((FLAT_OWNER_UI, repo, p.name))
            continue

        if _is_worktree_repo_dir(p):
            repo = p.name
            if _safe_seg(repo):
                results.append((FLAT_OWNER_UI, repo, str_t(t"{repo}/.git")))
            continue

    # Owner layouts under GIT_PROJECT_ROOT/owner/.
    for owner_dir in root_dirs:
        # If this folder itself is a repo, do not also treat it as an owner.
        if _is_bare_repo_dir(owner_dir) or _is_worktree_repo_dir(owner_dir):
            continue

        owner = owner_dir.name
        if not _safe_seg(owner):
            continue

        try:
            repo_dirs = sorted(
                [x for x in owner_dir.iterdir() if x.is_dir()], key=lambda x: x.name.lower()
            )
        except OSError:
            continue

        for p in repo_dirs:
            if p.name == ".git":
                continue

            if _is_bare_repo_dir(p):
                repo = _repo_name_from_git_dir_name(p.name)
                if _safe_seg(repo):
                    rel = str_t(t"{owner}/{p.name}")
                    results.append((owner, repo, rel))
                continue

            if _is_worktree_repo_dir(p):
                repo = p.name
                if _safe_seg(repo):
                    rel = str_t(t"{owner}/{repo}/.git")
                    results.append((owner, repo, rel))
                continue

    seen = set()
    uniq = []

    for owner, repo, rel in results:
        key = (owner, repo)
        if key not in seen:
            seen.add(key)
            uniq.append((owner, repo, rel))

    return uniq


def _repo_git_path(owner_ui: str, repo: str) -> str:
    """
    Resolve the real Git directory for a repository.

    Supported layouts:
      Flat bare with suffix:       GIT_PROJECT_ROOT/repo.git
      Flat bare without suffix:    GIT_PROJECT_ROOT/repo
      Flat non-bare:               GIT_PROJECT_ROOT/repo/.git
      Owner bare with suffix:      GIT_PROJECT_ROOT/owner/repo.git
      Owner bare without suffix:   GIT_PROJECT_ROOT/owner/repo
      Owner non-bare:              GIT_PROJECT_ROOT/owner/repo/.git

    If neither repo exists, return the .git bare path. This keeps create-repo
    working exactly like before, because new repos are still created as bare repos.
    """
    if owner_ui == FLAT_OWNER_UI:
        base = Path(GIT_PROJECT_ROOT)
    else:
        base = Path(GIT_PROJECT_ROOT) / owner_ui

    exact_bare = base / repo
    bare_dotgit = base / (repo + ".git")
    worktree_git = base / repo / ".git"

    # Prefer an exact bare repo folder first. This supports bare repos that do
    # not end in .git, for example C:\\Servidor_Git\\ProjectA.
    if _is_bare_repo_dir(exact_bare):
        return str(exact_bare)

    if _is_bare_repo_dir(bare_dotgit):
        return str(bare_dotgit)

    if _is_git_dir(worktree_git):
        return str(worktree_git)

    return str(bare_dotgit)


def _move_directory(source: Path, target: Path) -> None:
    """Rename a directory, copying across filesystems when a rename is impossible."""
    try:
        os.rename(source, target)
        return
    except OSError as e:
        import errno

        # EXDEV on POSIX; ERROR_NOT_SAME_DEVICE (17) on Windows.
        if e.errno != errno.EXDEV and getattr(e, "winerror", None) != 17:
            raise
    from .ci import remove_checkout

    try:
        shutil.copytree(source, target, symlinks=True)
    except BaseException:
        remove_checkout(str(target))
        raise
    remove_checkout(str(source))


def _repo_bare_path(owner_ui: str, repo: str) -> str:
    """
    Backward-compatible name used by the rest of the code.

    It now returns the real Git directory, which can be:
      - repo.git for a bare repo with the .git suffix
      - repo for a bare repo without the .git suffix
      - repo/.git for a normal/non-bare repo
    """
    return _repo_git_path(owner_ui, repo)


def _retention_head_commit(owner: str, repo: str) -> str | None:
    """Resolve the commit cleanup must have verified before deleting data."""
    from .repository_ci import resolve_commit

    try:
        return resolve_commit(_repo_bare_path(owner, repo), "HEAD")
    except OSError, ValueError, subprocess.SubprocessError:
        return None


configure_retention_head_resolver(_retention_head_commit)


def _git_dir_path_info(owner_ui: str, repo: str, rest: list[str]) -> str | None:
    """
    Build the PATH_INFO git-http-backend needs for the resolved repository.

    Returns None when the requested repo does not exist.
    """
    repo_git = Path(_repo_git_path(owner_ui, repo))

    if not _is_git_dir(repo_git):
        return None

    if owner_ui == FLAT_OWNER_UI:
        base = Path(GIT_PROJECT_ROOT)
        try:
            rel_parts = repo_git.relative_to(base).parts
        except ValueError:
            return None
    else:
        base = Path(GIT_PROJECT_ROOT)
        try:
            rel_parts = repo_git.relative_to(base).parts
        except ValueError:
            return None

    path_parts = [*rel_parts, *rest]
    return "/" + "/".join(path_parts)


# Values of `git_http_backend` that explicitly select the built-in Python backend.
_BUILTIN_GIT_BACKEND_NAMES = frozenset({"", "builtin", "python"})
_FALLBACK_BACKEND_SCRIPT = Path(__file__).resolve().with_name("git_http_fallback.py")
_fallback_backend_logged = False


def _git_backend_uses_fallback() -> bool:
    """True when the configured git-http-backend executable is unavailable."""
    configured = (GIT_HTTP_BACKEND or "").strip()
    return configured.lower() in _BUILTIN_GIT_BACKEND_NAMES or not os.path.isfile(configured)


def _git_backend_command() -> list[str]:
    """Command for the Git Smart HTTP CGI program.

    Uses the configured `git-http-backend` when it exists; otherwise the pure-Python
    replacement in `git_http_fallback.py`, which speaks the same CGI contract.
    """
    global _fallback_backend_logged
    if not _git_backend_uses_fallback():
        return [GIT_HTTP_BACKEND]
    if not _fallback_backend_logged:
        _fallback_backend_logged = True
        logger.warning(
            "git-http-backend not found at %r; using the built-in Python Git HTTP backend",
            GIT_HTTP_BACKEND,
        )
    return [sys.executable, "-I", str(_FALLBACK_BACKEND_SCRIPT)]


def _map_git_http_path_info(path_info: str) -> str:
    """
    Convert public Git smart HTTP URLs to the real on-disk Git directory.

    Supported public URLs include:
      /repo.git/...
      /repo/...
      /owner/repo.git/...
      /owner/repo/...

    For bare repos without .git, /repo.git/... is mapped to /repo/...
    For non-bare repos, /repo.git/... or /repo/... is mapped to /repo/.git/...
    """
    clean = path_info.lstrip("/")
    parts = clean.split("/") if clean else []

    if not parts:
        return path_info

    # Flat URL with .git suffix: /repo.git/info/refs
    if parts[0].endswith(".git"):
        repo = parts[0][:-4]
        if _safe_seg(repo):
            mapped = _git_dir_path_info(FLAT_OWNER_UI, repo, parts[1:])
            if mapped:
                return mapped

    # Owner URL with .git suffix: /owner/repo.git/info/refs
    if len(parts) >= 2 and parts[1].endswith(".git"):
        owner = parts[0]
        repo = parts[1][:-4]
        if _safe_seg(owner) and _safe_seg(repo):
            mapped = _git_dir_path_info(owner, repo, parts[2:])
            if mapped:
                return mapped

    # Flat URL without .git suffix: /repo/info/refs
    repo = parts[0]
    if _safe_seg(repo):
        mapped = _git_dir_path_info(FLAT_OWNER_UI, repo, parts[1:])
        if mapped:
            return mapped

    # Owner URL without .git suffix: /owner/repo/info/refs
    if len(parts) >= 2:
        owner = parts[0]
        repo = parts[1]
        if _safe_seg(owner) and _safe_seg(repo):
            mapped = _git_dir_path_info(owner, repo, parts[2:])
            if mapped:
                return mapped

    return path_info


async def _run_cmd(cmd: list[str], cwd: str | None = None) -> tuple[int, bytes, bytes]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    return int(proc.returncode or 0), out, err


async def _run_git(repo_git_dir: str, args: list[str]) -> tuple[int, bytes, bytes]:
    cmd = ["git", "--git-dir=" + repo_git_dir, *args]
    return await _run_cmd(cmd)


async def _git_default_branch(repo_git: str) -> str:
    code, out, _ = await _run_git(repo_git, ["symbolic-ref", "HEAD"])
    if code == 0:
        head = out.decode("utf-8", "replace").strip()
        if head.startswith("refs/heads/"):
            return head[len("refs/heads/") :]
    return "main"


async def _git_list_branches(repo_git: str) -> list[str]:
    code, out, _ = await _run_git(
        repo_git, ["for-each-ref", "refs/heads", "--format=%(refname:short)"]
    )
    if code != 0:
        return []
    branches = [ln.strip() for ln in out.decode("utf-8", "replace").splitlines() if ln.strip()]
    branches.sort(key=lambda s: s.lower())
    return branches


async def _git_resolve_commit(repo_git: str, refish: str) -> str | None:
    code, out, _ = await _run_git(repo_git, ["rev-parse", "--verify", refish + "^{commit}"])
    if code != 0:
        return None
    return out.decode("utf-8", "replace").strip()


async def _git_create_branch(repo_git: str, new_branch: str, from_ref: str) -> tuple[bool, str]:
    commit = await _git_resolve_commit(repo_git, from_ref)
    if not commit:
        return False, str_t(t"Could not resolve '{from_ref}' to a commit.")
    existing = await _git_resolve_commit(repo_git, "refs/heads/" + new_branch)
    if existing:
        return False, "Branch already exists."
    code, _out, err = await _run_git(
        repo_git, ["update-ref", "refs/heads/" + new_branch, commit, "0" * len(commit)]
    )
    if code != 0:
        return False, err.decode("utf-8", "replace").strip() or "git update-ref failed."
    return True, "Branch created."


async def _git_delete_branch(
    repo_git: str, branch: str, expected_commit: str | None = None
) -> tuple[bool, str]:
    args = ["update-ref", "-d", "refs/heads/" + branch]
    if expected_commit:
        args.append(expected_commit)
    code, _out, err = await _run_git(repo_git, args)
    if code != 0:
        return False, err.decode("utf-8", "replace").strip() or "git update-ref -d failed."
    return True, "Branch deleted."


async def _git_commit_meta(repo_git: str, commit: str) -> dict[str, str] | None:
    fmt = "%H%x00%P%x00%an%x00%ae%x00%ad%x00%s%x00%b"
    code, out, _ = await _run_git(repo_git, ["show", "-s", "--date=iso", "--format=" + fmt, commit])
    if code != 0:
        return None
    parts = out.decode("utf-8", "replace").split("\x00")
    if len(parts) < 7:
        return None
    return {
        "hash": parts[0].strip(),
        "parents": parts[1].strip(),
        "author_name": parts[2].strip(),
        "author_email": parts[3].strip(),
        "date": parts[4].strip(),
        "subject": parts[5].strip(),
        "body": parts[6].rstrip(),
    }


async def _ci_commit_subjects(
    repo_git: str, commits: Collection[str]
) -> dict[str, tuple[str, str]]:
    hashes = sorted(
        {sha.lower() for sha in commits if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", sha)}
    )
    if not hashes:
        return {}
    code, out, _ = await _run_git(
        repo_git,
        ["log", "--no-walk", "--ignore-missing", "--format=%H%x00%an%x00%s", *hashes, "--"],
    )
    subjects: dict[str, tuple[str, str]] = {}
    if code == 0:
        for line in out.decode("utf-8", "replace").split("\n"):
            fields = line.split("\0", 2)
            if len(fields) == 3:
                sha, author, subject = fields
                subjects[sha] = (subject.strip()[:240], author.strip()[:120])
    return subjects


def _ci_run_origin(
    base: str,
    event: str,
    commit: str,
    pr_id: int | None,
    pr_author: str,
    commit_author: str,
    pr_title: str = "",
) -> SafeHTML:
    label = {
        "pull_request": "Pull request opened",
        "pull_request_updated": "Pull request updated",
        "pull_request_reopened": "Pull request reopened",
        "pull_request_merged": "Pull request merged",
        "push": "Push",
        "manual": "Manual run",
    }.get(event, event.replace("_", " ").capitalize())
    pr_link = (
        safe_html(html_t(t'<a href="{base}/pulls/{pr_id}" title="{pr_title}">PR #{pr_id}</a>'))
        if pr_id is not None
        else safe_html("")
    )
    commit_link = (
        safe_html(html_t(t'<a href="{base}/commit/{commit}"><code>{commit[:8]}</code></a>'))
        if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit)
        else safe_html("")
    )
    author = (
        ("Opened by " if event == "pull_request" else "PR author: ") + pr_author
        if pr_author
        else ("Commit author: " + commit_author if commit_author else "")
    )
    author_html = safe_html(html_t(t"<span>{author}</span>")) if author else safe_html("")
    return safe_html(html_t(t"<span>{label}</span>{pr_link}{commit_link}{author_html}"))


def _ci_run_source_files(
    base: str, payload: Mapping[str, object], snapshot: Mapping[str, object]
) -> SafeHTML:
    from .repository_ci import CONFIG_FILE, configuration_path

    commit = payload.get("configuration_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit):
        return safe_html(
            '<p class="muted">This run has no recorded repository configuration commit.</p>'
        )
    files = [CONFIG_FILE]
    referenced = payload.get("configuration_file") or snapshot.get("repository_file")
    if isinstance(referenced, str) and referenced != CONFIG_FILE:
        try:
            files.append(configuration_path(referenced))
        except ValueError:
            pass  # Legacy or invalid paths are not repository CI sources.
    links = join_html(
        html_t(
            t'<li><a href="{base}/blob/{commit}/{q(path, safe="/")}"><code>{path}</code></a> <a class="pill" href="{base}/blob/{commit}/{q(path, safe="/")}?raw=1" aria-label="Raw contents of {path}">Raw</a></li>'
        )
        for path in files
    )
    return safe_html(
        html_t(
            t'<p class="muted">Committed files at <code>{commit}</code>. This is the source used to configure the run, not the current branch or its injected settings.</p><ul class="ci-run-source-files">{links}</ul>'
        )
    )


async def _git_commit_name_status(repo_git: str, commit: str) -> list[tuple[str, str]]:
    code, out, _ = await _run_git(repo_git, ["show", "--name-status", "--format=", commit])
    if code != 0:
        return []
    rows = []
    for ln in out.decode("utf-8", "replace").splitlines():
        ln = ln.rstrip("\n")
        if not ln.strip():
            continue
        parts = ln.split("\t")
        if len(parts) >= 2:
            rows.append((parts[0].strip(), parts[-1].strip()))
    return rows


async def _git_commit_patch(
    repo_git: str, commit: str, max_bytes: int = 600_000
) -> tuple[str, bool]:
    code, out, _ = await _run_git(repo_git, ["show", "--no-color", "--format=", commit])
    if code != 0:
        return "Could not render patch.", False
    if len(out) > max_bytes:
        return out[:max_bytes].decode("utf-8", "replace") + "\n\n[... truncated ...]\n", True
    return out.decode("utf-8", "replace"), False


async def _git_is_ancestor(repo_git: str, maybe_ancestor: str, maybe_descendant: str) -> bool:
    code, _out, _err = await _run_git(
        repo_git, ["merge-base", "--is-ancestor", maybe_ancestor, maybe_descendant]
    )
    return code == 0


async def _git_commit_count(repo_git: str, revision: str, path: str = "") -> int | None:
    code, output, _ = await _run_git(
        repo_git,
        ["--literal-pathspecs", "rev-list", "--count", revision] + (["--", path] if path else []),
    )
    return int(output.strip()) if code == 0 and output.strip().isdigit() else None


async def _git_list_commits(
    repo_git: str, rev_range: str, limit: int = 100, skip: int = 0, path: str = ""
) -> list[dict[str, str]]:
    fmt = "%H%x00%an%x00%ae%x00%ad%x00%s"
    args = [
        "--literal-pathspecs",
        "log",
        "--date=iso",
        "--format=" + fmt,
        "-n" + str(limit),
        "--skip=" + str(max(0, skip)),
        rev_range,
    ]
    if path:
        args += ["--", path]
    code, out, _err = await _run_git(repo_git, args)
    if code != 0:
        return []
    commits = []
    for ln in out.decode("utf-8", "replace").splitlines():
        parts = ln.split("\x00")
        if len(parts) != 5:
            continue
        commits.append(
            {
                "hash": parts[0].strip(),
                "author_name": parts[1].strip(),
                "author_email": parts[2].strip(),
                "date": parts[3].strip(),
                "subject": parts[4].strip(),
            }
        )
    return commits


async def _git_diff_between(
    repo_git: str, base: str, head: str, max_bytes: int = PR_PATCH_MAX_BYTES, path: str = ""
) -> tuple[str, bool]:
    args = ["diff", "--no-color", base + ".." + head]
    if path:
        args += ["--", path]
    code, out, err = await _run_git(repo_git, args)
    if code != 0:
        return err.decode("utf-8", "replace") or "Could not render diff.", False
    if len(out) > max_bytes:
        return out[:max_bytes].decode("utf-8", "replace") + "\n\n[... truncated ...]\n", True
    return out.decode("utf-8", "replace"), False


async def _git_diff_files(repo_git: str, base: str, head: str) -> list[ChangedFile]:
    """Return added/deleted line counts and change kinds per changed file."""
    code, out, _err = await _run_git(
        repo_git, ["--literal-pathspecs", "diff", "--numstat", "--no-color", base + ".." + head]
    )
    if code != 0:
        return []
    files: list[ChangedFile] = []
    for ln in out.decode("utf-8", "replace").splitlines():
        if not ln.strip():
            continue
        parts = ln.split("\t")
        if len(parts) < 3:
            continue
        adds, dels, name = parts[0], parts[1], parts[-1]
        kind = "modified"
        if adds == "-" and dels == "-":
            kind = "binary"
        elif adds == "0":
            kind = "deleted"
        elif dels == "0":
            kind = "added"
        files.append(
            {
                "path": name,
                "added": 0 if adds == "-" else int(adds),
                "deleted": 0 if dels == "-" else int(dels),
                "kind": kind,
            }
        )
    return files


async def _git_merge_base(repo_git: str, a: str, b: str) -> str | None:
    code, out, _err = await _run_git(repo_git, ["merge-base", a, b])
    if code != 0:
        return None
    return out.decode("utf-8", "replace").strip() or None


async def _git_merge_conflicts(repo_git: str, target_ref: str, source_ref: str) -> list[str]:
    """Detect whether merging source into target would conflict."""
    code, out, _err = await _run_git(
        repo_git, ["merge-tree", "--write-tree", target_ref, source_ref]
    )
    if code == 0:
        return []
    if code not in (1, 2):
        # Unsupported git version or repository error; no reliable answer.
        return []
    # "tree-ish <tree> ... CONFLICT ..."-style output; conflict message includes "CONFLICT".
    if out and b"CONFLICT" in out:
        return [ln for ln in out.decode("utf-8", "replace").splitlines() if ln.strip()]
    # Older merge-tree formats print conflicts as "changed in both" blocks
    # followed by "+<<<<<<< .our" style lines.
    text = out.decode("utf-8", "replace")
    if "+<<<<<<<" in text or "<<<<<<<<" in text:
        return [ln for ln in text.splitlines() if ln.strip()]
    return []


async def _git_ff_merge(
    repo_git: str,
    target_branch: str,
    source_branch: str,
    *,
    expected: tuple[str | None, str | None] | None = None,
) -> tuple[bool, str, str | None]:
    tgt_ref = "refs/heads/" + target_branch
    src_ref = "refs/heads/" + source_branch

    tgt = await _git_resolve_commit(repo_git, tgt_ref)
    src = await _git_resolve_commit(repo_git, src_ref)
    if not tgt:
        return False, str_t(t"Target branch '{target_branch}' not found."), None
    if not src:
        return False, str_t(t"Source branch '{source_branch}' not found."), None
    if expected is not None and expected != (tgt, src):
        return False, "Branches changed while checking CI; refresh and try again.", None

    if tgt == src:
        return True, "Already up to date.", tgt

    if not await _git_is_ancestor(repo_git, tgt, src):
        return False, "Non fast-forward merge required (this server supports ff-only merges).", None

    # Lock and verify both refs in one transaction, preventing a stale CI decision.
    process = await asyncio.create_subprocess_exec(
        "git",
        "--git-dir=" + repo_git,
        "update-ref",
        "--stdin",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _out, err = await asyncio.wait_for(
            process.communicate(
                f"start\nverify {src_ref} {src}\nupdate {tgt_ref} {src} {tgt}\nprepare\ncommit\n".encode()
            ),
            10,
        )
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()
    code = process.returncode
    if code != 0:
        return False, err.decode("utf-8", "replace").strip() or "git update-ref failed.", None
    return True, "Merged (fast-forward).", src


def _ip_allowed(ip: str, allow: set[str]) -> bool:
    if not FILTER_IPS:
        return True

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not allow:
        return False
    for item in allow:
        try:
            if addr in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            try:
                if ipaddress.ip_address(item) == addr:
                    return True
            except ValueError:
                if item == ip:
                    return True
    return False


def _ci_trust_admin_ips(value: str) -> frozenset[str]:
    """Only individual peer addresses may administer trust without a session."""
    entries = (entry.strip() for entry in value.replace(",", "\n").splitlines())
    try:
        return frozenset(str(ipaddress.ip_address(entry)) for entry in entries if entry)
    except ValueError:
        raise ValueError(
            "PYGITHOST_CI_TRUST_ADMIN_IPS must contain exact IP addresses, not networks."
        ) from None


def _ip_filter_trusts_ci_repositories(config: AppConfig, allowlist: set[str]) -> bool:
    if (
        not config.ip_trust_all_ci_repositories
        or config.require_auth
        or not config.filter_ips
        or not allowlist
    ):
        return False
    # No CIDRs, wildcard entries, or malformed addresses in trust-all mode.
    try:
        for entry in allowlist:
            ipaddress.ip_address(entry)
    except ValueError:
        return False
    return True


def _clip_markdown(body: str) -> str:
    """Trim a Markdown body to the storage cap without splitting an image.

    A partly-stored `![alt](data:…)` is worse than a missing image: the viewer
    cannot parse it and shows the raw base64 as text. If the cut lands inside a
    data-URL image, drop that unfinished image instead.
    """
    if len(body) <= MARKDOWN_BODY_LIMIT:
        return body
    clipped = body[:MARKDOWN_BODY_LIMIT]
    marker = clipped.rfind("![")
    if marker != -1:
        tail = clipped[marker:]
        open_paren = tail.find("](")
        if open_paren != -1 and ")" not in tail[open_paren + 2 :]:
            clipped = clipped[:marker].rstrip()
    return clipped


def _initials(name: str) -> str:
    """Up to two initials for an avatar placeholder."""
    letters = "".join(part[0] for part in re.split(r"[\s._-]+", name) if part)[:2]
    return letters.upper() or "?"


def _repo_context(path: str) -> tuple[str, str] | None:
    """Return (owner, repo) when *path* is inside a repository page."""
    parts = path.split("/")
    if len(parts) >= 4 and parts[1] == "r" and parts[2] and parts[3]:
        return unquote(parts[2]), unquote(parts[3])
    return None


def _app_header() -> SafeHTML:
    user, is_admin = _viewer.get()
    path = _request_path.get()
    signed_out = REQUIRE_AUTH and not user
    context = _repo_context(path)

    create_items: list[str] = [
        html_t(t'<a role="menuitem" href="/#new-repository">{octicon("repo")}New repository</a>')
    ]
    if context:
        base = str_t(t"/r/{q(context[0])}/{q(context[1])}")
        create_items.append(safe_html('<div class="app-menu-divider" role="separator"></div>'))
        create_items.append(html_t(t'<div class="app-menu-heading">This repository</div>'))
        create_items.extend(
            html_t(t'<a role="menuitem" href="{base}{suffix}">{octicon(icon)}{label}</a>')
            for suffix, icon, label in (
                ("/issues/new", "issue-opened", "New issue"),
                ("/pulls/new", "git-pull-request", "New pull request"),
                ("/discussions/new", "comment-discussion", "New discussion"),
                ("/branches", "git-branch", "New branch"),
            )
        )

    if signed_out:
        account = safe_html(
            html_t(t'<a class="btn btn-sm app-sign-in" href="{LOGIN_PATH}">Sign in</a>')
        )
        create_menu = safe_html("")
    else:
        admin_items: list[str] = []
        if is_admin or not REQUIRE_AUTH:
            admin_items.append(safe_html('<div class="app-menu-divider" role="separator"></div>'))
            admin_items.append(safe_html('<div class="app-menu-heading">Administration</div>'))
            admin_items.append(
                html_t(
                    t'<a role="menuitem" href="/admin/settings">{octicon("gear")}Server settings</a>'
                )
            )
            if REQUIRE_AUTH:
                admin_items.append(
                    html_t(t'<a role="menuitem" href="/admin/users">{octicon("people")}Users</a>')
                )
            admin_items.append(
                html_t(
                    t'<a role="menuitem" href="/admin/email">{octicon("mail")}Email notifications</a>'
                )
            )
        name = user or "Local user"
        sign_out = (
            html_t(
                t'<div class="app-menu-divider" role="separator"></div><a role="menuitem" href="/logout">{octicon("sign-out")}Sign out</a>'
            )
            if REQUIRE_AUTH
            else ""
        )
        account = safe_html(
            html_t(
                t"""<details class="app-menu app-user-menu"><summary class="app-avatar-button" aria-label="Open user menu" title="{name}"><span class="avatar" aria-hidden="true">{_initials(name)}</span></summary>
<div class="app-menu-list" role="menu"><div class="app-menu-header"><span class="avatar avatar-lg" aria-hidden="true">{_initials(name)}</span><div><strong>{name}</strong><span class="muted">{"Signed in" if user else "Authentication disabled"}</span></div></div>
<div class="app-menu-divider" role="separator"></div>
<a role="menuitem" href="/">{octicon("repo")}Your repositories</a>
<a role="menuitem" href="/tokens">{octicon("key")}Access tokens</a>
<a role="menuitem" href="/api/docs">{octicon("book")}API documentation</a>
{join_html(admin_items)}{safe_html(sign_out)}</div></details>"""
            )
        )
        create_menu = safe_html(
            html_t(
                t'<details class="app-menu app-create-menu"><summary class="btn btn-sm app-icon-button" aria-label="Create new…" title="Create new…">{octicon("plus")}{octicon("triangle-down", cls="app-caret")}</summary><div class="app-menu-list" role="menu">{join_html(create_items)}</div></details>'
            )
        )

    return safe_html(
        html_t(
            t"""<header class="app-header"><div class="app-header-inner">
<a class="app-logo" href="/" aria-label="Home"><img src="/favicon.ico" alt="" width="32" height="32"></a><a class="app-brand" href="/">{_display_name.get()}</a>
<nav class="app-header-nav" aria-label="Workspace navigation">{safe_html("" if signed_out else html_t(t'<a href="/"{safe_html(' aria-current="page"' if path == "/" else "")}>Repositories</a>'))}</nav>
<div class="app-header-actions">
{safe_html("" if signed_out else html_t(t'<form class="app-search" method="GET" action="/" role="search">{octicon("search")}<input type="search" name="q" placeholder="Search repositories" aria-label="Search repositories" autocomplete="off"><kbd aria-hidden="true">/</kbd></form>'))}
{create_menu}<button id="theme-toggle" class="btn btn-sm app-icon-button theme-toggle" type="button" title="Toggle dark mode" aria-label="Toggle dark mode">{octicon("moon", cls="theme-icon-dark")}{octicon("sun", cls="theme-icon-light")}</button>
{account}</div></div></header>"""
        )
    )


_SHELL_SCRIPT = safe_html(
    """<script>
(function() {
    const button = document.getElementById("theme-toggle");
    function updateButton() {
        if (!button) return;
        const dark = (document.documentElement.getAttribute("data-theme") || "light") === "dark";
        const label = dark ? "Switch to light mode" : "Switch to dark mode";
        button.setAttribute("aria-label", label);
        button.title = label;
    }
    if (button) button.addEventListener("click", function() {
        const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", next);
        try { localStorage.setItem("pygithost_theme", next); } catch (_error) {}
        updateButton();
    });
    updateButton();

    // GitHub-style dropdown menus: one open at a time, close on outside click / Escape.
    const menus = Array.from(document.querySelectorAll("details.app-menu"));
    menus.forEach(function(menu) {
        menu.addEventListener("toggle", function() {
            if (menu.open) menus.forEach(function(other) { if (other !== menu) other.open = false; });
        });
    });
    document.addEventListener("click", function(event) {
        menus.forEach(function(menu) { if (menu.open && !menu.contains(event.target)) menu.open = false; });
    });
    document.addEventListener("keydown", function(event) {
        if (event.key === "Escape") {
            menus.forEach(function(menu) {
                if (menu.open) { menu.open = false; menu.querySelector("summary").focus(); }
            });
            return;
        }
        // Press "/" anywhere to jump to search, like GitHub.
        if (event.key === "/" && !event.ctrlKey && !event.metaKey && !event.altKey &&
            !event.target.closest("input, textarea, select, [contenteditable=true], .monaco-editor")) {
            const local = document.querySelector("[data-hotkey-search]");
            const search = local || document.querySelector(".app-search input");
            if (search) { event.preventDefault(); search.focus(); search.select(); }
        }
    });
})();
</script>"""
)


def _html_page(title: str, body_html: str | SafeHTML, *, wide: bool = False) -> bytes:
    body = safe_html(body_html)
    body_class = "wide-page" if wide else ""
    name = _display_name.get()
    rendered = html_t(
        t"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="/favicon.ico">
<title>{title} · {name}</title>
<script>
(function() {{
    let saved = null;
    try {{ saved = localStorage.getItem("pygithost_theme"); }} catch (_error) {{}}
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.setAttribute("data-theme", saved || (prefersDark ? "dark" : "light"));
    document.documentElement.classList.add("js");
}})();
</script>
<link rel="stylesheet" href="/static/assets/prismjs/prism-okaidia.min.css" />
<link rel="stylesheet" href="/static/ui.css" />
<link rel="stylesheet" href="/static/ci.css" />
<link rel="stylesheet" href="/static/repository.css" />
</head>
<body class="{body_class}">
<a class="skip-link" href="#app-content">Skip to content</a>
{_app_header()}
<div id="app-content" class="app-container">
{body}
</div>
<footer class="app-footer"><div class="app-footer-inner"><span class="app-footer-brand"><img src="/favicon.ico" alt="" width="20" height="20">{name}</span><nav aria-label="Footer"><a href="/">Repositories</a><a href="/tokens">Access tokens</a><a href="/api/docs">API</a></nav></div></footer>
<script src="/static/assets/prismjs/prism.js"></script>
{_SHELL_SCRIPT}
<div id="load_scripts"></div>
</body>
</html>"""
    )
    return rendered.encode("utf-8")


def _prism_diff_patch_html(text: str, truncated: bool, truncated_label: str = "Diff") -> SafeHTML:
    """
    Render a Git diff/patch block.

    Small diffs are syntax-highlighted with PrismJS' diff grammar.
    Large/truncated diffs stay as plain escaped text to avoid freezing the browser.
    """
    patch_bytes = len((text or "").encode("utf-8", "replace"))
    can_highlight = (
        bool((text or "").strip())
        and not truncated
        and patch_bytes <= PRISM_DIFF_HIGHLIGHT_MAX_BYTES
    )

    notes: list[str] = []
    if truncated:
        notes.append(
            html_t(
                t"""<div class="warn" style="margin-bottom:12px">{truncated_label} truncated because it is too large.</div>"""
            )
        )
    elif patch_bytes > PRISM_DIFF_HIGHLIGHT_MAX_BYTES:
        notes.append(
            html_t(
                t"""<div class="warn" style="margin-bottom:12px">{truncated_label} is {patch_bytes:,} bytes, so syntax highlighting was skipped to keep the page responsive.</div>"""
            )
        )

    if can_highlight:
        notes.append(
            html_t(
                t"""<pre><code class="language-diff">{text}</code></pre>
<script>
(function() {{
    window.Prism = window.Prism || {{}};
    window.Prism.manual = true;

    function loadScript(src) {{
        return new Promise((resolve, reject) => {{
            if (document.querySelector(`script[src="${{src}}"]`)) {{
                resolve();
                return;
            }}

            const script = document.createElement("script");
            script.src = src;
            script.async = false;
            script.onload = () => resolve();
            script.onerror = () => reject(new Error(`Failed to load script: ${{src}}`));
            document.head.appendChild(script);
        }});
    }}

    document.addEventListener("DOMContentLoaded", async function() {{
        try {{
            const base = "/static/assets/prismjs/components";

            if (!window.Prism || !window.Prism.highlightElement) {{
                await loadScript(`${{base}}/prism-core.min.js`);
            }}

            if (!window.Prism.languages || !window.Prism.languages.diff) {{
                await loadScript(`${{base}}/prism-diff.min.js`);
            }}

            if (window.Prism && window.Prism.highlightElement) {{
                document.querySelectorAll("code.language-diff").forEach(function(element) {{
                    Prism.highlightElement(element);
                }});
            }}
        }} catch (error) {{
            console.error("Prism diff highlighting failed:", error);
        }}
    }});
}})();
</script>"""
            )
        )
    else:
        notes.append(html_t(t"""<pre>{text}</pre>"""))

    return join_html(notes)


# ============================================================
# Async HTTP primitives
# ============================================================
_STATUS_REASONS = {
    200: "OK",
    303: "See Other",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    410: "Gone",
    415: "Unsupported Media Type",
    500: "Internal Server Error",
}


class Headers:
    def __init__(self, pairs: list[tuple[str, str]]):
        self._pairs = pairs
        self._map: dict[str, list[str]] = {}
        for k, v in pairs:
            self._map.setdefault(k.lower(), []).append(v)

    @overload
    def get(self, name: str) -> str | None: ...

    @overload
    def get(self, name: str, default: str) -> str: ...

    @overload
    def get(self, name: str, default: str | None) -> str | None: ...

    def get(self, name: str, default: str | None = None) -> str | None:
        vals = self._map.get(name.lower())
        if not vals:
            return default
        return vals[-1]

    def items(self) -> list[tuple[str, str]]:
        return list(self._pairs)


class BodyReader:
    def __init__(self, reader: asyncio.StreamReader, prefix: bytes = b""):
        self._reader = reader
        self._prefix = bytearray(prefix)

    async def read(self, n: int = -1) -> bytes:
        if n == 0:
            return b""
        if not self._prefix:
            return await self._reader.read(n)
        if n < 0 or n >= len(self._prefix):
            data = bytes(self._prefix)
            self._prefix.clear()
            if n < 0:
                more = await self._reader.read(-1)
            else:
                more = await self._reader.read(n - len(data)) if n > len(data) else b""
            return data + more
        data = bytes(self._prefix[:n])
        del self._prefix[:n]
        return data

    async def readexactly(self, n: int) -> bytes:
        parts: list[bytes] = []
        remaining = n
        while remaining > 0:
            chunk = await self.read(remaining)
            if not chunk:
                raise asyncio.IncompleteReadError(b"".join(parts), n)
            parts.append(chunk)
            remaining -= len(chunk)
        return b"".join(parts)


@dataclass
class Request:
    method: str
    target: str
    version: str
    headers: Headers
    reader: BodyReader
    writer: asyncio.StreamWriter
    peer_ip: str
    remote_user: str | None = None
    remote_user_id: int | None = None
    remote_is_admin: bool = False
    remote_scopes: set[str] = field(default_factory=set)
    status: int | None = None
    response_size: int | None = None
    request_id: str | None = None


class BadRequest(Exception):
    pass


class ClientDisconnected(Exception):
    pass


async def _read_http_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Request:
    header = bytearray()
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            raise ClientDisconnected()
        header.extend(chunk)
        if len(header) > MAX_HEADER_BYTES:
            raise BadRequest("Headers too large")
        marker = header.find(b"\r\n\r\n")
        sep_len = 4
        if marker < 0:
            marker = header.find(b"\n\n")
            sep_len = 2
        if marker >= 0:
            head = bytes(header[:marker])
            rest = bytes(header[marker + sep_len :])
            break

    lines = head.decode("iso-8859-1", "replace").splitlines()
    if not lines:
        raise BadRequest("Missing request line")
    parts = lines[0].split()
    if len(parts) != 3:
        raise BadRequest("Malformed request line")
    method, target, version = parts
    if not version.startswith("HTTP/"):
        raise BadRequest("Malformed HTTP version")

    pairs: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        pairs.append((k.strip(), v.strip()))

    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else ""
    if ip == "::1":
        ip = "127.0.0.1"
    return Request(
        method=method.upper(),
        target=target,
        version=version,
        headers=Headers(pairs),
        reader=BodyReader(reader, rest),
        writer=writer,
        peer_ip=ip,
    )


async def _send_response(
    req: Request,
    status: int,
    body: bytes = b"",
    headers: list[tuple[str, str]] | None = None,
    reason: str | None = None,
    include_body: bool = True,
) -> None:
    req.status = status
    req.response_size = len(body)
    reason = reason or _STATUS_REASONS.get(status, "OK")
    headers = headers or []
    has_length = any(k.lower() == "content-length" for k, _ in headers)
    has_conn = any(k.lower() == "connection" for k, _ in headers)

    lines = [str_t(t"HTTP/1.1 {status} {reason}\r\n")]
    if not has_length:
        lines.append(str_t(t"Content-Length: {len(body)}\r\n"))
    if not has_conn:
        lines.append("Connection: close\r\n")
    for k, v in headers:
        lines.append(str_t(t"{k}: {v}\r\n"))
    lines.append("\r\n")

    try:
        req.writer.write("".join(lines).encode("iso-8859-1", "replace"))
        if include_body and body:
            req.writer.write(body)
        await req.writer.drain()
    except ConnectionResetError, BrokenPipeError, OSError:
        # The client closed the TCP connection before we could send the response.
        # This commonly happens with browser preconnects, health checks, aborted Git
        # clients, and port scanners. It is not a server error.
        req.writer.close()
        raise ClientDisconnected()


async def _send_html(req: Request, status: int, body: bytes) -> None:
    # Rendered pages may embed fresh asset versions; never let the browser
    # serve a stale page from heuristic caching.
    await _send_response(
        req,
        status,
        body,
        [("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store")],
    )


async def _send_text(req: Request, status: int, text: str) -> None:
    await _send_response(
        req,
        status,
        text.encode("utf-8", "replace"),
        [("Content-Type", "text/plain; charset=utf-8")],
    )


async def _send_redirect(
    req: Request, location: str, headers: list[tuple[str, str]] | None = None
) -> None:
    response_headers = [("Location", location)]
    if headers:
        response_headers.extend(headers)
    await _send_response(req, 303, b"", response_headers)


def _parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    cookies: dict[str, str] = {}
    if not cookie_header:
        return cookies
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        value = value.strip()
        if name:
            cookies[name] = value
    return cookies


def _session_cookie_header(session_token: str) -> str:
    parts = [
        str_t(t"{SESSION_COOKIE_NAME}={session_token}"),
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        str_t(t"Max-Age={SESSION_TTL_SECONDS}"),
    ]
    if SESSION_COOKIE_SECURE:
        parts.append("Secure")
    return "; ".join(parts)


def _delete_session_cookie_header() -> str:
    parts = [
        str_t(t"{SESSION_COOKIE_NAME}="),
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=0",
    ]
    if SESSION_COOKIE_SECURE:
        parts.append("Secure")
    return "; ".join(parts)


def _safe_next_url(raw: str | None) -> str:
    value = (raw or "/").strip()
    if not value.startswith("/") or value.startswith("//"):
        return "/"
    if "\r" in value or "\n" in value:
        return "/"
    if value.startswith(URL_PREFIX + "/"):
        return "/"
    return value or "/"


def _is_static_request_path(path: str) -> bool:
    return path == STATIC_URL_PREFIX or path.startswith(STATIC_URL_PREFIX + "/")


def _static_root() -> Path:
    return Path(STATIC_ROOT).resolve()


FAVICON_URL = "/favicon.ico"
MAX_FAVICON_BYTES = 512 * 1024
_FAVICON_TYPES = {
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".gif": "image/gif",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
}


def _default_favicon_path() -> Path | None:
    """Prefer favicon.ico next to static/, then static/, then the package root."""
    root = _static_root()
    for path in (
        root.parent / "favicon.ico",
        root / "favicon.ico",
        Path(__file__).resolve().parent.parent / "favicon.ico",
    ):
        if path.is_file():
            return path
    return None


def _favicon_content_type(filename: str, data: bytes) -> str:
    suffix = Path(filename or "").suffix.lower()
    content_type = _FAVICON_TYPES.get(suffix)
    if not content_type:
        raise ValueError("Choose an ICO, PNG, GIF, JPEG, WebP or SVG image.")
    if not data:
        raise ValueError("The selected favicon file is empty.")
    if len(data) > MAX_FAVICON_BYTES:
        raise ValueError(f"Favicon images must be at most {MAX_FAVICON_BYTES // 1024} KiB.")
    signatures = {
        ".ico": data.startswith(b"\x00\x00\x01\x00"),
        ".png": data.startswith(b"\x89PNG\r\n\x1a\n"),
        ".gif": data.startswith((b"GIF87a", b"GIF89a")),
        ".jpg": data.startswith(b"\xff\xd8\xff"),
        ".jpeg": data.startswith(b"\xff\xd8\xff"),
        ".webp": data[:4] == b"RIFF" and data[8:12] == b"WEBP",
    }
    if suffix == ".svg":
        if b"<svg" not in data.lstrip()[:2048].lower():
            raise ValueError("That file does not look like an SVG image.")
    elif not signatures.get(suffix, False):
        raise ValueError("That file does not look like the selected image type.")
    return content_type


def _static_path_from_url(path: str) -> Path | None:
    """Map /static/... to STATIC_ROOT safely. Prevents path traversal."""
    if not _is_static_request_path(path):
        return None

    rel_url = path[len(STATIC_URL_PREFIX) :].lstrip("/")
    rel_url = unquote(rel_url)

    if "\0" in rel_url or "\\" in rel_url:
        return None

    root = _static_root()
    candidate = (root / rel_url).resolve()

    try:
        candidate.relative_to(root)
    except ValueError:
        return None

    # Do not expose dotfiles or files inside hidden folders, for example .env.
    try:
        relative_parts = candidate.relative_to(root).parts
    except ValueError:
        return None
    if any(part.startswith(".") for part in relative_parts):
        return None

    if candidate.is_dir():
        for index_name in ("index.html", "index.htm"):
            index_path = candidate / index_name
            if index_path.is_file():
                return index_path.resolve()
        return None

    if not candidate.is_file():
        return None

    return candidate


def _static_content_type(path: Path) -> str:
    content_type, _encoding = mimetypes.guess_type(str(path))
    if not content_type:
        content_type = "application/octet-stream"

    lower_type = content_type.lower()
    text_like = lower_type.startswith("text/") or lower_type in {
        "application/javascript",
        "application/json",
        "application/xml",
        "image/svg+xml",
    }
    if text_like and "charset=" not in lower_type:
        content_type += "; charset=utf-8"
    return content_type


def _static_cache_control(path: Path) -> str:
    if path.suffix.lower() in {".html", ".htm"}:
        return "no-cache"
    return str_t(t"public, max-age={STATIC_CACHE_SECONDS}")


def _static_headers(path: Path) -> list[tuple[str, str]]:
    stat = path.stat()
    return [
        ("Content-Type", _static_content_type(path)),
        ("Cache-Control", _static_cache_control(path)),
        ("Last-Modified", formatdate(stat.st_mtime, usegmt=True)),
        ("X-Content-Type-Options", "nosniff"),
    ]


# ============================================================
# SERVER HANDLER
# ============================================================
class GitHTTPHandler:
    def __init__(self, request: Request, server: "AsyncGitServer"):
        self.request = request
        self.server = server
        self.path = request.target
        self.command = request.method
        self.headers = request.headers
        self.request_version = request.version
        self.remote_user: str | None = None
        self.remote_user_id: int | None = None
        self.remote_is_admin = False
        self.remote_scopes: set[str] = set()

    def _client_ip(self) -> str:
        return self.request.peer_ip

    def _allowlist(self) -> set[str]:
        return self.server.allowlist

    async def _require_auth(self) -> bool:
        if not REQUIRE_AUTH:
            return True

        auth_header = self.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Basic "):
            return await self._request_auth()

        try:
            decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode("utf-8")
            username, secret = decoded.split(":", 1)
        except Exception:
            return await self._request_auth()

        if not _safe_seg(username):
            return await self._request_auth()

        # First support the strict USERNAME:TOKEN form.
        info = await asyncio.to_thread(db_verify_token, username, secret)

        # Then support token-only login, where the Basic Auth username is only a
        # placeholder like "token", "git", or "x-access-token". The real user is
        # resolved from the token owner in SQLite.
        if not info:
            info = await asyncio.to_thread(db_verify_token_any_user, secret)

        # Finally fall back to normal USERNAME:PASSWORD login for the web UI.
        if not info:
            info = await asyncio.to_thread(db_verify_password, username, secret)

        if info:
            self._apply_auth_info(info)
            return True

        return await self._request_auth()

    async def _request_auth(self) -> bool:
        body = b"Authentication required.\n"
        await _send_response(
            self.request,
            401,
            body,
            [
                ("WWW-Authenticate", str_t(t'Basic realm="{REALM}"')),
                ("Content-Type", "text/plain; charset=utf-8"),
            ],
            reason="Unauthorized",
        )
        return False

    def _apply_auth_info(self, info: Mapping[str, object]) -> None:
        self.remote_user = str(info["username"])
        self.remote_user_id = int(cast(int | str, info["user_id"]))
        self.remote_is_admin = bool(info.get("is_admin"))
        raw_scopes = info.get("scopes")
        if not isinstance(raw_scopes, (set, frozenset, list, tuple)):
            raw_scopes = {"read"}
        self.remote_scopes = {str(scope) for scope in raw_scopes}
        self.request.remote_user = self.remote_user
        self.request.remote_user_id = self.remote_user_id
        self.request.remote_is_admin = self.remote_is_admin
        _viewer.set((self.remote_user, self.remote_is_admin))
        self.request.remote_scopes = self.remote_scopes

    async def _audit(
        self,
        action: str,
        outcome: str = "success",
        *,
        target: str | None = None,
        detail: str | None = None,
        actor: str | None = None,
        actor_user_id: int | None = None,
    ) -> None:
        """Append a security event without letting audit failures break requests."""
        if not self.server.audit_log:
            return
        try:
            await asyncio.to_thread(
                db_audit_append,
                action,
                outcome,
                actor=self.remote_user if actor is None else actor,
                actor_user_id=self.remote_user_id if actor_user_id is None else actor_user_id,
                target=target,
                detail=detail,
                ip=self._client_ip(),
                user_agent=self.headers.get("User-Agent") or "",
            )
        except Exception as exc:
            logger.warning(
                "Audit write failed",
                extra={
                    "event": "audit_failure",
                    "action": action,
                    "error_type": type(exc).__name__,
                },
            )

    async def _require_session_auth(self) -> bool:
        if not REQUIRE_AUTH:
            return True

        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        session_token = cookies.get(SESSION_COOKIE_NAME)
        info = await asyncio.to_thread(db_verify_session, session_token)
        if info:
            self._apply_auth_info(info)
            return True

        next_url = _safe_next_url(self.request.target)
        await _send_redirect(self.request, str_t(t"{LOGIN_PATH}?next={q(next_url)}"))
        return False

    async def _ui_login(self, notice: str = "", notice_kind: str = "warn") -> None:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query or "")
        next_url = _safe_next_url((qs.get("next") or ["/"])[0])
        if not notice and (qs.get("loggedout") or [""])[0] == "1":
            notice = "You have been logged out."
            notice_kind = "ok"

        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(
                html_t(t'<div class="{cls}" style="margin-bottom:12px">{notice}</div>')
            )

        body = html_t(
            t"""<main class="auth-page">
<img class="auth-logo" src="/favicon.ico" alt="" width="48" height="48">
<h1>Sign in to {_display_name.get()}</h1>
{notice_html}
<div class="box auth-box">
<form method="POST" action="/login">
<input type="hidden" name="next" value="{next_url}" />
<label for="login-username">Username</label><input id="login-username" name="username" autocomplete="username" autofocus required />
<label for="login-password">Password</label><input id="login-password" name="password" type="password" autocomplete="current-password" required />
<button type="submit">Sign in</button>
</form>
</div>
<div class="box auth-note"><p class="muted">Git clients should use <code>username:token</code> or <code>token:TOKEN_VALUE</code> against <code>{URL_PREFIX}</code>.</p></div>
</main>"""
        )
        await _send_html(self.request, 200, _html_page("Sign in", safe_html(body)))

    async def _ui_do_login(self) -> None:
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "application/x-www-form-urlencoded" not in ctype:
            return await _send_text(self.request, 415, "Unsupported Media Type\n")

        form = await self._read_form_urlencoded()
        username = (form.get("username") or "").strip()
        password = form.get("password") or ""
        next_url = _safe_next_url(form.get("next") or "/")

        if not _safe_seg(username):
            await self._audit(
                "login", "failure", actor=username or None, target="web", detail="invalid_username"
            )
            return await self._ui_login("Invalid username or password.", "warn")

        info = await asyncio.to_thread(db_verify_password, username, password)
        if not info:
            await self._audit(
                "login", "failure", actor=username, target="web", detail="invalid_credentials"
            )
            return await self._ui_login("Invalid username or password.", "warn")

        session_token = await asyncio.to_thread(
            db_create_session,
            int(cast(int | str, info["user_id"])),
            self._client_ip(),
            self.headers.get("User-Agent") or "",
        )
        self._apply_auth_info(info)
        await self._audit("login", "success", target="web")
        await _send_redirect(
            self.request,
            next_url,
            [("Set-Cookie", _session_cookie_header(session_token))],
        )

    async def _ui_logout(self) -> None:
        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        await self._audit("logout", "success", target="web")
        await asyncio.to_thread(db_revoke_session, cookies.get(SESSION_COOKIE_NAME))
        await _send_redirect(
            self.request,
            str_t(t"{LOGIN_PATH}?loggedout=1"),
            [("Set-Cookie", _delete_session_cookie_header())],
        )

    async def _forbidden(self, msg: bytes = b"403 Forbidden\n") -> None:
        await _send_text(self.request, 403, msg.decode("utf-8", "replace"))

    async def _not_found(self) -> None:
        await _send_text(self.request, 404, "404 Not Found\n")

    async def _serve_static(self, include_body: bool = True) -> None:
        parsed = urlparse(self.path)
        static_path = _static_path_from_url(parsed.path)
        if static_path is None:
            return await self._not_found()

        try:
            if include_body:
                body = await asyncio.to_thread(static_path.read_bytes)
            else:
                body = b""
                # Keep Content-Length correct for HEAD requests.
                size = static_path.stat().st_size
                headers = _static_headers(static_path)
                headers.append(("Content-Length", str(size)))
                return await _send_response(self.request, 200, body, headers, include_body=False)
        except PermissionError:
            return await self._forbidden(b"403 Forbidden: static file is not readable.\n")
        except FileNotFoundError:
            return await self._not_found()
        except OSError as e:
            return await _send_text(self.request, 500, str_t(t"500 Static file error: {e}\n"))

        return await _send_response(
            self.request, 200, body, _static_headers(static_path), include_body=include_body
        )

    async def _serve_favicon(self, include_body: bool = True) -> None:
        custom = await _call_in_thread(db_favicon_get)
        if custom:
            content_type, body = custom
        else:
            path = _default_favicon_path()
            if path is None:
                return await self._not_found()
            try:
                body = await asyncio.to_thread(path.read_bytes)
            except OSError:
                return await self._not_found()
            content_type = _FAVICON_TYPES.get(path.suffix.lower(), "image/x-icon")
        headers = [
            ("Content-Type", content_type),
            ("Cache-Control", "no-cache"),
            ("X-Content-Type-Options", "nosniff"),
        ]
        etag = '"' + hashlib.sha256(body).hexdigest()[:32] + '"'
        headers.append(("ETag", etag))
        if content_type == "image/svg+xml":
            # An SVG opened directly must not be able to run scripts.
            headers.append(
                (
                    "Content-Security-Policy",
                    "sandbox; default-src 'none'; style-src 'unsafe-inline'",
                )
            )
        if self.headers.get("If-None-Match") == etag:
            return await _send_response(
                self.request,
                304,
                b"",
                [("ETag", etag), ("Cache-Control", "no-cache")],
                include_body=False,
            )
        return await _send_response(self.request, 200, body, headers, include_body=include_body)

    async def _read_form_urlencoded(self) -> dict[str, str]:
        clen = int(self.headers.get("Content-Length") or 0)
        if clen <= 0:
            return {}
        raw = await self.request.reader.readexactly(clen)
        text = raw.decode("utf-8", "replace")
        qs = parse_qs(text, keep_blank_values=True)
        return {k: (v[0] if v else "") for k, v in qs.items()}

    async def _read_multipart_form(
        self, *, max_bytes: int
    ) -> tuple[dict[str, str], dict[str, tuple[str, bytes]]]:
        """Read one small multipart form without the removed cgi module."""
        from email.parser import BytesParser
        from email.policy import default as email_policy

        content_type = self.headers.get("Content-Type") or ""
        if not content_type.lower().startswith("multipart/form-data"):
            raise ValueError("Expected a multipart form.")
        clen = int(self.headers.get("Content-Length") or 0)
        if clen <= 0:
            raise ValueError("The upload is empty.")
        if clen > max_bytes:
            raise ValueError(f"Favicon images must be at most {MAX_FAVICON_BYTES // 1024} KiB.")
        body = await self.request.reader.readexactly(clen)
        try:
            message = BytesParser(policy=email_policy).parsebytes(
                f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode(
                    "latin-1", "replace"
                )
                + body
            )
        except Exception as exc:
            raise ValueError("Malformed multipart form.") from exc
        if not message.is_multipart():
            raise ValueError("Malformed multipart form.")
        fields: dict[str, str] = {}
        files: dict[str, tuple[str, bytes]] = {}
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if not isinstance(name, str) or not name:
                continue
            raw_payload = part.get_payload(decode=True)
            payload = raw_payload if isinstance(raw_payload, bytes) else b""
            filename = part.get_filename()
            if filename is not None:
                files[name] = (filename, payload)
            else:
                fields[name] = payload.decode(part.get_content_charset() or "utf-8", "replace")
        return fields, files

    # ========================================================
    # UI: Home / Tokens / Create Repo
    # ========================================================
    async def _ui_home(self, notice: str = "", notice_kind: str = "ok") -> None:
        all_repos = await _call_in_thread(
            lambda: sorted(
                _scan_repos(GIT_PROJECT_ROOT),
                key=lambda item: (item[0].casefold(), item[1].casefold()),
            )
        )
        params = parse_qs(urlparse(self.path).query or "")
        search = (params.get("q") or [""])[0].strip()[:128]
        repos = [
            item
            for item in all_repos
            if search.casefold() in f"{item[0]}/{item[1]} {item[2]}".casefold()
        ]
        total = len(repos)
        size = _page_size(params)
        page = _clamp_page(_page_number(params), total, size)
        repos = repos[(page - 1) * size : page * size]
        pagination = _pagination(
            "/",
            {"q": search} if search else {},
            page,
            page * size < total,
            total=total,
            per_page=size,
        )

        rows: list[str] = []
        for owner, repo, rel in repos:
            rows.append(
                html_t(
                    t"""<article class="repo-list-item"><div><h2>{octicon("repo", cls="repo-list-icon")}<a href="/r/{q(owner)}/{q(repo)}"><span class="repo-list-owner">{owner} / </span>{repo}</a></h2><p class="muted"><code>{rel}</code></p></div><nav aria-label="Links for {owner}/{repo}"><a href="/r/{q(owner)}/{q(repo)}/issues">{octicon("issue-opened")}Issues</a><a href="/r/{q(owner)}/{q(repo)}/pulls">{octicon("git-pull-request")}Pull requests</a><a href="/r/{q(owner)}/{q(repo)}/branches">{octicon("git-branch")}Branches</a><a href="/r/{q(owner)}/{q(repo)}/ci">{octicon("play")}CI</a></nav></article>"""
                )
            )

        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(
                html_t(t'<div class="{cls}" style="margin-bottom:12px">{notice}</div>')
            )

        rows_html = (
            join_html(rows)
            if rows
            else safe_html(
                html_t(
                    t'<div class="repo-empty">{octicon("repo", size=24)}<h2>{"No matching repositories" if search else "No repositories yet"}</h2><p class="muted">{"Try a different name or clear your search." if search else "Create a repository to get started."}</p></div>'
                )
            )
        )
        clear = (
            safe_html(html_t(t'<a class="btn" href="/">{octicon("x")}Clear search</a>'))
            if search
            else safe_html("")
        )
        heading = (
            html_t(t"{total} results for “{search}”")
            if search
            else html_t(t"{total} {'repository' if total == 1 else 'repositories'}")
        )
        body = html_t(
            t"""<main class="repo-page repo-home"><div class="topbar">
<div><h1>Repositories</h1><p class="muted">Repositories hosted on this server. Clone them over HTTP(S) or browse code, issues and pull requests here.</p></div>
</div>
{notice_html}
<div class="repo-home-toolbar"><form class="repo-search" method="GET" action="/" role="search"><input type="hidden" name="per_page" value="{size}"><label class="visually-hidden" for="repo-search">Find a repository</label><div class="repo-search-field">{octicon("search")}<input id="repo-search" type="search" name="q" value="{search}" placeholder="Find a repository…" maxlength="128" data-hotkey-search></div><button type="submit">Search</button>{clear}</form>
<a class="btn btn-primary repo-new-button" href="#new-repository">{octicon("repo")}New</a></div>
<details id="new-repository" class="box repo-create"{safe_html(" open" if not all_repos or notice_kind == "warn" else "")}><summary>Create a new repository</summary>
<p class="muted">A repository contains all project files, including the revision history. Requires <code>write</code> scope.</p>
<form method="POST" action="/create-repo">
<div class="row repo-create-fields">
<div><label for="repo-owner">Owner <span class="muted">(optional)</span></label><input id="repo-owner" name="owner" placeholder="{FLAT_OWNER_UI}" /></div>
<span class="repo-create-slash" aria-hidden="true">/</span>
<div><label for="repo-name">Repository name <span class="repo-required">*</span></label><input id="repo-name" name="repo" placeholder="my-repo" required /></div>
</div>
<p class="muted repo-create-hint">Great repository names are short and memorable. Leave owner empty to use the flat layout.</p>
<fieldset class="repo-create-init"><legend>Initialize this repository with:</legend>
<label class="repo-create-readme"><input type="checkbox" name="readme" value="1" /> Add a README file <span class="muted">— a <code>README.md</code> with the repository name.</span></label>
<div class="row repo-create-templates">
<div><label for="repo-gitignore">Add .gitignore</label><select id="repo-gitignore" name="gitignore"><option value="">None</option>{join_html([html_t(t'<option value="{g}">{g}</option>') for g in GITIGNORE_TEMPLATES])}</select></div>
<div><label for="repo-license">Choose a license</label><select id="repo-license" name="license"><option value="">None</option>{join_html([html_t(t'<option value="{k}">{v}</option>') for k, v in LICENSES.items()])}</select></div>
</div>
<p class="muted">Choosing any of these creates an initial commit on the default branch.</p>
</fieldset>
<div class="repo-create-actions"><button type="submit">Create repository</button></div>
</form>
</details>
<script>(function() {{
  const panel = document.getElementById("new-repository");
  function reveal() {{
    if (window.location.hash !== "#new-repository") return;
    panel.open = true;
    const name = document.getElementById("repo-name");
    if (name) setTimeout(function() {{ name.focus(); }}, 0);
  }}
  window.addEventListener("hashchange", reveal);
  document.querySelectorAll('a[href$="#new-repository"]').forEach(function(link) {{
    link.addEventListener("click", function() {{ if (window.location.hash === "#new-repository") reveal(); }});
  }});
  reveal();
}})();</script>
<section class="box repo-list"><div class="repo-panel-heading"><h2>{heading}</h2><span class="muted">{len(all_repos)} total</span></div>{rows_html}{pagination}</section></main>"""
        )
        await _send_html(self.request, 200, _html_page("Repositories", safe_html(body)))

    async def _ui_tokens(
        self, notice: str = "", notice_kind: str = "ok", new_token: str = ""
    ) -> None:
        user_id = int(self.remote_user_id or 0)
        tokens = await asyncio.to_thread(db_list_tokens_for_user, user_id)
        tokens, pagination, _page = _paginate_items(tokens, self.path, "/tokens")

        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(
                html_t(t'<div class="{cls}" style="margin-bottom:12px">{notice}</div>')
            )

        new_token_html = safe_html("")
        if new_token:
            new_token_html = safe_html(
                html_t(
                    t"""<div class="ok" style="margin-bottom:14px">
<div><b>Token created.</b> Copy it now. It will not be shown again.</div>
<pre><code>{new_token}</code></pre>
<div class="muted">Git example: <code>git clone http://token:{new_token}@HOST:{PORT}{URL_PREFIX}/repo.git</code></div>
</div>"""
                )
            )

        rows: list[str] = []
        for token_id, name, scopes, is_active, created_at, expires_at, revoked_at, status in tokens:
            status_class = "pill"
            if status == "expired":
                status_class = "pill muted"
            elif status == "revoked":
                status_class = "pill muted"

            expires_display = expires_at or "Never"
            revoked_display = revoked_at or ""
            revoked_html = safe_html("")
            if revoked_display:
                revoked_html = safe_html(
                    html_t(t'<br><small class="muted">Revoked: {revoked_display}</small>')
                )

            if status == "active":
                action_html = safe_html(
                    html_t(
                        t"""<form method="POST" action="/tokens/revoke" style="display:inline" onsubmit="return confirm('Revoke this token?');">
<input type="hidden" name="token_id" value="{token_id}" />
<button type="submit" class="danger">Revoke</button>
</form>"""
                    )
                )
            else:
                action_html = safe_html('<span class="muted">No action</span>')

            rows.append(
                html_t(
                    t"""<tr>
<td><b>{name}</b><br><small class="muted">Created: {created_at}</small></td>
<td><code>{scopes}</code></td>
<td>{expires_display}</td>
<td><span class="{status_class}">{status}</span>{revoked_html}</td>
<td style="text-align:right">{action_html}</td>
</tr>"""
                )
            )

        rows_html = (
            join_html(rows)
            if rows
            else safe_html(
                '<tr><td class="muted">No tokens yet.</td><td></td><td></td><td></td><td></td></tr>'
            )
        )

        body = html_t(
            t"""<div class="topbar">
<h1 style="margin:0">Tokens</h1>
<div></div>
</div>
{notice_html}
{new_token_html}
<div class="box" style="margin-bottom:14px">
<h2 style="margin:0 0 10px 0;font-size:16px">Create personal access token</h2>
<form method="POST" action="/tokens/create">
<div class="row">
<div><label>Token name</label><input name="name" placeholder="laptop, ci-server, vscode" maxlength="80" required /></div>
<div><label>Scopes</label><select name="scopes"><option value="read">read</option><option value="read,write" selected>read,write</option></select></div>
<div><label>Expiration date/time</label><input name="expires_at" type="datetime-local" /></div>
<div><button type="submit">Create token</button></div>
</div>
<p class="muted" style="margin:10px 0 0 0">Leave expiration empty for a token that never expires. Tokens are stored hashed, so only metadata is visible later.</p>
</form>
</div>
<div class="box">
<h2 style="margin:0 0 10px 0;font-size:16px">Your tokens</h2>
<table>
<tr><td><b>Name</b></td><td><b>Scopes</b></td><td><b>Expires</b></td><td><b>Status</b></td><td></td></tr>
{rows_html}
</table>
{pagination}
</div>"""
        )
        await _send_html(self.request, 200, _html_page("Tokens", safe_html(body)))

    async def _ui_create_token(self) -> None:
        form = await self._read_form_urlencoded()
        name = (form.get("name") or "").strip()
        scopes = (form.get("scopes") or "read,write").strip() or "read,write"
        expires_at = (form.get("expires_at") or "").strip()
        if not name:
            return await self._ui_tokens("Token name is required.", "warn")
        try:
            token = await asyncio.to_thread(
                db_create_token, int(self.remote_user_id or 0), name, scopes, expires_at
            )
        except ValueError as e:
            await self._audit("token_create", "failure", target=name, detail=str(e))
            return await self._ui_tokens(str(e), "warn")
        except Exception as e:
            await self._audit("token_create", "failure", target=name, detail=type(e).__name__)
            return await self._ui_tokens(str_t(t"Failed to create token: {e}"), "warn")
        await self._audit("token_create", "success", target=name, detail=f"scopes={scopes}")
        return await self._ui_tokens("Token created.", "ok", token)

    async def _ui_revoke_token(self) -> None:
        form = await self._read_form_urlencoded()
        try:
            token_id = int((form.get("token_id") or "0").strip())
        except Exception:
            return await self._ui_tokens("Invalid token id.", "warn")

        ok = await asyncio.to_thread(db_revoke_token, int(self.remote_user_id or 0), token_id)
        if not ok:
            await self._audit("token_revoke", "failure", target=str(token_id), detail="not_found")
            return await self._ui_tokens("Token was not found or was already revoked.", "warn")
        await self._audit("token_revoke", "success", target=str(token_id))
        return await self._ui_tokens("Token revoked.", "ok")

    async def _ui_create_repo(self) -> None:
        if not _has_write_scope(self):
            return await self._ui_home("You need write scope to create repos.", "warn")

        form = await self._read_form_urlencoded()
        owner = (form.get("owner") or "").strip()
        repo = (form.get("repo") or "").strip()
        owner_ui = FLAT_OWNER_UI if (not owner or owner == FLAT_OWNER_UI) else owner

        if owner_ui != FLAT_OWNER_UI and not _safe_seg(owner_ui):
            return await self._ui_home("Invalid owner name.", "warn")
        if not _safe_seg(repo):
            return await self._ui_home("Invalid repo name.", "warn")

        try:
            starter = initial_files(
                repo,
                readme=form.get("readme") == "1",
                gitignore=(form.get("gitignore") or "").strip(),
                license=(form.get("license") or "").strip(),
                holder=self.remote_user or (owner if owner_ui != FLAT_OWNER_UI else repo),
            )
        except KeyError:
            return await self._ui_home("Unknown .gitignore or license template.", "warn")

        repo_git = _repo_bare_path(owner_ui, repo)
        try:
            if owner_ui == FLAT_OWNER_UI:
                os.makedirs(GIT_PROJECT_ROOT, exist_ok=True)
            else:
                os.makedirs(os.path.join(GIT_PROJECT_ROOT, owner_ui), exist_ok=True)
        except Exception as e:
            return await self._ui_home(str_t(t"Failed to create owner folder: {e}"), "warn")

        if os.path.exists(repo_git):
            return await self._ui_home("Repo already exists.", "warn")

        code, out, err = await _run_cmd(["git", "init", "--bare", repo_git])
        if code != 0:
            msg = err.decode("utf-8", "replace").strip() or out.decode("utf-8", "replace").strip()
            return await self._ui_home(str_t(t"git init --bare failed: {msg}"), "warn")

        code, out, err = await _run_cmd(
            [
                "git",
                "--git-dir=" + repo_git,
                "config",
                "http.receivepack",
                "true",
            ]
        )
        if code != 0:
            msg = err.decode("utf-8", "replace").strip() or out.decode("utf-8", "replace").strip()
            return await self._ui_home(
                str_t(t"Repo created, but failed to enable push: {msg}"), "warn"
            )

        if starter:
            from .webide import IDEError, initial_commit

            branch = await _git_default_branch(repo_git)
            try:
                await asyncio.to_thread(initial_commit, repo_git, branch, starter, self.remote_user)
            except IDEError as e:
                return await self._ui_home(
                    str_t(t"Repo created, but the initial commit failed: {e}"), "warn"
                )

        return await self._ui_home(str_t(t"Repo created: {owner_ui}/{repo}"), "ok")

    def _can_delete_repo(self) -> bool:
        # Deleting is irreversible, so it requires an administrator. Without
        # authentication the IP allowlist is the boundary, as for other writes.
        return _require_admin(self) if REQUIRE_AUTH else True

    async def _ui_repo_settings(
        self, owner: str, repo: str, notice: str = "", notice_kind: str = "ok", status: int = 200
    ) -> None:
        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return await self._forbidden(b"403 Forbidden\n")
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        full_name = f"{owner}/{repo}"
        notice_html = (
            safe_html(html_t(t'<p class="{notice_kind}" role="status">{notice}</p>'))
            if notice
            else safe_html("")
        )
        if not self._can_delete_repo():
            delete_html = safe_html(
                '<p class="muted">Only administrators can delete repositories.</p>'
            )
        elif Path(repo_git).name == ".git":
            delete_html = safe_html(
                '<p class="muted">This repository has a working tree on the server, so it '
                "cannot be deleted from the web interface. Remove its folder on disk instead.</p>"
            )
        else:
            delete_html = safe_html(
                html_t(
                    t"""<details class="repo-delete"><summary class="btn danger">Delete this repository</summary>
<form method="POST" action="{base}/settings/delete" class="repo-delete-form" data-expected="{full_name}">
<input type="hidden" name="csrf" value="{self._settings_csrf_token()}">
<p class="warn" role="alert">This removes the <strong>{full_name}</strong> repository from the server: it can no longer be cloned or pushed, and its issues, pull requests, discussions, CI runs, deployments, and artifacts disappear from the web interface. The repository and its data are moved to the deleted-repositories archive, where only an administrator with access to the server can restore them.</p>
<label for="repo-delete-confirm">To confirm, type <strong>{full_name}</strong> in the box below</label>
<input id="repo-delete-confirm" name="confirm" autocomplete="off" spellcheck="false" required>
<button type="submit" class="danger" disabled>I understand, delete this repository</button>
</form></details>
<script>(function() {{
  document.querySelectorAll(".repo-delete-form").forEach(function(form) {{
    const input = form.querySelector("input[name=confirm]");
    const button = form.querySelector("button[type=submit]");
    input.addEventListener("input", function() {{ button.disabled = input.value !== form.dataset.expected; }});
    form.addEventListener("submit", function(event) {{
      if (input.value !== form.dataset.expected || !window.confirm("Delete " + form.dataset.expected + "? It will be moved to the deleted-repositories archive.")) event.preventDefault();
    }});
  }});
}})();</script>"""
                )
            )
        body = html_t(
            t"""<main class="repo-page">{_repo_tabs(base, "settings")}<div class="topbar"><div><h2>Settings</h2><p class="muted">Repository administration.</p></div></div>
{notice_html}
<section class="box repo-danger-zone"><h2>Danger zone</h2>
<div class="repo-danger-row"><div><strong>Delete this repository</strong><p class="muted">The repository is moved to the server's deleted-repositories archive. Restoring it requires server access. Please be certain.</p></div></div>
{delete_html}</section></main>"""
        )
        await _send_html(
            self.request,
            status,
            _html_page(str_t(t"Settings · {owner}/{repo}"), safe_html(body)),
        )

    async def _ui_repo_delete(self, owner: str, repo: str) -> None:
        from .database import db_repository_active_ci, db_repository_archive

        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return await self._forbidden(b"403 Forbidden\n")
        full_name = f"{owner}/{repo}"
        if not self._can_delete_repo():
            await self._audit("repo_delete", "failure", target=full_name, detail="forbidden")
            return await self._ui_repo_settings(
                owner, repo, "Only administrators can delete repositories.", "warn", 403
            )
        form = await self._read_form_urlencoded()
        if not self._valid_settings_csrf(form):
            return await self._ui_repo_settings(
                owner, repo, "The form expired. Reload the page and try again.", "warn", 403
            )
        if form.get("confirm", "") != full_name:
            return await self._ui_repo_settings(
                owner,
                repo,
                str_t(t"Confirmation did not match. Type {full_name} exactly to delete it."),
                "warn",
                422,
            )

        lock = self.server.push_locks.setdefault((owner, repo), asyncio.Lock())
        async with lock:
            repo_git = Path(_repo_bare_path(owner, repo))
            root = Path(GIT_PROJECT_ROOT).resolve()
            parent = root if owner == FLAT_OWNER_UI else root / owner
            if not _is_git_dir(repo_git):
                return await self._not_found()
            # Only delete a real bare repository directly inside its namespace:
            # never a symlinked alias or a working tree with uncommitted files.
            if (
                repo_git.name == ".git"
                or repo_git.is_symlink()
                or repo_git.parent.is_symlink()
                or repo_git.resolve().parent != parent
            ):
                await self._audit("repo_delete", "failure", target=full_name, detail="unsafe_path")
                return await self._ui_repo_settings(
                    owner, repo, "This repository cannot be deleted from the web interface.", "warn"
                )
            if await _call_in_thread(db_repository_active_ci, owner, repo):
                return await self._ui_repo_settings(
                    owner,
                    repo,
                    "CI is running for this repository. Cancel or wait for it, then try again.",
                    "warn",
                    409,
                )
            # Nothing is erased: the folder moves to the archive (outside the Git
            # root, so the Git service cannot reach it) and the database rows move
            # into a SQLite file beside it, so an administrator can restore both.
            config = self.server.context.config
            stamp = time.strftime("%Y%m%d-%H%M%S")
            dest = (
                config.deleted_repos_dir().absolute()
                / owner
                / f"{repo}-{stamp}-{secrets.token_hex(3)}"
            )
            archived_git = dest / repo_git.name
            try:
                dest.mkdir(parents=True)
                await asyncio.to_thread(_move_directory, repo_git, archived_git)
            except OSError as e:
                with contextlib.suppress(OSError):
                    dest.rmdir()
                await self._audit(
                    "repo_delete", "failure", target=full_name, detail=type(e).__name__
                )
                return await self._ui_repo_settings(
                    owner,
                    repo,
                    str_t(t"Failed to move repository to the archive: {e}"),
                    "warn",
                    500,
                )
            try:
                counts = await _call_in_thread(
                    db_repository_archive, owner, repo, str(dest / "data.sqlite")
                )
            except Exception as e:
                await asyncio.to_thread(_move_directory, archived_git, repo_git)
                with contextlib.suppress(OSError):
                    dest.rmdir()
                await self._audit(
                    "repo_delete", "failure", target=full_name, detail=type(e).__name__
                )
                return await self._ui_repo_settings(
                    owner, repo, "Failed to archive repository data; nothing was changed.", "warn"
                )
            manifest = {
                "owner": owner,
                "repo": repo,
                "deleted_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "deleted_by": self.remote_user or ("ip:" + self._client_ip()),
                "original_path": str(repo_git),
                "git_dir": repo_git.name,
                "rows": counts,
            }
            with contextlib.suppress(OSError):
                (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        await self._audit("repo_delete", "success", target=full_name, detail=str(dest))
        return await self._ui_home(
            str_t(t"Repository {full_name} was deleted and moved to the archive."), "ok"
        )

    # ========================================================
    # UI: Admin Users
    # ========================================================
    async def _ui_admin_settings(
        self, *, save: bool = False, notice_message: str = "", notice_kind: str = "ok"
    ) -> None:
        from .ci import parse_execution_trust
        from .database import (
            db_ci_execution_trust_get,
            db_ci_execution_trust_set,
            db_ci_preferences_get,
            db_ci_preferences_set,
            db_display_name_set,
        )
        from .settings_pages import (
            EXECUTION_TRUST_INPUT_LIMIT,
            basic_form,
            execution_trust_form,
            parse_preferences,
            preferences_forms,
            save_basic,
        )

        if REQUIRE_AUTH and not _require_admin(self):
            return await self._forbidden(b"403 Forbidden: admin required.\n")
        params = parse_qs(urlparse(self.path).query or "")
        favicon_flash = (params.get("favicon") or [""])[0]
        if not notice_message:
            notice_message = {
                "updated": "Favicon updated.",
                "reset": "Default favicon restored.",
            }.get(favicon_flash, "")
        notice = (
            safe_html(html_t(t'<p class="{notice_kind}" role="status">{notice_message}</p>'))
            if notice_message
            else safe_html("")
        )
        submitted_preferences: dict[str, str] | None = None
        trust_all_repositories = self.server.ci_manager.trust_all_repositories
        can_manage_trust = not trust_all_repositories and (
            _require_admin(self) if REQUIRE_AUTH else self._is_ci_trust_admin_peer()
        )
        response_status = 200
        value = await self.server.display_name()
        if save:
            form = await self._read_form_urlencoded()
            action = form.get("action", "appearance")
            if action != "appearance" and not self._valid_settings_csrf(form):
                return await self._forbidden(b"403 Forbidden: invalid security token.\n")
            try:
                if action == "ci_execution_trust":
                    if not can_manage_trust:
                        return await self._forbidden(
                            b"403 Forbidden: an admin session or configured CI trust admin IP is required.\n"
                        )
                    raw = form.get("trusted_repositories")
                    if raw is None or form.get("confirm_execution_trust") != "yes":
                        raise ValueError("Confirm the trusted repository changes before saving.")
                    if len(raw) > EXECUTION_TRUST_INPUT_LIMIT:
                        raise ValueError("The trusted repository list is too long.")
                    trusted = parse_execution_trust(raw)
                    async with self.server.settings_lock:
                        saved = await _call_in_thread(
                            db_ci_execution_trust_set,
                            "\n".join(sorted(trusted)),
                            form.get("trust_revision", ""),
                            actor=self.remote_user if REQUIRE_AUTH else "ip:" + self._client_ip(),
                            actor_user_id=self.remote_user_id if REQUIRE_AUTH else None,
                            ip=self._client_ip(),
                        )
                    if not saved:
                        response_status = 409
                        raise ValueError(
                            "Trusted CI repositories changed since you opened this page. "
                            "Review the current list before saving again."
                        )
                    message = "Trusted CI repositories saved. No restart is required."
                elif action.startswith("ci_"):
                    async with self.server.settings_lock:
                        global_values, _repo = await _call_in_thread(db_ci_preferences_get)
                        values = parse_preferences(form, global_values)
                        await _call_in_thread(db_ci_preferences_set, values)
                    message = "Server CI defaults saved. Repositories without an override inherit these values. New settings apply to future runs."
                    if action == "ci_retention":
                        message = "Server retention defaults saved and applied to stored runs and artifacts without a repository override."
                elif action == "basic":
                    async with self.server.settings_lock:
                        await _call_in_thread(save_basic, self.server.config_path, form)
                    message = "Server configuration saved. Restart the server to apply it; running settings are unchanged."
                elif action == "appearance":
                    value = form.get("display_name", "").strip() or "pygithost"
                    if len(value) > 80 or any(ord(char) < 32 or ord(char) == 127 for char in value):
                        raise ValueError(
                            "Display name must be at most 80 characters without control characters."
                        )
                    await _call_in_thread(db_display_name_set, value)
                    self.server._display_name = value
                    _display_name.set(value)
                    message = "Settings saved."
                else:
                    raise ValueError("Unknown settings action.")
                if action != "ci_execution_trust":
                    await self._audit(
                        "settings_save", "success", target=action, detail=f"fields={len(form)}"
                    )
                notice = safe_html(html_t(t'<p class="ok" role="status">{message}</p>'))
            except (ValueError, OSError) as exc:
                await self._audit(
                    "settings_save", "failure", target=action, detail=type(exc).__name__
                )
                notice = safe_html(html_t(t'<p class="warn" role="alert">{str(exc)}</p>'))
                submitted_preferences = form if action.startswith("ci_") else None
        global_values, _repo = await _call_in_thread(db_ci_preferences_get)
        token = self._settings_csrf_token()
        execution_trust = safe_html("")
        if trust_all_repositories:
            execution_trust = safe_html(
                '<section class="box" id="trusted-ci-repositories"><h2>Trusted CI repositories</h2>'
                '<p class="warn">IP-only mode trusts all repositories for host jobs and deployments. '
                "Every allowed client with write access can change the commands that run on GitHost. "
                "Authenticated Docker runners may claim jobs for any repository; worker limits still apply. "
                "Per-repository authorization resumes when sign-in is enabled.</p></section>"
            )
        elif can_manage_trust:
            trusted_repositories, trust_revision = await _call_in_thread(db_ci_execution_trust_get)
            execution_trust = execution_trust_form(
                "/admin/settings",
                token,
                trusted_repositories,
                trust_revision,
                os.environ.get("PYGITHOST_CI_TRUSTED_REPOSITORIES", ""),
                ip_only=not REQUIRE_AUTH,
            )
        custom_favicon = await _call_in_thread(db_favicon_get)
        if custom_favicon:
            favicon_type, favicon_data = custom_favicon
            favicon_digest = hashlib.sha256(favicon_data).hexdigest()[:12]
            favicon_status = safe_html(
                html_t(
                    t'<p class="muted">Current: uploaded {favicon_type}, {len(favicon_data)} bytes.</p><p><img src="/favicon.ico?v={favicon_digest}" alt="Current favicon" width="32" height="32"></p>'
                )
            )
        else:
            has_default = _default_favicon_path() is not None
            favicon_status = safe_html(
                '<p class="muted">Current: the bundled default favicon.</p>'
                + (
                    '<p><img src="/favicon.ico" alt="Current favicon" width="32" height="32"></p>'
                    if has_default
                    else ""
                )
            )
        favicon_html = safe_html(
            html_t(t'''<form method="POST" action="/admin/settings/favicon" enctype="multipart/form-data" style="margin-top:18px;border-top:1px solid var(--border);padding-top:16px">
<input type="hidden" name="csrf" value="{token}">
<label for="favicon-file">Favicon image</label><input id="favicon-file" type="file" name="favicon" accept=".ico,.png,.gif,.jpg,.jpeg,.webp,.svg,image/x-icon,image/png,image/gif,image/jpeg,image/webp,image/svg+xml">
{favicon_status}<p class="muted">Shown in browser tabs and bookmarks on every page. ICO, PNG, GIF, JPEG, WebP or SVG up to 512 KiB. <strong>Use default</strong> restores the bundled favicon.ico.</p>
<div class="row"><button type="submit" name="action" value="upload">Upload favicon</button><button type="submit" name="action" value="reset" formnovalidate>Use default</button></div></form>''')
        )
        try:
            basic = basic_form(
                "/admin/settings",
                token,
                self.server.context.config.to_dict(),
                self.server.config_path,
            )
        except (ValueError, OSError) as exc:
            basic = safe_html(
                html_t(
                    t'<p class="warn">Could not read the startup configuration: {str(exc)}</p>{basic_form("/admin/settings", token, self.server.context.config.to_dict(), None)}'
                )
            )
        preferences = preferences_forms(
            "/admin/settings", token, global_values, submitted=submitted_preferences
        )
        body = html_t(t'''<main class="repo-page"><div class="topbar"><h1>Server settings</h1><nav class="row"><a class="pill" href="/admin/email">Email delivery</a><a class="pill" href="/admin/users">Users</a></nav></div>{notice}
<section class="box"><h2>Appearance</h2><form method="POST" action="/admin/settings"><label for="display-name">Display name</label><input id="display-name" name="display_name" value="{value}" maxlength="80" placeholder="pygithost"><p class="muted">Shown in the top-left header on all pages. Leave blank to restore pygithost. This does not change repository URLs or email sender settings.</p><button type="submit">Save settings</button></form>{favicon_html}</section>{basic}{execution_trust}{preferences}<script src="/static/settings-pages.js" defer></script></main>''')
        return await _send_html(
            self.request, response_status, _html_page("Server settings", safe_html(body))
        )

    async def _ui_favicon_save(self) -> None:
        if REQUIRE_AUTH and not _require_admin(self):
            return await self._forbidden(b"403 Forbidden: admin required.\n")
        try:
            form, files = await self._read_multipart_form(max_bytes=MAX_FAVICON_BYTES + 64 * 1024)
        except ValueError as exc:
            return await self._ui_admin_settings(notice_message=str(exc), notice_kind="warn")
        if not self._valid_settings_csrf(form):
            return await self._forbidden(b"403 Forbidden: invalid security token.\n")
        action = form.get("action", "upload")
        try:
            if action == "reset":
                await _call_in_thread(db_favicon_clear)
            elif action == "upload":
                filename, data = files.get("favicon", ("", b""))
                content_type = _favicon_content_type(filename, data)
                await _call_in_thread(db_favicon_set, content_type, data)
            else:
                raise ValueError("Unknown favicon action.")
        except ValueError as exc:
            return await self._ui_admin_settings(notice_message=str(exc), notice_kind="warn")
        return await _send_redirect(
            self.request, "/admin/settings?favicon=" + ("reset" if action == "reset" else "updated")
        )

    def _is_ci_trust_admin_peer(self) -> bool:
        try:
            peer = str(ipaddress.ip_address(self._client_ip()))
        except ValueError:
            return False
        return peer in self.server.ci_trust_admin_ips

    def _settings_csrf_token(self) -> str:
        import hashlib
        import hmac

        session = _parse_cookie_header(self.headers.get("Cookie")).get(SESSION_COOKIE_NAME, "")
        identity = session if REQUIRE_AUTH else "ip:" + self._client_ip()
        return hmac.new(
            self.server.settings_csrf_secret, identity.encode(), hashlib.sha256
        ).hexdigest()

    def _valid_settings_csrf(self, form: dict[str, str]) -> bool:
        return secrets.compare_digest(
            form.get("csrf", "").encode(), self._settings_csrf_token().encode()
        )

    async def _ui_ci_preferences_save(self, owner: str, repo: str) -> None:
        from .database import db_ci_preferences_get, db_ci_preferences_set
        from .settings_pages import parse_preferences

        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        if REQUIRE_AUTH and not _require_admin(self):
            return await self._forbidden(b"403 Forbidden: admin required.\n")
        form = await self._read_form_urlencoded()
        if not self._valid_settings_csrf(form):
            return await self._forbidden(b"403 Forbidden: invalid security token.\n")
        if form.get("action") != "ci_environment":
            return await _send_text(
                self.request,
                400,
                "Only repository environment variables can be saved here. Configure project "
                "retention in ci/config.json; server defaults remain on the server settings page.\n",
            )
        try:
            async with self.server.settings_lock:
                _global, values = await _call_in_thread(db_ci_preferences_get, owner, repo)
                values = parse_preferences(form, values, repository=True)
                await _call_in_thread(db_ci_preferences_set, values, owner, repo)
        except (ValueError, OSError) as exc:
            return await self._ui_ci_config(
                owner, repo, notice=str(exc), error=True, preferences_submitted=form
            )
        return await self._ui_ci_config(
            owner,
            repo,
            notice="Repository settings saved. New runs use the updated environment variables.",
        )

    async def _ui_admin_users(self, notice: str = "", notice_kind: str = "ok") -> None:
        if not _require_admin(self):
            return await self._forbidden(b"403 Forbidden: admin only.\n")

        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(
                html_t(t'<div class="{cls}" style="margin-bottom:12px">{notice}</div>')
            )

        users = await asyncio.to_thread(db_list_users)
        all_users = users
        users, pagination, _page = _paginate_items(users, self.path, "/admin/users")
        rows: list[str] = []
        for uid, uname, is_admin, is_active, created_at in users:
            pill_admin = safe_html(
                '<span class="pill">admin</span>'
                if is_admin
                else '<span class="pill muted">user</span>'
            )
            pill_active = safe_html(
                '<span class="pill">active</span>'
                if is_active
                else '<span class="pill muted">disabled</span>'
            )
            toggle_label = "Disable" if is_active else "Enable"
            toggle_btn_class = "danger" if is_active else ""
            disable_self_guard = safe_html("")
            if int(uid) == int(self.remote_user_id or -1):
                disable_self_guard = safe_html('<span class="muted"> (you)</span>')
            rows.append(
                html_t(
                    t"""<tr>
<td><code>{uname}</code> {pill_admin} {pill_active}{disable_self_guard}</td>
<td class="muted">{created_at}</td>
<td style="text-align:right">
<form method="POST" action="/admin/users/toggle" style="display:inline">
<input type="hidden" name="user_id" value="{uid}"/>
<input type="hidden" name="make_active" value="{0 if is_active else 1}"/>
<button type="submit" class="{toggle_btn_class}">{toggle_label}</button>
</form>
</td>
</tr>"""
                )
            )
        rows_html = (
            join_html(rows) if rows else safe_html('<tr><td class="muted">No users.</td></tr>')
        )
        options_html = join_html(
            [html_t(t'<option value="{uid}">{uname}</option>') for uid, uname, *_rest in all_users]
        )

        body = html_t(
            t"""<div class="topbar"><h1 style="margin:0">Admin · Users</h1></div>
{notice_html}
<div class="box" style="margin-bottom:14px">
<h2 style="margin:0 0 10px 0;font-size:16px">Create user</h2>
<form method="POST" action="/admin/users/create">
<div class="row">
<div><label>Username</label><input name="username" placeholder="john" required /></div>
<div><label>Password</label><input name="password" type="password" placeholder="••••••••" required /></div>
<div><label>Admin?</label><select name="is_admin"><option value="0" selected>No</option><option value="1">Yes</option></select></div>
<div><button type="submit">Create</button></div>
</div>
</form>
</div>
<div class="box" style="margin-bottom:14px">
<h2 style="margin:0 0 10px 0;font-size:16px">Reset password</h2>
<form method="POST" action="/admin/users/reset">
<div class="row">
<div><label>User</label><select name="user_id">{options_html}</select></div>
<div><label>New password</label><input name="new_password" type="password" required /></div>
<div><button type="submit">Reset</button></div>
</div>
</form>
</div>
<div class="box"><h2 style="margin:0 0 10px 0;font-size:16px">All users</h2><table>{rows_html}</table>{pagination}</div>"""
        )
        await _send_html(self.request, 200, _html_page("Admin · Users", safe_html(body)))

    async def _ui_admin_users_create(self) -> None:
        if not _require_admin(self):
            return await self._forbidden(b"403 Forbidden: admin only.\n")
        form = await self._read_form_urlencoded()
        username = (form.get("username") or "").strip()
        password = (form.get("password") or "").strip()
        is_admin = (form.get("is_admin") or "0").strip() == "1"
        if not _safe_seg(username):
            return await self._ui_admin_users("Invalid username (use letters/numbers/._-).", "warn")
        if len(password) < 4:
            return await self._ui_admin_users("Password too short (min 4).", "warn")
        try:
            await asyncio.to_thread(db_create_user, username, password, is_admin)
        except sqlite3.IntegrityError:
            await self._audit("user_create", "failure", target=username, detail="already_exists")
            return await self._ui_admin_users("User already exists.", "warn")
        except Exception as e:
            await self._audit("user_create", "failure", target=username, detail=type(e).__name__)
            return await self._ui_admin_users(str_t(t"Failed to create user: {e}"), "warn")
        await self._audit(
            "user_create", "success", target=username, detail=f"admin={bool(is_admin)}"
        )
        return await self._ui_admin_users(str_t(t"User created: {username}"), "ok")

    async def _ui_admin_users_reset(self) -> None:
        if not _require_admin(self):
            return await self._forbidden(b"403 Forbidden: admin only.\n")
        form = await self._read_form_urlencoded()
        try:
            user_id = int((form.get("user_id") or "0").strip())
        except Exception:
            return await self._ui_admin_users("Invalid user id.", "warn")
        new_password = (form.get("new_password") or "").strip()
        if len(new_password) < 4:
            return await self._ui_admin_users("Password too short (min 4).", "warn")
        u = await asyncio.to_thread(db_get_user_by_id, user_id)
        if not u:
            return await self._ui_admin_users("User not found.", "warn")
        try:
            await asyncio.to_thread(db_reset_password, user_id, new_password)
        except Exception as e:
            await self._audit(
                "user_password_reset", "failure", target=u[1], detail=type(e).__name__
            )
            return await self._ui_admin_users(str_t(t"Failed to reset password: {e}"), "warn")
        await self._audit("user_password_reset", "success", target=u[1])
        return await self._ui_admin_users(str_t(t"Password updated for: {u[1]}"), "ok")

    async def _ui_admin_users_toggle(self) -> None:
        if not _require_admin(self):
            return await self._forbidden(b"403 Forbidden: admin only.\n")
        form = await self._read_form_urlencoded()
        try:
            user_id = int((form.get("user_id") or "0").strip())
        except Exception:
            return await self._ui_admin_users("Invalid user id.", "warn")
        make_active = (form.get("make_active") or "0").strip() == "1"
        u = await asyncio.to_thread(db_get_user_by_id, user_id)
        if not u:
            return await self._ui_admin_users("User not found.", "warn")
        if int(user_id) == int(self.remote_user_id or -1) and not make_active:
            return await self._ui_admin_users(
                "You cannot disable your own account from the UI.", "warn"
            )
        try:
            await asyncio.to_thread(db_set_user_active, user_id, make_active)
        except Exception as e:
            await self._audit("user_status", "failure", target=u[1], detail=type(e).__name__)
            return await self._ui_admin_users(str_t(t"Failed to update user: {e}"), "warn")
        status = "active" if make_active else "disabled"
        await self._audit("user_status", "success", target=u[1], detail=status)
        return await self._ui_admin_users(str_t(t"User '{u[1]}' is now {status}."), "ok")

    # ========================================================
    # UI: Repo + Branches + PRs
    # ========================================================
    async def _ui_repo(self, owner: str, repo: str) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return await self._forbidden(b"403 Forbidden\n")
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()

        query = parse_qs(urlparse(self.path).query or "")
        query_params = {key: values[0] for key, values in query.items()}

        default_branch, branches = await asyncio.gather(
            _git_default_branch(repo_git), _git_list_branches(repo_git)
        )
        default_commit = await _git_resolve_commit(repo_git, "refs/heads/" + default_branch)

        async def load_files() -> tuple[
            list[tuple[str, str]],
            list[tuple[str, str]],
            RepositoryOverview,
            int,
            int,
            int,
        ]:
            code, output, _ = await _run_git(
                repo_git, ["ls-tree", "-z", f"{default_commit or default_branch}:"]
            )
            entries = []
            if code == 0:
                for line in output.decode("utf-8", "replace").split("\0"):
                    if "\t" not in line:
                        continue
                    metadata, name = line.split("\t", 1)
                    parts = metadata.split()
                    entries.append((parts[1] if len(parts) >= 2 else "blob", name))
            entries.sort(key=lambda item: (0 if item[0] == "tree" else 1, item[1].lower()))
            total = len(entries)
            page = 1
            size = REPO_FILES_PAGE_SIZE
            page_entries = entries
            if total > REPO_FILES_PAGE_SIZE:
                size = _page_size(query, default=REPO_FILES_PAGE_SIZE)
                page = _clamp_page(_page_number(query), total, size)
                page_entries = entries[(page - 1) * size : page * size]
            overview: RepositoryOverview = await repository_overview(
                owner,
                repo,
                repo_git,
                default_commit,
                page_entries,
                page=page if total > REPO_FILES_PAGE_SIZE else None,
                page_size=size,
            )
            return entries, page_entries, overview, page, total, size

        languages, readme, latest_ci, tags_result, files = await asyncio.gather(
            repository_languages(owner, repo, repo_git, default_commit),
            _run_git(repo_git, ["show", f"{default_commit or default_branch}:README.md"]),
            _call_in_thread(db_ci_latest_run, owner, repo, default_branch),
            _run_git(
                repo_git,
                ["for-each-ref", "refs/tags", "--sort=-creatordate", "--format=%(refname:short)"],
            ),
            load_files(),
        )
        root_entries, page_entries, overview, files_page, files_total, files_size = files
        readme_code, readme_out, _ = readme
        tag_code, tag_output, _ = tags_result
        language_html = _language_panel(languages, default_branch)
        readme_text = ""
        readme_html = safe_html("")
        if readme_code == 0:
            readme_text = readme_out.decode("utf-8", "replace")
            readme_html = safe_html(
                html_t(
                    t"""<section id="repo-readme" class="box repo-document">
<div class="repo-markdown">{render_readme(readme_text)}</div><details><summary>View Markdown source</summary><pre><code id="readmeSource" class="language-markdown">{readme_text}</code></pre></details>
<script>
document.addEventListener("DOMContentLoaded", function() {{
    const code = document.getElementById("readmeSource");
    if (!code || !window.Prism) return;
    const script = document.createElement("script");
    script.src = "/static/assets/prismjs/components/prism-markdown.min.js";
    script.onload = function() {{ Prism.highlightElement(code); }};
    document.head.appendChild(script);
}});
</script>
</section>"""
                )
            )
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        if latest_ci:
            ci_status = latest_ci[1]
            current_commit = default_commit
            if current_commit != latest_ci[4]:
                ci_status = "stale"
            ci_badge = safe_html(
                html_t(
                    t'<a class="ci-status" data-status="{ci_status}" href="{base}/ci/runs/{latest_ci[0]}" title="{default_branch}: {latest_ci[2]} · {latest_ci[4][:8]}">CI: {ci_status}</a>'
                )
            )
        else:
            ci_badge = safe_html("")
        latest = overview["latest"]
        latest_html = safe_html("")
        if latest:
            initials = "".join(part[0] for part in latest["author"].split()[:2]).upper() or "?"
            latest_html = safe_html(
                html_t(
                    t'<div class="repo-latest-commit"><span class="repo-avatar" aria-hidden="true">{initials}</span><strong>{latest["author"]}</strong><a class="repo-latest-subject" href="{base}/commit/{latest["hash"]}">{latest["subject"]}</a>{ci_badge}<span class="repo-latest-meta"><a class="repo-latest-sha" href="{base}/commit/{latest["hash"]}">{latest["hash"][:7]}</a> · <time class="muted" datetime="{latest["date"]}" title="{latest["date"]}">{_relative_time(latest["date"])}</time></span><a class="repo-latest-history" href="{base}/commits?ref={q(default_branch)}">{octicon("history")}<span><strong>{overview["commit_count"] if overview["commit_count"] is not None else ""}</strong> Commits</span></a></div>'
                )
            )
        file_rows: list[str] = []
        for kind, name in page_entries:
            if kind == "tree":
                href = str_t(t"{base}/tree/{q(default_branch)}/{q(name, safe='/')}/")
                icon = TREE_FOLDER_ICON
            else:
                href = str_t(t"{base}/blob/{q(default_branch)}/{q(name, safe='/')}")
                icon = TREE_FILE_ICON
            change = overview["entries"].get(name)
            message = (
                safe_html(
                    html_t(
                        t'<a href="{base}/commit/{change["hash"]}" title="{change["subject"]}">{change["subject"]}</a>'
                    )
                )
                if change
                else safe_html('<span class="muted">—</span>')
            )
            changed_at = (
                safe_html(
                    html_t(
                        t'<time datetime="{change["date"]}" title="{change["date"]}">{_relative_time(change["date"])}</time>'
                    )
                )
                if change
                else safe_html("—")
            )
            file_rows.append(
                html_t(
                    t'<tr><td class="repo-entry-name">{icon}<a class="tree-name" href="{href}">{name}</a></td><td class="repo-entry-message">{message}</td><td class="repo-entry-date muted">{changed_at}</td></tr>'
                )
            )
        files_html = (
            join_html(file_rows)
            if file_rows
            else safe_html(
                '<tr><td colspan="3" class="muted">No files on the default branch.</td></tr>'
            )
        )
        files_pagination = (
            _pagination(
                base,
                query_params,
                files_page,
                files_page * files_size < files_total,
                total=files_total,
                per_page=files_size,
            )
            if files_total > REPO_FILES_PAGE_SIZE
            else safe_html("")
        )
        tags = tag_output.decode("utf-8", "replace").splitlines() if tag_code == 0 else []
        tags_html = (
            join_html(
                [
                    html_t(
                        t'<li><a href="{base}/tree/{q(tag)}/">{tag}</a><a href="{base}/archive.zip?{urlencode({"ref": tag})}" aria-label="Download source for tag {tag}">{octicon("download")}</a></li>'
                    )
                    for tag in tags[:5]
                ]
            )
            if tags
            else safe_html('<li class="muted">No tags yet.</li>')
        )
        contributors = overview["contributors"]
        contributors_html = (
            join_html(
                [
                    html_t(
                        t'<li><span class="repo-avatar" aria-hidden="true">{_initials(str(person["name"]))}</span><strong>{person["name"]}</strong><span class="muted">{person["commits"]} {"commit" if person["commits"] == 1 else "commits"}</span></li>'
                    )
                    for person in contributors[:5]
                ]
            )
            if contributors
            else safe_html('<li class="muted">No contributors found.</li>')
        )
        more_contributors = safe_html("")
        if len(contributors) > 5:
            remaining = join_html(
                [
                    html_t(
                        t'<li><span class="repo-avatar" aria-hidden="true">{_initials(str(person["name"]))}</span><strong>{person["name"]}</strong><span class="muted">{person["commits"]} {"commit" if person["commits"] == 1 else "commits"}</span></li>'
                    )
                    for person in contributors[5:]
                ]
            )
            more_contributors = safe_html(
                html_t(
                    t'<details class="repo-contributors-more"><summary>Show all {len(contributors)} contributors</summary><ul class="repo-summary-list">{remaining}</ul></details>'
                )
            )
        summary = next(
            (
                line.strip()
                for line in readme_text.splitlines()
                if line.strip() and not line.lstrip().startswith(("#", "```", "-", "*", "|", "!"))
            ),
            "",
        )
        summary = summary[:240] + ("…" if len(summary) > 240 else "")
        license_html, license_link = safe_html(""), safe_html("")
        license_label_text = ""
        for kind, filename in root_entries:
            if kind == "blob" and filename.casefold() in (
                "license",
                "license.md",
                "license.txt",
                "copying",
                "copying.txt",
            ):
                license_code, license_bytes, _ = await _run_git(
                    repo_git, ["show", f"{default_commit}:{filename}"]
                )
                if license_code == 0:
                    license_text = license_bytes[:65536].decode("utf-8", "replace")
                    license_label = (
                        "MIT license"
                        if "Permission is hereby granted, free of charge" in license_text
                        else "License"
                    )
                    license_label_text = license_label
                    license_link = safe_html(
                        html_t(t'<a href="#repo-license">{octicon("law")}{license_label}</a>')
                    )
                    license_html = safe_html(
                        html_t(
                            t'<section id="repo-license" class="box repo-document"><h2>{license_label}</h2><pre>{license_text}</pre><a href="{base}/blob/{q(default_branch)}/{q(filename)}">View full license file</a></section>'
                        )
                    )
                break
        document_nav = (
            safe_html(
                html_t(
                    t'<nav class="repo-document-nav" aria-label="Repository files navigation">{safe_html(html_t(t'<a href="#repo-readme" aria-current="true">{octicon("book")}README</a>')) if readme_text else safe_html("")}{license_link}</nav>'
                )
            )
            if readme_text or license_html
            else safe_html("")
        )
        about_html = safe_html(
            html_t(
                t'<section class="box"><h2>About</h2><p class="repo-about-summary">{summary or "No description available in README."}</p><div class="repo-about-counts">{safe_html(html_t(t'<a href="#repo-readme">{octicon("book")}Readme</a>') if readme_text else "")}{safe_html(html_t(t'<a href="#repo-license">{octicon("law")}{license_label_text}</a>') if license_label_text else "")}<a href="{base}/commits?ref={q(default_branch)}">{octicon("history")}<strong>{overview["commit_count"] if overview["commit_count"] is not None else "—"}</strong> commits</a><a href="{base}/branches">{octicon("git-branch")}<strong>{len(branches)}</strong> {"branch" if len(branches) == 1 else "branches"}</a><a href="#repo-tags">{octicon("tag")}<strong>{len(tags)}</strong> {"tag" if len(tags) == 1 else "tags"}</a></div></section><section id="repo-tags" class="box"><h2>Tags</h2><ul class="repo-summary-list">{tags_html}</ul></section><section class="box"><h2>Contributors <span class="Counter">{len(contributors)}</span></h2><ul class="repo-summary-list">{contributors_html}</ul>{more_contributors}</section>'
            )
        )

        options: list[str] = []
        for b in branches:
            selected = safe_html(" selected") if b == default_branch else safe_html("")
            options.append(html_t(t'<option value="{b}"{selected}>{b}</option>'))
        options_html = join_html(options) if options else safe_html("<option>(none)</option>")

        tag_count = len(tags)
        readme_panel = (
            safe_html(
                html_t(
                    t'<div class="box repo-readme-panel">{document_nav}{readme_html}{license_html}</div>'
                )
            )
            if readme_text or license_html
            else safe_html("")
        )
        body = html_t(
            t"""{_repo_tabs(base, "code")}
<div class="repo-content-layout"><div class="repo-content-main">
<div class="repo-code-toolbar"><label class="repo-branch-picker" title="Switch branches">{octicon("git-branch")}<span class="visually-hidden">Switch branch</span><select id="branchSel" onchange="goBranch()">{options_html}</select></label>
<a class="repo-toolbar-link" href="{base}/branches">{octicon("git-branch")}<strong>{len(branches)}</strong> {"Branch" if len(branches) == 1 else "Branches"}</a><a class="repo-toolbar-link" href="#repo-tags">{octicon("tag")}<strong>{tag_count}</strong> {"Tag" if tag_count == 1 else "Tags"}</a>
<noscript><button type="button">Browse</button></noscript>{_repo_code_menu(owner, repo, default_branch, can_edit=_has_write_scope(self))}</div>
<script>function goBranch(){{var b=document.getElementById('branchSel').value;if(!b)return;window.location='{base}/tree/' + encodeURIComponent(b) + '/';}}</script>
<div class="box repo-files-panel">{latest_html}<div class="repo-files-scroll"><table><thead class="visually-hidden"><tr><th>Name</th><th>Last commit message</th><th>Last commit date</th></tr></thead><tbody>{files_html}</tbody></table></div>{files_pagination}</div>
{readme_panel}</div><aside class="repo-sidebar">{about_html}{language_html}</aside></div>"""
        )
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"{owner}/{repo}"),
                safe_html(html_t(t'<main class="repo-page">{safe_html(body)}</main>')),
            ),
        )

    async def _ui_branches(
        self, owner: str, repo: str, notice: str = "", notice_kind: str = "ok"
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return await self._forbidden(b"403 Forbidden\n")
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()

        default_branch = await _git_default_branch(repo_git)
        params = parse_qs(urlparse(self.path).query or "")
        search = (params.get("q") or [""])[0].strip()[:128]
        view = (params.get("view") or ["all"])[0]
        view = view if view in ("all", "protected", "merged") else "all"
        sort = (params.get("sort") or ["updated"])[0]
        sort = sort if sort in ("updated", "name") else "updated"
        code, output, _ = await _run_git(
            repo_git,
            [
                "for-each-ref",
                "refs/heads",
                "--sort=" + ("refname" if sort == "name" else "-committerdate"),
                "--format=%(refname:strip=2)%00%(objectname)%00%(subject)%00%(authorname)%00%(committerdate:iso8601-strict)",
            ],
        )
        branch_data = []
        for line in output.decode("utf-8", "replace").splitlines() if code == 0 else []:
            fields = line.split("\0")
            if len(fields) == 5:
                branch_data.append(fields)
        branches = [fields[0] for fields in branch_data]
        # GitHub marks branches whose commits are all contained in the default
        # branch with a purple "Merged" label, so leftover head branches are
        # easy to spot and delete after their pull request lands.
        code, merged_output, _ = await _run_git(
            repo_git,
            [
                "for-each-ref",
                "--merged=" + default_branch,
                "--format=%(refname:strip=2)",
                "refs/heads",
            ],
        )
        merged_branches = (
            {
                line.strip()
                for line in merged_output.decode("utf-8", "replace").splitlines()
                if line.strip()
            }
            if code == 0
            else set()
        )
        policy = await self.server.ci_manager.config(owner, repo)
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(
                html_t(t'<div class="{cls}" style="margin-bottom:12px">{notice}</div>')
            )
        can_write = _has_write_scope(self)

        rows: list[str] = []
        default_rows: list[str] = []
        for b, sha, subject, author, updated in branch_data:
            is_protected = protected_branch(policy, b)
            is_merged = b != default_branch and b in merged_branches
            if (
                search.casefold() not in b.casefold()
                or (view == "protected" and not is_protected)
                or (view == "merged" and not is_merged)
            ):
                continue
            browse = str_t(t"{base}/tree/{q(b)}/")
            if can_write and b != default_branch and not is_protected:
                del_html = safe_html(
                    html_t(
                        t'''<form method="POST" action="{base}/branches/delete" data-branch="{b}" onsubmit="return confirm('Delete branch ' + this.dataset.branch + '? This cannot be undone from the web interface.');">
<input type="hidden" name="branch" value="{b}"><input type="hidden" name="expected_commit" value="{sha}"><button class="repo-delete" type="submit" aria-label="Delete branch {b}">Delete</button></form>'''
                    )
                )
            elif b == default_branch or is_protected:
                del_html = safe_html('<span class="muted repo-lock">Deletion blocked</span>')
            else:
                del_html = safe_html('<span class="muted repo-lock">Read only</span>')
            default_pill = safe_html(
                ' <span class="pill repo-default">Default</span>' if b == default_branch else ""
            )
            protected_pill = safe_html(
                ' <span class="pill">Protected</span>' if is_protected else ""
            )
            merged_pill = safe_html(
                html_t(
                    t' <span class="pill pill-merged" title="Every commit is contained in {default_branch}">Merged</span>'
                )
                if b != default_branch and b in merged_branches
                else ""
            )
            compare_link = (
                safe_html(
                    html_t(
                        t'<a class="pill" href="{base}/pulls/new?{urlencode({"source": b, "target": default_branch})}">New pull request</a>'
                    )
                )
                if b != default_branch
                else safe_html("")
            )
            row = html_t(t'''<article class="repo-branch-row"><div class="repo-branch-info"><div class="repo-branch-name"><a href="{browse}"><code>{b}</code></a>{default_pill}{protected_pill}{merged_pill}</div>
<p class="repo-commit-subject"><a href="{base}/commit/{sha}" title="{subject}">{subject or "Untitled commit"}</a></p><p class="muted"><a href="{base}/commit/{sha}"><code>{sha[:8]}</code></a> · {author} · <time datetime="{updated}">{updated.replace("T", " ")}</time></p></div>
<div class="repo-branch-actions"><a class="pill" href="{base}/commits?ref={q(b)}">Commits</a>{compare_link}{del_html}</div></article>''')
            (default_rows if b == default_branch else rows).append(row)

        if can_write:
            create_box = safe_html(
                html_t(
                    t"""<details id="new-branch" class="box repo-create"{safe_html(" open" if notice_kind == "warn" else "")}><summary>New branch</summary>
<form method="POST" action="{base}/branches/create"><div class="row">
<div><label for="branch-name">New branch name</label><input id="branch-name" name="new_branch" placeholder="feature/my-change" required/></div>
<div><label for="branch-base">Create from branch, tag, or commit</label><input id="branch-base" name="from_ref" list="branch-bases" value="{default_branch}" required/><datalist id="branch-bases">{join_html([html_t(t'<option value="{b}"></option>') for b in branches])}</datalist></div>
<div><button type="submit">Create branch</button></div>
</div><p class="muted">Your new branch starts at the selected revision. Protected branch names cannot be created here.</p></form></details>"""
                )
            )
        else:
            create_box = safe_html(
                '<div class="box warn" style="margin-bottom:14px">You don’t have <code>write</code> scope, so branch create/delete is disabled.</div>'
            )
        rows, pagination, _page = _paginate_items(rows, self.path, base + "/branches")
        if search:
            rows_heading = "Matching branches"
        elif view == "merged":
            rows_heading = "Merged branches"
        elif view == "protected":
            rows_heading = "Protected branches"
        else:
            rows_heading = "Other branches"
        if rows:
            rows_html = join_html(rows)
        elif view == "merged" and not search:
            rows_html = safe_html(
                '<div class="repo-empty"><h2>No merged branches</h2><p class="muted">Branches whose commits are all in the default branch appear here after a merge.</p></div>'
            )
        elif search or view != "all":
            rows_html = safe_html(
                '<div class="repo-empty"><h2>No matching branches</h2><p class="muted">Try a different search or filter.</p></div>'
            )
        else:
            rows_html = safe_html(
                '<div class="repo-empty"><h2>No other branches yet</h2><p class="muted">Create a branch to work on changes without updating the default branch.</p></div>'
            )
        default_html = (
            safe_html(
                html_t(
                    t'<section class="box repo-list"><div class="repo-panel-heading"><h2>Default branch</h2></div>{join_html(default_rows)}</section>'
                )
            )
            if default_rows
            else safe_html("")
        )
        body = html_t(
            t"""<main class="repo-page">{_repo_tabs(base, "branches")}<div class="topbar"><div><h2>Branches</h2><p class="muted">Manage development branches and open pull requests.</p></div><span class="pill">{len(branches)} branches</span></div>
{notice_html}
<form class="repo-search" method="GET" action="{base}/branches" role="search"><input type="hidden" name="per_page" value="{_page_size(params)}"><label for="branch-search">Find a branch</label><div class="row"><input id="branch-search" type="search" name="q" value="{search}" placeholder="Search branches…" maxlength="128">
<select name="view" aria-label="Branch filter"><option value="all"{safe_html(" selected" if view == "all" else "")}>All branches</option><option value="protected"{safe_html(" selected" if view == "protected" else "")}>Protected branches</option><option value="merged"{safe_html(" selected" if view == "merged" else "")}>Merged branches</option></select>
<select name="sort" aria-label="Branch sort"><option value="updated"{safe_html(" selected" if sort == "updated" else "")}>Recently updated</option><option value="name"{safe_html(" selected" if sort == "name" else "")}>Name</option></select><button type="submit">Find branches</button><a class="pill" href="{base}/branches">Reset</a></div></form>
{create_box}{default_html}<section class="box repo-list"><div class="repo-panel-heading"><h2>{rows_heading}</h2><span class="muted">{len(rows)} shown</span></div>{rows_html}{pagination}</section></main>"""
        )
        await _send_html(
            self.request, 200, _html_page(str_t(t"Branches · {owner}/{repo}"), safe_html(body))
        )

    async def _ui_branch_create(self, owner: str, repo: str) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._ui_branches(
                owner, repo, "You need write scope to create branches.", "warn"
            )
        form = await self._read_form_urlencoded()
        new_branch = (form.get("new_branch") or "").strip()
        from_ref = (form.get("from_ref") or "").strip()
        if not _safe_branch_name(new_branch):
            return await self._ui_branches(owner, repo, "Invalid branch name.", "warn")
        if not from_ref:
            return await self._ui_branches(owner, repo, "From ref is required.", "warn")
        if protected_branch(await self.server.ci_manager.config(owner, repo), new_branch):
            return await self._ui_branches(
                owner,
                repo,
                "Protected branch creation is blocked; change protection settings first.",
                "warn",
            )
        ok, msg = await _git_create_branch(_repo_bare_path(owner, repo), new_branch, from_ref)
        return await self._ui_branches(owner, repo, msg, "ok" if ok else "warn")

    async def _ui_branch_delete(self, owner: str, repo: str) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._ui_branches(
                owner, repo, "You need write scope to delete branches.", "warn"
            )
        form = await self._read_form_urlencoded()
        branch = (form.get("branch") or "").strip()
        if not _safe_branch_name(branch):
            return await self._ui_branches(owner, repo, "Invalid branch name.", "warn")
        if protected_branch(await self.server.ci_manager.config(owner, repo), branch):
            return await self._ui_branches(
                owner, repo, "Protected branches cannot be deleted.", "warn"
            )
        repo_git = _repo_bare_path(owner, repo)
        default_branch = await _git_default_branch(repo_git)
        if branch == default_branch:
            return await self._ui_branches(
                owner, repo, "Default branch is protected and cannot be deleted.", "warn"
            )
        expected = (form.get("expected_commit") or "").strip()
        if expected and not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", expected):
            return await self._ui_branches(
                owner, repo, "Invalid branch revision. Refresh and try again.", "warn"
            )
        current = await _git_resolve_commit(repo_git, "refs/heads/" + branch)
        if not current or (expected and expected != current):
            return await self._ui_branches(
                owner,
                repo,
                "Branch changed or no longer exists. Refresh before deleting it.",
                "warn",
            )
        ok, msg = await _git_delete_branch(repo_git, branch, expected_commit=expected or current)
        return await self._ui_branches(owner, repo, msg, "ok" if ok else "warn")

    async def _ui_pulls(
        self, owner: str, repo: str, notice: str = "", notice_kind: str = "ok"
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return await self._forbidden(b"403 Forbidden\n")
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()

        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query or "")
        status = (qs.get("status") or ["open"])[0].strip().lower()
        if status not in ("open", "closed", "merged", "all"):
            status = "open"
        from .database import db_pr_comment_counts, db_pr_count

        size = _page_size(qs)
        totals: dict[str, int] = {}
        for tab in ("open", "merged", "closed"):
            totals[tab] = await asyncio.to_thread(db_pr_count, owner, repo, tab)
        totals["all"] = await asyncio.to_thread(db_pr_count, owner, repo)
        total = totals.get(status, 0)
        page = _clamp_page(_page_number(qs), total, size)
        rows_db = await asyncio.to_thread(
            db_pr_list,
            owner,
            repo,
            None if status == "all" else status,
            limit=size,
            offset=(page - 1) * size,
        )
        pagination = _pagination(
            str_t(t"/r/{q(owner)}/{q(repo)}/pulls"),
            {key: values[0] for key, values in qs.items() if key != "page"},
            page,
            page * size < total,
            total=total,
            per_page=size,
        )
        comment_counts = await asyncio.to_thread(db_pr_comment_counts, [row[0] for row in rows_db])
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(
                html_t(t'<div class="{cls}" style="margin-bottom:12px">{notice}</div>')
            )

        rows: list[str] = []
        for pr_id, title, src, tgt, st, created_at in rows_db:
            count = comment_counts.get(pr_id, 0)
            when = _relative_time(created_at) or created_at
            count_suffix = (
                safe_html(
                    html_t(
                        t'<a class="topic-row-comments" href="{base}/pulls/{pr_id}" title="{count} comment(s)">{octicon("comment")}{count}</a>'
                    )
                )
                if count
                else safe_html("")
            )
            rows.append(
                html_t(
                    t"""<li class="topic-list-row pr-list-row">
<span class="pull-status-icon pull-status-{st}" title="{st.capitalize()}">{_PULL_STATE_ICONS.get(st, _PULL_STATE_ICONS["open"])}</span>
<div><a class="review-row-title" href="{base}/pulls/{pr_id}">{title}</a> <span class="pill pill-{st}">{st}</span>
<div class="review-row-meta">#{pr_id} opened <time title="{created_at}">{when}</time> · <code>{src}</code> → <code>{tgt}</code></div></div>
<div class="topic-row-badges">{count_suffix}</div></li>"""
                )
            )
        rows_html = (
            join_html(rows)
            if rows
            else safe_html(
                html_t(
                    t'<li class="topic-list-empty">{octicon("git-pull-request", size=24)}<h3>No pull requests</h3><p class="muted">Pull requests let you propose, review and merge changes between branches.</p></li>'
                )
            )
        )
        tab_links = join_html(
            html_t(
                t'<a href="{base}/pulls?status={key}"{safe_html(' aria-current="page"' if status == key else "")}>{octicon(icon)}{label} {totals[key]}</a>'
            )
            for key, icon, label in (
                ("open", "git-pull-request", "Open"),
                ("merged", "git-merge", "Merged"),
                ("closed", "git-pull-request-closed", "Closed"),
                ("all", "git-commit", "All"),
            )
        )
        body = html_t(
            t"""{_repo_tabs(base, "pulls")}<div class="topbar"><h2>Pull requests</h2><a class="btn btn-primary" href="{base}/pulls/new">New pull request</a></div>
{notice_html}
<section class="topic-list-panel" aria-label="Pull request list"><div class="topic-list-heading"><nav aria-label="Pull request status">{tab_links}</nav><span class="muted">{total} {"pull request" if total == 1 else "pull requests"}</span></div><ul class="topic-list">{rows_html}</ul></section>{pagination}"""
        )
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"Pull requests · {owner}/{repo}"),
                safe_html(
                    html_t(
                        t'<main class="repo-page review-page review-list">{safe_html(body)}</main>'
                    )
                ),
            ),
        )

    async def _ui_pulls_new(
        self, owner: str, repo: str, notice: str = "", notice_kind: str = "ok"
    ) -> None:
        """Dedicated pull-request creation page (linked from '+ New pull request')."""
        owner = unquote(owner)
        repo = unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        repo_git = _repo_bare_path(owner, repo)
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query or "")
        default_branch = await _git_default_branch(repo_git)
        branches = await _git_list_branches(repo_git)
        if not branches:
            return await self._ui_pulls(
                owner, repo, "Create a branch before opening a pull request.", "warn"
            )
        selected_source = (qs.get("source") or [""])[0]
        selected_target = (qs.get("target") or [default_branch])[0]
        if selected_target not in branches:
            selected_target = default_branch
        opt_src = join_html(
            [
                html_t(
                    t'<option value="{b}"{safe_html(" selected" if b == selected_source else "")}>{b}</option>'
                )
                for b in branches
            ]
        )
        opt_tgt = join_html(
            [
                html_t(
                    t'<option value="{b}"{safe_html(" selected" if b == selected_target else "")}>{b}</option>'
                )
                for b in branches
            ]
        )
        warn_merge = safe_html(
            '<div class="warn" style="margin-top:10px">Merging is <b>fast-forward only</b> on this server.</div>'
        )
        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(
                html_t(t'<div class="{cls}" style="margin-bottom:12px">{notice}</div>')
            )
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        body = html_t(
            t"""{_repo_tabs(base, "pulls")}<div class="topbar"><h2>Open a pull request</h2>
</div>
{notice_html}
<div class="box" style="margin-bottom:14px">{_pr_create_form_html(base, opt_src, opt_tgt, warn_merge)}</div>"""
        )
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"Open a pull request · {owner}/{repo}"),
                safe_html(
                    html_t(
                        t'<main class="repo-page">{safe_html(body)}{self._issue_editor_assets()}</main>'
                    )
                ),
            ),
        )

    async def _ui_pulls_create(self, owner: str, repo: str) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return await self._forbidden(b"403 Forbidden\n")
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()
        form = await self._read_form_urlencoded()
        title = (form.get("title") or "").strip()
        body = (form.get("body") or "").strip()
        source_branch = (form.get("source_branch") or "").strip()
        target_branch = (form.get("target_branch") or "").strip()
        if not title:
            return await self._ui_pulls_new(owner, repo, "Title is required.", "warn")
        if not (_safe_branch_name(source_branch) and _safe_branch_name(target_branch)):
            return await self._ui_pulls_new(owner, repo, "Invalid branch name.", "warn")
        if source_branch == target_branch:
            return await self._ui_pulls_new(
                owner, repo, "Source and target must be different.", "warn"
            )
        src = await _git_resolve_commit(repo_git, "refs/heads/" + source_branch)
        tgt = await _git_resolve_commit(repo_git, "refs/heads/" + target_branch)
        if not src:
            return await self._ui_pulls_new(
                owner, repo, str_t(t"Source branch not found: {source_branch}"), "warn"
            )
        if not tgt:
            return await self._ui_pulls_new(
                owner, repo, str_t(t"Target branch not found: {target_branch}"), "warn"
            )
        pr_id = await asyncio.to_thread(
            db_pr_create,
            owner,
            repo,
            title,
            body,
            source_branch,
            target_branch,
            self.remote_user_id,
        )
        await self.server.ci_manager.enqueue(
            owner,
            repo,
            "pull_request",
            target_branch,
            tgt,
            {
                "pr_number": pr_id,
                "base_branch": target_branch,
                "head_branch": source_branch,
                "base_commit": tgt,
                "head_commit": src,
            },
        )
        await _send_redirect(self.request, str_t(t"/r/{q(owner)}/{q(repo)}/pulls/{pr_id}"))

    async def _ui_pull_view(
        self, owner: str, repo: str, pr_id: int, notice: str = "", notice_kind: str = "ok"
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        row = await asyncio.to_thread(db_pr_get, pr_id)
        if not row:
            return await self._not_found()
        (
            _id,
            db_owner,
            db_repo,
            title,
            body,
            src_branch,
            tgt_branch,
            author_user_id,
            status,
            created_at,
            closed_at,
            merged_at,
            merge_method,
            merge_commit,
        ) = row
        if db_owner != owner or db_repo != repo:
            return await self._not_found()
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        src_commit = await _git_resolve_commit(repo_git, "refs/heads/" + src_branch)
        tgt_commit = await _git_resolve_commit(repo_git, "refs/heads/" + tgt_branch)
        commits: list[dict[str, str]] = []
        params = parse_qs(urlparse(self.path).query or "")
        pr_url = f"{base}/pulls/{pr_id}"
        view = (params.get("tab") or [""])[0]
        if view not in ("conversation", "commits", "checks", "files"):
            view = (
                "files" if "file" in params else "commits" if "page" in params else "conversation"
            )
        page = _page_number(params)
        size = _page_size(params)
        total: int | None = 0
        merge_base = (
            await _git_merge_base(repo_git, tgt_commit, src_commit)
            if (src_commit and tgt_commit)
            else None
        )
        if src_commit and tgt_commit and src_commit != tgt_commit:
            total = await _git_commit_count(repo_git, tgt_commit + ".." + src_commit)
            if total is not None:
                page = _clamp_page(page, total, size)
            if view == "commits":
                commits = await _git_list_commits(
                    repo_git, tgt_commit + ".." + src_commit, limit=size + 1, skip=(page - 1) * size
                )
        commits_pagination = _pagination(
            pr_url, {"tab": "commits"}, page, len(commits) > size, total=total, per_page=size
        )
        commits = commits[:size]
        changed_files: list[ChangedFile] = (
            await _git_diff_files(repo_git, merge_base, src_commit)
            if (merge_base and src_commit and merge_base != src_commit)
            else []
        )
        selected_file = (params.get("file") or [""])[0]
        if selected_file and not any(f["path"] == selected_file for f in changed_files):
            selected_file = ""
        diff_text, diff_trunc = "", False
        if view == "files" and src_commit and tgt_commit and src_commit != tgt_commit:
            # Three-dot diff: show what this PR adds relative to the merge base,
            # not unrelated target-branch changes.
            diff_text, diff_trunc = await _git_diff_between(
                repo_git,
                merge_base or tgt_commit,
                src_commit,
                max_bytes=PR_PATCH_MAX_BYTES,
                path=selected_file,
            )
        elif src_commit and tgt_commit and src_commit == tgt_commit:
            diff_text, diff_trunc = "(No changes; branches point to the same commit.)", False
        else:
            diff_text, diff_trunc = "(Could not resolve one or both branches.)", False
        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(
                html_t(t'<div class="{cls}" style="margin-bottom:12px">{notice}</div>')
            )
        can_write = _has_write_scope(self)
        merge_box = safe_html("")
        needs_checks = view in ("conversation", "checks")
        ci_policy = (
            await self.server.ci_manager.config(owner, repo, include_secrets=False)
            if needs_checks
            else {"require_ci": False}
        )
        check = (
            await self.server.ci_manager.merge_check(
                owner, repo, pr_id, tgt_commit or "", src_commit or "", tgt_branch
            )
            if needs_checks
            else None
        )
        ci_passed = bool(check and check[1] == "success" and src_commit and tgt_commit)
        ci_label = (
            check[1].replace("_", " ")
            if check
            else "not run for current commits (missing or outdated)"
        )
        ci_requirement = "required" if ci_policy["require_ci"] else "informational"
        check_href = f"{base}/ci/runs/{check[0]}" if check else f"{base}/ci"
        ci_panel = safe_html(
            html_t(
                t'<section class="box pr-check-panel"><h2>CI checks</h2><p>CI is {ci_requirement}: {ci_label}.</p><a href="{check_href}">{"View check run" if check else "View CI runs"}</a></section>'
            )
        )
        merge_note = safe_html("")
        if status == "merged":
            short_commit = (merge_commit or "")[:8]
            merge_note = safe_html(
                html_t(
                    t'<div class="ok" style="margin-top:10px">Merged ({merge_method or ""}). Target now at <code>{short_commit}</code>.</div>'
                )
            )
        elif status == "closed":
            merge_note = safe_html('<div class="warn" style="margin-top:10px">Closed.</div>')

        conflicts = None
        if view == "conversation" and status == "open" and src_commit and tgt_commit:
            if merge_base is None:
                conflicts = None  # incompatible histories; simulate unavailable
            elif merge_base != tgt_commit:
                conflicts = await _git_merge_conflicts(
                    repo_git, "refs/heads/" + tgt_branch, "refs/heads/" + src_branch
                )
            else:
                conflicts = []  # fast-forward possible; no conflict simulation needed
        conflict_html = safe_html("")
        if status == "open" and can_write:
            if conflicts is None:
                conflict_html = safe_html(
                    '<div class="warn" style="margin-top:10px">Cannot simulate a merge (incompatible histories); a fast-forward merge will still verify the current commits.</div>'
                )
            elif merge_base == tgt_commit:
                conflict_html = safe_html(
                    '<div class="muted" style="margin-top:10px">The target is an ancestor of this branch; a clean fast-forward merge is possible.</div>'
                )
            elif conflicts:
                conflict_html = safe_html(
                    html_t(
                        t'<div class="warn" style="margin-top:10px"><b>Merge conflict:</b> <code>{tgt_branch}</code> has advanced past the merge base, and merging this branch now would conflict. <a class="pill" href="{base}/pulls/{pr_id}/resolve/ide">Resolve conflicts in the web IDE</a> creates a merge commit on <code>{src_branch}</code>, or update the branch with Git (merge/rebase, resolve, push).</div>'
                    )
                )
            else:
                conflict_html = safe_html(
                    '<div class="muted" style="margin-top:10px">The target has advanced past the merge base, but the simulated merge reports no conflicts. Fast-forward merges still verify both commits at merge time.</div>'
                )
        merge_disabled = safe_html(
            ' disabled title="Successful CI for the current PR commits is required"'
            if ci_policy["require_ci"] and not ci_passed
            else ""
        )
        if status == "open":
            if can_write:
                merge_box = safe_html(
                    html_t(
                        t"""<div class="box" style="margin-bottom:14px"><h2 style="margin:0 0 10px 0;font-size:16px">Merge</h2>
<div class="muted">This server supports <b>fast-forward only</b> merges.</div>
{conflict_html}
<form method="POST" action="{base}/pulls/{pr_id}/merge" style="margin-top:10px"><button type="submit"{merge_disabled}>Merge (ff-only)</button></form>
<form method="POST" action="{base}/pulls/{pr_id}/close" style="margin-top:10px"><button class="secondary" type="submit">{octicon("git-pull-request-closed", cls="issue-action-icon-close-pr")}Close pull request</button></form></div>"""
                    )
                )
            else:
                merge_box = safe_html(
                    '<div class="box warn" style="margin-bottom:14px">You don’t have <code>write</code> scope. You can’t merge/close this PR from the UI.</div>'
                )
        elif status == "closed" and can_write:
            merge_box = safe_html(
                html_t(
                    t'<div class="box"><form method="POST" action="{base}/pulls/{pr_id}/reopen"><button class="secondary" type="submit">Reopen pull request</button></form></div>'
                )
            )

        commit_rows: list[str] = []
        for c in commits:
            ch = c["hash"]
            commit_rows.append(
                html_t(
                    t"""<tr><td style="width:110px"><a href="{base}/commit/{q(ch)}"><code>{ch[:8]}</code></a></td>
<td>{c["subject"]}</td><td class="muted">{c["author_name"]}</td><td class="muted"><small>{c["date"]}</small></td></tr>"""
                )
            )
        commits_html = (
            join_html(commit_rows)
            if commit_rows
            else safe_html(
                '<tr><td class="muted">No commits (or branches not resolvable).</td></tr>'
            )
        )
        diff_html = _prism_diff_patch_html(diff_text, diff_trunc, "Diff") if view == "files" else ""
        if selected_file:
            heading = safe_html(
                html_t(
                    t'Diff — <code>{selected_file}</code> <a class="pill" href="{pr_url}?tab=files#diff">All files</a>'
                )
            )
        else:
            heading = safe_html("Diff")
        description = (
            safe_html(html_t(t'<div class="md-body">{body}</div>'))
            if (body or "").strip()
            else safe_html('<span class="muted">(no description)</span>')
        )
        src_short = (src_commit or "")[:8]
        tgt_short = (tgt_commit or "")[:8]
        file_rows: list[str] = []
        for f in changed_files:
            path = str(f["path"])
            kind = str(f["kind"])
            adds, dels = f["added"], f["deleted"]
            meta = {
                "added": ("A", "ok"),
                "deleted": ("D", "warn"),
                "modified": ("M", "muted"),
                "binary": ("B", "muted"),
            }
            badge, cls = meta.get(str(kind), meta["modified"])
            link = safe_html(
                html_t(t'<a href="{pr_url}?tab=files&amp;file={q(path)}#diff">{path}</a>')
            )
            selected = (
                safe_html(' class="pr-file-selected"') if path == selected_file else safe_html("")
            )
            file_rows.append(
                html_t(
                    t'<tr{selected}><td style="width:26px"><span class="pull-file-badge pull-file-{kind}" title="{kind}">{badge}</span></td><td>{link}</td><td class="muted" style="width:110px"><span class="add">+{adds}</span> <span class="del">−{dels}</span></td></tr>'
                )
            )
        files_html = (
            join_html(file_rows)
            if file_rows
            else safe_html('<tr><td class="muted">No changed files.</td></tr>')
        )
        files_panel = (
            safe_html(
                html_t(
                    t'<div class="box" style="margin-bottom:14px"><h2 style="margin:0 0 10px 0;font-size:16px">Changed files ({len(changed_files)})</h2><table>{files_html}</table></div>'
                )
            )
            if changed_files and view == "files"
            else safe_html("")
        )
        total_adds = sum(f["added"] for f in changed_files)
        total_dels = sum(f["deleted"] for f in changed_files)
        summary = (
            safe_html(
                html_t(
                    t'<div class="muted" style="margin-bottom:10px">{total if total is not None else "—"} commit(s), {len(changed_files)} file(s) changed: <span class="add">+{total_adds}</span> <span class="del">−{total_dels}</span></div>'
                )
            )
            if changed_files
            else safe_html("")
        )
        comments = (
            await asyncio.to_thread(db_pr_comment_list, pr_id) if view == "conversation" else []
        )
        comment_count = (
            len(comments)
            if view == "conversation"
            else await _call_in_thread(db_pr_comment_count, pr_id)
        )
        author = (
            await _call_in_thread(db_get_user_by_id, author_user_id)
            if author_user_id is not None
            else None
        )
        author_name = author[1] if author else "Anonymous"
        viewer_id = self.remote_user_id
        viewer_admin = bool(getattr(self, "remote_is_admin", False))
        comment_rows = []
        for comment in comments:
            cid, c_author, c_username, c_body, c_created, c_edited = comment
            edited = " (edited)" if c_edited else ""
            when = _relative_time(c_created) or c_created
            can_manage = (
                (not REQUIRE_AUTH and can_write)
                or (viewer_id is not None and c_author == viewer_id)
                or viewer_admin
            )
            controls = safe_html("")
            if can_manage:
                controls = safe_html(
                    html_t(
                        t'<form method="POST" action="{base}/pulls/{pr_id}/comments/{cid}/delete" class="pr-comment-actions"><button class="danger" type="submit">Delete</button></form>'
                    )
                )
            comment_rows.append(
                html_t(
                    t'<div class="pr-comment"><div class="pr-comment-head"><b>{c_username or "anonymous"}</b> <span class="muted"><time title="{c_created}">{when}</time>{edited}</span>{controls}</div><div class="pr-comment-body md-body">{c_body}</div></div>'
                )
            )
        comments_join = (
            join_html(comment_rows)
            if comment_rows
            else safe_html('<p class="muted">No comments yet.</p>')
        )
        comment_form = safe_html("")
        if status == "open" and can_write:
            comment_form = safe_html(
                html_t(
                    t'<form method="POST" action="{base}/pulls/{pr_id}/comments" class="pr-comment-form pr-md-form"><label>Add comment</label><textarea name="body" data-markdown required maxlength="{MARKDOWN_BODY_LIMIT}" placeholder="Write a comment… Markdown and image uploads supported"></textarea><button type="submit">Comment</button></form>'
                )
            )
        else:
            comment_form = safe_html('<p class="muted">Write scope is required to comment.</p>')
        comments_box = safe_html(
            html_t(
                t'<section id="discussion" class="pr-conversation"><h2>Conversation</h2>{comments_join}</section>'
            )
        )
        title_form = safe_html("")
        if status == "open" and can_write:
            title_form = safe_html(
                html_t(
                    t'<details style="margin-top:10px"><summary>Edit title and description</summary><form method="POST" action="{base}/pulls/{pr_id}/update" class="pr-update-form pr-md-form"><label>Title</label><input name="title" value="{title}" required maxlength="200"><label>Description</label><textarea name="body" data-markdown maxlength="{MARKDOWN_BODY_LIMIT}">{body}</textarea><button type="submit">Save</button></form></details>'
                )
            )
        tabs = join_html(
            html_t(
                t'''<a href="{pr_url + ("?tab=" + key if key != "conversation" else "")}"{safe_html(' aria-current="page"' if view == key else "")}>{label}{safe_html(html_t(t"<span>{count}</span>")) if count is not None else safe_html("")}</a>'''
            )
            for key, label, count in (
                ("conversation", "Conversation", comment_count),
                ("commits", "Commits", total),
                ("checks", "Checks", None),
                ("files", "Files changed", len(changed_files)),
            )
        )
        sidebar = html_t(t"""<aside class="review-sidebar" aria-label="Pull request details">
<h3>Pull request details</h3><dl><dt>Source branch</dt><dd><code>{src_branch}</code><br><code>{src_short}</code></dd><dt>Target branch</dt><dd><code>{tgt_branch}</code><br><code>{tgt_short}</code></dd>
<dt>Changes</dt><dd>{len(changed_files)} files <span class="add">+{total_adds}</span> <span class="del">−{total_dels}</span></dd></dl></aside>""")
        if view == "conversation":
            panel = html_t(t"""<div class="review-layout pr-conversation-layout"><div class="review-main">
<article class="pr-comment pr-description"><div class="pr-comment-head"><b>{author_name}</b> <span class="muted">opened this pull request <time title="{created_at}">{_relative_time(created_at)}</time></span></div>
<div class="pr-comment-body">{description}{title_form}</div></article>
{comments_box}<div class="pr-merge-stack">{merge_note}{ci_panel}{merge_box}</div>{comment_form}</div>{safe_html(sidebar)}</div>""")
        elif view == "commits":
            panel = html_t(
                t'<section class="box pr-tab-panel" id="pr-commits"><h2>Commits</h2><div class="pr-commit-scroll"><table>{commits_html}</table></div>{commits_pagination}</section>'
            )
        elif view == "checks":
            panel = str(ci_panel)
        else:
            panel = html_t(
                t'<div class="pr-files-layout"><section class="box pr-tab-panel" id="diff"><h2>{heading}</h2>{summary}{diff_html}</section><aside class="pr-files-sidebar" aria-label="Changed files">{files_panel}</aside></div>'
            )
        body_html = html_t(
            t"""{_repo_tabs(base, "pulls")}<div class="review-breadcrumb"><a href="{base}/pulls">Pull requests</a> <span>/</span> #{pr_id}</div>
<header class="pr-detail-header"><div><h2>{title} <span>#{pr_id}</span></h2>
<div class="pr-detail-meta"><span class="pill pill-{status}">{status.capitalize()}</span> <strong>{author_name}</strong><span>·</span>
<code>{src_branch}</code> <span>→</span> <code>{tgt_branch}</code></div></div>
<div class="pr-header-actions">{_repo_code_menu(owner, repo, src_branch, can_edit=can_write and bool(src_commit))}</div></header>
{notice_html}<nav class="review-section-nav pr-detail-tabs" aria-label="Pull request views">{tabs}</nav>{safe_html(panel)}"""
        )
        editor_assets = self._issue_editor_assets() if view == "conversation" else safe_html("")
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"PR #{pr_id} · {owner}/{repo}"),
                safe_html(
                    html_t(
                        t'<main class="repo-page review-page review-detail">{safe_html(body_html)}{editor_assets}</main>'
                    )
                ),
            ),
        )

    async def _ui_pull_comment(self, owner: str, repo: str, pr_id: int) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        pr = await asyncio.to_thread(db_pr_get, pr_id)
        if not pr or pr[1] != owner or pr[2] != repo or pr[8] != "open":
            return await self._not_found()
        form = await self._read_form_urlencoded()
        body = (form.get("body") or "").strip()
        if not body:
            return await self._ui_pull_view(owner, repo, pr_id, "Comment text is required.", "warn")
        await asyncio.to_thread(db_pr_comment_add, pr_id, self.remote_user_id, _clip_markdown(body))
        return await self._ui_pull_view(owner, repo, pr_id, "Comment added.", "ok")

    def _can_manage_comment(self, author_id: int | None) -> bool:
        if not REQUIRE_AUTH and _has_write_scope(self):
            return True  # auth disabled: IP allowlist is the trust boundary
        if author_id is None or self.remote_user_id is None:
            return False
        return author_id == self.remote_user_id or getattr(self, "remote_is_admin", False)

    async def _ui_pull_comment_delete(
        self, owner: str, repo: str, pr_id: int, comment_id: int
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        row = await asyncio.to_thread(db_pr_comment_get, pr_id, comment_id)
        if not row:
            return await self._not_found()
        if not self._can_manage_comment(row[2]):
            return await self._forbidden(
                b"403 Forbidden: only the comment author or an admin can delete.\n"
            )
        await asyncio.to_thread(db_pr_comment_delete, comment_id)
        return await self._ui_pull_view(owner, repo, pr_id, "Comment deleted.", "ok")

    async def _ui_pull_comment_edit(
        self, owner: str, repo: str, pr_id: int, comment_id: int
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        row = await asyncio.to_thread(db_pr_comment_get, pr_id, comment_id)
        if not row:
            return await self._not_found()
        if not self._can_manage_comment(row[2]):
            return await self._forbidden(
                b"403 Forbidden: only the comment author or an admin can edit.\n"
            )
        form = await self._read_form_urlencoded()
        body = (form.get("body") or "").strip()
        if not body:
            return await self._ui_pull_view(owner, repo, pr_id, "Comment text is required.", "warn")
        await asyncio.to_thread(db_pr_comment_update, comment_id, _clip_markdown(body))
        return await self._ui_pull_view(owner, repo, pr_id, "Comment updated.", "ok")

    async def _ui_pull_update(self, owner: str, repo: str, pr_id: int) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        pr = await asyncio.to_thread(db_pr_get, pr_id)
        if not pr or pr[1] != owner or pr[2] != repo or pr[8] != "open":
            return await self._not_found()
        form = await self._read_form_urlencoded()
        title = (form.get("title") or "").strip()
        body = (form.get("body") or "").strip()
        if not title:
            return await self._ui_pull_view(owner, repo, pr_id, "Title is required.", "warn")
        await asyncio.to_thread(db_pr_update_text, pr_id, title, _clip_markdown(body))
        return await self._ui_pull_view(owner, repo, pr_id, "Pull request updated.", "ok")

    # ---------- Issues ----------
    async def _ui_issues(
        self, owner: str, repo: str, notice: str = "", notice_kind: str = "ok"
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query or "")
        status = (qs.get("status") or ["open"])[0]
        if status not in ("open", "closed", "all"):
            status = "open"
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        from .database import db_issue_comment_counts, db_issue_count, db_issue_list

        size = _page_size(qs)
        total = await asyncio.to_thread(
            db_issue_count, owner, repo, None if status == "all" else status
        )
        page = _clamp_page(_page_number(qs), total, size)
        rows_db = await asyncio.to_thread(
            db_issue_list,
            owner,
            repo,
            None if status == "all" else status,
            limit=size,
            offset=(page - 1) * size,
        )
        comment_counts = await asyncio.to_thread(
            db_issue_comment_counts, [row[0] for row in rows_db]
        )
        rows: list[str] = []
        for issue_id, title, st, created_at, _author_id, username in rows_db:
            count = comment_counts.get(issue_id, 0)
            rows.append(
                html_t(
                    t"""<li class="topic-list-row issue-list-row">
<span class="issue-status-icon issue-status-{st}">{_ISSUE_STATE_ICONS.get(st, _ISSUE_STATE_ICONS["open"])}</span>
<div><a class="review-row-title" href="{base}/issues/{issue_id}">{title}</a>
<div class="review-row-meta">#{issue_id} · Opened <time title="{created_at}">{_relative_time(created_at)}</time> by {username or "anonymous"}</div></div>
<div class="topic-row-badges"><span class="pill pill-{st}">{st.capitalize()}</span><small class="muted">{count} {"comment" if count == 1 else "comments"}</small></div></li>"""
                )
            )
        rows_html = (
            join_html(rows)
            if rows
            else safe_html(
                html_t(
                    t'<li class="topic-list-empty">{octicon("issue-opened", size=24)}<h3>No issues</h3><p class="muted">Issues track bugs, ideas and tasks for this repository.</p></li>'
                )
            )
        )
        pagination = _pagination(
            str_t(t"/r/{q(owner)}/{q(repo)}/issues"),
            {key: values[0] for key, values in qs.items() if key != "page"},
            page,
            page * size < total,
            total=total,
            per_page=size,
        )
        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(
                html_t(t'<div class="{cls}" style="margin-bottom:12px">{notice}</div>')
            )
        can_write = _has_write_scope(self)
        new_pill = (
            safe_html('<a class="btn btn-primary" href="{0}/issues/new">New issue</a>'.format(base))
            if can_write
            else safe_html("")
        )
        body = html_t(
            t"""{_repo_tabs(base, "issues")}<div class="topbar"><h2>Issues</h2>{new_pill}</div>
{notice_html}
<section class="topic-list-panel" aria-label="Issue list"><div class="topic-list-heading"><nav aria-label="Issue status">
{join_html(html_t(t'''<a href="{base}/issues?status={key}" id="issues-tab-{key}"{safe_html(' aria-current="page"' if status == key else "")}>{octicon(icon)}{label}</a>''') for key, icon, label in (("open", "issue-opened", "Open"), ("closed", "check", "Closed"), ("all", "issue-opened", "All")))}
</nav><span class="muted">{total} {"issue" if total == 1 else "issues"}</span></div><ul class="topic-list">{safe_html(rows_html)}</ul></section>{pagination}"""
        )
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"Issues · {owner}/{repo}"),
                safe_html(html_t(t'<main class="repo-page">{safe_html(body)}</main>')),
            ),
        )

    def _webide_assets(self) -> SafeHTML:
        """Web IDE assets with a cache-busting stamp for the workbench glue."""
        static = Path(__file__).resolve().parent.parent / "static"
        stamp = f"{int((static / 'webide.js').stat().st_mtime)}-{int((static / 'webide.css').stat().st_mtime)}"
        return safe_html(
            html_t(
                t'<link rel="stylesheet" href="/static/webide.css?v={stamp}">'
                t'<script src="/static/vendor/monaco/vs/loader.js"></script>'
                t'<script src="/static/webide.js?v={stamp}" defer></script>'
            )
        )

    def _issue_editor_assets(self) -> SafeHTML:
        """Editor assets with a cache-busting version stamp (mtime of the glue)."""
        glue = Path(__file__).resolve().parent.parent / "static" / "markdown.js"
        bundle = (
            Path(__file__).resolve().parent.parent
            / "static"
            / "vendor"
            / "tui-editor"
            / "toastui-editor-all.min.js"
        )
        stamp = f"{int(glue.stat().st_mtime)}-{int(bundle.stat().st_mtime)}"
        return safe_html(
            html_t(
                t'<link rel="stylesheet" href="/static/vendor/tui-editor/toastui-editor.css?v={stamp}">'
                t'<link rel="stylesheet" href="/static/vendor/tui-editor/toastui-editor-viewer.css?v={stamp}">'
                t'<link rel="stylesheet" href="/static/vendor/tui-editor/theme/toastui-editor-dark.css?v={stamp}">'
                t'<script src="/static/vendor/tui-editor/toastui-editor-all.min.js?v={stamp}"></script>'
                t'<script src="/static/markdown.js?v={stamp}" defer></script>'
            )
        )

    async def _ui_issues_new(
        self, owner: str, repo: str, notice: str = "", notice_kind: str = "ok"
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(
                html_t(t'<div class="{cls}" style="margin-bottom:12px">{notice}</div>')
            )
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        body = html_t(
            t"""{_repo_tabs(base, "issues")}<div class="topbar"><h2>New issue</h2>
</div>
{notice_html}
<div class="box" style="margin-bottom:14px"><form method="POST" action="{base}/issues/create">
<label>Title</label><input name="title" required maxlength="300" placeholder="Describe the problem or request" style="width:100%">
<label style="margin-top:10px">Description</label>
<textarea name="body" data-markdown maxlength="{MARKDOWN_BODY_LIMIT}" placeholder="Explain the issue. Markdown is supported."></textarea>
<button type="submit" style="margin-top:10px">Submit new issue</button></form></div>{self._issue_editor_assets()}"""
        )
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"New issue · {owner}/{repo}"),
                safe_html(html_t(t'<main class="repo-page">{safe_html(body)}</main>')),
            ),
        )

    async def _ui_issues_create(self, owner: str, repo: str) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return await self._forbidden(b"403 Forbidden\n")
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        if not os.path.isdir(_repo_bare_path(owner, repo)):
            return await self._not_found()
        form = await self._read_form_urlencoded()
        title = (form.get("title") or "").strip()
        body_md = (form.get("body") or "").strip()
        if not title:
            return await self._ui_issues_new(owner, repo, "Title is required.", "warn")
        issue_id = await asyncio.to_thread(
            db_issue_create,
            owner,
            repo,
            title,
            _clip_markdown(body_md),
            getattr(self, "remote_user_id", None),
        )
        await _send_redirect(self.request, f"/r/{owner}/{repo}/issues/{issue_id}")

    async def _ui_issue_view(
        self, owner: str, repo: str, issue_id: int, notice: str = "", notice_kind: str = "ok"
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        issue = await asyncio.to_thread(db_issue_get, issue_id)
        if not issue or issue[1] != owner or issue[2] != repo:
            return await self._not_found()
        (
            _iid,
            _owner,
            _repo_db,
            title,
            body_md,
            author_id,
            username,
            status,
            created_at,
            updated_at,
            closed_at,
        ) = issue
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        comments = await asyncio.to_thread(db_issue_comment_list, issue_id)
        can_write = _has_write_scope(self)
        author_label = (
            safe_html(html_t(t"{username or 'anonymous'}")) if author_id else safe_html("anonymous")
        )
        # GitHub-style: the issue first post is a bordered comment block.
        comment_rows: list[str] = []
        for cid, c_author, c_username, c_body, c_created, c_edited in comments:
            when = _relative_time(c_created) or c_created
            edited = " (edited)" if c_edited else ""
            can_manage = self._can_manage_comment(c_author)
            controls = safe_html("")
            if can_manage:
                controls = safe_html(
                    html_t(
                        t'<form method="POST" action="{base}/issues/{issue_id}/comments/{cid}/delete" class="issue-comment-actions"><button class="danger" type="submit">Delete</button></form>'
                    )
                )
            comment_rows.append(
                html_t(
                    t'<article id="comment-{cid}" class="pr-comment"><div class="pr-comment-head"><b>{c_username or "anonymous"}</b> <a class="muted" href="#comment-{cid}"><time title="{c_created}">{when}</time>{edited}</a>{controls}</div><div class="pr-comment-body md-body">{c_body}</div></article>'
                )
            )
        comments_inner = (
            join_html(comment_rows)
            if comment_rows
            else safe_html('<p class="muted">No comments yet.</p>')
        )
        comments_box = safe_html(
            html_t(
                t'<section class="pr-conversation topic-replies"><h2>Comments ({len(comments)})</h2>{comments_inner}</section>'
            )
        )
        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(
                html_t(t'<div class="{cls}" style="margin-bottom:12px">{notice}</div>')
            )
        controls_area = safe_html("")
        if can_write:
            action = "Close issue" if status == "open" else "Reopen issue"
            route = "close" if status == "open" else "reopen"
            controls_area = safe_html(
                html_t(
                    t'<form method="POST" action="{base}/issues/{issue_id}/{route}" style="margin-top:10px"><button class="secondary" type="submit">{octicon("issue-closed" if route == "close" else "issue-opened", cls="issue-action-icon-" + route)}{action}</button></form>'
                )
            )
        title_form = safe_html("")
        if can_write:
            title_form = safe_html(
                html_t(
                    t'<details style="margin-top:10px"><summary>Edit title and description</summary><form method="POST" action="{base}/issues/{issue_id}/update"><label>Title</label><input name="title" value="{title}" required maxlength="300"><label style="margin-top:10px">Description</label><textarea name="body" data-markdown maxlength="{MARKDOWN_BODY_LIMIT}">{body_md}</textarea><button type="submit" style="margin-top:10px">Save</button></form></details>'
                )
            )
        comment_form = safe_html("")
        if can_write:
            comment_form = safe_html(
                html_t(
                    t'<form method="POST" action="{base}/issues/{issue_id}/comments" class="pr-md-form"><label>Add comment</label><textarea name="body" data-markdown required maxlength="{MARKDOWN_BODY_LIMIT}" placeholder="Write a comment… Markdown and image uploads supported"></textarea><button type="submit" style="margin-top:10px">Comment</button></form>'
                )
            )
        else:
            comment_form = safe_html('<p class="muted">Write scope is required to comment.</p>')
        body = html_t(
            t"""{_repo_tabs(base, "issues")}<div class="review-breadcrumb"><a href="{base}/issues">Issues</a> <span>/</span> Issue #{issue_id}</div>
<header class="pr-detail-header"><div><h2>{title} <span>#{issue_id}</span></h2><div class="pr-detail-meta"><span class="pill pill-{status}">{status.capitalize()}</span>{author_label} opened this issue <time title="{created_at}">{_relative_time(created_at)}</time></div></div></header>
{notice_html}<div class="review-layout topic-thread"><div class="review-main">
<article class="pr-comment issue-first-post"><div class="pr-comment-head"><b>{author_label}</b><span class="muted">opened this issue</span></div><div class="pr-comment-body"><div class="md-body">{body_md}</div>{title_form}</div></article>
{comments_box}{comment_form}</div>
<aside class="review-sidebar" aria-label="Issue details"><h3>Issue details</h3><dl><dt>Status</dt><dd>{status.capitalize()}</dd><dt>Updated</dt><dd><time title="{updated_at}">{_relative_time(updated_at)}</time></dd></dl>{controls_area}</aside>
</div>{self._issue_editor_assets()}"""
        )
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"Issue #{issue_id} · {owner}/{repo}"),
                safe_html(html_t(t'<main class="repo-page review-page">{safe_html(body)}</main>')),
            ),
        )

    async def _ui_issue_comment(self, owner: str, repo: str, issue_id: int) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        issue = await asyncio.to_thread(db_issue_get, issue_id)
        if not issue or issue[1] != owner or issue[2] != repo:
            return await self._not_found()
        form = await self._read_form_urlencoded()
        body_md = (form.get("body") or "").strip()
        if not body_md:
            return await self._ui_issue_view(
                owner, repo, issue_id, "Comment text is required.", "warn"
            )
        await asyncio.to_thread(
            db_issue_comment_add,
            issue_id,
            getattr(self, "remote_user_id", None),
            _clip_markdown(body_md),
        )
        return await self._ui_issue_view(owner, repo, issue_id, "Comment added.", "ok")

    async def _issue_and_comment(
        self, owner: str, repo: str, issue_id: int, comment_id: int
    ) -> tuple[IssueRow | None, CommentIdentityRow | None]:
        issue = await asyncio.to_thread(db_issue_get, issue_id)
        if not issue or issue[1] != unquote(owner) or issue[2] != unquote(repo):
            return None, None
        comment = await asyncio.to_thread(db_issue_comment_get, issue_id, comment_id)
        return issue, comment

    async def _ui_issue_comment_delete(
        self, owner: str, repo: str, issue_id: int, comment_id: int
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        issue, comment = await self._issue_and_comment(owner, repo, issue_id, comment_id)
        if not comment:
            return await self._not_found()
        if not self._can_manage_comment(comment[2]):
            return await self._forbidden(
                b"403 Forbidden: only the comment author or an admin can delete.\n"
            )
        await asyncio.to_thread(db_issue_comment_delete, comment_id)
        return await self._ui_issue_view(owner, repo, issue_id, "Comment deleted.", "ok")

    async def _ui_issue_comment_edit(
        self, owner: str, repo: str, issue_id: int, comment_id: int
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        issue, comment = await self._issue_and_comment(owner, repo, issue_id, comment_id)
        if not comment:
            return await self._not_found()
        if not self._can_manage_comment(comment[2]):
            return await self._forbidden(
                b"403 Forbidden: only the comment author or an admin can edit.\n"
            )
        form = await self._read_form_urlencoded()
        body_md = (form.get("body") or "").strip()
        if not body_md:
            return await self._ui_issue_view(
                owner, repo, issue_id, "Comment text is required.", "warn"
            )
        await asyncio.to_thread(db_issue_comment_update, comment_id, _clip_markdown(body_md))
        return await self._ui_issue_view(owner, repo, issue_id, "Comment updated.", "ok")

    async def _ui_issue_close(self, owner: str, repo: str, issue_id: int) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        issue = await asyncio.to_thread(db_issue_get, issue_id)
        if not issue or issue[1] != owner or issue[2] != repo:
            return await self._not_found()
        if issue[7] == "closed":
            return await self._ui_issue_view(
                owner, repo, issue_id, "Issue is already closed.", "warn"
            )
        await asyncio.to_thread(db_issue_close, issue_id)
        return await self._ui_issue_view(owner, repo, issue_id, "Issue closed.", "ok")

    async def _ui_issue_reopen(self, owner: str, repo: str, issue_id: int) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        issue = await asyncio.to_thread(db_issue_get, issue_id)
        if not issue or issue[1] != owner or issue[2] != repo:
            return await self._not_found()
        if issue[7] == "open":
            return await self._ui_issue_view(
                owner, repo, issue_id, "Issue is already open.", "warn"
            )
        await asyncio.to_thread(db_issue_reopen, issue_id)
        return await self._ui_issue_view(owner, repo, issue_id, "Issue reopened.", "ok")

    async def _ui_issue_update(self, owner: str, repo: str, issue_id: int) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        issue = await asyncio.to_thread(db_issue_get, issue_id)
        if not issue or issue[1] != owner or issue[2] != repo:
            return await self._not_found()
        form = await self._read_form_urlencoded()
        title = (form.get("title") or "").strip()
        body_md = (form.get("body") or "").strip()
        if not title:
            return await self._ui_issue_view(owner, repo, issue_id, "Title is required.", "warn")
        await asyncio.to_thread(db_issue_update_text, issue_id, title, _clip_markdown(body_md))
        return await self._ui_issue_view(owner, repo, issue_id, "Issue updated.", "ok")

    # ---------- Discussions ----------
    def _discussion_categories(self) -> tuple[str, ...]:
        from .discussion_rules import CATEGORIES

        return CATEGORIES

    async def _ui_discussions(
        self, owner: str, repo: str, notice: str = "", notice_kind: str = "ok"
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        qs = parse_qs(urlparse(self.path).query or "")
        category = (qs.get("category") or [""])[0]
        if category not in self._discussion_categories():
            category = ""
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        size = _page_size(qs)
        total = await asyncio.to_thread(db_discussion_count, owner, repo, category or None)
        page = _clamp_page(_page_number(qs), total, size)
        rows_db = await asyncio.to_thread(
            db_discussion_list, owner, repo, category or None, limit=size, offset=(page - 1) * size
        )
        comment_counts = await asyncio.to_thread(
            db_discussion_comment_counts, [row[0] for row in rows_db]
        )
        rows: list[str] = []
        for discussion_id, title, cat, created_at, _author_id, username, answered_id in rows_db:
            count = comment_counts.get(discussion_id, 0)
            answer = (
                safe_html(
                    html_t(
                        t'<span class="pill pill-open">{octicon("check-circle-fill")}Answered</span>'
                    )
                )
                if answered_id
                else safe_html("")
            )
            rows.append(
                html_t(
                    t"""<li class="topic-list-row discussion-list-row">
<span class="issue-status-icon discussion-cat" aria-hidden="true">{octicon("comment-discussion")}</span>
<div><a class="review-row-title" href="{base}/discussions/{discussion_id}">{title}</a>
<div class="review-row-meta">#{discussion_id} · Started <time title="{created_at}">{_relative_time(created_at)}</time> by {username or "anonymous"}</div></div>
<div class="topic-row-badges"><span class="pill">{cat}</span>{answer}<small class="muted">{count} {"reply" if count == 1 else "replies"}</small></div></li>"""
                )
            )
        rows_html = (
            join_html(rows)
            if rows
            else safe_html('<li class="topic-list-empty muted">No discussions.</li>')
        )
        pagination = _pagination(
            str_t(t"/r/{q(owner)}/{q(repo)}/discussions"),
            {key: values[0] for key, values in qs.items() if key != "page"},
            page,
            page * size < total,
            total=total,
            per_page=size,
        )
        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(
                html_t(t'<div class="{cls}" style="margin-bottom:12px">{notice}</div>')
            )
        new_pill = (
            safe_html(
                html_t(
                    t'<a class="btn btn-primary" href="{base}/discussions/new">New discussion</a>'
                )
            )
            if _has_write_scope(self)
            else safe_html("")
        )
        counts: dict[str, int] = {}
        for cat in self._discussion_categories():
            counts[cat] = await asyncio.to_thread(db_discussion_count, owner, repo, cat)
        counts["all"] = (
            await asyncio.to_thread(db_discussion_count, owner, repo) if category else total
        )
        tab_links = [
            safe_html(
                html_t(
                    t'''<a href="{base}/discussions" id="discussions-tab-all"{safe_html(' aria-current="page"' if not category else "")}>All discussions <span>{counts["all"]}</span></a>'''
                )
            )
        ]
        for cat in self._discussion_categories():
            tab_links.append(
                safe_html(
                    html_t(
                        t'''<a href="{base}/discussions?category={q(cat)}" id="discussions-tab-{q(cat)}"{safe_html(' aria-current="page"' if category == cat else "")}>{cat} <span>{counts[cat]}</span></a>'''
                    )
                )
            )
        body = html_t(
            t"""{_repo_tabs(base, "discussions")}<div class="topbar"><h2>Discussions</h2>{new_pill}</div>
{notice_html}
<div class="topic-browser"><nav class="topic-category-nav" aria-label="Discussion categories"><h3>Categories</h3>{join_html(tab_links)}</nav>
<div><section class="topic-list-panel" aria-label="Discussion list"><div class="topic-list-heading"><strong>{category or "All discussions"}</strong><span class="muted">{total} {"discussion" if total == 1 else "discussions"}</span></div><ul class="topic-list">{safe_html(rows_html)}</ul></section>{pagination}</div></div>"""
        )
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"Discussions · {owner}/{repo}"),
                safe_html(html_t(t'<main class="repo-page">{safe_html(body)}</main>')),
            ),
        )

    async def _ui_discussions_new(
        self, owner: str, repo: str, notice: str = "", notice_kind: str = "ok"
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(
                html_t(t'<div class="{cls}" style="margin-bottom:12px">{notice}</div>')
            )
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        category_options = join_html(
            [
                html_t(
                    t'<option value="{cat}"{safe_html(" selected" if cat == "General" else "")}>{cat}</option>'
                )
                for cat in self._discussion_categories()
            ]
        )
        body = html_t(
            t"""{_repo_tabs(base, "discussions")}<div class="topbar"><h2>New discussion</h2>
</div>
{notice_html}
<div class="box" style="margin-bottom:14px"><form method="POST" action="{base}/discussions/create">
<label>Category</label><select name="category" required>{category_options}</select>
<label style="margin-top:10px">Title</label><input name="title" required maxlength="300" placeholder="Start the conversation" style="width:100%">
<label style="margin-top:10px">Description</label>
<textarea name="body" data-markdown maxlength="{MARKDOWN_BODY_LIMIT}" placeholder="Explain your idea or question. Markdown is supported."></textarea>
<button type="submit" style="margin-top:10px">Start discussion</button></form></div>{self._issue_editor_assets()}"""
        )
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"New discussion · {owner}/{repo}"),
                safe_html(html_t(t'<main class="repo-page">{safe_html(body)}</main>')),
            ),
        )

    async def _ui_discussions_create(self, owner: str, repo: str) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return await self._forbidden(b"403 Forbidden\n")
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        if not os.path.isdir(_repo_bare_path(owner, repo)):
            return await self._not_found()
        form = await self._read_form_urlencoded()
        title = (form.get("title") or "").strip()
        category = (form.get("category") or "General").strip()
        body_md = (form.get("body") or "").strip()
        if category not in self._discussion_categories():
            category = "General"
        if not title:
            return await self._ui_discussions_new(owner, repo, "Title is required.", "warn")
        discussion_id = await asyncio.to_thread(
            db_discussion_create,
            owner,
            repo,
            category,
            title,
            _clip_markdown(body_md),
            getattr(self, "remote_user_id", None),
        )
        await _send_redirect(self.request, f"/r/{owner}/{repo}/discussions/{discussion_id}")

    async def _ui_discussion_view(
        self, owner: str, repo: str, discussion_id: int, notice: str = "", notice_kind: str = "ok"
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        discussion = await asyncio.to_thread(db_discussion_get, discussion_id)
        if not discussion or discussion[1] != owner or discussion[2] != repo:
            return await self._not_found()
        (
            _id,
            _own,
            _rep,
            category,
            title,
            body_md,
            author_id,
            username,
            locked,
            _locked_by,
            answered_id,
            created_at,
            updated_at,
        ) = discussion
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        comments = await asyncio.to_thread(db_discussion_comment_list, discussion_id)
        can_write = _has_write_scope(self)
        answered = bool(answered_id)
        comment_rows: list[str] = []
        for cid, c_author, c_username, c_body, c_created, c_edited in comments:
            when = _relative_time(c_created) or c_created
            edited = " (edited)" if c_edited else ""
            answer_badge = (
                safe_html(
                    html_t(
                        t' <span class="pill pill-open">{octicon("check-circle-fill")}Answer</span>'
                    )
                )
                if cid == answered_id
                else safe_html("")
            )
            controls = safe_html("")
            if self._can_manage_comment(c_author):
                controls = safe_html(
                    html_t(
                        t'<form method="POST" action="{base}/discussions/{discussion_id}/comments/{cid}/delete" class="issue-comment-actions"><button class="danger" type="submit">Delete</button></form>'
                    )
                )
            answer_toggle = safe_html("")
            if can_write and category == "Q&A":
                if cid == answered_id:
                    answer_toggle = safe_html(
                        html_t(
                            t'<form method="POST" action="{base}/discussions/{discussion_id}/unanswer/{cid}" class="issue-comment-actions"><button class="secondary btn-sm" type="submit">Unmark answer</button></form>'
                        )
                    )
                else:
                    answer_toggle = safe_html(
                        html_t(
                            t'<form method="POST" action="{base}/discussions/{discussion_id}/answer/{cid}" class="issue-comment-actions"><button class="secondary btn-sm" type="submit">{octicon("check-circle-fill")}Mark as answer</button></form>'
                        )
                    )
            highlight = safe_html(" discussion-answered") if cid == answered_id else safe_html("")
            comment_rows.append(
                html_t(
                    t'<article id="reply-{cid}" class="pr-comment{highlight}"><div class="pr-comment-head"><b>{c_username or "anonymous"}</b>{answer_badge} <a class="muted" href="#reply-{cid}"><time title="{c_created}">{when}</time>{edited}</a>{controls}{answer_toggle}</div><div class="pr-comment-body md-body">{c_body}</div></article>'
                )
            )
        comments_inner = (
            join_html(comment_rows)
            if comment_rows
            else safe_html('<p class="muted">No comments yet.</p>')
        )
        comments_box = safe_html(
            html_t(
                t'<section class="pr-conversation topic-replies"><h2>Replies ({len(comments)})</h2>{comments_inner}</section>'
            )
        )
        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(
                html_t(t'<div class="{cls}" style="margin-bottom:12px">{notice}</div>')
            )
        answered_pill = (
            safe_html(
                html_t(
                    t' <span class="pill pill-open">{octicon("check-circle-fill")}Answered</span>'
                )
            )
            if answered
            else safe_html("")
        )
        locked_pill = (
            safe_html(' <span class="muted">· 🔒 Locked</span>') if locked else safe_html("")
        )
        state_bits = safe_html(
            html_t(
                t'<span class="pill">{category}</span>{answered_pill} <span class="muted">· asked by {username or "anonymous"} <time title="{created_at}">{_relative_time(created_at)}</time></span>'
            )
        )
        lock_note = (
            safe_html(
                '<div class="warn" style="margin-top:10px">This discussion is locked; new replies are disabled.</div>'
            )
            if locked
            else safe_html("")
        )
        controls_area = safe_html("")
        if can_write:
            lock_action = "Lock" if not locked else "Unlock"
            lock_route = "lock" if not locked else "unlock"
            controls_area = safe_html(
                html_t(
                    t'<form method="POST" action="{base}/discussions/{discussion_id}/{lock_route}" style="margin-top:10px"><button class="secondary" type="submit">{octicon("lock")}{lock_action}</button></form>'
                )
            )
        title_form = safe_html("")
        if can_write:
            category_options = join_html(
                [
                    html_t(
                        t'<option value="{cat}"{safe_html(" selected" if cat == category else "")}>{cat}</option>'
                    )
                    for cat in self._discussion_categories()
                ]
            )
            title_form = safe_html(
                html_t(
                    t'<details style="margin-top:10px"><summary>Edit discussion</summary><form method="POST" action="{base}/discussions/{discussion_id}/update"><label>Category</label><select name="category">{category_options}</select><label style="margin-top:10px">Title</label><input name="title" value="{title}" required maxlength="300"><label style="margin-top:10px">Description</label><textarea name="body" data-markdown maxlength="{MARKDOWN_BODY_LIMIT}">{body_md}</textarea><button type="submit" style="margin-top:10px">Save</button></form></details>'
                )
            )
        comment_form = safe_html("")
        if can_write and not locked:
            comment_form = safe_html(
                html_t(
                    t'<form method="POST" action="{base}/discussions/{discussion_id}/comments" class="pr-md-form"><label>Reply</label><textarea name="body" data-markdown required maxlength="{MARKDOWN_BODY_LIMIT}" placeholder="Write a reply… (Markdown supported)"></textarea><button type="submit" style="margin-top:10px">Reply</button></form>'
                )
            )
        elif not locked:
            comment_form = safe_html('<p class="muted">Write scope is required to reply.</p>')
        answer_link = (
            safe_html(html_t(t'<p><a href="#reply-{answered_id}">Jump to accepted answer</a></p>'))
            if answered
            else safe_html("")
        )
        body = html_t(
            t"""{_repo_tabs(base, "discussions")}<div class="review-breadcrumb"><a href="{base}/discussions">Discussions</a> <span>/</span> #{discussion_id}</div>
<header class="pr-detail-header"><div><h2>{title} <span>#{discussion_id}</span></h2><div class="pr-detail-meta">{state_bits}{locked_pill}</div></div></header>
{notice_html}{lock_note}<div class="review-layout topic-thread"><div class="review-main">
<article class="pr-comment issue-first-post"><div class="pr-comment-head"><b>{username or "anonymous"}</b><span class="muted">started this discussion</span></div><div class="pr-comment-body"><div class="md-body">{body_md}</div>{title_form}</div></article>
{comments_box}{comment_form}</div>
<aside class="review-sidebar" aria-label="Discussion details"><h3>Discussion details</h3><dl><dt>Category</dt><dd><a href="{base}/discussions?category={q(category)}">{category}</a></dd><dt>Replies</dt><dd>{len(comments)}</dd></dl>{answer_link}{controls_area}</aside>
</div>{self._issue_editor_assets()}"""
        )
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"Discussion #{discussion_id} · {owner}/{repo}"),
                safe_html(html_t(t'<main class="repo-page review-page">{safe_html(body)}</main>')),
            ),
        )

    async def _discussion_and_comment(
        self, owner: str, repo: str, discussion_id: int, comment_id: int
    ) -> tuple[DiscussionRow | None, CommentIdentityRow | None]:
        discussion = await asyncio.to_thread(db_discussion_get, discussion_id)
        if not discussion or discussion[1] != unquote(owner) or discussion[2] != unquote(repo):
            return None, None
        comment = await asyncio.to_thread(db_discussion_comment_get, discussion_id, comment_id)
        return discussion, comment

    async def _ui_discussion_comment(self, owner: str, repo: str, discussion_id: int) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        discussion = await asyncio.to_thread(db_discussion_get, discussion_id)
        if not discussion or discussion[1] != owner or discussion[2] != repo:
            return await self._not_found()
        if discussion[8]:
            return await self._ui_discussion_view(
                owner,
                repo,
                discussion_id,
                "This discussion is locked; replies are disabled.",
                "warn",
            )
        form = await self._read_form_urlencoded()
        body_md = (form.get("body") or "").strip()
        if not body_md:
            return await self._ui_discussion_view(
                owner, repo, discussion_id, "Reply text is required.", "warn"
            )
        await asyncio.to_thread(
            db_discussion_comment_add,
            discussion_id,
            getattr(self, "remote_user_id", None),
            _clip_markdown(body_md),
        )
        return await self._ui_discussion_view(owner, repo, discussion_id, "Reply added.", "ok")

    async def _ui_discussion_comment_delete(
        self, owner: str, repo: str, discussion_id: int, comment_id: int
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        discussion, comment = await self._discussion_and_comment(
            owner, repo, discussion_id, comment_id
        )
        if not discussion or not comment:
            return await self._not_found()
        if not self._can_manage_comment(comment[2]):
            return await self._forbidden(
                b"403 Forbidden: only the comment author or an admin can delete.\n"
            )
        await asyncio.to_thread(db_discussion_comment_delete, comment_id)
        if discussion[10] == comment_id:
            await asyncio.to_thread(db_discussion_set_answer, discussion_id, None)
        return await self._ui_discussion_view(owner, repo, discussion_id, "Reply deleted.", "ok")

    async def _ui_discussion_comment_edit(
        self, owner: str, repo: str, discussion_id: int, comment_id: int
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        discussion, comment = await self._discussion_and_comment(
            owner, repo, discussion_id, comment_id
        )
        if not discussion or not comment:
            return await self._not_found()
        if not self._can_manage_comment(comment[2]):
            return await self._forbidden(
                b"403 Forbidden: only the comment author or an admin can edit.\n"
            )
        form = await self._read_form_urlencoded()
        body_md = (form.get("body") or "").strip()
        if not body_md:
            return await self._ui_discussion_view(
                owner, repo, discussion_id, "Reply text is required.", "warn"
            )
        await asyncio.to_thread(db_discussion_comment_update, comment_id, _clip_markdown(body_md))
        return await self._ui_discussion_view(owner, repo, discussion_id, "Reply updated.", "ok")

    async def _ui_discussion_lock(self, owner: str, repo: str, discussion_id: int) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        discussion = await asyncio.to_thread(db_discussion_get, discussion_id)
        if not discussion or discussion[1] != owner or discussion[2] != repo:
            return await self._not_found()
        if not discussion[8]:
            await asyncio.to_thread(
                db_discussion_set_locked, discussion_id, True, getattr(self, "remote_user_id", None)
            )
        return await self._ui_discussion_view(
            owner, repo, discussion_id, "Discussion locked.", "ok"
        )

    async def _ui_discussion_unlock(self, owner: str, repo: str, discussion_id: int) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        discussion = await asyncio.to_thread(db_discussion_get, discussion_id)
        if not discussion or discussion[1] != owner or discussion[2] != repo:
            return await self._not_found()
        if discussion[8]:
            await asyncio.to_thread(db_discussion_set_locked, discussion_id, False, None)
        return await self._ui_discussion_view(
            owner, repo, discussion_id, "Discussion unlocked.", "ok"
        )

    async def _ui_discussion_answer(
        self, owner: str, repo: str, discussion_id: int, comment_id: int
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        discussion, comment = await self._discussion_and_comment(
            owner, repo, discussion_id, comment_id
        )
        if not discussion or not comment:
            return await self._not_found()
        if discussion[3] != "Q&A":
            return await self._ui_discussion_view(
                owner, repo, discussion_id, "Only Q&A discussions can have a marked answer.", "warn"
            )
        await asyncio.to_thread(db_discussion_set_answer, discussion_id, comment_id)
        return await self._ui_discussion_view(owner, repo, discussion_id, "Answer marked.", "ok")

    async def _ui_discussion_unanswer(
        self, owner: str, repo: str, discussion_id: int, comment_id: int
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        discussion, comment = await self._discussion_and_comment(
            owner, repo, discussion_id, comment_id
        )
        if not comment:
            return await self._not_found()
        await asyncio.to_thread(db_discussion_set_answer, discussion_id, None)
        return await self._ui_discussion_view(owner, repo, discussion_id, "Answer unmarked.", "ok")

    async def _ui_discussion_update(self, owner: str, repo: str, discussion_id: int) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        discussion = await asyncio.to_thread(db_discussion_get, discussion_id)
        if not discussion or discussion[1] != owner or discussion[2] != repo:
            return await self._not_found()
        form = await self._read_form_urlencoded()
        title = (form.get("title") or "").strip()
        category = (form.get("category") or discussion[3]).strip()
        body_md = (form.get("body") or "").strip()
        if category not in self._discussion_categories():
            category = discussion[3]
        if not title:
            return await self._ui_discussion_view(
                owner, repo, discussion_id, "Title is required.", "warn"
            )
        await asyncio.to_thread(
            db_discussion_update_text, discussion_id, category, title, _clip_markdown(body_md)
        )
        return await self._ui_discussion_view(
            owner, repo, discussion_id, "Discussion updated.", "ok"
        )

    def _repo_git_async(self, owner: str, repo: str) -> Awaitable[str]:
        return asyncio.to_thread(_repo_bare_path, owner, repo)

    async def _ui_pull_resolve(
        self, owner: str, repo: str, pr_id: int, notice: str = "", notice_kind: str = "ok"
    ) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        pr = await asyncio.to_thread(db_pr_get, pr_id)
        if not pr or pr[1] != owner or pr[2] != repo or pr[8] != "open":
            return await self._not_found()
        (
            _id,
            _owner,
            _repo,
            title,
            _body,
            src_branch,
            tgt_branch,
            _author,
            status,
            created_at,
            _closed_at,
            _merged_at,
            _method,
            _mcommit,
        ) = pr
        repo_git = _repo_bare_path(owner, repo)
        src = await _git_resolve_commit(repo_git, "refs/heads/" + src_branch)
        tgt = await _git_resolve_commit(repo_git, "refs/heads/" + tgt_branch)
        merge_base = await _git_merge_base(repo_git, tgt, src) if (src and tgt) else None
        if not (src and tgt and merge_base):
            return await self._ui_pull_view(
                owner, repo, pr_id, "Unable to run conflict resolution in this state.", "warn"
            )
        conflicts = await asyncio.to_thread(
            pr_resolver.list_conflicts, repo_git, merge_base, src, tgt
        )
        too_many = len(conflicts) > pr_resolver.MAX_CONFLICT_FILES
        display = conflicts if too_many else conflicts[: pr_resolver.MAX_CONFLICT_FILES]
        rows: list[str] = []
        if not too_many:
            previews = await asyncio.to_thread(
                lambda: [
                    pr_resolver.preview(repo_git, item, src_branch, tgt_branch) for item in display
                ]
            )
            for index, (item, (text, kind)) in enumerate(zip(display, previews)):
                kind_note = {
                    "deleted-here": "The file was deleted on this branch; the target content is shown.",
                    "deleted-there": "The target deleted this file; keep the source content or delete it.",
                    "nonmergeable": "Binary, too large or unmergeable; the source content is shown.",
                }.get(kind, "")
                delete_checked = safe_html(" checked") if kind == "deleted-here" else safe_html("")
                escaped_text = text.decode("utf-8", "replace") if text else ""
                rows.append(
                    html_t(
                        t'<fieldset class="pr-conflict-file"><legend><code>{item["path"]}</code></legend>'
                        t'<input type="hidden" name="path_{index}" value="{item["path"]}">'
                        t'<textarea name="content_{index}" spellcheck="false">{escaped_text}</textarea>'
                        t'<label><input type="checkbox" name="delete_{index}" value="yes"{delete_checked}> Delete this file</label>'
                        t'<p class="muted">{kind_note}</p></fieldset>'
                    )
                )
        notice_html = safe_html("")
        if notice:
            notice_html = safe_html(
                html_t(
                    t'<div class="{"warn" if notice_kind != "ok" else "ok"}" style="margin-bottom:12px">{notice}</div>'
                )
            )
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        overflow = (
            safe_html(
                '<p class="warn">More than 40 conflicted files. The web resolver cannot show this many; resolve with Git and push.</p>'
            )
            if too_many
            else safe_html("")
        )
        empty = (
            safe_html(
                '<p class="ok">No conflicts remain between these branches. Reload the pull request; the merge button may be available.</p>'
            )
            if not conflicts
            else safe_html("")
        )
        default_message = str_t(t"Merge branch '{tgt_branch}' into {src_branch}")
        form_html = safe_html("")
        if rows and not too_many and conflicts:
            form_html = safe_html(
                html_t(
                    t'<form method="POST" action="{base}/pulls/{pr_id}/resolve" class="pr-resolve-form">'
                    t'<input type="hidden" name="csrf" value="{self._email_csrf_token()}">'
                    t"{join_html(rows)}"
                    t"<label>Merge commit message</label>"
                    t'<textarea name="message" required maxlength="4000">{default_message}</textarea>'
                    t'<p class="muted">Applying the resolution creates a merge commit on <code>{src_branch}</code>. Edit the marked sections (<<<<<<<, =======, >>>>>>>), then apply.</p>'
                    t'<button type="submit">Apply resolution</button></form>'
                )
            )
        body_html = html_t(
            t"""{_repo_tabs(base, "pulls")}<div class="topbar"><div><h2>Resolve conflicts — PR #{pr_id}</h2>
<div class="muted"><code>{src_branch}</code> ← <code>{tgt_branch}</code></div></div>
<div><a class="pill" href="{base}/pulls/{pr_id}">Back to PR</a> <a class="pill" href="{base}/pulls/{pr_id}/resolve/ide">Open in Web IDE</a></div></div>
{notice_html}{empty}{overflow}
<div class="box pr-resolve-files">{form_html}</div>"""
        )
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"Resolve conflicts · PR #{pr_id} · {owner}/{repo}"),
                safe_html(html_t(t'<main class="repo-page">{safe_html(body_html)}</main>')),
            ),
        )

    async def _ui_pull_resolve_apply(self, owner: str, repo: str, pr_id: int) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        form = await self._read_form_urlencoded()
        if not secrets.compare_digest(
            form.get("csrf", "").encode(), self._email_csrf_token().encode()
        ):
            return await self._forbidden(b"403 Forbidden: invalid security token.\n")
        try:
            count = min(
                pr_resolver.MAX_CONFLICT_FILES, max(0, int(form.get("conflict_count") or 0))
            )
        except ValueError:
            count = 0
        resolutions = []
        for index in range(count):
            path = form.get(f"path_{index}") or ""
            delete = bool(form.get(f"delete_{index}"))
            content = form.get(f"content_{index}") or ""
            if path:
                resolutions.append((path, content, delete))
        user = getattr(self, "remote_user", None) or "Browser user"
        try:
            lock = self.server.push_locks.setdefault((owner, repo), asyncio.Lock())
            async with lock:
                state = await self._ui_pull_resolve_poststate(owner, repo, pr_id)
                if not state:
                    return await self._not_found()
                src_branch, tgt_branch, src, tgt, merge_base, repo_git = state
                blocked = await self._pull_resolution_policy_error(owner, repo, src_branch)
                if blocked:
                    status, error = blocked
                    return await _send_response(self.request, status, error.encode())
                message = form.get("message") or f"Merge branch '{tgt_branch}' into {src_branch}"
                commit = await asyncio.to_thread(
                    pr_resolver.apply_resolution,
                    repo_git,
                    merge_base,
                    src,
                    tgt,
                    src_branch,
                    resolutions,
                    message,
                    user,
                )
        except pr_resolver.ResolverError as exc:
            return await self._ui_pull_resolve(owner, repo, pr_id, str(exc), "warn")
        await asyncio.to_thread(
            db_pr_comment_add,
            pr_id,
            self.remote_user_id,
            f"Resolved merge conflicts with the target branch via the web UI ({len(resolutions)} file(s) changed).",
        )
        run = await self.server.ci_manager.enqueue(
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
        return await self._ui_pull_view(
            owner,
            repo,
            pr_id,
            "Merge conflicts resolved. The source branch now contains the target."
            + (
                " A CI run was queued."
                if run
                else " No CI run was queued (no pipeline is configured or PR runs are disabled)."
            ),
            "ok",
        )

    async def _pull_resolution_policy_error(
        self, owner: str, repo: str, source_branch: str
    ) -> tuple[int, str] | None:
        """Check the source-branch write under the repository push lock."""
        policy = await self.server.ci_manager.config(owner, repo, include_secrets=False)
        if policy.get("_configuration_git_error"):
            return 503, "Repository CI policy cannot be verified."
        if protected_branch(policy, source_branch):
            return 403, "Conflict resolution cannot write to a protected source branch."
        return None

    async def _ui_pull_resolve_poststate(
        self, owner: str, repo: str, pr_id: int
    ) -> tuple[str, str, str, str, str, str] | None:
        """Shared validation for the resolve flows: (pr row, branches, commits) or error page."""
        pr = await asyncio.to_thread(db_pr_get, pr_id)
        if not pr or pr[1] != owner or pr[2] != repo or pr[8] != "open":
            return None
        (
            _id,
            _owner,
            _repo,
            _title,
            _body,
            src_branch,
            tgt_branch,
            _author,
            _status,
            _created,
            _closed,
            _merged,
            _method,
            _mcommit,
        ) = pr
        repo_git = _repo_bare_path(owner, repo)
        src = await _git_resolve_commit(repo_git, "refs/heads/" + src_branch)
        tgt = await _git_resolve_commit(repo_git, "refs/heads/" + tgt_branch)
        merge_base = await _git_merge_base(repo_git, tgt, src) if (src and tgt) else None
        if not (src and tgt and merge_base):
            return None
        return src_branch, tgt_branch, src, tgt, merge_base, repo_git

    async def _ui_pull_resolve_commit(self, owner: str, repo: str, pr_id: int) -> None:
        """JSON endpoint used by the Web IDE resolve mode (form-encoded csrf+payload)."""
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")

        async def respond_json(status: int, value: object) -> None:
            return await _send_response(
                self.request,
                status,
                json.dumps(value).encode(),
                [
                    ("Content-Type", "application/json; charset=utf-8"),
                    ("Cache-Control", "no-store"),
                ],
            )

        try:
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= 5 * 1024 * 1024:
                return await respond_json(
                    413, {"error": "Resolution request exceeds the size limit."}
                )
            form = await self._read_form_urlencoded()
            if not secrets.compare_digest(
                form.get("csrf", "").encode(), self._email_csrf_token().encode()
            ):
                return await respond_json(
                    403, {"error": "Invalid security token. Reload the editor."}
                )
            payload = json.loads(form.get("payload", "{}"))
            if not isinstance(payload, dict):
                raise ValueError("Invalid resolution request.")
            changes = payload.get("changes")
            if (
                not isinstance(changes, dict)
                or not changes
                or len(changes) > pr_resolver.MAX_CONFLICT_FILES
            ):
                return await respond_json(
                    400,
                    {
                        "error": f"Edit the conflicted files (up to {pr_resolver.MAX_CONFLICT_FILES})."
                    },
                )
            resolutions = [
                (path, value if value is None else str(value), value is None)
                for path, value in changes.items()
            ]
            # Serialize with pushes; the resolver CAS-protects the source branch itself.
            lock = self.server.push_locks.setdefault((owner, repo), asyncio.Lock())
            async with lock:
                state = await self._ui_pull_resolve_poststate(owner, repo, pr_id)
                if not state:
                    return await respond_json(
                        409, {"error": "The pull request state changed. Reload the editor."}
                    )
                src_branch, tgt_branch, src, tgt, merge_base, repo_git = state
                if payload.get("branch") != src_branch:
                    return await respond_json(
                        403, {"error": "Conflict resolution applies to the source branch only."}
                    )
                blocked = await self._pull_resolution_policy_error(owner, repo, src_branch)
                if blocked:
                    status, error = blocked
                    return await respond_json(status, {"error": error})
                message = payload.get("message") or f"Merge branch '{tgt_branch}' into {src_branch}"
                commit = await asyncio.to_thread(
                    pr_resolver.apply_resolution,
                    repo_git,
                    merge_base,
                    src,
                    tgt,
                    src_branch,
                    resolutions,
                    message,
                    getattr(self, "remote_user", "Browser user"),
                )
        except pr_resolver.ResolverError as exc:
            return await respond_json(409, {"error": str(exc)})
        except (ValueError, TypeError) as exc:
            return await respond_json(400, {"error": str(exc)})
        await asyncio.to_thread(
            db_pr_comment_add,
            pr_id,
            getattr(self, "remote_user_id", None),
            f"Resolved merge conflicts with the target branch via the web IDE ({len(resolutions)} file(s) changed).",
        )
        run = await self.server.ci_manager.enqueue(
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
        if run:
            return await respond_json(200, {"commit": commit})
        return await respond_json(
            200,
            {
                "commit": commit,
                "warning": "No CI run was queued (no pipeline is configured or PR runs are disabled).",
            },
        )

    async def _ui_pull_resolve_ide(self, owner: str, repo: str, pr_id: int) -> None:
        """Web IDE in resolve mode: the conflicted PR files with conflict markers."""
        from . import webide

        owner = unquote(owner)
        repo = unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return await self._not_found()
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        state = await self._ui_pull_resolve_poststate(owner, repo, pr_id)
        if not state:
            return await self._not_found()
        src_branch, tgt_branch, src, tgt, merge_base, repo_git = state
        conflicts = await asyncio.to_thread(
            pr_resolver.list_conflicts, repo_git, merge_base, src, tgt
        )
        too_many = len(conflicts) > pr_resolver.MAX_CONFLICT_FILES
        if too_many or not conflicts:
            return await self._ui_pull_resolve(
                owner,
                repo,
                pr_id,
                "Conflict resolution in the web IDE is unavailable for this state.",
                "warn",
            )
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        return_url = str_t(t"{base}/pulls/{pr_id}")
        conflict_paths_json = json.dumps([item["path"] for item in conflicts])
        token = self._email_csrf_token()
        body = html_t(t'''<main class="repo-page webide-page">{_repo_tabs(base, "pulls")}
<section id="webide" data-base="{base}/ide" data-csrf="{token}" data-mode="resolve"
 data-commit-url="{base}/pulls/{pr_id}/resolve/ide" data-return="{return_url}"
 data-pr="{pr_id}" data-branch="{src_branch}" data-commit="{src}" data-conflicts="{conflict_paths_json}">
<header class="ide-titlebar"><a id="ide-exit" href="{return_url}" class="ide-back">← Back to pull request</a><strong>{owner} / {repo}</strong><span class="ide-mode-label">Resolve PR #{pr_id}</span>
<button id="ide-quick-open" type="button" title="Go to file (Ctrl+P / ⌘P)">Go to file… <kbd>Ctrl/⌘ P</kbd></button>
<span class="pill">source branch: {src_branch}</span></header>
<div class="ide-toolbar"><div class="ide-write-tabs"><button id="ide-write" type="button" aria-pressed="true">Write</button><button id="ide-review" type="button" aria-pressed="false">Preview changes</button></div>
<div class="ide-file-tools"><button id="ide-delete" type="button">Delete file</button><button id="ide-discard-file" type="button">Discard file changes</button><button id="ide-show-changes" type="button">Review &amp; apply <span id="ide-count">0</span></button></div></div>
<div class="ide-workspace"><nav class="ide-activity" aria-label="Workspace views">
<button id="ide-explorer-view" type="button" aria-pressed="true" title="Conflicted files (Ctrl+Shift+E)"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 3h12v15H8zM4 7v14h12"/></svg><span class="ide-sr-only">Explorer</span></button>
<button id="ide-search-view" type="button" aria-pressed="false" title="Search (Ctrl+Shift+F)"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="10" cy="10" r="6"/><path d="m15 15 6 6"/></svg><span class="ide-sr-only">Search</span></button>
<button id="ide-source-view" type="button" aria-pressed="false" title="Source Control (Ctrl+Shift+G)"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="6" cy="4" r="2"/><circle cx="6" cy="20" r="2"/><circle cx="18" cy="6" r="2"/><path d="M6 6v12m0-6h6a6 6 0 0 0 6-6"/></svg><span class="ide-sr-only">Source Control</span><span id="ide-source-count">0</span></button></nav>
<aside id="ide-sidebar" data-view="explorer"><section class="ide-explorer-pane"><div class="ide-pane-heading"><h2>Conflicted files</h2><button id="ide-collapse" type="button" title="Collapse all folders">Collapse all folders</button></div><label class="ide-sr-only" for="ide-filter">Filter files</label><input id="ide-filter" placeholder="Filter files…" autocomplete="off"><div id="ide-files" role="group" aria-label="Conflicted files"></div></section>
<section class="ide-search-pane"><div class="ide-pane-heading"><h2>Search</h2></div><form id="ide-search-form"><label for="ide-search-input">Search file contents</label><input id="ide-search-input" maxlength="200" required placeholder="Search conflicted files…" autocomplete="off"><button type="submit">Search</button></form><p id="ide-search-status" class="ide-note" role="status" aria-live="polite"></p><div id="ide-search-results"></div></section>
<section class="ide-source-pane"><div class="ide-pane-heading"><h2>Apply resolution</h2><span id="ide-change-summary">Resolving…</span></div>
<form id="ide-commit"><label for="ide-message">Merge commit message</label><textarea id="ide-message" rows="3" maxlength="4000" required autocomplete="off">{str_t(t"Merge branch '{tgt_branch}' into {src_branch}")}</textarea><button id="ide-submit" type="submit">Apply resolution</button><a id="ide-cancel" href="{return_url}">Cancel</a></form>
<div class="ide-changes-heading"><h3>Conflicted files</h3><button id="ide-discard" type="button">Discard all</button></div><div id="ide-changes"></div><p class="ide-note">Edit each conflicted file until the &lt;&lt;&lt;&lt;&lt;&lt;&lt;, ======= and &gt;&gt;&gt;&gt;&gt;&gt;&gt; markers are gone, then apply. Applying creates one merge commit on the source branch so it contains the target; the pull request page then offers the ff-only merge. Mark a file for deletion to remove it.</p></section></aside>
<section class="ide-editor-pane" aria-label="Code editor"><div id="ide-tabs" role="tablist" aria-label="Open files"></div><h2 id="ide-filename">Select a file</h2><div class="ide-editor-container"><div id="ide-editor"></div><div id="ide-empty"><strong>Resolving a merge conflict.</strong><p>Open a conflicted file on the left, edit the marked sections, then apply the resolution.</p></div></div></section></div>
<footer class="ide-statusbar"><button id="ide-branch" type="button" disabled title="Branch locked while resolving this conflict" aria-label="Branch {src_branch} (locked while resolving this conflict)" data-branch="{src_branch}" data-branches="[]"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="6" cy="4" r="2"/><circle cx="6" cy="20" r="2"/><circle cx="18" cy="6" r="2"/><path d="M6 6v12m0-6h6a6 6 0 0 0 6-6"/></svg><span id="ide-branch-name">{src_branch}</span><svg class="ide-chevron" viewBox="0 0 12 12" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><path d="m2.5 4.5 3.5 3.5 3.5-3.5"/></svg></button><button id="ide-language" type="button" title="Select language" aria-haspopup="listbox">Plain Text</button><button id="ide-wrap" type="button" title="Toggle word wrap (Alt+Z)" aria-pressed="true">Word wrap</button><p id="ide-status" role="status" aria-live="polite">Loading editor…</p><span id="ide-cursor">UTF-8</span></footer>
<dialog id="ide-picker"><form method="dialog"><div class="ide-pane-heading"><label for="ide-picker-input">Go to file</label><button value="cancel" aria-label="Close picker">×</button></div><input id="ide-picker-input" placeholder="Search conflicted files…" autocomplete="off"><div id="ide-picker-results"></div></form></dialog>
</section></main>{self._webide_assets()}''')
        return await _send_response(
            self.request,
            200,
            _html_page(f"Resolve conflicts · PR #{pr_id} · {owner}/{repo}", safe_html(body)),
            [("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store")],
        )

    async def _ui_pull_close(self, owner: str, repo: str, pr_id: int) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        pr = await asyncio.to_thread(db_pr_get, pr_id)
        if not pr or pr[1] != owner or pr[2] != repo:
            return await self._not_found()
        await asyncio.to_thread(db_pr_close, pr_id)
        return await self._ui_pull_view(owner, repo, pr_id, "Pull request closed.", "ok")

    async def _ui_pull_reopen(self, owner: str, repo: str, pr_id: int) -> None:
        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return await self._forbidden(b"403 Forbidden\\n")
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\\n")
        pr = await asyncio.to_thread(db_pr_get, pr_id)
        if not pr or pr[1] != owner or pr[2] != repo:
            return await self._not_found()
        if pr[8] == "merged":
            return await self._ui_pull_view(
                owner, repo, pr_id, "Merged pull requests cannot be reopened.", "warn"
            )
        if pr[8] == "closed":
            await asyncio.to_thread(db_pr_reopen, pr_id)
            repo_git = _repo_bare_path(owner, repo)
            base_commit = await _git_resolve_commit(repo_git, "refs/heads/" + pr[6]) or ""
            head_commit = await _git_resolve_commit(repo_git, "refs/heads/" + pr[5]) or ""
            await self.server.ci_manager.enqueue(
                owner,
                repo,
                "pull_request_reopened",
                pr[6],
                base_commit,
                {
                    "pr_number": pr_id,
                    "base_branch": pr[6],
                    "head_branch": pr[5],
                    "base_commit": base_commit,
                    "head_commit": head_commit,
                },
            )
        return await self._ui_pull_view(owner, repo, pr_id, "Pull request reopened.", "ok")

    async def _ui_pull_merge(self, owner: str, repo: str, pr_id: int) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        pr = await asyncio.to_thread(db_pr_get, pr_id)
        if not pr:
            return await self._not_found()
        (
            _id,
            db_owner,
            db_repo,
            _title,
            _body,
            src_branch,
            tgt_branch,
            _author_user_id,
            status,
            _created_at,
            _closed_at,
            _merged_at,
            _merge_method,
            _merge_commit,
        ) = pr
        if db_owner != owner or db_repo != repo:
            return await self._not_found()
        if status != "open":
            return await self._ui_pull_view(owner, repo, pr_id, "PR is not open.", "warn")
        # Serialize with HTTP pushes; the Git transaction also verifies both SHAs.
        lock = self.server.push_locks.setdefault((owner, repo), asyncio.Lock())
        async with lock:
            current_pr = await _call_in_thread(db_pr_get, pr_id)
            if not current_pr or current_pr[8] != "open":
                return await self._ui_pull_view(owner, repo, pr_id, "PR is no longer open.", "warn")
            repo_git = _repo_bare_path(owner, repo)
            tgt = await _git_resolve_commit(repo_git, "refs/heads/" + tgt_branch)
            src = await _git_resolve_commit(repo_git, "refs/heads/" + src_branch)
            # CI requirements are repository-wide and come from the default
            # branch. The exact target commit still selects the required checks.
            policy = await self.server.ci_manager.config(owner, repo)
            if policy.get("_configuration_git_error"):
                return await self._ui_pull_view(
                    owner,
                    repo,
                    pr_id,
                    "Merge blocked: repository CI policy cannot be verified.",
                    "warn",
                )
            check = await self.server.ci_manager.merge_check(
                owner, repo, pr_id, tgt or "", src or "", tgt_branch
            )
            if policy["require_ci"] and (not tgt or not src or not check or check[1] != "success"):
                return await self._ui_pull_view(
                    owner,
                    repo,
                    pr_id,
                    "Merge blocked: successful CI is required for the current source and target commits.",
                    "warn",
                )
            before_refs = await self.server._branch_refs(owner, repo)
            ok, msg, new_commit = await _git_ff_merge(
                repo_git, tgt_branch, src_branch, expected=(tgt, src)
            )
            if ok and new_commit:
                await _call_in_thread(db_pr_mark_merged, pr_id, "ff-only", new_commit)
                # A merge changes the target for other open PRs, invalidating
                # their previous checks just like a push would.
                await self.server._queue_push_changes(owner, repo, before_refs)
        if not ok:
            return await self._ui_pull_view(owner, repo, pr_id, msg, "warn")
        if new_commit:
            await self.server.ci_manager.enqueue(
                owner,
                repo,
                "pull_request_merged",
                tgt_branch,
                new_commit,
                {
                    "pr_number": pr_id,
                    "base_branch": tgt_branch,
                    "head_branch": src_branch,
                    "base_commit": new_commit,
                },
            )
        return await self._ui_pull_view(owner, repo, pr_id, msg, "ok")

    def _email_csrf_token(self) -> str:
        token = getattr(self.server, "email_csrf_token", None)
        if not token:
            token = secrets.token_urlsafe(32)
            self.server.email_csrf_token = token
        return token

    async def _ui_admin_email(
        self, notice: str = "", error: bool = False, submitted: dict[str, object] | None = None
    ) -> None:
        if REQUIRE_AUTH and not _require_admin(self):
            return await self._forbidden(b"403 Forbidden: admin required.\n")
        settings = await _call_in_thread(load_email_settings)
        display = submitted if submitted is not None else settings
        token = self._email_csrf_token()
        password_status = (
            "A password is configured."
            if settings.get("password")
            else "No password is configured."
        )
        notice_html = (
            safe_html(
                html_t(t'<div class="{"warn" if error else "ok"}" role="alert">{notice}</div>')
            )
            if notice
            else safe_html("")
        )
        tls_options = join_html(
            [
                html_t(
                    t'<option value="{value}"{safe_html(" selected" if display.get("tls") == value else "")}>{label}</option>'
                )
                for value, label in (
                    ("starttls", "STARTTLS (usually port 587)"),
                    ("ssl", "Implicit TLS (usually port 465)"),
                )
            ]
        )
        body = safe_html(
            html_t(t'''<div class="topbar"><h1>Email settings</h1><a class="pill" href="/">Repositories</a></div>{notice_html}
<div class="box"><p>Server-wide SMTP settings for CI notifications. Saved web settings override SMTP environment settings immediately, without restarting.</p>
<p class="warn">Use HTTPS. The SMTP password is stored in the server database, not encrypted. Protect database files and backups. It is never displayed or passed to job environments. Host CI still requires trusted code.</p>
<form method="POST" action="/admin/email"><input type="hidden" name="csrf" value="{token}">
<label>SMTP hostname</label><input name="host" value="{display.get("host", "")}" required autocomplete="off">
<label>Port</label><input name="port" type="number" min="1" max="65535" value="{display.get("port", "587")}" required>
<label>Transport security</label><select name="tls">{tls_options}</select>
<label><input type="checkbox" name="trust_server_cert"{safe_html(" checked" if display.get("trust_server_cert", False) else "")}> Trust server certificate without verification (insecure)</label>
<p class="warn">When checked, no pasted certificate is needed. TLS still encrypts the connection, but certificate, hostname, and expiry checks are disabled. An attacker could impersonate the mail server and steal SMTP credentials. This overrides certificate trust settings below.</p>
<label>Trusted SMTP certificate / CA certificates (optional, PEM)</label>
<textarea name="ca_cert" maxlength="65536" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----">{display.get("ca_cert", "")}</textarea>
<p>For verified TLS with a self-signed server, paste its public certificate, or paste your internal CA certificate. Verify its fingerprint with your mail administrator first. Never paste a private key. Leave blank for system trust only. Hostname and expiry checks remain enabled unless the checkbox above is checked.</p>
<label>Sender email address</label><input name="sender" type="email" value="{display.get("sender", "")}" required>
<label>Username (blank for no authentication)</label><input name="username" value="{display.get("username", "")}" autocomplete="off">
<label>Password (leave blank to keep existing)</label><input name="password" type="password" value="" autocomplete="new-password">
<p>{password_status}</p><label><input type="checkbox" name="clear_password"> Clear existing password</label>
<label>Public server URL (optional, for run links)</label><input name="public_url" type="url" value="{display.get("public_url", "")}" placeholder="https://git.example.com">
<button type="submit">Save email settings</button></form></div>
<div class="box"><h2>Send test email</h2><p>Uses saved settings, including the certificate verification choice, not unsaved edits.</p>
<form method="POST" action="/admin/email/test"><input type="hidden" name="csrf" value="{token}">
<label>Recipient</label><input type="email" name="recipient" required><button type="submit">Send test email</button></form>
<p>Choose recipients and notification preferences separately in each repository's CI settings.</p></div>''')
        )
        return await _send_response(
            self.request,
            200,
            _html_page("Email settings", body),
            [("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store")],
        )

    async def _ui_admin_email_save(self, test: bool = False) -> None:
        if REQUIRE_AUTH and not _require_admin(self):
            return await self._forbidden(b"403 Forbidden: admin required.\n")
        form = await self._read_form_urlencoded()
        if not secrets.compare_digest(
            str(form.get("csrf", "")).encode("utf-8"), self._email_csrf_token().encode("utf-8")
        ):
            return await self._forbidden(b"403 Forbidden: invalid form token.\n")
        current = await _call_in_thread(load_email_settings)
        if test:
            try:
                recipients = validate_recipients(form.get("recipient", ""))
                if len(recipients) != 1:
                    raise ValueError("Enter exactly one test recipient.")
                validate_email_settings(current)
            except ValueError as exc:
                return await self._ui_admin_email(notice=str(exc), error=True)
            try:
                await _call_in_thread(
                    send_notification,
                    "server",
                    "email-test",
                    (0, "test", "", "", "test", "", 0, None),
                    recipients,
                    current,
                )
            except Exception as exc:
                return await self._ui_admin_email(
                    notice=f"Test email failed ({type(exc).__name__}). Check SMTP settings and connectivity.",
                    error=True,
                )
            return await self._ui_admin_email(
                notice="Test email accepted by SMTP server. Check the recipient's inbox."
            )
        settings: dict[str, object] = {
            key: form.get(key, "")
            for key in (
                "host",
                "port",
                "tls",
                "sender",
                "username",
                "password",
                "public_url",
                "ca_cert",
            )
        }
        settings["trust_server_cert"] = "trust_server_cert" in form
        if "clear_password" in form:
            settings["password"] = ""
        elif not settings["password"]:
            settings["password"] = current.get("password", "")
        try:
            settings = dict(validate_email_settings(settings))
        except ValueError as exc:
            return await self._ui_admin_email(notice=str(exc), error=True, submitted=settings)
        await _call_in_thread(db_email_settings_set, json.dumps(settings))
        return await self._ui_admin_email(notice="Email settings saved.")

    async def _ui_deployments(
        self, owner: str, repo: str, deployment_id: int | None = None
    ) -> None:
        from .database import db_deployment_detail, db_deployments_count, db_deployments_list

        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        if deployment_id is not None:
            row = await _call_in_thread(db_deployment_detail, owner, repo, deployment_id)
            if not row:
                return await self._not_found()
            rows = [row]
        else:
            params = parse_qs(urlparse(self.path).query or "")
            value = (params.get("before") or [""])[0]
            before = int(value) if value.isascii() and value.isdecimal() and len(value) < 19 else 0
            size = _page_size(params)
            total = await _call_in_thread(db_deployments_count, owner, repo, before)
            page = _clamp_page(_page_number(params), total, size)
            rows = await _call_in_thread(
                db_deployments_list, owner, repo, before, size, (page - 1) * size
            )
        entries: list[str] = []
        for row in rows:
            identity, run_id, commit, status, started, finished, notification, raw, retained = row[
                :9
            ]
            config = json.loads(raw or "{}")
            branch = config.get("deploy_branch", "—")
            if deployment_id is None:
                entries.append(
                    html_t(t'''<section class="box deployment-summary"><div class="topbar"><h2><a href="{base}/ci/deployments/{identity}">Deployment #{identity}</a> · <span class="ci-status" data-status="{status}">{status.replace("_", " ")}</span></h2><a class="pill" href="{base}/ci/deployments/{identity}">View details</a></div>
<p><strong>{config.get("deployment_name") or config.get("pipeline_id", "default")}</strong> · <code>{branch}</code> · <a href="{base}/commit/{q(commit)}"><code>{commit[:8]}</code></a></p>
<p class="muted">Started: {started} · Duration: {_ci_elapsed(started, finished)}</p></section>''')
                )
                continue
            run_link = (
                safe_html(
                    html_t(t'<a class="pill" href="{base}/ci/runs/{run_id}">CI run #{run_id}</a>')
                )
                if retained
                else safe_html(
                    html_t(t'<span class="muted">CI run #{run_id} no longer retained</span>')
                )
            )
            steps = json.loads(row[10] or "[]")
            step_html = join_html(
                [
                    html_t(
                        t'<details class="ci-step" open><summary><span class="ci-status" data-status="{step["status"]}">{step["status"]}</span> <strong>{step["name"]}</strong></summary><pre tabindex="0">{step["output"] or "No output yet."}</pre></details>'
                    )
                    for step in steps
                ]
            )
            logs = safe_html(
                html_t(
                    t'{step_html}<details><summary>Combined output</summary><div class="ci-log-toolbar"><button type="button" data-copy-deployment="deployment-output-{identity}">Copy output</button><span class="muted" role="status" data-copy-feedback></span></div><pre id="deployment-output-{identity}" tabindex="0" aria-label="Deployment output">{row[9] or "No output yet."}</pre></details>'
                )
            )
            entries.append(
                html_t(t'''<section class="box"><h2><a href="{base}/ci/deployments/{identity}">Deployment #{identity}</a> · <span class="ci-status" data-status="{status}">{status.replace("_", " ")}</span></h2>
<p>Deployment: <code>{config.get("deployment_name") or config.get("pipeline_id", "default")}</code> · Pipeline: <code>{config.get("pipeline_id", "default")}</code> · Branch: <code>{branch}</code> · Commit: <a href="{base}/commit/{q(commit)}"><code>{commit}</code></a></p>
<p class="muted">Started: {started} · Finished: {finished or "—"} · Duration: {_ci_elapsed(started, finished)} · Email: {notification or "not queued"}</p>{run_link}{logs}</section>''')
            )
        listing = (
            join_html(entries)
            if entries
            else safe_html(
                '<section class="box"><h2>No deployments yet</h2><p>Deployment attempts appear here after matching CI succeeds. Skipped deployments are not recorded.</p></section>'
            )
        )
        older = (
            _pagination(
                base + "/ci/deployments",
                {"before": str(before)} if before else {},
                page,
                page * size < total,
                total=total,
                per_page=size,
            )
            if deployment_id is None
            else safe_html("")
        )
        results = safe_html(html_t(t'<div id="deployment-results">{listing}{older}</div>'))
        if (parse_qs(urlparse(self.path).query or "").get("partial") or [""])[0] == "1":
            return await _send_response(
                self.request,
                200,
                str(results).encode("utf-8"),
                [("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store")],
            )
        body = html_t(t'''{_ci_tabs(base, "deployments")}<div class="topbar"><h2>Deployment history</h2><a class="pill" href="{base}/ci/deployments">Latest deployments</a></div>
<script>document.addEventListener("click", async function(event) {{ const button = event.target.closest("[data-copy-deployment]"); if (!button) return; const log = document.getElementById(button.dataset.copyDeployment); const feedback = button.parentElement.querySelector("[data-copy-feedback]"); if (!log) return; try {{ await navigator.clipboard.writeText(log.textContent); feedback.textContent = "Copied."; }} catch (_) {{ feedback.textContent = "Could not copy. Select the output and copy it manually."; }} }});</script>
{results}
<script>(function() {{ let busy = false; const timer = setInterval(async function() {{ if (busy) return; busy = true; try {{ const url = new URL(location.href); url.searchParams.set("partial", "1"); const response = await fetch(url, {{cache:"no-store", credentials:"same-origin"}}); if (!response.ok || response.redirected) {{ clearInterval(timer); return; }} const text = await response.text(); const current = document.getElementById("deployment-results"); const states = Array.from(current.querySelectorAll("details")).map(el => el.open); const scrolls = Array.from(current.querySelectorAll("pre")).map(el => [el.scrollTop, el.scrollHeight - el.clientHeight - el.scrollTop < 24]); current.outerHTML = text; const updated = document.getElementById("deployment-results"); updated.querySelectorAll("details").forEach((el, i) => {{ if (i < states.length) el.open = states[i]; }}); updated.querySelectorAll("pre").forEach((el, i) => {{ if (scrolls[i]) el.scrollTop = scrolls[i][1] ? el.scrollHeight : scrolls[i][0]; }}); }} catch (_) {{ }} finally {{ busy = false; }} }}, 2000); }})();</script>''')
        return await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"Deployments · {owner}/{repo}"),
                safe_html(html_t(t'<main class="ci-page">{safe_html(body)}</main>')),
            ),
        )

    async def _ui_ci(
        self,
        owner: str,
        repo: str,
        run_id: int | None = None,
        notice: str = "",
        partial: bool = False,
    ) -> None:
        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        if run_id is not None:
            return await self._ui_ci_run_detail(owner, repo, run_id, partial=partial)
        query_params = parse_qs(urlparse(getattr(self, "path", "")).query or "")
        filters = {
            key: (query_params.get(key) or [""])[0].strip()
            for key in ("status", "event", "branch", "q", "warnings")
        }
        allowed_statuses = {
            "queued",
            "running",
            "success",
            "failed",
            "timed_out",
            "interrupted",
            "cancelled",
        }
        allowed_events = {
            "push",
            "pull_request",
            "pull_request_updated",
            "pull_request_reopened",
            "pull_request_merged",
            "manual",
        }
        if filters["status"] not in allowed_statuses:
            filters["status"] = ""
        if filters["event"] not in allowed_events:
            filters["event"] = ""
        if filters["warnings"] not in ("yes", "no"):
            filters["warnings"] = ""
        filters["q"] = filters["q"][:128]
        pipeline = (query_params.get("pipeline") or [""])[0][:64]
        cursor = (query_params.get("before") or [""])[0]
        before = (
            int(cursor) if cursor.isascii() and cursor.isdigit() and len(cursor) <= 18 else None
        )
        from .database import db_ci_run_contexts, db_ci_run_workflows, db_ci_runs_count

        size = _page_size(query_params)
        total = await _call_in_thread(
            db_ci_runs_count,
            owner,
            repo,
            status=filters["status"],
            event=filters["event"],
            branch=filters["branch"],
            query=filters["q"],
            before=before,
            warnings=filters["warnings"],
            pipeline=pipeline,
        )
        page = _clamp_page(_page_number(query_params), total, size)
        runs = await _call_in_thread(
            db_ci_runs_list,
            owner,
            repo,
            size,
            status=filters["status"],
            event=filters["event"],
            branch=filters["branch"],
            query=filters["q"],
            summary=True,
            warnings=filters["warnings"],
            include_warnings=True,
            include_pipeline=True,
            pipeline=pipeline,
            before=before,
            offset=(page - 1) * size,
        )
        has_next = page * size < total
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        contexts = await _call_in_thread(db_ci_run_contexts, owner, repo, [row[0] for row in runs])
        commit_hashes = {
            row[0]: contexts.get(row[0], ("", "", None, "", ""))[0] or row[3] for row in runs
        }
        subjects = await _ci_commit_subjects(
            _repo_bare_path(owner, repo), set(commit_hashes.values())
        )
        status_labels = {
            "success": "Completed successfully",
            "failed": "Failed",
            "timed_out": "Timed out",
            "running": "In progress",
            "queued": "Queued",
            "cancelled": "Cancelled",
            "interrupted": "Interrupted",
        }
        rows: list[str] = []
        status_symbols = {
            "success": "✓",
            "failed": "×",
            "timed_out": "!",
            "running": "◌",
            "queued": "·",
            "cancelled": "−",
            "interrupted": "!",
        }
        for run in runs:
            run_event = str(run[1])
            _, head_branch, pr_id, pr_title, pr_author = contexts.get(
                run[0], ("", "", None, "", "")
            )
            run_branch = head_branch or run[2]
            run_commit = commit_hashes[run[0]]
            subject, author = subjects.get(run_commit.lower(), ("", ""))
            title = (
                subject
                or pr_title
                or f"{run_event.replace('_', ' ').capitalize()} on {run_branch or 'repository'}"
            )
            origin = _ci_run_origin(base, run_event, run_commit, pr_id, pr_author, author, pr_title)
            run_status = str(run[4])
            status_label = status_labels.get(run_status, run_status.replace("_", " ").capitalize())
            warning = (
                safe_html(
                    html_t(
                        t'<a class="ci-warning-badge" href="{base}/ci/runs/{run[0]}#ci-run-warnings" title="{run[11]}"><span aria-hidden="true">⚠</span> Warning</a>'
                    )
                )
                if run[11]
                else safe_html("")
            )
            rows.append(
                html_t(
                    t'''<li class="ci-workflow-run">
<span class="ci-run-marker" data-status="{run_status}" aria-hidden="true">{status_symbols.get(run_status, "·")}</span>
<div class="ci-run-primary"><a class="ci-run-link" href="{base}/ci/runs/{run[0]}">{title}</a>
<div class="ci-run-meta"><span>{run[12]} #{run[0]}</span>{origin}<span>{status_label}</span>{warning}</div></div>
<span class="ci-run-branch" title="{run_branch}">{run_branch or "—"}</span>
<div class="ci-run-when"><time datetime="{str(run[8]).replace(" ", "T")}" title="{run[8]} UTC">{_relative_time(run[8])}</time><span>{_ci_elapsed(run[9], run[10])}</span></div>
</li>'''
                )
            )
        empty = (
            "No runs match this view." if pipeline or any(filters.values()) else "No CI runs yet."
        )
        runs_html = (
            safe_html(html_t(t'<ul class="ci-workflow-list">{join_html(rows)}</ul>'))
            if rows
            else safe_html(html_t(t'<p class="ci-workflow-empty muted">{empty}</p>'))
        )
        view_params = {"pipeline": pipeline} if pipeline else {}
        pagination = _pagination(
            base + "/ci",
            {
                **{key: value for key, value in filters.items() if value},
                **view_params,
                **({"before": str(before)} if before is not None else {}),
            },
            page,
            has_next,
            total=total,
            per_page=size,
        )
        run_count = f"{total:,} workflow {'run' if total == 1 else 'runs'}"
        results_html = safe_html(
            html_t(t"""<div id="ci-results">
<div class="ci-workflow-panel"><div class="ci-workflow-panel-header"><strong>{run_count}</strong><span class="muted">Refreshes every 5 seconds</span></div>{runs_html}</div>{pagination}</div>""")
        )
        if partial:
            return await _send_response(
                self.request,
                200,
                str(results_html).encode("utf-8"),
                [("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store")],
            )
        branches = await _git_list_branches(_repo_bare_path(owner, repo))
        workflow_names = set(await _call_in_thread(db_ci_run_workflows, owner, repo))
        config = await self.server.ci_manager.config(owner, repo, include_secrets=False)
        workflow_names.update(
            item["pipeline_id"]
            for item in CIManager.pipelines(config)
            if item.get("command") or item.get("steps") or item.get("repository_config")
        )
        if pipeline:
            workflow_names.add(pipeline)

        def workflow_href(name: str, *, keep_filters: bool = True) -> str:
            params = {key: value for key, value in filters.items() if value and keep_filters}
            if name:
                params["pipeline"] = name
            if query_params.get("per_page"):
                params["per_page"] = str(size)
            return base + "/ci" + ("?" + urlencode(params) if params else "")

        links = join_html(
            html_t(
                t'''<a class="ci-workflow-nav-link" href="{workflow_href(name)}"{safe_html(' aria-current="page"' if name == pipeline else "")}><span aria-hidden="true">{icon}</span>{label}</a>'''
            )
            for name, label, icon in [
                ("", "All workflows", "▤"),
                *((name, name, "◇") for name in sorted(workflow_names)),
            ]
        )
        filter_options = {
            "warnings": [
                ("", "All warnings"),
                ("yes", "With warnings"),
                ("no", "Without warnings"),
            ],
            "status": [
                ("", "All statuses"),
                ("queued", "Queued"),
                ("running", "Running"),
                ("success", "Success"),
                ("failed", "Failed"),
                ("timed_out", "Timed out"),
                ("interrupted", "Interrupted"),
                ("cancelled", "Cancelled"),
            ],
            "event": [
                ("", "All events"),
                ("push", "Push"),
                ("pull_request", "PR opened"),
                ("pull_request_updated", "PR updated"),
                ("pull_request_reopened", "PR reopened"),
                ("pull_request_merged", "PR merged"),
                ("manual", "Manual"),
            ],
        }
        options_html: dict[str, str] = {}
        for name, options in filter_options.items():
            options_html[name] = join_html(
                [
                    html_t(
                        t'<option value="{value}"{safe_html(" selected" if value == filters[name] else "")}>{label}</option>'
                    )
                    for value, label in options
                ]
            )
        branch_values = [("", "All branches")] + [(branch, branch) for branch in branches]
        if filters["branch"] and filters["branch"] not in branches:
            branch_values.append((filters["branch"], filters["branch"]))
        branch_options = join_html(
            [
                html_t(
                    t'<option value="{value}"{safe_html(" selected" if value == filters["branch"] else "")}>{label}</option>'
                )
                for value, label in branch_values
            ]
        )
        active_filters = sum(bool(value) for value in filters.values())
        filter_label = f"Filters ({active_filters} active)" if active_filters else "Filters"
        pipeline_input = (
            safe_html(html_t(t'<input type="hidden" name="pipeline" value="{pipeline}">'))
            if pipeline
            else safe_html("")
        )
        filter_form = safe_html(
            html_t(t'''<details class="box ci-compact ci-run-filters"><summary>{filter_label}</summary><form method="GET" action="{base}/ci" class="ci-toolbar">
<input type="hidden" name="per_page" value="{size}">{pipeline_input}
<input aria-label="Search runs" name="q" value="{filters["q"]}" placeholder="Run ID, commit, or output text">
<select aria-label="Status" name="status">{options_html["status"]}</select><select aria-label="Event" name="event">{options_html["event"]}</select>
<select aria-label="Warnings" name="warnings">{options_html["warnings"]}</select>
<select aria-label="Branch" name="branch">{branch_options}</select><button type="submit">Filter runs</button>
<a class="pill" href="{workflow_href(pipeline, keep_filters=False)}">Clear filters</a></form></details>''')
        )
        notice_html = (
            safe_html(html_t(t'<div class="ok">{notice}</div>')) if notice else safe_html("")
        )
        body = html_t(t"""{_ci_tabs(base, "runs")}{notice_html}
<div class="ci-workflows-layout"><nav class="ci-workflow-nav" aria-label="Workflows"><h2>Workflows</h2>{links}</nav>
<section class="ci-workflows-main"><header class="ci-workflows-heading"><div><h2>{pipeline or "All workflows"}</h2><p class="muted">{("Run history for " + pipeline + ".") if pipeline else "Run history for all workflows."}</p></div><a class="pill" href="{base}/ci/run">Run pipeline</a></header>{filter_form}{results_html}</section></div>
<script>(function() {{ let polling = false; let timer = null; async function update() {{ if (polling) return; polling = true; try {{ const url = new URL(window.location.href); url.searchParams.set("partial", "1"); const response = await fetch(url, {{cache:"no-store", credentials:"same-origin"}}); if (response.redirected || !response.ok) {{ clearInterval(timer); return; }} const fragment = await response.text(); const current = document.getElementById("ci-results"); if (!current) {{ clearInterval(timer); return; }} current.outerHTML = fragment; }} catch (_error) {{ /* Keep the current results and retry on the next interval. */ }} finally {{ polling = false; }} }} timer = setInterval(update, 5000); }})();</script>""")
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"CI · {owner}/{repo}"),
                safe_html(html_t(t'<main class="ci-page">{safe_html(body)}</main>')),
            ),
        )

    async def _ui_ci_manual(
        self, owner: str, repo: str, *, branch: str = "", notice: str = ""
    ) -> None:
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return await self._not_found()
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        branches = await _git_list_branches(repo_git)
        query_params = parse_qs(urlparse(getattr(self, "path", "")).query or "")
        selected_branch = branch or (query_params.get("run_branch") or [""])[0]
        if selected_branch not in branches:
            default_branch = await _git_default_branch(repo_git)
            selected_branch = (
                default_branch if default_branch in branches else next(iter(branches), "")
            )
        manual_options = join_html(
            html_t(
                t'<option value="{b}"{safe_html(" selected" if b == selected_branch else "")}>{b}</option>'
            )
            for b in branches
        )
        config = await self.server.ci_manager.config(
            owner,
            repo,
            "refs/heads/" + selected_branch if selected_branch else "HEAD",
            include_secrets=False,
        )
        config_commit = config.get("_configuration_commit") or ""
        config_status = config.get("_configuration_status", "unavailable")
        config_error = config.get("_configuration_error") or ""
        pipelines = CIManager.pipelines(config)
        pipeline_options = join_html(
            [
                html_t(
                    t'<option value="{item.get("pipeline_id", "default")}">{item.get("pipeline_id", "default")}</option>'
                )
                for item in pipelines
            ]
        )
        manual_enabled = bool(
            any(
                item.get("command") or item.get("steps") or item.get("repository_config")
                for item in pipelines
            )
            and branches
            and config_status in ("valid", "blocked")
            and _has_write_scope(self)
        )
        disabled = safe_html("" if manual_enabled else " disabled")
        manual_notice = (
            ""
            if manual_enabled
            else "Manual runs require write access, a runnable pipeline, and an existing branch."
        )
        notice_html = (
            safe_html(html_t(t'<div class="warn" role="status">{notice}</div>'))
            if notice
            else safe_html("")
        )
        body = html_t(t'''{_ci_tabs(base, "run")}<div class="topbar"><h2>Run pipeline</h2></div>{notice_html}
<div class="box"><h3>Check configuration</h3><form class="ci-toolbar" method="GET" action="{base}/ci/run"><label>Branch to validate <select name="run_branch" required>{manual_options}</select></label><button type="submit">Check configuration</button></form>
<p>Configuration: <strong>{config_status}</strong> <code>{config_commit}</code> {config_error}</p></div>
<div class="box"><h3>Run manually</h3><form class="ci-toolbar" method="POST" action="{base}/ci/run"><input type="hidden" name="branch" value="{selected_branch}"><input type="hidden" name="sha" value="{config_commit}"><label>Pipeline <select name="pipeline">{pipeline_options}</select></label><button type="submit"{disabled}>Queue run</button><small class="muted">{manual_notice}</small></form></div>''')
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"Run pipeline · {owner}/{repo}"),
                safe_html(html_t(t'<main class="ci-page">{safe_html(body)}</main>')),
            ),
        )

    async def _ui_ci_run_detail(
        self, owner: str, repo: str, run_id: int, *, partial: bool = False
    ) -> None:
        run = await _call_in_thread(db_ci_run_get, owner, repo, run_id)
        if not run:
            if partial:
                return await _send_text(self.request, 404, "CI run not found.\n")
            return await self._not_found()

        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        active = run[4] in ("queued", "running")
        meta = await _call_in_thread(db_ci_run_metadata, owner, repo, run_id)
        if meta is None:
            if partial:
                return await _send_text(self.request, 404, "CI run not found.\n")
            return await self._not_found()
        snapshot = json.loads(meta["config"] or "{}")
        payload = json.loads(meta["payload"] or "{}")
        workflow = str(payload.get("pipeline_id") or "default")
        configuration_files = _ci_run_source_files(base, payload, snapshot)
        command_details = safe_html("")
        if not REQUIRE_AUTH or _require_admin(self):
            saved_command = (
                json.dumps(snapshot["steps"], indent=2)
                if snapshot.get("steps")
                else snapshot.get("command", "Legacy run: no snapshot available.")
            )
            command_details = safe_html(
                html_t(
                    t'<h3>Execution snapshot</h3><p class="muted">Image: {snapshot.get("image", "—")}</p><pre>{saved_command}</pre>'
                )
            )
        configuration_snapshot = safe_html(
            html_t(
                t'<details id="ci-run-config" class="ci-run-disclosure"><summary>Configuration snapshot</summary>{configuration_files}{command_details}</details>'
            )
        )
        can_write = _has_write_scope(self)
        actions = safe_html("")
        if can_write:
            action = "cancel" if active else "rerun"
            unavailable = safe_html(
                ' disabled title="Legacy run has no configuration snapshot"'
                if not active and not snapshot
                else ""
            )
            actions = safe_html(
                html_t(
                    t'<form method="POST" action="{base}/ci/runs/{run_id}/{action}"><button{unavailable}>{action.capitalize()}</button></form>'
                )
            )
        email_action = safe_html("")
        if (not REQUIRE_AUTH or _require_admin(self)) and meta["notification"].startswith(
            ("failed", "delivery unknown")
        ):
            email_action = safe_html(
                html_t(
                    t'<form method="POST" action="{base}/ci/runs/{run_id}/notify"><button>Retry email (may duplicate an uncertain delivery)</button></form>'
                )
            )
        waiting = (
            "Waiting for a runner slot or an earlier run in this repository."
            if run[4] == "queued"
            else ""
        )
        output = run[5] or "No output yet."
        exit_code = "pending" if run[7] is None else run[7]
        started_at = run[9] or "—"
        finished_at = run[10] or "—"
        truncated_notice = (
            safe_html('<p class="muted">Output truncated at 1 MiB.</p>')
            if run[6]
            else safe_html("")
        )
        steps = json.loads(await _call_in_thread(db_ci_steps_get, run_id))
        steps_html = join_html(
            [
                html_t(
                    t'''<details id="ci-step-{index}" class="ci-step"{safe_html(" open" if step["status"] in ("running", "failed", "timed_out") else "")}><summary><strong>{step["name"]}</strong><span class="ci-status" data-status="{step["status"]}">{step["status"].replace("_", " ")}</span><span class="muted">{step["duration"]}</span></summary><p class="muted">Started: {step["started_at"] or "—"} · Finished: {step["finished_at"] or "—"} · Exit: {step["return_code"] if step["return_code"] is not None else "—"}</p><pre id="ci-step-log-{index}" data-ci-scroll tabindex="0" aria-label="Output for {step["name"]}">{step["output"] or "No output."}</pre></details>'''
                )
                for index, step in enumerate(steps)
            ]
        )
        steps_section = (
            safe_html(
                html_t(
                    t'<section class="box ci-run-steps" aria-labelledby="ci-run-steps-title"><div class="ci-section-heading"><h2 id="ci-run-steps-title">Steps</h2><span class="muted">{len(steps)} steps · select a step to view output</span></div>{steps_html}</section>'
                )
            )
            if steps
            else safe_html("")
        )
        artifact_size = await _call_in_thread(db_ci_artifact_get, owner, repo, run_id)
        from .database import db_deployments_for_run

        deployments = await _call_in_thread(db_deployments_for_run, run_id)
        deployment_html = join_html(
            [
                html_t(
                    t'<section class="box"><h2>Deployment: {entry[2]} · {json.loads(entry[5] or "{}").get("deployment_name") or entry[1]}</h2><p class="muted">Deployment email: {entry[4] or "not queued"}</p><pre>{entry[3] or "No output yet. Logs are available when deployment finishes."}</pre></section>'
                )
                for entry in deployments
            ]
        )
        active = active or any(
            entry[2] == "running" or entry[4] in ("queued", "sending") for entry in deployments
        )
        active = active or bool(run[4] == "success" and run_id in self.server.ci_manager.active)
        has_artifact = isinstance(artifact_size, int) and artifact_size > 0
        artifact_html = (
            safe_html(
                html_t(
                    t'<section id="ci-run-artifacts" class="box ci-run-artifacts"><div class="ci-section-heading"><h2>Artifact archive</h2></div><div class="ci-run-artifact-row"><span>ci-{run_id}-artifacts.zip <small class="muted">{artifact_size / 1024:.1f} KiB</small></span><a class="pill" href="{base}/ci/runs/{run_id}/artifacts">Download ZIP</a></div></section>'
                )
            )
            if isinstance(artifact_size, int) and has_artifact
            else safe_html("")
        )
        artifact_nav = (
            safe_html('<a href="#ci-run-artifacts">Artifact archive</a>')
            if has_artifact
            else safe_html("")
        )
        reason = waiting or meta["reason"]
        reason_html = (
            safe_html(html_t(t'<p class="warn" role="status">{reason}</p>'))
            if reason and reason != meta["warnings"]
            else safe_html("")
        )
        warning_html = (
            safe_html(
                html_t(
                    t'<div id="ci-run-warnings" class="warn" role="status"><strong>Run warnings</strong><p class="ci-warning-details">{meta["warnings"]}</p></div>'
                )
            )
            if meta["warnings"]
            else safe_html("")
        )
        result_html = safe_html(
            html_t(t'''<div id="ci-run-result" data-active="{"true" if active or meta["notification"] in ("queued", "sending") else "false"}">
<div class="ci-run-layout">
<nav class="ci-run-sidebar" aria-label="Run navigation">
<a class="ci-run-sidebar-summary" href="#ci-run-overview">Summary</a>
<h3>Jobs</h3><a class="ci-run-sidebar-job" href="#ci-run-job"><span class="ci-status" data-status="{run[4]}">{run[4].replace("_", " ")}</span><span>{workflow}</span></a>
<a href="#ci-run-output">Combined log</a>{artifact_nav}
</nav>
<div class="ci-run-content">
<section id="ci-run-overview" class="box ci-run-overview" aria-label="Run summary"><div class="ci-section-heading"><h2>Summary</h2><div class="ci-run-actions">{actions}<a class="pill" href="{base}/ci/runs/{run_id}/log">Download raw log</a></div></div>
<div class="ci-run-summary"><div><span>Status</span><span class="ci-status" data-status="{run[4]}">{run[4].replace("_", " ")}</span></div><div><span>Duration</span><strong>{_ci_elapsed(run[9], run[10])}</strong></div><div><span>Runner</span><strong>{snapshot.get("runner", "legacy host")}</strong></div><div><span>Exit code</span><strong>{exit_code}</strong></div></div>
{warning_html}{reason_html}
<details id="ci-run-metadata" class="ci-run-disclosure"><summary>Run details</summary><dl class="ci-run-metadata"><dt>Pipeline</dt><dd>{payload.get("pipeline_id", "default")}</dd><dt>Created</dt><dd>{run[8]}</dd><dt>Started</dt><dd>{started_at}</dd><dt>Finished</dt><dd>{finished_at}</dd><dt>Queue wait</dt><dd>{_ci_elapsed(run[8], run[9] or run[10])}</dd><dt>Phase</dt><dd>{meta["phase"] or "queued"}</dd><dt>Email</dt><dd>{meta["notification"] or "not sent"}</dd><dt>Commit</dt><dd><code>{run[3]}</code></dd><dt>Configuration commit</dt><dd><code>{payload.get("configuration_commit", "—")}</code></dd><dt>Base</dt><dd><code>{payload.get("base_commit", "—")}</code></dd><dt>Head</dt><dd><code>{payload.get("head_commit", "—")}</code></dd></dl>{email_action}</details>{configuration_snapshot}</section>
<section id="ci-run-job" class="ci-run-job" aria-labelledby="ci-run-job-title">
<header class="ci-run-job-header"><div><span class="muted">Job</span><h2 id="ci-run-job-title">{workflow}</h2></div><span class="ci-status" data-status="{run[4]}">{run[4].replace("_", " ")}</span></header>
{steps_section}<details id="ci-run-output" class="box ci-run-output"{safe_html(" open" if not steps else "")}><summary>{"Combined run log" if steps else "Output"}</summary><div class="ci-log-toolbar"><label><input id="ci-follow" type="checkbox" checked> Follow output</label><button id="ci-copy-output" type="button">Copy output</button><span id="ci-copy-feedback" class="muted" role="status"></span></div>
<pre id="ci-log" data-ci-scroll tabindex="0" aria-label="Run output">{output}</pre>{truncated_notice}</details></section>
{artifact_html}{deployment_html}</div></div></div>''')
        )
        if partial:
            return await _send_response(
                self.request,
                200,
                str(result_html).encode("utf-8"),
                [("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store")],
            )

        from .database import db_ci_run_contexts

        contexts = await _call_in_thread(db_ci_run_contexts, owner, repo, [run_id])
        head_commit, head_branch, pr_id, pr_title, pr_author = contexts.get(
            run_id, ("", "", None, "", "")
        )
        title_commit = head_commit or run[3]
        subjects = await _ci_commit_subjects(_repo_bare_path(owner, repo), {title_commit})
        subject, author = subjects.get(title_commit.lower(), ("", ""))
        origin = _ci_run_origin(base, run[1], title_commit, pr_id, pr_author, author, pr_title)
        run_title = (
            subject
            or pr_title
            or str_t(t"{run[1].replace('_', ' ').capitalize()} run on {run[2] or 'repository'}")
        )
        workflow_href = base + "/ci?" + urlencode({"pipeline": workflow})
        body = safe_html(
            html_t(t'''{_ci_tabs(base, "runs")}<div class="topbar"><div><h2 id="ci-run-title">{run_title}</h2><div class="ci-run-meta"><a href="{workflow_href}">{workflow}</a><span>Run #{run_id}</span>{origin}<span class="ci-run-branch">{head_branch or run[2]}</span></div></div>
<div><a class="pill" href="{base}/ci">← All runs</a></div></div>
{result_html}
<script>(function() {{
function revealLog(hash) {{
 if (hash !== "#ci-run-output") return;
 const log = document.getElementById("ci-run-output"); if (log) log.open = true;
}}
revealLog(window.location.hash);
window.addEventListener("hashchange", () => revealLog(window.location.hash));
document.addEventListener("click", event => {{
 if (event.target.closest('.ci-run-sidebar a[href="#ci-run-output"]')) revealLog("#ci-run-output");
}});
document.addEventListener("click", async event => {{ if (!event.target.closest("#ci-copy-output")) return;
 const log = document.getElementById("ci-log"); const feedback = document.getElementById("ci-copy-feedback");
 try {{ await navigator.clipboard.writeText(log.textContent); feedback.textContent = "Copied."; }}
 catch (_error) {{ const selection = window.getSelection(); const range = document.createRange(); range.selectNodeContents(log); selection.removeAllRanges(); selection.addRange(range); feedback.textContent = "Output selected. Press Ctrl+C or Command+C."; }}
}});
const current = document.getElementById("ci-run-result"); if (!current || current.dataset.active !== "true") return;
let polling = false; const timer = setInterval(async function() {{ if (polling) return; polling = true; try {{
const response = await fetch(window.location.pathname + "?partial=1", {{cache:"no-store", credentials:"same-origin"}});
if (response.redirected || !response.ok) {{ clearInterval(timer); return; }}
const fragment = await response.text(); const node = document.getElementById("ci-run-result");
if (!node) {{ clearInterval(timer); return; }}
const expanded = new Map([...node.querySelectorAll("details[id]")].map(item => [item.id, item.open]));
const positions = new Map([...node.querySelectorAll("[data-ci-scroll]")].map(item => [item.id, item.scrollTop]));
const follow = document.getElementById("ci-follow").checked; const focus = document.activeElement.id;
node.outerHTML = fragment;
const replacement = document.getElementById("ci-run-result");
replacement.querySelectorAll("details[id]").forEach(item => {{ if (expanded.has(item.id)) item.open = expanded.get(item.id); }});
document.getElementById("ci-follow").checked = follow;
replacement.querySelectorAll("[data-ci-scroll]").forEach(item => item.scrollTop = follow ? item.scrollHeight : (positions.get(item.id) || 0));
if (focus) {{ const focused = document.getElementById(focus); if (focused) focused.focus({{preventScroll:true}}); }}
if (document.getElementById("ci-run-result").dataset.active !== "true") clearInterval(timer);
}} catch (_error) {{ /* Retry on the next interval. */ }} finally {{ polling = false; }} }}, 3000); }})();</script>''')
        )
        return await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"CI run #{run[0]} · {owner}/{repo}"),
                safe_html(html_t(t'<main class="ci-page">{body}</main>')),
            ),
        )

    async def _ui_api_docs(self) -> None:
        if not _ip_allowed(self._client_ip(), self._allowlist()):
            return await self._forbidden(b"403 Forbidden: IP not allowed.\n")
        if not await self._require_session_auth():
            return
        from .ci_docs import render_manual

        path = Path(__file__).resolve().parent.parent / "docs" / "api.md"
        try:
            text = await asyncio.to_thread(path.read_text, encoding="utf-8")
            content = render_manual(text, "docs/api.md", "/api/docs")
        except OSError:
            content = safe_html(
                "<p>The full API manual is unavailable in this installation. "
                "Use GET /api/v1/openapi.json with a read-scoped bearer token "
                "for the implemented API contract. Writes require write scope "
                "and an Idempotency-Key header. Tokens are "
                "required even when web authentication is disabled.</p>"
            )
        body = safe_html(
            html_t(
                t'<main class="ci-page"><div class="topbar"><h1>API documentation</h1></div><nav class="row" aria-label="API documentation sections"><a href="#repository-browsing-and-comparisons">Repository browsing</a><a href="#discussions">Discussions</a><a href="#ci-automation">CI automation</a><a href="#ci-api-safety-and-test-coverage">CI safety and tests</a><a href="#responses-pagination-and-errors">Responses and errors</a><a href="#remaining-api-coverage-gaps">Remaining API gaps</a></nav><article class="box ci-guide">{content}</article></main>'
            )
        )
        return await _send_html(self.request, 200, _html_page("API documentation", body))

    async def _ui_ci_docs(self, owner: str, repo: str) -> None:
        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        from .ci_docs import EXAMPLES, GUIDES, manual_content

        query = parse_qs(urlparse(self.path).query)
        guide = (query.get("guide") or ["reference"])[0]
        example = (query.get("example") or [""])[0]
        try:
            content = await _call_in_thread(manual_content, guide, example, base + "/ci/docs")
        except OSError:
            content = ci_configuration_guide()
        if content is None:
            return await self._not_found()
        guide_links = join_html(
            [
                html_t(
                    t'<a class="pill" href="{base}/ci/docs?guide={key}"{safe_html(' aria-current="page"' if key == guide and not example else "")}>{title}</a>'
                )
                for key, (title, _path) in GUIDES.items()
            ]
        )
        example_links = join_html(
            [
                html_t(t'<a class="pill" href="{base}/ci/docs?example={key}">{title}</a>')
                for key, (title, _path) in EXAMPLES.items()
            ]
        )
        body = safe_html(
            html_t(t'''<main class="ci-page">{_ci_tabs(base, "docs")}<div class="topbar"><h2>CI documentation</h2></div>
<section class="box"><h2>Repository CI files</h2>
<ol>
<li>Commit <code>ci/config.json</code> with a simple steps pipeline or a full configuration with named pipelines and deployments. This is the only project configuration entry point. Any referenced pipeline files must also be under <code>ci/</code>; commands run from the checkout root.</li>
<li>Keep credentials out of Git. Add them in <a href="{base}/ci/config">CI → Settings</a>, where repository secrets and environment variables are still managed.</li>
<li>Push the commit, then check <a href="{base}/ci/run">CI → Run pipeline</a>. You can queue a manual run to verify the configuration without deploying.</li>
</ol>
<p>Upgrading from the old editor? Move the saved definitions into <code>ci/config.json</code>; they are not imported automatically. Host jobs and enabled deployments still require administrator authorization.</p>
<nav class="row" aria-label="Repository CI setup"><a href="{base}/ci/docs?guide=start#repository-ci-directory">Directory layout</a><a href="{base}/ci/docs?guide=examples#multiple-git-managed-pipelines">Multiple pipeline files</a><a href="{base}/ci/docs?guide=migration">Migration guide</a><a href="{base}/ci/docs?example=repository-pipeline">Repository pipeline example</a></nav></section>
<nav class="row" aria-label="Documentation sections">{guide_links}</nav><section class="box"><h2>Complete JSON examples</h2><nav class="row" aria-label="Configuration examples">{example_links}</nav></section>
<article id="ci-configuration-guide" class="box ci-guide">{content}</article></main><script src="/static/ci-docs.js" defer></script>''')
        )
        return await _send_html(
            self.request, 200, _html_page(str_t(t"CI documentation · {owner}/{repo}"), body)
        )

    async def _ui_ci_config(
        self,
        owner: str,
        repo: str,
        notice: str = "",
        error: bool = False,
        preferences_submitted: dict[str, str] | None = None,
    ) -> None:
        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        if REQUIRE_AUTH and not _require_admin(self):
            return await self._forbidden(b"403 Forbidden: admin required.\\n")
        config = await self.server.ci_manager.config(owner, repo)
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        from .database import db_ci_preferences_get
        from .settings_pages import preferences_forms

        notice_html = (
            safe_html(
                html_t(t'<div class="{"warn" if error else "ok"}" role="alert">{notice}</div>')
            )
            if notice
            else safe_html("")
        )
        if config.get("_repository_config_invalid"):
            config_warning = safe_html(
                '<p class="warn" role="alert">The repository CI configuration in '
                "<code>ci/config.json</code> is invalid. Fix the file to run pipelines.</p>"
            )
        elif config.get("_repository_config_error"):
            config_warning = safe_html(
                '<p class="warn" role="alert">The repository CI configuration is blocked. '
                "Host and deployment execution require administrator authorization; "
                "check <code>ci/config.json</code> and server policy.</p>"
            )
        else:
            config_warning = safe_html("")
        global_values, repository_values = await _call_in_thread(db_ci_preferences_get, owner, repo)
        raw_config = await _call_in_thread(db_ci_config_get, owner, repo)
        raw_document: dict[str, Any] = json.loads(raw_config) if raw_config else {}
        env = raw_document.get("env", {})
        raw_pipelines = raw_document.get("pipelines", [])
        legacy_pipelines = (
            list(raw_pipelines.values())
            if isinstance(raw_pipelines, dict)
            else raw_pipelines
            if isinstance(raw_pipelines, list)
            else []
        )
        legacy = (
            {
                "env": env,
                "pipeline_env": {
                    str(item["pipeline_id"]): item["env"]
                    for item in legacy_pipelines
                    if isinstance(item, dict)
                    and item.get("pipeline_id")
                    and isinstance(item.get("env"), dict)
                    and item["env"] != env
                },
            }
            if raw_document
            else {}
        )
        preferences = preferences_forms(
            base + "/ci/preferences",
            self._settings_csrf_token(),
            global_values,
            repository_values,
            legacy=legacy,
            pipelines=[item["pipeline_id"] for item in CIManager.pipelines(config)],
            submitted=preferences_submitted,
        )
        body = html_t(t'''{_ci_tabs(base, "settings")}<div class="topbar"><h2>CI settings</h2><nav class="row"><a class="pill" href="/admin/settings">Server defaults</a><a class="pill" href="{base}/ci/docs">JSON reference and examples</a></nav></div>{notice_html}{config_warning}
<section class="box"><h2>Project pipelines</h2><p>Project CI pipeline definitions are read from <code>ci/config.json</code> in the repository. Commit changes to that file; pipelines are not edited on this page. See the <a href="{base}/ci/docs?guide=start">CI quick start</a> or <a href="{base}/ci/docs?guide=migration">migration guide</a>.</p><p class="muted">Environment variables and secrets for this repository remain below. Retention limits come from repository configuration and the <a href="/admin/settings">server defaults</a>.</p><p class="muted">Host or deployment execution additionally requires administrator authorization; repository files cannot grant it.</p></section>
{preferences}<script src="/static/settings-pages.js" defer></script>''')
        return await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"CI settings · {owner}/{repo}"),
                safe_html(
                    html_t(t'<main class="ci-page ci-settings-page">{safe_html(body)}</main>')
                ),
            ),
        )

    async def _ui_ci_config_save(self, owner: str, repo: str) -> None:
        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        if REQUIRE_AUTH and not _require_admin(self):
            return await self._forbidden(b"403 Forbidden: admin required.\n")
        return await _send_text(
            self.request,
            410,
            "CI configuration is repository-owned. Commit project pipeline definitions to "
            "ci/config.json; this settings page only manages environment variables and "
            "secrets.\n",
        )

    async def _ui_ci_run(self, owner: str, repo: str) -> None:
        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\\n")
        form = await self._read_form_urlencoded()
        branch = (form.get("branch") or "").strip()
        commit = (
            await _git_resolve_commit(_repo_bare_path(owner, repo), "refs/heads/" + branch)
            if _safe_branch_name(branch)
            else None
        )
        if not commit:
            return await self._ui_ci_manual(owner, repo, notice="Select a valid branch.")
        if form.get("sha") and form["sha"] != commit:
            return await self._ui_ci_manual(
                owner, repo, branch=branch, notice="Branch changed. Check its configuration again."
            )
        try:
            run_id = await self.server.ci_manager.enqueue(
                owner, repo, "manual", branch, commit, pipeline=form.get("pipeline", "default")
            )
        except ValueError as exc:
            return await self._ui_ci_manual(owner, repo, branch=branch, notice=str(exc))
        if run_id:
            return await _send_redirect(
                self.request, str_t(t"/r/{q(owner)}/{q(repo)}/ci/runs/{run_id}")
            )
        if (await self.server.ci_manager.config(owner, repo, commit, include_secrets=False)).get(
            "_autodetect_repository_config"
        ):
            return await self._ui_ci_manual(
                owner,
                repo,
                branch=branch,
                notice="No run queued. Add ci/config.json to the selected branch to use automatic repository CI.",
            )
        return await self._ui_ci_manual(
            owner,
            repo,
            branch=branch,
            notice="No run queued. Select a runnable pipeline with steps or a repository file.",
        )

    async def _ui_ci_action(self, owner: str, repo: str, run_id: int, action: str) -> None:
        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        if action == "notify" and REQUIRE_AUTH and not _require_admin(self):
            return await self._forbidden(b"403 Forbidden: admin required.\n")
        if not await _call_in_thread(db_ci_run_get, owner, repo, run_id):
            return await self._not_found()
        try:
            if action == "cancel":
                await self.server.ci_manager.cancel(owner, repo, run_id)
            elif action == "notify":
                await self.server.ci_manager.retry_email(owner, repo, run_id)
            else:
                new_run_id = await self.server.ci_manager.rerun(owner, repo, run_id)
                if new_run_id is not None:
                    run_id = new_run_id
        except ValueError as exc:
            return await self._ui_ci(owner, repo, notice=str(exc))
        return await _send_redirect(
            self.request, str_t(t"/r/{q(owner)}/{q(repo)}/ci/runs/{run_id}")
        )

    async def _ui_ci_log(self, owner: str, repo: str, run_id: int) -> None:
        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        run = await _call_in_thread(db_ci_run_get, owner, repo, run_id)
        if not run:
            return await self._not_found()
        return await _send_response(
            self.request,
            200,
            run[5].encode("utf-8"),
            [
                ("Content-Type", "text/plain; charset=utf-8"),
                ("Content-Disposition", f'attachment; filename="ci-{run_id}.log"'),
                ("Cache-Control", "no-store"),
            ],
        )

    async def _ui_artifacts(self, owner: str, repo: str) -> None:
        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        params = parse_qs(urlparse(self.path).query or "")
        cursor = (params.get("before") or [""])[0]
        before = (
            int(cursor) if cursor.isascii() and cursor.isdigit() and len(cursor) <= 18 else None
        )
        from .database import db_ci_artifacts_count

        size = _page_size(params)
        total = await _call_in_thread(db_ci_artifacts_count, owner, repo, before)
        page = _clamp_page(_page_number(params), total, size)
        artifacts = await _call_in_thread(
            db_ci_artifacts_list, owner, repo, before=before, limit=size, offset=(page - 1) * size
        )
        rows: list[str] = []
        for run_id, branch, commit, status, event, created, archive_size, expires in artifacts:
            size_label = (
                f"{archive_size / (1024 * 1024):.1f} MiB"
                if archive_size >= 1024 * 1024
                else f"{archive_size / 1024:.1f} KiB"
            )
            rows.append(
                html_t(t'''<tr><td><a class="ci-artifact-name" href="{base}/ci/runs/{run_id}/artifacts">ci-{run_id}-artifacts.zip</a><div class="muted">{size_label} · Created {created} UTC</div></td>
<td><a href="{base}/ci/runs/{run_id}">Run #{run_id}</a> <span class="ci-status" data-status="{status}">{status.replace("_", " ")}</span><div class="muted">{branch or "—"} · <code>{commit[:8]}</code> · {event.replace("_", " ")}</div></td>
<td><span class="muted">{("Expires " + expires + " UTC") if expires else "Never expires"}</span></td><td><a class="pill" href="{base}/ci/runs/{run_id}/artifacts" aria-label="Download artifacts from run {run_id}">Download ZIP ↓</a></td></tr>''')
            )
        if rows:
            listing = safe_html(
                html_t(
                    t'<div class="ci-table-scroll"><table><thead><tr><th scope="col">Archive</th><th scope="col">Source run</th><th scope="col">Retention</th><th scope="col">Download</th></tr></thead><tbody>{join_html(rows)}</tbody></table></div>'
                )
            )
        else:
            listing = safe_html(
                html_t(
                    t'''<div class="ci-artifacts-empty"><div class="ci-artifact-symbol" aria-hidden="true">↓</div><h2>{"No older artifacts" if before else "No artifacts yet"}</h2><p class="muted">Save build packages, screenshots, or reports from your CI runs.<br>Configure artifact paths in <code>ci/config.json</code> to start collecting downloads.</p><a class="pill" href="{base}/ci/docs">CI documentation</a> <a class="pill" href="{base}/ci">View CI runs</a></div>'''
                )
            )
        pagination = _pagination(
            base + "/artifacts",
            {"before": str(before)} if before is not None else {},
            page,
            page * size < total,
            total=total,
            per_page=size,
        )
        back = (
            safe_html(html_t(t'<a class="pill" href="{base}/artifacts">Newest artifacts</a>'))
            if before
            else safe_html("")
        )
        body = safe_html(
            html_t(t'''<main class="ci-page">{_repo_tabs(base, "artifacts")}<div class="topbar"><div><h2>Artifacts</h2><p class="muted">Build outputs from your CI runs, ready to download.</p></div><a class="pill" href="{base}/ci/docs">CI documentation</a></div>
<section class="box ci-artifacts-panel"><div class="ci-section-heading"><h2>Available downloads</h2><span class="muted">Retention configured in CI settings; count limits also apply</span></div>{listing}<div class="row">{back}{pagination}</div></section></main>''')
        )
        return await _send_html(
            self.request, 200, _html_page(str_t(t"Artifacts · {owner}/{repo}"), body)
        )

    async def _ui_ci_artifact(self, owner: str, repo: str, run_id: int) -> None:
        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        archive = await _call_in_thread(db_ci_artifact_get, owner, repo, run_id, content=True)
        if not isinstance(archive, bytes):
            return await self._not_found()
        return await _send_response(
            self.request,
            200,
            archive,
            [
                ("Content-Type", "application/zip"),
                ("Content-Disposition", f'attachment; filename="ci-{run_id}-artifacts.zip"'),
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
            ],
        )

    # ========================================================
    # UI: Commits, Commit, Tree, Blob
    # ========================================================
    async def _ui_commits(self, owner: str, repo: str, ref: str) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        ref = unquote(ref)
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()
        resolved_ref = await _git_resolve_commit(repo_git, ref)
        if not resolved_ref:
            if (parse_qs(urlparse(self.path).query or "").get("partial") or [""])[0] == "1":
                return await _send_text(self.request, 400, "400 Bad Request: invalid commit ref.\n")
            body = html_t(
                t'<h1>Commits</h1><p>Could not resolve ref: {ref}</p><p><a class="pill" href="/">Back</a></p>'
            )
            return await _send_html(self.request, 400, _html_page("Commits", safe_html(body)))
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query or "")
        try:
            skip = max(0, int((qs.get("skip") or ["0"])[0]))
        except ValueError:
            skip = 0
        size = _page_size(qs, default=50)
        if "page" in qs:
            skip = (_page_number(qs) - 1) * size
        partial = (qs.get("partial") or [""])[0] == "1"
        history_path = _clean_repo_path((qs.get("path") or [""])[0])
        total = await _git_commit_count(repo_git, resolved_ref, history_path)
        if not partial and total is not None:
            skip = (_clamp_page(skip // size + 1, total, size) - 1) * size
        commits = await _git_list_commits(
            repo_git,
            resolved_ref,
            limit=size + 1,
            skip=skip,
            **({"path": history_path} if history_path else {}),
        )
        has_more = len(commits) > size
        commits = commits[:size]
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        groups: dict[str, list[dict[str, str]]] = {}
        for commit in commits:
            try:
                stamp = datetime.fromisoformat(commit["date"])
                commit["date_key"] = stamp.date().isoformat()
                commit["date_label"] = f"{stamp:%b} {stamp.day}, {stamp.year}"
            except ValueError, TypeError:
                commit["date_key"], commit["date_label"] = "unknown", "Unknown date"
            groups.setdefault(commit["date_key"], []).append(commit)
        rows = []
        for day, items in groups.items():
            rows.append(
                html_t(
                    t'<tr class="repo-commit-date" data-date-heading="{day}"><th colspan="4">Commits on {items[0]["date_label"]}</th></tr>'
                )
            )
            for commit in items:
                hsh = commit["hash"]
                rows.append(
                    html_t(
                        t'<tr data-commit-date="{day}"><td><a href="{base}/commit/{q(hsh)}"><code>{hsh[:8]}</code></a></td><td>{commit["subject"]}</td><td>{commit["author_name"]}</td><td><time class="muted" datetime="{commit["date"]}" title="{commit["date"]}">{commit["date"]}</time></td></tr>'
                    )
                )
        if partial:
            payload = json.dumps(
                {"commits": commits, "has_more": has_more, "next_skip": skip + len(commits)}
            )
            return await _send_response(
                self.request,
                200,
                payload.encode("utf-8"),
                [("Content-Type", "application/json; charset=utf-8")],
            )
        rows_html = (
            join_html(rows) if rows else safe_html('<tr><td class="muted">No commits.</td></tr>')
        )
        load_more = (
            safe_html(
                html_t(
                    t'<button id="loadMoreCommits" type="button" data-ref="{resolved_ref}" data-path="{history_path}" data-next-skip="{skip + len(commits)}">Load more commits</button>'
                )
            )
            if has_more
            else safe_html("")
        )
        pagination = _pagination(
            base + "/commits",
            {"ref": resolved_ref, **({"path": history_path} if history_path else {})},
            skip // size + 1,
            has_more,
            total=total,
            per_page=size,
        )
        body = html_t(
            t"""{_repo_tabs(base, "code")}<div class="review-breadcrumb"><a href="{base}">{owner} / {repo}</a> <span>/</span> Commits</div><div class="topbar"><h2>Commits</h2>
</div>
<div class="box"><div class="topbar"><p class="muted">ref: <code>{ref}</code> {history_path}</p>{pagination}</div><table><tbody id="commitRows">{rows_html}</tbody></table>
<div id="loadMoreStatus" class="muted" style="margin-top:10px">{load_more}</div>{pagination}</div>
<script>
(function() {{
    const button = document.getElementById("loadMoreCommits");
    if (!button) return;
    const tbody = document.getElementById("commitRows");
    const status = document.getElementById("loadMoreStatus");
    button.addEventListener("click", async function() {{
        button.disabled = true;
        button.textContent = "Loading…";
        const params = new URLSearchParams({{
            ref: button.dataset.ref,
            skip: button.dataset.nextSkip,
            per_page: "{size}",
            partial: "1"
        }});
        if (button.dataset.path) params.set("path", button.dataset.path);
        try {{
            const response = await fetch("{base}/commits?" + params.toString());
            if (!response.ok) throw new Error("Request failed");
            const page = await response.json();
            for (const commit of page.commits) {{
                let heading = [...tbody.querySelectorAll("[data-date-heading]")].find(item => item.dataset.dateHeading === commit.date_key);
                if (!heading) {{
                    heading = document.createElement("tr"); heading.className = "repo-commit-date";
                    heading.dataset.dateHeading = commit.date_key;
                    const label = document.createElement("th"); label.colSpan = 4;
                    label.textContent = "Commits on " + commit.date_label; heading.appendChild(label); tbody.appendChild(heading);
                }}
                const row = document.createElement("tr");
                row.dataset.commitDate = commit.date_key;
                const hashCell = document.createElement("td");
                const link = document.createElement("a");
                link.href = "{base}/commit/" + encodeURIComponent(commit.hash);
                const hash = document.createElement("code");
                hash.textContent = commit.hash.slice(0, 8);
                link.appendChild(hash);
                hashCell.appendChild(link);
                row.appendChild(hashCell);
                for (const value of [commit.subject, commit.author_name]) {{
                    const cell = document.createElement("td");
                    cell.textContent = value;
                    row.appendChild(cell);
                }}
                const dateCell = document.createElement("td");
                const date = document.createElement("time");
                date.className = "muted";
                date.dateTime = commit.date;
                date.title = commit.date;
                date.textContent = commit.date;
                dateCell.appendChild(date);
                row.appendChild(dateCell);
                let nextHeading = heading.nextElementSibling;
                while (nextHeading && !nextHeading.hasAttribute("data-date-heading")) nextHeading = nextHeading.nextElementSibling;
                tbody.insertBefore(row, nextHeading);
            }}
            button.dataset.nextSkip = page.next_skip;
            if (!page.has_more) {{
                status.remove();
            }} else {{
                button.disabled = false;
                button.textContent = "Load more commits";
            }}
        }} catch (_error) {{
            button.disabled = false;
            button.textContent = "Retry loading commits";
        }}
    }});
}})();
</script>"""
        )
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"Commits · {owner}/{repo}"),
                safe_html(
                    html_t(
                        t'<main class="repo-page review-page review-list review-commits">{safe_html(body)}</main>'
                    )
                ),
            ),
        )

    async def _ui_commit(self, owner: str, repo: str, commitish: str) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        commitish = unquote(commitish)
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return await self._forbidden(b"403 Forbidden\n")
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()
        commit = await _git_resolve_commit(repo_git, commitish)
        if not commit:
            return await self._not_found()
        meta = await _git_commit_meta(repo_git, commit)
        if not meta:
            return await self._not_found()
        files = await _git_commit_name_status(repo_git, commit)
        files, pagination, _page = _paginate_items(files, self.path)
        patch_text, truncated = await _git_commit_patch(repo_git, commit)
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        parent_links: list[str] = []
        for p in [p for p in (meta["parents"] or "").split() if p.strip()]:
            parent_links.append(
                html_t(t'<a class="pill" href="{base}/commit/{q(p)}"><code>{p[:8]}</code></a>')
            )
        parents_html = safe_html("")
        if parent_links:
            parents_html = safe_html(
                html_t(
                    t'<div class="muted" style="margin-top:6px">Parents: {join_html(parent_links)}</div>'
                )
            )
        file_rows: list[str] = []
        for status, path in files:
            if status.startswith("D"):
                file_rows.append(
                    html_t(
                        t'<tr><td style="width:70px"><span class="pill">{status}</span></td><td><code>{path}</code></td></tr>'
                    )
                )
            else:
                href = str_t(t"{base}/blob/{q(commit)}/{q(path, safe='/')}")
                file_rows.append(
                    html_t(
                        t'<tr><td style="width:70px"><span class="pill">{status}</span></td><td><a href="{href}"><code>{path}</code></a></td></tr>'
                    )
                )
        files_html = (
            join_html(file_rows)
            if file_rows
            else safe_html('<tr><td class="muted">No file list.</td></tr>')
        )
        patch_html = _prism_diff_patch_html(patch_text, truncated, "Patch")
        body = html_t(
            t"""{_repo_tabs(base, "code")}<div class="review-breadcrumb"><a href="{base}">{owner} / {repo}</a> <span>/</span> <a href="{base}/commits?ref={q(commit)}">Commits</a> <span>/</span> <code>{commit[:8]}</code></div><div class="topbar"><div><h2>{meta["subject"]}</h2>
<div class="muted">{meta["author_name"]} &lt;{meta["author_email"]}&gt; · {meta["date"]}</div>{parents_html}</div>
<div>{_repo_code_menu(owner, repo, commit)}</div></div>
<nav class="review-section-nav" aria-label="Commit sections"><a href="#commit-files">Files</a><a href="#commit-patch">Changes</a></nav>
<div class="review-layout"><div class="review-main"><div class="box" id="commit-files" style="margin-bottom:14px"><h2 style="margin:0 0 10px 0;font-size:16px">Files</h2><table>{files_html}</table>{pagination}</div>
<div class="box" id="commit-patch"><h2 style="margin:0 0 10px 0;font-size:16px">Patch</h2>{patch_html}</div></div>
<aside class="review-sidebar" aria-label="Commit details"><h3>Commit details</h3><dl><dt>Commit SHA</dt><dd><code>{commit}</code></dd><dt>Author</dt><dd>{meta["author_name"]}</dd><dt>Committed</dt><dd>{meta["date"]}</dd><dt>Parents</dt><dd>{parents_html if parent_links else "Initial commit"}</dd></dl></aside></div>"""
        )
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"Commit {commit[:8]} · {owner}/{repo}"),
                safe_html(
                    html_t(
                        t'<main class="repo-page review-page review-detail">{safe_html(body)}</main>'
                    )
                ),
            ),
        )

    async def _ui_archive(self, owner: str, repo: str) -> None:
        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)) or not os.path.isdir(
            _repo_bare_path(owner, repo)
        ):
            return await self._not_found()
        params = parse_qs(urlparse(self.path).query or "")
        ref = (params.get("ref") or [""])[0]
        if (
            not ref
            or len(ref) > 256
            or ref.startswith("-")
            or any(char in ref for char in "\0\r\n")
        ):
            return await _send_text(self.request, 400, "Select a valid branch, tag, or commit.\n")
        bare = _repo_bare_path(owner, repo)
        commit = await _git_resolve_commit(bare, ref)
        if not commit:
            return await self._not_found()
        name = f"{repo}-{commit[:8]}"
        process = None
        # Spool before sending headers: no partial-success response on failure,
        # and archive size is bounded without loading the ZIP into memory.
        with tempfile.TemporaryFile() as archive:
            try:
                process = await asyncio.create_subprocess_exec(
                    "git",
                    "--git-dir=" + bare,
                    "archive",
                    "--format=zip",
                    "--prefix=" + name + "/",
                    commit,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                size = 0
                assert process.stdout is not None
                async with asyncio.timeout(60):
                    while chunk := await process.stdout.read(65536):
                        size += len(chunk)
                        if size > 256 * 1024 * 1024:
                            return await _send_text(
                                self.request, 413, "Source ZIP exceeds the 256 MiB limit.\n"
                            )
                        archive.write(chunk)
                    await process.wait()
                if process.returncode:
                    return await _send_text(
                        self.request, 500, "Could not create the source archive.\n"
                    )
                archive.seek(0)
                await _send_response(
                    self.request,
                    200,
                    headers=[
                        ("Content-Type", "application/zip"),
                        ("Content-Length", str(size)),
                        ("Content-Disposition", f'attachment; filename="{name}.zip"'),
                        ("Cache-Control", "no-store"),
                        ("X-Content-Type-Options", "nosniff"),
                    ],
                    include_body=False,
                )
                while chunk := archive.read(65536):
                    self.request.writer.write(chunk)
                    await self.request.writer.drain()
            except asyncio.TimeoutError:
                return await _send_text(
                    self.request, 503, "Source archive generation timed out. Try again later.\n"
                )
            except ConnectionResetError, BrokenPipeError:
                raise ClientDisconnected()
            finally:
                if process is not None and process.returncode is None:
                    process.kill()
                    await process.communicate()

    async def _ui_ide(self, owner: str, repo: str, action: str = "") -> None:
        from . import webide

        owner, repo = unquote(owner), unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return await self._not_found()
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")

        async def respond(status: int, value: object) -> None:
            body = json.dumps(value).encode()
            headers = [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Cache-Control", "no-store"),
            ]
            # Branch snapshots and search results are large and downloaded on
            # every IDE load; gzip cuts the file list by roughly 8-10x.
            if (
                len(body) > 16 * 1024
                and "gzip" in (self.headers.get("Accept-Encoding") or "").lower()
            ):
                body = gzip.compress(body, 6)
                headers += [("Content-Encoding", "gzip"), ("Vary", "Accept-Encoding")]
            return await _send_response(self.request, status, body, headers)

        params = parse_qs(urlparse(self.path).query or "")
        branch = (params.get("branch") or [""])[0]
        try:
            if action == "commit":
                length = int(self.headers.get("Content-Length") or 0)
                if not 0 < length <= webide.MAX_REQUEST * 2:
                    return await respond(413, {"error": "Commit request exceeds the size limit."})
                form = await self._read_form_urlencoded()
                if not secrets.compare_digest(
                    form.get("csrf", "").encode(), self._email_csrf_token().encode()
                ):
                    return await respond(
                        403, {"error": "Invalid security token. Reload the editor."}
                    )
                payload = json.loads(form.get("payload", "{}"))
                if not isinstance(payload, dict):
                    raise webide.IDEError("Invalid commit request.")
                branch = payload.get("branch", "")
                # Validate the branch before policy matching.
                await asyncio.to_thread(webide.head, repo_git, branch)

                async def commit_transaction() -> tuple[int, dict[str, str]]:
                    lock = self.server.push_locks.setdefault((owner, repo), asyncio.Lock())
                    async with lock:
                        policy = await self.server.ci_manager.config(owner, repo)
                        if policy["block_direct_pushes"] and protected_branch(policy, branch):
                            return 403, {
                                "error": "Direct commits to this protected branch are blocked. Create a branch and open a pull request."
                            }
                        before = await self.server._branch_refs(owner, repo)
                        base = payload.get("base")
                        changes = payload.get("changes")
                        message = payload.get("message")
                        if (
                            not isinstance(base, str)
                            or not isinstance(changes, dict)
                            or not isinstance(message, str)
                        ):
                            raise webide.IDEError("Invalid commit request.")
                        commit = await asyncio.to_thread(
                            webide.commit_changes,
                            repo_git,
                            branch,
                            base,
                            changes,
                            message,
                            getattr(self, "remote_user", "Browser user"),
                        )
                        result = {"commit": commit}
                        try:
                            await self.server._queue_push_changes(owner, repo, before)
                        except Exception:
                            # The ref was already committed. Never report it as a failed commit.
                            result["warning"] = (
                                "Commit saved, but CI scheduling failed. Check CI runs."
                            )
                        return 200, result

                task = asyncio.create_task(commit_transaction())
                self.server.push_finalizers.add(task)
                task.add_done_callback(self.server.push_finalizers.discard)
                try:
                    status, result = await asyncio.shield(task)
                except asyncio.CancelledError:
                    # Do not release the push lock while its Git thread is still writing.
                    await asyncio.shield(task)
                    raise
                return await respond(status, result)
            if action == "snapshot":
                return await respond(
                    200, await asyncio.to_thread(webide.snapshot, repo_git, branch)
                )
            if action == "tree":
                return await respond(
                    200,
                    await asyncio.to_thread(
                        webide.children,
                        repo_git,
                        branch,
                        (params.get("commit") or [""])[0],
                        (params.get("path") or [""])[0],
                    ),
                )
            if action == "index":
                return await respond(
                    200,
                    await asyncio.to_thread(
                        webide.index, repo_git, branch, (params.get("commit") or [""])[0]
                    ),
                )
            if action == "file":
                content = await asyncio.to_thread(
                    webide.read_file,
                    repo_git,
                    branch,
                    (params.get("commit") or [""])[0],
                    (params.get("path") or [""])[0],
                )
                return await respond(200, {"content": content})
            if action == "search":
                return await respond(
                    200,
                    await asyncio.to_thread(
                        webide.search,
                        repo_git,
                        branch,
                        (params.get("commit") or [""])[0],
                        (params.get("q") or [""])[0],
                    ),
                )
            if action == "conflict":
                pr_id = int((params.get("pr") or ["0"])[0])
                pr = await asyncio.to_thread(db_pr_get, pr_id)
                if not pr or pr[1] != owner or pr[2] != repo or pr[8] != "open":
                    raise webide.IDEError("The pull request is not open.")
                if branch != pr[5]:
                    raise webide.IDEError("Conflict resolution applies to the source branch only.")
                state = await self._ui_pull_resolve_poststate(owner, repo, pr_id)
                if not state:
                    raise webide.IDEError("The pull request state changed. Reload the editor.")
                _src_branch, tgt_branch, src, tgt, merge_base, repo_git_state = state
                webide.path((params.get("path") or [""])[0])
                conflicts = await asyncio.to_thread(
                    pr_resolver.list_conflicts, repo_git_state, merge_base, src, tgt
                )
                item = next(
                    (
                        entry
                        for entry in conflicts
                        if entry["path"] == (params.get("path") or [""])[0]
                    ),
                    None,
                )
                if item is None:
                    raise webide.IDEError(
                        "No conflict information for this path. Reload the editor."
                    )
                text, kind = await asyncio.to_thread(
                    pr_resolver.preview, repo_git_state, item, pr[5], pr[6]
                )
                decoded_content: str | None = None
                if text and kind != "nonmergeable":
                    try:
                        decoded_content = text.decode("utf-8")
                    except UnicodeDecodeError:
                        decoded_content, kind = None, "nonmergeable"
                return await respond(200, {"content": decoded_content, "kind": kind})
            branches = await _git_list_branches(repo_git)
            if not branches:
                return await _send_text(
                    self.request,
                    400,
                    "Create a branch with an initial commit before opening the Web IDE.\n",
                )
            if branch and branch not in branches:
                return await _send_text(
                    self.request,
                    400,
                    "Choose an existing branch to edit. Tags and historical commits are read-only.\n",
                )
            if not branch:
                default_branch = await _git_default_branch(repo_git)
                branch = default_branch if default_branch in branches else branches[0]
            base = str_t(t"/r/{q(owner)}/{q(repo)}")
            filename = (params.get("path") or [""])[0]
            folder = (params.get("folder") or [""])[0]
            single = action == "edit"
            if filename:
                webide.path(filename)
            if folder:
                webide.path(folder)
            if single and not filename:
                raise webide.IDEError("Choose a file to edit from the repository browser.")
            if single:
                await asyncio.to_thread(
                    webide.read_file,
                    repo_git,
                    branch,
                    await asyncio.to_thread(webide.head, repo_git, branch),
                    filename,
                )
            mode = "single" if single else "workspace"
            # The status-bar branch control is a searchable quick pick like the
            # language selector, so every branch is embedded as raw JSON and the
            # client filters it locally.
            branches_json = json.dumps(branches)
            token = self._email_csrf_token()
            return_url = (
                str_t(t"{base}/blob/{q(branch)}/{q(filename, safe='/')}")
                if filename
                else str_t(t"{base}/tree/{q(branch)}/")
            )
            body = html_t(t'''<main class="repo-page webide-page">{_repo_tabs(base, "code")}
<section id="webide" data-base="{base}/ide" data-csrf="{token}" data-mode="{mode}" data-path="{filename}" data-folder="{folder}">
<header class="ide-titlebar"><a id="ide-exit" href="{return_url}" class="ide-back">← Back to repository</a><strong>{owner} / {repo}</strong><span class="ide-mode-label">{"Edit single file" if single else "Web IDE"}</span>
<button id="ide-quick-open" class="ide-workspace-only" type="button" title="Go to file (Ctrl+P / ⌘P)">Go to file… <kbd>Ctrl/⌘ P</kbd></button>
<a id="ide-expand" class="ide-single-only pill" href="{base}/ide?{urlencode({"branch": branch, "path": filename})}">Open in Web IDE</a></header>
<div class="ide-toolbar"><div class="ide-write-tabs"><button id="ide-write" type="button" aria-pressed="true">Write</button><button id="ide-review" type="button" aria-pressed="false">Preview changes</button></div>
<div class="ide-file-tools"><button id="ide-new" class="ide-workspace-only" type="button">+ New file</button><button id="ide-delete" type="button">Delete file</button><button id="ide-discard-file" type="button">Discard file changes</button><button id="ide-show-changes" class="ide-workspace-only" type="button">Review &amp; commit <span id="ide-count">0</span></button></div></div>
<div class="ide-workspace"><nav class="ide-activity ide-workspace-only" aria-label="Workspace views">
<button id="ide-explorer-view" type="button" aria-pressed="true" title="Explorer (Ctrl+Shift+E)"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 3h12v15H8zM4 7v14h12"/></svg><span class="ide-sr-only">Explorer</span></button>
<button id="ide-search-view" type="button" aria-pressed="false" title="Search (Ctrl+Shift+F)"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="10" cy="10" r="6"/><path d="m15 15 6 6"/></svg><span class="ide-sr-only">Search</span></button>
<button id="ide-source-view" type="button" aria-pressed="false" title="Source Control (Ctrl+Shift+G)"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="6" cy="4" r="2"/><circle cx="6" cy="20" r="2"/><circle cx="18" cy="6" r="2"/><path d="M6 6v12m0-6h6a6 6 0 0 0 6-6"/></svg><span class="ide-sr-only">Source Control</span><span id="ide-source-count">0</span></button></nav>
<aside id="ide-sidebar" data-view="explorer"><section class="ide-explorer-pane"><div class="ide-pane-heading"><h2>Explorer</h2><button id="ide-collapse" type="button" title="Collapse all folders">Collapse all folders</button></div><div class="ide-explorer-actions"><button id="ide-explorer-new" type="button">+ New file</button><button id="ide-new-folder" type="button">+ New folder</button></div><label class="ide-sr-only" for="ide-filter">Filter files</label><input id="ide-filter" placeholder="Filter files…" autocomplete="off"><div id="ide-files" role="group" aria-label="Repository files"></div></section>
<section class="ide-search-pane"><div class="ide-pane-heading"><h2>Search</h2></div><form id="ide-search-form"><label for="ide-search-input">Search file contents</label><input id="ide-search-input" maxlength="200" required placeholder="Search workspace…" autocomplete="off"><button type="submit">Search</button></form><p class="ide-note">Literal, case-insensitive search across the branch snapshot and pending edits. Up to 200 matching lines; run again after editing.</p><p id="ide-search-status" class="ide-note" role="status" aria-live="polite"></p><div id="ide-search-results"></div></section>
<section class="ide-source-pane"><div class="ide-pane-heading"><h2>Source Control</h2><span id="ide-change-summary">No changes</span></div>
<form id="ide-commit"><label for="ide-message">Commit message</label><textarea id="ide-message" rows="3" maxlength="4000" required placeholder="Describe your changes" autocomplete="off"></textarea><button id="ide-submit" type="submit">Commit changes</button><a id="ide-cancel" class="ide-single-only" href="{return_url}">Cancel</a></form>
<div class="ide-changes-heading"><h3>Changes</h3><button id="ide-discard" type="button">Discard all</button></div><div id="ide-changes"></div><p class="ide-note">Commits include all pending changes. Only UTF-8 text files up to 1 MiB; up to 100 changed files. Edits stay in this tab until committed or discarded.</p><a class="ide-workspace-only" href="{base}/branches">Create or manage branches</a><a id="ide-pull-request" class="ide-workspace-only" href="{base}/pulls">Create a pull request</a></section></aside>
<section class="ide-editor-pane" aria-label="Code editor"><div id="ide-tabs" class="ide-workspace-only" role="tablist" aria-label="Open files"></div><h2 id="ide-filename">Select a file</h2><div class="ide-editor-container"><div id="ide-editor"></div><div id="ide-empty"><strong>Ready to make a change?</strong><p>Choose a file from Explorer, or press <kbd>Ctrl/⌘ P</kbd> to find one.</p><p>Changes are collected in Source Control before you commit.</p></div></div></section></div>
<footer class="ide-statusbar"><button id="ide-branch" type="button" title="Switch branch" aria-haspopup="listbox" aria-label="Switch branch (currently {branch})" data-branch="{branch}" data-branches="{branches_json}"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="6" cy="4" r="2"/><circle cx="6" cy="20" r="2"/><circle cx="18" cy="6" r="2"/><path d="M6 6v12m0-6h6a6 6 0 0 0 6-6"/></svg><span id="ide-branch-name">{branch}</span><svg class="ide-chevron" viewBox="0 0 12 12" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><path d="m2.5 4.5 3.5 3.5 3.5-3.5"/></svg></button><button id="ide-language" type="button" title="Select language" aria-haspopup="listbox">Plain Text</button><button id="ide-wrap" type="button" title="Toggle word wrap (Alt+Z)" aria-pressed="true">Word wrap</button><p id="ide-status" role="status" aria-live="polite">Loading editor…</p><span id="ide-cursor">UTF-8</span></footer>
<dialog id="ide-picker"><form method="dialog"><div class="ide-pane-heading"><label for="ide-picker-input">Go to file</label><button value="cancel" aria-label="Close picker">×</button></div><input id="ide-picker-input" placeholder="Search files by name…" autocomplete="off"><div id="ide-picker-results"></div></form></dialog>
</section></main>{self._webide_assets()}''')
            return await _send_response(
                self.request,
                200,
                _html_page("Web IDE", safe_html(body)),
                [("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store")],
            )
        except (webide.IDEError, ValueError, TypeError) as exc:
            if action in ("", "edit"):
                body = html_t(
                    t'<main class="repo-page"><h1>Editor unavailable</h1><p class="warn">{str(exc)}</p><a href="/r/{q(owner)}/{q(repo)}">Back to repository</a></main>'
                )
                return await _send_html(
                    self.request, 400, _html_page("Editor unavailable", safe_html(body))
                )
            return await respond(409 if action == "commit" else 400, {"error": str(exc)})

    async def _ui_tree(self, owner: str, repo: str, ref: str, subpath: str) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        ref = unquote(ref)
        if (
            not (_safe_seg(owner) and _safe_seg(repo))
            or not ref
            or ref.startswith("-")
            or "\0" in ref
        ):
            return await self._not_found()
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()
        subpath = _clean_repo_path(subpath)
        commit = await _git_resolve_commit(repo_git, ref)
        if not commit:
            return await self._not_found()
        spec = commit + (":" + subpath if subpath else ":")
        code, out, err = await _run_git(repo_git, ["ls-tree", "-z", spec])
        if code != 0:
            msg = err.decode("utf-8", "replace")
            body = html_t(t'<h1>Tree</h1><pre>{msg}</pre><p><a class="pill" href="/">Back</a></p>')
            return await _send_html(self.request, 400, _html_page("Tree", safe_html(body)))
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        entries: list[tuple[str, str]] = []
        for ln in out.decode("utf-8", "replace").split("\0"):
            # git ls-tree: mode type object\tname
            if "\t" not in ln:
                continue
            meta_part, name = ln.split("\t", 1)
            parts = meta_part.split()
            kind = parts[1] if len(parts) >= 2 else "blob"
            entries.append((kind, name))

        # Show folders first, then files. Keep alphabetical order inside each group.
        entries.sort(key=lambda item: (0 if item[0] == "tree" else 1, item[1].lower()))

        query = parse_qs(urlparse(self.path).query or "")
        query_params = {key: values[0] for key, values in query.items()}
        total = len(entries)
        page = 1
        size = REPO_FILES_PAGE_SIZE
        page_entries = entries
        if total > REPO_FILES_PAGE_SIZE:
            size = _page_size(query, default=REPO_FILES_PAGE_SIZE)
            page = _clamp_page(_page_number(query), total, size)
            page_entries = entries[(page - 1) * size : page * size]

        overview = await repository_overview(
            owner,
            repo,
            repo_git,
            commit,
            page_entries,
            subpath=subpath,
            page=page if total > REPO_FILES_PAGE_SIZE else None,
            page_size=size,
            include_summary=False,
        )
        rows: list[str] = []
        for kind, name in page_entries:
            if kind == "tree":
                newpath = _join_repo_path(subpath, name)
                href = str_t(t"{base}/tree/{q(ref)}/{q(newpath, safe='/')}/")
                icon = TREE_FOLDER_ICON
            else:
                newpath = _join_repo_path(subpath, name)
                href = str_t(t"{base}/blob/{q(ref)}/{q(newpath, safe='/')}")
                icon = TREE_FILE_ICON
            change = overview["entries"].get(name)
            message = (
                safe_html(
                    html_t(
                        t'<a href="{base}/commit/{change["hash"]}" title="{change["subject"]}">{change["subject"]}</a>'
                    )
                )
                if change
                else safe_html('<span class="muted">—</span>')
            )
            changed_at = (
                safe_html(
                    html_t(
                        t'<time datetime="{change["date"]}" title="{change["date"]}">{_relative_time(change["date"])}</time>'
                    )
                )
                if change
                else safe_html("—")
            )
            rows.append(
                html_t(
                    t'<tr><td class="repo-entry-name">{icon}<a class="tree-name" href="{href}">{name}</a></td><td class="repo-entry-message">{message}</td><td class="repo-entry-date muted">{changed_at}</td></tr>'
                )
            )
        up = safe_html("")
        if subpath:
            parent = "/".join(subpath.split("/")[:-1])
            parent_href = (
                str_t(t"{base}/tree/{q(ref)}/{q(parent, safe='/')}/")
                if parent
                else str_t(t"{base}/tree/{q(ref)}/")
            )
            up = safe_html(html_t(t'<p><a class="pill" href="{parent_href}">Up one level</a></p>'))
        rows_html = (
            join_html(rows)
            if rows
            else safe_html('<tr><td colspan="3" class="muted">Empty.</td></tr>')
        )
        list_url = (
            str_t(t"{base}/tree/{q(ref)}/{q(subpath, safe='/')}/")
            if subpath
            else str_t(t"{base}/tree/{q(ref)}/")
        )
        pagination = (
            _pagination(
                list_url, query_params, page, page * size < total, total=total, per_page=size
            )
            if total > REPO_FILES_PAGE_SIZE
            else safe_html("")
        )
        body = html_t(
            t"""{_repo_tabs(base, "code")}<div class="topbar"><div>{_repo_breadcrumbs(owner, repo, ref, subpath)}<p class="muted">ref: <code>{ref}</code></p></div>
<div>{_repo_code_menu(owner, repo, ref, can_edit=_has_write_scope(self) and ref in await _git_list_branches(repo_git), path=subpath)}</div></div>
{up}<div class="box repo-files-panel"><div class="repo-files-scroll"><table><thead><tr><th>Name</th><th>Last commit message</th><th>Last commit date</th></tr></thead><tbody>{rows_html}</tbody></table></div>{pagination}</div>"""
        )
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"Browse · {owner}/{repo}"),
                safe_html(html_t(t'<main class="repo-page">{safe_html(body)}</main>')),
            ),
        )

    async def _ui_blob(self, owner: str, repo: str, ref: str, filepath: str) -> None:
        owner = unquote(owner)
        repo = unquote(repo)
        ref = unquote(ref)
        if (
            not (_safe_seg(owner) and _safe_seg(repo))
            or not ref
            or ref.startswith("-")
            or "\0" in ref
        ):
            return await self._not_found()
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()
        filepath = _clean_repo_path(filepath)
        if not filepath:
            return await self._not_found()
        commit = await _git_resolve_commit(repo_git, ref)
        if not commit or not filepath:
            return await self._not_found()
        spec = commit + ":" + filepath
        code, out, err = await _run_git(repo_git, ["show", spec])
        if code != 0:
            msg = err.decode("utf-8", "replace")
            body = html_t(t'<h1>File</h1><pre>{msg}</pre><p><a class="pill" href="/">Back</a></p>')
            return await _send_html(self.request, 400, _html_page("File", safe_html(body)))
        params = parse_qs(urlparse(self.path).query or "")
        download = (params.get("download") or [""])[0] == "1"
        raw = (params.get("raw") or [""])[0] == "1"
        binary = b"\0" in out
        if download or raw:
            filename = filepath.rsplit("/", 1)[-1]
            disposition = "attachment; filename*=UTF-8''" + q(filename) if download else "inline"
            return await _send_response(
                self.request,
                200,
                out,
                [
                    (
                        "Content-Type",
                        "application/octet-stream"
                        if download or binary
                        else "text/plain; charset=utf-8",
                    ),
                    ("Content-Disposition", disposition),
                    ("X-Content-Type-Options", "nosniff"),
                    ("Content-Security-Policy", "sandbox; default-src 'none'"),
                    ("Cache-Control", "no-store"),
                ],
            )
        text = out.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
        line_count = max(1, text.count("\n") + (0 if text.endswith("\n") else 1))
        highlight_file = not binary and len(out) <= 100 * 1024 and line_count <= 2000
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        back = str_t(t"{base}/tree/{q(ref)}/")
        if "/" in filepath:
            folder = "/".join(filepath.split("/")[:-1])
            back = str_t(t"{base}/tree/{q(ref)}/{q(folder, safe='/')}/")
        file_language = PRISM_LANGUAGE_BY_EXTENSION.get("." + filepath.split(".")[-1], "none")
        lang = file_language if highlight_file else "none"
        file_url = str_t(t"{base}/blob/{q(commit)}/{q(filepath, safe='/')}")
        breadcrumbs = _repo_breadcrumbs(owner, repo, ref, filepath, is_file=True)
        numbers = (
            join_html(
                [
                    html_t(
                        t'<a id="L{index}" href="#L{index}" aria-label="Line {index}">{index}</a>'
                    )
                    for index in range(1, line_count + 1)
                ]
            )
            if not binary
            else safe_html("")
        )
        notice = safe_html("")
        file_view = (
            safe_html(
                html_t(
                    t'<div id="repo-file-horizontal" class="repo-file-horizontal" tabindex="0" role="region" aria-label="Scroll file horizontally" hidden><div></div></div><div id="repo-file-viewport" class="repo-file-code" tabindex="0" role="region" aria-label="Scrollable file contents"><div class="repo-line-numbers" aria-label="Line numbers">{numbers}</div><pre><code id="repo-file-source" class="language-{lang}">{text}</code></pre></div>'
                )
            )
            if not binary
            else safe_html(
                '<div class="repo-empty"><h2>Binary file</h2><p class="muted">This file cannot be displayed as text. Use Download to save the original file.</p></div>'
            )
        )
        copy_button = (
            safe_html('<button id="repo-copy-file" type="button">Copy contents</button>')
            if not binary
            else safe_html("")
        )
        highlight_button = (
            safe_html(
                '<button id="repo-highlight-file" type="button" aria-pressed="false">Highlight syntax</button>'
            )
            if not binary and file_language != "none"
            else safe_html("")
        )
        can_edit_branch = _has_write_scope(self) and ref in await _git_list_branches(repo_git)
        edit_query = urlencode({"branch": ref, "path": filepath})
        edit_single = safe_html("")
        if can_edit_branch and not binary and len(out) <= 1024 * 1024:
            try:
                out.decode("utf-8")
                edit_single = safe_html(
                    html_t(
                        t'<a href="{base}/edit?{edit_query}"><strong>Edit single file</strong><small>Make a quick change to this file.</small></a>'
                    )
                )
            except UnicodeDecodeError:
                pass
        edit_menu = (
            safe_html(
                html_t(
                    t'<details class="repo-edit-menu"><summary>Edit <span aria-hidden="true">▾</span></summary><div>{edit_single}<a href="{base}/ide?{edit_query}"><strong>Open in Web IDE</strong><small>Edit multiple files in a full workspace.</small></a></div></details>'
                )
            )
            if can_edit_branch
            else safe_html("")
        )
        body = html_t(
            t"""{_repo_tabs(base, "code")}<div class="topbar"><div>{breadcrumbs}<p class="muted">{ref} · {len(out):,} bytes</p></div>{_repo_code_menu(owner, repo, ref, can_edit=can_edit_branch, path=filepath, is_file=True)}</div>
<section class="box repo-file-panel"><div class="repo-file-toolbar"><a class="pill" href="{back}">Back to folder</a><div class="repo-file-actions"><a class="pill" href="{file_url}?raw=1">Raw</a><a class="pill" href="{file_url}?download=1">Download</a>{copy_button}{highlight_button}<a class="pill" href="{file_url}">Permalink</a><a class="pill" href="{base}/commits?{urlencode({"ref": commit, "path": filepath})}">History</a>{edit_menu}</div></div><span id="repo-file-feedback" class="muted" role="status" aria-live="polite"></span>{notice}{file_view}
<script>
const fileViewport = document.getElementById("repo-file-viewport");
const horizontalScroll = document.getElementById("repo-file-horizontal");
function updateFileScroll() {{
 if (!fileViewport || !horizontalScroll) return;
 const overflows = fileViewport.scrollWidth > fileViewport.clientWidth;
 horizontalScroll.hidden = !overflows;
 horizontalScroll.style.width = fileViewport.clientWidth + "px";
 horizontalScroll.firstElementChild.style.width = fileViewport.scrollWidth + "px";
 horizontalScroll.scrollLeft = fileViewport.scrollLeft;
}}
if (fileViewport && horizontalScroll) {{
 horizontalScroll.addEventListener("scroll", () => {{ if (fileViewport.scrollLeft !== horizontalScroll.scrollLeft) fileViewport.scrollLeft = horizontalScroll.scrollLeft; }});
 fileViewport.addEventListener("scroll", () => {{ if (horizontalScroll.scrollLeft !== fileViewport.scrollLeft) horizontalScroll.scrollLeft = fileViewport.scrollLeft; }});
 window.addEventListener("resize", updateFileScroll);
 if (window.ResizeObserver) {{ const observer = new ResizeObserver(updateFileScroll); observer.observe(fileViewport); observer.observe(document.getElementById("repo-file-source")); }}
 updateFileScroll();
}}
document.getElementById("repo-copy-file")?.addEventListener("click", async function() {{
 const source = document.getElementById("repo-file-source"); const feedback = document.getElementById("repo-file-feedback");
 try {{ await navigator.clipboard.writeText(source.textContent); feedback.textContent = "Contents copied."; }}
 catch (_error) {{ const range = document.createRange(); range.selectNodeContents(source); const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range); feedback.textContent = "Contents selected. Press Ctrl+C or Command+C to copy."; }}
}});

    window.Prism = window.Prism || {{}};
    window.Prism.manual = true;

    function loadScript(src) {{
        return new Promise((resolve, reject) => {{
            if (document.querySelector(`script[src="${{src}}"]`)) {{
                resolve();
                return;
            }}

            const script = document.createElement("script");
            script.src = src;
            script.async = false;

            script.onload = () => resolve();
            script.onerror = () => {{ script.remove(); reject(new Error(`Failed to load script: ${{src}}`)); }};

            document.head.appendChild(script);
        }});
    }}

    async function loadPrismLanguage(lang) {{
        const base = "/static/assets/prismjs/components";

        await loadScript(`${{base}}/prism-core.min.js`);

        if (lang === "csharp" || lang === "javascript" || lang === "java" || lang === "c" || lang === "cpp") {{
            await loadScript(`${{base}}/prism-clike.min.js`);
        }}

        if (lang && lang !== "none") {{
            await loadScript(`${{base}}/prism-${{lang}}.min.js`);
        }}
    }}

    const highlightButton = document.getElementById("repo-highlight-file");
    const fileSource = document.getElementById("repo-file-source");
    const plainSource = fileSource ? fileSource.textContent : "";
    let isHighlighted = false;
    async function toggleFileHighlight() {{
        if (!highlightButton || highlightButton.disabled) return;
        const feedback = document.getElementById("repo-file-feedback");
        if (isHighlighted) {{
            fileSource.textContent = plainSource;
            fileSource.className = fileSource.parentElement.className = "language-none";
            isHighlighted = false; highlightButton.textContent = "Highlight syntax";
            highlightButton.setAttribute("aria-pressed", "false");
            feedback.textContent = "Highlighting disabled."; updateFileScroll(); return;
        }}
        highlightButton.disabled = true;
        highlightButton.textContent = "Highlighting…";
        feedback.textContent = "Applying syntax highlighting…";
        try {{
            await loadPrismLanguage("{file_language}");
            if (!window.Prism || !Prism.languages["{file_language}"]) throw new Error("Language unavailable");
            await new Promise(resolve => setTimeout(resolve, 0));
            fileSource.className = "language-{file_language}";
            Prism.highlightElement(fileSource);
            isHighlighted = true; highlightButton.textContent = "Disable highlighting";
            highlightButton.setAttribute("aria-pressed", "true");
            feedback.textContent = "Syntax highlighting enabled.";
        }} catch (error) {{
            fileSource.textContent = plainSource;
            fileSource.className = fileSource.parentElement.className = "language-none";
            highlightButton.textContent = "Highlight syntax";
            feedback.textContent = "Could not load highlighting. You can try again; the complete file remains available.";
        }} finally {{
            highlightButton.disabled = false; updateFileScroll();
        }}
    }}
    highlightButton?.addEventListener("click", toggleFileHighlight);
    document.addEventListener("DOMContentLoaded", () => {{
        if ({"true" if not highlight_file else "false"}) {{ updateFileScroll(); return; }}
        toggleFileHighlight();
    }});

</script>
</section>"""
        )
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"{filepath} · {owner}/{repo}"),
                safe_html(html_t(t'<main class="repo-page">{safe_html(body)}</main>')),
                wide=True,
            ),
        )

    # ========================================================
    # Git smart HTTP backend
    # ========================================================
    def _git_request_needs_write(self, path_info: str, query: str) -> bool:
        qs = parse_qs(query or "")
        services = {s for values in qs.values() for s in values}
        return path_info.endswith("/git-receive-pack") or "git-receive-pack" in services

    async def _send_continue_if_needed(self) -> None:
        """Support clients that send: Expect: 100-continue."""
        expect = (self.headers.get("Expect") or "").strip().lower()
        if expect == "100-continue":
            self.request.writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            await self.request.writer.drain()

    async def _read_body_line(self, limit: int = 8192) -> bytes:
        """Read one CRLF/LF terminated line from the already-parsed HTTP body."""
        buf = bytearray()
        while True:
            ch = await self.request.reader.read(1)
            if not ch:
                raise ClientDisconnected()
            buf.extend(ch)
            if len(buf) > limit:
                raise BadRequest("HTTP body line too large")
            if ch == b"\n":
                return bytes(buf)

    async def _pipe_content_length_body_to_stdin(
        self, stdin: asyncio.StreamWriter, content_len: int
    ) -> None:
        remaining = content_len
        while remaining > 0:
            data = await self.request.reader.read(min(READ_CHUNK, remaining))
            if not data:
                raise asyncio.IncompleteReadError(b"", remaining)
            stdin.write(data)
            await stdin.drain()
            remaining -= len(data)

    async def _pipe_chunked_body_to_stdin(self, stdin: asyncio.StreamWriter) -> None:
        """
        Decode HTTP/1.1 Transfer-Encoding: chunked and pass the decoded bytes
        to git-http-backend. CGI programs do not receive raw chunk framing.
        """
        while True:
            line = await self._read_body_line()
            size_part = line.strip().split(b";", 1)[0]
            if not size_part:
                continue

            try:
                chunk_size = int(size_part, 16)
            except ValueError as exc:
                raise BadRequest("Invalid chunk size") from exc

            if chunk_size == 0:
                # Drain optional trailer headers until the blank line.
                while True:
                    trailer = await self._read_body_line()
                    if trailer in (b"\r\n", b"\n"):
                        return

            remaining = chunk_size
            while remaining > 0:
                data = await self.request.reader.read(min(READ_CHUNK, remaining))
                if not data:
                    raise asyncio.IncompleteReadError(b"", remaining)
                stdin.write(data)
                await stdin.drain()
                remaining -= len(data)

            # Each chunk is followed by CRLF.
            crlf = await self.request.reader.readexactly(2)
            if crlf != b"\r\n":
                raise BadRequest("Invalid chunk terminator")

    async def _pipe_request_body_to_stdin(
        self, proc: asyncio.subprocess.Process, content_len: int
    ) -> None:
        if proc.stdin is None:
            return

        try:
            transfer_encoding = (self.headers.get("Transfer-Encoding") or "").lower()
            if "chunked" in transfer_encoding:
                await self._pipe_chunked_body_to_stdin(proc.stdin)
            else:
                await self._pipe_content_length_body_to_stdin(proc.stdin, content_len)
        except (
            asyncio.IncompleteReadError,
            ClientDisconnected,
            ConnectionResetError,
            BrokenPipeError,
            OSError,
        ):
            # Client disconnected or git-http-backend closed stdin early.
            pass
        finally:
            with contextlib.suppress(Exception):
                proc.stdin.close()
            with contextlib.suppress(Exception):
                await proc.stdin.wait_closed()

    async def _handle_git(self) -> None:
        if not self.path.startswith(URL_PREFIX + "/"):
            return await self._not_found()

        parsed = urlparse(self.path)
        path_info = parsed.path[len(URL_PREFIX) :]
        path_info = _map_git_http_path_info(path_info)
        query = parsed.query or ""

        if self._git_request_needs_write(path_info, query) and not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required for git push.\n")

        raw_clen = self.headers.get("Content-Length")
        try:
            clen = int(raw_clen) if raw_clen else 0
        except ValueError:
            return await _send_text(self.request, 400, "400 Bad Request: invalid Content-Length\n")

        transfer_encoding = (self.headers.get("Transfer-Encoding") or "").lower()
        is_chunked = "chunked" in transfer_encoding

        env = os.environ.copy()
        env["GIT_PROJECT_ROOT"] = GIT_PROJECT_ROOT
        env["GIT_HTTP_EXPORT_ALL"] = "1"
        env["REQUEST_METHOD"] = self.command
        env["PATH_INFO"] = path_info
        env["QUERY_STRING"] = query
        env["SCRIPT_NAME"] = URL_PREFIX
        env["REMOTE_ADDR"] = self._client_ip()
        env["SERVER_PROTOCOL"] = self.request_version
        env["SERVER_SOFTWARE"] = "PyGitHTTP-Async/1.0"
        if self.remote_user:
            env["REMOTE_USER"] = self.remote_user

        # CGI receives decoded stdin. Do not forward hop-by-hop HTTP headers,
        # especially Transfer-Encoding: chunked, to git-http-backend.
        skip_headers = {
            "authorization",
            "connection",
            "content-length",
            "content-type",
            "expect",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        }
        for k, v in self.headers.items():
            if k.lower() in skip_headers:
                continue
            env["HTTP_" + k.upper().replace("-", "_")] = v

        ctype = self.headers.get("Content-Type")
        if ctype:
            env["CONTENT_TYPE"] = ctype
        if raw_clen and not is_chunked:
            env["CONTENT_LENGTH"] = str(clen)
        else:
            env.pop("CONTENT_LENGTH", None)

        stderr_target: IO[Any] | int | None = None
        trace_file: BinaryIO | None = None
        body_task: asyncio.Task[None] | None = None
        proc: asyncio.subprocess.Process | None = None
        push_identity: tuple[str, str] | None = None
        push_lock: asyncio.Lock | None = None
        push_lock_acquired = False
        before_refs: dict[str, str] | None = {}
        protection_hooks: tempfile.TemporaryDirectory[str] | None = None
        connected = True
        is_receive_pack_post = self.command == "POST" and path_info.endswith("/git-receive-pack")
        if is_receive_pack_post:
            for candidate_owner, candidate_repo, rel in _scan_repos(GIT_PROJECT_ROOT):
                if path_info.startswith("/" + rel.strip("/") + "/"):
                    push_identity = (candidate_owner, candidate_repo)
                    break
        if push_identity:
            current_task = asyncio.current_task()
            if current_task is not None:
                self.server.push_requests.add(current_task)
        try:
            if push_identity:
                push_lock = self.server.push_locks.setdefault(push_identity, asyncio.Lock())
                await push_lock.acquire()
                push_lock_acquired = True
                before_refs = await self.server._branch_refs(*push_identity)
                policy = await self.server.ci_manager.config(*push_identity)
                if policy.get("_configuration_git_error"):
                    return await _send_text(
                        self.request,
                        503,
                        "503 Service Unavailable: repository CI policy cannot be verified; "
                        "push rejected.\n",
                    )
                if policy["block_direct_pushes"]:
                    bare = _repo_bare_path(*push_identity)
                    _code, hooks_output, _err = await _run_git(
                        bare, ["rev-parse", "--path-format=absolute", "--git-path", "hooks"]
                    )
                    if _code:
                        return await _send_text(
                            self.request, 500, "Cannot resolve receive hooks; push rejected.\n"
                        )
                    original = hooks_output.decode("utf-8").strip()
                    patterns = [
                        line.strip()
                        for line in policy["protected_branches"].splitlines()
                        if line.strip()
                    ]
                    protection_hooks, hooks_path = await _call_in_thread(
                        prepare_hooks, original, patterns
                    )
                    count = int(env.get("GIT_CONFIG_COUNT", "0"))
                    env[f"GIT_CONFIG_KEY_{count}"] = "core.hooksPath"
                    env[f"GIT_CONFIG_VALUE_{count}"] = hooks_path
                    env["GIT_CONFIG_COUNT"] = str(count + 1)
            if TRACE_LOG:
                _ensure_dir(TRACE_LOG)
                trace_file = open(TRACE_LOG, "ab", buffering=0)
                stderr_target = trace_file
            else:
                stderr_target = asyncio.subprocess.DEVNULL

            await self._send_continue_if_needed()

            proc = await asyncio.create_subprocess_exec(
                *_git_backend_command(),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=stderr_target,
                env=env,
                start_new_session=(os.name != "nt"),
            )

            body_task = asyncio.create_task(self._pipe_request_body_to_stdin(proc, clen))

            header_bytes = bytearray()
            assert proc.stdout is not None
            while True:
                b = await proc.stdout.read(1)
                if not b:
                    break
                header_bytes.extend(b)
                if header_bytes.endswith(b"\r\n\r\n") or header_bytes.endswith(b"\n\n"):
                    break

            header_text = header_bytes.decode("iso-8859-1", errors="replace")
            status_code = 200
            reason = "OK"
            extra_headers: list[tuple[str, str]] = []
            for line in header_text.splitlines():
                if not line.strip():
                    continue
                if line.lower().startswith("status:"):
                    try:
                        _, rest = line.split(":", 1)
                        rest = rest.strip()
                        code_str, _, reason_part = rest.partition(" ")
                        status_code = int(code_str)
                        if reason_part:
                            reason = reason_part.strip()
                    except Exception:
                        pass
                elif ":" in line:
                    k, v = line.split(":", 1)
                    if k.strip().lower() not in ("status", "content-length"):
                        extra_headers.append((k.strip(), v.strip()))

            has_conn = any(k.lower() == "connection" for k, _ in extra_headers)
            response_lines = [str_t(t"HTTP/1.1 {status_code} {reason}\r\n")]
            for k, v in extra_headers:
                response_lines.append(str_t(t"{k}: {v}\r\n"))
            if not has_conn:
                response_lines.append("Connection: close\r\n")
            response_lines.append("\r\n")
            self.request.status = status_code
            self.request.response_size = 0
            connected = await self._write_git_response(
                "".join(response_lines).encode("iso-8859-1", "replace")
            )

            while True:
                if connected:
                    chunk = await proc.stdout.read(READ_CHUNK)
                else:
                    chunk = await asyncio.wait_for(proc.stdout.read(READ_CHUNK), timeout=30)
                if not chunk:
                    break
                if connected:
                    connected = await self._write_git_response(chunk)
                    if connected:
                        self.request.response_size += len(chunk)

            if body_task is not None:
                await body_task

            try:
                await asyncio.wait_for(proc.wait(), timeout=30 if not connected else 5)
            except asyncio.TimeoutError:
                if os.name == "nt":
                    proc.kill()
                else:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(proc.pid, signal.SIGKILL)
                await proc.wait()
        finally:
            try:
                if push_identity and push_lock_acquired:
                    if proc is not None and proc.returncode is None:
                        try:
                            active_task = asyncio.current_task()
                            if active_task is not None and active_task.cancelling():
                                if os.name == "nt":
                                    proc.kill()
                                else:
                                    with contextlib.suppress(ProcessLookupError):
                                        os.killpg(proc.pid, signal.SIGKILL)
                                await proc.wait()
                            else:
                                await asyncio.wait_for(
                                    proc.wait(), timeout=30 if not connected else 5
                                )
                        except asyncio.TimeoutError:
                            if os.name == "nt":
                                proc.kill()
                            else:
                                with contextlib.suppress(ProcessLookupError):
                                    os.killpg(proc.pid, signal.SIGKILL)
                            await proc.wait()
                    finalizer = asyncio.create_task(
                        self.server._queue_push_changes(*push_identity, before_refs)
                    )
                    self.server.push_finalizers.add(finalizer)
                    finalizer.add_done_callback(self.server.push_finalizers.discard)
                    try:
                        await asyncio.shield(finalizer)
                    except asyncio.CancelledError:
                        with contextlib.suppress(Exception, asyncio.CancelledError):
                            await asyncio.shield(finalizer)
                        raise
            finally:
                if protection_hooks is not None:
                    protection_hooks.cleanup()
                try:
                    if body_task is not None and not body_task.done():
                        body_task.cancel()
                        with contextlib.suppress(asyncio.CancelledError, Exception):
                            await body_task
                finally:
                    try:
                        if proc is not None and proc.returncode is None:
                            with contextlib.suppress(Exception):
                                proc.kill()
                                await proc.wait()
                    finally:
                        try:
                            if trace_file:
                                with contextlib.suppress(Exception):
                                    trace_file.flush()
                                    trace_file.close()
                        finally:
                            if push_identity:
                                self.server.push_requests.discard(asyncio.current_task())
                            if push_lock and push_lock_acquired:
                                push_lock.release()

    async def _write_git_response(self, data: bytes) -> bool:
        try:
            self.request.writer.write(data)
            await self.request.writer.drain()
            return True
        except ConnectionResetError, BrokenPipeError, OSError:
            return False

    # ========================================================
    # ROUTING
    # ========================================================
    async def do_GET(self) -> None:
        ip = self._client_ip()
        if not _ip_allowed(ip, self._allowlist()):
            return await self._forbidden(b"403 Forbidden: IP not allowed.\n")

        parsed = urlparse(self.path)
        p = parsed.path

        if _is_static_request_path(p):
            if STATIC_REQUIRES_AUTH and not await self._require_session_auth():
                return
            return await self._serve_static()

        if p == FAVICON_URL:
            return await self._serve_favicon()

        if p == LOGIN_PATH:
            cookies = _parse_cookie_header(self.headers.get("Cookie"))
            info = await asyncio.to_thread(db_verify_session, cookies.get(SESSION_COOKIE_NAME))
            if info:
                return await _send_redirect(self.request, "/")
            return await self._ui_login()
        if p == "/logout":
            return await self._ui_logout()

        if self.path.startswith(URL_PREFIX + "/"):
            if not await self._require_auth():
                return
            return await self._handle_git()

        if not await self._require_session_auth():
            return

        if p == "/":
            return await self._ui_home()
        if p == "/tokens":
            return await self._ui_tokens()
        if p == "/admin/users":
            return await self._ui_admin_users()
        if p == "/admin/email":
            return await self._ui_admin_email()
        if p == "/admin/settings":
            return await self._ui_admin_settings()
        m = re.match(r"^/r/([^/]+)/([^/]+)/ide(?:/(snapshot|tree|index|file|search|conflict))?$", p)
        if m:
            return await self._ui_ide(m.group(1), m.group(2), m.group(3) or "")
        m = re.match(r"^/r/([^/]+)/([^/]+)/edit$", p)
        if m:
            return await self._ui_ide(m.group(1), m.group(2), "edit")
        m = re.match(r"^/r/([^/]+)/([^/]+)/ci/config$", p)
        if m:
            return await self._ui_ci_config(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/ci/deployments(?:/(\d+))?$", p)
        if m:
            return await self._ui_deployments(
                m.group(1), m.group(2), int(m.group(3)) if m.group(3) else None
            )
        m = re.match(r"^/r/([^/]+)/([^/]+)/artifacts$", p)
        if m:
            return await self._ui_artifacts(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/archive\.zip$", p)
        if m:
            return await self._ui_archive(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/ci/docs$", p)
        if m:
            return await self._ui_ci_docs(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/ci/run$", p)
        if m:
            return await self._ui_ci_manual(unquote(m.group(1)), unquote(m.group(2)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/ci$", p)
        if m:
            qs = parse_qs(parsed.query or "")
            partial = (qs.get("partial") or [""])[0] == "1"
            return await self._ui_ci(m.group(1), m.group(2), partial=partial)
        m = re.match(r"^/r/([^/]+)/([^/]+)/ci/runs/(\d+)$", p)
        if m:
            qs = parse_qs(parsed.query or "")
            partial = (qs.get("partial") or [""])[0] == "1"
            return await self._ui_ci(m.group(1), m.group(2), int(m.group(3)), partial=partial)
        m = re.match(r"^/r/([^/]+)/([^/]+)/ci/runs/(\d+)/log$", p)
        if m:
            return await self._ui_ci_log(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/ci/runs/(\d+)/artifacts$", p)
        if m:
            return await self._ui_ci_artifact(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)$", p)
        if m:
            return await self._ui_repo(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/branches$", p)
        if m:
            return await self._ui_branches(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/settings$", p)
        if m:
            return await self._ui_repo_settings(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls$", p)
        if m:
            return await self._ui_pulls(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/new$", p)
        if m:
            return await self._ui_pulls_new(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/issues/new$", p)
        if m:
            return await self._ui_issues_new(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/issues$", p)
        if m:
            return await self._ui_issues(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/issues/(\d+)$", p)
        if m:
            return await self._ui_issue_view(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/discussions/new$", p)
        if m:
            return await self._ui_discussions_new(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/discussions$", p)
        if m:
            return await self._ui_discussions(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/discussions/(\d+)$", p)
        if m:
            return await self._ui_discussion_view(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)$", p)
        if m:
            return await self._ui_pull_view(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/resolve$", p)
        if m:
            return await self._ui_pull_resolve(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/resolve/ide$", p)
        if m:
            return await self._ui_pull_resolve_ide(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/commits$", p)
        if m:
            qs = parse_qs(parsed.query or "")
            ref = (qs.get("ref") or ["main"])[0]
            return await self._ui_commits(m.group(1), m.group(2), ref)
        m = re.match(r"^/r/([^/]+)/([^/]+)/commit/([^/]+)$", p)
        if m:
            return await self._ui_commit(m.group(1), m.group(2), m.group(3))
        m = re.match(r"^/r/([^/]+)/([^/]+)/tree/([^/]+)(/.*)?$", p)
        if m:
            subpath = unquote(m.group(4) or "/")
            return await self._ui_tree(m.group(1), m.group(2), m.group(3), subpath)
        m = re.match(r"^/r/([^/]+)/([^/]+)/blob/([^/]+)(/.*)$", p)
        if m:
            filepath = m.group(4) or ""
            return await self._ui_blob(m.group(1), m.group(2), m.group(3), filepath)
        return await self._not_found()

    async def do_POST(self) -> None:
        ip = self._client_ip()
        if not _ip_allowed(ip, self._allowlist()):
            return await self._forbidden(b"403 Forbidden: IP not allowed.\n")

        parsed = urlparse(self.path)
        if parsed.path == LOGIN_PATH:
            return await self._ui_do_login()

        if self.path.startswith(URL_PREFIX + "/"):
            if not await self._require_auth():
                return
            return await self._handle_git()

        if not await self._require_session_auth():
            return

        if parsed.path == "/admin/settings/favicon":
            return await self._ui_favicon_save()

        ctype = (self.headers.get("Content-Type") or "").lower()
        if "application/x-www-form-urlencoded" not in ctype:
            return await _send_text(self.request, 415, "Unsupported Media Type\n")
        m = re.match(r"^/r/([^/]+)/([^/]+)/ide/commit$", parsed.path)
        if m:
            return await self._ui_ide(m.group(1), m.group(2), "commit")
        if parsed.path == "/create-repo":
            return await self._ui_create_repo()
        if parsed.path in ("/tokens/create", "/admin/token"):
            return await self._ui_create_token()
        if parsed.path == "/tokens/revoke":
            return await self._ui_revoke_token()
        if parsed.path == "/admin/users/create":
            return await self._ui_admin_users_create()
        if parsed.path == "/admin/email":
            return await self._ui_admin_email_save()
        if parsed.path == "/admin/settings":
            return await self._ui_admin_settings(save=True)
        if parsed.path == "/admin/email/test":
            return await self._ui_admin_email_save(test=True)
        if parsed.path == "/admin/users/reset":
            return await self._ui_admin_users_reset()
        if parsed.path == "/admin/users/toggle":
            return await self._ui_admin_users_toggle()
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/create$", parsed.path)
        if m:
            return await self._ui_pulls_create(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/issues/create$", parsed.path)
        if m:
            return await self._ui_issues_create(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/issues/(\d+)/comments$", parsed.path)
        if m:
            return await self._ui_issue_comment(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/issues/(\d+)/comments/(\d+)/delete$", parsed.path)
        if m:
            return await self._ui_issue_comment_delete(
                m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
            )
        m = re.match(r"^/r/([^/]+)/([^/]+)/issues/(\d+)/comments/(\d+)/edit$", parsed.path)
        if m:
            return await self._ui_issue_comment_edit(
                m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
            )
        m = re.match(r"^/r/([^/]+)/([^/]+)/issues/(\d+)/close$", parsed.path)
        if m:
            return await self._ui_issue_close(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/issues/(\d+)/reopen$", parsed.path)
        if m:
            return await self._ui_issue_reopen(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/issues/(\d+)/update$", parsed.path)
        if m:
            return await self._ui_issue_update(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/discussions/create$", parsed.path)
        if m:
            return await self._ui_discussions_create(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/comments$", parsed.path)
        if m:
            return await self._ui_discussion_comment(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/comments/(\d+)/delete$", parsed.path)
        if m:
            return await self._ui_discussion_comment_delete(
                m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
            )
        m = re.match(r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/comments/(\d+)/edit$", parsed.path)
        if m:
            return await self._ui_discussion_comment_edit(
                m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
            )
        m = re.match(r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/lock$", parsed.path)
        if m:
            return await self._ui_discussion_lock(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/unlock$", parsed.path)
        if m:
            return await self._ui_discussion_unlock(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/answer/(\d+)$", parsed.path)
        if m:
            return await self._ui_discussion_answer(
                m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
            )
        m = re.match(r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/unanswer/(\d+)$", parsed.path)
        if m:
            return await self._ui_discussion_unanswer(
                m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
            )
        m = re.match(r"^/r/([^/]+)/([^/]+)/discussions/(\d+)/update$", parsed.path)
        if m:
            return await self._ui_discussion_update(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/close$", parsed.path)
        if m:
            return await self._ui_pull_close(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/resolve$", parsed.path)
        if m:
            return await self._ui_pull_resolve_apply(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/resolve/ide/commit$", parsed.path)
        if m:
            return await self._ui_pull_resolve_commit(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/reopen$", parsed.path)
        if m:
            return await self._ui_pull_reopen(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/merge$", parsed.path)
        if m:
            return await self._ui_pull_merge(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/comments$", parsed.path)
        if m:
            return await self._ui_pull_comment(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/comments/(\d+)/delete$", parsed.path)
        if m:
            return await self._ui_pull_comment_delete(
                m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
            )
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/comments/(\d+)/edit$", parsed.path)
        if m:
            return await self._ui_pull_comment_edit(
                m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
            )
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/update$", parsed.path)
        if m:
            return await self._ui_pull_update(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/ci/config$", parsed.path)
        if m:
            return await self._ui_ci_config_save(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/ci/preferences$", parsed.path)
        if m:
            return await self._ui_ci_preferences_save(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/ci/run$", parsed.path)
        if m:
            return await self._ui_ci_run(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/ci/runs/(\d+)/(cancel|rerun|notify)$", parsed.path)
        if m:
            return await self._ui_ci_action(m.group(1), m.group(2), int(m.group(3)), m.group(4))
        m = re.match(r"^/r/([^/]+)/([^/]+)/branches/create$", parsed.path)
        if m:
            return await self._ui_branch_create(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/branches/delete$", parsed.path)
        if m:
            return await self._ui_branch_delete(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/settings/delete$", parsed.path)
        if m:
            return await self._ui_repo_delete(m.group(1), m.group(2))
        return await self._not_found()

    async def do_HEAD(self) -> None:
        ip = self._client_ip()
        if not _ip_allowed(ip, self._allowlist()):
            return await self._forbidden(b"403 Forbidden: IP not allowed.\n")

        parsed = urlparse(self.path)
        if _is_static_request_path(parsed.path):
            if STATIC_REQUIRES_AUTH and not await self._require_session_auth():
                return
            return await self._serve_static(include_body=False)

        if parsed.path == FAVICON_URL:
            return await self._serve_favicon(include_body=False)

        return await _send_text(self.request, 400, "HEAD is only implemented for static files.\n")

    async def dispatch(self) -> None:
        path = urlparse(self.path).path
        if path == "/api" or path.startswith("/api/"):
            if path == "/api/runner/v1" or path.startswith("/api/runner/v1/"):
                from .remote_ci import RunnerAPI

                await RunnerAPI(self).dispatch()
                return
            if path == "/api/docs" and self.command == "GET":
                return await self._ui_api_docs()
            from .api.router import API

            await API(self).dispatch()
            return
        if not _is_static_request_path(path) and not path.startswith(URL_PREFIX + "/"):
            _display_name.set(await self.server.display_name())
            _request_path.set(path)
            _viewer.set((None, False))
        if self.command == "GET":
            return await self.do_GET()
        if self.command == "POST":
            return await self.do_POST()
        if self.command == "HEAD":
            return await self.do_HEAD()
        return await _send_text(self.request, 400, "Unsupported method.\n")


class AsyncGitServer:
    def __init__(
        self,
        context: AppContext | None = None,
        allowlist: set[str] | None = None,
        config_path: str | os.PathLike[str] | None = None,
    ) -> None:
        self.context = context or AppContext(AppConfig.from_mapping(default_config_for_platform()))
        apply_config(self.context.config)
        self.allowlist = allowlist if allowlist is not None else ALLOWED_CLIENT_IPS
        configured_trust_ips = (
            _ci_trust_admin_ips(os.environ.get("PYGITHOST_CI_TRUST_ADMIN_IPS", ""))
            if self.context.config.filter_ips and not self.context.config.require_auth
            else frozenset()
        )
        self.ci_trust_admin_ips = frozenset(
            ip for ip in configured_trust_ips if _ip_allowed(ip, self.allowlist)
        )
        self.ci_manager = CIManager(
            _repo_bare_path,
            allow_page_trust=self.context.config.require_auth or bool(self.ci_trust_admin_ips),
            trust_all_repositories=_ip_filter_trusts_ci_repositories(
                self.context.config, self.allowlist
            ),
        )
        self.push_locks: dict[tuple[str, str], asyncio.Lock] = {}
        self.push_requests: set[asyncio.Task[Any]] = set()
        self.push_finalizers: set[asyncio.Task[Any]] = set()
        self._display_name: str | None = None
        self._display_name_lock = asyncio.Lock()
        self.config_path = Path(config_path).resolve() if config_path is not None else None
        server_config = self.context.config
        self.log_file = configure_logging(
            level=server_config.log_level,
            log_file=server_config.log_file,
            max_bytes=server_config.log_max_bytes,
            backup_count=server_config.log_backup_count,
            log_format=server_config.log_format,
        )
        if self.ci_manager.trust_all_repositories:
            logger.warning(
                "IP-only CI trust enabled for all repositories: host jobs, deployments, and authenticated runners.",
                extra={"event": "ci_ip_trust_all_enabled"},
            )
        elif server_config.ip_trust_all_ci_repositories and not server_config.require_auth:
            logger.warning(
                "IP-only CI trust ignored: enable IP filtering with exact allowed addresses.",
                extra={"event": "ci_ip_trust_all_ignored"},
            )
        self.access_log = bool(server_config.access_log)
        self.audit_log = bool(server_config.audit_log)
        self.settings_lock = asyncio.Lock()
        self.settings_csrf_secret = secrets.token_bytes(32)
        self.email_csrf_token: str | None = None
        from .api.policy import RateLimiter

        self.api_limiter = RateLimiter()
        self.api_slots = asyncio.Semaphore(8)
        self.api_download_slots = asyncio.Semaphore(2)

    async def display_name(self) -> str:
        from .database import db_display_name_get

        if self._display_name is None:
            async with self._display_name_lock:
                if self._display_name is None:
                    self._display_name = await _call_in_thread(db_display_name_get)
        return self._display_name or "pygithost"

    async def _branch_refs(self, owner: str, repo: str) -> dict[str, str] | None:
        code, out, _ = await _run_git(
            _repo_bare_path(owner, repo),
            ["for-each-ref", "--format=%(refname) %(objectname)", "refs/heads"],
        )
        if code:
            return None
        refs: dict[str, str] = {}
        for line in out.decode("ascii", "replace").splitlines():
            ref, _, oid = line.partition(" ")
            if ref.startswith("refs/heads/") and oid:
                refs[ref[len("refs/heads/") :]] = oid
        return refs

    async def _queue_push_changes(
        self, owner: str, repo: str, before_refs: dict[str, str] | None
    ) -> None:
        after_refs = await self._branch_refs(owner, repo)
        if after_refs is None or before_refs is None:
            return
        if after_refs != before_refs:
            try:
                await self.ci_manager.refresh_retention(owner, repo)
            except Exception as exc:
                # The ref update is already accepted. Leave the old cache in
                # place so cleanup stays paused, but still queue its CI runs.
                logger.warning(
                    "CI retention refresh failed; cleanup paused",
                    extra={
                        "event": "ci_retention_refresh_failure",
                        "owner": owner,
                        "repo": repo,
                        "error_type": type(exc).__name__,
                    },
                )
        repo_git = _repo_bare_path(owner, repo)
        for branch, commit in after_refs.items():
            old_commit = before_refs.get(branch)
            if old_commit == commit:
                continue
            await self.ci_manager.enqueue(
                owner, repo, "push", branch, commit, {"old_commit": old_commit or ""}
            )
            for pr_id, target_branch in await asyncio.to_thread(
                db_prs_for_source, owner, repo, branch
            ):
                base_commit = (
                    await _git_resolve_commit(repo_git, "refs/heads/" + target_branch) or ""
                )
                await self.ci_manager.enqueue(
                    owner,
                    repo,
                    "pull_request_updated",
                    target_branch,
                    base_commit,
                    {
                        "pr_number": pr_id,
                        "base_branch": target_branch,
                        "head_branch": branch,
                        "base_commit": base_commit,
                        "head_commit": commit,
                    },
                )
            for pr_id, source_branch in await asyncio.to_thread(
                db_prs_for_target, owner, repo, branch
            ):
                # A source+target update in one push must yield one check per PR.
                if before_refs.get(source_branch) != after_refs.get(source_branch):
                    continue
                head_commit = (
                    await _git_resolve_commit(repo_git, "refs/heads/" + source_branch) or ""
                )
                if head_commit:
                    await self.ci_manager.enqueue(
                        owner,
                        repo,
                        "pull_request_updated",
                        branch,
                        commit,
                        {
                            "pr_number": pr_id,
                            "base_branch": branch,
                            "head_branch": source_branch,
                            "base_commit": commit,
                            "head_commit": head_commit,
                        },
                    )

    async def shutdown(self) -> None:
        pending = tuple(self.push_requests)
        if pending:
            _done, still_pending = await asyncio.wait(pending, timeout=30)
            for task in still_pending:
                task.cancel()
            if still_pending:
                await asyncio.gather(*still_pending, return_exceptions=True)
        finalizers = tuple(self.push_finalizers)
        if finalizers:
            await asyncio.gather(*finalizers, return_exceptions=True)
        await self.ci_manager.stop()

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        started = time.monotonic()
        req: Request | None = None
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else ""
        try:
            req = await _read_http_request(reader, writer)
            handler = GitHTTPHandler(req, self)
            await handler.dispatch()
        except ClientDisconnected:
            # Client connected and closed without sending a full HTTP request,
            # or disconnected while we were sending a response. Ignore it quietly.
            pass
        except BadRequest as e:
            dummy_req = Request("GET", "/", "HTTP/1.1", Headers([]), BodyReader(reader), writer, ip)
            req = req or dummy_req
            with contextlib.suppress(
                ClientDisconnected, ConnectionResetError, BrokenPipeError, OSError
            ):
                await _send_text(dummy_req, 400, str_t(t"400 Bad Request: {e}\n"))
            req.status = dummy_req.status
        except Exception as e:
            dummy_req = Request("GET", "/", "HTTP/1.1", Headers([]), BodyReader(reader), writer, ip)
            req = req or dummy_req
            with contextlib.suppress(
                ClientDisconnected, ConnectionResetError, BrokenPipeError, OSError
            ):
                await _send_text(dummy_req, 500, str_t(t"500 Internal Server Error: {e}\n"))
            req.status = dummy_req.status
            # Never log exception text here: it can include request data.  The
            # type plus the access record is enough to locate the request.
            logger.error(
                "Unhandled request failure",
                extra={
                    "event": "request_failure",
                    "error_type": type(e).__name__,
                    "method": req.method,
                    "path": safe_target(req.target),
                    "ip": ip,
                    "request_id": req.request_id,
                },
            )
            logger.debug("Unhandled request traceback", exc_info=True)
        finally:
            if self.access_log:
                log_access(
                    method=req.method if req else "?",
                    target=req.target if req else "/",
                    status=req.status if req else None,
                    duration_ms=(time.monotonic() - started) * 1000,
                    ip=ip,
                    user=req.remote_user if req else None,
                    size=req.response_size if req else None,
                    protocol=req.version if req else "HTTP/1.1",
                    request_id=req.request_id if req else None,
                    level=logging.DEBUG if (req is not None and req.status is None) else None,
                )
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()


async def main_async(config_path: str | os.PathLike[str]) -> None:
    try:
        config = AppConfig.from_file(config_path)
        apply_config(config)
    except Exception as exc:
        print(str_t(t"ERROR: Could not load config file '{config_path}': {exc}"), file=sys.stderr)
        sys.exit(1)

    if _git_backend_uses_fallback():
        if shutil.which("git") is None:
            print(
                str_t(
                    t"ERROR: GIT_HTTP_BACKEND not found ('{GIT_HTTP_BACKEND}') and no `git` "
                    t"executable is on PATH for the built-in Python backend."
                ),
                file=sys.stderr,
            )
            sys.exit(1)
        print(
            str_t(
                t"WARNING: GIT_HTTP_BACKEND not found ('{GIT_HTTP_BACKEND}'); "
                t"using the built-in Python Git HTTP backend."
            ),
            file=sys.stderr,
        )
    if not os.path.isdir(GIT_PROJECT_ROOT):
        print(str_t(t"ERROR: GIT_PROJECT_ROOT does not exist: {GIT_PROJECT_ROOT}"), file=sys.stderr)
        sys.exit(1)

    await asyncio.to_thread(_db_init)
    await asyncio.to_thread(db_ensure_default_admin)
    await asyncio.to_thread(os.makedirs, STATIC_ROOT, exist_ok=True)

    os.environ["GIT_PROJECT_ROOT"] = GIT_PROJECT_ROOT
    os.environ["GIT_HTTP_EXPORT_ALL"] = "1"

    try:
        app = AsyncGitServer(AppContext(config), config_path=config_path)
    except (OSError, ValueError) as exc:
        print(f"ERROR: could not configure logging: {exc}", file=sys.stderr)
        sys.exit(1)

    server: asyncio.Server | None = None
    try:
        await app.ci_manager.start()
        server = await asyncio.start_server(app.handle_client, HOST, PORT)
    except BaseException:
        await app.shutdown()
        raise
    assert server is not None

    print("=" * 60)
    print(str_t(t"Async Git Smart HTTP + Web UI running on port {PORT}"))
    print(str_t(t"Loaded config: {Path(config_path).expanduser()}"))
    print(str_t(t"Platform config: {CURRENT_PLATFORM}"))
    print(str_t(t"Git URL prefix: {URL_PREFIX}"))
    print(str_t(t"UI: http://localhost:{PORT}/"))
    print(str_t(t"GIT_PROJECT_ROOT: {GIT_PROJECT_ROOT}"))
    print(str_t(t"DB: {DB_PATH}"))
    print(str_t(t"Static files: {STATIC_ROOT} -> {STATIC_URL_PREFIX}/"))
    print("Web UI auth: /login uses username/password + secure HttpOnly session cookie")
    print("Git auth: accepts username:password, username:token, or token:TOKEN_VALUE")
    print("Admin users page: /admin/users")
    print("Tokens page: /tokens")
    print("Pull requests: /r/<owner>/<repo>/pulls (ff-only merge)")
    print("=" * 60)
    logger.info(
        "Server started",
        extra={
            "event": "server_start",
            "port": PORT,
            "platform": CURRENT_PLATFORM,
            "path": URL_PREFIX,
            "delivery": app.log_file or "stderr",
        },
    )

    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error(
            "Server stopped unexpectedly",
            extra={"event": "server_error", "error_type": type(exc).__name__},
        )
        raise
    finally:
        await app.shutdown()
        logger.info("Server stopped", extra={"event": "server_stop", "port": PORT})


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pygithost",
        description="Async Git Smart HTTP + Web UI server.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser(
        "run", help="Run the Git HTTP server using a JSON config file."
    )
    run_parser.add_argument(
        "--config",
        default=str(_default_config_path()),
        help=str_t(t"Path to the JSON config file. Default: {_default_config_path()}"),
    )

    generate_parser = subparsers.add_parser(
        "generate-config", help="Generate a platform-dependent JSON config file."
    )
    generate_parser.add_argument(
        "--config",
        default=str(_default_config_path()),
        help=str_t(
            t"Path where the JSON config file will be written. Default: {_default_config_path()}"
        ),
    )
    generate_parser.add_argument(
        "--platform",
        choices=["Windows", "Linux", "Darwin"],
        default=platform.system(),
        help="Platform defaults to generate. Defaults to the current platform.",
    )
    generate_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite the config file if it already exists.",
    )
    generate_parser.add_argument(
        "--print",
        dest="print_only",
        action="store_true",
        help="Print the generated config to stdout instead of writing a file.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "generate-config":
        try:
            if args.print_only:
                print(json.dumps(default_config_for_platform(args.platform), indent=4))
            else:
                config_path = write_config_file(
                    args.config, target_platform=args.platform, overwrite=args.overwrite
                )
                print(str_t(t"Config file generated: {config_path}"))
        except Exception as exc:
            print(str_t(t"ERROR: {exc}"), file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "run":
        config_path = Path(args.config).expanduser()
        if not config_path.is_file():
            print(str_t(t"ERROR: Config file not found: {config_path}"), file=sys.stderr)
            print(
                str_t(
                    t"Create one first with: {Path(sys.argv[0]).name} generate-config --config {config_path}"
                ),
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            asyncio.run(main_async(config_path))
        except KeyboardInterrupt:
            pass
        return

    parser.error("Unknown command.")


if __name__ == "__main__":
    main()
