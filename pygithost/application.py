import argparse
import asyncio
import json
import base64
import contextlib
import ipaddress
import mimetypes
import os
import platform
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from email.utils import formatdate
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from hl_mappings import PRISM_LANGUAGE_BY_EXTENSION
from .config import AppConfig
from .context import AppContext
from .database import (
    _db_init,
    _ensure_dir,
    configure as configure_database,
    db_create_session,
    db_create_token,
    db_create_user,
    db_ensure_default_admin,
    db_get_user_by_id,
    db_list_tokens_for_user,
    db_list_users,
    db_pr_close,
    db_pr_create,
    db_pr_get,
    db_pr_list,
    db_pr_mark_merged,
    db_reset_password,
    db_revoke_session,
    db_revoke_token,
    db_set_user_active,
    db_verify_password,
    db_verify_session,
    db_verify_token,
    db_verify_token_any_user,
)
from .rendering import SafeHTML, html_t, join_html, q, safe_html, str_t

# ============================================================
# CONFIG
# ============================================================
CONFIG_SCHEMA_VERSION = 1
DEFAULT_CONFIG_FILENAME = "pygithost.config.json"
CURRENT_PLATFORM = platform.system()


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

    ALLOWED_CLIENT_IPS = set(str(ip) for ip in config.get("allowed_client_ips", []))
    configure_database(config_model)


def write_config_file(path: str | os.PathLike[str], target_platform: str | None = None, overwrite: bool = False) -> Path:
    return AppConfig.default_for_platform(target_platform).write(path, overwrite=overwrite)


# Initialize module globals with platform defaults. The CLI `run` command replaces
# these values with the JSON file values before the server starts.
apply_config(default_config_for_platform())

TREE_FOLDER_ICON = safe_html(
    """<span class="tree-icon folder" aria-hidden="true">
<svg viewBox="0 0 24 24" focusable="false">
<path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h4.2l2 2.2h6.8A2.5 2.5 0 0 1 21 9.7v7.8A2.5 2.5 0 0 1 18.5 20h-13A2.5 2.5 0 0 1 3 17.5v-10Z"></path>
<path d="M3.2 9h17.6"></path>
</svg>
</span>"""
)

TREE_FILE_ICON = safe_html(
    """<span class="tree-icon file" aria-hidden="true">
<svg viewBox="0 0 24 24" focusable="false">
<path d="M6 3.5h8l4 4V20a1.5 1.5 0 0 1-1.5 1.5h-9A1.5 1.5 0 0 1 6 20V3.5Z"></path>
<path d="M14 3.5v4h4"></path>
<path d="M8.5 12h7"></path>
<path d="M8.5 15.5h7"></path>
</svg>
</span>"""
)


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
    return bool(s) and SAFE_SEG.match(s) is not None and ".." not in s and "/" not in s and "\\" not in s


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
        ok = (
            ("a" <= ch <= "z")
            or ("A" <= ch <= "Z")
            or ("0" <= ch <= "9")
            or ch in "._-/"
        )
        if not ok:
            return False
    return True


def _has_write_scope(handler: object) -> bool:
    # When authentication is disabled, IP allowlist becomes the security boundary.
    # The request has already passed ALLOWED_CLIENT_IPS in do_GET/do_POST before
    # this function is reached, so Git push/write operations should be allowed.
    if not REQUIRE_AUTH:
        return True

    scopes = getattr(handler, "remote_scopes", set()) or set()
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
            repo_dirs = sorted([x for x in owner_dir.iterdir() if x.is_dir()], key=lambda x: x.name.lower())
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


def _repo_bare_path(owner_ui: str, repo: str) -> str:
    """
    Backward-compatible name used by the rest of the code.

    It now returns the real Git directory, which can be:
      - repo.git for a bare repo with the .git suffix
      - repo for a bare repo without the .git suffix
      - repo/.git for a normal/non-bare repo
    """
    return _repo_git_path(owner_ui, repo)


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
    code, out, _ = await _run_git(repo_git, ["for-each-ref", "refs/heads", "--format=%(refname:short)"])
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
    code, _out, err = await _run_git(repo_git, ["update-ref", "refs/heads/" + new_branch, commit])
    if code != 0:
        return False, err.decode("utf-8", "replace").strip() or "git update-ref failed."
    return True, "Branch created."


async def _git_delete_branch(repo_git: str, branch: str) -> tuple[bool, str]:
    code, _out, err = await _run_git(repo_git, ["update-ref", "-d", "refs/heads/" + branch])
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


async def _git_commit_patch(repo_git: str, commit: str, max_bytes: int = 600_000) -> tuple[str, bool]:
    code, out, _ = await _run_git(repo_git, ["show", "--no-color", "--format=", commit])
    if code != 0:
        return "Could not render patch.", False
    if len(out) > max_bytes:
        return out[:max_bytes].decode("utf-8", "replace") + "\n\n[... truncated ...]\n", True
    return out.decode("utf-8", "replace"), False


async def _git_is_ancestor(repo_git: str, maybe_ancestor: str, maybe_descendant: str) -> bool:
    code, _out, _err = await _run_git(repo_git, ["merge-base", "--is-ancestor", maybe_ancestor, maybe_descendant])
    return code == 0


async def _git_list_commits(repo_git: str, rev_range: str, limit: int = 100) -> list[dict[str, str]]:
    fmt = "%H%x00%an%x00%ae%x00%ad%x00%s"
    code, out, _err = await _run_git(repo_git, ["log", "--date=iso", "--format=" + fmt, "-n" + str(limit), rev_range])
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


async def _git_diff_between(repo_git: str, base: str, head: str, max_bytes: int = PR_PATCH_MAX_BYTES) -> tuple[str, bool]:
    code, out, err = await _run_git(repo_git, ["diff", "--no-color", base + ".." + head])
    if code != 0:
        return err.decode("utf-8", "replace") or "Could not render diff.", False
    if len(out) > max_bytes:
        return out[:max_bytes].decode("utf-8", "replace") + "\n\n[... truncated ...]\n", True
    return out.decode("utf-8", "replace"), False


async def _git_ff_merge(repo_git: str, target_branch: str, source_branch: str) -> tuple[bool, str, str | None]:
    tgt_ref = "refs/heads/" + target_branch
    src_ref = "refs/heads/" + source_branch

    tgt = await _git_resolve_commit(repo_git, tgt_ref)
    src = await _git_resolve_commit(repo_git, src_ref)
    if not tgt:
        return False, str_t(t"Target branch '{target_branch}' not found."), None
    if not src:
        return False, str_t(t"Source branch '{source_branch}' not found."), None

    if tgt == src:
        return True, "Already up to date.", tgt

    if not await _git_is_ancestor(repo_git, tgt, src):
        return False, "Non fast-forward merge required (this server supports ff-only merges).", None

    code, _out, err = await _run_git(repo_git, ["update-ref", tgt_ref, src])
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


def _html_page(title: str, body_html: str | SafeHTML, *, wide: bool = False) -> bytes:
    body = safe_html(body_html)
    body_class = "wide-page" if wide else ""
    rendered = html_t(
        t"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root{{
  color-scheme:light;
  --bg:#ffffff;
  --fg:#111827;
  --muted:#666666;
  --link:#0f4c81;
  --border:#eeeeee;
  --border-strong:#dddddd;
  --box:#ffffff;
  --pre-bg:#fafafa;
  --input-bg:#ffffff;
  --input-fg:#111827;
  --button-bg:#111111;
  --button-fg:#ffffff;
  --pill-bg:#ffffff;
  --pill-fg:#444444;
  --warn-bg:#fff7ed;
  --warn-border:#fed7aa;
  --warn-fg:#9a3412;
  --ok-bg:#ecfdf5;
  --ok-border:#a7f3d0;
  --ok-fg:#065f46;
}}
html[data-theme="dark"]{{
  color-scheme:dark;
  --bg:#0b1220;
  --fg:#e5e7eb;
  --muted:#9ca3af;
  --link:#93c5fd;
  --border:#1f2937;
  --border-strong:#374151;
  --box:#111827;
  --pre-bg:#030712;
  --input-bg:#0f172a;
  --input-fg:#e5e7eb;
  --button-bg:#e5e7eb;
  --button-fg:#111827;
  --pill-bg:#0f172a;
  --pill-fg:#e5e7eb;
  --warn-bg:#431407;
  --warn-border:#9a3412;
  --warn-fg:#fed7aa;
  --ok-bg:#052e16;
  --ok-border:#047857;
  --ok-fg:#a7f3d0;
}}
*{{box-sizing:border-box}}
body{{font-family:system-ui,Segoe UI,Arial;margin:24px;max-width:1200px;background:var(--bg);color:var(--fg)}}
body.wide-page{{max-width:none}}
a{{text-decoration:none;color:var(--link)}} a:hover{{text-decoration:underline}}
code,pre{{font-family:ui-monospace,Consolas,monospace}}
pre{{padding:12px;border:1px solid var(--border-strong);border-radius:10px;overflow:auto;background:var(--pre-bg);color:var(--fg)}}
table{{border-collapse:collapse;width:100%}}
td{{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}}
.muted{{color:var(--muted)}}
.pill{{display:inline-block;padding:2px 10px;border:1px solid var(--border-strong);border-radius:999px;font-size:12px;color:var(--pill-fg);background:var(--pill-bg)}}
.topbar{{display:flex;gap:12px;align-items:center;justify-content:space-between;margin-bottom:16px}}
.box{{border:1px solid var(--border);border-radius:14px;padding:14px;background:var(--box)}}
.row{{display:flex;gap:10px;flex-wrap:wrap;align-items:end}}
label{{display:block;font-size:12px;color:var(--muted);margin-bottom:4px}}
input,select,textarea{{padding:10px;border:1px solid var(--border-strong);border-radius:10px;font-size:14px;background:var(--input-bg);color:var(--input-fg)}}
textarea{{width:100%;min-height:90px}}
button{{padding:10px 14px;border:1px solid var(--button-bg);border-radius:10px;background:var(--button-bg);color:var(--button-fg);cursor:pointer}}
button:hover{{opacity:.92}}
.danger{{border-color:#7f1d1d;background:#7f1d1d;color:#ffffff}}
.danger:hover{{opacity:.92}}
.warn{{background:var(--warn-bg);border:1px solid var(--warn-border);color:var(--warn-fg);padding:10px;border-radius:12px}}
.ok{{background:var(--ok-bg);border:1px solid var(--ok-border);color:var(--ok-fg);padding:10px;border-radius:12px}}
.theme-toggle{{position:fixed;right:18px;bottom:18px;z-index:9999;border-radius:999px;box-shadow:0 10px 30px rgba(0,0,0,.18)}}
.tree-icon{{display:inline-flex;width:22px;height:22px;align-items:center;justify-content:center;vertical-align:-6px;color:var(--muted)}}
.tree-icon svg{{display:block;width:19px;height:19px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}}
.tree-icon.folder{{color:#d97706}}
.tree-icon.file{{color:var(--muted)}}
.tree-name{{padding-left:2px}}
@media (max-width:700px){{body{{margin:14px}}.topbar{{align-items:flex-start;flex-direction:column}}.theme-toggle{{right:12px;bottom:12px}}}}
</style>
<script>
(function() {{
    const saved = localStorage.getItem("pygithost_theme");
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    const theme = saved || (prefersDark ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", theme);
}})();
</script>
<link rel="stylesheet" href="/static/assets/prismjs/prism-okaidia.min.css" />
</head>
<body class="{body_class}">
<button id="theme-toggle" class="theme-toggle" type="button" title="Toggle dark mode">Dark mode</button>

{body}

<script src="/static/assets/prismjs/prism.js"></script>
<script>
(function() {{
    const button = document.getElementById("theme-toggle");
    if (!button) return;

    function updateButton() {{
        const theme = document.documentElement.getAttribute("data-theme") || "light";
        button.textContent = theme === "dark" ? "Light mode" : "Dark mode";
        button.setAttribute("aria-label", theme === "dark" ? "Switch to light mode" : "Switch to dark mode");
    }}

    button.addEventListener("click", function() {{
        const current = document.documentElement.getAttribute("data-theme") || "light";
        const next = current === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", next);
        localStorage.setItem("pygithost_theme", next);
        updateButton();
    }});

    updateButton();
}})();
</script>
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
    can_highlight = bool((text or "").strip()) and not truncated and patch_bytes <= PRISM_DIFF_HIGHLIGHT_MAX_BYTES

    notes: list[str] = []
    if truncated:
        notes.append(html_t(t"""<div class="warn" style="margin-bottom:12px">{truncated_label} truncated because it is too large.</div>"""))
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
    415: "Unsupported Media Type",
    500: "Internal Server Error",
}


class Headers:
    def __init__(self, pairs: list[tuple[str, str]]):
        self._pairs = pairs
        self._map: dict[str, list[str]] = {}
        for k, v in pairs:
            self._map.setdefault(k.lower(), []).append(v)

    def get(self, name: str, default: str | None = None) -> str | None:
        vals = self._map.get(name.lower())
        if not vals:
            return default
        return vals[-1]

    def items(self):
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
    return Request(method=method.upper(), target=target, version=version, headers=Headers(pairs), reader=BodyReader(reader, rest), writer=writer, peer_ip=ip)


async def _send_response(req: Request, status: int, body: bytes = b"", headers: list[tuple[str, str]] | None = None, reason: str | None = None, include_body: bool = True) -> None:
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
    except (ConnectionResetError, BrokenPipeError, OSError):
        # The client closed the TCP connection before we could send the response.
        # This commonly happens with browser preconnects, health checks, aborted Git
        # clients, and port scanners. It is not a server error.
        req.writer.close()
        raise ClientDisconnected()


async def _send_html(req: Request, status: int, body: bytes) -> None:
    await _send_response(req, status, body, [("Content-Type", "text/html; charset=utf-8")])


async def _send_text(req: Request, status: int, text: str) -> None:
    await _send_response(req, status, text.encode("utf-8", "replace"), [("Content-Type", "text/plain; charset=utf-8")])


async def _send_redirect(req: Request, location: str, headers: list[tuple[str, str]] | None = None) -> None:
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
    text_like = (
        lower_type.startswith("text/")
        or lower_type in {
            "application/javascript",
            "application/json",
            "application/xml",
            "image/svg+xml",
        }
    )
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

    def _apply_auth_info(self, info: dict[str, object]) -> None:
        self.remote_user = str(info["username"])
        self.remote_user_id = int(info["user_id"])
        self.remote_is_admin = bool(info.get("is_admin"))
        self.remote_scopes = set(info.get("scopes", {"read"}))
        self.request.remote_user = self.remote_user
        self.request.remote_user_id = self.remote_user_id
        self.request.remote_is_admin = self.remote_is_admin
        self.request.remote_scopes = self.remote_scopes

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

    async def _ui_login(self, notice: str = "", notice_kind: str = "warn"):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query or "")
        next_url = _safe_next_url((qs.get("next") or ["/"])[0])
        if not notice and (qs.get("loggedout") or [""])[0] == "1":
            notice = "You have been logged out."
            notice_kind = "ok"

        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(html_t(t"<div class=\"{cls}\" style=\"margin-bottom:12px\">{notice}</div>"))

        body = html_t(
            t"""<div style="max-width:440px;margin:80px auto">
<div class="box">
<h1 style="margin:0 0 6px 0">Sign in</h1>
<p class="muted" style="margin-top:0">Use your server username and password to manage repositories, branches, PRs, and tokens.</p>
{notice_html}
<form method="POST" action="/login">
<input type="hidden" name="next" value="{next_url}" />
<div style="margin-bottom:10px"><label>Username</label><input name="username" autocomplete="username" autofocus required style="width:100%;box-sizing:border-box" /></div>
<div style="margin-bottom:14px"><label>Password</label><input name="password" type="password" autocomplete="current-password" required style="width:100%;box-sizing:border-box" /></div>
<button type="submit" style="width:100%">Sign in</button>
</form>
<p class="muted" style="font-size:12px;margin-bottom:0">Git clients should continue to use <code>username:token</code> or <code>token:TOKEN_VALUE</code> against <code>{URL_PREFIX}</code>.</p>
</div>
</div>"""
        )
        await _send_html(self.request, 200, _html_page("Sign in", safe_html(body)))

    async def _ui_do_login(self):
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "application/x-www-form-urlencoded" not in ctype:
            return await _send_text(self.request, 415, "Unsupported Media Type\n")

        form = await self._read_form_urlencoded()
        username = (form.get("username") or "").strip()
        password = form.get("password") or ""
        next_url = _safe_next_url(form.get("next") or "/")

        if not _safe_seg(username):
            return await self._ui_login("Invalid username or password.", "warn")

        info = await asyncio.to_thread(db_verify_password, username, password)
        if not info:
            return await self._ui_login("Invalid username or password.", "warn")

        session_token = await asyncio.to_thread(
            db_create_session,
            int(info["user_id"]),
            self._client_ip(),
            self.headers.get("User-Agent") or "",
        )
        self._apply_auth_info(info)
        await _send_redirect(
            self.request,
            next_url,
            [("Set-Cookie", _session_cookie_header(session_token))],
        )

    async def _ui_logout(self):
        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        await asyncio.to_thread(db_revoke_session, cookies.get(SESSION_COOKIE_NAME))
        await _send_redirect(
            self.request,
            str_t(t"{LOGIN_PATH}?loggedout=1"),
            [("Set-Cookie", _delete_session_cookie_header())],
        )

    async def _forbidden(self, msg: bytes = b"403 Forbidden\n"):
        await _send_text(self.request, 403, msg.decode("utf-8", "replace"))

    async def _not_found(self):
        await _send_text(self.request, 404, "404 Not Found\n")

    async def _serve_static(self, include_body: bool = True):
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

        return await _send_response(self.request, 200, body, _static_headers(static_path), include_body=include_body)

    async def _read_form_urlencoded(self) -> dict[str, str]:
        clen = int(self.headers.get("Content-Length") or 0)
        if clen <= 0:
            return {}
        raw = await self.request.reader.readexactly(clen)
        text = raw.decode("utf-8", "replace")
        qs = parse_qs(text, keep_blank_values=True)
        return {k: (v[0] if v else "") for k, v in qs.items()}

    # ========================================================
    # UI: Home / Tokens / Create Repo
    # ========================================================
    async def _ui_home(self, notice: str = "", notice_kind: str = "ok"):
        repos = _scan_repos(GIT_PROJECT_ROOT)

        rows = []
        for owner, repo, rel in repos:
            rows.append(
                html_t(t"""<tr>
<td><a href="/r/{owner}/{repo}">{owner}/{repo}</a></td>
<td class="muted"><code>{rel}</code></td>
</tr>""")
            )

        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(html_t(t"<div class=\"{cls}\" style=\"margin-bottom:12px\">{notice}</div>"))

        admin_link = safe_html("")
        if _require_admin(self):
            admin_link = safe_html("<a class=\"pill\" href=\"/admin/users\">Admin: Users</a>")

        rows_html = join_html(rows) if rows else safe_html('<tr><td class="muted">No repos found.</td><td></td></tr>')
        body = html_t(
            t"""<div class="topbar">
<h1 style="margin:0">Repos</h1>
<div>{admin_link} <a class="pill" href="/tokens">Tokens</a> <span class="pill">User: <code>{self.remote_user or "?"}</code></span> <a class="pill" href="/logout">Logout</a></div>
</div>
{notice_html}
<div class="box" style="margin-bottom:14px">
<h2 style="margin:0 0 10px 0;font-size:16px">Create repository</h2>
<form method="POST" action="/create-repo">
<div class="row">
<div><label>Owner (optional)</label><input name="owner" placeholder="{FLAT_OWNER_UI} for flat layout" /></div>
<div><label>Repo name</label><input name="repo" placeholder="my-repo" required /></div>
<div><button type="submit">Create</button></div>
</div>
<p class="muted" style="margin:10px 0 0 0">Create requires <code>write</code> scope.</p>
</form>
</div>
<div class="box" style="margin-bottom:14px">
<h2 style="margin:0 0 10px 0;font-size:16px">Tokens</h2>
<p class="muted" style="margin:0">Create, view, expire, and revoke your personal access tokens from the <a href="/tokens">Tokens tab</a>.</p>
</div>
<div class="box">
<p class="muted">GIT_PROJECT_ROOT: <code>{GIT_PROJECT_ROOT}</code></p>
<table>{rows_html}</table>
</div>"""
        )
        await _send_html(self.request, 200, _html_page("Repos", safe_html(body)))

    async def _ui_tokens(self, notice: str = "", notice_kind: str = "ok", new_token: str = ""):
        user_id = int(self.remote_user_id or 0)
        tokens = await asyncio.to_thread(db_list_tokens_for_user, user_id)

        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(html_t(t"<div class=\"{cls}\" style=\"margin-bottom:12px\">{notice}</div>"))

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
                revoked_html = safe_html(html_t(t"<br><small class=\"muted\">Revoked: {revoked_display}</small>"))

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
                action_html = safe_html("<span class=\"muted\">No action</span>")

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

        rows_html = join_html(rows) if rows else safe_html('<tr><td class="muted">No tokens yet.</td><td></td><td></td><td></td><td></td></tr>')

        body = html_t(
            t"""<div class="topbar">
<h1 style="margin:0">Tokens</h1>
<div><a class="pill" href="/">Home</a> <span class="pill">User: <code>{self.remote_user or "?"}</code></span></div>
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
</div>"""
        )
        await _send_html(self.request, 200, _html_page("Tokens", safe_html(body)))

    async def _ui_create_token(self):
        form = await self._read_form_urlencoded()
        name = (form.get("name") or "").strip()
        scopes = (form.get("scopes") or "read,write").strip() or "read,write"
        expires_at = (form.get("expires_at") or "").strip()
        if not name:
            return await self._ui_tokens("Token name is required.", "warn")
        try:
            token = await asyncio.to_thread(db_create_token, int(self.remote_user_id or 0), name, scopes, expires_at)
        except ValueError as e:
            return await self._ui_tokens(str(e), "warn")
        except Exception as e:
            return await self._ui_tokens(str_t(t"Failed to create token: {e}"), "warn")
        return await self._ui_tokens("Token created.", "ok", token)

    async def _ui_revoke_token(self):
        form = await self._read_form_urlencoded()
        try:
            token_id = int((form.get("token_id") or "0").strip())
        except Exception:
            return await self._ui_tokens("Invalid token id.", "warn")

        ok = await asyncio.to_thread(db_revoke_token, int(self.remote_user_id or 0), token_id)
        if not ok:
            return await self._ui_tokens("Token was not found or was already revoked.", "warn")
        return await self._ui_tokens("Token revoked.", "ok")

    async def _ui_create_repo(self):
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

        code, out, err = await _run_cmd([
            "git",
            "--git-dir=" + repo_git,
            "config",
            "http.receivepack",
            "true",
        ])
        if code != 0:
            msg = err.decode("utf-8", "replace").strip() or out.decode("utf-8", "replace").strip()
            return await self._ui_home(str_t(t"Repo created, but failed to enable push: {msg}"), "warn")

        return await self._ui_home(str_t(t"Repo created: {owner_ui}/{repo}"), "ok")

    # ========================================================
    # UI: Admin Users
    # ========================================================
    async def _ui_admin_users(self, notice: str = "", notice_kind: str = "ok"):
        if not _require_admin(self):
            return await self._forbidden(b"403 Forbidden: admin only.\n")

        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(html_t(t"<div class=\"{cls}\" style=\"margin-bottom:12px\">{notice}</div>"))

        users = await asyncio.to_thread(db_list_users)
        rows = []
        options = []
        for uid, uname, is_admin, is_active, created_at in users:
            pill_admin = safe_html('<span class="pill">admin</span>' if is_admin else '<span class="pill muted">user</span>')
            pill_active = safe_html('<span class="pill">active</span>' if is_active else '<span class="pill muted">disabled</span>')
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
            options.append(html_t(t"<option value=\"{uid}\">{uname}</option>"))

        rows_html = join_html(rows) if rows else safe_html('<tr><td class="muted">No users.</td></tr>')
        options_html = join_html(options)

        body = html_t(
            t"""<div class="topbar"><h1 style="margin:0">Admin · Users</h1><div><a class="pill" href="/">Home</a></div></div>
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
<div class="box"><h2 style="margin:0 0 10px 0;font-size:16px">All users</h2><table>{rows_html}</table></div>"""
        )
        await _send_html(self.request, 200, _html_page("Admin · Users", safe_html(body)))

    async def _ui_admin_users_create(self):
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
            return await self._ui_admin_users("User already exists.", "warn")
        except Exception as e:
            return await self._ui_admin_users(str_t(t"Failed to create user: {e}"), "warn")
        return await self._ui_admin_users(str_t(t"User created: {username}"), "ok")

    async def _ui_admin_users_reset(self):
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
            return await self._ui_admin_users(str_t(t"Failed to reset password: {e}"), "warn")
        return await self._ui_admin_users(str_t(t"Password updated for: {u[1]}"), "ok")

    async def _ui_admin_users_toggle(self):
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
            return await self._ui_admin_users("You cannot disable your own account from the UI.", "warn")
        try:
            await asyncio.to_thread(db_set_user_active, user_id, make_active)
        except Exception as e:
            return await self._ui_admin_users(str_t(t"Failed to update user: {e}"), "warn")
        status = "active" if make_active else "disabled"
        return await self._ui_admin_users(str_t(t"User '{u[1]}' is now {status}."), "ok")

    # ========================================================
    # UI: Repo + Branches + PRs
    # ========================================================
    async def _ui_repo(self, owner: str, repo: str):
        owner = unquote(owner)
        repo = unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return await self._forbidden(b"403 Forbidden\n")
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()

        default_branch = await _git_default_branch(repo_git)
        branches = await _git_list_branches(repo_git)
        if owner == FLAT_OWNER_UI:
            clone_path = str_t(t"{URL_PREFIX}/{q(repo)}.git")
        else:
            clone_path = str_t(t"{URL_PREFIX}/{q(owner)}/{q(repo)}.git")
        clone_user = self.remote_user or "USER"

        options = []
        for b in branches:
            selected = safe_html(" selected") if b == default_branch else safe_html("")
            options.append(html_t(t"<option value=\"{b}\"{selected}>{b}</option>"))
        options_html = join_html(options) if options else safe_html("<option>(none)</option>")
        base = str_t(t"/r/{q(owner)}/{q(repo)}")

        body = html_t(
            t"""<div class="topbar">
<div><h1 style="margin:0">{owner}/{repo}</h1><div class="muted">Default branch: <code>{default_branch}</code></div></div>
<div><a class="pill" href="/">All repos</a> <a class="pill" href="{base}/branches">Branches</a> <a class="pill" href="{base}/pulls">Pull requests</a></div>
</div>
<div class="box" style="margin-bottom:14px">
<div class="row"><div><label>Switch branch</label><select id="branchSel">{options_html}</select></div><div><button type="button" onclick="goBranch()">Browse</button></div></div>
<script>function goBranch(){{var b=document.getElementById('branchSel').value;if(!b)return;window.location='{base}/tree/' + encodeURIComponent(b) + '/';}}</script>
</div>
<div class="box">
<p><a href="{base}/commits?ref={q(default_branch)}">Commits</a> | <a href="{base}/tree/{q(default_branch)}/">Browse default</a></p>
<p class="muted" style="margin-top:14px">Clone:</p>
<pre><code id="cloneUrl" data-user="{clone_user}" data-path="{clone_path}"></code></pre>
<script>
(function() {{
    const element = document.getElementById("cloneUrl");
    const username = encodeURIComponent(element.dataset.user);
    element.textContent = window.location.protocol + "//" + username +
        ":SECRET@" + window.location.host + element.dataset.path;
}})();
</script>
</div>"""
        )
        await _send_html(self.request, 200, _html_page(str_t(t"{owner}/{repo}"), safe_html(body)))

    async def _ui_branches(self, owner: str, repo: str, notice: str = "", notice_kind: str = "ok"):
        owner = unquote(owner)
        repo = unquote(repo)
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return await self._forbidden(b"403 Forbidden\n")
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()

        default_branch = await _git_default_branch(repo_git)
        branches = await _git_list_branches(repo_git)
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(html_t(t"<div class=\"{cls}\" style=\"margin-bottom:12px\">{notice}</div>"))
        can_write = _has_write_scope(self)

        rows = []
        for b in branches:
            browse = str_t(t"{base}/tree/{q(b)}/")
            if can_write and b != default_branch:
                del_html = safe_html(
                    html_t(
                        t"""<form method="POST" action="{base}/branches/delete" style="display:inline">
<input type="hidden" name="branch" value="{b}"/><button class="danger" type="submit">Delete</button></form>"""
                    )
                )
            elif b == default_branch:
                del_html = safe_html('<span class="muted">protected</span>')
            else:
                del_html = safe_html('<span class="muted">no write scope</span>')
            default_pill = safe_html(' <span class="pill">default</span>' if b == default_branch else "")
            rows.append(
                html_t(
                    t"""<tr><td><code>{b}</code>{default_pill}</td>
<td><a class="pill" href="{browse}">Browse</a> <a class="pill" href="{base}/commits?ref={q(b)}">Commits</a></td>
<td style="text-align:right">{del_html}</td></tr>"""
                )
            )

        if can_write:
            create_box = safe_html(
                html_t(
                    t"""<div class="box" style="margin-bottom:14px">
<h2 style="margin:0 0 10px 0;font-size:16px">Create branch</h2>
<form method="POST" action="{base}/branches/create"><div class="row">
<div><label>New branch name</label><input name="new_branch" placeholder="feature/x" required/></div>
<div><label>From (branch/tag/commit)</label><input name="from_ref" value="{default_branch}" required/></div>
<div><button type="submit">Create</button></div>
</div></form></div>"""
                )
            )
        else:
            create_box = safe_html('<div class="box warn" style="margin-bottom:14px">You don’t have <code>write</code> scope, so branch create/delete is disabled.</div>')
        rows_html = join_html(rows) if rows else safe_html('<tr><td class="muted">No branches.</td><td></td><td></td></tr>')
        body = html_t(
            t"""<div class="topbar"><h1 style="margin:0">Branches</h1>
<div><a class="pill" href="{base}">Repo</a> <a class="pill" href="/">Home</a> <a class="pill" href="{base}/pulls">Pull requests</a></div></div>
{notice_html}{create_box}<div class="box"><table>{rows_html}</table></div>"""
        )
        await _send_html(self.request, 200, _html_page(str_t(t"Branches · {owner}/{repo}"), safe_html(body)))

    async def _ui_branch_create(self, owner: str, repo: str):
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._ui_branches(owner, repo, "You need write scope to create branches.", "warn")
        form = await self._read_form_urlencoded()
        new_branch = (form.get("new_branch") or "").strip()
        from_ref = (form.get("from_ref") or "").strip()
        if not _safe_branch_name(new_branch):
            return await self._ui_branches(owner, repo, "Invalid branch name.", "warn")
        if not from_ref:
            return await self._ui_branches(owner, repo, "From ref is required.", "warn")
        ok, msg = await _git_create_branch(_repo_bare_path(owner, repo), new_branch, from_ref)
        return await self._ui_branches(owner, repo, msg, "ok" if ok else "warn")

    async def _ui_branch_delete(self, owner: str, repo: str):
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._ui_branches(owner, repo, "You need write scope to delete branches.", "warn")
        form = await self._read_form_urlencoded()
        branch = (form.get("branch") or "").strip()
        if not _safe_branch_name(branch):
            return await self._ui_branches(owner, repo, "Invalid branch name.", "warn")
        repo_git = _repo_bare_path(owner, repo)
        default_branch = await _git_default_branch(repo_git)
        if branch == default_branch:
            return await self._ui_branches(owner, repo, "Default branch is protected and cannot be deleted.", "warn")
        ok, msg = await _git_delete_branch(repo_git, branch)
        return await self._ui_branches(owner, repo, msg, "ok" if ok else "warn")

    async def _ui_pulls(self, owner: str, repo: str, notice: str = "", notice_kind: str = "ok"):
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
        rows_db = await asyncio.to_thread(db_pr_list, owner, repo, None if status == "all" else status)
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(html_t(t"<div class=\"{cls}\" style=\"margin-bottom:12px\">{notice}</div>"))

        rows = []
        for pr_id, title, src, tgt, st, created_at in rows_db:
            rows.append(
                html_t(
                    t"""<tr>
<td><a href="{base}/pulls/{pr_id}">PR #{pr_id}: {title}</a></td>
<td class="muted"><code>{src}</code> → <code>{tgt}</code></td>
<td><span class="pill">{st}</span></td><td class="muted">{created_at}</td></tr>"""
                )
            )
        default_branch = await _git_default_branch(repo_git)
        branches = await _git_list_branches(repo_git)
        opt_src = join_html([html_t(t"<option value=\"{b}\">{b}</option>") for b in branches])
        opt_tgt_list = []
        for b in branches:
            selected = safe_html(" selected") if b == default_branch else safe_html("")
            opt_tgt_list.append(html_t(t"<option value=\"{b}\"{selected}>{b}</option>"))
        opt_tgt = join_html(opt_tgt_list)
        can_write = _has_write_scope(self)
        warn_merge = safe_html(
            '<div class="warn" style="margin-top:10px">Merging is <b>fast-forward only</b> on this server.</div>'
            if can_write
            else '<div class="warn" style="margin-top:10px">You don’t have <code>write</code> scope; you can open PRs but cannot merge.</div>'
        )
        rows_html = join_html(rows) if rows else safe_html('<tr><td class="muted">No pull requests.</td><td></td><td></td><td></td></tr>')
        body = html_t(
            t"""<div class="topbar"><h1 style="margin:0">Pull requests</h1>
<div><a class="pill" href="{base}">Repo</a> <a class="pill" href="{base}/branches">Branches</a> <a class="pill" href="/">Home</a></div></div>
{notice_html}
<div class="box" style="margin-bottom:14px"><div class="row" style="justify-content:space-between;align-items:center"><div>
<a class="pill" href="{base}/pulls?status=open">Open</a> <a class="pill" href="{base}/pulls?status=merged">Merged</a> <a class="pill" href="{base}/pulls?status=closed">Closed</a> <a class="pill" href="{base}/pulls?status=all">All</a>
</div><div class="muted">Filter: <code>{status}</code></div></div></div>
<div class="box" style="margin-bottom:14px"><h2 style="margin:0 0 10px 0;font-size:16px">Open a pull request</h2>
<form method="POST" action="{base}/pulls/create">
<div class="row"><div style="min-width:220px"><label>Source branch</label><select name="source_branch" required>{opt_src}</select></div>
<div style="min-width:220px"><label>Target branch</label><select name="target_branch" required>{opt_tgt}</select></div></div>
<div class="row" style="margin-top:10px"><div style="flex:1;min-width:260px"><label>Title</label><input name="title" placeholder="Add feature X" required style="width:100%"/></div></div>
<div style="margin-top:10px"><label>Description</label><textarea name="body" placeholder="What does this change?"></textarea></div>
<div style="margin-top:10px"><button type="submit">Create PR</button></div></form>{warn_merge}</div>
<div class="box"><table>{rows_html}</table></div>"""
        )
        await _send_html(self.request, 200, _html_page(str_t(t"Pull requests · {owner}/{repo}"), safe_html(body)))

    async def _ui_pulls_create(self, owner: str, repo: str):
        owner = unquote(owner)
        repo = unquote(repo)
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
            return await self._ui_pulls(owner, repo, "Title is required.", "warn")
        if not (_safe_branch_name(source_branch) and _safe_branch_name(target_branch)):
            return await self._ui_pulls(owner, repo, "Invalid branch name.", "warn")
        if source_branch == target_branch:
            return await self._ui_pulls(owner, repo, "Source and target must be different.", "warn")
        src = await _git_resolve_commit(repo_git, "refs/heads/" + source_branch)
        tgt = await _git_resolve_commit(repo_git, "refs/heads/" + target_branch)
        if not src:
            return await self._ui_pulls(owner, repo, str_t(t"Source branch not found: {source_branch}"), "warn")
        if not tgt:
            return await self._ui_pulls(owner, repo, str_t(t"Target branch not found: {target_branch}"), "warn")
        pr_id = await asyncio.to_thread(db_pr_create, owner, repo, title, body, source_branch, target_branch, int(self.remote_user_id or 0))
        await _send_redirect(self.request, str_t(t"/r/{q(owner)}/{q(repo)}/pulls/{pr_id}"))

    async def _ui_pull_view(self, owner: str, repo: str, pr_id: int, notice: str = "", notice_kind: str = "ok"):
        owner = unquote(owner)
        repo = unquote(repo)
        row = await asyncio.to_thread(db_pr_get, pr_id)
        if not row:
            return await self._not_found()
        (_id, db_owner, db_repo, title, body, src_branch, tgt_branch, author_user_id, status, created_at, closed_at, merged_at, merge_method, merge_commit) = row
        if db_owner != owner or db_repo != repo:
            return await self._not_found()
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        src_commit = await _git_resolve_commit(repo_git, "refs/heads/" + src_branch)
        tgt_commit = await _git_resolve_commit(repo_git, "refs/heads/" + tgt_branch)
        commits = []
        if src_commit and tgt_commit and src_commit != tgt_commit:
            commits = await _git_list_commits(repo_git, tgt_commit + ".." + src_commit, limit=200)
        if src_commit and tgt_commit and src_commit != tgt_commit:
            diff_text, diff_trunc = await _git_diff_between(repo_git, tgt_commit, src_commit, max_bytes=PR_PATCH_MAX_BYTES)
        elif src_commit and tgt_commit and src_commit == tgt_commit:
            diff_text, diff_trunc = "(No changes; branches point to the same commit.)", False
        else:
            diff_text, diff_trunc = "(Could not resolve one or both branches.)", False

        notice_html = safe_html("")
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = safe_html(html_t(t"<div class=\"{cls}\" style=\"margin-bottom:12px\">{notice}</div>"))
        merge_note = safe_html("")
        if status == "merged":
            short_commit = (merge_commit or "")[:8]
            merge_note = safe_html(html_t(t"<div class=\"ok\" style=\"margin-top:10px\">Merged ({merge_method or ''}). Target now at <code>{short_commit}</code>.</div>"))
        elif status == "closed":
            merge_note = safe_html('<div class="warn" style="margin-top:10px">Closed.</div>')

        can_write = _has_write_scope(self)
        merge_box = safe_html("")
        if status == "open":
            if can_write:
                merge_box = safe_html(
                    html_t(
                        t"""<div class="box" style="margin-bottom:14px"><h2 style="margin:0 0 10px 0;font-size:16px">Merge</h2>
<div class="muted">This server supports <b>fast-forward only</b> merges.</div>
<form method="POST" action="{base}/pulls/{pr_id}/merge" style="margin-top:10px"><button type="submit">Merge (ff-only)</button></form>
<form method="POST" action="{base}/pulls/{pr_id}/close" style="margin-top:10px"><button class="danger" type="submit">Close PR</button></form></div>"""
                    )
                )
            else:
                merge_box = safe_html('<div class="box warn" style="margin-bottom:14px">You don’t have <code>write</code> scope. You can’t merge/close this PR from the UI.</div>')

        commit_rows = []
        for c in commits:
            ch = c["hash"]
            commit_rows.append(
                html_t(
                    t"""<tr><td style="width:110px"><a href="{base}/commit/{q(ch)}"><code>{ch[:8]}</code></a></td>
<td>{c['subject']}</td><td class="muted">{c['author_name']}</td><td class="muted"><small>{c['date']}</small></td></tr>"""
                )
            )
        commits_html = join_html(commit_rows) if commit_rows else safe_html('<tr><td class="muted">No commits (or branches not resolvable).</td></tr>')
        diff_html = _prism_diff_patch_html(diff_text, diff_trunc, "Diff")
        description = safe_html(html_t(t"{body}")) if (body or "").strip() else safe_html('<span class="muted">(no description)</span>')
        src_short = (src_commit or "")[:8]
        tgt_short = (tgt_commit or "")[:8]
        body_html = html_t(
            t"""<div class="topbar"><div><h1 style="margin:0">PR #{pr_id}: {title}</h1>
<div class="muted"><code>{src_branch}</code> → <code>{tgt_branch}</code> | Created: {created_at}</div></div>
<div><a class="pill" href="{base}/pulls">All PRs</a> <a class="pill" href="{base}">Repo</a></div></div>
{notice_html}
<div class="box" style="margin-bottom:14px"><span class="pill">{status}</span>{merge_note}
<div style="margin-top:10px">{description}</div>
<div class="muted" style="margin-top:10px">Source: <code>{src_branch}</code> @ <code>{src_short}</code><br>Target: <code>{tgt_branch}</code> @ <code>{tgt_short}</code></div></div>
{merge_box}
<div class="box" style="margin-bottom:14px"><h2 style="margin:0 0 10px 0;font-size:16px">Commits</h2><table>{commits_html}</table></div>
<div class="box"><h2 style="margin:0 0 10px 0;font-size:16px">Diff</h2>{diff_html}</div>"""
        )
        await _send_html(self.request, 200, _html_page(str_t(t"PR #{pr_id} · {owner}/{repo}"), safe_html(body_html)))

    async def _ui_pull_close(self, owner: str, repo: str, pr_id: int):
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        pr = await asyncio.to_thread(db_pr_get, pr_id)
        if not pr or pr[1] != owner or pr[2] != repo:
            return await self._not_found()
        await asyncio.to_thread(db_pr_close, pr_id)
        return await self._ui_pull_view(owner, repo, pr_id, "Pull request closed.", "ok")

    async def _ui_pull_merge(self, owner: str, repo: str, pr_id: int):
        owner = unquote(owner)
        repo = unquote(repo)
        if not _has_write_scope(self):
            return await self._forbidden(b"403 Forbidden: write scope required.\n")
        pr = await asyncio.to_thread(db_pr_get, pr_id)
        if not pr:
            return await self._not_found()
        (_id, db_owner, db_repo, _title, _body, src_branch, tgt_branch, _author_user_id, status, _created_at, _closed_at, _merged_at, _merge_method, _merge_commit) = pr
        if db_owner != owner or db_repo != repo:
            return await self._not_found()
        if status != "open":
            return await self._ui_pull_view(owner, repo, pr_id, "PR is not open.", "warn")
        ok, msg, new_commit = await _git_ff_merge(_repo_bare_path(owner, repo), tgt_branch, src_branch)
        if not ok:
            return await self._ui_pull_view(owner, repo, pr_id, msg, "warn")
        if new_commit:
            await asyncio.to_thread(db_pr_mark_merged, pr_id, "ff-only", new_commit)
        return await self._ui_pull_view(owner, repo, pr_id, msg, "ok")

    # ========================================================
    # UI: Commits, Commit, Tree, Blob
    # ========================================================
    async def _ui_commits(self, owner: str, repo: str, ref: str):
        owner = unquote(owner)
        repo = unquote(repo)
        ref = unquote(ref)
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()
        fmt = "%H|%an|%ad|%s"
        code, out, err = await _run_git(repo_git, ["log", "--date=iso", "--format=" + fmt, "-n", "50", ref])
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        if code != 0:
            msg = err.decode("utf-8", "replace")
            body = html_t(t"<h1>Commits</h1><pre>{msg}</pre><p><a class=\"pill\" href=\"/\">Back</a></p>")
            return await _send_html(self.request, 400, _html_page("Commits", safe_html(body)))
        rows = []
        for ln in out.decode("utf-8", "replace").splitlines():
            parts = ln.split("|", 3)
            if len(parts) != 4:
                continue
            hsh, an, ad, subj = parts
            rows.append(html_t(t"<tr><td><a href=\"{base}/commit/{q(hsh)}\"><code>{hsh[:8]}</code></a></td><td>{subj}</td><td>{an}</td><td><small class=\"muted\">{ad}</small></td></tr>"))
        rows_html = join_html(rows) if rows else safe_html('<tr><td class="muted">No commits.</td></tr>')
        body = html_t(
            t"""<div class="topbar"><h1 style="margin:0">Commits</h1>
<div><a class="pill" href="{base}">Repo</a> <a class="pill" href="{base}/branches">Branches</a> <a class="pill" href="{base}/pulls">Pull requests</a></div></div>
<div class="box"><p class="muted">ref: <code>{ref}</code></p><table>{rows_html}</table></div>"""
        )
        await _send_html(self.request, 200, _html_page(str_t(t"Commits · {owner}/{repo}"), safe_html(body)))

    async def _ui_commit(self, owner: str, repo: str, commitish: str):
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
        patch_text, truncated = await _git_commit_patch(repo_git, commit)
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        parent_links = []
        for p in [p for p in (meta["parents"] or "").split() if p.strip()]:
            parent_links.append(html_t(t"<a class=\"pill\" href=\"{base}/commit/{q(p)}\"><code>{p[:8]}</code></a>"))
        parents_html = safe_html("")
        if parent_links:
            parents_html = safe_html(html_t(t"<div class=\"muted\" style=\"margin-top:6px\">Parents: {join_html(parent_links)}</div>"))
        file_rows = []
        for status, path in files:
            if status.startswith("D"):
                file_rows.append(html_t(t"<tr><td style=\"width:70px\"><span class=\"pill\">{status}</span></td><td><code>{path}</code></td></tr>"))
            else:
                href = str_t(t"{base}/blob/{q(commit)}/{q(path, safe='/')}")
                file_rows.append(html_t(t"<tr><td style=\"width:70px\"><span class=\"pill\">{status}</span></td><td><a href=\"{href}\"><code>{path}</code></a></td></tr>"))
        files_html = join_html(file_rows) if file_rows else safe_html('<tr><td class="muted">No file list.</td></tr>')
        patch_html = _prism_diff_patch_html(patch_text, truncated, "Patch")
        body = html_t(
            t"""<div class="topbar"><div><h1 style="margin:0"><code>{commit[:8]}</code> {meta['subject']}</h1>
<div class="muted">{meta['author_name']} &lt;{meta['author_email']}&gt; · {meta['date']}</div>{parents_html}</div>
<div><a class="pill" href="{base}">Repo</a> <a class="pill" href="{base}/branches">Branches</a> <a class="pill" href="{base}/pulls">Pull requests</a></div></div>
<div class="box" style="margin-bottom:14px"><h2 style="margin:0 0 10px 0;font-size:16px">Files</h2><table>{files_html}</table></div>
<div class="box"><h2 style="margin:0 0 10px 0;font-size:16px">Patch</h2>{patch_html}</div>"""
        )
        await _send_html(self.request, 200, _html_page(str_t(t"Commit {commit[:8]} · {owner}/{repo}"), safe_html(body)))

    async def _ui_tree(self, owner: str, repo: str, ref: str, subpath: str):
        owner = unquote(owner)
        repo = unquote(repo)
        ref = unquote(ref)
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()
        subpath = _clean_repo_path(subpath)
        spec = ref + (":" + subpath if subpath else ":")
        code, out, err = await _run_git(repo_git, ["ls-tree", spec])
        if code != 0:
            msg = err.decode("utf-8", "replace")
            body = html_t(t"<h1>Tree</h1><pre>{msg}</pre><p><a class=\"pill\" href=\"/\">Back</a></p>")
            return await _send_html(self.request, 400, _html_page("Tree", safe_html(body)))
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        entries: list[tuple[str, str]] = []
        for ln in out.decode("utf-8", "replace").splitlines():
            # git ls-tree: mode type object\tname
            if "\t" not in ln:
                continue
            meta_part, name = ln.split("\t", 1)
            parts = meta_part.split()
            kind = parts[1] if len(parts) >= 2 else "blob"
            entries.append((kind, name))

        # Show folders first, then files. Keep alphabetical order inside each group.
        entries.sort(key=lambda item: (0 if item[0] == "tree" else 1, item[1].lower()))

        rows = []
        for kind, name in entries:
            if kind == "tree":
                newpath = _join_repo_path(subpath, name)
                href = str_t(t"{base}/tree/{q(ref)}/{q(newpath, safe='/')}/")
                rows.append(html_t(t"<tr><td style=\"width:40px\">{TREE_FOLDER_ICON}</td><td><a class=\"tree-name\" href=\"{href}\">{name}</a></td></tr>"))
            else:
                newpath = _join_repo_path(subpath, name)
                href = str_t(t"{base}/blob/{q(ref)}/{q(newpath, safe='/')}")
                rows.append(html_t(t"<tr><td style=\"width:40px\">{TREE_FILE_ICON}</td><td><a class=\"tree-name\" href=\"{href}\">{name}</a></td></tr>"))
        up = safe_html("")
        if subpath:
            parent = "/".join(subpath.split("/")[:-1])
            parent_href = str_t(t"{base}/tree/{q(ref)}/{q(parent, safe='/')}/") if parent else str_t(t"{base}/tree/{q(ref)}/")
            up = safe_html(html_t(t"<p><a class=\"pill\" href=\"{parent_href}\">Up one level</a></p>"))
        rows_html = join_html(rows) if rows else safe_html('<tr><td class="muted">Empty.</td></tr>')
        body = html_t(
            t"""<div class="topbar"><div><h1 style="margin:0">{owner}/{repo}</h1><div class="muted">ref: <code>{ref}</code></div></div>
<div><a class="pill" href="{base}">Repo</a> <a class="pill" href="{base}/branches">Branches</a> <a class="pill" href="{base}/pulls">Pull requests</a></div></div>
{up}<div class="box"><table>{rows_html}</table></div>"""
        )
        await _send_html(self.request, 200, _html_page(str_t(t"Browse · {owner}/{repo}"), safe_html(body)))

    async def _ui_blob(self, owner: str, repo: str, ref: str, filepath: str):
        owner = unquote(owner)
        repo = unquote(repo)
        ref = unquote(ref)
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return await self._not_found()
        filepath = _clean_repo_path(filepath)
        if not filepath:
            return await self._not_found()
        spec = ref + ":" + filepath
        code, out, err = await _run_git(repo_git, ["show", spec])
        if code != 0:
            msg = err.decode("utf-8", "replace")
            body = html_t(t"<h1>File</h1><pre>{msg}</pre><p><a class=\"pill\" href=\"/\">Back</a></p>")
            return await _send_html(self.request, 400, _html_page("File", safe_html(body)))
        text = out.decode("utf-8", "replace")
        base = str_t(t"/r/{q(owner)}/{q(repo)}")
        back = str_t(t"{base}/tree/{q(ref)}/")
        if "/" in filepath:
            folder = "/".join(filepath.split("/")[:-1])
            back = str_t(t"{base}/tree/{q(ref)}/{q(folder, safe='/')}/")
        lang = PRISM_LANGUAGE_BY_EXTENSION.get("." + filepath.split(".")[-1], "")
        body = html_t(
            t"""<p><a class="pill" href="{back}">Back to folder</a> <a class="pill" href="{base}/branches">Branches</a> <a class="pill" href="{base}/pulls">Pull requests</a></p>
<h1 style="margin-top:10px"><code>{filepath}</code>
</h1><div class="box"><pre><code class="language-{lang}">{text}</code></pre>
<script>

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

    document.addEventListener("DOMContentLoaded", async () => {{
        try {{
            await loadPrismLanguage("{lang}");

            if (window.Prism) {{
                Prism.highlightAll();
            }}
        }} catch (error) {{
            console.error("Prism failed:", error);
        }}
    }});

</script>
</div>"""
        )
        await _send_html(
            self.request,
            200,
            _html_page(
                str_t(t"{filepath} · {owner}/{repo}"),
                safe_html(body),
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

    async def _pipe_content_length_body_to_stdin(self, stdin: asyncio.StreamWriter, content_len: int) -> None:
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

    async def _pipe_request_body_to_stdin(self, proc: asyncio.subprocess.Process, content_len: int) -> None:
        if proc.stdin is None:
            return

        try:
            transfer_encoding = (self.headers.get("Transfer-Encoding") or "").lower()
            if "chunked" in transfer_encoding:
                await self._pipe_chunked_body_to_stdin(proc.stdin)
            else:
                await self._pipe_content_length_body_to_stdin(proc.stdin, content_len)
        except (asyncio.IncompleteReadError, ClientDisconnected, ConnectionResetError, BrokenPipeError, OSError):
            # Client disconnected or git-http-backend closed stdin early.
            pass
        finally:
            with contextlib.suppress(Exception):
                proc.stdin.close()
            with contextlib.suppress(Exception):
                await proc.stdin.wait_closed()

    async def _handle_git(self):
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

        stderr_target = None
        trace_file = None
        body_task = None
        proc = None
        try:
            if TRACE_LOG:
                _ensure_dir(TRACE_LOG)
                trace_file = open(TRACE_LOG, "ab", buffering=0)
                stderr_target = trace_file
            else:
                stderr_target = asyncio.subprocess.DEVNULL

            await self._send_continue_if_needed()

            proc = await asyncio.create_subprocess_exec(
                GIT_HTTP_BACKEND,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=stderr_target,
                env=env,
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
            self.request.writer.write("".join(response_lines).encode("iso-8859-1", "replace"))
            await self.request.writer.drain()

            while True:
                chunk = await proc.stdout.read(READ_CHUNK)
                if not chunk:
                    break
                self.request.writer.write(chunk)
                await self.request.writer.drain()

            if body_task is not None:
                await body_task

            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(proc.wait(), timeout=5)
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
        finally:
            if body_task is not None and not body_task.done():
                body_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await body_task
            if proc is not None and proc.returncode is None:
                with contextlib.suppress(Exception):
                    proc.kill()
                    await proc.wait()
            if trace_file:
                with contextlib.suppress(Exception):
                    trace_file.flush()
                    trace_file.close()

    # ========================================================
    # ROUTING
    # ========================================================
    async def do_GET(self):
        ip = self._client_ip()
        if not _ip_allowed(ip, self._allowlist()):
            return await self._forbidden(b"403 Forbidden: IP not allowed.\n")

        parsed = urlparse(self.path)
        p = parsed.path

        if _is_static_request_path(p):
            if STATIC_REQUIRES_AUTH and not await self._require_session_auth():
                return
            return await self._serve_static()

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
        m = re.match(r"^/r/([^/]+)/([^/]+)$", p)
        if m:
            return await self._ui_repo(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/branches$", p)
        if m:
            return await self._ui_branches(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls$", p)
        if m:
            return await self._ui_pulls(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)$", p)
        if m:
            return await self._ui_pull_view(m.group(1), m.group(2), int(m.group(3)))
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

    async def do_POST(self):
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

        ctype = (self.headers.get("Content-Type") or "").lower()
        if "application/x-www-form-urlencoded" not in ctype:
            return await _send_text(self.request, 415, "Unsupported Media Type\n")
        if parsed.path == "/create-repo":
            return await self._ui_create_repo()
        if parsed.path in ("/tokens/create", "/admin/token"):
            return await self._ui_create_token()
        if parsed.path == "/tokens/revoke":
            return await self._ui_revoke_token()
        if parsed.path == "/admin/users/create":
            return await self._ui_admin_users_create()
        if parsed.path == "/admin/users/reset":
            return await self._ui_admin_users_reset()
        if parsed.path == "/admin/users/toggle":
            return await self._ui_admin_users_toggle()
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/create$", parsed.path)
        if m:
            return await self._ui_pulls_create(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/close$", parsed.path)
        if m:
            return await self._ui_pull_close(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/pulls/(\d+)/merge$", parsed.path)
        if m:
            return await self._ui_pull_merge(m.group(1), m.group(2), int(m.group(3)))
        m = re.match(r"^/r/([^/]+)/([^/]+)/branches/create$", parsed.path)
        if m:
            return await self._ui_branch_create(m.group(1), m.group(2))
        m = re.match(r"^/r/([^/]+)/([^/]+)/branches/delete$", parsed.path)
        if m:
            return await self._ui_branch_delete(m.group(1), m.group(2))
        return await self._not_found()

    async def do_HEAD(self):
        ip = self._client_ip()
        if not _ip_allowed(ip, self._allowlist()):
            return await self._forbidden(b"403 Forbidden: IP not allowed.\n")

        parsed = urlparse(self.path)
        if _is_static_request_path(parsed.path):
            if STATIC_REQUIRES_AUTH and not await self._require_session_auth():
                return
            return await self._serve_static(include_body=False)

        return await _send_text(self.request, 400, "HEAD is only implemented for static files.\n")

    async def dispatch(self):
        if self.command == "GET":
            return await self.do_GET()
        if self.command == "POST":
            return await self.do_POST()
        if self.command == "HEAD":
            return await self.do_HEAD()
        return await _send_text(self.request, 400, "Unsupported method.\n")


class AsyncGitServer:
    def __init__(self, context: AppContext | None = None, allowlist: set[str] | None = None):
        self.context = context or AppContext(AppConfig.from_mapping(default_config_for_platform()))
        apply_config(self.context.config)
        self.allowlist = allowlist if allowlist is not None else ALLOWED_CLIENT_IPS

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            req = await _read_http_request(reader, writer)
            handler = GitHTTPHandler(req, self)
            await handler.dispatch()
        except ClientDisconnected:
            # Client connected and closed without sending a full HTTP request,
            # or disconnected while we were sending a response. Ignore it quietly.
            pass
        except BadRequest as e:
            peer = writer.get_extra_info("peername")
            ip = peer[0] if peer else ""
            dummy_req = Request("GET", "/", "HTTP/1.1", Headers([]), BodyReader(reader), writer, ip)
            with contextlib.suppress(ClientDisconnected, ConnectionResetError, BrokenPipeError, OSError):
                await _send_text(dummy_req, 400, str_t(t"400 Bad Request: {e}\n"))
        except Exception as e:
            peer = writer.get_extra_info("peername")
            ip = peer[0] if peer else ""
            dummy_req = Request("GET", "/", "HTTP/1.1", Headers([]), BodyReader(reader), writer, ip)
            with contextlib.suppress(ClientDisconnected, ConnectionResetError, BrokenPipeError, OSError):
                await _send_text(dummy_req, 500, str_t(t"500 Internal Server Error: {e}\n"))
            print(str_t(t"[ERROR] {type(e).__name__}: {e}"), file=sys.stderr)
        finally:
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

    if not os.path.isfile(GIT_HTTP_BACKEND):
        print(str_t(t"ERROR: GIT_HTTP_BACKEND not found: {GIT_HTTP_BACKEND}"), file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(GIT_PROJECT_ROOT):
        print(str_t(t"ERROR: GIT_PROJECT_ROOT does not exist: {GIT_PROJECT_ROOT}"), file=sys.stderr)
        sys.exit(1)

    await asyncio.to_thread(_db_init)
    await asyncio.to_thread(db_ensure_default_admin)
    await asyncio.to_thread(os.makedirs, STATIC_ROOT, exist_ok=True)

    os.environ["GIT_PROJECT_ROOT"] = GIT_PROJECT_ROOT
    os.environ["GIT_HTTP_EXPORT_ALL"] = "1"

    app = AsyncGitServer(AppContext(config))
    server = await asyncio.start_server(app.handle_client, HOST, PORT)

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

    async with server:
        await server.serve_forever()


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pygithost",
        description="Async Git Smart HTTP + Web UI server.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run the Git HTTP server using a JSON config file.")
    run_parser.add_argument(
        "--config",
        default=str(_default_config_path()),
        help=str_t(t"Path to the JSON config file. Default: {_default_config_path()}"),
    )

    generate_parser = subparsers.add_parser("generate-config", help="Generate a platform-dependent JSON config file.")
    generate_parser.add_argument(
        "--config",
        default=str(_default_config_path()),
        help=str_t(t"Path where the JSON config file will be written. Default: {_default_config_path()}"),
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
                config_path = write_config_file(args.config, target_platform=args.platform, overwrite=args.overwrite)
                print(str_t(t"Config file generated: {config_path}"))
        except Exception as exc:
            print(str_t(t"ERROR: {exc}"), file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "run":
        config_path = Path(args.config).expanduser()
        if not config_path.is_file():
            print(str_t(t"ERROR: Config file not found: {config_path}"), file=sys.stderr)
            print(str_t(t"Create one first with: {Path(sys.argv[0]).name} generate-config --config {config_path}"), file=sys.stderr)
            sys.exit(1)
        try:
            asyncio.run(main_async(config_path))
        except KeyboardInterrupt:
            pass
        return

    parser.error("Unknown command.")


if __name__ == "__main__":
    main()
