import asyncio
import base64
import contextlib
import hashlib
import hmac
import html
import ipaddress
import mimetypes
import os
import platform
import re
import secrets
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.utils import formatdate
from pathlib import Path
from string.templatelib import Interpolation, Template
from urllib.parse import parse_qs, quote, unquote, urlparse

from hl_mappings import PRISM_LANGUAGE_BY_EXTENSION

# ============================================================
# CONFIG
# ============================================================
HOST = ""  # bind all interfaces
PORT = 8000

CURRENT_PLATFORM = platform.system()

if CURRENT_PLATFORM == "Windows":
    GIT_PROJECT_ROOT = r"C:\Servidor_Git"
    GIT_HTTP_BACKEND = r"C:\Program Files\Git\mingw64\libexec\git-core\git-http-backend.exe"
    TRACE_LOG = r"C:\temp\git-http-backend.log"
    DB_PATH = r"C:\temp\pygithost.db"

elif CURRENT_PLATFORM == "Linux":
    GIT_PROJECT_ROOT = str(Path.home() / "git_repos")
    GIT_HTTP_BACKEND = "/usr/lib/git-core/git-http-backend"
    TRACE_LOG = None
    DB_PATH = str(Path.home() / ".local/share/pygithost/pygithost.db")

elif CURRENT_PLATFORM == "Darwin":
    git_project_path = Path.home() / "git"
    git_project_path.mkdir(exist_ok=True)
    GIT_PROJECT_ROOT = str(git_project_path)
    GIT_HTTP_BACKEND = "/opt/homebrew/opt/git/libexec/git-core/git-http-backend"
    TRACE_LOG = "/tmp/git-http-backend.log"
    DB_PATH = str(Path.home() / ".local/share/pygithost/pygithost.db")

else:
    raise NotImplementedError(CURRENT_PLATFORM)

URL_PREFIX = "/git"
ALLOWED_CLIENT_IPS = {"127.0.0.1"}  # add CIDRs if needed, e.g. "192.168.1.0/24"

REQUIRE_AUTH = True
REALM = "Git Repositories"

FLAT_OWNER_UI = "root"
PR_PATCH_MAX_BYTES = 800_000
PRISM_DIFF_HIGHLIGHT_MAX_BYTES = 250_000
MAX_HEADER_BYTES = 64 * 1024
READ_CHUNK = 64 * 1024

# Web UI sessions. Git clients still use Basic Auth with password/token.
SESSION_COOKIE_NAME = "pygithost_session"
SESSION_TTL_SECONDS = 12 * 60 * 60
SESSION_COOKIE_SECURE = False  # Set True when this server is served over HTTPS.
LOGIN_PATH = "/login"

# Static files. Put files in ./static and access them with /static/filename.ext.
# Examples:
#   ./static/css/site.css -> http://HOST:8000/static/css/site.css
#   ./static/js/app.js    -> http://HOST:8000/static/js/app.js
#   ./static/index.html   -> http://HOST:8000/static/index.html
STATIC_URL_PREFIX = "/static"
STATIC_ROOT = str(Path(__file__).resolve().parent / "static")
STATIC_CACHE_SECONDS = 60 * 60
STATIC_REQUIRES_AUTH = False  # Keep False so CSS/JS can load on /login.

# ============================================================
# t-string rendering helpers
# ============================================================
class SafeHTML(str):
    """String already safe for insertion into HTML."""


def safe_html(value: object) -> SafeHTML:
    return SafeHTML(str(value))


def str_t(template: Template) -> str:
    """Render a t-string without escaping. Use for internal non-HTML strings."""
    parts: list[str] = []
    for part in template:
        if isinstance(part, Interpolation):
            parts.append(str(part.value))
        else:
            parts.append(part)
    return "".join(parts)


def html_t(template: Template) -> str:
    """Render a t-string as HTML, auto-escaping interpolated values."""
    parts: list[str] = []
    for part in template:
        if isinstance(part, Interpolation):
            value = part.value
            if isinstance(value, SafeHTML):
                parts.append(str(value))
            else:
                parts.append(html.escape(str(value), quote=True))
        else:
            parts.append(part)
    return "".join(parts)


def join_html(parts: list[str]) -> SafeHTML:
    return safe_html("".join(parts))


def q(value: str, safe: str = "") -> str:
    return quote(value, safe=safe)


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
    scopes = getattr(handler, "remote_scopes", set()) or set()
    if getattr(handler, "remote_is_admin", False):
        return True
    return "write" in {str(s).lower() for s in scopes}


def _require_admin(handler: object) -> bool:
    return bool(getattr(handler, "remote_is_admin", False))


# ============================================================
# HELPERS: DB (SQLite)
# ============================================================
def _ensure_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def _db_connect() -> sqlite3.Connection:
    _ensure_dir(DB_PATH)
    conn = sqlite3.connect(DB_PATH, timeout=5, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def _db_init() -> None:
    conn = _db_connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                pass_salt BLOB NOT NULL,
                pass_hash BLOB NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                token_hash BLOB NOT NULL,
                scopes TEXT NOT NULL DEFAULT 'read,write',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT,
                revoked_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        token_cols = {row[1] for row in conn.execute("PRAGMA table_info(tokens)")}
        if "expires_at" not in token_cols:
            conn.execute("ALTER TABLE tokens ADD COLUMN expires_at TEXT")
        if "revoked_at" not in token_cols:
            conn.execute("ALTER TABLE tokens ADD COLUMN revoked_at TEXT")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tokens_status ON tokens(user_id, is_active, expires_at, revoked_at)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_hash BLOB NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
                expires_at TEXT NOT NULL,
                last_seen_at TEXT,
                revoked_at TEXT,
                ip TEXT,
                user_agent TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_hash ON sessions(session_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, expires_at, revoked_at)")
        conn.execute("DELETE FROM sessions WHERE expires_at <= datetime('now', 'localtime')")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pull_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner TEXT NOT NULL,
                repo TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL DEFAULT '',
                source_branch TEXT NOT NULL,
                target_branch TEXT NOT NULL,
                author_user_id INTEGER,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                closed_at TEXT,
                merged_at TEXT,
                merge_method TEXT,
                merge_commit TEXT,
                FOREIGN KEY(author_user_id) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pr_repo ON pull_requests(owner, repo, status, id)")
    finally:
        conn.close()


def _pbkdf2_hash_password(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def _token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def db_create_user(username: str, password: str, is_admin: bool = False) -> None:
    if not _safe_seg(username):
        raise ValueError("Invalid username format.")
    salt = secrets.token_bytes(16)
    ph = _pbkdf2_hash_password(password, salt)
    conn = _db_connect()
    try:
        conn.execute(
            "INSERT INTO users(username, pass_salt, pass_hash, is_admin, is_active) VALUES(?,?,?,?,1)",
            (username, salt, ph, 1 if is_admin else 0),
        )
    finally:
        conn.close()


def db_get_user_by_username(username: str):
    conn = _db_connect()
    try:
        cur = conn.execute(
            "SELECT id, username, pass_salt, pass_hash, is_admin, is_active FROM users WHERE username=?",
            (username,),
        )
        return cur.fetchone()
    finally:
        conn.close()


def db_get_user_by_id(user_id: int):
    conn = _db_connect()
    try:
        cur = conn.execute(
            "SELECT id, username, is_admin, is_active, created_at FROM users WHERE id=?",
            (user_id,),
        )
        return cur.fetchone()
    finally:
        conn.close()


def db_list_users():
    conn = _db_connect()
    try:
        cur = conn.execute(
            "SELECT id, username, is_admin, is_active, created_at FROM users ORDER BY username COLLATE NOCASE"
        )
        return cur.fetchall()
    finally:
        conn.close()


def db_set_user_active(user_id: int, is_active: bool) -> None:
    conn = _db_connect()
    try:
        conn.execute("UPDATE users SET is_active=? WHERE id=?", (1 if is_active else 0, user_id))
    finally:
        conn.close()


def db_set_user_admin(user_id: int, is_admin: bool) -> None:
    conn = _db_connect()
    try:
        conn.execute("UPDATE users SET is_admin=? WHERE id=?", (1 if is_admin else 0, user_id))
    finally:
        conn.close()


def db_reset_password(user_id: int, new_password: str) -> None:
    salt = secrets.token_bytes(16)
    ph = _pbkdf2_hash_password(new_password, salt)
    conn = _db_connect()
    try:
        conn.execute("UPDATE users SET pass_salt=?, pass_hash=? WHERE id=?", (salt, ph, user_id))
    finally:
        conn.close()


def db_verify_password(username: str, password: str):
    row = db_get_user_by_username(username)
    if not row:
        return None
    uid, uname, salt, ph, is_admin, is_active = row
    if not is_active:
        return None
    computed = _pbkdf2_hash_password(password, salt)
    if hmac.compare_digest(computed, ph):
        return {
            "user_id": uid,
            "username": uname,
            "is_admin": bool(is_admin),
            "scopes": {"read", "write"},
        }
    return None


def db_create_session(user_id: int, ip: str = "", user_agent: str = "") -> str:
    token = secrets.token_urlsafe(48)
    session_hash = _token_hash(token)
    expires_at = (datetime.now() + timedelta(seconds=SESSION_TTL_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
    conn = _db_connect()
    try:
        conn.execute(
            """
            INSERT INTO sessions(user_id, session_hash, expires_at, ip, user_agent)
            VALUES(?,?,?,?,?)
            """,
            (int(user_id), session_hash, expires_at, ip[:80], user_agent[:300]),
        )
    finally:
        conn.close()
    return token


def db_verify_session(session_token: str | None):
    if not session_token:
        return None
    session_hash = _token_hash(session_token)
    conn = _db_connect()
    try:
        cur = conn.execute(
            """
            SELECT s.id, u.id, u.username, u.is_admin, u.is_active, s.expires_at, s.revoked_at
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.session_hash=?
            LIMIT 1
            """,
            (session_hash,),
        )
        row = cur.fetchone()
        if not row:
            return None
        session_id, uid, uname, is_admin, is_active, expires_at, revoked_at = row
        if not is_active or revoked_at or _token_is_expired(expires_at):
            return None
        conn.execute(
            "UPDATE sessions SET last_seen_at=datetime('now', 'localtime') WHERE id=?",
            (int(session_id),),
        )
        return {
            "user_id": uid,
            "username": uname,
            "is_admin": bool(is_admin),
            "scopes": {"read", "write"},
        }
    finally:
        conn.close()


def db_revoke_session(session_token: str | None) -> None:
    if not session_token:
        return
    session_hash = _token_hash(session_token)
    conn = _db_connect()
    try:
        conn.execute(
            """
            UPDATE sessions
            SET revoked_at=COALESCE(revoked_at, datetime('now', 'localtime'))
            WHERE session_hash=?
            """,
            (session_hash,),
        )
    finally:
        conn.close()


def _normalize_token_expires_at(raw: str | None) -> str | None:
    """
    Normalize the UI expiration value for SQLite.

    Accepted input examples:
      - "" or None                 -> no expiration
      - "2026-06-30"              -> 2026-06-30 23:59:59
      - "2026-06-30T17:30"        -> 2026-06-30 17:30:00
      - "2026-06-30 17:30:00"     -> 2026-06-30 17:30:00
    """
    value = (raw or "").strip()
    if not value:
        return None

    value = value.replace("T", " ")

    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        value = str_t(t"{value} 23:59:59")
    elif re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", value):
        value = str_t(t"{value}:00")

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("Expiration must be a valid date or date/time.") from exc

    if parsed.tzinfo is not None:
        # Store a simple SQLite-friendly local-looking value. The server compares
        # against SQLite local time so the UI behaves like the machine clock.
        parsed = parsed.astimezone().replace(tzinfo=None)

    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def _token_is_expired(expires_at: str | None) -> bool:
    if not expires_at:
        return False
    try:
        return datetime.fromisoformat(expires_at.replace("T", " ")) <= datetime.now()
    except ValueError:
        # If a bad legacy value somehow exists, fail closed.
        return True


def _normalize_token_scopes(scopes: str | None) -> str:
    raw = (scopes or "read").strip()
    parts = []
    for part in raw.split(","):
        item = part.strip().lower()
        if not item:
            continue
        if item not in {"read", "write", "admin"}:
            raise ValueError(str_t(t"Invalid token scope: {item}"))
        if item not in parts:
            parts.append(item)
    if not parts:
        parts = ["read"]
    if "write" in parts and "read" not in parts:
        parts.insert(0, "read")
    return ",".join(parts)


def db_create_token(user_id: int, name: str, scopes: str = "read,write", expires_at: str | None = None) -> str:
    clean_name = (name or "").strip()
    if not clean_name:
        raise ValueError("Token name is required.")
    if len(clean_name) > 80:
        raise ValueError("Token name is too long. Use 80 characters or fewer.")

    clean_scopes = _normalize_token_scopes(scopes)
    clean_expires_at = _normalize_token_expires_at(expires_at)

    token = secrets.token_urlsafe(32)
    th = _token_hash(token)
    conn = _db_connect()
    try:
        conn.execute(
            """
            INSERT INTO tokens(user_id, name, token_hash, scopes, is_active, expires_at)
            VALUES(?,?,?,?,1,?)
            """,
            (user_id, clean_name, th, clean_scopes, clean_expires_at),
        )
    finally:
        conn.close()
    return token


def db_list_tokens_for_user(user_id: int):
    conn = _db_connect()
    try:
        cur = conn.execute(
            """
            SELECT
                id,
                name,
                scopes,
                is_active,
                created_at,
                expires_at,
                revoked_at,
                CASE
                    WHEN revoked_at IS NOT NULL OR is_active = 0 THEN 'revoked'
                    WHEN expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now', 'localtime') THEN 'expired'
                    ELSE 'active'
                END AS status
            FROM tokens
            WHERE user_id=?
            ORDER BY id DESC
            """,
            (int(user_id),),
        )
        return cur.fetchall()
    finally:
        conn.close()


def db_revoke_token(user_id: int, token_id: int) -> bool:
    conn = _db_connect()
    try:
        cur = conn.execute(
            """
            UPDATE tokens
            SET is_active=0,
                revoked_at=COALESCE(revoked_at, datetime('now', 'localtime'))
            WHERE id=? AND user_id=? AND is_active=1
            """,
            (int(token_id), int(user_id)),
        )
        return cur.rowcount > 0
    finally:
        conn.close()


def _token_info_from_row(row):
    if not row:
        return None
    uid, uname, is_admin, user_active, scopes, token_active, expires_at, revoked_at = row
    if not user_active or not token_active or revoked_at:
        return None
    if _token_is_expired(expires_at):
        return None
    scopes_set = {s.strip().lower() for s in (scopes or "").split(",") if s.strip()}
    return {"user_id": uid, "username": uname, "is_admin": bool(is_admin), "scopes": scopes_set}


def db_verify_token(username: str, token: str):
    """
    Verify a personal token only when the Basic Auth username matches the token owner.
    This preserves the strict USERNAME:TOKEN behavior.
    """
    th = _token_hash(token)
    conn = _db_connect()
    try:
        cur = conn.execute(
            """
            SELECT u.id, u.username, u.is_admin, u.is_active,
                   t.scopes, t.is_active, t.expires_at, t.revoked_at
            FROM tokens t
            JOIN users u ON u.id = t.user_id
            WHERE u.username=? AND t.token_hash=?
            LIMIT 1
            """,
            (username, th),
        )
        row = cur.fetchone()
    finally:
        conn.close()
    return _token_info_from_row(row)


def db_verify_token_any_user(token: str):
    """
    Verify a personal token without requiring the Basic Auth username to match.

    This makes Git usage easier because the username part can be any safe placeholder,
    for example:
        git clone http://token:TOKEN_VALUE@host:8000/git/repo.git

    The authenticated server-side user is still the token owner from the database.
    """
    th = _token_hash(token)
    conn = _db_connect()
    try:
        cur = conn.execute(
            """
            SELECT u.id, u.username, u.is_admin, u.is_active,
                   t.scopes, t.is_active, t.expires_at, t.revoked_at
            FROM tokens t
            JOIN users u ON u.id = t.user_id
            WHERE t.token_hash=?
            LIMIT 1
            """,
            (th,),
        )
        row = cur.fetchone()
    finally:
        conn.close()
    return _token_info_from_row(row)

def db_ensure_default_admin() -> None:
    conn = _db_connect()
    try:
        cur = conn.execute("SELECT COUNT(*) FROM users")
        count = int(cur.fetchone()[0])
    finally:
        conn.close()

    if count == 0:
        default_password = os.environ.get("PYGITHOST_DEFAULT_ADMIN_PASSWORD") or secrets.token_urlsafe(18)
        print("[DB] No users found. Creating default admin user: admin")
        print(str_t(t"[DB] Default admin password (save it now): {default_password}"))
        db_create_user("admin", default_password, is_admin=True)
        u = db_get_user_by_username("admin")
        if u:
            token = db_create_token(u[0], "default", scopes="read,write,admin")
            print(str_t(t"[DB] Default admin token (save it now): {token}"))


# ---------- PR DB helpers ----------
def db_pr_create(owner: str, repo: str, title: str, body: str, source_branch: str, target_branch: str, author_user_id: int) -> int:
    conn = _db_connect()
    try:
        cur = conn.execute(
            """
            INSERT INTO pull_requests(owner, repo, title, body, source_branch, target_branch, author_user_id, status)
            VALUES(?,?,?,?,?,?,?, 'open')
            """,
            (owner, repo, title, body or "", source_branch, target_branch, int(author_user_id)),
        )
        return int(cur.lastrowid)
    finally:
        conn.close()


def db_pr_get(pr_id: int):
    conn = _db_connect()
    try:
        cur = conn.execute(
            """
            SELECT id, owner, repo, title, body, source_branch, target_branch,
                   author_user_id, status, created_at, closed_at, merged_at, merge_method, merge_commit
            FROM pull_requests
            WHERE id=?
            """,
            (int(pr_id),),
        )
        return cur.fetchone()
    finally:
        conn.close()


def db_pr_list(owner: str, repo: str, status: str | None = None):
    conn = _db_connect()
    try:
        if status:
            cur = conn.execute(
                """
                SELECT id, title, source_branch, target_branch, status, created_at
                FROM pull_requests
                WHERE owner=? AND repo=? AND status=?
                ORDER BY id DESC
                """,
                (owner, repo, status),
            )
        else:
            cur = conn.execute(
                """
                SELECT id, title, source_branch, target_branch, status, created_at
                FROM pull_requests
                WHERE owner=? AND repo=?
                ORDER BY id DESC
                """,
                (owner, repo),
            )
        return cur.fetchall()
    finally:
        conn.close()


def db_pr_close(pr_id: int) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "UPDATE pull_requests SET status='closed', closed_at=datetime('now') WHERE id=? AND status='open'",
            (int(pr_id),),
        )
    finally:
        conn.close()


def db_pr_mark_merged(pr_id: int, method: str, merge_commit: str) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            """
            UPDATE pull_requests
            SET status='merged', merged_at=datetime('now'), merge_method=?, merge_commit=?
            WHERE id=? AND status='open'
            """,
            (method, merge_commit, int(pr_id)),
        )
    finally:
        conn.close()


# ============================================================
# HELPERS: repos + git + HTTP
# ============================================================
def _is_git_dir(p: Path) -> bool:
    """
    Return True for a real Git directory.

    This supports both:
      - bare repo folders, for example: repo.git/
      - normal repo Git dirs, for example: repo/.git/
    """
    return p.is_dir() and (p / "HEAD").is_file()


def _is_bare_repo_dir(p: Path) -> bool:
    """Return True for a bare repository directory, for example repo.git/."""
    return _is_git_dir(p)


def _is_worktree_repo_dir(p: Path) -> bool:
    """Return True for a normal/non-bare repository, for example repo/.git/."""
    return p.is_dir() and _is_git_dir(p / ".git")


def _scan_repos(project_root: str) -> list[tuple[str, str, str]]:
    """
    Scan GIT_PROJECT_ROOT and return repositories for the web UI.

    Supported layouts:
      Flat bare:      GIT_PROJECT_ROOT/repo.git
      Flat non-bare:  GIT_PROJECT_ROOT/repo/.git
      Owner bare:     GIT_PROJECT_ROOT/owner/repo.git
      Owner non-bare: GIT_PROJECT_ROOT/owner/repo/.git
    """
    root = Path(project_root)
    results: list[tuple[str, str, str]] = []

    if not root.exists():
        return results

    # Flat bare repos: GIT_PROJECT_ROOT/repo.git
    for p in sorted(root.glob("*.git")):
        if p.name == ".git":
            continue

        if _is_bare_repo_dir(p):
            repo = p.name[:-4]
            if _safe_seg(repo):
                results.append((FLAT_OWNER_UI, repo, p.name))

    # Flat normal repos: GIT_PROJECT_ROOT/repo/.git
    for p in sorted([x for x in root.iterdir() if x.is_dir()]):
        if _is_worktree_repo_dir(p):
            repo = p.name
            if _safe_seg(repo):
                results.append((FLAT_OWNER_UI, repo, str_t(t"{repo}/.git")))

    # Owner layouts:
    #   GIT_PROJECT_ROOT/owner/repo.git
    #   GIT_PROJECT_ROOT/owner/repo/.git
    for owner_dir in sorted([x for x in root.iterdir() if x.is_dir()]):
        # If this folder itself is a normal repo, do not also treat it as an owner.
        if _is_worktree_repo_dir(owner_dir):
            continue

        # If this folder itself is a bare repo, do not treat it as an owner.
        if _is_bare_repo_dir(owner_dir):
            continue

        owner = owner_dir.name
        if not _safe_seg(owner):
            continue

        for p in sorted(owner_dir.glob("*.git")):
            if p.name == ".git":
                continue

            if _is_bare_repo_dir(p):
                repo = p.name[:-4]
                if _safe_seg(repo):
                    rel = str_t(t"{owner}/{p.name}")
                    results.append((owner, repo, rel))

        for p in sorted([x for x in owner_dir.iterdir() if x.is_dir()]):
            if _is_worktree_repo_dir(p):
                repo = p.name
                if _safe_seg(repo):
                    rel = str_t(t"{owner}/{repo}/.git")
                    results.append((owner, repo, rel))

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
      Flat bare:      GIT_PROJECT_ROOT/repo.git
      Flat non-bare:  GIT_PROJECT_ROOT/repo/.git
      Owner bare:     GIT_PROJECT_ROOT/owner/repo.git
      Owner non-bare: GIT_PROJECT_ROOT/owner/repo/.git

    If neither repo exists, return the bare path. This keeps create-repo
    working exactly like before, because new repos are still created as bare repos.
    """
    if owner_ui == FLAT_OWNER_UI:
        base = Path(GIT_PROJECT_ROOT)
    else:
        base = Path(GIT_PROJECT_ROOT) / owner_ui

    bare = base / (repo + ".git")
    worktree_git = base / repo / ".git"

    if _is_bare_repo_dir(bare):
        return str(bare)

    if _is_git_dir(worktree_git):
        return str(worktree_git)

    return str(bare)


def _repo_bare_path(owner_ui: str, repo: str) -> str:
    """
    Backward-compatible name used by the rest of the code.

    It now returns the real Git directory, which can be either:
      - repo.git for a bare repo
      - repo/.git for a normal/non-bare repo
    """
    return _repo_git_path(owner_ui, repo)


def _map_git_http_path_info(path_info: str) -> str:
    """
    Convert public Git smart HTTP URLs to the real on-disk Git directory.

    Clients can keep using URLs like:
      /git/repo.git
      /git/owner/repo.git

    If the repo is non-bare, the PATH_INFO sent to git-http-backend becomes:
      /repo/.git/...
      /owner/repo/.git/...

    Bare repositories are left unchanged.
    """
    clean = path_info.lstrip("/")
    parts = clean.split("/") if clean else []

    if not parts:
        return path_info

    # Flat URL: /repo.git/info/refs
    if len(parts) >= 1 and parts[0].endswith(".git"):
        repo = parts[0][:-4]

        if _safe_seg(repo):
            actual_git = Path(_repo_git_path(FLAT_OWNER_UI, repo))
            expected_worktree_git = Path(GIT_PROJECT_ROOT) / repo / ".git"

            if actual_git == expected_worktree_git and _is_git_dir(expected_worktree_git):
                parts[0] = repo
                parts.insert(1, ".git")
                return "/" + "/".join(parts)

    # Owner URL: /owner/repo.git/info/refs
    if len(parts) >= 2 and parts[1].endswith(".git"):
        owner = parts[0]
        repo = parts[1][:-4]

        if _safe_seg(owner) and _safe_seg(repo):
            actual_git = Path(_repo_git_path(owner, repo))
            expected_worktree_git = Path(GIT_PROJECT_ROOT) / owner / repo / ".git"

            if actual_git == expected_worktree_git and _is_git_dir(expected_worktree_git):
                parts[1] = repo
                parts.insert(2, ".git")
                return "/" + "/".join(parts)

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


def _html_page(title: str, body_html: str | SafeHTML) -> bytes:
    body = safe_html(body_html)
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
.tree-icon{{display:inline-block;width:20px;height:18px;position:relative;vertical-align:-4px}}
.tree-icon.folder{{color:#d97706}}
.tree-icon.folder::before{{content:"";position:absolute;left:1px;top:6px;width:18px;height:11px;border:1.5px solid currentColor;border-radius:3px;background:rgba(217,119,6,.12)}}
.tree-icon.folder::after{{content:"";position:absolute;left:2px;top:2px;width:9px;height:6px;border:1.5px solid currentColor;border-bottom:0;border-radius:3px 3px 0 0;background:rgba(217,119,6,.12)}}
.tree-icon.file{{color:var(--muted)}}
.tree-icon.file::before{{content:"";position:absolute;left:4px;top:1px;width:12px;height:16px;border:1.5px solid currentColor;border-radius:3px;background:transparent}}
.tree-icon.file::after{{content:"";position:absolute;right:3px;top:1px;width:5px;height:5px;border-left:1.5px solid currentColor;border-bottom:1.5px solid currentColor;background:var(--box)}}
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
<body>
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
            clone_url = str_t(t"http://USER:SECRET@HOST:{PORT}{URL_PREFIX}/{repo}.git")
        else:
            clone_url = str_t(t"http://USER:SECRET@HOST:{PORT}{URL_PREFIX}/{owner}/{repo}.git")

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
<p class="muted" style="margin-top:14px">Clone:</p><pre><code>{clone_url}</code></pre>
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
                rows.append(html_t(t"<tr><td style=\"width:40px\"><span class=\"tree-icon folder\" aria-hidden=\"true\"></span></td><td><a class=\"tree-name\" href=\"{href}\">{name}</a></td></tr>"))
            else:
                newpath = _join_repo_path(subpath, name)
                href = str_t(t"{base}/blob/{q(ref)}/{q(newpath, safe='/')}")
                rows.append(html_t(t"<tr><td style=\"width:40px\"><span class=\"tree-icon file\" aria-hidden=\"true\"></span></td><td><a class=\"tree-name\" href=\"{href}\">{name}</a></td></tr>"))
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
        await _send_html(self.request, 200, _html_page(str_t(t"{filepath} · {owner}/{repo}"), safe_html(body)))

    # ========================================================
    # Git smart HTTP backend
    # ========================================================
    def _git_request_needs_write(self, path_info: str, query: str) -> bool:
        qs = parse_qs(query or "")
        services = {s for values in qs.values() for s in values}
        return path_info.endswith("/git-receive-pack") or "git-receive-pack" in services

    async def _pipe_request_body_to_stdin(self, proc: asyncio.subprocess.Process, content_len: int) -> None:
        try:
            remaining = content_len
            while remaining > 0:
                data = await self.request.reader.read(min(READ_CHUNK, remaining))
                if not data:
                    break
                if proc.stdin is None:
                    break
                proc.stdin.write(data)
                await proc.stdin.drain()
                remaining -= len(data)
        except Exception:
            pass
        finally:
            if proc.stdin is not None:
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
        for k, v in self.headers.items():
            env["HTTP_" + k.upper().replace("-", "_")] = v
        ctype = self.headers.get("Content-Type")
        if ctype:
            env["CONTENT_TYPE"] = ctype
        clen = int(self.headers.get("Content-Length") or 0)
        if clen:
            env["CONTENT_LENGTH"] = str(clen)

        stderr_target = None
        trace_file = None
        try:
            if TRACE_LOG:
                _ensure_dir(TRACE_LOG)
                trace_file = open(TRACE_LOG, "ab", buffering=0)
                stderr_target = trace_file
            else:
                stderr_target = asyncio.subprocess.DEVNULL

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

            await body_task
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(proc.wait(), timeout=5)
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
        finally:
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
    def __init__(self, allowlist: set[str] | None = None):
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


async def main_async() -> None:
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

    app = AsyncGitServer()
    server = await asyncio.start_server(app.handle_client, HOST, PORT)

    print("=" * 60)
    print(str_t(t"Async Git Smart HTTP + Web UI running on port {PORT}"))
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


def main() -> None:
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
