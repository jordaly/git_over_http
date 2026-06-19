"""SQLite persistence for users, sessions, tokens, and pull requests."""

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta

from .config import AppConfig
from .rendering import str_t

DB_PATH = ""
SESSION_TTL_SECONDS = 12 * 60 * 60


def configure(config: AppConfig) -> None:
    """Set process-level database paths used by the synchronous DB helpers."""
    global DB_PATH, SESSION_TTL_SECONDS
    DB_PATH = config.db_path
    SESSION_TTL_SECONDS = config.session_ttl_seconds



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


