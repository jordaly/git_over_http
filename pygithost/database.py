"""SQLite persistence for users, sessions, tokens, and pull requests."""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

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


def _db_migrate_pr_author_nullable(conn):
    """Upgrade legacy NOT NULL authors without changing PR identities/data.

    SQLite requires a table rebuild to relax NOT NULL. Keep the original DDL,
    indexes, triggers, sequence high-water mark and incoming foreign keys.
    """
    columns = conn.execute("PRAGMA table_xinfo(pull_requests)").fetchall()
    author = next((column for column in columns if column[1].lower() == "author_user_id"), None)
    if not author or not author[3]:
        return
    foreign_keys = conn.execute("PRAGMA foreign_keys").fetchone()[0]
    legacy_alter = conn.execute("PRAGMA legacy_alter_table").fetchone()[0]
    # These pragmas must be set outside the transaction. Disabling FK actions
    # during DROP avoids cascading into tables referencing the existing PRs.
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("PRAGMA legacy_alter_table=ON")
    try:
        conn.execute("BEGIN IMMEDIATE")
        columns = conn.execute("PRAGMA table_xinfo(pull_requests)").fetchall()
        author = next(column for column in columns if column[1].lower() == "author_user_id")
        if not author[3]:  # Another startup may already have migrated it.
            conn.commit()
            return
        original_sql = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='pull_requests' COLLATE NOCASE").fetchone()[0]
        new_sql, changed = re.subn(
            r'((?:"author_user_id"|`author_user_id`|\[author_user_id\]|\bauthor_user_id\b)\s+(?:INTEGER|INT|BIGINT)\s+)NOT\s+NULL\b',
            r'\1', original_sql, count=1, flags=re.IGNORECASE)
        if changed != 1:
            raise ValueError("Unsupported legacy pull-request author definition; database was not modified.")
        temporary = "__pull_requests_nullable_" + secrets.token_hex(8)
        new_sql, renamed = re.subn(
            r'^(\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?)(?:"pull_requests"|`pull_requests`|\[pull_requests\]|pull_requests)(?=\s|\()',
            lambda match: match[1] + '"' + temporary + '"', new_sql, count=1, flags=re.IGNORECASE)
        if renamed != 1:
            raise ValueError("Unsupported legacy pull-request table definition; database was not modified.")
        objects = conn.execute("SELECT sql FROM sqlite_master WHERE tbl_name='pull_requests' COLLATE NOCASE AND type IN ('index','trigger') AND sql IS NOT NULL").fetchall()
        sequence = conn.execute("SELECT seq FROM sqlite_sequence WHERE name='pull_requests' COLLATE NOCASE").fetchone()
        existing_violations = set(conn.execute("PRAGMA foreign_key_check").fetchall())
        names = ",".join('"' + column[1].replace('"', '""') + '"' for column in columns if not column[6])
        conn.execute(new_sql)
        conn.execute(f'INSERT INTO "{temporary}" ({names}) SELECT {names} FROM pull_requests')
        conn.execute("DROP TABLE pull_requests")
        conn.execute(f'ALTER TABLE "{temporary}" RENAME TO pull_requests')
        for (sql,) in objects:
            conn.execute(sql)
        if sequence:
            conn.execute("UPDATE sqlite_sequence SET seq=MAX(seq,?) WHERE name='pull_requests'", (sequence[0],))
            conn.execute("INSERT INTO sqlite_sequence(name,seq) SELECT 'pull_requests',? WHERE NOT EXISTS(SELECT 1 FROM sqlite_sequence WHERE name='pull_requests')", (sequence[0],))
        if set(conn.execute("PRAGMA foreign_key_check").fetchall()) - existing_violations:
            raise sqlite3.IntegrityError("Pull-request author migration would introduce a foreign-key violation.")
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.execute(f"PRAGMA legacy_alter_table={int(legacy_alter)}")
        conn.execute(f"PRAGMA foreign_keys={int(foreign_keys)}")


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
        _db_migrate_pr_author_nullable(conn)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pr_repo ON pull_requests(owner, repo, status, id)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pr_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pr_id INTEGER NOT NULL,
                author_user_id INTEGER,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                edited_at TEXT,
                FOREIGN KEY(pr_id) REFERENCES pull_requests(id) ON DELETE CASCADE,
                FOREIGN KEY(author_user_id) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pr_comments_pr ON pr_comments(pr_id, id)")
        conn.execute("""CREATE TABLE IF NOT EXISTS ci_configs (
            owner TEXT NOT NULL, repo TEXT NOT NULL, config_json TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT (datetime('now')), PRIMARY KEY(owner, repo))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS ci_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, repo TEXT NOT NULL,
            event TEXT NOT NULL, branch TEXT NOT NULL DEFAULT '', commit_hash TEXT NOT NULL DEFAULT '',
            payload_json TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'queued',
            output TEXT NOT NULL DEFAULT '', truncated INTEGER NOT NULL DEFAULT 0,
            return_code INTEGER, created_at TEXT NOT NULL DEFAULT (datetime('now')),
            started_at TEXT, finished_at TEXT)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ci_runs_repo ON ci_runs(owner, repo, id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ci_runs_status ON ci_runs(status, id)")
        conn.execute("""CREATE TABLE IF NOT EXISTS ci_deployments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            owner TEXT NOT NULL, repo TEXT NOT NULL, commit_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'running', output TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL DEFAULT (datetime('now')), finished_at TEXT,
            UNIQUE(owner, repo, commit_hash))""")
        deployment_columns = {row[1] for row in conn.execute("PRAGMA table_info(ci_deployments)")}
        for name in ("notification", "config_json"):
            if name not in deployment_columns:
                conn.execute(f"ALTER TABLE ci_deployments ADD COLUMN {name} TEXT NOT NULL DEFAULT ''")
        if "pipeline_id" not in deployment_columns:
            # Replace the old repository/commit uniqueness constraint, retaining
            # IDs and historical attempts as the default pipeline's records.
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("""CREATE TABLE ci_deployments_multi (
                id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL,
                owner TEXT NOT NULL, repo TEXT NOT NULL, commit_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running', output TEXT NOT NULL DEFAULT '',
                started_at TEXT NOT NULL DEFAULT (datetime('now')), finished_at TEXT,
                notification TEXT NOT NULL DEFAULT '', config_json TEXT NOT NULL DEFAULT '',
                pipeline_id TEXT NOT NULL DEFAULT 'default',
                UNIQUE(owner,repo,commit_hash,pipeline_id))""")
            conn.execute("""INSERT INTO ci_deployments_multi
                SELECT id,run_id,owner,repo,commit_hash,status,output,started_at,finished_at,
                    notification,config_json,'default' FROM ci_deployments""")
            conn.execute("DROP TABLE ci_deployments")
            conn.execute("ALTER TABLE ci_deployments_multi RENAME TO ci_deployments")
            conn.execute("COMMIT")
        conn.execute("CREATE TABLE IF NOT EXISTS server_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("""CREATE TABLE IF NOT EXISTS repository_ci_settings (
            owner TEXT NOT NULL, repo TEXT NOT NULL, settings_json TEXT NOT NULL,
            PRIMARY KEY(owner,repo))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS repository_languages (
            owner TEXT NOT NULL, repo TEXT NOT NULL, commit_hash TEXT NOT NULL,
            languages_json TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY(owner,repo,commit_hash))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS repository_overviews (
            owner TEXT NOT NULL, repo TEXT NOT NULL, commit_hash TEXT NOT NULL,
            overview_json TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY(owner,repo,commit_hash))""")
        columns = {row[1] for row in conn.execute("PRAGMA table_info(ci_runs)")}
        for name in ("config_json", "phase", "reason", "notification", "warnings"):
            if name not in columns:
                conn.execute(f"ALTER TABLE ci_runs ADD COLUMN {name} TEXT NOT NULL DEFAULT ''")
                if name == "warnings":
                    conn.execute("""UPDATE ci_runs SET warnings=reason WHERE
                        reason LIKE 'Temporary directory cleanup failed:%' OR
                        reason LIKE 'Container cleanup failed:%' OR
                        reason LIKE 'Container cleanup failed;%' OR
                        reason LIKE 'Step metadata could not be saved:%'""")
        conn.execute("""CREATE TABLE IF NOT EXISTS ci_steps (
            run_id INTEGER PRIMARY KEY REFERENCES ci_runs(id) ON DELETE CASCADE,
            steps_json TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS ci_artifacts (
            run_id INTEGER PRIMARY KEY REFERENCES ci_runs(id) ON DELETE CASCADE,
            archive BLOB NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))""")
        # Match live filters and newest-first history queries. Create these only
        # after column migrations so existing installations can upgrade safely.
        for statement in (
            "CREATE INDEX IF NOT EXISTS idx_ci_runs_repo_branch ON ci_runs(owner,repo,branch,id DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ci_runs_repo_result ON ci_runs(owner,repo,status,id DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ci_runs_repo_event ON ci_runs(owner,repo,event,id DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ci_runs_warnings ON ci_runs(owner,repo,id DESC) WHERE warnings!=''",
            "CREATE INDEX IF NOT EXISTS idx_ci_runs_pending_email ON ci_runs(id) WHERE notification='queued'",
            "CREATE INDEX IF NOT EXISTS idx_deployments_repo_history ON ci_deployments(owner,repo,id DESC)",
            "CREATE INDEX IF NOT EXISTS idx_deployments_run ON ci_deployments(run_id)",
            "CREATE INDEX IF NOT EXISTS idx_deployments_pending_email ON ci_deployments(run_id) WHERE notification='queued'",
            "CREATE INDEX IF NOT EXISTS idx_pr_repo_history ON pull_requests(owner,repo,id DESC)",
            "CREATE INDEX IF NOT EXISTS idx_pr_open_source ON pull_requests(owner,repo,source_branch) WHERE status='open'",
            "CREATE INDEX IF NOT EXISTS idx_pr_open_target ON pull_requests(owner,repo,target_branch) WHERE status='open'",
            "CREATE INDEX IF NOT EXISTS idx_users_name_order ON users(username COLLATE NOCASE)",
        ):
            conn.execute(statement)
        _db_ci_cleanup_artifacts(conn)
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
def db_pr_comment_add(pr_id: int, author_user_id: int | None, body: str) -> int:
    conn = _db_connect()
    try:
        cur = conn.execute(
            "INSERT INTO pr_comments(pr_id, author_user_id, body) VALUES(?,?,?)",
            (int(pr_id), int(author_user_id) if author_user_id is not None else None, body),
        )
        return int(cur.lastrowid)
    finally:
        conn.close()


def db_pr_comment_list(pr_id: int):
    conn = _db_connect()
    try:
        return conn.execute(
            """
            SELECT c.id, c.author_user_id, u.username, c.body, c.created_at
            FROM pr_comments c LEFT JOIN users u ON u.id=c.author_user_id
            WHERE c.pr_id=? ORDER BY c.id
            """,
            (int(pr_id),),
        ).fetchall()
    finally:
        conn.close()


def db_pr_comment_get(pr_id: int, comment_id: int):
    conn = _db_connect()
    try:
        return conn.execute(
            "SELECT id, pr_id, author_user_id, body FROM pr_comments WHERE id=? AND pr_id=?",
            (int(comment_id), int(pr_id)),
        ).fetchone()
    finally:
        conn.close()


def db_pr_comment_update(comment_id: int, body: str) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "UPDATE pr_comments SET body=?, edited_at=datetime('now') WHERE id=?",
            (body, int(comment_id)),
        )
    finally:
        conn.close()


def db_pr_comment_delete(comment_id: int) -> None:
    conn = _db_connect()
    try:
        conn.execute("DELETE FROM pr_comments WHERE id=?", (int(comment_id),))
    finally:
        conn.close()


def db_pr_update_text(pr_id: int, title: str, body: str) -> None:
    conn = _db_connect()
    try:
        conn.execute("UPDATE pull_requests SET title=?, body=? WHERE id=?", (title, body, int(pr_id)))
    finally:
        conn.close()


def db_pr_comment_count(pr_id: int) -> int:
    conn = _db_connect()
    try:
        return conn.execute("SELECT COUNT(*) FROM pr_comments WHERE pr_id=?", (int(pr_id),)).fetchone()[0]
    finally:
        conn.close()


def db_pr_create(owner: str, repo: str, title: str, body: str, source_branch: str, target_branch: str, author_user_id: int | None) -> int:
    conn = _db_connect()
    try:
        cur = conn.execute(
            """
            INSERT INTO pull_requests(owner, repo, title, body, source_branch, target_branch, author_user_id, status)
            VALUES(?,?,?,?,?,?,?, 'open')
            """,
            (owner, repo, title, body or "", source_branch, target_branch, int(author_user_id) if author_user_id is not None else None),
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


def db_pr_count(owner, repo, status=None):
    conn = _db_connect()
    try:
        return conn.execute("SELECT COUNT(*) FROM pull_requests WHERE owner=? AND repo=?" +
            (" AND status=?" if status else ""), (owner, repo, status) if status else (owner, repo)).fetchone()[0]
    finally:
        conn.close()


def db_pr_list(owner: str, repo: str, status: str | None = None, *, limit=None, offset=0):
    conn = _db_connect()
    try:
        query = "SELECT id,title,source_branch,target_branch,status,created_at FROM pull_requests WHERE owner=? AND repo=?"
        params = [owner, repo]
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY id DESC"
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend((max(1, min(500, int(limit))), max(0, int(offset))))
        cur = conn.execute(query, params)
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


def db_repository_overview_get(owner, repo, commit):
    conn = _db_connect()
    try:
        row = conn.execute("SELECT overview_json FROM repository_overviews WHERE owner=? AND repo=? AND commit_hash=?", (owner, repo, commit)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def db_repository_overview_set(owner, repo, commit, overview_json):
    conn = _db_connect()
    try:
        conn.execute("INSERT INTO repository_overviews(owner,repo,commit_hash,overview_json) VALUES(?,?,?,?) ON CONFLICT(owner,repo,commit_hash) DO UPDATE SET overview_json=excluded.overview_json,updated_at=datetime('now')", (owner, repo, commit, overview_json))
        conn.execute("""DELETE FROM repository_overviews WHERE owner=? AND repo=? AND rowid NOT IN
            (SELECT rowid FROM repository_overviews WHERE owner=? AND repo=? ORDER BY updated_at DESC,rowid DESC LIMIT 10)""", (owner, repo, owner, repo))
    finally:
        conn.close()


def db_repository_languages_get(owner, repo, commit):
    conn = _db_connect()
    try:
        row = conn.execute("SELECT languages_json FROM repository_languages WHERE owner=? AND repo=? AND commit_hash=?", (owner, repo, commit)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def db_repository_languages_set(owner, repo, commit, languages_json):
    conn = _db_connect()
    try:
        conn.execute("INSERT INTO repository_languages(owner,repo,commit_hash,languages_json) VALUES(?,?,?,?) ON CONFLICT(owner,repo,commit_hash) DO UPDATE SET languages_json=excluded.languages_json,updated_at=datetime('now')", (owner, repo, commit, languages_json))
        conn.execute("""DELETE FROM repository_languages WHERE owner=? AND repo=? AND rowid NOT IN
            (SELECT rowid FROM repository_languages WHERE owner=? AND repo=? ORDER BY updated_at DESC,rowid DESC LIMIT 10)""", (owner, repo, owner, repo))
    finally:
        conn.close()


def db_ci_config_get(owner: str, repo: str):
    conn = _db_connect()
    try:
        row = conn.execute("SELECT config_json FROM ci_configs WHERE owner=? AND repo=?", (owner, repo)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def db_deployment_claim(run_id, owner, repo, commit, config_json=""):
    conn = _db_connect()
    try:
        cursor = conn.execute("""INSERT OR IGNORE INTO ci_deployments
            (run_id,owner,repo,commit_hash,config_json,pipeline_id) VALUES(?,?,?,?,?,?)""", (run_id, owner, repo, commit, config_json, json.loads(config_json or "{}").get("deployment_name") or json.loads(config_json or "{}").get("pipeline_id", "default")))
        return cursor.rowcount == 1
    finally:
        conn.close()


def db_deployment_finish(run_id, status, output, deployment_key=None):
    conn = _db_connect()
    try:
        conn.execute("""UPDATE ci_deployments SET status=?, output=?, notification='queued',
            finished_at=datetime('now') WHERE run_id=? AND pipeline_id=COALESCE(?,
                (SELECT pipeline_id FROM ci_deployments WHERE run_id=? ORDER BY id LIMIT 1))""", (status, output, run_id, deployment_key, run_id))
    finally:
        conn.close()


def db_deployment_get(run_id):
    conn = _db_connect()
    try:
        return conn.execute("SELECT status,output FROM ci_deployments WHERE run_id=?", (run_id,)).fetchone()
    finally:
        conn.close()


def db_deployment_recover():
    conn = _db_connect()
    try:
        conn.execute("UPDATE ci_deployments SET notification='delivery unknown' WHERE notification='sending'")
        conn.execute("""UPDATE ci_deployments SET status='interrupted', notification='queued',
            finished_at=datetime('now') WHERE status='running'""")
    finally:
        conn.close()


def db_deployment_email_record(run_id, deployment_key=None):
    conn = _db_connect()
    try:
        return conn.execute("""SELECT run_id,owner,repo,commit_hash,status,config_json,
            notification,started_at,finished_at FROM ci_deployments WHERE run_id=?
            AND (? IS NULL OR pipeline_id=?) ORDER BY id LIMIT 1""", (run_id, deployment_key, deployment_key)).fetchone()
    finally:
        conn.close()


def db_deployments_count(owner, repo, before=0):
    conn = _db_connect()
    try:
        return conn.execute("SELECT COUNT(*) FROM ci_deployments WHERE owner=? AND repo=? AND (?=0 OR id<?)",
            (owner, repo, before, before)).fetchone()[0]
    finally:
        conn.close()


def db_deployments_list(owner, repo, before=0, limit=25, offset=0):
    conn = _db_connect()
    try:
        return conn.execute("""SELECT d.id,d.run_id,d.commit_hash,d.status,d.started_at,
            d.finished_at,d.notification,d.config_json,r.id
            FROM ci_deployments d LEFT JOIN ci_runs r ON r.id=d.run_id
            WHERE d.owner=? AND d.repo=? AND (?=0 OR d.id<?)
            ORDER BY d.id DESC LIMIT ? OFFSET ?""", (owner, repo, before, before, limit, max(0, offset))).fetchall()
    finally:
        conn.close()


def db_deployment_detail(owner, repo, deployment_id):
    conn = _db_connect()
    try:
        return conn.execute("""SELECT d.id,d.run_id,d.commit_hash,d.status,d.started_at,
            d.finished_at,d.notification,d.config_json,r.id,d.output
            FROM ci_deployments d LEFT JOIN ci_runs r ON r.id=d.run_id
            WHERE d.owner=? AND d.repo=? AND d.id=?""", (owner, repo, deployment_id)).fetchone()
    finally:
        conn.close()


def db_deployment_email_pending():
    conn = _db_connect()
    try:
        return conn.execute("SELECT run_id,owner,repo FROM ci_deployments WHERE notification='queued'").fetchall()
    finally:
        conn.close()


def db_deployment_email_update(run_id, state, claim=False, deployment_key=None):
    conn = _db_connect()
    try:
        cursor = conn.execute("""UPDATE ci_deployments SET notification=? WHERE run_id=?
            AND pipeline_id=COALESCE(?,(SELECT pipeline_id FROM ci_deployments WHERE run_id=? ORDER BY id LIMIT 1))""" +
            (" AND notification='queued'" if claim else ""), (state, run_id, deployment_key, run_id))
        return cursor.rowcount == 1
    finally:
        conn.close()


def db_deployment_previous_result(owner, repo, run_id, deployment_key=None):
    conn = _db_connect()
    try:
        row = conn.execute("""SELECT status FROM ci_deployments WHERE owner=? AND repo=?
            AND pipeline_id=COALESCE(?,(SELECT pipeline_id FROM ci_deployments WHERE run_id=? ORDER BY id LIMIT 1))
            AND run_id<? AND status!='running' ORDER BY id DESC LIMIT 1""", (owner, repo, deployment_key, run_id, run_id)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def db_deployments_for_run(run_id):
    conn = _db_connect()
    try:
        return conn.execute("""SELECT id,pipeline_id,status,output,notification,config_json
            FROM ci_deployments WHERE run_id=? ORDER BY id""", (run_id,)).fetchall()
    finally:
        conn.close()


def db_email_settings_get():
    conn = _db_connect()
    try:
        row = conn.execute("SELECT value FROM server_settings WHERE key='smtp'").fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def db_display_name_get():
    conn = _db_connect()
    try:
        row = conn.execute("SELECT value FROM server_settings WHERE key='display_name'").fetchone()
        return row[0] if row else "pygithost"
    finally:
        conn.close()


def db_display_name_set(value):
    conn = _db_connect()
    try:
        conn.execute("INSERT INTO server_settings(key,value) VALUES('display_name',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (value,))
    finally:
        conn.close()


def db_email_settings_set(value: str):
    conn = _db_connect()
    try:
        if os.name == "posix":
            # SMTP credentials must not be readable by other OS users. SQLite
            # creates future sidecars using the database's permissions.
            os.chmod(DB_PATH, 0o600)
            for suffix in ("-wal", "-shm"):
                try:
                    os.chmod(str(DB_PATH) + suffix, 0o600)
                except FileNotFoundError:
                    pass
        conn.execute("INSERT INTO server_settings(key,value) VALUES('smtp',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (value,))
    finally:
        conn.close()


def db_ci_config_set(owner: str, repo: str, config_json: str, *, preferences=None) -> None:
    conn = _db_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if preferences is not None:
            conn.execute("INSERT INTO repository_ci_settings(owner,repo,settings_json) VALUES(?,?,?) ON CONFLICT(owner,repo) DO UPDATE SET settings_json=excluded.settings_json", (owner, repo, json.dumps(preferences)))
        conn.execute("""INSERT INTO ci_configs(owner,repo,config_json) VALUES(?,?,?)
            ON CONFLICT(owner,repo) DO UPDATE SET config_json=excluded.config_json, updated_at=datetime('now')""",
            (owner, repo, config_json))
        _db_ci_cleanup_artifacts(conn, owner, repo)
        _db_ci_prune_completed(conn, owner, repo)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def db_ci_preferences_get(owner=None, repo=None):
    from .ci_preferences import read
    conn = _db_connect()
    try:
        return read(conn, owner, repo)
    finally:
        conn.close()


def db_ci_preferences_set(values, owner=None, repo=None):
    from .ci_preferences import validate
    values = validate(values)
    conn = _db_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if owner is None:
            conn.execute("INSERT INTO server_settings(key,value) VALUES('ci_defaults',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(values),))
        else:
            conn.execute("INSERT INTO repository_ci_settings(owner,repo,settings_json) VALUES(?,?,?) ON CONFLICT(owner,repo) DO UPDATE SET settings_json=excluded.settings_json", (owner, repo, json.dumps(values)))
        _db_ci_cleanup_artifacts(conn, owner, repo)
        repositories = [(owner, repo)] if owner is not None else conn.execute("SELECT DISTINCT owner,repo FROM ci_runs").fetchall()
        for item_owner, item_repo in repositories:
            _db_ci_prune_completed(conn, item_owner, item_repo)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def db_ci_run_create(owner: str, repo: str, event: str, branch: str, commit_hash: str, payload_json: str, config_json: str = "", notification: str = "") -> int:
    conn = _db_connect()
    try:
        cur = conn.execute("INSERT INTO ci_runs(owner,repo,event,branch,commit_hash,payload_json,config_json,notification) VALUES(?,?,?,?,?,?,?,?)",
            (owner, repo, event, branch, commit_hash, payload_json, config_json, notification))
        return int(cur.lastrowid)
    finally:
        conn.close()


def db_ci_run_update(run_id: int, **values) -> None:
    allowed = {"status", "output", "truncated", "return_code", "started_at", "finished_at", "phase", "reason", "notification", "warnings"}
    values = {key: val for key, val in values.items() if key in allowed}
    if not values:
        return
    conn = _db_connect()
    try:
        cols = ", ".join(f"{key}=?" for key in values)
        conn.execute(f"UPDATE ci_runs SET {cols} WHERE id=?", (*values.values(), int(run_id)))
        if values.get("status") in {"success", "failed", "timed_out", "interrupted", "cancelled"}:
            row = conn.execute("SELECT owner,repo FROM ci_runs WHERE id=?", (int(run_id),)).fetchone()
            if row:
                _db_ci_prune_completed(conn, row[0], row[1])
    finally:
        conn.close()


def db_ci_runs_count(owner, repo, *, status="", event="", branch="", query="", before=None, warnings=""):
    conn = _db_connect()
    try:
        conditions, params = ["owner=?", "repo=?"], [owner, repo]
        if warnings in ("yes", "no"):
            conditions.append("warnings!=''" if warnings == "yes" else "warnings=''")
        if before is not None:
            conditions.append("id<?")
            params.append(before)
        for column, value in (("status", status), ("event", event), ("branch", branch)):
            if value:
                conditions.append(f"{column}=?")
                params.append(value)
        query = (query or "").strip().lower()[:128]
        if query:
            pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            conditions.append("(CAST(id AS TEXT) LIKE ? ESCAPE '\\' OR lower(commit_hash) LIKE ? ESCAPE '\\' OR lower(output) LIKE ? ESCAPE '\\')")
            params.extend((pattern, pattern, pattern))
        return conn.execute(f"SELECT COUNT(*) FROM ci_runs WHERE {' AND '.join(conditions)}", params).fetchone()[0]
    finally:
        conn.close()


def db_ci_runs_list(
    owner: str,
    repo: str,
    limit: int = 100,
    *,
    status: str = "",
    event: str = "",
    branch: str = "",
    query: str = "",
    summary: bool = False,
    before: int | None = None,
    offset: int = 0,
    warnings: str = "",
    include_warnings: bool = False,
    include_pipeline: bool = False,
):
    conn = _db_connect()
    try:
        conditions = ["owner=?", "repo=?"]
        params = [owner, repo]
        if warnings in ("yes", "no"):
            conditions.append("warnings!=''" if warnings == "yes" else "warnings=''")
        if before is not None:
            conditions.append("id<?")
            params.append(before)
        for column, value in (("status", status), ("event", event), ("branch", branch)):
            if value:
                conditions.append(f"{column}=?")
                params.append(value)
        query = (query or "").strip().lower()[:128]
        if query:
            escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = f"%{escaped}%"
            conditions.append(
                "(CAST(id AS TEXT) LIKE ? ESCAPE '\\' OR "
                "lower(commit_hash) LIKE ? ESCAPE '\\' OR lower(output) LIKE ? ESCAPE '\\')"
            )
            params.extend((pattern, pattern, pattern))
        params.append(max(1, min(int(limit), 500)))
        params.append(max(0, int(offset)))
        output_column = "''" if summary else "output"
        pipeline_column = ",COALESCE(json_extract(payload_json,'$.pipeline_id'),'default')" if include_pipeline else ""
        return conn.execute(
            f"SELECT id,event,branch,commit_hash,status,{output_column},truncated,return_code,created_at,started_at,finished_at{',warnings' if include_warnings else ''}{pipeline_column} "
            f"FROM ci_runs WHERE {' AND '.join(conditions)} ORDER BY id DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
    finally:
        conn.close()


def db_ci_run_get(owner: str, repo: str, run_id: int):
    conn = _db_connect()
    try:
        return conn.execute("SELECT id,event,branch,commit_hash,status,output,truncated,return_code,created_at,started_at,finished_at FROM ci_runs WHERE owner=? AND repo=? AND id=?", (owner, repo, int(run_id))).fetchone()
    finally:
        conn.close()


def db_ci_run_metadata(owner: str, repo: str, run_id: int):
    conn = _db_connect()
    try:
        row = conn.execute("SELECT payload_json,config_json,phase,reason,notification,warnings FROM ci_runs WHERE owner=? AND repo=? AND id=?", (owner, repo, run_id)).fetchone()
        return dict(zip(("payload", "config", "phase", "reason", "notification", "warnings"), row)) if row else None
    finally:
        conn.close()


def db_ci_steps_set(run_id, steps_json):
    conn = _db_connect()
    try:
        conn.execute("INSERT INTO ci_steps VALUES(?,?) ON CONFLICT(run_id) DO UPDATE SET steps_json=excluded.steps_json", (run_id, steps_json))
    finally:
        conn.close()


def db_ci_steps_get(run_id):
    conn = _db_connect()
    try:
        row = conn.execute("SELECT steps_json FROM ci_steps WHERE run_id=?", (run_id,)).fetchone()
        return row[0] if row else "[]"
    finally:
        conn.close()


def _db_ci_retention(conn, owner, repo):
    from .ci_preferences import read, retention, legacy_retention
    row = conn.execute("SELECT config_json FROM ci_configs WHERE owner=? AND repo=?", (owner, repo)).fetchone()
    global_values, repository_values = read(conn, owner, repo)
    return retention(global_values, repository_values, legacy_retention(json.loads(row[0]) if row else {}))


def _db_ci_cleanup_artifacts(conn, owner=None, repo=None):
    conditions, params = (" WHERE r.owner=? AND r.repo=?", (owner, repo)) if owner is not None else ("", ())
    repositories = conn.execute("SELECT DISTINCT r.owner,r.repo FROM ci_artifacts a JOIN ci_runs r ON r.id=a.run_id" + conditions, params).fetchall()
    for artifact_owner, artifact_repo in repositories:
        config = _db_ci_retention(conn, artifact_owner, artifact_repo)
        days = config.get("artifact_retention_days", 7)
        count = config.get("artifact_retention_count", 0)
        if days:
            conn.execute("""DELETE FROM ci_artifacts WHERE run_id IN
                (SELECT id FROM ci_runs WHERE owner=? AND repo=?)
                AND created_at <= datetime('now', ?)""", (artifact_owner, artifact_repo, f"-{days} days"))
        if count:
            conn.execute("""DELETE FROM ci_artifacts WHERE run_id IN
                (SELECT id FROM ci_runs WHERE owner=? AND repo=?) AND run_id NOT IN
                (SELECT a.run_id FROM ci_artifacts a JOIN ci_runs r ON r.id=a.run_id
                 WHERE r.owner=? AND r.repo=? ORDER BY a.run_id DESC LIMIT ?)""",
                (artifact_owner, artifact_repo, artifact_owner, artifact_repo, count))


def db_ci_artifact_set(run_id, archive):
    conn = _db_connect()
    try:
        conn.execute("INSERT OR REPLACE INTO ci_artifacts(run_id,archive) VALUES(?,?)", (run_id, archive))
        _db_ci_cleanup_artifacts(conn)
    finally:
        conn.close()


def db_ci_artifact_get(owner, repo, run_id, *, content=False):
    conn = _db_connect()
    try:
        _db_ci_cleanup_artifacts(conn, owner, repo)
        column = "a.archive" if content else "length(a.archive)"
        row = conn.execute(f"SELECT {column} FROM ci_artifacts a JOIN ci_runs r ON r.id=a.run_id WHERE r.owner=? AND r.repo=? AND r.id=?", (owner, repo, run_id)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def db_ci_artifacts_count(owner, repo, before=None):
    conn = _db_connect()
    try:
        _db_ci_cleanup_artifacts(conn, owner, repo)
        return conn.execute("SELECT COUNT(*) FROM ci_artifacts a JOIN ci_runs r ON r.id=a.run_id WHERE r.owner=? AND r.repo=?" +
            (" AND r.id<?" if before is not None else ""), (owner, repo, before) if before is not None else (owner, repo)).fetchone()[0]
    finally:
        conn.close()


def db_ci_artifacts_list(owner, repo, *, before=None, limit=50, offset=0):
    conn = _db_connect()
    try:
        _db_ci_cleanup_artifacts(conn, owner, repo)
        days = _db_ci_retention(conn, owner, repo).get("artifact_retention_days", 7)
        conditions, params = ["r.owner=?", "r.repo=?"], [owner, repo]
        if before is not None:
            conditions.append("r.id<?")
            params.append(before)
        params.append(max(1, min(int(limit), 100)))
        params.append(max(0, int(offset)))
        return conn.execute(f"""SELECT r.id,r.branch,r.commit_hash,r.status,r.event,
            a.created_at,length(a.archive),{'datetime(a.created_at, ?)' if days else 'NULL'}
            FROM ci_artifacts a JOIN ci_runs r ON r.id=a.run_id
            WHERE {' AND '.join(conditions)} ORDER BY r.id DESC LIMIT ? OFFSET ?""", ([f"+{days} days"] if days else []) + params).fetchall()
    finally:
        conn.close()


def db_ci_merge_check(owner, repo, pr_id, base, head, pipeline_id="default"):
    """Only the newest run for this exact PR base/head pair counts."""
    conn = _db_connect()
    try:
        row = conn.execute("""SELECT id,status FROM ci_runs WHERE owner=? AND repo=?
            AND event IN ('pull_request','pull_request_updated','pull_request_reopened')
            AND json_extract(payload_json,'$.pr_number')=?
            AND json_extract(payload_json,'$.base_commit')=?
            AND json_extract(payload_json,'$.head_commit')=?
            AND COALESCE(json_extract(payload_json,'$.pipeline_id'),'default')=?
            ORDER BY id DESC LIMIT 1""", (owner, repo, pr_id, base, head, pipeline_id)).fetchone()
        return row
    finally:
        conn.close()


def db_ci_previous_result(owner: str, repo: str, branch: str, event: str, run_id: int, pr_number=None):
    conn = _db_connect()
    try:
        if pr_number is not None and event != "pull_request_merged":
            row = conn.execute("SELECT status FROM ci_runs WHERE owner=? AND repo=? AND event IN ('pull_request','pull_request_updated','pull_request_reopened') AND json_extract(payload_json,'$.pr_number')=? AND COALESCE(json_extract(payload_json,'$.pipeline_id'),'default')=(SELECT COALESCE(json_extract(payload_json,'$.pipeline_id'),'default') FROM ci_runs WHERE id=?) AND id<? AND status IN ('success','failed','timed_out') ORDER BY id DESC LIMIT 1", (owner, repo, pr_number, run_id, run_id)).fetchone()
        else:
            row = conn.execute("SELECT status FROM ci_runs WHERE owner=? AND repo=? AND branch=? AND event=? AND COALESCE(json_extract(payload_json,'$.pipeline_id'),'default')=(SELECT COALESCE(json_extract(payload_json,'$.pipeline_id'),'default') FROM ci_runs WHERE id=?) AND id<? AND status IN ('success','failed','timed_out') ORDER BY id DESC LIMIT 1", (owner, repo, branch, event, run_id, run_id)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def db_ci_pending_notifications():
    conn = _db_connect()
    try:
        return conn.execute("SELECT id,owner,repo,event,branch,commit_hash,payload_json FROM ci_runs WHERE notification='queued' AND status NOT IN ('queued','running') ORDER BY id").fetchall()
    finally:
        conn.close()


def db_prs_for_target(owner: str, repo: str, branch: str):
    conn = _db_connect()
    try:
        return conn.execute("SELECT id,source_branch FROM pull_requests WHERE owner=? AND repo=? AND target_branch=? AND status='open'", (owner, repo, branch)).fetchall()
    finally:
        conn.close()


def db_ci_latest_run(owner: str, repo: str, branch: str | None = None):
    conn = _db_connect()
    try:
        condition = " AND branch=? AND event IN ('push','manual','pull_request_merged')" if branch is not None else ""
        params = (owner, repo, branch) if branch is not None else (owner, repo)
        return conn.execute(f"SELECT id,status,event,branch,commit_hash,created_at FROM ci_runs WHERE owner=? AND repo=?{condition} ORDER BY id DESC LIMIT 1", params).fetchone()
    finally:
        conn.close()


def db_ci_queued_runs():
    conn = _db_connect()
    try:
        return conn.execute("SELECT id,owner,repo,event,branch,commit_hash,payload_json FROM ci_runs WHERE status='queued' ORDER BY id").fetchall()
    finally:
        conn.close()


def db_ci_recover_runs():
    conn = _db_connect()
    try:
        for run_id, steps_json in conn.execute("SELECT s.run_id,s.steps_json FROM ci_steps s JOIN ci_runs r ON r.id=s.run_id WHERE r.status='running'").fetchall():
            steps = json.loads(steps_json)
            for step in steps:
                if step["status"] == "running":
                    step.update(status="interrupted", finished_at=datetime.now(timezone.utc).isoformat(), return_code=-1)
                elif step["status"] == "pending":
                    step["status"] = "skipped"
            conn.execute("UPDATE ci_steps SET steps_json=? WHERE run_id=?", (json.dumps(steps), run_id))
        conn.execute("UPDATE ci_runs SET status='interrupted', finished_at=datetime('now') WHERE status='running'")
        conn.execute("UPDATE ci_runs SET notification='delivery unknown after restart (not retried)' WHERE notification='sending'")
        for owner, repo in conn.execute("SELECT DISTINCT owner,repo FROM ci_runs").fetchall():
            _db_ci_prune_completed(conn, owner, repo)
    finally:
        conn.close()


def _db_ci_prune_completed(conn, owner: str, repo: str) -> None:
    config = _db_ci_retention(conn, owner, repo)
    retention = config.get("run_retention_count", max(0, min(10000, int(os.environ.get("PYGITHOST_CI_RETENTION", "100")))))
    _db_ci_cleanup_artifacts(conn, owner, repo)
    if not retention:
        return
    conn.execute("""DELETE FROM ci_runs AS old
        WHERE old.owner=? AND old.repo=? AND old.status NOT IN ('queued','running')
          AND old.notification NOT IN ('queued','sending')
          AND NOT EXISTS (SELECT 1 FROM ci_artifacts a WHERE a.run_id=old.id)
          AND old.id NOT IN (SELECT newer.id FROM ci_runs AS newer
            WHERE newer.owner=? AND newer.repo=? AND newer.status NOT IN ('queued','running')
            ORDER BY newer.id DESC LIMIT ?)""", (owner, repo, owner, repo, retention))


def db_prs_for_source(owner: str, repo: str, branch: str):
    conn = _db_connect()
    try:
        return conn.execute("SELECT id,target_branch FROM pull_requests WHERE owner=? AND repo=? AND source_branch=? AND status='open'", (owner, repo, branch)).fetchall()
    finally:
        conn.close()


def db_pr_reopen(pr_id: int) -> None:
    conn = _db_connect()
    try:
        conn.execute("UPDATE pull_requests SET status='open', closed_at=NULL WHERE id=? AND status='closed'", (int(pr_id),))
    finally:
        conn.close()
