"""SQLite persistence for users, sessions, tokens, and pull requests."""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Protocol, TypeAlias, TypedDict, cast, overload

from .config import AppConfig
from .database_types import (
    AuthInfo,
    CIArtifactRow,
    CIRunLatestRow,
    CIRunListPipelineRow,
    CIRunListRow,
    CIRunListWarningsPipelineRow,
    CIRunListWarningsRow,
    CIRunMetadata,
    CIRunNotificationRow,
    CIRunRow,
    CIRunStatusRow,
    CommentIdentityRow,
    CommentRow,
    DeploymentEmailRow,
    DeploymentListRow,
    DeploymentRow,
    DeploymentRunRow,
    DiscussionListRow,
    DiscussionRow,
    IssueListRow,
    IssueRow,
    JSONObject,
    PullRequestBranchRow,
    PullRequestListRow,
    PullRequestRow,
    RetentionConfig,
    SessionRow,
    SQLValue,
    TokenAuthRow,
    TokenListRow,
    UserAuthRow,
    UserRow,
    decode_json_object,
)
from .rendering import str_t

DB_PATH = ""
SESSION_TTL_SECONDS = 12 * 60 * 60

RetentionHeadResolver: TypeAlias = Callable[[str, str], str | None]
_retention_head_resolver: RetentionHeadResolver | None = None


def configure_retention_head_resolver(resolver: RetentionHeadResolver | None) -> None:
    """Register how cleanup resolves the current default-branch commit.

    Cleanup deletes only when the cached retention policy was verified at the
    commit this resolver reports now. ``None`` keeps cleanup paused, which is
    the safe result when the repository cannot be read.
    """
    global _retention_head_resolver
    _retention_head_resolver = resolver


def _db_ci_retention_head(owner: str, repo: str) -> str | None:
    resolver = _retention_head_resolver
    if resolver is None:
        return None
    return resolver(owner, repo)


class _TransactionInfo(TypedDict):
    connection: int
    operation: str
    thread: int
    pid: int
    started: float


class _SQLParameterSequence(Protocol):
    """A positional SQLite parameter sequence, as accepted by the driver."""

    def __len__(self) -> int: ...

    def __getitem__(self, index: int, /) -> object: ...


SQLParameters: TypeAlias = _SQLParameterSequence | Mapping[str, object]


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


_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")


def _safe_seg(value: str) -> bool:
    """Match the server's username rules without importing the application."""
    return bool(value) and _SAFE_SEGMENT.match(value) is not None and ".." not in value


_transactions: dict[int, _TransactionInfo] = {}
_transactions_lock = threading.Lock()


def sqlite_busy(exc: BaseException) -> bool:
    """Only SQLite's BUSY family is safe to wait for; not arbitrary SQL errors."""
    code: int = getattr(exc, "sqlite_errorcode", 0)
    return isinstance(exc, sqlite3.OperationalError) and code & 255 == sqlite3.SQLITE_BUSY


class _Connection(sqlite3.Connection):
    """Parameter-free diagnostics for long transactions and lock failures."""

    operation: str

    def execute(self, sql: str, parameters: SQLParameters = ()) -> sqlite3.Cursor:
        started = time.monotonic()
        try:
            return super().execute(sql, parameters)
        except sqlite3.Error as exc:
            if sqlite_busy(exc):
                with _transactions_lock:
                    holders = [
                        dict(info, age_seconds=round(time.monotonic() - info["started"], 3))
                        for info in _transactions.values()
                    ]
                logging.getLogger(__name__).warning(
                    "SQLite busy: connection=%s operation=%s thread=%s active_transactions=%s",
                    id(self),
                    getattr(self, "operation", "unknown"),
                    threading.get_ident(),
                    holders,
                )
            raise
        finally:
            with _transactions_lock:
                if self.in_transaction:
                    _transactions.setdefault(
                        id(self),
                        {
                            "connection": id(self),
                            "operation": getattr(self, "operation", "unknown"),
                            "thread": threading.get_ident(),
                            "pid": os.getpid(),
                            "started": started,
                        },
                    )
                else:
                    _transactions.pop(id(self), None)
            elapsed = time.monotonic() - started
            if elapsed >= 1:
                logging.getLogger(__name__).warning(
                    "Slow SQLite statement: connection=%s operation=%s elapsed_seconds=%.3f",
                    id(self),
                    getattr(self, "operation", "unknown"),
                    elapsed,
                )

    def _transaction_end(self) -> None:
        with _transactions_lock:
            info = _transactions.pop(id(self), None)
        if info and time.monotonic() - info["started"] >= 1:
            logging.getLogger(__name__).warning(
                "Long SQLite transaction: connection=%s operation=%s elapsed_seconds=%.3f",
                id(self),
                info["operation"],
                time.monotonic() - info["started"],
            )

    def commit(self) -> None:
        super().commit()
        self._transaction_end()

    def rollback(self) -> None:
        super().rollback()
        self._transaction_end()

    def close(self) -> None:
        try:
            super().close()
        finally:
            self._transaction_end()


def _db_connect() -> _Connection:
    _ensure_dir(DB_PATH)
    operation = sys._getframe(1).f_code.co_name
    for attempt in range(3):
        conn = sqlite3.connect(DB_PATH, timeout=5, isolation_level=None, factory=_Connection)
        conn.operation = operation
        try:
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            return conn
        except BaseException as exc:
            conn.close()
            if not sqlite_busy(exc) or attempt == 2:
                raise
            # No application SQL has run: reopening cannot replay a mutation.
            logging.getLogger(__name__).warning(
                "Retrying SQLite connection setup: operation=%s attempt=%s", operation, attempt + 1
            )
            time.sleep(0.05 * (2**attempt))
    raise RuntimeError("SQLite connection setup failed.")


def _db_migrate_pr_author_nullable(conn: _Connection) -> None:
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
        original_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='pull_requests' COLLATE NOCASE"
        ).fetchone()[0]
        new_sql, changed = re.subn(
            r'((?:"author_user_id"|`author_user_id`|\[author_user_id\]|\bauthor_user_id\b)\s+(?:INTEGER|INT|BIGINT)\s+)NOT\s+NULL\b',
            r"\1",
            original_sql,
            count=1,
            flags=re.IGNORECASE,
        )
        if changed != 1:
            raise ValueError(
                "Unsupported legacy pull-request author definition; database was not modified."
            )
        temporary = "__pull_requests_nullable_" + secrets.token_hex(8)
        new_sql, renamed = re.subn(
            r'^(\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?)(?:"pull_requests"|`pull_requests`|\[pull_requests\]|pull_requests)(?=\s|\()',
            lambda match: match[1] + '"' + temporary + '"',
            new_sql,
            count=1,
            flags=re.IGNORECASE,
        )
        if renamed != 1:
            raise ValueError(
                "Unsupported legacy pull-request table definition; database was not modified."
            )
        objects = conn.execute(
            "SELECT sql FROM sqlite_master WHERE tbl_name='pull_requests' COLLATE NOCASE AND type IN ('index','trigger') AND sql IS NOT NULL"
        ).fetchall()
        sequence = conn.execute(
            "SELECT seq FROM sqlite_sequence WHERE name='pull_requests' COLLATE NOCASE"
        ).fetchone()
        existing_violations = set(conn.execute("PRAGMA foreign_key_check").fetchall())
        names = ",".join(
            '"' + column[1].replace('"', '""') + '"' for column in columns if not column[6]
        )
        conn.execute(new_sql)
        conn.execute(f'INSERT INTO "{temporary}" ({names}) SELECT {names} FROM pull_requests')
        conn.execute("DROP TABLE pull_requests")
        conn.execute(f'ALTER TABLE "{temporary}" RENAME TO pull_requests')
        for (sql,) in objects:
            conn.execute(sql)
        if sequence:
            conn.execute(
                "UPDATE sqlite_sequence SET seq=MAX(seq,?) WHERE name='pull_requests'",
                (sequence[0],),
            )
            conn.execute(
                "INSERT INTO sqlite_sequence(name,seq) SELECT 'pull_requests',? WHERE NOT EXISTS(SELECT 1 FROM sqlite_sequence WHERE name='pull_requests')",
                (sequence[0],),
            )
        if set(conn.execute("PRAGMA foreign_key_check").fetchall()) - existing_violations:
            raise sqlite3.IntegrityError(
                "Pull-request author migration would introduce a foreign-key violation."
            )
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
        mode = conn.execute("PRAGMA journal_mode=WAL;").fetchone()[0]
        if mode.lower() != "wal":
            raise RuntimeError("SQLite WAL initialization failed.")
        from .remote_ci import initialize_schema

        initialize_schema(conn)
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

        conn.execute("""CREATE TABLE IF NOT EXISTS api_mutations (
            user_id INTEGER NOT NULL,
            key_hash TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            request_id TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'pending',
            status INTEGER,
            response_json TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            finished_at TEXT,
            PRIMARY KEY(user_id,key_hash)
        )""")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_api_mutations_created ON api_mutations(created_at)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tokens_status ON tokens(user_id, is_active, expires_at, revoked_at)"
        )
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
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, expires_at, revoked_at)"
        )
        conn.execute("DELETE FROM sessions WHERE expires_at <= datetime('now', 'localtime')")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                actor TEXT,
                actor_user_id INTEGER,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                target TEXT,
                detail TEXT,
                ip TEXT,
                user_agent TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action, created_at)"
        )
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
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pr_repo ON pull_requests(owner, repo, status, id)"
        )
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner TEXT NOT NULL,
                repo TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL DEFAULT '',
                author_user_id INTEGER,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT,
                closed_at TEXT,
                FOREIGN KEY(author_user_id) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_issue_repo ON issues(owner, repo, status, id)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS issue_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issue_id INTEGER NOT NULL,
                author_user_id INTEGER,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                edited_at TEXT,
                FOREIGN KEY(issue_id) REFERENCES issues(id) ON DELETE CASCADE,
                FOREIGN KEY(author_user_id) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_issue_comments_issue ON issue_comments(issue_id, id)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS discussions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner TEXT NOT NULL,
                repo TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'General',
                title TEXT NOT NULL,
                body TEXT NOT NULL DEFAULT '',
                author_user_id INTEGER,
                locked INTEGER NOT NULL DEFAULT 0,
                locked_by INTEGER,
                locked_at TEXT,
                answered_comment_id INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT,
                FOREIGN KEY(author_user_id) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_discussion_repo ON discussions(owner, repo, category, id)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS discussion_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                discussion_id INTEGER NOT NULL,
                author_user_id INTEGER,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                edited_at TEXT,
                FOREIGN KEY(discussion_id) REFERENCES discussions(id) ON DELETE CASCADE,
                FOREIGN KEY(author_user_id) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_discussion_comments_discussion ON discussion_comments(discussion_id, id)"
        )
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
        conn.execute("""CREATE TABLE IF NOT EXISTS ci_retention_policy (
            owner TEXT NOT NULL, repo TEXT NOT NULL, policy_json TEXT NOT NULL,
            commit_hash TEXT NOT NULL DEFAULT '', PRIMARY KEY(owner, repo))""")
        retention_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(ci_retention_policy)")
        }
        if "commit_hash" not in retention_columns:
            # Rows from older servers have no verified commit and therefore pause
            # cleanup until the next successful default-branch refresh.
            conn.execute(
                "ALTER TABLE ci_retention_policy ADD COLUMN commit_hash TEXT NOT NULL DEFAULT ''"
            )
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
                conn.execute(
                    f"ALTER TABLE ci_deployments ADD COLUMN {name} TEXT NOT NULL DEFAULT ''"
                )
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
        if "steps_json" not in {
            row[1] for row in conn.execute("PRAGMA table_info(ci_deployments)")
        }:
            conn.execute(
                "ALTER TABLE ci_deployments ADD COLUMN steps_json TEXT NOT NULL DEFAULT '[]'"
            )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS server_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        conn.execute("""CREATE TABLE IF NOT EXISTS server_favicon (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            content_type TEXT NOT NULL,
            data BLOB NOT NULL,
            updated_at TEXT NOT NULL DEFAULT (datetime('now')))""")
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
    finally:
        conn.close()


def _pbkdf2_hash_password(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def _token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def _require_lastrowid(cursor: sqlite3.Cursor) -> int:
    """Return the row id of a successful INSERT without type-narrowing noise."""
    rowid = cursor.lastrowid
    if rowid is None:
        raise RuntimeError("SQLite INSERT did not produce a row id.")
    return rowid


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


def db_get_user_by_username(username: str) -> UserAuthRow | None:
    conn = _db_connect()
    try:
        cur = conn.execute(
            "SELECT id, username, pass_salt, pass_hash, is_admin, is_active FROM users WHERE username=?",
            (username,),
        )
        return cast(UserAuthRow | None, cur.fetchone())
    finally:
        conn.close()


def db_get_user_by_id(user_id: int) -> UserRow | None:
    conn = _db_connect()
    try:
        cur = conn.execute(
            "SELECT id, username, is_admin, is_active, created_at FROM users WHERE id=?",
            (user_id,),
        )
        return cast(UserRow | None, cur.fetchone())
    finally:
        conn.close()


def db_list_users() -> list[UserRow]:
    conn = _db_connect()
    try:
        cur = conn.execute(
            "SELECT id, username, is_admin, is_active, created_at FROM users ORDER BY username COLLATE NOCASE"
        )
        return cast(list[UserRow], cur.fetchall())
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


def db_verify_password(username: str, password: str) -> AuthInfo | None:
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
    expires_at = (datetime.now() + timedelta(seconds=SESSION_TTL_SECONDS)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
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


def db_verify_session(session_token: str | None) -> AuthInfo | None:
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
        row = cast(SessionRow | None, cur.fetchone())
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


def db_create_token(
    user_id: int, name: str, scopes: str = "read,write", expires_at: str | None = None
) -> str:
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


def db_list_tokens_for_user(user_id: int) -> list[TokenListRow]:
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
        return cast(list[TokenListRow], cur.fetchall())
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


def db_audit_append(
    action: str,
    outcome: str = "success",
    *,
    actor: str | None = None,
    actor_user_id: int | None = None,
    target: str | None = None,
    detail: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Persist one security-relevant event. Never accepts passwords or tokens."""

    def clip(value: object, limit: int) -> str | None:
        if value is None:
            return None
        text = str(value).replace("\x00", "")
        return text[:limit]

    conn = _db_connect()
    try:
        conn.execute(
            """INSERT INTO audit_events(actor,actor_user_id,action,outcome,target,detail,ip,user_agent)
               VALUES(?,?,?,?,?,?,?,?)""",
            (
                clip(actor, 256),
                actor_user_id,
                clip(action, 64),
                clip(outcome, 32),
                clip(target, 512),
                clip(detail, 1000),
                clip(ip, 64),
                clip(user_agent, 512),
            ),
        )
    finally:
        conn.close()


def db_audit_list(limit: int = 100, action: str | None = None) -> list[dict[str, object]]:
    """Return the most recent audit events, newest first (tests and admin tools)."""
    limit = max(1, min(int(limit), 1000))
    conn = _db_connect()
    try:
        if action:
            rows = conn.execute(
                """SELECT id,created_at,actor,actor_user_id,action,outcome,target,detail,ip,user_agent
                   FROM audit_events WHERE action=? ORDER BY id DESC LIMIT ?""",
                (action, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT id,created_at,actor,actor_user_id,action,outcome,target,detail,ip,user_agent
                   FROM audit_events ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
    finally:
        conn.close()
    keys = (
        "id",
        "created_at",
        "actor",
        "actor_user_id",
        "action",
        "outcome",
        "target",
        "detail",
        "ip",
        "user_agent",
    )
    return [dict(zip(keys, row, strict=True)) for row in rows]


def _token_info_from_row(row: TokenAuthRow | None) -> AuthInfo | None:
    if not row:
        return None
    uid, uname, is_admin, user_active, scopes, token_active, expires_at, revoked_at = row
    if not user_active or not token_active or revoked_at:
        return None
    if _token_is_expired(expires_at):
        return None
    scopes_set = {s.strip().lower() for s in (scopes or "").split(",") if s.strip()}
    return {"user_id": uid, "username": uname, "is_admin": bool(is_admin), "scopes": scopes_set}


def db_verify_token(username: str, token: str) -> AuthInfo | None:
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
        row = cast(TokenAuthRow | None, cur.fetchone())
    finally:
        conn.close()
    return _token_info_from_row(row)


def db_verify_token_any_user(token: str) -> AuthInfo | None:
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
        row = cast(TokenAuthRow | None, cur.fetchone())
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
        default_password = os.environ.get(
            "PYGITHOST_DEFAULT_ADMIN_PASSWORD"
        ) or secrets.token_urlsafe(18)
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
        return _require_lastrowid(cur)
    finally:
        conn.close()


def db_pr_comment_list(pr_id: int) -> list[CommentRow]:
    conn = _db_connect()
    try:
        return cast(
            list[CommentRow],
            conn.execute(
                """
                SELECT c.id, c.author_user_id, u.username, c.body, c.created_at, c.edited_at
                FROM pr_comments c LEFT JOIN users u ON u.id=c.author_user_id
                WHERE c.pr_id=? ORDER BY c.id
                """,
                (int(pr_id),),
            ).fetchall(),
        )
    finally:
        conn.close()


def db_pr_comment_get(pr_id: int, comment_id: int) -> CommentIdentityRow | None:
    conn = _db_connect()
    try:
        return cast(
            CommentIdentityRow | None,
            conn.execute(
                "SELECT id, pr_id, author_user_id, body FROM pr_comments WHERE id=? AND pr_id=?",
                (int(comment_id), int(pr_id)),
            ).fetchone(),
        )
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


def db_pr_comment_counts(pr_ids: Iterable[int | str]) -> dict[int, int]:
    ids = [int(value) for value in pr_ids if str(value).isdigit()]
    if not ids:
        return {}
    conn = _db_connect()
    try:
        marks = ",".join("?" * len(ids))
        rows = cast(
            list[tuple[int, int]],
            conn.execute(
                f"SELECT pr_id, COUNT(*) FROM pr_comments WHERE pr_id IN ({marks}) GROUP BY pr_id",
                ids,
            ).fetchall(),
        )
        return {int(pr_id): int(count) for pr_id, count in rows}
    finally:
        conn.close()


def db_pr_update_text(pr_id: int, title: str, body: str) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "UPDATE pull_requests SET title=?, body=? WHERE id=?", (title, body, int(pr_id))
        )
    finally:
        conn.close()


def db_pr_comment_count(pr_id: int) -> int:
    conn = _db_connect()
    try:
        return int(
            conn.execute(
                "SELECT COUNT(*) FROM pr_comments WHERE pr_id=?", (int(pr_id),)
            ).fetchone()[0]
        )
    finally:
        conn.close()


# ---------- Issue DB helpers ----------
def db_issue_create(
    owner: str, repo: str, title: str, body: str, author_user_id: int | None
) -> int:
    conn = _db_connect()
    try:
        cur = conn.execute(
            "INSERT INTO issues(owner, repo, title, body, author_user_id, status) VALUES(?,?,?,?,?, 'open')",
            (owner, repo, title, body, int(author_user_id) if author_user_id is not None else None),
        )
        return _require_lastrowid(cur)
    finally:
        conn.close()


def db_issue_get(issue_id: int) -> IssueRow | None:
    conn = _db_connect()
    try:
        return cast(
            IssueRow | None,
            conn.execute(
                """
                SELECT i.id, i.owner, i.repo, i.title, i.body, i.author_user_id, u.username,
                       i.status, i.created_at, i.updated_at, i.closed_at
                FROM issues i LEFT JOIN users u ON u.id=i.author_user_id
                WHERE i.id=?
                """,
                (int(issue_id),),
            ).fetchone(),
        )
    finally:
        conn.close()


def db_issue_list(
    owner: str, repo: str, status: str | None = "open", limit: int = 50, offset: int = 0
) -> list[IssueListRow]:
    conn = _db_connect()
    try:
        if status is None:
            where = ""
            params: list[SQLValue] = [owner, repo]
        else:
            where = "AND i.status=?"
            params = [owner, repo, status]
        return cast(
            list[IssueListRow],
            conn.execute(
                f"""
                SELECT i.id, i.title, i.status, i.created_at, i.author_user_id, u.username
                FROM issues i LEFT JOIN users u ON u.id=i.author_user_id
                WHERE i.owner=? AND i.repo=? {where}
                ORDER BY i.id DESC LIMIT ? OFFSET ?
                """,
                [*params, int(limit), int(offset)],
            ).fetchall(),
        )
    finally:
        conn.close()


def db_issue_count(owner: str, repo: str, status: str | None = None) -> int:
    conn = _db_connect()
    try:
        if status is None:
            row = conn.execute(
                "SELECT COUNT(*) FROM issues WHERE owner=? AND repo=?", (owner, repo)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) FROM issues WHERE owner=? AND repo=? AND status=?",
                (owner, repo, status),
            ).fetchone()
        return int(row[0])
    finally:
        conn.close()


def db_issue_close(issue_id: int) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "UPDATE issues SET status='closed', closed_at=datetime('now'), updated_at=datetime('now') WHERE id=?",
            (int(issue_id),),
        )
    finally:
        conn.close()


def db_issue_reopen(issue_id: int) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "UPDATE issues SET status='open', closed_at=NULL, updated_at=datetime('now') WHERE id=?",
            (int(issue_id),),
        )
    finally:
        conn.close()


def db_issue_update_text(issue_id: int, title: str, body: str) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "UPDATE issues SET title=?, body=?, updated_at=datetime('now') WHERE id=?",
            (title, body, int(issue_id)),
        )
    finally:
        conn.close()


def db_issue_comment_add(issue_id: int, author_user_id: int | None, body: str) -> int:
    conn = _db_connect()
    try:
        cur = conn.execute(
            "INSERT INTO issue_comments(issue_id, author_user_id, body) VALUES(?,?,?)",
            (int(issue_id), int(author_user_id) if author_user_id is not None else None, body),
        )
        conn.execute("UPDATE issues SET updated_at=datetime('now') WHERE id=?", (int(issue_id),))
        return _require_lastrowid(cur)
    finally:
        conn.close()


def db_issue_comment_list(issue_id: int) -> list[CommentRow]:
    conn = _db_connect()
    try:
        return cast(
            list[CommentRow],
            conn.execute(
                """
                SELECT c.id, c.author_user_id, u.username, c.body, c.created_at, c.edited_at
                FROM issue_comments c LEFT JOIN users u ON u.id=c.author_user_id
                WHERE c.issue_id=? ORDER BY c.id
                """,
                (int(issue_id),),
            ).fetchall(),
        )
    finally:
        conn.close()


def db_issue_comment_get(issue_id: int, comment_id: int) -> CommentIdentityRow | None:
    conn = _db_connect()
    try:
        return cast(
            CommentIdentityRow | None,
            conn.execute(
                "SELECT id, issue_id, author_user_id, body FROM issue_comments WHERE id=? AND issue_id=?",
                (int(comment_id), int(issue_id)),
            ).fetchone(),
        )
    finally:
        conn.close()


def db_issue_comment_update(comment_id: int, body: str) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "UPDATE issue_comments SET body=?, edited_at=datetime('now') WHERE id=?",
            (body, int(comment_id)),
        )
    finally:
        conn.close()


def db_issue_comment_delete(comment_id: int) -> None:
    conn = _db_connect()
    try:
        conn.execute("DELETE FROM issue_comments WHERE id=?", (int(comment_id),))
    finally:
        conn.close()


def db_issue_comment_counts(issue_ids: Iterable[int | str]) -> dict[int, int]:
    ids = [int(value) for value in issue_ids if str(value).isdigit()]
    if not ids:
        return {}
    conn = _db_connect()
    try:
        marks = ",".join("?" * len(ids))
        rows = cast(
            list[tuple[int, int]],
            conn.execute(
                f"SELECT issue_id, COUNT(*) FROM issue_comments WHERE issue_id IN ({marks}) GROUP BY issue_id",
                ids,
            ).fetchall(),
        )
        return {int(issue_id): int(count) for issue_id, count in rows}
    finally:
        conn.close()


def db_issue_comment_count(issue_id: int) -> int:
    conn = _db_connect()
    try:
        return int(
            conn.execute(
                "SELECT COUNT(*) FROM issue_comments WHERE issue_id=?", (int(issue_id),)
            ).fetchone()[0]
        )
    finally:
        conn.close()


# ---------- Discussion DB helpers ----------
def db_discussion_create(
    owner: str, repo: str, category: str, title: str, body: str, author_user_id: int | None
) -> int:
    conn = _db_connect()
    try:
        cur = conn.execute(
            "INSERT INTO discussions(owner, repo, category, title, body, author_user_id) VALUES(?,?,?,?,?,?)",
            (
                owner,
                repo,
                category,
                title,
                body,
                int(author_user_id) if author_user_id is not None else None,
            ),
        )
        return _require_lastrowid(cur)
    finally:
        conn.close()


def db_discussion_get(discussion_id: int) -> DiscussionRow | None:
    conn = _db_connect()
    try:
        return cast(
            DiscussionRow | None,
            conn.execute(
                """
                SELECT d.id, d.owner, d.repo, d.category, d.title, d.body, d.author_user_id, u.username,
                       d.locked, d.locked_by, d.answered_comment_id, d.created_at, d.updated_at
                FROM discussions d LEFT JOIN users u ON u.id=d.author_user_id
                WHERE d.id=?
                """,
                (int(discussion_id),),
            ).fetchone(),
        )
    finally:
        conn.close()


def db_discussion_list(
    owner: str, repo: str, category: str | None = None, limit: int = 50, offset: int = 0
) -> list[DiscussionListRow]:
    conn = _db_connect()
    try:
        if category:
            params: list[SQLValue] = [owner, repo, category]
            where = "AND d.category=?"
        else:
            params = [owner, repo]
            where = ""
        return cast(
            list[DiscussionListRow],
            conn.execute(
                f"""
                SELECT d.id, d.title, d.category, d.created_at, d.author_user_id, u.username, d.answered_comment_id
                FROM discussions d LEFT JOIN users u ON u.id=d.author_user_id
                WHERE d.owner=? AND d.repo=? {where}
                ORDER BY d.id DESC LIMIT ? OFFSET ?
                """,
                [*params, int(limit), int(offset)],
            ).fetchall(),
        )
    finally:
        conn.close()


def db_discussion_count(owner: str, repo: str, category: str | None = None) -> int:
    conn = _db_connect()
    try:
        if category:
            row = conn.execute(
                "SELECT COUNT(*) FROM discussions WHERE owner=? AND repo=? AND category=?",
                (owner, repo, category),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) FROM discussions WHERE owner=? AND repo=?", (owner, repo)
            ).fetchone()
        return int(row[0])
    finally:
        conn.close()


def db_discussion_update_text(discussion_id: int, category: str, title: str, body: str) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "UPDATE discussions SET category=?, title=?, body=?, updated_at=datetime('now') WHERE id=?",
            (category, title, body, int(discussion_id)),
        )
    finally:
        conn.close()


def db_discussion_set_locked(discussion_id: int, locked: bool, locked_by: int | None) -> None:
    conn = _db_connect()
    try:
        if locked:
            conn.execute(
                "UPDATE discussions SET locked=1, locked_by=?, locked_at=datetime('now'), updated_at=datetime('now') WHERE id=?",
                (int(locked_by) if locked_by is not None else None, int(discussion_id)),
            )
        else:
            conn.execute(
                "UPDATE discussions SET locked=0, locked_by=NULL, locked_at=NULL, updated_at=datetime('now') WHERE id=?",
                (int(discussion_id),),
            )
    finally:
        conn.close()


def db_discussion_set_answer(discussion_id: int, comment_id: int | None) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "UPDATE discussions SET answered_comment_id=?, updated_at=datetime('now') WHERE id=?",
            (int(comment_id) if comment_id is not None else None, int(discussion_id)),
        )
    finally:
        conn.close()


def db_discussion_comment_add(discussion_id: int, author_user_id: int | None, body: str) -> int:
    conn = _db_connect()
    try:
        cur = conn.execute(
            "INSERT INTO discussion_comments(discussion_id, author_user_id, body) VALUES(?,?,?)",
            (int(discussion_id), int(author_user_id) if author_user_id is not None else None, body),
        )
        conn.execute(
            "UPDATE discussions SET updated_at=datetime('now') WHERE id=?", (int(discussion_id),)
        )
        return _require_lastrowid(cur)
    finally:
        conn.close()


def db_discussion_comment_list(discussion_id: int) -> list[CommentRow]:
    conn = _db_connect()
    try:
        return cast(
            list[CommentRow],
            conn.execute(
                """
                SELECT c.id, c.author_user_id, u.username, c.body, c.created_at, c.edited_at
                FROM discussion_comments c LEFT JOIN users u ON u.id=c.author_user_id
                WHERE c.discussion_id=? ORDER BY c.id
                """,
                (int(discussion_id),),
            ).fetchall(),
        )
    finally:
        conn.close()


def db_discussion_comment_get(discussion_id: int, comment_id: int) -> CommentIdentityRow | None:
    conn = _db_connect()
    try:
        return cast(
            CommentIdentityRow | None,
            conn.execute(
                "SELECT id, discussion_id, author_user_id, body FROM discussion_comments WHERE id=? AND discussion_id=?",
                (int(comment_id), int(discussion_id)),
            ).fetchone(),
        )
    finally:
        conn.close()


def db_discussion_comment_update(comment_id: int, body: str) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "UPDATE discussion_comments SET body=?, edited_at=datetime('now') WHERE id=?",
            (body, int(comment_id)),
        )
    finally:
        conn.close()


def db_discussion_comment_delete(comment_id: int) -> None:
    conn = _db_connect()
    try:
        conn.execute("DELETE FROM discussion_comments WHERE id=?", (int(comment_id),))
    finally:
        conn.close()


def db_discussion_comment_counts(discussion_ids: Iterable[int | str]) -> dict[int, int]:
    ids = [int(value) for value in discussion_ids if str(value).isdigit()]
    if not ids:
        return {}
    conn = _db_connect()
    try:
        marks = ",".join("?" * len(ids))
        rows = cast(
            list[tuple[int, int]],
            conn.execute(
                f"SELECT discussion_id, COUNT(*) FROM discussion_comments WHERE discussion_id IN ({marks}) GROUP BY discussion_id",
                ids,
            ).fetchall(),
        )
        return {int(discussion_id): int(count) for discussion_id, count in rows}
    finally:
        conn.close()


def db_discussion_comment_count(discussion_id: int) -> int:
    conn = _db_connect()
    try:
        return int(
            conn.execute(
                "SELECT COUNT(*) FROM discussion_comments WHERE discussion_id=?",
                (int(discussion_id),),
            ).fetchone()[0]
        )
    finally:
        conn.close()


def db_pr_create(
    owner: str,
    repo: str,
    title: str,
    body: str,
    source_branch: str,
    target_branch: str,
    author_user_id: int | None,
) -> int:
    conn = _db_connect()
    try:
        cur = conn.execute(
            """
            INSERT INTO pull_requests(owner, repo, title, body, source_branch, target_branch, author_user_id, status)
            VALUES(?,?,?,?,?,?,?, 'open')
            """,
            (
                owner,
                repo,
                title,
                body or "",
                source_branch,
                target_branch,
                int(author_user_id) if author_user_id is not None else None,
            ),
        )
        return _require_lastrowid(cur)
    finally:
        conn.close()


def db_pr_get(pr_id: int) -> PullRequestRow | None:
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
        return cast(PullRequestRow | None, cur.fetchone())
    finally:
        conn.close()


def db_pr_count(owner: str, repo: str, status: str | None = None) -> int:
    conn = _db_connect()
    try:
        return int(
            conn.execute(
                "SELECT COUNT(*) FROM pull_requests WHERE owner=? AND repo=?"
                + (" AND status=?" if status else ""),
                (owner, repo, status) if status else (owner, repo),
            ).fetchone()[0]
        )
    finally:
        conn.close()


def db_pr_list(
    owner: str, repo: str, status: str | None = None, *, limit: int | None = None, offset: int = 0
) -> list[PullRequestListRow]:
    conn = _db_connect()
    try:
        query = "SELECT id,title,source_branch,target_branch,status,created_at FROM pull_requests WHERE owner=? AND repo=?"
        params: list[SQLValue] = [owner, repo]
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY id DESC"
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend((max(1, min(500, int(limit))), max(0, int(offset))))
        cur = conn.execute(query, params)
        return cast(list[PullRequestListRow], cur.fetchall())
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


def db_repository_overview_get(owner: str, repo: str, commit: str) -> str | None:
    conn = _db_connect()
    try:
        row = conn.execute(
            "SELECT overview_json FROM repository_overviews WHERE owner=? AND repo=? AND commit_hash=?",
            (owner, repo, commit),
        ).fetchone()
        return cast(str, row[0]) if row else None
    finally:
        conn.close()


def db_repository_overview_set(owner: str, repo: str, commit: str, overview_json: str) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "INSERT INTO repository_overviews(owner,repo,commit_hash,overview_json) VALUES(?,?,?,?) ON CONFLICT(owner,repo,commit_hash) DO UPDATE SET overview_json=excluded.overview_json,updated_at=datetime('now')",
            (owner, repo, commit, overview_json),
        )
        conn.execute(
            """DELETE FROM repository_overviews WHERE owner=? AND repo=? AND rowid NOT IN
            (SELECT rowid FROM repository_overviews WHERE owner=? AND repo=? ORDER BY updated_at DESC,rowid DESC LIMIT 10)""",
            (owner, repo, owner, repo),
        )
    finally:
        conn.close()


def db_repository_languages_get(owner: str, repo: str, commit: str) -> str | None:
    conn = _db_connect()
    try:
        row = conn.execute(
            "SELECT languages_json FROM repository_languages WHERE owner=? AND repo=? AND commit_hash=?",
            (owner, repo, commit),
        ).fetchone()
        return cast(str, row[0]) if row else None
    finally:
        conn.close()


def db_repository_languages_set(owner: str, repo: str, commit: str, languages_json: str) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "INSERT INTO repository_languages(owner,repo,commit_hash,languages_json) VALUES(?,?,?,?) ON CONFLICT(owner,repo,commit_hash) DO UPDATE SET languages_json=excluded.languages_json,updated_at=datetime('now')",
            (owner, repo, commit, languages_json),
        )
        conn.execute(
            """DELETE FROM repository_languages WHERE owner=? AND repo=? AND rowid NOT IN
            (SELECT rowid FROM repository_languages WHERE owner=? AND repo=? ORDER BY updated_at DESC,rowid DESC LIMIT 10)""",
            (owner, repo, owner, repo),
        )
    finally:
        conn.close()


def db_ci_config_get(owner: str, repo: str) -> str | None:
    conn = _db_connect()
    try:
        row = conn.execute(
            "SELECT config_json FROM ci_configs WHERE owner=? AND repo=?", (owner, repo)
        ).fetchone()
        return cast(str, row[0]) if row else None
    finally:
        conn.close()


def db_deployment_claim(
    run_id: int, owner: str, repo: str, commit: str, config_json: str = ""
) -> bool:
    conn = _db_connect()
    try:
        document = decode_json_object(config_json or "{}")
        deployment_name = document.get("deployment_name")
        pipeline_id = document.get("pipeline_id", "default")
        cursor = conn.execute(
            """INSERT OR IGNORE INTO ci_deployments
            (run_id,owner,repo,commit_hash,config_json,pipeline_id) VALUES(?,?,?,?,?,?)""",
            (
                run_id,
                owner,
                repo,
                commit,
                config_json,
                cast(str, deployment_name or pipeline_id or "default"),
            ),
        )
        return cursor.rowcount == 1
    finally:
        conn.close()


def db_deployment_attempted(owner: str, repo: str, commit: str, deployment_key: str) -> bool:
    conn = _db_connect()
    try:
        return (
            conn.execute(
                "SELECT 1 FROM ci_deployments WHERE owner=? AND repo=? AND commit_hash=? AND pipeline_id=? LIMIT 1",
                (owner, repo, commit, deployment_key),
            ).fetchone()
            is not None
        )
    finally:
        conn.close()


def db_deployment_progress(run_id: int, deployment_key: str, output: str, steps_json: str) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "UPDATE ci_deployments SET output=?,steps_json=? WHERE run_id=? AND pipeline_id=? AND status='running'",
            (output, steps_json, run_id, deployment_key),
        )
    finally:
        conn.close()


def db_deployment_finish(
    run_id: int, status: str, output: str, deployment_key: str | None = None
) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            """UPDATE ci_deployments SET status=?, output=?, notification='queued',
            finished_at=datetime('now') WHERE run_id=? AND pipeline_id=COALESCE(?,
                (SELECT pipeline_id FROM ci_deployments WHERE run_id=? ORDER BY id LIMIT 1))""",
            (status, output, run_id, deployment_key, run_id),
        )
    finally:
        conn.close()


def db_deployment_get(run_id: int) -> DeploymentRow | None:
    conn = _db_connect()
    try:
        return cast(
            DeploymentRow | None,
            conn.execute(
                "SELECT status,output FROM ci_deployments WHERE run_id=?", (run_id,)
            ).fetchone(),
        )
    finally:
        conn.close()


def db_deployment_recover() -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "UPDATE ci_deployments SET notification='delivery unknown' WHERE notification='sending'"
        )
        conn.execute("""UPDATE ci_deployments SET status='interrupted', notification='queued',
            finished_at=datetime('now') WHERE status='running'""")
    finally:
        conn.close()


def db_deployment_email_record(
    run_id: int, deployment_key: str | None = None
) -> DeploymentEmailRow | None:
    conn = _db_connect()
    try:
        return cast(
            DeploymentEmailRow | None,
            conn.execute(
                """SELECT run_id,owner,repo,commit_hash,status,config_json,
                notification,started_at,finished_at FROM ci_deployments WHERE run_id=?
                AND (? IS NULL OR pipeline_id=?) ORDER BY id LIMIT 1""",
                (run_id, deployment_key, deployment_key),
            ).fetchone(),
        )
    finally:
        conn.close()


def db_deployments_count(owner: str, repo: str, before: int = 0) -> int:
    conn = _db_connect()
    try:
        return int(
            conn.execute(
                "SELECT COUNT(*) FROM ci_deployments WHERE owner=? AND repo=? AND (?=0 OR id<?)",
                (owner, repo, before, before),
            ).fetchone()[0]
        )
    finally:
        conn.close()


def db_deployments_list(
    owner: str, repo: str, before: int = 0, limit: int = 25, offset: int = 0
) -> list[DeploymentListRow]:
    conn = _db_connect()
    try:
        return cast(
            list[DeploymentListRow],
            conn.execute(
                """SELECT d.id,d.run_id,d.commit_hash,d.status,d.started_at,
                d.finished_at,d.notification,d.config_json,r.id,d.output,d.steps_json
                FROM ci_deployments d LEFT JOIN ci_runs r ON r.id=d.run_id
                WHERE d.owner=? AND d.repo=? AND (?=0 OR d.id<?)
                ORDER BY d.id DESC LIMIT ? OFFSET ?""",
                (owner, repo, before, before, limit, max(0, offset)),
            ).fetchall(),
        )
    finally:
        conn.close()


def db_deployment_detail(owner: str, repo: str, deployment_id: int) -> DeploymentListRow | None:
    conn = _db_connect()
    try:
        return cast(
            DeploymentListRow | None,
            conn.execute(
                """SELECT d.id,d.run_id,d.commit_hash,d.status,d.started_at,
                d.finished_at,d.notification,d.config_json,r.id,d.output,d.steps_json
                FROM ci_deployments d LEFT JOIN ci_runs r ON r.id=d.run_id
                WHERE d.owner=? AND d.repo=? AND d.id=?""",
                (owner, repo, deployment_id),
            ).fetchone(),
        )
    finally:
        conn.close()


def db_deployment_email_pending() -> list[tuple[int, str, str]]:
    conn = _db_connect()
    try:
        return cast(
            list[tuple[int, str, str]],
            conn.execute(
                "SELECT run_id,owner,repo FROM ci_deployments WHERE notification='queued'"
            ).fetchall(),
        )
    finally:
        conn.close()


def db_deployment_email_update(
    run_id: int, state: str, claim: bool = False, deployment_key: str | None = None
) -> bool:
    conn = _db_connect()
    try:
        cursor = conn.execute(
            """UPDATE ci_deployments SET notification=? WHERE run_id=?
            AND pipeline_id=COALESCE(?,(SELECT pipeline_id FROM ci_deployments WHERE run_id=? ORDER BY id LIMIT 1))"""
            + (" AND notification='queued'" if claim else ""),
            (state, run_id, deployment_key, run_id),
        )
        return cursor.rowcount == 1
    finally:
        conn.close()


def db_deployment_previous_result(
    owner: str, repo: str, run_id: int, deployment_key: str | None = None
) -> str | None:
    conn = _db_connect()
    try:
        row = conn.execute(
            """SELECT status FROM ci_deployments WHERE owner=? AND repo=?
            AND pipeline_id=COALESCE(?,(SELECT pipeline_id FROM ci_deployments WHERE run_id=? ORDER BY id LIMIT 1))
            AND run_id<? AND status!='running' ORDER BY id DESC LIMIT 1""",
            (owner, repo, deployment_key, run_id, run_id),
        ).fetchone()
        return cast(str, row[0]) if row else None
    finally:
        conn.close()


def db_deployments_for_run(run_id: int) -> list[DeploymentRunRow]:
    conn = _db_connect()
    try:
        return cast(
            list[DeploymentRunRow],
            conn.execute(
                """SELECT id,pipeline_id,status,output,notification,config_json
                FROM ci_deployments WHERE run_id=? ORDER BY id""",
                (run_id,),
            ).fetchall(),
        )
    finally:
        conn.close()


def db_email_settings_get() -> str | None:
    conn = _db_connect()
    try:
        row = conn.execute("SELECT value FROM server_settings WHERE key='smtp'").fetchone()
        return cast(str, row[0]) if row else None
    finally:
        conn.close()


def db_display_name_get() -> str:
    conn = _db_connect()
    try:
        row = conn.execute("SELECT value FROM server_settings WHERE key='display_name'").fetchone()
        return cast(str, row[0]) if row else "pygithost"
    finally:
        conn.close()


def db_display_name_set(value: str) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "INSERT INTO server_settings(key,value) VALUES('display_name',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (value,),
        )
    finally:
        conn.close()


def db_favicon_get() -> tuple[str, bytes] | None:
    """Return (content_type, bytes) for the uploaded favicon, or None."""
    conn = _db_connect()
    try:
        row = conn.execute("SELECT content_type, data FROM server_favicon WHERE id=1").fetchone()
        return (str(row[0]), bytes(row[1])) if row else None
    finally:
        conn.close()


def db_favicon_set(content_type: str, data: bytes) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "INSERT INTO server_favicon(id, content_type, data) VALUES(1,?,?) "
            "ON CONFLICT(id) DO UPDATE SET content_type=excluded.content_type, data=excluded.data, "
            "updated_at=datetime('now')",
            (content_type, sqlite3.Binary(data)),
        )
    finally:
        conn.close()


def db_favicon_clear() -> None:
    conn = _db_connect()
    try:
        conn.execute("DELETE FROM server_favicon WHERE id=1")
    finally:
        conn.close()


def db_email_settings_set(value: str) -> None:
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
        conn.execute(
            "INSERT INTO server_settings(key,value) VALUES('smtp',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (value,),
        )
    finally:
        conn.close()


def db_ci_config_set(
    owner: str,
    repo: str,
    config_json: str,
    *,
    preferences: JSONObject | None = None,
) -> None:
    conn = _db_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if preferences is not None:
            conn.execute(
                "INSERT INTO repository_ci_settings(owner,repo,settings_json) VALUES(?,?,?) ON CONFLICT(owner,repo) DO UPDATE SET settings_json=excluded.settings_json",
                (owner, repo, json.dumps(preferences)),
            )
        conn.execute(
            """INSERT INTO ci_configs(owner,repo,config_json) VALUES(?,?,?)
            ON CONFLICT(owner,repo) DO UPDATE SET config_json=excluded.config_json, updated_at=datetime('now')""",
            (owner, repo, config_json),
        )
        _db_ci_cleanup_artifacts(conn, owner, repo)
        _db_ci_prune_completed(conn, owner, repo)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _ci_execution_trust(conn: sqlite3.Connection) -> tuple[str, str]:
    values: dict[str, str] = dict(
        conn.execute(
            """SELECT key,value FROM server_settings
               WHERE key IN ('ci_execution_trust','ci_execution_trust_revision')"""
        )
    )
    return values.get("ci_execution_trust", ""), values.get("ci_execution_trust_revision", "0")


def db_ci_execution_trust_get() -> tuple[str, str]:
    conn = _db_connect()
    try:
        return _ci_execution_trust(conn)
    finally:
        conn.close()


def db_ci_execution_trust_set(
    value: str,
    expected_revision: str,
    *,
    actor: str | None,
    actor_user_id: int | None,
    ip: str,
) -> bool:
    """Replace the exact grants and record each change atomically."""
    conn = _db_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        previous, revision = _ci_execution_trust(conn)
        if revision != expected_revision:
            return False
        before, after = set(previous.splitlines()), set(value.splitlines())
        if before == after:
            return True
        conn.executemany(
            """INSERT INTO server_settings(key,value) VALUES(?,?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
            (
                ("ci_execution_trust", value),
                ("ci_execution_trust_revision", secrets.token_hex(16)),
            ),
        )
        conn.executemany(
            """INSERT INTO audit_events(actor,actor_user_id,action,outcome,target,ip)
            VALUES(?,?,?,'success',?,?)""",
            [
                (actor, actor_user_id, action, identity, ip)
                for action, identities in (
                    ("ci_execution_trust_grant", after - before),
                    ("ci_execution_trust_revoke", before - after),
                )
                for identity in sorted(identities)
            ],
        )
        conn.commit()
        return True
    finally:
        conn.close()


def db_ci_preferences_get(
    owner: str | None = None, repo: str | None = None
) -> tuple[JSONObject, JSONObject]:
    from .ci_preferences import read

    conn = _db_connect()
    try:
        return read(conn, owner, repo)
    finally:
        conn.close()


def db_ci_preferences_set(
    values: JSONObject, owner: str | None = None, repo: str | None = None
) -> None:
    from .ci_preferences import validate

    if owner is None:
        if repo is not None:
            raise ValueError("CI preferences require both owner and repo.")
        repository: tuple[str, str] | None = None
    else:
        if repo is None:
            raise ValueError("CI preferences require both owner and repo.")
        repository = (owner, repo)

    values = validate(values)
    conn = _db_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if repository is None:
            conn.execute(
                "INSERT INTO server_settings(key,value) VALUES('ci_defaults',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (json.dumps(values),),
            )
        else:
            repository_owner, repository_repo = repository
            conn.execute(
                "INSERT INTO repository_ci_settings(owner,repo,settings_json) VALUES(?,?,?) ON CONFLICT(owner,repo) DO UPDATE SET settings_json=excluded.settings_json",
                (repository_owner, repository_repo, json.dumps(values)),
            )
        _db_ci_cleanup_artifacts(conn, owner, repo)
        repositories = (
            [repository]
            if repository is not None
            else cast(
                list[tuple[str, str]],
                conn.execute("SELECT DISTINCT owner,repo FROM ci_runs").fetchall(),
            )
        )
        for item_owner, item_repo in repositories:
            _db_ci_prune_completed(conn, item_owner, item_repo)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def db_ci_run_create(
    owner: str,
    repo: str,
    event: str,
    branch: str,
    commit_hash: str,
    payload_json: str,
    config_json: str = "",
    notification: str = "",
) -> int:
    conn = _db_connect()
    try:
        cur = conn.execute(
            "INSERT INTO ci_runs(owner,repo,event,branch,commit_hash,payload_json,config_json,notification) VALUES(?,?,?,?,?,?,?,?)",
            (owner, repo, event, branch, commit_hash, payload_json, config_json, notification),
        )
        return _require_lastrowid(cur)
    finally:
        conn.close()


def db_ci_run_coordinator_error(run_id: int, *, database_error: bool, finished_at: str) -> None:
    """Record infrastructure failure without destroying evidence or terminal results."""
    conn = _db_connect()
    try:
        conn.execute(
            """UPDATE ci_runs SET status=?, reason=?, finished_at=?
               WHERE id=? AND status IN ('queued','running')""",
            (
                "interrupted" if database_error else "failed",
                "GitHost database error; execution outcome is uncertain. No automatic retry."
                if database_error
                else "GitHost coordinator error; inspect server logs.",
                finished_at,
                run_id,
            ),
        )
    finally:
        conn.close()


def db_ci_run_update(run_id: int, **values: SQLValue) -> None:
    allowed = {
        "status",
        "output",
        "truncated",
        "return_code",
        "started_at",
        "finished_at",
        "phase",
        "reason",
        "notification",
        "warnings",
    }
    values = {key: val for key, val in values.items() if key in allowed}
    if not values:
        return
    conn = _db_connect()
    try:
        cols = ", ".join(f"{key}=?" for key in values)
        conn.execute(f"UPDATE ci_runs SET {cols} WHERE id=?", (*values.values(), int(run_id)))
        if values.get("status") in {"success", "failed", "timed_out", "interrupted", "cancelled"}:
            row = cast(
                tuple[str, str] | None,
                conn.execute(
                    "SELECT owner,repo FROM ci_runs WHERE id=?", (int(run_id),)
                ).fetchone(),
            )
            if row:
                _db_ci_prune_completed(conn, row[0], row[1])
    finally:
        conn.close()


_CI_PIPELINE_ID = """COALESCE(CASE WHEN json_valid(payload_json)
    THEN json_extract(payload_json,'$.pipeline_id') END,'default')"""


def db_ci_run_workflows(owner: str, repo: str) -> list[str]:
    conn = _db_connect()
    try:
        return [
            row[0]
            for row in conn.execute(
                f"""SELECT DISTINCT {_CI_PIPELINE_ID} FROM ci_runs
                WHERE owner=? AND repo=? AND typeof({_CI_PIPELINE_ID})='text' ORDER BY 1""",
                (owner, repo),
            )
        ]
    finally:
        conn.close()


def db_ci_run_contexts(
    owner: str, repo: str, run_ids: Sequence[int]
) -> dict[int, tuple[str, str, int | None, str, str]]:
    """Return only the presentation fields for the requested repository runs."""
    if not run_ids:
        return {}
    conn = _db_connect()
    try:
        placeholders = ",".join("?" for _ in run_ids)
        return dict(
            (
                run_id,
                (head_commit, head_branch, pr_id, title, author),
            )
            for run_id, head_commit, head_branch, pr_id, title, author in conn.execute(
                f"""WITH selected AS (
                    SELECT id, owner, repo, CASE WHEN json_valid(payload_json)
                        THEN payload_json ELSE '{{}}' END AS payload
                    FROM ci_runs WHERE owner=? AND repo=? AND id IN ({placeholders})
                )
                SELECT s.id, COALESCE(CAST(json_extract(s.payload,'$.head_commit') AS TEXT),''),
                       COALESCE(CAST(json_extract(s.payload,'$.head_branch') AS TEXT),''),
                       p.id, COALESCE(p.title,''), COALESCE(u.username,'')
                FROM selected s
                LEFT JOIN pull_requests p ON p.owner=s.owner AND p.repo=s.repo
                     AND p.id=json_extract(s.payload,'$.pr_number')
                LEFT JOIN users u ON u.id=p.author_user_id""",
                (owner, repo, *run_ids),
            )
        )
    finally:
        conn.close()


def db_ci_runs_count(
    owner: str,
    repo: str,
    *,
    status: str = "",
    event: str = "",
    branch: str = "",
    query: str = "",
    before: int | None = None,
    warnings: str = "",
    pipeline: str = "",
) -> int:
    conn = _db_connect()
    try:
        conditions: list[str] = ["owner=?", "repo=?"]
        params: list[SQLValue] = [owner, repo]
        if pipeline:
            conditions.append(f"{_CI_PIPELINE_ID}=?")
            params.append(pipeline)
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
            pattern = (
                "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            )
            conditions.append(
                "(CAST(id AS TEXT) LIKE ? ESCAPE '\\' OR lower(commit_hash) LIKE ? ESCAPE '\\' OR lower(output) LIKE ? ESCAPE '\\')"
            )
            params.extend((pattern, pattern, pattern))
        return int(
            conn.execute(
                f"SELECT COUNT(*) FROM ci_runs WHERE {' AND '.join(conditions)}", params
            ).fetchone()[0]
        )
    finally:
        conn.close()


# Keep the widest projection first: when this overloaded helper is passed
# through a generic Callable wrapper, mypy binds that value to the first
# overload and otherwise loses the optional trailing warning/pipeline columns.
@overload
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
    include_warnings: Literal[True],
    include_pipeline: Literal[True],
    pipeline: str = "",
) -> list[CIRunListWarningsPipelineRow]: ...


@overload
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
    include_warnings: Literal[True],
    include_pipeline: Literal[False] = False,
    pipeline: str = "",
) -> list[CIRunListWarningsRow]: ...


@overload
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
    include_warnings: Literal[False] = False,
    include_pipeline: Literal[True],
    pipeline: str = "",
) -> list[CIRunListPipelineRow]: ...


@overload
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
    include_warnings: Literal[False] = False,
    include_pipeline: Literal[False] = False,
    pipeline: str = "",
) -> list[CIRunListRow]: ...


@overload
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
    pipeline: str = "",
) -> list[
    CIRunListRow | CIRunListWarningsRow | CIRunListPipelineRow | CIRunListWarningsPipelineRow
]: ...


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
    pipeline: str = "",
) -> list[Any]:
    conn = _db_connect()
    try:
        conditions = ["owner=?", "repo=?"]
        params: list[SQLValue] = [owner, repo]
        if pipeline:
            conditions.append(f"{_CI_PIPELINE_ID}=?")
            params.append(pipeline)
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
        pipeline_column = f",{_CI_PIPELINE_ID}" if include_pipeline else ""
        return conn.execute(
            f"SELECT id,event,branch,commit_hash,status,{output_column},truncated,return_code,created_at,started_at,finished_at{',warnings' if include_warnings else ''}{pipeline_column} "
            f"FROM ci_runs WHERE {' AND '.join(conditions)} ORDER BY id DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
    finally:
        conn.close()


def db_ci_run_get(owner: str, repo: str, run_id: int) -> CIRunRow | None:
    conn = _db_connect()
    try:
        return cast(
            CIRunRow | None,
            conn.execute(
                "SELECT id,event,branch,commit_hash,status,output,truncated,return_code,created_at,started_at,finished_at FROM ci_runs WHERE owner=? AND repo=? AND id=?",
                (owner, repo, int(run_id)),
            ).fetchone(),
        )
    finally:
        conn.close()


def db_ci_run_metadata(owner: str, repo: str, run_id: int) -> CIRunMetadata | None:
    conn = _db_connect()
    try:
        row = conn.execute(
            "SELECT payload_json,config_json,phase,reason,notification,warnings FROM ci_runs WHERE owner=? AND repo=? AND id=?",
            (owner, repo, run_id),
        ).fetchone()
        if not row:
            return None
        payload, config, phase, reason, notification, warnings = cast(
            tuple[str, str, str, str, str, str], row
        )
        return CIRunMetadata(
            payload=payload,
            config=config,
            phase=phase,
            reason=reason,
            notification=notification,
            warnings=warnings,
        )
    finally:
        conn.close()


def db_ci_steps_set(run_id: int, steps_json: str) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "INSERT INTO ci_steps VALUES(?,?) ON CONFLICT(run_id) DO UPDATE SET steps_json=excluded.steps_json",
            (run_id, steps_json),
        )
    finally:
        conn.close()


def db_ci_steps_get(run_id: int) -> str:
    conn = _db_connect()
    try:
        row = conn.execute("SELECT steps_json FROM ci_steps WHERE run_id=?", (run_id,)).fetchone()
        return cast(str, row[0]) if row else "[]"
    finally:
        conn.close()


def db_ci_retention_repositories() -> list[tuple[str, str]]:
    conn = _db_connect()
    try:
        return cast(
            list[tuple[str, str]],
            conn.execute("SELECT DISTINCT owner,repo FROM ci_runs").fetchall(),
        )
    finally:
        conn.close()


def db_ci_retention_policy_set(
    owner: str, repo: str, policy: JSONObject, *, commit: str | None = None
) -> None:
    """Store a policy together with the default-branch commit it was read from."""
    if commit is None:
        commit = _db_ci_retention_head(owner, repo)
    conn = _db_connect()
    try:
        conn.execute(
            """INSERT INTO ci_retention_policy VALUES (?,?,?,?)
               ON CONFLICT(owner,repo) DO UPDATE SET
               policy_json=excluded.policy_json, commit_hash=excluded.commit_hash""",
            (owner, repo, json.dumps(policy), commit or ""),
        )
    finally:
        conn.close()


def db_ci_retention_policy_cached(owner: str, repo: str) -> bool:
    """Cheap check for a cache row carrying a verified commit."""
    conn = _db_connect()
    try:
        return (
            conn.execute(
                "SELECT 1 FROM ci_retention_policy WHERE owner=? AND repo=? AND commit_hash<>''",
                (owner, repo),
            ).fetchone()
            is not None
        )
    finally:
        conn.close()


def _db_ci_retention_state(
    conn: sqlite3.Connection, owner: str, repo: str
) -> tuple[RetentionConfig, str] | None:
    """Return effective limits only when the cache row is verified at HEAD.

    A missing row means cleanup has never confirmed the repository policy (or a
    first cache write failed), so deletion pauses rather than assuming defaults.
    """
    from .ci_preferences import read, retention

    row = conn.execute(
        "SELECT policy_json, commit_hash FROM ci_retention_policy WHERE owner=? AND repo=?",
        (owner, repo),
    ).fetchone()
    if row is None:
        return None
    global_values, _repository_values = read(conn, owner, repo)
    policy = decode_json_object(row[0])
    commit = str(row[1] or "")
    if not commit or policy.get("unavailable") is True:
        return None
    current = _db_ci_retention_head(owner, repo)
    if current is None or current != commit:
        # A ref update, default-branch switch, out-of-band write or unreadable
        # repository leaves the cached limits unverified. Do not delete.
        return None
    bounded = {}
    for key, value in policy.items():
        if type(value) is not int:
            continue
        ceiling = global_values.get(key)
        bounded[key] = min(value or ceiling, ceiling) if type(ceiling) is int and ceiling else value
    return retention(global_values, {}, bounded), commit


def _db_ci_retention_unchanged(
    conn: sqlite3.Connection, owner: str, repo: str, commit: str
) -> bool:
    """True while the verified cache state used for a delete is still current."""
    row = conn.execute(
        "SELECT commit_hash FROM ci_retention_policy WHERE owner=? AND repo=?",
        (owner, repo),
    ).fetchone()
    return (
        row is not None
        and str(row[0] or "") == commit
        and _db_ci_retention_head(owner, repo) == commit
    )


def _db_ci_retention(conn: sqlite3.Connection, owner: str, repo: str) -> RetentionConfig:
    state = _db_ci_retention_state(conn, owner, repo)
    if state is not None:
        return state[0]
    return RetentionConfig(
        artifact_retention_days=0, artifact_retention_count=0, run_retention_count=0
    )


def _db_ci_cleanup_artifacts(
    conn: sqlite3.Connection, owner: str | None = None, repo: str | None = None
) -> bool:
    """Delete artifacts only under a cache entry verified at the current HEAD.

    Returns ``False`` when any examined repository was stale or changed while
    deleting, so a caller pruning runs can abandon the same operation.
    """
    if owner is not None:
        conditions = " WHERE r.owner=? AND r.repo=?"
        params: tuple[SQLValue, ...] = (owner, repo)
    else:
        conditions = ""
        params = ()
    repositories = cast(
        list[tuple[str, str]],
        conn.execute(
            "SELECT DISTINCT r.owner,r.repo FROM ci_artifacts a JOIN ci_runs r ON r.id=a.run_id"
            + conditions,
            params,
        ).fetchall(),
    )
    consistent = True
    for artifact_owner, artifact_repo in repositories:
        state = _db_ci_retention_state(conn, artifact_owner, artifact_repo)
        if state is None:
            consistent = False
            continue
        config, commit = state
        days = config.get("artifact_retention_days", 7)
        count = config.get("artifact_retention_count", 0)
        if not days and not count:
            continue
        conn.execute("SAVEPOINT ci_retention_cleanup")
        deleted = False
        try:
            if days:
                cursor = conn.execute(
                    """DELETE FROM ci_artifacts WHERE run_id IN
                    (SELECT id FROM ci_runs WHERE owner=? AND repo=?)
                    AND created_at <= datetime('now', ?)
                    AND EXISTS (SELECT 1 FROM ci_retention_policy p
                     WHERE p.owner=? AND p.repo=? AND p.commit_hash=?)""",
                    (
                        artifact_owner,
                        artifact_repo,
                        f"-{days} days",
                        artifact_owner,
                        artifact_repo,
                        commit,
                    ),
                )
                deleted = cursor.rowcount > 0
            if count:
                cursor = conn.execute(
                    """DELETE FROM ci_artifacts WHERE run_id IN
                    (SELECT id FROM ci_runs WHERE owner=? AND repo=?) AND run_id NOT IN
                    (SELECT a.run_id FROM ci_artifacts a JOIN ci_runs r ON r.id=a.run_id
                     WHERE r.owner=? AND r.repo=? ORDER BY a.run_id DESC LIMIT ?)
                    AND EXISTS (SELECT 1 FROM ci_retention_policy p
                     WHERE p.owner=? AND p.repo=? AND p.commit_hash=?)""",
                    (
                        artifact_owner,
                        artifact_repo,
                        artifact_owner,
                        artifact_repo,
                        count,
                        artifact_owner,
                        artifact_repo,
                        commit,
                    ),
                )
                deleted = deleted or cursor.rowcount > 0
            if deleted and not _db_ci_retention_unchanged(
                conn, artifact_owner, artifact_repo, commit
            ):
                # HEAD or the cache changed while deleting. Keep the old limits
                # from applying to the new state; the next refresh verifies it.
                conn.execute("ROLLBACK TO SAVEPOINT ci_retention_cleanup")
                conn.execute("RELEASE SAVEPOINT ci_retention_cleanup")
                consistent = False
                continue
            conn.execute("RELEASE SAVEPOINT ci_retention_cleanup")
        except BaseException:
            conn.execute("ROLLBACK TO SAVEPOINT ci_retention_cleanup")
            conn.execute("RELEASE SAVEPOINT ci_retention_cleanup")
            raise
    return consistent


def db_ci_artifact_set(run_id: int, archive: bytes | memoryview) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO ci_artifacts(run_id,archive) VALUES(?,?)", (run_id, archive)
        )
        row = cast(
            tuple[str, str] | None,
            conn.execute("SELECT owner,repo FROM ci_runs WHERE id=?", (int(run_id),)).fetchone(),
        )
        if row:
            _db_ci_cleanup_artifacts(conn, row[0], row[1])
    finally:
        conn.close()


@overload
def db_ci_artifact_get(
    owner: str, repo: str, run_id: int, *, content: Literal[False] = False
) -> int | None: ...


@overload
def db_ci_artifact_get(
    owner: str, repo: str, run_id: int, *, content: Literal[True]
) -> bytes | None: ...


@overload
def db_ci_artifact_get(
    owner: str, repo: str, run_id: int, *, content: bool
) -> bytes | int | None: ...


def db_ci_artifact_get(
    owner: str, repo: str, run_id: int, *, content: bool = False
) -> bytes | int | None:
    conn = _db_connect()
    try:
        _db_ci_cleanup_artifacts(conn, owner, repo)
        column = "a.archive" if content else "length(a.archive)"
        row = conn.execute(
            f"SELECT {column} FROM ci_artifacts a JOIN ci_runs r ON r.id=a.run_id WHERE r.owner=? AND r.repo=? AND r.id=?",
            (owner, repo, run_id),
        ).fetchone()
        return cast(bytes | int, row[0]) if row else None
    finally:
        conn.close()


def db_ci_artifacts_count(owner: str, repo: str, before: int | None = None) -> int:
    conn = _db_connect()
    try:
        _db_ci_cleanup_artifacts(conn, owner, repo)
        return int(
            conn.execute(
                "SELECT COUNT(*) FROM ci_artifacts a JOIN ci_runs r ON r.id=a.run_id WHERE r.owner=? AND r.repo=?"
                + (" AND r.id<?" if before is not None else ""),
                (owner, repo, before) if before is not None else (owner, repo),
            ).fetchone()[0]
        )
    finally:
        conn.close()


def db_ci_artifacts_list(
    owner: str,
    repo: str,
    *,
    before: int | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[CIArtifactRow]:
    conn = _db_connect()
    try:
        _db_ci_cleanup_artifacts(conn, owner, repo)
        days = _db_ci_retention(conn, owner, repo).get("artifact_retention_days", 7)
        conditions: list[str] = ["r.owner=?", "r.repo=?"]
        params: list[SQLValue] = [owner, repo]
        if before is not None:
            conditions.append("r.id<?")
            params.append(before)
        params.append(max(1, min(int(limit), 100)))
        params.append(max(0, int(offset)))
        day_params: list[SQLValue] = [f"+{days} days"] if days else []
        return cast(
            list[CIArtifactRow],
            conn.execute(
                f"""SELECT r.id,r.branch,r.commit_hash,r.status,r.event,
                a.created_at,length(a.archive),{"datetime(a.created_at, ?)" if days else "NULL"}
                FROM ci_artifacts a JOIN ci_runs r ON r.id=a.run_id
                WHERE {" AND ".join(conditions)} ORDER BY r.id DESC LIMIT ? OFFSET ?""",
                day_params + params,
            ).fetchall(),
        )
    finally:
        conn.close()


def db_ci_merge_check(
    owner: str,
    repo: str,
    pr_id: int,
    base: str,
    head: str,
    pipeline_id: str = "default",
) -> CIRunStatusRow | None:
    """Only the newest run for this exact PR base/head pair counts."""
    conn = _db_connect()
    try:
        row = conn.execute(
            """SELECT id,status FROM ci_runs WHERE owner=? AND repo=?
            AND event IN ('pull_request','pull_request_updated','pull_request_reopened')
            AND json_extract(payload_json,'$.pr_number')=?
            AND json_extract(payload_json,'$.base_commit')=?
            AND json_extract(payload_json,'$.head_commit')=?
            AND COALESCE(json_extract(payload_json,'$.pipeline_id'),'default')=?
            ORDER BY id DESC LIMIT 1""",
            (owner, repo, pr_id, base, head, pipeline_id),
        ).fetchone()
        return cast(CIRunStatusRow | None, row)
    finally:
        conn.close()


def db_ci_previous_result(
    owner: str,
    repo: str,
    branch: str,
    event: str,
    run_id: int,
    pr_number: int | None = None,
) -> str | None:
    conn = _db_connect()
    try:
        if pr_number is not None and event != "pull_request_merged":
            row = conn.execute(
                "SELECT status FROM ci_runs WHERE owner=? AND repo=? AND event IN ('pull_request','pull_request_updated','pull_request_reopened') AND json_extract(payload_json,'$.pr_number')=? AND COALESCE(json_extract(payload_json,'$.pipeline_id'),'default')=(SELECT COALESCE(json_extract(payload_json,'$.pipeline_id'),'default') FROM ci_runs WHERE id=?) AND id<? AND status IN ('success','failed','timed_out') ORDER BY id DESC LIMIT 1",
                (owner, repo, pr_number, run_id, run_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT status FROM ci_runs WHERE owner=? AND repo=? AND branch=? AND event=? AND COALESCE(json_extract(payload_json,'$.pipeline_id'),'default')=(SELECT COALESCE(json_extract(payload_json,'$.pipeline_id'),'default') FROM ci_runs WHERE id=?) AND id<? AND status IN ('success','failed','timed_out') ORDER BY id DESC LIMIT 1",
                (owner, repo, branch, event, run_id, run_id),
            ).fetchone()
        return cast(str, row[0]) if row else None
    finally:
        conn.close()


def db_ci_pending_notifications() -> list[CIRunNotificationRow]:
    conn = _db_connect()
    try:
        return cast(
            list[CIRunNotificationRow],
            conn.execute(
                "SELECT id,owner,repo,event,branch,commit_hash,payload_json FROM ci_runs WHERE notification='queued' AND status NOT IN ('queued','running') ORDER BY id"
            ).fetchall(),
        )
    finally:
        conn.close()


def db_prs_for_target(owner: str, repo: str, branch: str) -> list[PullRequestBranchRow]:
    conn = _db_connect()
    try:
        return cast(
            list[PullRequestBranchRow],
            conn.execute(
                "SELECT id,source_branch FROM pull_requests WHERE owner=? AND repo=? AND target_branch=? AND status='open'",
                (owner, repo, branch),
            ).fetchall(),
        )
    finally:
        conn.close()


def db_ci_latest_run(owner: str, repo: str, branch: str | None = None) -> CIRunLatestRow | None:
    conn = _db_connect()
    try:
        condition = (
            " AND branch=? AND event IN ('push','manual','pull_request_merged')"
            if branch is not None
            else ""
        )
        params = (owner, repo, branch) if branch is not None else (owner, repo)
        return cast(
            CIRunLatestRow | None,
            conn.execute(
                f"SELECT id,status,event,branch,commit_hash,created_at FROM ci_runs WHERE owner=? AND repo=?{condition} ORDER BY id DESC LIMIT 1",
                params,
            ).fetchone(),
        )
    finally:
        conn.close()


def db_ci_queued_runs() -> list[CIRunNotificationRow]:
    conn = _db_connect()
    try:
        return cast(
            list[CIRunNotificationRow],
            conn.execute(
                "SELECT id,owner,repo,event,branch,commit_hash,payload_json FROM ci_runs WHERE status='queued' ORDER BY id"
            ).fetchall(),
        )
    finally:
        conn.close()


def db_ci_recover_runs() -> None:
    conn = _db_connect()
    try:
        interrupted_steps = cast(
            list[tuple[int, str]],
            conn.execute(
                "SELECT s.run_id,s.steps_json FROM ci_steps s JOIN ci_runs r ON r.id=s.run_id WHERE r.status='running'"
            ).fetchall(),
        )
        for run_id, steps_json in interrupted_steps:
            steps = cast(list[dict[str, object]], json.loads(steps_json))
            for step in steps:
                if step["status"] == "running":
                    step.update(
                        status="interrupted",
                        finished_at=datetime.now(timezone.utc).isoformat(),
                        return_code=-1,
                    )
                elif step["status"] == "pending":
                    step["status"] = "skipped"
            conn.execute(
                "UPDATE ci_steps SET steps_json=? WHERE run_id=?", (json.dumps(steps), run_id)
            )
        conn.execute(
            "UPDATE ci_runs SET status='interrupted', finished_at=datetime('now') WHERE status='running'"
        )
        conn.execute(
            "UPDATE ci_runs SET notification='delivery unknown after restart (not retried)' WHERE notification='sending'"
        )
        repositories = cast(
            list[tuple[str, str]],
            conn.execute("SELECT DISTINCT owner,repo FROM ci_runs").fetchall(),
        )
        for owner, repo in repositories:
            _db_ci_prune_completed(conn, owner, repo)
    finally:
        conn.close()


def _db_ci_prune_completed(conn: sqlite3.Connection, owner: str, repo: str) -> None:
    state = _db_ci_retention_state(conn, owner, repo)
    if state is None:
        return
    config, commit = state
    retention = config.get(
        "run_retention_count",
        max(0, min(10000, int(os.environ.get("PYGITHOST_CI_RETENTION", "100")))),
    )
    if not _db_ci_cleanup_artifacts(conn, owner, repo):
        return
    if not retention:
        return
    conn.execute("SAVEPOINT ci_retention_prune")
    try:
        cursor = conn.execute(
            """DELETE FROM ci_runs AS old
            WHERE old.owner=? AND old.repo=? AND old.status NOT IN ('queued','running')
              AND old.notification NOT IN ('queued','sending')
              AND NOT EXISTS (SELECT 1 FROM ci_artifacts a WHERE a.run_id=old.id)
              AND old.id NOT IN (SELECT newer.id FROM ci_runs AS newer
                WHERE newer.owner=? AND newer.repo=? AND newer.status NOT IN ('queued','running')
                ORDER BY newer.id DESC LIMIT ?)
              AND EXISTS (SELECT 1 FROM ci_retention_policy p
                WHERE p.owner=? AND p.repo=? AND p.commit_hash=?)""",
            (owner, repo, owner, repo, retention, owner, repo, commit),
        )
        if cursor.rowcount and not _db_ci_retention_unchanged(conn, owner, repo, commit):
            conn.execute("ROLLBACK TO SAVEPOINT ci_retention_prune")
            conn.execute("RELEASE SAVEPOINT ci_retention_prune")
            return
        conn.execute("RELEASE SAVEPOINT ci_retention_prune")
    except BaseException:
        conn.execute("ROLLBACK TO SAVEPOINT ci_retention_prune")
        conn.execute("RELEASE SAVEPOINT ci_retention_prune")
        raise


def db_prs_for_source(owner: str, repo: str, branch: str) -> list[PullRequestBranchRow]:
    conn = _db_connect()
    try:
        return cast(
            list[PullRequestBranchRow],
            conn.execute(
                "SELECT id,target_branch FROM pull_requests WHERE owner=? AND repo=? AND source_branch=? AND status='open'",
                (owner, repo, branch),
            ).fetchall(),
        )
    finally:
        conn.close()


def db_pr_reopen(pr_id: int) -> None:
    conn = _db_connect()
    try:
        conn.execute(
            "UPDATE pull_requests SET status='open', closed_at=NULL WHERE id=? AND status='closed'",
            (int(pr_id),),
        )
    finally:
        conn.close()
