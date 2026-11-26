"""SQLite storage for pull request reviews, review threads, reviewers and timeline events.

Every table carries ``pr_id`` so deleting (archiving) a repository moves these rows
together with its pull requests. Author columns are nullable: with web sign-in
disabled the UI acts as an anonymous "local user".
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from typing import Any, Literal, TypedDict, cast

from . import database

ReviewState = Literal["pending", "commented", "approved", "changes_requested", "dismissed"]
Side = Literal["LEFT", "RIGHT"]
REVIEW_STATES = ("pending", "commented", "approved", "changes_requested", "dismissed")

# Child tables of pull_requests, in the order the archiver should copy them.
CHILD_TABLES = (
    "pr_review_comments",
    "pr_review_threads",
    "pr_reviews",
    "pr_review_requests",
    "pr_viewed_files",
    "pr_events",
)


class Review(TypedDict):
    id: int
    pr_id: int
    author_user_id: int | None
    author: str | None
    state: ReviewState
    body: str
    commit_sha: str
    created_at: str
    submitted_at: str | None
    dismissed_at: str | None
    dismissed_by: str | None
    dismiss_reason: str


class ReviewComment(TypedDict):
    id: int
    thread_id: int
    review_id: int | None
    author_user_id: int | None
    author: str | None
    body: str
    created_at: str
    edited_at: str | None
    pending: bool


class Thread(TypedDict):
    id: int
    pr_id: int
    path: str
    side: Side
    line: int
    start_line: int | None
    commit_sha: str
    base_sha: str
    resolved: bool
    resolved_by: str | None
    resolved_at: str | None
    created_at: str
    comments: list[ReviewComment]


class Event(TypedDict):
    id: int
    pr_id: int
    actor_user_id: int | None
    actor: str | None
    kind: str
    data: dict[str, Any]
    created_at: str


class ReviewRequest(TypedDict):
    user_id: int
    login: str
    requested_by: str | None
    created_at: str


def init_schema(conn: sqlite3.Connection) -> None:
    """Create review tables and add the pull request columns they rely on."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(pull_requests)")}
    if "draft" not in columns:
        conn.execute("ALTER TABLE pull_requests ADD COLUMN draft INTEGER NOT NULL DEFAULT 0")
    if "head_deleted_sha" not in columns:
        # Tip of the head branch when it was deleted after merging, for "Restore branch".
        conn.execute("ALTER TABLE pull_requests ADD COLUMN head_deleted_sha TEXT")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS pr_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pr_id INTEGER NOT NULL,
            author_user_id INTEGER,
            state TEXT NOT NULL CHECK (state IN
                ('pending','commented','approved','changes_requested','dismissed')),
            body TEXT NOT NULL DEFAULT '',
            commit_sha TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            submitted_at TEXT,
            dismissed_at TEXT,
            dismissed_by INTEGER,
            dismiss_reason TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(pr_id) REFERENCES pull_requests(id) ON DELETE CASCADE,
            FOREIGN KEY(author_user_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY(dismissed_by) REFERENCES users(id) ON DELETE SET NULL
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pr_reviews_pr ON pr_reviews(pr_id, id)")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS pr_review_threads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pr_id INTEGER NOT NULL,
            path TEXT NOT NULL,
            side TEXT NOT NULL CHECK (side IN ('LEFT','RIGHT')),
            line INTEGER NOT NULL CHECK (line > 0),
            start_line INTEGER CHECK (start_line IS NULL OR start_line > 0),
            commit_sha TEXT NOT NULL,
            base_sha TEXT NOT NULL DEFAULT '',
            resolved INTEGER NOT NULL DEFAULT 0,
            resolved_by INTEGER,
            resolved_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY(pr_id) REFERENCES pull_requests(id) ON DELETE CASCADE,
            FOREIGN KEY(resolved_by) REFERENCES users(id) ON DELETE SET NULL
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pr_review_threads_pr ON pr_review_threads(pr_id, id)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS pr_review_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pr_id INTEGER NOT NULL,
            thread_id INTEGER NOT NULL,
            review_id INTEGER,
            author_user_id INTEGER,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            edited_at TEXT,
            FOREIGN KEY(pr_id) REFERENCES pull_requests(id) ON DELETE CASCADE,
            FOREIGN KEY(thread_id) REFERENCES pr_review_threads(id) ON DELETE CASCADE,
            FOREIGN KEY(review_id) REFERENCES pr_reviews(id) ON DELETE CASCADE,
            FOREIGN KEY(author_user_id) REFERENCES users(id) ON DELETE SET NULL
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pr_review_comments_thread"
        " ON pr_review_comments(thread_id, id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pr_review_comments_pr ON pr_review_comments(pr_id, id)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS pr_review_requests (
            pr_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            requested_by INTEGER,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY(pr_id, user_id),
            FOREIGN KEY(pr_id) REFERENCES pull_requests(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(requested_by) REFERENCES users(id) ON DELETE SET NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS pr_viewed_files (
            pr_id INTEGER NOT NULL,
            viewer TEXT NOT NULL,
            path TEXT NOT NULL,
            blob_sha TEXT NOT NULL,
            PRIMARY KEY(pr_id, viewer, path),
            FOREIGN KEY(pr_id) REFERENCES pull_requests(id) ON DELETE CASCADE
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS pr_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pr_id INTEGER NOT NULL,
            actor_user_id INTEGER,
            kind TEXT NOT NULL,
            data TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY(pr_id) REFERENCES pull_requests(id) ON DELETE CASCADE,
            FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pr_events_pr ON pr_events(pr_id, id)")


def _connect() -> sqlite3.Connection:
    return database._db_connect()


def _user(user_id: int | None) -> int | None:
    return int(user_id) if user_id is not None else None


# ---------------------------------------------------------------- pull request flags


def pr_flags(pr_id: int) -> tuple[bool, str | None]:
    """(draft, head_deleted_sha) for a pull request."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT draft, head_deleted_sha FROM pull_requests WHERE id=?", (int(pr_id),)
        ).fetchone()
    finally:
        conn.close()
    return (bool(row[0]), row[1]) if row else (False, None)


def pr_flags_many(pr_ids: Iterable[int]) -> dict[int, bool]:
    """Draft flag per pull request id (for list pages)."""
    ids = [int(value) for value in pr_ids]
    if not ids:
        return {}
    conn = _connect()
    try:
        marks = ",".join("?" for _ in ids)
        rows = conn.execute(
            f"SELECT id, draft FROM pull_requests WHERE id IN ({marks})", ids
        ).fetchall()
    finally:
        conn.close()
    return {int(row[0]): bool(row[1]) for row in rows}


def set_draft(pr_id: int, draft: bool) -> bool:
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE pull_requests SET draft=? WHERE id=? AND status='open' AND draft<>?",
            (int(draft), int(pr_id), int(draft)),
        )
        return cur.rowcount > 0
    finally:
        conn.close()


def set_base(pr_id: int, base: str) -> bool:
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE pull_requests SET target_branch=? WHERE id=? AND status='open'",
            (base, int(pr_id)),
        )
        return cur.rowcount > 0
    finally:
        conn.close()


def set_head_deleted(pr_id: int, sha: str | None) -> None:
    conn = _connect()
    try:
        conn.execute("UPDATE pull_requests SET head_deleted_sha=? WHERE id=?", (sha, int(pr_id)))
    finally:
        conn.close()


def create_pull(
    owner: str,
    repo: str,
    title: str,
    body: str,
    head: str,
    base: str,
    author_user_id: int | None,
    draft: bool,
) -> int:
    """Create a pull request (optionally as a draft) and its "opened" event."""
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                """INSERT INTO pull_requests(owner, repo, title, body, source_branch,
                       target_branch, author_user_id, status, draft)
                   VALUES(?,?,?,?,?,?,?,'open',?)""",
                (owner, repo, title, body or "", head, base, _user(author_user_id), int(draft)),
            )
            pr_id = int(cast(int, cur.lastrowid))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return pr_id


# ---------------------------------------------------------------- events


def add_event(
    pr_id: int, actor_user_id: int | None, kind: str, data: Mapping[str, Any] | None = None
) -> int:
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO pr_events(pr_id, actor_user_id, kind, data) VALUES(?,?,?,?)",
            (int(pr_id), _user(actor_user_id), kind, json.dumps(dict(data or {}))),
        )
        return int(cast(int, cur.lastrowid))
    finally:
        conn.close()


def list_events(pr_id: int) -> list[Event]:
    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT e.id, e.pr_id, e.actor_user_id, u.username, e.kind, e.data, e.created_at
               FROM pr_events e LEFT JOIN users u ON u.id = e.actor_user_id
               WHERE e.pr_id=? ORDER BY e.id""",
            (int(pr_id),),
        ).fetchall()
    finally:
        conn.close()
    events: list[Event] = []
    for row in rows:
        try:
            data = json.loads(row[5])
        except ValueError:
            data = {}
        events.append(
            {
                "id": row[0],
                "pr_id": row[1],
                "actor_user_id": row[2],
                "actor": row[3],
                "kind": row[4],
                "data": data if isinstance(data, dict) else {},
                "created_at": row[6],
            }
        )
    return events


# ---------------------------------------------------------------- reviews

_REVIEW_SELECT = """SELECT r.id, r.pr_id, r.author_user_id, u.username, r.state, r.body,
    r.commit_sha, r.created_at, r.submitted_at, r.dismissed_at, d.username, r.dismiss_reason
    FROM pr_reviews r
    LEFT JOIN users u ON u.id = r.author_user_id
    LEFT JOIN users d ON d.id = r.dismissed_by"""


def _review(row: tuple[Any, ...]) -> Review:
    return {
        "id": row[0],
        "pr_id": row[1],
        "author_user_id": row[2],
        "author": row[3],
        "state": cast(ReviewState, row[4]),
        "body": row[5],
        "commit_sha": row[6],
        "created_at": row[7],
        "submitted_at": row[8],
        "dismissed_at": row[9],
        "dismissed_by": row[10],
        "dismiss_reason": row[11],
    }


def get_review(pr_id: int, review_id: int) -> Review | None:
    conn = _connect()
    try:
        row = conn.execute(
            _REVIEW_SELECT + " WHERE r.pr_id=? AND r.id=?", (int(pr_id), int(review_id))
        ).fetchone()
    finally:
        conn.close()
    return _review(row) if row else None


def pending_review(pr_id: int, author_user_id: int | None) -> Review | None:
    conn = _connect()
    try:
        row = conn.execute(
            _REVIEW_SELECT
            + " WHERE r.pr_id=? AND r.state='pending' AND r.author_user_id IS ?"
            + " ORDER BY r.id DESC LIMIT 1",
            (int(pr_id), _user(author_user_id)),
        ).fetchone()
    finally:
        conn.close()
    return _review(row) if row else None


def list_reviews(pr_id: int, viewer_user_id: int | None, viewer_known: bool) -> list[Review]:
    """Submitted reviews, plus the viewer's own pending review.

    An unknown viewer (sign-in disabled) is the anonymous local user, who owns the
    pending reviews recorded without an author.
    """
    viewer = _user(viewer_user_id) if viewer_known else None
    conn = _connect()
    try:
        rows = conn.execute(
            _REVIEW_SELECT
            + " WHERE r.pr_id=? AND (r.state<>'pending' OR (? AND r.author_user_id IS ?))"
            + " ORDER BY r.id",
            (int(pr_id), int(viewer_known or viewer_user_id is None), viewer),
        ).fetchall()
    finally:
        conn.close()
    return [_review(row) for row in rows]


def start_review(pr_id: int, author_user_id: int | None, commit_sha: str) -> int:
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO pr_reviews(pr_id, author_user_id, state, commit_sha) VALUES(?,?,'pending',?)",
            (int(pr_id), _user(author_user_id), commit_sha),
        )
        return int(cast(int, cur.lastrowid))
    finally:
        conn.close()


def submit_review(review_id: int, state: ReviewState, body: str, commit_sha: str) -> bool:
    conn = _connect()
    try:
        cur = conn.execute(
            """UPDATE pr_reviews SET state=?, body=?, commit_sha=?, submitted_at=datetime('now')
               WHERE id=? AND state='pending'""",
            (state, body, commit_sha, int(review_id)),
        )
        return cur.rowcount > 0
    finally:
        conn.close()


def delete_pending_review(review_id: int) -> bool:
    """Discard a pending review and the threads it started (cascade removes comments)."""
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT pr_id FROM pr_reviews WHERE id=? AND state='pending'", (int(review_id),)
            ).fetchone()
            if not row:
                conn.execute("ROLLBACK")
                return False
            # Threads whose every comment belongs to this review disappear with it.
            conn.execute(
                """DELETE FROM pr_review_threads WHERE id IN (
                       SELECT thread_id FROM pr_review_comments WHERE review_id=?)
                   AND NOT EXISTS (SELECT 1 FROM pr_review_comments c
                       WHERE c.thread_id = pr_review_threads.id
                       AND (c.review_id IS NULL OR c.review_id<>?))""",
                (int(review_id), int(review_id)),
            )
            conn.execute("DELETE FROM pr_reviews WHERE id=?", (int(review_id),))
            conn.execute("COMMIT")
            return True
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


def dismiss_review(review_id: int, by_user_id: int | None, reason: str) -> bool:
    conn = _connect()
    try:
        cur = conn.execute(
            """UPDATE pr_reviews SET state='dismissed', dismissed_at=datetime('now'),
                   dismissed_by=?, dismiss_reason=?
               WHERE id=? AND state IN ('approved','changes_requested')""",
            (_user(by_user_id), reason, int(review_id)),
        )
        return cur.rowcount > 0
    finally:
        conn.close()


def dismiss_stale_approvals(pr_id: int, head_sha: str) -> int:
    """Dismiss approvals given on an older head commit (new commits were pushed)."""
    conn = _connect()
    try:
        cur = conn.execute(
            """UPDATE pr_reviews SET state='dismissed', dismissed_at=datetime('now'),
                   dismiss_reason='New commits were pushed.'
               WHERE pr_id=? AND state='approved' AND commit_sha<>?""",
            (int(pr_id), head_sha),
        )
        return cur.rowcount
    finally:
        conn.close()


def reviewer_states(pr_id: int) -> dict[int | None, Review]:
    """Each reviewer's latest decisive review (approved / changes requested / dismissed).

    A later "commented" review does not replace an earlier decision, as on GitHub.
    """
    latest: dict[int | None, Review] = {}
    for review in list_reviews(pr_id, None, False):
        if review["state"] == "pending":
            continue
        if review["state"] in ("approved", "changes_requested", "dismissed"):
            latest[review["author_user_id"]] = review
        elif review["author_user_id"] not in latest:
            latest[review["author_user_id"]] = review
    return latest


# ---------------------------------------------------------------- threads and comments


def create_thread(
    *,
    pr_id: int,
    path: str,
    side: Side,
    line: int,
    start_line: int | None,
    commit_sha: str,
    base_sha: str,
    body: str,
    author_user_id: int | None,
    review_id: int | None,
) -> tuple[int, int]:
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                """INSERT INTO pr_review_threads(pr_id, path, side, line, start_line,
                       commit_sha, base_sha) VALUES(?,?,?,?,?,?,?)""",
                (int(pr_id), path, side, int(line), start_line, commit_sha, base_sha),
            )
            thread_id = int(cast(int, cur.lastrowid))
            cur = conn.execute(
                """INSERT INTO pr_review_comments(pr_id, thread_id, review_id, author_user_id, body)
                   VALUES(?,?,?,?,?)""",
                (int(pr_id), thread_id, review_id, _user(author_user_id), body),
            )
            comment_id = int(cast(int, cur.lastrowid))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return thread_id, comment_id


def add_reply(
    pr_id: int, thread_id: int, body: str, author_user_id: int | None, review_id: int | None
) -> int:
    conn = _connect()
    try:
        cur = conn.execute(
            """INSERT INTO pr_review_comments(pr_id, thread_id, review_id, author_user_id, body)
               VALUES(?,?,?,?,?)""",
            (int(pr_id), int(thread_id), review_id, _user(author_user_id), body),
        )
        return int(cast(int, cur.lastrowid))
    finally:
        conn.close()


def list_threads(
    pr_id: int, viewer_user_id: int | None, viewer_known: bool, thread_id: int | None = None
) -> list[Thread]:
    """Threads with their visible comments; pending comments only for their author."""
    conn = _connect()
    try:
        params: list[Any] = [int(pr_id)]
        where = "t.pr_id=?"
        if thread_id is not None:
            where += " AND t.id=?"
            params.append(int(thread_id))
        threads = conn.execute(
            f"""SELECT t.id, t.pr_id, t.path, t.side, t.line, t.start_line, t.commit_sha,
                       t.base_sha, t.resolved, u.username, t.resolved_at, t.created_at
                FROM pr_review_threads t LEFT JOIN users u ON u.id = t.resolved_by
                WHERE {where} ORDER BY t.id""",
            params,
        ).fetchall()
        comments = conn.execute(
            f"""SELECT c.id, c.thread_id, c.review_id, c.author_user_id, u.username, c.body,
                       c.created_at, c.edited_at, COALESCE(r.state = 'pending', 0)
                FROM pr_review_comments c
                JOIN pr_review_threads t ON t.id = c.thread_id
                LEFT JOIN users u ON u.id = c.author_user_id
                LEFT JOIN pr_reviews r ON r.id = c.review_id
                WHERE {where}
                ORDER BY c.id""",
            params,
        ).fetchall()
    finally:
        conn.close()
    by_thread: dict[int, list[ReviewComment]] = {}
    for row in comments:
        pending = bool(row[8])
        owner = viewer_user_id if viewer_known else None
        if pending and row[3] != owner:
            continue
        by_thread.setdefault(row[1], []).append(
            {
                "id": row[0],
                "thread_id": row[1],
                "review_id": row[2],
                "author_user_id": row[3],
                "author": row[4],
                "body": row[5],
                "created_at": row[6],
                "edited_at": row[7],
                "pending": pending,
            }
        )
    result: list[Thread] = []
    for row in threads:
        visible = by_thread.get(row[0], [])
        if not visible:
            continue
        result.append(
            {
                "id": row[0],
                "pr_id": row[1],
                "path": row[2],
                "side": cast(Side, row[3]),
                "line": row[4],
                "start_line": row[5],
                "commit_sha": row[6],
                "base_sha": row[7],
                "resolved": bool(row[8]),
                "resolved_by": row[9],
                "resolved_at": row[10],
                "created_at": row[11],
                "comments": visible,
            }
        )
    return result


def set_resolved(pr_id: int, thread_id: int, resolved: bool, by_user_id: int | None) -> bool:
    conn = _connect()
    try:
        cur = conn.execute(
            """UPDATE pr_review_threads SET resolved=?,
                   resolved_by=CASE WHEN ? THEN ? ELSE NULL END,
                   resolved_at=CASE WHEN ? THEN datetime('now') ELSE NULL END
               WHERE pr_id=? AND id=?""",
            (
                int(resolved),
                int(resolved),
                _user(by_user_id),
                int(resolved),
                int(pr_id),
                int(thread_id),
            ),
        )
        return cur.rowcount > 0
    finally:
        conn.close()


def unresolved_thread_count(pr_id: int) -> int:
    """Unresolved threads that other people can see (pending-only threads excluded)."""
    conn = _connect()
    try:
        return int(
            conn.execute(
                """SELECT COUNT(*) FROM pr_review_threads t WHERE t.pr_id=? AND t.resolved=0
                   AND EXISTS (SELECT 1 FROM pr_review_comments c
                       LEFT JOIN pr_reviews r ON r.id = c.review_id
                       WHERE c.thread_id = t.id AND (r.id IS NULL OR r.state<>'pending'))""",
                (int(pr_id),),
            ).fetchone()[0]
        )
    finally:
        conn.close()


def get_comment(pr_id: int, comment_id: int) -> ReviewComment | None:
    conn = _connect()
    try:
        row = conn.execute(
            """SELECT c.id, c.thread_id, c.review_id, c.author_user_id, u.username, c.body,
                      c.created_at, c.edited_at, COALESCE(r.state = 'pending', 0)
               FROM pr_review_comments c
               LEFT JOIN users u ON u.id = c.author_user_id
               LEFT JOIN pr_reviews r ON r.id = c.review_id
               WHERE c.pr_id=? AND c.id=?""",
            (int(pr_id), int(comment_id)),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "thread_id": row[1],
        "review_id": row[2],
        "author_user_id": row[3],
        "author": row[4],
        "body": row[5],
        "created_at": row[6],
        "edited_at": row[7],
        "pending": bool(row[8]),
    }


def update_comment(comment_id: int, body: str) -> None:
    conn = _connect()
    try:
        conn.execute(
            "UPDATE pr_review_comments SET body=?, edited_at=datetime('now') WHERE id=?",
            (body, int(comment_id)),
        )
    finally:
        conn.close()


def delete_comment(comment_id: int) -> None:
    """Delete one review comment; a thread left without comments is removed too."""
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT thread_id FROM pr_review_comments WHERE id=?", (int(comment_id),)
            ).fetchone()
            conn.execute("DELETE FROM pr_review_comments WHERE id=?", (int(comment_id),))
            if row:
                conn.execute(
                    """DELETE FROM pr_review_threads WHERE id=? AND NOT EXISTS
                       (SELECT 1 FROM pr_review_comments WHERE thread_id=?)""",
                    (row[0], row[0]),
                )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


def review_comment_count(review_id: int) -> int:
    conn = _connect()
    try:
        return int(
            conn.execute(
                "SELECT COUNT(*) FROM pr_review_comments WHERE review_id=?", (int(review_id),)
            ).fetchone()[0]
        )
    finally:
        conn.close()


# ---------------------------------------------------------------- review requests


def request_reviewers(pr_id: int, user_ids: Iterable[int], by_user_id: int | None) -> list[int]:
    """Add review requests; returns the ids that were newly requested."""
    added: list[int] = []
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            for user_id in user_ids:
                cur = conn.execute(
                    """INSERT INTO pr_review_requests(pr_id, user_id, requested_by)
                       VALUES(?,?,?) ON CONFLICT(pr_id, user_id) DO NOTHING""",
                    (int(pr_id), int(user_id), _user(by_user_id)),
                )
                if cur.rowcount:
                    added.append(int(user_id))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return added


def remove_review_request(pr_id: int, user_id: int) -> bool:
    conn = _connect()
    try:
        cur = conn.execute(
            "DELETE FROM pr_review_requests WHERE pr_id=? AND user_id=?",
            (int(pr_id), int(user_id)),
        )
        return cur.rowcount > 0
    finally:
        conn.close()


def list_review_requests(pr_id: int) -> list[ReviewRequest]:
    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT q.user_id, u.username, b.username, q.created_at
               FROM pr_review_requests q
               JOIN users u ON u.id = q.user_id
               LEFT JOIN users b ON b.id = q.requested_by
               WHERE q.pr_id=? ORDER BY u.username COLLATE NOCASE""",
            (int(pr_id),),
        ).fetchall()
    finally:
        conn.close()
    return [
        {"user_id": row[0], "login": row[1], "requested_by": row[2], "created_at": row[3]}
        for row in rows
    ]


def active_users() -> list[tuple[int, str]]:
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, username FROM users WHERE is_active=1 ORDER BY username COLLATE NOCASE"
        ).fetchall()
    finally:
        conn.close()
    return [(int(row[0]), str(row[1])) for row in rows]


def user_ids_for_logins(logins: Iterable[str]) -> dict[str, int]:
    names = [str(login) for login in logins]
    if not names:
        return {}
    conn = _connect()
    try:
        marks = ",".join("?" for _ in names)
        rows = conn.execute(
            f"SELECT username, id FROM users WHERE is_active=1 AND username IN ({marks})", names
        ).fetchall()
    finally:
        conn.close()
    return {str(row[0]): int(row[1]) for row in rows}


# ---------------------------------------------------------------- viewed files


def viewed_files(pr_id: int, viewer: str) -> dict[str, str]:
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT path, blob_sha FROM pr_viewed_files WHERE pr_id=? AND viewer=?",
            (int(pr_id), viewer),
        ).fetchall()
    finally:
        conn.close()
    return {str(row[0]): str(row[1]) for row in rows}


def set_viewed(pr_id: int, viewer: str, path: str, blob_sha: str | None) -> None:
    """Mark a file viewed at its current blob (None clears the mark)."""
    conn = _connect()
    try:
        if blob_sha is None:
            conn.execute(
                "DELETE FROM pr_viewed_files WHERE pr_id=? AND viewer=? AND path=?",
                (int(pr_id), viewer, path),
            )
        else:
            conn.execute(
                """INSERT INTO pr_viewed_files(pr_id, viewer, path, blob_sha) VALUES(?,?,?,?)
                   ON CONFLICT(pr_id, viewer, path) DO UPDATE SET blob_sha=excluded.blob_sha""",
                (int(pr_id), viewer, path, blob_sha),
            )
    finally:
        conn.close()
