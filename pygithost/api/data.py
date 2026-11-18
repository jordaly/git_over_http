"""Bounded repository-scoped reads and explicit public serializers."""

import hashlib
import json
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, cast

from .. import database
from ..database_types import SQLRow, SQLValue
from .types import (
    Artifact,
    Comment,
    Discussion,
    Issue,
    Pull,
    Run,
)


def timestamp(value: SQLValue) -> str | None:
    if not value:
        return None
    # Legacy SQLite timestamps are server-local wall time, not UTC.
    parsed = datetime.fromisoformat(cast(str, value))
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def utc_timestamp(value: SQLValue) -> str | None:
    """CI's SQLite defaults use datetime('now'), unlike legacy UI local time."""
    if not value:
        return None
    parsed = datetime.fromisoformat(cast(str, value))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _query(
    sql: str,
    params: Sequence[SQLValue],
    connection: sqlite3.Connection | None = None,
) -> list[SQLRow]:
    if connection is not None:
        return connection.execute(sql, params).fetchall()
    conn = database._db_connect()
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def _text(value: SQLValue) -> str:
    return cast(str, value)


def _text_or_none(value: SQLValue) -> str | None:
    return cast(str | None, value)


def _integer(value: SQLValue) -> int:
    return cast(int, value)


def _integer_or_none(value: SQLValue) -> int | None:
    return cast(int | None, value)


def revision(value: object) -> str:
    """Content revision also catches edits made by the existing HTML handlers."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def versioned(value: Mapping[str, Any]) -> dict[str, Any]:
    return {**value, "revision": revision(value)}


def issue(row: Sequence[Any]) -> Issue:
    return cast(
        Issue,
        versioned(
            {
                "id": _integer(row[0]),
                "title": _text(row[1]),
                "body": _text(row[2]),
                "user": {"id": _integer(row[3]), "login": _text_or_none(row[4])}
                if row[3] is not None
                else None,
                "state": _text(row[5]),
                "created_at": timestamp(row[6]),
                "updated_at": timestamp(row[7]),
                "closed_at": timestamp(row[8]),
            }
        ),
    )


def issues(
    owner: str,
    repo: str,
    state: str,
    limit: int,
    offset: int,
    identity: int | None = None,
    _connection: sqlite3.Connection | None = None,
) -> list[Issue]:
    where = "i.owner=? AND i.repo=?"
    params: list[SQLValue] = [owner, repo]
    if identity is not None:
        where += " AND i.id=?"
        params.append(identity)
    if state != "all":
        where += " AND i.status=?"
        params.append(state)
    rows = _query(
        "SELECT i.id,i.title,i.body,i.author_user_id,u.username,i.status,"
        "i.created_at,i.updated_at,i.closed_at FROM issues i "
        "LEFT JOIN users u ON u.id=i.author_user_id WHERE "
        + where
        + " ORDER BY i.id DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
        _connection,
    )
    return [issue(row) for row in rows]


def pulls(
    owner: str,
    repo: str,
    state: str,
    limit: int,
    offset: int,
    identity: int | None = None,
    _connection: sqlite3.Connection | None = None,
) -> list[Pull]:
    where = "p.owner=? AND p.repo=?"
    params: list[SQLValue] = [owner, repo]
    if identity is not None:
        where += " AND p.id=?"
        params.append(identity)
    if state != "all":
        where += " AND p.status=?"
        params.append(state)
    rows = _query(
        "SELECT p.id,p.title,p.body,p.author_user_id,u.username,p.status,"
        "p.created_at,p.closed_at,p.merged_at,p.source_branch,p.target_branch,"
        "p.merge_method,p.merge_commit FROM pull_requests p "
        "LEFT JOIN users u ON u.id=p.author_user_id WHERE "
        + where
        + " ORDER BY p.id DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
        _connection,
    )
    return [
        cast(
            Pull,
            versioned(
                {
                    "id": _integer(r[0]),
                    "title": _text(r[1]),
                    "body": _text(r[2]),
                    "user": {"id": _integer(r[3]), "login": _text_or_none(r[4])}
                    if r[3] is not None
                    else None,
                    "state": _text(r[5]),
                    "created_at": timestamp(r[6]),
                    "closed_at": timestamp(r[7]),
                    "merged_at": timestamp(r[8]),
                    "head": {"ref": _text(r[9])},
                    "base": {"ref": _text(r[10])},
                    "merge_method": _text_or_none(r[11]),
                    "merge_commit_sha": _text_or_none(r[12]),
                }
            ),
        )
        for r in rows
    ]


def comments(
    kind: str,
    owner: str,
    repo: str,
    identity: int,
    limit: int,
    offset: int,
    comment_id: int | None = None,
    _connection: sqlite3.Connection | None = None,
) -> list[Comment]:
    # Table identifiers come only from this fixed selection, not from requests.
    parent, table, column = (
        ("issues", "issue_comments", "issue_id")
        if kind == "issues"
        else ("pull_requests", "pr_comments", "pr_id")
    )
    extra = " AND c.id=?" if comment_id is not None else ""
    params: list[SQLValue] = [owner, repo, identity]
    if comment_id is not None:
        params.append(comment_id)
    rows = _query(
        f"SELECT c.id,c.body,c.author_user_id,u.username,c.created_at,c.edited_at "
        f"FROM {table} c JOIN {parent} p ON p.id=c.{column} "
        "LEFT JOIN users u ON u.id=c.author_user_id "
        "WHERE p.owner=? AND p.repo=? AND p.id=?" + extra + " ORDER BY c.id ASC LIMIT ? OFFSET ?",
        [*params, limit, offset],
        _connection,
    )
    return [
        cast(
            Comment,
            versioned(
                {
                    "id": _integer(r[0]),
                    "body": _text(r[1]),
                    "user": {"id": _integer(r[2]), "login": _text_or_none(r[3])}
                    if r[2] is not None
                    else None,
                    "created_at": timestamp(r[4]),
                    "edited_at": timestamp(r[5]),
                }
            ),
        )
        for r in rows
    ]


def runs(
    owner: str,
    repo: str,
    limit: int,
    offset: int,
    *,
    identity: int | None = None,
    status: str = "",
    branch: str = "",
) -> list[Run]:
    where = "owner=? AND repo=?"
    params: list[SQLValue] = [owner, repo]
    for column, value in (("id", identity), ("status", status), ("branch", branch)):
        if value is not None and value != "":
            where += f" AND {column}=?"
            params.append(value)
    # Deliberately exclude logs, config snapshots, payloads and notification data.
    rows = _query(
        "SELECT id,event,branch,commit_hash,status,return_code,created_at,started_at,"
        "finished_at,COALESCE(json_extract(payload_json,'$.pipeline_id'),'default') "
        "FROM ci_runs WHERE " + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    )
    return [
        cast(
            Run,
            {
                "id": _integer(r[0]),
                "event": _text(r[1]),
                "branch": _text(r[2]),
                "head_sha": _text(r[3]),
                "status": _text(r[4]),
                "return_code": _integer_or_none(r[5]),
                "created_at": utc_timestamp(r[6]),
                "started_at": utc_timestamp(r[7]),
                "finished_at": utc_timestamp(r[8]),
                "pipeline": _text(r[9]),
            },
        )
        for r in rows
    ]


def run_log(owner: str, repo: str, identity: int, offset: int, limit: int) -> SQLRow | None:
    """Slice in SQLite so a legacy oversized log isn't loaded into Python."""
    rows = _query(
        "SELECT status,truncated,length(CAST(output AS BLOB)),"
        "substr(CAST(output AS BLOB),?,?),phase,substr(reason,1,4096) "
        "FROM ci_runs WHERE owner=? AND repo=? AND id=?",
        (offset + 1, limit, owner, repo, identity),
    )
    return rows[0] if rows else None


def artifacts(
    owner: str,
    repo: str,
    limit: int,
    offset: int,
    identity: int | None = None,
) -> list[Artifact]:
    conn = database._db_connect()
    try:
        database._db_ci_cleanup_artifacts(conn, owner, repo)
        days = database._db_ci_retention(conn, owner, repo).get("artifact_retention_days", 7)
        where = "r.owner=? AND r.repo=?"
        params: list[SQLValue] = [owner, repo]
        if identity is not None:
            where += " AND r.id=?"
            params.append(identity)
        expiry = "datetime(a.created_at, ?)" if days else "NULL"
        rows = conn.execute(
            f"SELECT a.run_id,length(a.archive),a.created_at,{expiry} "
            "FROM ci_artifacts a JOIN ci_runs r ON r.id=a.run_id WHERE "
            + where
            + " ORDER BY a.run_id DESC LIMIT ? OFFSET ?",
            ([f"+{days} days"] if days else []) + [*params, limit, offset],
        ).fetchall()
        return [
            cast(
                Artifact,
                {
                    "id": _integer(r[0]),
                    "run_id": _integer(r[0]),
                    "name": f"ci-{_integer(r[0])}-artifacts.zip",
                    "size_in_bytes": _integer(r[1]),
                    "created_at": utc_timestamp(r[2]),
                    "expires_at": utc_timestamp(r[3]),
                },
            )
            for r in rows
        ]
    finally:
        conn.close()


def artifact_content(
    owner: str,
    repo: str,
    identity: int,
    maximum: int,
    *,
    head: bool = False,
) -> SQLRow | None:
    conn = database._db_connect()
    try:
        database._db_ci_cleanup_artifacts(conn, owner, repo)
        # A single statement checks size and fetches data from the same version.
        # HEAD and oversized archives never transfer the BLOB into Python.
        content = "NULL" if head else "CASE WHEN length(a.archive)<=? THEN a.archive ELSE NULL END"
        row = conn.execute(
            f"SELECT length(a.archive),{content} FROM ci_artifacts a "
            "JOIN ci_runs r ON r.id=a.run_id WHERE r.owner=? AND r.repo=? AND r.id=?",
            ([] if head else [maximum]) + [owner, repo, identity],
        ).fetchone()
        return cast(tuple[Any, ...] | None, row)
    finally:
        conn.close()


def discussions(
    owner: str,
    repo: str,
    limit: int,
    offset: int,
    *,
    identity: int | None = None,
    category: str = "",
    locked: bool | None = None,
    connection: sqlite3.Connection | None = None,
) -> list[Discussion]:
    where = "d.owner=? AND d.repo=?"
    params: list[SQLValue] = [owner, repo]
    for column, value in (
        ("d.id", identity),
        ("d.category", category or None),
        ("d.locked", locked),
    ):
        if value is not None:
            where += f" AND {column}=?"
            params.append(value)
    rows = _query(
        "SELECT d.id,d.category,d.title,d.body,d.author_user_id,u.username,d.locked,"
        "d.locked_by,d.answered_comment_id,d.created_at,d.updated_at "
        "FROM discussions d LEFT JOIN users u ON u.id=d.author_user_id WHERE "
        + where
        + " ORDER BY d.id DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
        connection,
    )
    return [
        cast(
            Discussion,
            versioned(
                {
                    "id": _integer(r[0]),
                    "category": _text(r[1]),
                    "title": _text(r[2]),
                    "body": _text(r[3]),
                    "user": {"id": _integer(r[4]), "login": _text_or_none(r[5])}
                    if r[4] is not None
                    else None,
                    "locked": bool(r[6]),
                    "locked_by": _integer_or_none(r[7]),
                    "answered_comment_id": _integer_or_none(r[8]),
                    "created_at": utc_timestamp(r[9]),
                    "updated_at": utc_timestamp(r[10]),
                }
            ),
        )
        for r in rows
    ]


def discussion_comments(
    owner: str,
    repo: str,
    identity: int,
    limit: int,
    offset: int,
    *,
    comment_id: int | None = None,
    connection: sqlite3.Connection | None = None,
) -> list[Comment]:
    params: list[SQLValue] = [owner, repo, identity]
    extra = ""
    if comment_id is not None:
        extra = " AND c.id=?"
        params.append(comment_id)
    rows = _query(
        "SELECT c.id,c.body,c.author_user_id,u.username,c.created_at,c.edited_at "
        "FROM discussion_comments c JOIN discussions d ON d.id=c.discussion_id "
        "LEFT JOIN users u ON u.id=c.author_user_id "
        "WHERE d.owner=? AND d.repo=? AND d.id=?" + extra + " ORDER BY c.id ASC LIMIT ? OFFSET ?",
        [*params, limit, offset],
        connection,
    )
    return [
        cast(
            Comment,
            versioned(
                {
                    "id": _integer(r[0]),
                    "body": _text(r[1]),
                    "user": {"id": _integer(r[2]), "login": _text_or_none(r[3])}
                    if r[2] is not None
                    else None,
                    "created_at": utc_timestamp(r[4]),
                    "edited_at": utc_timestamp(r[5]),
                }
            ),
        )
        for r in rows
    ]
