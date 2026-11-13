"""Bounded repository-scoped reads and explicit public serializers."""

from datetime import datetime, timezone
import hashlib
import json

from .. import database


def timestamp(value):
    if not value:
        return None
    # Legacy SQLite timestamps are server-local wall time, not UTC.
    parsed = datetime.fromisoformat(value)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def utc_timestamp(value):
    """CI's SQLite defaults use datetime('now'), unlike legacy UI local time."""
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _query(sql, params, connection=None):
    if connection is not None:
        return connection.execute(sql, params).fetchall()
    conn = database._db_connect()
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def revision(value):
    """Content revision also catches edits made by the existing HTML handlers."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def versioned(value):
    return {**value, "revision": revision(value)}


def issue(row):
    return versioned({
        "id": row[0], "title": row[1], "body": row[2],
        "user": {"id": row[3], "login": row[4]} if row[3] is not None else None,
        "state": row[5], "created_at": timestamp(row[6]),
        "updated_at": timestamp(row[7]), "closed_at": timestamp(row[8]),
    })


def issues(owner, repo, state, limit, offset, identity=None, _connection=None):
    where, params = "i.owner=? AND i.repo=?", [owner, repo]
    if identity is not None:
        where += " AND i.id=?"
        params.append(identity)
    if state != "all":
        where += " AND i.status=?"
        params.append(state)
    rows = _query(
        "SELECT i.id,i.title,i.body,i.author_user_id,u.username,i.status,"
        "i.created_at,i.updated_at,i.closed_at FROM issues i "
        "LEFT JOIN users u ON u.id=i.author_user_id WHERE " + where +
        " ORDER BY i.id DESC LIMIT ? OFFSET ?", [*params, limit, offset], _connection)
    return [issue(row) for row in rows]


def pulls(owner, repo, state, limit, offset, identity=None, _connection=None):
    where, params = "p.owner=? AND p.repo=?", [owner, repo]
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
        "LEFT JOIN users u ON u.id=p.author_user_id WHERE " + where +
        " ORDER BY p.id DESC LIMIT ? OFFSET ?", [*params, limit, offset], _connection)
    return [versioned({
        "id": r[0], "title": r[1], "body": r[2],
        "user": {"id": r[3], "login": r[4]} if r[3] is not None else None,
        "state": r[5], "created_at": timestamp(r[6]), "closed_at": timestamp(r[7]),
        "merged_at": timestamp(r[8]), "head": {"ref": r[9]}, "base": {"ref": r[10]},
        "merge_method": r[11], "merge_commit_sha": r[12],
    }) for r in rows]


def comments(kind, owner, repo, identity, limit, offset, comment_id=None, _connection=None):
    # Table identifiers come only from this fixed selection, not from requests.
    parent, table, column = (
        ("issues", "issue_comments", "issue_id") if kind == "issues"
        else ("pull_requests", "pr_comments", "pr_id"))
    extra = " AND c.id=?" if comment_id is not None else ""
    params = [owner, repo, identity]
    if comment_id is not None:
        params.append(comment_id)
    rows = _query(
        f"SELECT c.id,c.body,c.author_user_id,u.username,c.created_at,c.edited_at "
        f"FROM {table} c JOIN {parent} p ON p.id=c.{column} "
        "LEFT JOIN users u ON u.id=c.author_user_id "
        "WHERE p.owner=? AND p.repo=? AND p.id=?" + extra + " ORDER BY c.id ASC LIMIT ? OFFSET ?",
        [*params, limit, offset], _connection)
    return [versioned({
        "id": r[0], "body": r[1],
        "user": {"id": r[2], "login": r[3]} if r[2] is not None else None,
        "created_at": timestamp(r[4]),
        "edited_at": timestamp(r[5]),
    }) for r in rows]


def runs(owner, repo, limit, offset, *, identity=None, status="", branch=""):
    where, params = "owner=? AND repo=?", [owner, repo]
    for column, value in (("id", identity), ("status", status), ("branch", branch)):
        if value is not None and value != "":
            where += f" AND {column}=?"
            params.append(value)
    # Deliberately exclude logs, config snapshots, payloads and notification data.
    rows = _query(
        "SELECT id,event,branch,commit_hash,status,return_code,created_at,started_at,"
        "finished_at,COALESCE(json_extract(payload_json,'$.pipeline_id'),'default') "
        "FROM ci_runs WHERE " + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
        [*params, limit, offset])
    return [{
        "id": r[0], "event": r[1], "branch": r[2], "head_sha": r[3],
        "status": r[4], "return_code": r[5], "created_at": utc_timestamp(r[6]),
        "started_at": utc_timestamp(r[7]), "finished_at": utc_timestamp(r[8]), "pipeline": r[9],
    } for r in rows]


def run_log(owner, repo, identity, offset, limit):
    """Slice in SQLite so a legacy oversized log isn't loaded into Python."""
    rows = _query(
        "SELECT status,truncated,length(CAST(output AS BLOB)),"
        "substr(CAST(output AS BLOB),?,?),phase,substr(reason,1,4096) "
        "FROM ci_runs WHERE owner=? AND repo=? AND id=?",
        (offset + 1, limit, owner, repo, identity))
    return rows[0] if rows else None


def artifacts(owner, repo, limit, offset, identity=None):
    conn = database._db_connect()
    try:
        database._db_ci_cleanup_artifacts(conn, owner, repo)
        days = database._db_ci_retention(conn, owner, repo).get("artifact_retention_days", 7)
        where, params = "r.owner=? AND r.repo=?", [owner, repo]
        if identity is not None:
            where += " AND r.id=?"
            params.append(identity)
        expiry = "datetime(a.created_at, ?)" if days else "NULL"
        rows = conn.execute(
            f"SELECT a.run_id,length(a.archive),a.created_at,{expiry} "
            "FROM ci_artifacts a JOIN ci_runs r ON r.id=a.run_id WHERE " + where +
            " ORDER BY a.run_id DESC LIMIT ? OFFSET ?",
            ([f"+{days} days"] if days else []) + [*params, limit, offset]).fetchall()
        return [{
            "id": r[0], "run_id": r[0], "name": f"ci-{r[0]}-artifacts.zip",
            "size_in_bytes": r[1], "created_at": utc_timestamp(r[2]),
            "expires_at": utc_timestamp(r[3]),
        } for r in rows]
    finally:
        conn.close()


def artifact_content(owner, repo, identity, maximum, *, head=False):
    conn = database._db_connect()
    try:
        database._db_ci_cleanup_artifacts(conn, owner, repo)
        # A single statement checks size and fetches data from the same version.
        # HEAD and oversized archives never transfer the BLOB into Python.
        content = "NULL" if head else "CASE WHEN length(a.archive)<=? THEN a.archive ELSE NULL END"
        row = conn.execute(
            f"SELECT length(a.archive),{content} FROM ci_artifacts a "
            "JOIN ci_runs r ON r.id=a.run_id WHERE r.owner=? AND r.repo=? AND r.id=?",
            ([] if head else [maximum]) + [owner, repo, identity]).fetchone()
        return row
    finally:
        conn.close()


def discussions(owner, repo, limit, offset, *, identity=None, category="", locked=None, connection=None):
    where, params = "d.owner=? AND d.repo=?", [owner, repo]
    for column, value in (("d.id", identity), ("d.category", category or None), ("d.locked", locked)):
        if value is not None:
            where += f" AND {column}=?"
            params.append(value)
    rows = _query(
        "SELECT d.id,d.category,d.title,d.body,d.author_user_id,u.username,d.locked,"
        "d.locked_by,d.answered_comment_id,d.created_at,d.updated_at "
        "FROM discussions d LEFT JOIN users u ON u.id=d.author_user_id WHERE " +
        where + " ORDER BY d.id DESC LIMIT ? OFFSET ?", [*params, limit, offset], connection)
    return [versioned({
        "id": r[0], "category": r[1], "title": r[2], "body": r[3],
        "user": {"id": r[4], "login": r[5]} if r[4] is not None else None,
        "locked": bool(r[6]), "locked_by": r[7], "answered_comment_id": r[8],
        "created_at": utc_timestamp(r[9]), "updated_at": utc_timestamp(r[10]),
    }) for r in rows]


def discussion_comments(owner, repo, identity, limit, offset, *, comment_id=None, connection=None):
    params = [owner, repo, identity]
    extra = ""
    if comment_id is not None:
        extra = " AND c.id=?"
        params.append(comment_id)
    rows = _query(
        "SELECT c.id,c.body,c.author_user_id,u.username,c.created_at,c.edited_at "
        "FROM discussion_comments c JOIN discussions d ON d.id=c.discussion_id "
        "LEFT JOIN users u ON u.id=c.author_user_id "
        "WHERE d.owner=? AND d.repo=? AND d.id=?" + extra + " ORDER BY c.id ASC LIMIT ? OFFSET ?",
        [*params, limit, offset], connection)
    return [versioned({
        "id": r[0], "body": r[1],
        "user": {"id": r[2], "login": r[3]} if r[2] is not None else None,
        "created_at": utc_timestamp(r[4]), "edited_at": utc_timestamp(r[5]),
    }) for r in rows]
