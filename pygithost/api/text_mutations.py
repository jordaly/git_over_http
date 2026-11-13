"""Repository-scoped issue/PR/comment edits with transactional revision checks."""

from .. import database
from . import data
from .errors import APIError
from .validation import expected_revision, fields, text


def edit(kind, owner, repo, identity, document, actor, *, comment_id=None, delete=False):
    """BEGIN IMMEDIATE serializes with web edits, not just other API requests."""
    if comment_id is not None:
        allowed = {"expected_revision"} | (set() if delete else {"body"})
    else:
        allowed = {"expected_revision", "title", "body", "state"}
    fields(document, allowed, {"expected_revision"})
    expected_revision(document)
    if not delete and set(document) == {"expected_revision"}:
        raise APIError(422, "validation_error", "Provide at least one field to update.")
    if "title" in document:
        text(document, "title", maximum=256)
    if "body" in document:
        text(document, "body", empty=comment_id is None)
    if "state" in document and document["state"] not in ("open", "closed"):
        raise APIError(422, "validation_error", "State must be open or closed.")
    read = data.issues if kind == "issues" else data.pulls
    table = "issues" if kind == "issues" else "pull_requests"
    conn = database._db_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        parent = read(owner, repo, "all", 1, 0, identity, _connection=conn)
        if not parent:
            raise APIError(404, "not_found", "Resource not found.")
        if comment_id is None:
            current = parent[0]
        else:
            found = data.comments(kind, owner, repo, identity, 1, 0, comment_id, _connection=conn)
            if not found:
                raise APIError(404, "not_found", "Comment not found.")
            current = found[0]
            if not actor["is_admin"] and (not current["user"] or current["user"]["id"] != actor["user_id"]):
                raise APIError(403, "forbidden", "Only the comment author or an administrator can edit or delete it.")
        if document["expected_revision"] != current["revision"]:
            raise APIError(409, "revision_conflict", "Resource changed. Fetch its current revision before updating.")
        if comment_id is None and kind == "pulls" and current["state"] == "merged":
            raise APIError(409, "state_conflict", "Merged pull requests cannot be edited or reopened.")
        if comment_id is not None:
            comment_table = "issue_comments" if kind == "issues" else "pr_comments"
            if delete:
                conn.execute(f"DELETE FROM {comment_table} WHERE id=?", (comment_id,))
                result = {"deleted": True, "id": comment_id}
            else:
                conn.execute(f"UPDATE {comment_table} SET body=?,edited_at=datetime('now','localtime') WHERE id=?",
                             (document["body"], comment_id))
                result = data.comments(kind, owner, repo, identity, 1, 0, comment_id, _connection=conn)[0]
        else:
            updates, params = [], []
            for key in ("title", "body"):
                if key in document:
                    updates.append(key + "=?")
                    params.append(document[key])
            if "state" in document:
                updates.extend(["status=?", "closed_at=" +
                                ("datetime('now','localtime')" if document["state"] == "closed" else "NULL")])
                params.append(document["state"])
            if kind == "issues":
                updates.append("updated_at=datetime('now','localtime')")
            conn.execute(f"UPDATE {table} SET {','.join(updates)} WHERE id=? AND owner=? AND repo=?",
                         [*params, identity, owner, repo])
            result = read(owner, repo, "all", 1, 0, identity, _connection=conn)[0]
        conn.commit()
        return result
    finally:
        conn.close()
