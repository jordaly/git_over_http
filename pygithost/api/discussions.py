"""Discussion reads/edits, comment CRUD, locking and accepted answers."""

import asyncio
import re

from .. import database
from ..discussion_rules import CATEGORIES
from . import data
from .errors import APIError
from .validation import expected_revision, fields, text


PATTERN = r"discussions(?:/([0-9]{1,18})(?:/comments(?:/([0-9]{1,18}))?)?)?"


def category(value):
    if value not in CATEGORIES:
        raise APIError(422, "validation_error", "Unknown discussion category.")
    return value


def require(rows, label="Discussion"):
    if not rows:
        raise APIError(404, "not_found", label + " not found.")
    return rows[0]


async def read(api, owner, repo, tail):
    if tail == "discussions/categories":
        api.parameters()
        rows = [{"name": name, "accepts_answers": name == "Q&A"} for name in CATEGORIES]
        return api.listing(rows[api.offset:api.offset + api.per_page + 1])
    match = re.fullmatch(PATTERN, tail)
    if not match:
        raise APIError(404, "not_found", "Discussion endpoint not found.")
    identity, comment_id = match.groups()
    api.parameters(*(["category", "locked"] if not identity else []))
    if not identity:
        from .browsing import query_bool
        selected = api.value("category")
        if selected and selected not in CATEGORIES:
            raise APIError(400, "invalid_query", "Unknown discussion category.")
        return api.listing(await asyncio.to_thread(
            data.discussions, owner, repo, api.per_page + 1, api.offset, category=selected,
            locked=query_bool(api, "locked") if "locked" in api.query else None))
    identity = int(identity)
    parent = require(await asyncio.to_thread(data.discussions, owner, repo, 1, 0, identity=identity))
    if comment_id:
        return require(await asyncio.to_thread(
            data.discussion_comments, owner, repo, identity, 1, 0, comment_id=int(comment_id)), "Comment")
    if tail.endswith("/comments"):
        return api.listing(await asyncio.to_thread(
            data.discussion_comments, owner, repo, identity, api.per_page + 1, api.offset))
    return parent


def mutate(owner, repo, tail, method, document, actor):
    match = re.fullmatch(PATTERN, tail)
    if not match:
        raise APIError(405, "method_not_allowed", "Unsupported discussion mutation.")
    identity, comment_id = match.groups()
    if identity is None and method == "POST":
        fields(document, {"title", "body", "category"}, {"title"})
        text(document, "title", maximum=256)
        if "body" in document:
            text(document, "body", empty=True)
        category(document.get("category", "General"))
    elif identity and not comment_id and tail.endswith("/comments") and method == "POST":
        fields(document, {"body"}, {"body"})
        text(document, "body")
    elif identity and not tail.endswith("/comments") and method in ("PATCH", "DELETE"):
        if comment_id is None and method == "DELETE":
            raise APIError(405, "method_not_allowed", "Discussion deletion is not implemented.")
        allowed = {"expected_revision"}
        if method == "PATCH":
            allowed |= {"body"} if comment_id else {"title", "body", "category", "locked", "answered_comment_id"}
        fields(document, allowed, {"expected_revision"})
        expected_revision(document)
        if method == "PATCH" and len(document) == 1:
            raise APIError(422, "validation_error", "Provide at least one field to update.")
        if "title" in document:
            text(document, "title", maximum=256)
        if "body" in document:
            text(document, "body", empty=comment_id is None)
        if "category" in document:
            category(document["category"])
        if "locked" in document and type(document["locked"]) is not bool:
            raise APIError(422, "validation_error", "locked must be a boolean.")
        if "answered_comment_id" in document:
            answer = document["answered_comment_id"]
            if answer is not None and (type(answer) is not int or not 1 <= answer <= 9223372036854775807):
                raise APIError(422, "validation_error", "answered_comment_id must be a comment ID or null.")
    else:
        raise APIError(405, "method_not_allowed", "Unsupported discussion mutation.")
    conn = database._db_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if identity is None:
            identity = conn.execute(
                "INSERT INTO discussions(owner,repo,category,title,body,author_user_id) VALUES(?,?,?,?,?,?)",
                (owner, repo, document.get("category", "General"), document["title"],
                 document.get("body", ""), actor["user_id"])).lastrowid
            result = data.discussions(owner, repo, 1, 0, identity=identity, connection=conn)[0]
            status = 201
        else:
            identity = int(identity)
            parent = require(data.discussions(owner, repo, 1, 0, identity=identity, connection=conn))
            if tail.endswith("/comments") and method == "POST":
                if parent["locked"]:
                    raise APIError(409, "discussion_locked", "This discussion is locked; new replies are disabled.")
                comment = conn.execute(
                    "INSERT INTO discussion_comments(discussion_id,author_user_id,body) VALUES(?,?,?)",
                    (identity, actor["user_id"], document["body"])).lastrowid
                conn.execute("UPDATE discussions SET updated_at=datetime('now') WHERE id=?", (identity,))
                result = data.discussion_comments(owner, repo, identity, 1, 0, comment_id=comment, connection=conn)[0]
                status = 201
            elif comment_id:
                comment_id = int(comment_id)
                comment = require(data.discussion_comments(
                    owner, repo, identity, 1, 0, comment_id=comment_id, connection=conn), "Comment")
                if not actor["is_admin"] and (not comment["user"] or comment["user"]["id"] != actor["user_id"]):
                    raise APIError(403, "forbidden", "Only the comment author or an administrator can edit or delete it.")
                if document["expected_revision"] != comment["revision"]:
                    raise APIError(409, "revision_conflict", "Comment changed. Fetch its current revision.")
                if method == "DELETE":
                    conn.execute("DELETE FROM discussion_comments WHERE id=?", (comment_id,))
                    conn.execute("UPDATE discussions SET answered_comment_id=NULL,updated_at=datetime('now') "
                                 "WHERE id=? AND answered_comment_id=?", (identity, comment_id))
                    result = {"deleted": True, "id": comment_id}
                else:
                    conn.execute("UPDATE discussion_comments SET body=?,edited_at=datetime('now') WHERE id=?",
                                 (document["body"], comment_id))
                    result = data.discussion_comments(
                        owner, repo, identity, 1, 0, comment_id=comment_id, connection=conn)[0]
                status = 200
            else:
                if document["expected_revision"] != parent["revision"]:
                    raise APIError(409, "revision_conflict", "Discussion changed. Fetch its current revision.")
                values = {key: document.get(key, parent[key]) for key in ("title", "body", "category")}
                answer = document.get("answered_comment_id", parent["answered_comment_id"])
                if answer is not None and "answered_comment_id" in document:
                    if values["category"] != "Q&A":
                        raise APIError(409, "state_conflict", "Only Q&A discussions can have accepted answers.")
                    require(data.discussion_comments(
                        owner, repo, identity, 1, 0, comment_id=answer, connection=conn), "Answer comment")
                if values["category"] != "Q&A":
                    answer = None
                conn.execute("UPDATE discussions SET title=?,body=?,category=?,answered_comment_id=?,"
                             "updated_at=datetime('now') WHERE id=?",
                             (values["title"], values["body"], values["category"], answer, identity))
                if "locked" in document:
                    if document["locked"] and not parent["locked"]:
                        conn.execute("UPDATE discussions SET locked=1,locked_by=?,locked_at=datetime('now') WHERE id=?",
                                     (actor["user_id"], identity))
                    elif not document["locked"]:
                        conn.execute("UPDATE discussions SET locked=0,locked_by=NULL,locked_at=NULL WHERE id=?", (identity,))
                result = data.discussions(owner, repo, 1, 0, identity=identity, connection=conn)[0]
                status = 200
        conn.commit()
        return status, result
    finally:
        conn.close()
