"""Repository-scoped deployment diagnostics with SQL-bounded log reads."""

import asyncio
import re

from . import data
from .errors import APIError


def records(owner, repo, limit, offset, identity=None):
    rows = data._query(
        "SELECT d.id,d.run_id,d.commit_hash,d.status,d.started_at,d.finished_at,"
        "substr(d.notification,1,256),"
        "substr(json_extract(d.config_json,'$.deployment_name'),1,256),"
        "substr(json_extract(d.config_json,'$.pipeline_id'),1,256),"
        "substr(json_extract(d.config_json,'$.deploy_branch'),1,256),"
        "EXISTS(SELECT 1 FROM ci_runs r WHERE r.id=d.run_id),"
        "length(CAST(d.output AS BLOB)) FROM ci_deployments d "
        "WHERE d.owner=? AND d.repo=?" + (" AND d.id=?" if identity is not None else "") +
        " ORDER BY d.id DESC LIMIT ? OFFSET ?",
        [owner, repo, *([identity] if identity is not None else []), limit, offset])
    return [{"id": r[0], "run_id": r[1], "commit_sha": r[2], "status": r[3],
             "started_at": data.utc_timestamp(r[4]), "finished_at": data.utc_timestamp(r[5]),
             "notification": r[6], "name": r[7] or r[8] or "default",
             "pipeline": r[8] or "default", "branch": r[9],
             "run_retained": bool(r[10]), "log_size_in_bytes": r[11]} for r in rows]


def steps(owner, repo, identity, limit, offset):
    rows = data._query(
        "SELECT CAST(s.key AS INTEGER),substr(json_extract(s.value,'$.name'),1,256),"
        "substr(json_extract(s.value,'$.status'),1,64),"
        "length(CAST(COALESCE(json_extract(s.value,'$.output'),'') AS BLOB)) "
        "FROM ci_deployments d,json_each(d.steps_json) s "
        "WHERE d.owner=? AND d.repo=? AND d.id=? ORDER BY CAST(s.key AS INTEGER) LIMIT ? OFFSET ?",
        [owner, repo, identity, limit, offset])
    return [{"index": r[0], "name": r[1], "status": r[2], "log_size_in_bytes": r[3]} for r in rows]


def log(owner, repo, identity, offset, limit, step=None):
    if step is None:
        rows = data._query(
            "SELECT status,length(CAST(output AS BLOB)),substr(CAST(output AS BLOB),?,?) "
            "FROM ci_deployments WHERE owner=? AND repo=? AND id=?",
            [offset + 1, limit, owner, repo, identity])
    else:
        rows = data._query(
            "SELECT json_extract(s.value,'$.status'),"
            "length(CAST(COALESCE(json_extract(s.value,'$.output'),'') AS BLOB)),"
            "substr(CAST(COALESCE(json_extract(s.value,'$.output'),'') AS BLOB),?,?) "
            "FROM ci_deployments d,json_each(d.steps_json) s "
            "WHERE d.owner=? AND d.repo=? AND d.id=? AND CAST(s.key AS INTEGER)=?",
            [offset + 1, limit, owner, repo, identity, step])
    return rows[0] if rows else None


async def read(api, owner, repo, tail):
    if tail == "deployments":
        api.parameters()
        return api.listing(await asyncio.to_thread(records, owner, repo, api.per_page + 1, api.offset))
    match = re.fullmatch(r"deployments/([0-9]{1,18})(?:/(steps|logs|steps/([0-9]{1,3})/logs))?", tail)
    if not match:
        raise APIError(404, "not_found", "Deployment endpoint not found.")
    identity, resource, step = int(match[1]), match[2], match[3]
    if resource and resource.endswith("logs"):
        api.parameters("offset", "limit")
        offset = api.integer("offset", 0, 0, 2147483647)
        limit = api.integer("limit", 16384, 4, 65536)
        row = await asyncio.to_thread(log, owner, repo, identity, offset, limit,
                                      int(step) if step is not None else None)
        if row is None:
            raise APIError(404, "not_found", "Deployment or step not found.")
        status, size, chunk = row
        if offset > size:
            raise APIError(400, "invalid_offset", "Log offset exceeds stored size.")
        chunk = chunk or b""
        try:
            content = chunk.decode("utf-8")
        except UnicodeDecodeError as exc:
            if exc.reason != "unexpected end of data":
                raise APIError(400, "invalid_offset", "Use a UTF-8 character boundary.") from None
            chunk = chunk[:exc.start]
            content = chunk.decode("utf-8")
        next_offset = offset + len(chunk)
        return {"deployment_id": identity, "step_index": int(step) if step is not None else None,
                "status": status, "encoding": "utf-8", "content": content,
                "offset": offset, "next_offset": next_offset, "size_in_bytes": size,
                "has_more": next_offset < size,
                "complete": status not in ("queued", "running") and next_offset == size}
    api.parameters()
    rows = await asyncio.to_thread(records, owner, repo, 1, 0, identity)
    if not rows:
        raise APIError(404, "not_found", "Deployment not found.")
    if resource == "steps":
        return api.listing(await asyncio.to_thread(steps, owner, repo, identity,
                                                  api.per_page + 1, api.offset))
    return rows[0]
