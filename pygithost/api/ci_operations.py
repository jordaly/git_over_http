"""CI automation without configuration overrides, deployment controls or webhooks."""

import asyncio
import re
from urllib.parse import quote

from . import data
from .errors import APIError
from .responses import BinaryDownload
from .validation import fields, sha, text


MAX_LOG_BYTES = 65536
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024


async def run(owner, repo, identity):
    rows = await asyncio.to_thread(data.runs, owner, repo, 1, 0, identity=identity)
    if not rows:
        raise APIError(404, "not_found", "CI run not found.")
    return rows[0]


async def mutate(api, owner, repo, path, tail):
    """Called under the same repository lock as other API/Git mutations."""
    from .writes import branch_head
    manager, document = api.handler.server.ci_manager, api.document
    if tail == "ci/runs":
        fields(document, {"branch", "pipeline", "sha"}, {"branch", "pipeline"})
        branch = text(document, "branch", maximum=256)
        pipeline = text(document, "pipeline", maximum=64)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", pipeline):
            raise APIError(422, "validation_error", "Invalid pipeline name.")
        commit = await branch_head(path, branch)
        if "sha" in document and sha(document, "sha") != commit:
            raise APIError(409, "revision_conflict", "Branch changed. Refresh its SHA before triggering CI.")
        config = await manager.config(owner, repo)
        selected = next((p for p in manager.pipelines(config) if p["pipeline_id"] == pipeline), None)
        if selected is None:
            raise APIError(404, "not_found", "Pipeline not found.")
        if not (selected["steps"] or selected["command"] or selected["repository_config"]):
            raise APIError(409, "pipeline_not_runnable", "Pipeline has no runnable steps or repository file.")
        try:
            identity = await manager.enqueue(owner, repo, "manual", branch, commit, pipeline=pipeline)
        except ValueError:
            raise APIError(409, "pipeline_changed", "Pipeline changed while queuing the run. Refresh its configuration.") from None
        if identity is None:
            raise APIError(409, "run_not_queued", "No run queued. Check the repository CI file and scheduler availability.")
        return 202, await run(owner, repo, identity)
    match = re.fullmatch(r"ci/runs/([0-9]{1,18})/(cancel|rerun)", tail)
    if not match:
        raise APIError(405, "method_not_allowed", "Unsupported CI action.")
    fields(document, set())
    identity, action = int(match[1]), match[2]
    current = await run(owner, repo, identity)
    if action == "cancel":
        if current["status"] == "cancelled":
            return 200, current
        if current["status"] not in ("queued", "running"):
            raise APIError(409, "run_not_cancellable", "Only queued or running CI jobs can be cancelled.")
        if not await manager.cancel(owner, repo, identity):
            raise APIError(409, "run_not_cancellable", "Run finished or is not owned by this scheduler.")
        return 200, await run(owner, repo, identity)
    if current["status"] in ("queued", "running"):
        raise APIError(409, "run_in_progress", "Wait for this run to finish or cancel it before rerunning.")
    try:
        new_identity = await manager.rerun(owner, repo, identity)
    except ValueError:
        raise APIError(409, "snapshot_unavailable", "Run has no usable configuration snapshot. Trigger a new run instead.") from None
    if new_identity is None:
        raise APIError(409, "run_not_queued", "Scheduler could not queue the rerun.")
    return 202, await run(owner, repo, new_identity)


async def read(api, owner, repo, tail):
    if tail == "ci/artifacts":
        api.parameters()
        return api.listing(await artifact_list(api, owner, repo))
    match = re.fullmatch(r"ci/runs/([0-9]{1,18})/(logs|artifacts(?:/download)?)", tail)
    if not match:
        raise APIError(404, "not_found", "CI endpoint not found.")
    identity, resource = int(match[1]), match[2]
    if resource == "logs":
        api.parameters("offset", "limit")
        offset = api.integer("offset", 0, 0, 2147483647)
        limit = api.integer("limit", 16384, 4, MAX_LOG_BYTES)
        row = await asyncio.to_thread(data.run_log, owner, repo, identity, offset, limit)
        if row is None:
            raise APIError(404, "not_found", "CI run not found.")
        status, truncated, size, chunk, phase, reason = row
        chunk = chunk or b""  # SQLite substr of an empty BLOB can return NULL.
        if offset > size:
            raise APIError(400, "invalid_offset", "Log offset exceeds the stored log size.")
        try:
            content = chunk.decode("utf-8")
        except UnicodeDecodeError as exc:
            if exc.reason != "unexpected end of data":
                raise APIError(400, "invalid_offset", "Log offset must be at a UTF-8 character boundary.") from None
            # Do not split a UTF-8 character at the byte limit. Clients continue
            # at the returned next_offset, never by counting JSON characters.
            chunk = chunk[:exc.start]
            content = chunk.decode("utf-8")
        next_offset = offset + len(chunk)
        has_more = next_offset < size
        return {"run_id": identity, "encoding": "utf-8", "content": content,
                "offset": offset, "next_offset": next_offset, "size_in_bytes": size,
                "has_more": has_more, "truncated": bool(truncated), "status": status,
                "complete": status not in ("queued", "running") and not has_more,
                "phase": phase, "reason": reason}
    api.parameters()
    if resource == "artifacts":
        await run(owner, repo, identity)
        return api.listing(await artifact_list(api, owner, repo, identity))
    if api.request.method != "HEAD":
        # Keep this permit through the transfer, not just the database read.
        # Otherwise slow clients could retain an unbounded number of ZIP bodies.
        await api.handler.server.api_download_slots.acquire()
        api.download_slot = True
    row = await asyncio.to_thread(
        data.artifact_content, owner, repo, identity, MAX_ARTIFACT_BYTES,
        head=api.request.method == "HEAD")
    if row is None:
        raise APIError(404, "not_found", "Artifact archive is missing or expired.")
    size, content = row
    if size > MAX_ARTIFACT_BYTES:
        raise APIError(413, "artifact_too_large", "Archive exceeds the 32 MiB API download limit.")
    return BinaryDownload(content or b"", size, f"ci-{identity}-artifacts.zip")


async def artifact_list(api, owner, repo, identity=None):
    rows = await asyncio.to_thread(
        data.artifacts, owner, repo, api.per_page + 1, api.offset, identity)
    base = "/api/v1/repos/" + quote(owner, safe="") + "/" + quote(repo, safe="")
    return [{**row, "downloadable": row["size_in_bytes"] <= MAX_ARTIFACT_BYTES,
             "download_url": base + f"/ci/runs/{row['run_id']}/artifacts/download"} for row in rows]
