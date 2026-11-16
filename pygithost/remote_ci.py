"""Outbound HTTP CI protocol. Runner credentials are separate from user tokens."""

import asyncio
import base64
import hashlib
import hmac
import io
import json
import re
import secrets
import subprocess
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from . import database
from .api.errors import APIError
from .api.router import API

MAX_SOURCE = 32 * 1024 * 1024
MAX_ARTIFACT = 16 * 1024 * 1024
LEASE = 90


def connect():
    conn = database._db_connect()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS ci_runner_tokens (
            digest TEXT PRIMARY KEY, name TEXT NOT NULL, repositories TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS ci_remote_jobs (
            run_id INTEGER PRIMARY KEY, owner TEXT NOT NULL, repo TEXT NOT NULL,
            document TEXT NOT NULL, source BLOB NOT NULL,
            state TEXT NOT NULL DEFAULT 'queued', runner TEXT, attempt TEXT,
            heartbeat REAL, result TEXT, artifact BLOB);
    """)
    return conn


def create_token(name, repositories):
    if not repositories or not all(re.fullmatch(r"[^/\s]+/[^/\s]+", r) for r in repositories):
        raise ValueError("Provide explicit owner/repository restrictions.")
    token = secrets.token_urlsafe(32)
    conn = connect()
    try:
        conn.execute("INSERT INTO ci_runner_tokens VALUES(?,?,?)",
                     (hashlib.sha256(token.encode()).hexdigest(), name, json.dumps(repositories)))
    finally:
        conn.close()
    return token


def recover_jobs():
    """A scheduler restart cannot prove that a remote process has stopped."""
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""UPDATE ci_runs SET status='interrupted',return_code=-1,
            finished_at=datetime('now'),reason='HTTP runner coordinator restarted; no automatic replay.'
            WHERE status IN ('queued','running') AND id IN
            (SELECT run_id FROM ci_remote_jobs WHERE state IN ('queued','claimed','finished'))""")
        conn.execute("UPDATE ci_remote_jobs SET state='closed',source=X'',artifact=NULL WHERE state!='closed'")
        conn.commit()
    finally:
        conn.close()


def source_bundle(bare, commit, head):
    """Bundle only the required histories, never expose server paths/credentials."""
    for value in (commit, head):
        if value and not re.fullmatch(r"[0-9a-fA-F]{40,64}", value):
            raise ValueError("Remote CI requires full commit IDs.")
    with tempfile.TemporaryDirectory(prefix="pygithost-bundle-") as root:
        clone, bundle = str(Path(root) / "repo.git"), Path(root) / "source.bundle"
        def git(*args):
            subprocess.run(["git", *args], check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=60)
        git("clone", "--bare", "--shared", "--", str(Path(bare).resolve()), clone)
        refs = []
        for name, sha in (("base", commit), ("head", head)):
            if sha:
                ref = "refs/heads/ci-" + name
                git("--git-dir", clone, "update-ref", ref, sha)
                refs.append(ref)
        git("--git-dir", clone, "bundle", "create", str(bundle), *refs)
        if bundle.stat().st_size > MAX_SOURCE:
            raise ValueError("Remote CI source exceeds the 32 MiB bundle limit.")
        return bundle.read_bytes()


async def execute_remote(manager, row, config):
    from .ci import _db_call
    run_id, owner, repo, event, branch, commit, payload = row
    # Deployment configuration never leaves GitHost.
    execution = {k: v for k, v in config.items()
                 if not k.startswith("deploy") and k not in ("document", "pipelines")}
    execution.update(runner="docker", email_mode="off")
    source = await asyncio.to_thread(source_bundle, manager.repo_path(owner, repo),
                                    commit, json.loads(payload).get("head_commit", ""))
    document = json.dumps(dict(row=list(row), config=execution))
    def enqueue():
        conn = connect()
        try:
            # Never replace an existing attempt, including uncertain executions.
            conn.execute("INSERT INTO ci_remote_jobs(run_id,owner,repo,document,source) VALUES(?,?,?,?,?)",
                         (run_id, owner, repo, document, source))
        finally:
            conn.close()
    await asyncio.to_thread(enqueue)
    await _db_call(database.db_ci_run_update, run_id, phase="waiting for HTTP runner")
    try:
        while True:
            def state():
                conn = connect()
                try:
                    return conn.execute("SELECT state,heartbeat,result,artifact FROM ci_remote_jobs WHERE run_id=?",
                                        (run_id,)).fetchone()
                finally:
                    conn.close()
            status, heartbeat, result, artifact = await asyncio.to_thread(state)
            if status == "finished":
                values = json.loads(result)
                steps = values.pop("steps", [])
                await _db_call(database.db_ci_steps_set, run_id, json.dumps(steps))
                if artifact:
                    await _db_call(database.db_ci_artifact_set, run_id, artifact)
                await _db_call(database.db_ci_run_update, run_id, **values)
                return
            if status == "claimed" and time.time() - heartbeat > LEASE:
                await _db_call(database.db_ci_run_update, run_id, status="interrupted", return_code=-1,
                               reason="Remote runner heartbeat expired; execution is uncertain. No automatic retry.",
                               finished_at=datetime.now(timezone.utc).isoformat())
                return
            await asyncio.sleep(1)
    finally:
        def close():
            conn = connect()
            try:
                conn.execute("UPDATE ci_remote_jobs SET state='closed',source=X'',artifact=NULL WHERE run_id=?",
                             (run_id,))
            finally:
                conn.close()
        await asyncio.to_thread(close)


def operation(digest, repositories, action, document):
    """All claims and attempt transitions are serialized by SQLite."""
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if action == "claim":
            # Startup recovery/retention may have interrupted or removed a run.
            conn.execute("""UPDATE ci_remote_jobs SET state='closed',source=X'',artifact=NULL
                WHERE state IN ('queued','claimed') AND NOT EXISTS
                (SELECT 1 FROM ci_runs r WHERE r.id=run_id AND r.status IN ('queued','running'))""")
            # Repeated claim requests after a lost response return the same job.
            row = conn.execute("SELECT run_id,document,attempt FROM ci_remote_jobs WHERE runner=? AND state='claimed'",
                               (digest,)).fetchone()
            if not row:
                for candidate in conn.execute(
                        "SELECT run_id,owner,repo,document FROM ci_remote_jobs WHERE state='queued' ORDER BY run_id"):
                    run_id, owner, repo, raw = candidate
                    if f"{owner}/{repo}" not in repositories:
                        continue
                    attempt = secrets.token_hex(32)
                    conn.execute("UPDATE ci_remote_jobs SET state='claimed',runner=?,attempt=?,heartbeat=? WHERE run_id=?",
                                 (digest, attempt, time.time(), run_id))
                    row = (run_id, raw, attempt)
                    break
            conn.commit()
            return {"job": dict(json.loads(row[1]), run_id=row[0], attempt=row[2]) if row else None}
        run_id, attempt = document.get("run_id"), document.get("attempt")
        if type(run_id) is not int or not isinstance(attempt, str):
            raise APIError(422, "validation_error", "A run_id and attempt are required.")
        row = conn.execute("SELECT owner,repo,state,runner,attempt,source,heartbeat FROM ci_remote_jobs WHERE run_id=?",
                           (run_id,)).fetchone()
        if (not row or f"{row[0]}/{row[1]}" not in repositories or row[3] != digest
                or not hmac.compare_digest(row[4] or "", attempt)):
            raise APIError(404, "not_found", "Assigned job not found.")
        run = conn.execute("SELECT status FROM ci_runs WHERE id=?", (run_id,)).fetchone()
        if not run or run[0] not in ("queued", "running"):
            conn.execute("UPDATE ci_remote_jobs SET state='closed',source=X'',artifact=NULL WHERE run_id=?", (run_id,))
            conn.commit()
            return {"cancel": True}
        if row[2] != "claimed" or time.time() - row[6] > LEASE:
            # A duplicate completion is acknowledged, but never applied twice.
            if action == "complete" and row[2] == "finished":
                conn.commit()
                return {"accepted": True}
            conn.commit()
            return {"cancel": True}
        if action == "source":
            conn.execute("UPDATE ci_remote_jobs SET heartbeat=? WHERE run_id=?", (time.time(), run_id))
            conn.commit()
            return {"bundle": base64.b64encode(row[5]).decode()}
        if action not in ("heartbeat", "complete"):
            raise APIError(404, "not_found", "Unknown runner operation.")
        values = validate_progress(document.get("progress", {}), final=action == "complete")
        artifact = None
        if action == "complete" and document.get("artifact"):
            try:
                artifact = base64.b64decode(document["artifact"], validate=True)
            except (ValueError, TypeError):
                raise APIError(422, "validation_error", "Invalid artifact encoding.") from None
            if len(artifact) > MAX_ARTIFACT:
                raise APIError(413, "too_large", "Artifact exceeds 16 MiB.")
            try:
                with zipfile.ZipFile(io.BytesIO(artifact)) as archive:
                    files = archive.infolist()
                    if (len(files) > 1000 or sum(f.file_size for f in files) > 20 * 1024 * 1024
                            or any(f.filename.startswith(("/", "\\")) or "\\" in f.filename
                                   or ".." in f.filename.split("/") for f in files)):
                        raise ValueError()
            except (ValueError, zipfile.BadZipFile):
                raise APIError(422, "validation_error", "Invalid or excessive artifact ZIP.") from None
        if action == "complete":
            conn.execute("UPDATE ci_remote_jobs SET state='finished',result=?,artifact=? WHERE run_id=?",
                         (json.dumps(values), artifact, run_id))
        else:
            conn.execute("UPDATE ci_remote_jobs SET heartbeat=? WHERE run_id=?", (time.time(), run_id))
            updates = {k: v for k, v in values.items() if k in ("output", "truncated", "phase")}
            updates["status"] = "running"
            if updates:
                conn.execute("UPDATE ci_runs SET " + ",".join(k + "=?" for k in updates) + " WHERE id=?",
                             (*updates.values(), run_id))
                conn.execute("UPDATE ci_runs SET started_at=COALESCE(started_at,datetime('now')) WHERE id=?", (run_id,))
            if "steps" in values:
                conn.execute("INSERT OR REPLACE INTO ci_steps VALUES(?,?)", (run_id, json.dumps(values["steps"])))
        conn.commit()
        return {"accepted": True, "cancel": False}
    finally:
        conn.close()


def validate_progress(raw, *, final):
    from .ci import MAX_OUTPUT
    allowed = {"status", "output", "truncated", "return_code", "finished_at",
               "started_at", "phase", "reason", "warnings", "steps"}
    if not isinstance(raw, dict) or set(raw) - allowed:
        raise APIError(422, "validation_error", "Invalid progress fields.")
    if len(json.dumps(raw, ensure_ascii=False).encode()) > 3 * MAX_OUTPUT:
        raise APIError(413, "too_large", "Progress exceeds 3 MiB.")
    if final and (raw.get("status") not in ("success", "failed", "timed_out", "interrupted")
                  or type(raw.get("return_code")) is not int
                  or (raw.get("status") == "success" and raw["return_code"] != 0)):
        raise APIError(422, "validation_error", "Invalid terminal result.")
    for key in allowed - {"steps", "truncated", "return_code"}:
        if key in raw and (not isinstance(raw[key], str) or len(raw[key].encode()) > MAX_OUTPUT):
            raise APIError(422, "validation_error", "Invalid progress text.")
    if "steps" in raw and (not isinstance(raw["steps"], list) or len(raw["steps"]) > 64):
        raise APIError(422, "validation_error", "Invalid steps.")
    for step in raw.get("steps", []):
        if (not isinstance(step, dict) or not isinstance(step.get("name"), str)
                or step.get("status") not in ("pending", "running", "success", "failed",
                                              "skipped", "cancelled", "interrupted", "timed_out")
                or not isinstance(step.get("output", ""), str)):
            raise APIError(422, "validation_error", "Invalid step state.")
    if "truncated" in raw and type(raw["truncated"]) is not int:
        raise APIError(422, "validation_error", "Invalid truncation flag.")
    return raw


class RunnerAPI(API):
    async def dispatch(self):
        try:
            if not self.app._ip_allowed(self.request.peer_ip, self.handler.server.allowlist):
                raise APIError(403, "forbidden", "Client IP is not allowed.")
            self.handler.server.api_limiter.check(("runner-ip", self.request.peer_ip))
            authorization = self.request.headers.get("Authorization", "")
            if (len([k for k, _v in self.request.headers.items() if k.lower() == "authorization"]) != 1
                    or not authorization.startswith("Bearer ") or len(authorization) > 256):
                raise APIError(401, "unauthorized", "Runner bearer token required.")
            digest = hashlib.sha256(authorization[7:].encode()).hexdigest()
            def authenticate():
                conn = connect()
                try:
                    return conn.execute("SELECT repositories FROM ci_runner_tokens WHERE digest=?", (digest,)).fetchone()
                finally:
                    conn.close()
            token = await asyncio.to_thread(authenticate)
            if not token:
                raise APIError(401, "unauthorized", "Invalid runner token.")
            action = self.request.target.removeprefix("/api/runner/v1/")
            if action == "openapi.json" and self.request.method == "GET":
                return await self.send(200, runner_specification())
            if self.request.method != "POST":
                raise APIError(405, "method_not_allowed", "Runner operations use POST.")
            if action not in ("claim", "source", "heartbeat", "complete"):
                raise APIError(404, "not_found", "Unknown runner operation.")
            # Larger body only for bounded artifact completion; standard API limits remain unchanged.
            size = self.request.headers.get("Content-Length", "")
            if (len([k for k, _v in self.request.headers.items() if k.lower() == "content-length"]) != 1
                    or self.request.headers.get("Transfer-Encoding") or not size.isascii() or not size.isdecimal()
                    or len(size) > 8 or int(size) > 26 * 1024 * 1024):
                raise APIError(413, "too_large", "Runner request exceeds 26 MiB or lacks a valid length.")
            if self.request.headers.get("Content-Type", "").split(";")[0] != "application/json":
                raise APIError(415, "unsupported_media_type", "Use application/json.")
            async with self.handler.server.api_slots:
                async with asyncio.timeout(60):
                    raw = await self.request.reader.readexactly(int(size))
                    def pairs(items):
                        result = {}
                        for key, value in items:
                            if key in result:
                                raise ValueError("Duplicate JSON key")
                            result[key] = value
                        return result
                    def constant(_value):
                        raise ValueError("Non-finite JSON number")
                    try:
                        document = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                                              parse_constant=constant)
                        json.dumps(document, ensure_ascii=False, allow_nan=False).encode("utf-8")
                    except (ValueError, UnicodeError, RecursionError):
                        raise APIError(400, "invalid_json", "Invalid JSON.") from None
                    if not isinstance(document, dict):
                        raise APIError(422, "validation_error", "Expected a JSON object.")
                    result = await asyncio.to_thread(operation, digest, json.loads(token[0]), action, document)
            body = json.dumps(result).encode()
            await self.app._send_response(self.request, 200, body, [
                ("Content-Type", "application/json"), ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff")])
        except APIError as exc:
            await self.send(exc.status, {"code": exc.code, "message": exc.message})
        except TimeoutError:
            await self.send(504, {"code": "timeout", "message": "Runner request timed out."})
        except self.app.ClientDisconnected:
            raise
        except Exception as exc:
            self.log_failure(exc)
            await self.send(500, {"code": "internal_error", "message": "Runner request failed."})


def runner_specification():
    identity = {"run_id": {"type": "integer", "minimum": 1},
                "attempt": {"type": "string", "pattern": "^[a-f0-9]{64}$"}}
    progress = {"type": "object", "properties": {
        "status": {"enum": ["success", "failed", "timed_out", "interrupted"]},
        "return_code": {"type": "integer"}, "output": {"type": "string"},
        "truncated": {"type": "integer"}, "phase": {"type": "string"},
        "started_at": {"type": "string"}, "finished_at": {"type": "string"},
        "reason": {"type": "string"}, "warnings": {"type": "string"},
        "steps": {"type": "array", "maxItems": 64, "items": {"type": "object"}}},
        "additionalProperties": False}
    paths = {}
    for action in ("claim", "source", "heartbeat", "complete"):
        properties = {} if action == "claim" else dict(identity)
        required = [] if action == "claim" else list(identity)
        if action in ("heartbeat", "complete"):
            properties["progress"] = progress
        if action == "complete":
            required.append("progress")
            properties["artifact"] = {"type": "string", "contentEncoding": "base64",
                                      "description": "Optional ZIP, at most 16 MiB compressed."}
        paths["/" + action] = {"post": {
            "operationId": "runner_" + action,
            "description": "Repository-restricted runner token required. Assignment identity makes retries safe; no Idempotency-Key.",
            "requestBody": {"required": True, "content": {"application/json": {"schema": {
                "type": "object", "properties": properties, "required": required}}}},
            "responses": {"200": {"description": "Job, bundle, acknowledgement or cancel flag.",
                                   "content": {"application/json": {"schema": {"type": "object"}}}},
                          "401": {"description": "Invalid or revoked runner token."},
                          "404": {"description": "Unknown operation or foreign assignment."},
                          "413": {"description": "Request or artifact limit exceeded."},
                          "422": {"description": "Invalid assignment or progress."}}}}
    return {"openapi": "3.1.0", "info": {"title": "PyGitHost runner protocol", "version": "1.0.0"},
            "servers": [{"url": "/api/runner/v1"}], "paths": paths,
            "security": [{"runnerToken": []}],
            "components": {"securitySchemes": {"runnerToken": {"type": "http", "scheme": "bearer"}}}}
