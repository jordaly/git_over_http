"""Outbound HTTP CI protocol. Runner credentials are separate from user tokens."""

import asyncio
import base64
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Collection, Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

from . import database
from .api.errors import APIError
from .api.router import API
from .ci_limits import (
    DEFAULT_SOURCE_LIMIT_MB,
    MIB,
    completion_bytes,
    execution_limits,
    progress_bytes,
    source_limit_bytes,
)
from .runner_types import JsonObject, RunRow, SourceManager

LEASE = 90
_SECRET_CONFIG_KEYS = ("env", "pipeline_env", "env_scopes")


def _redacted_document(document: object) -> str:
    """Drop live environment values while retaining durable assignment evidence."""
    try:
        decoded: object = json.loads(document) if isinstance(document, str) else document
    except TypeError, ValueError:
        return "{}"
    if not isinstance(decoded, dict):
        return "{}"
    config = decoded.get("config")
    if isinstance(config, dict):
        for key in _SECRET_CONFIG_KEYS:
            config.pop(key, None)
    return json.dumps(decoded)


def _close_assignments(
    conn: sqlite3.Connection, assignments: Iterable[tuple[object, object]]
) -> None:
    """Close persisted assignments without leaving injected environment values."""
    conn.executemany(
        """UPDATE ci_remote_jobs SET state='closed',document=?,source=X'',source_path=NULL,
        artifact=NULL WHERE run_id=?""",
        [(_redacted_document(document), run_id) for run_id, document in assignments],
    )


def connect() -> database._Connection:
    conn = database._db_connect()
    conn.operation = "remote_ci." + sys._getframe(1).f_code.co_name
    return conn


def initialize_schema(conn: sqlite3.Connection) -> None:
    """Run schema changes once at startup, never during runner polling."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS ci_runner_tokens (
            digest TEXT PRIMARY KEY, name TEXT NOT NULL, repositories TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS ci_remote_jobs (
            run_id INTEGER PRIMARY KEY, owner TEXT NOT NULL, repo TEXT NOT NULL,
            document TEXT NOT NULL, source BLOB NOT NULL,
            state TEXT NOT NULL DEFAULT 'queued', runner TEXT, attempt TEXT,
            heartbeat REAL, result TEXT, artifact BLOB);
        CREATE TABLE IF NOT EXISTS ci_remote_source_cleanup (
            path TEXT PRIMARY KEY,
            created_at TEXT NOT NULL DEFAULT (datetime('now')));
    """)
    if "source_path" not in {r[1] for r in conn.execute("PRAGMA table_info(ci_remote_jobs)")}:
        try:
            conn.execute("ALTER TABLE ci_remote_jobs ADD COLUMN source_path TEXT")
        except Exception:
            if "source_path" not in {
                r[1] for r in conn.execute("PRAGMA table_info(ci_remote_jobs)")
            }:
                raise
    # A previous release closed assignments without removing their injected
    # environment. Scrub terminal rows without changing their terminal state.
    conn.executemany(
        "UPDATE ci_remote_jobs SET document=? WHERE run_id=?",
        [
            (_redacted_document(document), run_id)
            for run_id, document in conn.execute(
                """SELECT run_id,document FROM ci_remote_jobs
                WHERE state NOT IN ('queued','claimed') AND document LIKE '%env%'"""
            )
        ],
    )


def _queue_source_cleanup(conn: sqlite3.Connection, paths: Iterable[str | None]) -> None:
    """Record paths in the same transaction that closes their assignments."""
    conn.executemany(
        "INSERT OR IGNORE INTO ci_remote_source_cleanup(path) VALUES(?)",
        [(str(path),) for path in set(paths) if path],
    )


def _delete_sources(paths: Iterable[str | None]) -> None:
    """Best-effort deletion, retaining failed paths for the next claim/recovery."""
    conn = connect()
    try:
        _queue_source_cleanup(conn, paths)
        pending = [row[0] for row in conn.execute("SELECT path FROM ci_remote_source_cleanup")]
        for path in pending:
            try:
                Path(path).unlink(missing_ok=True)
            except OSError as exc:
                # Windows readers/scanners can temporarily deny deletion. Do not
                # turn a successful/cancelled run or server startup into failure.
                logging.getLogger(__name__).warning(
                    "Remote source cleanup deferred",
                    extra={"event": "source_cleanup_deferred", "error_type": type(exc).__name__},
                )
            else:
                conn.execute("DELETE FROM ci_remote_source_cleanup WHERE path=?", (path,))
    finally:
        conn.close()


def create_token(name: str, repositories: Sequence[str]) -> str:
    if not repositories or not all(re.fullmatch(r"[^/\s]+/[^/\s]+", r) for r in repositories):
        raise ValueError("Provide explicit owner/repository restrictions.")
    token = secrets.token_urlsafe(32)
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO ci_runner_tokens VALUES(?,?,?)",
            (hashlib.sha256(token.encode()).hexdigest(), name, json.dumps(repositories)),
        )
    finally:
        conn.close()
    # Runner tokens grant repository access, so issuance is always audited even
    # when HTTP audit logging is disabled. Audit failures never block issuance.
    try:
        database.db_audit_append(
            "runner_token_create",
            "success",
            actor="cli",
            target=str(name),
            detail="repositories=" + json.dumps(repositories),
        )
    except Exception:
        logging.getLogger(__name__).warning("Runner token audit write failed")
    return token


def recover_jobs() -> None:
    """A scheduler restart cannot prove that a remote process has stopped."""
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        assignments = [
            (r[0], r[1]) for r in conn.execute("SELECT run_id,document FROM ci_remote_jobs")
        ]
        paths = [r[0] for r in conn.execute("SELECT source_path FROM ci_remote_jobs")]
        _queue_source_cleanup(conn, paths)
        conn.execute("""UPDATE ci_runs SET status='interrupted',return_code=-1,
            finished_at=datetime('now'),reason='HTTP runner coordinator restarted; no automatic replay.'
            WHERE status IN ('queued','running') AND id IN
            (SELECT run_id FROM ci_remote_jobs WHERE state IN ('queued','claimed','finished'))""")
        _close_assignments(conn, assignments)
        conn.commit()
        _delete_sources(paths)
    finally:
        conn.close()


def source_bundle(
    bare: str | os.PathLike[str],
    commit: str,
    head: str,
    limit_mb: int = DEFAULT_SOURCE_LIMIT_MB,
    timeout: int = 60,
    *,
    destination: str | os.PathLike[str] | None = None,
) -> bytes | Path:
    """Bundle only the required histories, never expose server paths/credentials."""
    maximum = source_limit_bytes(limit_mb)
    if type(timeout) is not int or timeout <= 0:
        raise ValueError("Source preparation timeout must be a positive integer.")
    deadline = time.monotonic() + timeout
    for value in (commit, head):
        if value and not re.fullmatch(r"[0-9a-fA-F]{40,64}", value):
            raise ValueError("Remote CI requires full commit IDs.")
    with tempfile.TemporaryDirectory(prefix="pygithost-bundle-") as root:
        clone, bundle = str(Path(root) / "repo.git"), Path(root) / "source.bundle"

        def git(*args: str) -> None:
            subprocess.run(
                ["git", *args],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=max(0.001, deadline - time.monotonic()),
            )

        git("clone", "--bare", "--shared", "--", str(Path(bare).resolve()), clone)
        refs: list[str] = []
        for name, sha in (("base", commit), ("head", head)):
            if sha:
                ref = "refs/heads/ci-" + name
                git("--git-dir", clone, "update-ref", ref, sha)
                refs.append(ref)
        git("--git-dir", clone, "bundle", "create", str(bundle), *refs)
        if bundle.stat().st_size > maximum:
            raise ValueError(
                f"Remote CI source exceeds the configured {limit_mb} MiB bundle limit."
            )
        if destination is not None:
            shutil.copyfile(bundle, destination)
            return Path(destination)
        return bundle.read_bytes()


def source_bundle_file(
    bare: str | os.PathLike[str],
    commit: str,
    head: str,
    limit_mb: int = DEFAULT_SOURCE_LIMIT_MB,
    timeout: int = 60,
) -> str:
    """Keep the source outside SQLite in an exclusively created private file."""
    fd, name = tempfile.mkstemp(prefix="pygithost-source-", suffix=".bundle")
    os.close(fd)
    try:
        source_bundle(bare, commit, head, limit_mb, timeout, destination=name)
        return name
    except BaseException:
        _delete_sources([name])
        raise


async def execute_remote(manager: SourceManager, row: RunRow, config: Mapping[str, Any]) -> None:
    from .ci import _db_call

    run_id, owner, repo, event, branch, commit, payload = row
    # Deployment configuration never leaves GitHost.
    execution = {
        k: v
        for k, v in config.items()
        if not k.startswith("deploy") and k not in ("document", "pipelines")
    }
    execution.update(runner="docker", email_mode="off")
    preparation = asyncio.create_task(
        asyncio.to_thread(
            source_bundle_file,
            manager.repo_path(owner, repo),
            commit,
            json.loads(payload).get("head_commit", ""),
            config.get("source_limit_mb", DEFAULT_SOURCE_LIMIT_MB),
            execution_limits(config.get("limits"))["source_timeout_seconds"],
        )
    )
    try:
        source = await asyncio.shield(preparation)
    except asyncio.CancelledError:
        # A cancelled to_thread await does not stop Git. Drain preparation before
        # returning, otherwise shutdown can leave an untracked temporary file.
        result = await asyncio.gather(preparation, return_exceptions=True)
        if not isinstance(result[0], BaseException):
            _delete_sources([result[0]])
        raise
    document = json.dumps(dict(row=list(row), config=execution))

    def enqueue() -> None:
        conn = connect()
        try:
            # Never replace an existing attempt, including uncertain executions.
            conn.execute(
                "INSERT INTO ci_remote_jobs(run_id,owner,repo,document,source,source_path) VALUES(?,?,?,?,X'',?)",
                (run_id, owner, repo, document, source),
            )
        finally:
            conn.close()

    enqueue_task = asyncio.create_task(asyncio.to_thread(enqueue))
    try:
        await asyncio.shield(enqueue_task)
        await _db_call(database.db_ci_run_update, run_id, phase="waiting for HTTP runner")
        while True:

            def state() -> tuple[Any, ...] | None:
                conn = connect()
                try:
                    found: tuple[Any, ...] | None = conn.execute(
                        "SELECT state,heartbeat,result,artifact FROM ci_remote_jobs WHERE run_id=?",
                        (run_id,),
                    ).fetchone()
                    return found
                finally:
                    conn.close()

            state_row = await asyncio.to_thread(state)
            if state_row is None:
                raise RuntimeError("Remote job assignment disappeared while waiting.")
            status, heartbeat, result, artifact = state_row
            if status == "finished":
                values = json.loads(result)
                steps = values.pop("steps", [])
                await _db_call(database.db_ci_steps_set, run_id, json.dumps(steps))
                if artifact:
                    await _db_call(database.db_ci_artifact_set, run_id, artifact)
                await _db_call(database.db_ci_run_update, run_id, **values)
                return
            if status == "claimed" and time.time() - heartbeat > LEASE:
                await _db_call(
                    database.db_ci_run_update,
                    run_id,
                    status="interrupted",
                    return_code=-1,
                    reason="Remote runner heartbeat expired; execution is uncertain. No automatic retry.",
                    finished_at=datetime.now(timezone.utc).isoformat(),
                )
                return
            await asyncio.sleep(1)
    finally:
        # Cancellation can arrive after INSERT but before the phase write.
        # Drain the insertion before closing so no late queued attempt survives.
        await asyncio.gather(enqueue_task, return_exceptions=True)

        def close() -> None:
            conn = connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                _queue_source_cleanup(conn, [source])
                assignment = conn.execute(
                    "SELECT document FROM ci_remote_jobs WHERE run_id=?", (run_id,)
                ).fetchone()
                _close_assignments(
                    conn, [(run_id, assignment[0])] if assignment is not None else []
                )
                conn.commit()
            finally:
                conn.close()

        try:
            await asyncio.to_thread(close)
        finally:
            _delete_sources([source])


def operation(
    digest: str,
    repositories: Collection[str] | None,
    action: str,
    document: Mapping[str, Any],
) -> JsonObject:
    """Serialize claims and transitions. None means server-authorized all-repository access."""
    conn = connect()
    try:
        prepared: tuple[JsonObject, bytes | None] | None = None
        if action in ("heartbeat", "complete"):
            if type(document.get("run_id")) is not int or not isinstance(
                document.get("attempt"), str
            ):
                raise APIError(422, "validation_error", "A run_id and attempt are required.")
            # Expensive JSON/base64/ZIP validation must not hold the writer lock.
            candidate = conn.execute(
                """SELECT j.owner,j.repo,j.document,j.attempt,j.heartbeat
                FROM ci_remote_jobs j JOIN ci_runs r ON r.id=j.run_id
                WHERE j.run_id=? AND j.runner=? AND j.state='claimed'
                AND r.status IN ('queued','running')""",
                (document.get("run_id"), digest),
            ).fetchone()
            if (
                candidate
                and (repositories is None or f"{candidate[0]}/{candidate[1]}" in repositories)
                and isinstance(document.get("attempt"), str)
                and hmac.compare_digest(candidate[3] or "", document["attempt"])
                and time.time() - candidate[4] <= LEASE
            ):
                limits = execution_limits(json.loads(candidate[2]).get("config", {}).get("limits"))
                prepared = _prepare_progress(action, document, limits)
                result_json = json.dumps(prepared[0]) if action == "complete" else None
                steps_json = json.dumps(prepared[0]["steps"]) if "steps" in prepared[0] else None
        conn.execute("BEGIN IMMEDIATE")
        if action == "claim":
            # Startup recovery/retention may have interrupted or removed a run.
            abandoned = [
                (r[0], r[1], r[2])
                for r in conn.execute("""SELECT run_id,source_path,document FROM ci_remote_jobs
                WHERE state IN ('queued','claimed') AND NOT EXISTS
                (SELECT 1 FROM ci_runs r WHERE r.id=run_id AND r.status IN ('queued','running'))""")
            ]
            _queue_source_cleanup(conn, [r[1] for r in abandoned])
            _close_assignments(conn, [(r[0], r[2]) for r in abandoned])
            # Repeated claim requests after a lost response return the same job.
            row = conn.execute(
                "SELECT run_id,document,attempt,owner,repo FROM ci_remote_jobs WHERE runner=? AND state='claimed'",
                (digest,),
            ).fetchone()
            if row and repositories is not None and f"{row[3]}/{row[4]}" not in repositories:
                # A policy change must not expose or replay an out-of-scope assignment.
                conn.commit()
                _delete_sources([r[1] for r in abandoned])
                return {"job": None}
            if not row:
                for candidate in conn.execute(
                    "SELECT run_id,owner,repo,document FROM ci_remote_jobs WHERE state='queued' ORDER BY run_id"
                ):
                    candidate_run_id, candidate_owner, candidate_repo, raw = candidate
                    if (
                        repositories is not None
                        and f"{candidate_owner}/{candidate_repo}" not in repositories
                    ):
                        continue
                    attempt = secrets.token_hex(32)
                    conn.execute(
                        "UPDATE ci_remote_jobs SET state='claimed',runner=?,attempt=?,heartbeat=? WHERE run_id=?",
                        (digest, attempt, time.time(), candidate_run_id),
                    )
                    row = (candidate_run_id, raw, attempt, candidate_owner, candidate_repo)
                    break
            conn.commit()
            _delete_sources([r[1] for r in abandoned])
            return {"job": dict(json.loads(row[1]), run_id=row[0], attempt=row[2]) if row else None}
        claimed_run_id = document.get("run_id")
        claimed_attempt = document.get("attempt")
        if type(claimed_run_id) is not int or not isinstance(claimed_attempt, str):
            raise APIError(422, "validation_error", "A run_id and attempt are required.")
        run_id, attempt = claimed_run_id, claimed_attempt
        row = conn.execute(
            "SELECT owner,repo,state,runner,attempt,source,heartbeat,document,source_path FROM ci_remote_jobs WHERE run_id=?",
            (run_id,),
        ).fetchone()
        if (
            not row
            or (repositories is not None and f"{row[0]}/{row[1]}" not in repositories)
            or row[3] != digest
            or not hmac.compare_digest(row[4] or "", attempt)
        ):
            raise APIError(404, "not_found", "Assigned job not found.")
        config = json.loads(row[7]).get("config", {})
        limits = execution_limits(config.get("limits"))
        run = conn.execute("SELECT status FROM ci_runs WHERE id=?", (run_id,)).fetchone()
        if not run or run[0] not in ("queued", "running"):
            _queue_source_cleanup(conn, [row[8]])
            _close_assignments(conn, [(run_id, row[7])])
            conn.commit()
            _delete_sources([row[8]])
            return {"cancel": True}
        if row[2] != "claimed" or time.time() - row[6] > LEASE:
            # A duplicate completion is acknowledged, but never applied twice.
            if action == "complete" and row[2] == "finished":
                conn.commit()
                return {"accepted": True}
            conn.commit()
            return {"cancel": True}
        if action == "source":
            conn.execute(
                "UPDATE ci_remote_jobs SET heartbeat=? WHERE run_id=?", (time.time(), run_id)
            )
            conn.commit()
            # No write lock is held while reading/encoding a potentially large file.
            maximum = source_limit_bytes(config.get("source_limit_mb", DEFAULT_SOURCE_LIMIT_MB))
            if row[8]:
                try:
                    with open(row[8], "rb") as stream:
                        if os.fstat(stream.fileno()).st_size > maximum:
                            raise APIError(
                                413,
                                "source_too_large",
                                "Source exceeds this run's configured bundle limit.",
                            )
                        source = bytearray()
                        while True:
                            chunk = stream.read(min(65536, maximum + 1 - len(source)))
                            if not chunk:
                                break
                            source.extend(chunk)
                            if len(source) > maximum:
                                raise APIError(
                                    413,
                                    "source_too_large",
                                    "Source exceeds this run's configured bundle limit.",
                                )
                except FileNotFoundError:
                    return {"cancel": True}
            else:
                source = row[5]  # Compatibility with jobs queued before migration.
            if len(source) > maximum:
                raise APIError(
                    413, "source_too_large", "Source exceeds this run's configured bundle limit."
                )
            return {"bundle": base64.b64encode(source).decode()}
        if action not in ("heartbeat", "complete"):
            raise APIError(404, "not_found", "Unknown runner operation.")
        if prepared is None:
            # State changed since the unlocked read. Do not validate while locked.
            conn.rollback()
            return {"cancel": True}
        values, artifact = prepared
        if action == "complete":
            conn.execute(
                "UPDATE ci_remote_jobs SET state='finished',result=?,artifact=?,document=? WHERE run_id=?",
                (result_json, artifact, _redacted_document(row[7]), run_id),
            )
        else:
            conn.execute(
                "UPDATE ci_remote_jobs SET heartbeat=? WHERE run_id=?", (time.time(), run_id)
            )
            updates = {k: v for k, v in values.items() if k in ("output", "truncated", "phase")}
            updates["status"] = "running"
            if updates:
                conn.execute(
                    "UPDATE ci_runs SET " + ",".join(k + "=?" for k in updates) + " WHERE id=?",
                    (*updates.values(), run_id),
                )
                conn.execute(
                    "UPDATE ci_runs SET started_at=COALESCE(started_at,datetime('now')) WHERE id=?",
                    (run_id,),
                )
            if "steps" in values:
                conn.execute("INSERT OR REPLACE INTO ci_steps VALUES(?,?)", (run_id, steps_json))
        conn.commit()
        return {"accepted": True, "cancel": False}
    finally:
        conn.close()


def _prepare_progress(
    action: str, document: Mapping[str, Any], limits: Mapping[str, Any]
) -> tuple[JsonObject, bytes | None]:
    values = validate_progress(
        document.get("progress", {}), final=action == "complete", limits=limits
    )
    artifact: bytes | None = None
    if action == "complete" and document.get("artifact"):
        try:
            artifact = base64.b64decode(document["artifact"], validate=True)
        except ValueError, TypeError:
            raise APIError(422, "validation_error", "Invalid artifact encoding.") from None
        if len(artifact) > limits["artifact_mb"] * MIB:
            raise APIError(
                413, "too_large", "Artifact exceeds this run's configured compressed limit."
            )
        try:
            with zipfile.ZipFile(io.BytesIO(artifact)) as archive:
                files = archive.infolist()
                if (
                    len(files) > limits["artifact_files"]
                    or sum(f.file_size for f in files) > limits["artifact_uncompressed_mb"] * MIB
                    or any(
                        f.filename.startswith(("/", "\\"))
                        or "\\" in f.filename
                        or ".." in f.filename.split("/")
                        for f in files
                    )
                ):
                    raise ValueError()
        except ValueError, zipfile.BadZipFile:
            raise APIError(422, "validation_error", "Invalid or excessive artifact ZIP.") from None
    return values, artifact


def validate_progress(
    raw: object, *, final: bool, limits: Mapping[str, Any] | None = None
) -> JsonObject:
    maximum = execution_limits(limits)["log_mb"] * MIB
    allowed = {
        "status",
        "output",
        "truncated",
        "return_code",
        "finished_at",
        "started_at",
        "phase",
        "reason",
        "warnings",
        "steps",
    }
    if not isinstance(raw, dict) or set(raw) - allowed:
        raise APIError(422, "validation_error", "Invalid progress fields.")
    if len(json.dumps(raw, ensure_ascii=False).encode()) > 3 * maximum:
        raise APIError(413, "too_large", "Progress exceeds the configured log budget.")
    if final and (
        raw.get("status") not in ("success", "failed", "timed_out", "interrupted")
        or type(raw.get("return_code")) is not int
        or (raw.get("status") == "success" and raw["return_code"] != 0)
    ):
        raise APIError(422, "validation_error", "Invalid terminal result.")
    for key in allowed - {"steps", "truncated", "return_code"}:
        if key in raw and (not isinstance(raw[key], str) or len(raw[key].encode()) > maximum):
            raise APIError(422, "validation_error", "Invalid progress text.")
    if "steps" in raw and (not isinstance(raw["steps"], list) or len(raw["steps"]) > 64):
        raise APIError(422, "validation_error", "Invalid steps.")
    for step in raw.get("steps", []):
        if (
            not isinstance(step, dict)
            or not isinstance(step.get("name"), str)
            or step.get("status")
            not in (
                "pending",
                "running",
                "success",
                "failed",
                "skipped",
                "cancelled",
                "interrupted",
                "timed_out",
            )
            or not isinstance(step.get("output", ""), str)
        ):
            raise APIError(422, "validation_error", "Invalid step state.")
    if "truncated" in raw and type(raw["truncated"]) is not int:
        raise APIError(422, "validation_error", "Invalid truncation flag.")
    return raw


def assigned_limits(
    digest: str, repositories: Collection[str] | None, run_id: str
) -> dict[str, int]:
    """Resolve upload bounds from a token-owned assignment, never request JSON."""
    if not run_id.isascii() or not run_id.isdecimal() or len(run_id) > 18:
        raise APIError(422, "validation_error", "Invalid X-Runner-Run-ID.")
    conn = connect()
    try:
        row = conn.execute(
            "SELECT owner,repo,document FROM ci_remote_jobs WHERE run_id=? AND runner=?",
            (int(run_id), digest),
        ).fetchone()
        if not row or (repositories is not None and f"{row[0]}/{row[1]}" not in repositories):
            raise APIError(404, "not_found", "Active assignment not found.")
        return execution_limits(json.loads(row[2]).get("config", {}).get("limits"))
    finally:
        conn.close()


class RunnerAPI(API):
    async def dispatch(self) -> None:
        try:
            if not self.app._ip_allowed(self.request.peer_ip, self.handler.server.allowlist):
                raise APIError(403, "forbidden", "Client IP is not allowed.")
            self.handler.server.api_limiter.check(("runner-ip", self.request.peer_ip))
            authorization = self.request.headers.get("Authorization", "")
            if (
                len([k for k, _v in self.request.headers.items() if k.lower() == "authorization"])
                != 1
                or not authorization.startswith("Bearer ")
                or len(authorization) > 256
            ):
                raise APIError(401, "unauthorized", "Runner bearer token required.")
            digest = hashlib.sha256(authorization[7:].encode()).hexdigest()

            def authenticate() -> tuple[Any, ...] | None:
                conn = connect()
                try:
                    found: tuple[Any, ...] | None = conn.execute(
                        "SELECT repositories FROM ci_runner_tokens WHERE digest=?", (digest,)
                    ).fetchone()
                    return found
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
            repositories: Collection[str] | None = (
                None
                if self.handler.server.ci_manager.trust_all_repositories
                else json.loads(token[0])
            )
            limits = execution_limits()
            run_id = self.request.headers.get("X-Runner-Run-ID", "")
            if run_id and action in ("heartbeat", "complete"):
                limits = await asyncio.to_thread(assigned_limits, digest, repositories, run_id)
            maximum = (
                completion_bytes(limits)
                if action == "complete"
                else progress_bytes(limits)
                if action == "heartbeat"
                else MIB
            )
            size = self.request.headers.get("Content-Length", "")
            if (
                len([k for k, _v in self.request.headers.items() if k.lower() == "content-length"])
                != 1
                or self.request.headers.get("Transfer-Encoding")
                or not size.isascii()
                or not size.isdecimal()
                or len(size) > len(str(maximum))
                or int(size) > maximum
            ):
                raise APIError(
                    413,
                    "too_large",
                    "Runner request exceeds its configured budget or lacks a valid length.",
                )
            if self.request.headers.get("Content-Type", "").split(";")[0] != "application/json":
                raise APIError(415, "unsupported_media_type", "Use application/json.")
            async with self.handler.server.api_slots:
                async with asyncio.timeout(limits["transfer_timeout_seconds"]):
                    raw = await self.request.reader.readexactly(int(size))

                    def pairs(items: Iterable[tuple[str, Any]]) -> JsonObject:
                        result: JsonObject = {}
                        for key, value in items:
                            if key in result:
                                raise ValueError("Duplicate JSON key")
                            result[key] = value
                        return result

                    def constant(_value: str) -> NoReturn:
                        raise ValueError("Non-finite JSON number")

                    try:
                        document = json.loads(
                            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant
                        )
                        json.dumps(document, ensure_ascii=False, allow_nan=False).encode("utf-8")
                    except ValueError, UnicodeError, RecursionError:
                        raise APIError(400, "invalid_json", "Invalid JSON.") from None
                    if not isinstance(document, dict):
                        raise APIError(422, "validation_error", "Expected a JSON object.")
                    result = await asyncio.to_thread(
                        operation, digest, repositories, action, document
                    )
            body = json.dumps(result).encode()
            await self.app._send_response(
                self.request,
                200,
                body,
                [
                    ("Content-Type", "application/json"),
                    ("Cache-Control", "no-store"),
                    ("X-Content-Type-Options", "nosniff"),
                ],
            )
        except APIError as exc:
            await self.send(exc.status, {"code": exc.code, "message": exc.message})
        except TimeoutError:
            await self.send(504, {"code": "timeout", "message": "Runner request timed out."})
        except self.app.ClientDisconnected:
            raise
        except Exception as exc:
            self.log_failure(exc)
            await self.send(500, {"code": "internal_error", "message": "Runner request failed."})


def runner_specification() -> JsonObject:
    identity = {
        "run_id": {"type": "integer", "minimum": 1},
        "attempt": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
    }
    progress = {
        "type": "object",
        "properties": {
            "status": {"enum": ["success", "failed", "timed_out", "interrupted"]},
            "return_code": {"type": "integer"},
            "output": {"type": "string"},
            "truncated": {"type": "integer"},
            "phase": {"type": "string"},
            "started_at": {"type": "string"},
            "finished_at": {"type": "string"},
            "reason": {"type": "string"},
            "warnings": {"type": "string"},
            "steps": {"type": "array", "maxItems": 64, "items": {"type": "object"}},
        },
        "additionalProperties": False,
    }
    paths = {}
    for action in ("claim", "source", "heartbeat", "complete"):
        properties = {} if action == "claim" else dict(identity)
        required = [] if action == "claim" else list(identity)
        if action in ("heartbeat", "complete"):
            properties["progress"] = progress
        if action == "complete":
            required.append("progress")
            properties["artifact"] = {
                "type": "string",
                "contentEncoding": "base64",
                "description": "Optional ZIP, bounded by the assignment's limits.artifact_mb.",
            }
        paths["/" + action] = {
            "post": {
                "operationId": "runner_" + action,
                "description": "Repository-restricted runner token required. Assignment identity makes retries safe; no Idempotency-Key. "
                "X-Runner-Run-ID resolves token-owned progress/artifact upload budgets from the stored run snapshot.",
                "parameters": (
                    [
                        {
                            "name": "X-Runner-Run-ID",
                            "in": "header",
                            "required": False,
                            "schema": {"type": "integer", "minimum": 1},
                            "description": "Required for uploads exceeding the default operation budget.",
                        }
                    ]
                    if action in ("heartbeat", "complete")
                    else []
                ),
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": properties,
                                "required": required,
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Job, bundle, acknowledgement or cancel flag.",
                        "content": {"application/json": {"schema": {"type": "object"}}},
                    },
                    "401": {"description": "Invalid or revoked runner token."},
                    "404": {"description": "Unknown operation or foreign assignment."},
                    "413": {"description": "Request or artifact limit exceeded."},
                    "422": {"description": "Invalid assignment or progress."},
                },
            }
        }
    return {
        "openapi": "3.1.0",
        "info": {"title": "PyGitHost runner protocol", "version": "1.0.0"},
        "servers": [{"url": "/api/runner/v1"}],
        "paths": paths,
        "security": [{"runnerToken": []}],
        "components": {"securitySchemes": {"runnerToken": {"type": "http", "scheme": "bearer"}}},
    }
