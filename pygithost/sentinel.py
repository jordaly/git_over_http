"""Background exporter for the Fuente Sentinel logs and heartbeat API."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import random
import sqlite3
import threading
import time
import uuid
from contextlib import closing
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from http.client import HTTPException
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

logger = logging.getLogger(__name__)

DEFAULT_APPLICATION = "PyGitHost"
_BATCH_SIZE = 100
_BUFFER_SIZE = 20_000
_DEAD_LETTER_SIZE = 500
_HTTP_TIMEOUT = 10
_HEARTBEAT_INTERVAL = 60
_CONFIGURATION_BACKOFF = 900


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        # Never forward the ingestion key to another URL.
        return None


class SentinelExporter:
    def __init__(
        self,
        url: str,
        key: str,
        environment: str,
        spool: Path,
        application: str = DEFAULT_APPLICATION,
    ) -> None:
        self.url = url.rstrip("/")
        self._key = key
        self.environment = environment
        self.application = application
        self.spool = spool
        self.session_id = uuid.uuid4().hex
        self.started = time.monotonic()
        self._pending: queue.Queue[tuple[int, str]] = queue.Queue(maxsize=1024)
        self._queue_dropped = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="sentinel-exporter", daemon=True)
        self._opener = build_opener(_NoRedirect())

    @classmethod
    def from_environment(cls, db_path: str) -> SentinelExporter | None:
        url = os.environ.get("PYGITHOST_SENTINEL_URL", "").strip()
        # Keep the credential out of environments inherited by child processes.
        key = os.environ.pop("PYGITHOST_SENTINEL_KEY", "").strip()
        if not url:
            return None
        environment = os.environ.get("PYGITHOST_SENTINEL_ENVIRONMENT", "production").strip()
        application = (
            os.environ.get("PYGITHOST_SENTINEL_APPLICATION", "").strip() or DEFAULT_APPLICATION
        )
        try:
            parsed = urlsplit(url)
            # Validate the port now rather than retrying a malformed URL forever.
            port = parsed.port
            valid = (
                parsed.hostname
                and (port is None or port > 0)
                and not (parsed.username or parsed.password or parsed.query or parsed.fragment)
                and (
                    parsed.scheme == "https"
                    or (
                        parsed.scheme == "http"
                        and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
                    )
                )
            )
        except ValueError:
            valid = False
        if (
            not valid
            or not key
            or not key.isascii()
            or not key.isprintable()
            or not (0 < len(environment) <= 256 and environment.isprintable())
            or not (len(application) <= 256 and application.isprintable())
        ):
            logger.warning("Fuente Sentinel disabled due to invalid exporter settings")
            return None
        # Spooled events embed the application name, so each one gets its own spool.
        target = f"{url.rstrip('/')}\n{environment}"
        if application != DEFAULT_APPLICATION:
            target += f"\n{application}"
        destination = hashlib.sha256(target.encode()).hexdigest()[:16]
        spool = Path(db_path).expanduser().with_suffix(f".sentinel-{destination}.sqlite3")
        return cls(url, key, environment, spool, application)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)

    def emit(
        self,
        name: str,
        level: str,
        *,
        attributes: dict[str, str | int | float] | None = None,
        correlation_id: str | None = None,
        trace_id: str | None = None,
        span_id: str | None = None,
    ) -> None:
        event = {
            "application": self.application,
            "environment": self.environment,
            "session_id": self.session_id,
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(UTC).isoformat(),
            "event_name": name,
            "level": level,
            "message": name.replace("_", " "),
            "attributes": attributes or {},
        }
        if correlation_id:
            event["correlation_id"] = correlation_id
        if trace_id:
            event["trace_id"] = trace_id
            if span_id:
                event["span_id"] = span_id
        try:
            self._pending.put_nowait((int(level in {"Warning", "Error"}), json.dumps(event)))
        except queue.Full:
            self._queue_dropped += 1

    # Placeholders for the metrics and traces pipeline (not yet exported).
    def count(self, name: str, value: float, attributes: dict[str, Any] | None) -> None:
        pass

    def observe(self, name: str, value_ms: float, attributes: dict[str, Any] | None) -> None:
        pass

    def span(
        self,
        name: str,
        start: datetime,
        end: datetime,
        *,
        trace_id: str,
        span_id: str,
        parent_span_id: str | None,
        kind: str,
        status: str,
        status_message: str | None,
        attributes: dict[str, Any] | None,
    ) -> None:
        pass

    def _run(self) -> None:
        pending: list[tuple[int, str]] = []
        while True:
            try:
                with closing(sqlite3.connect(self.spool, timeout=1)) as db:
                    db.executescript("""
                        CREATE TABLE IF NOT EXISTS installation (id TEXT PRIMARY KEY);
                        CREATE TABLE IF NOT EXISTS events (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            priority INTEGER NOT NULL, body TEXT NOT NULL
                        );
                        CREATE INDEX IF NOT EXISTS events_priority ON events(priority, id);
                        CREATE TABLE IF NOT EXISTS dead_letters (
                            id INTEGER PRIMARY KEY, reason TEXT NOT NULL, body TEXT NOT NULL
                        );
                        """)
                    with db:
                        db.execute(
                            "INSERT INTO installation SELECT ? WHERE NOT EXISTS "
                            "(SELECT 1 FROM installation)",
                            (str(uuid.uuid4()),),
                        )
                    client_id: str = db.execute("SELECT id FROM installation").fetchone()[0]
                    self._work(db, client_id, pending)
                return
            except Exception as exc:
                logger.warning(
                    "Fuente Sentinel exporter paused",
                    extra={"error_type": type(exc).__name__},
                )
                if self._stop.wait(10):
                    return

    def _work(self, db: sqlite3.Connection, client_id: str, pending: list[tuple[int, str]]) -> None:
        next_send = 0.0
        next_heartbeat = 0.0
        backoff = 1.0
        batch_size = _BATCH_SIZE
        dropped_reported = 0
        spool_dropped = 0
        while True:
            stopping = self._stop.is_set()
            while len(pending) < 1024:
                try:
                    pending.append(self._pending.get_nowait())
                except queue.Empty:
                    break
            if pending:
                with db:
                    db.executemany("INSERT INTO events(priority, body) VALUES (?, ?)", pending)
                    overflow = db.execute(
                        "SELECT max(count(*) - ?, 0) FROM events", (_BUFFER_SIZE,)
                    )
                    dropped = overflow.fetchone()[0]
                    if dropped:
                        db.execute(
                            "DELETE FROM events WHERE id IN "
                            "(SELECT id FROM events ORDER BY priority, id LIMIT ?)",
                            (dropped,),
                        )
                pending.clear()
                spool_dropped += dropped
            dropped_total = spool_dropped + self._queue_dropped
            if dropped_total != dropped_reported:
                dropped_reported = dropped_total
                logger.warning(
                    "Fuente Sentinel telemetry buffer overflow",
                    extra={"dropped_events": dropped_reported},
                )
            if self._stop.is_set():
                if stopping and self._pending.empty():
                    return
                continue
            now = time.monotonic()
            if now >= next_heartbeat:
                status, retry, _ = self._post(
                    "/api/v1/clients/heartbeat",
                    {
                        "application": self.application,
                        "environment": self.environment,
                        "client_id": client_id,
                        "session_id": self.session_id,
                        "timestamp": datetime.now(UTC).isoformat(),
                        "uptime_seconds": int(now - self.started),
                    },
                )
                next_heartbeat = time.monotonic() + max(
                    _HEARTBEAT_INTERVAL,
                    retry,
                    _CONFIGURATION_BACKOFF if status in {401, 403} else 0,
                )
                continue
            if now >= next_send:
                rows = db.execute(
                    "SELECT id, body FROM events ORDER BY id LIMIT ?", (batch_size,)
                ).fetchall()
                if rows:
                    delay, split = self._send_batch(db, client_id, rows)
                    if split:
                        batch_size = max(1, len(rows) // 2)
                    elif delay is None:
                        backoff = 1.0
                    else:
                        next_send = time.monotonic() + max(delay, backoff * random.uniform(0.5, 1))
                        backoff = min(backoff * 2, 300)
                    continue
            self._stop.wait(0.25)

    def _send_batch(
        self, db: sqlite3.Connection, client_id: str, rows: list[tuple[int, str]]
    ) -> tuple[float | None, bool]:
        events = [json.loads(body) for _, body in rows]
        status, retry, response = self._post(
            "/api/v1/logs/batch",
            {
                "schema_version": 1,
                "resource": {"service.name": self.application, "client.id": client_id},
                "events": events,
            },
        )
        if status == 413 and len(rows) > 1:
            return None, True
        if status in {401, 403}:
            logger.warning("Fuente Sentinel declined the ingestion credentials or application")
            return max(retry, _CONFIGURATION_BACKOFF), False
        if status == 200:
            try:
                errors = {item["index"]: item["code"] for item in response["errors"]}
                counts = [response[key] for key in ("accepted", "duplicates", "rejected")]
                if (
                    not all(type(i) is int and 0 <= i < len(rows) for i in errors)
                    or not all(type(count) is int and count >= 0 for count in counts)
                    or len(errors) != counts[2]
                    or len(response["errors"]) != counts[2]
                    or sum(counts) != len(rows)
                    or not all(isinstance(code, str) and code for code in errors.values())
                ):
                    return retry, False
            except KeyError, TypeError:
                return retry, False
        elif status in {400, 413, 415, 422}:
            errors = dict.fromkeys(range(len(rows)), f"http_{status}")
        else:
            return retry, False

        keep = False
        with db:
            for index, (row_id, body) in enumerate(rows):
                reason = errors.get(index)
                if reason and (
                    reason.startswith("unauthorized_") or reason == "unknown_application"
                ):
                    keep = True
                    continue
                if reason:
                    db.execute(
                        "INSERT INTO dead_letters(reason, body) VALUES (?, ?)", (reason[:256], body)
                    )
                db.execute("DELETE FROM events WHERE id = ?", (row_id,))
            if errors:
                db.execute(
                    "DELETE FROM dead_letters WHERE id IN "
                    "(SELECT id FROM dead_letters ORDER BY id DESC LIMIT -1 OFFSET ?)",
                    (_DEAD_LETTER_SIZE,),
                )
        return _CONFIGURATION_BACKOFF if keep else None, False

    def _post(self, endpoint: str, payload: dict[str, Any]) -> tuple[int, float, Any]:
        request = Request(
            self.url + endpoint,
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {self._key}", "Content-Type": "application/json"},
        )
        try:
            with self._opener.open(request, timeout=_HTTP_TIMEOUT) as response:
                if endpoint.endswith("/logs/batch") and response.status == 200:
                    body = response.read(256 * 1024 + 1)
                    if len(body) <= 256 * 1024:
                        return 200, 0, json.loads(body)
                return response.status, 0, None
        except HTTPError as exc:
            with exc:
                return exc.code, _retry_after(exc.headers.get("Retry-After")), None
        except HTTPException, OSError, ValueError:
            return 0, 0, None


def _retry_after(value: str | None) -> float:
    if value:
        try:
            return float(max(0, int(value)))
        except ValueError, OverflowError:
            try:
                return max(0, parsedate_to_datetime(value).timestamp() - time.time())
            except ValueError, TypeError, OverflowError, OSError:
                pass
    return 0


# ---------------------------------------------------------------------------
# Module-level instrumentation API.
#
# Call sites anywhere in PyGitHost (CI, pull requests, auth, ...) use these
# helpers; they are no-ops while no exporter is active, never raise, and never
# block. Attribute values must be low-cardinality scalars and must not contain
# usernames, IP addresses, raw URLs, query strings, bodies, tokens or
# tracebacks. Repository full names ("owner/repo") are allowed.
# ---------------------------------------------------------------------------

Attributes = dict[str, str | int | float | bool]

_current: SentinelExporter | None = None


def set_current(exporter: SentinelExporter | None) -> None:
    """Install (or clear) the process-wide exporter used by the helpers below."""
    global _current
    _current = exporter


def current() -> SentinelExporter | None:
    return _current


def new_trace_id() -> str:
    """32 lowercase hex characters (W3C trace ID)."""
    return uuid.uuid4().hex


def new_span_id() -> str:
    """16 lowercase hex characters (W3C span ID)."""
    return uuid.uuid4().hex[:16]


def emit_event(
    name: str,
    level: str = "Information",
    attributes: Attributes | None = None,
    *,
    correlation_id: str | None = None,
    trace_id: str | None = None,
    span_id: str | None = None,
) -> None:
    """Send a log event. ``level`` is Information, Warning or Error."""
    exporter = _current
    if exporter is None:
        return
    try:
        exporter.emit(
            name,
            level,
            attributes=dict(attributes) if attributes else None,
            correlation_id=correlation_id,
            trace_id=trace_id,
            span_id=span_id,
        )
    except Exception:  # pragma: no cover - telemetry must never break callers
        logger.debug("Fuente Sentinel emit failed", exc_info=True)


def count(name: str, value: float = 1, attributes: Attributes | None = None) -> None:
    """Add to a delta counter metric (aggregated in-process, flushed periodically)."""
    exporter = _current
    if exporter is None:
        return
    try:
        exporter.count(name, value, dict(attributes) if attributes else None)
    except Exception:  # pragma: no cover
        logger.debug("Fuente Sentinel count failed", exc_info=True)


def observe(name: str, value_ms: float, attributes: Attributes | None = None) -> None:
    """Record a duration in milliseconds into an aggregated histogram metric."""
    exporter = _current
    if exporter is None:
        return
    try:
        exporter.observe(name, value_ms, dict(attributes) if attributes else None)
    except Exception:  # pragma: no cover
        logger.debug("Fuente Sentinel observe failed", exc_info=True)


def record_span(
    name: str,
    start: datetime,
    end: datetime,
    *,
    trace_id: str,
    span_id: str,
    parent_span_id: str | None = None,
    kind: str = "internal",
    status: str = "unset",
    status_message: str | None = None,
    attributes: Attributes | None = None,
) -> None:
    """Send a finished span. ``start``/``end`` must be timezone-aware datetimes.

    ``kind``: internal, server, client, producer, consumer.
    ``status``: unset, ok, error. ``status_message`` must be a fixed, non-sensitive text.
    """
    exporter = _current
    if exporter is None:
        return
    try:
        exporter.span(
            name,
            start,
            end,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            kind=kind,
            status=status,
            status_message=status_message,
            attributes=dict(attributes) if attributes else None,
        )
    except Exception:  # pragma: no cover
        logger.debug("Fuente Sentinel span failed", exc_info=True)
