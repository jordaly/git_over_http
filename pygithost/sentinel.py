"""Background exporter for the Fuente Sentinel logs, metrics and traces API."""

from __future__ import annotations

import bisect
import hashlib
import json
import logging
import math
import os
import platform
import queue
import random
import re
import socket
import sqlite3
import sys
import threading
import time
import tomllib
import uuid
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from functools import lru_cache
from http.client import HTTPException
from pathlib import Path
from typing import Any, ClassVar
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
_METRIC_INTERVAL = 60
_CONFIGURATION_BACKOFF = 900

_KINDS = ("log", "metric", "span")
_BATCH_TARGETS: dict[str, tuple[str, str]] = {
    "log": ("/api/v1/logs/batch", "events"),
    "metric": ("/api/v1/metrics/batch", "metrics"),
    "span": ("/api/v1/traces/batch", "spans"),
}

_REQUEST_LOG_MODES = frozenset({"errors", "all", "off"})
_METRIC_MODES = frozenset({"on", "off"})
_DEFAULT_TRACE_SAMPLE_RATE = 0.01
_DEFAULT_SLOW_REQUEST_MS = 2000.0

_METRIC_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_./-]{0,254}")
_HEX_ID = re.compile(r"[0-9a-fA-F]+")
_MAX_METRIC_SERIES = 500
_MAX_METRIC_ATTRIBUTES = 16
_MAX_ATTRIBUTE_KEY = 128
_MAX_ATTRIBUTE_STRING = 256
_MAX_SPAN_NAME = 256
_MAX_STATUS_MESSAGE = 8192
_SPAN_KINDS = frozenset({"internal", "server", "client", "producer", "consumer"})
_SPAN_STATUSES = frozenset({"unset", "ok", "error"})
_HISTOGRAM_BOUNDS: tuple[float, ...] = (
    5,
    10,
    25,
    50,
    100,
    250,
    500,
    1000,
    2500,
    5000,
    10000,
    30000,
    60000,
)

MetricScalar = str | int | float | bool
MetricAttributes = dict[str, MetricScalar]
_SeriesKey = tuple[str, tuple[tuple[str, MetricScalar], ...]]


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        # Never forward the ingestion key to another URL.
        return None


@dataclass
class _HistogramState:
    counts: list[int] = field(default_factory=lambda: [0] * (len(_HISTOGRAM_BOUNDS) + 1))
    count: int = 0
    total: float = 0.0
    minimum: float = math.inf
    maximum: float = -math.inf


def _valid_metric_name(name: object) -> bool:
    return isinstance(name, str) and _METRIC_NAME.fullmatch(name) is not None


def _clean_attributes(attributes: Mapping[str, Any] | None) -> MetricAttributes:
    """Keep flat, bounded scalars so a metric cannot blow up a series."""
    if not attributes:
        return {}
    cleaned: MetricAttributes = {}
    for key in sorted(attributes)[:16]:
        if len(cleaned) >= _MAX_METRIC_ATTRIBUTES:
            break
        if not isinstance(key, str) or not key or len(key) > _MAX_ATTRIBUTE_KEY:
            continue
        value = attributes[key]
        if isinstance(value, bool):
            cleaned[key] = value
        elif isinstance(value, int):
            cleaned[key] = value
        elif isinstance(value, float):
            if math.isfinite(value):
                cleaned[key] = value
        elif isinstance(value, str):
            cleaned[key] = value[:_MAX_ATTRIBUTE_STRING]
    return cleaned


def _attribute_key(attributes: MetricAttributes) -> tuple[tuple[str, MetricScalar], ...]:
    return tuple(sorted(attributes.items()))


def _valid_hex_id(value: object, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length or _HEX_ID.fullmatch(value) is None:
        return False
    return value.strip("0") != ""


@lru_cache(maxsize=1)
def _package_version() -> str | None:
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("pygithost")
        except PackageNotFoundError:
            pass
    except Exception:
        pass
    try:
        with (Path(__file__).resolve().parent.parent / "pyproject.toml").open("rb") as handle:
            data = tomllib.load(handle)
    except OSError, ValueError:
        return None
    project = data.get("project")
    if isinstance(project, dict):
        value = project.get("version")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _read_ref(git_dir: Path, ref: str) -> str | None:
    candidates = [git_dir]
    commondir = git_dir / "commondir"
    if commondir.is_file():
        try:
            common = (git_dir / commondir.read_text(encoding="utf-8").strip()).resolve()
        except OSError:
            pass
        else:
            candidates.append(common)
    for base in candidates:
        try:
            value = (base / ref).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if re.fullmatch(r"[0-9a-fA-F]{40,64}", value):
            return value
    for base in candidates:
        try:
            lines = (base / "packed-refs").read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            if not line or line.startswith(("#", "^")):
                continue
            sha, _, name = line.partition(" ")
            if name.strip() == ref and re.fullmatch(r"[0-9a-fA-F]{40,64}", sha):
                return sha
    return None


@lru_cache(maxsize=1)
def _git_short_commit() -> str | None:
    root = Path(__file__).resolve().parent.parent
    checkout: Path | None = None
    for candidate in (root, *root.parents):
        if (candidate / ".git").exists():
            checkout = candidate
            break
    if checkout is None:
        return None
    dotgit = checkout / ".git"
    if dotgit.is_dir():
        git_dir = dotgit
    else:
        try:
            text = dotgit.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if not text.startswith("gitdir:"):
            return None
        git_dir = Path(text[len("gitdir:") :].strip())
        if not git_dir.is_absolute():
            git_dir = (checkout / git_dir).resolve()
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if head.startswith("ref: "):
        sha = _read_ref(git_dir, head[len("ref: ") :].strip())
        return sha[:7] if sha else None
    return head[:7] if re.fullmatch(r"[0-9a-fA-F]{40,64}", head) else None


@lru_cache(maxsize=1)
def _service_version() -> str | None:
    base = _package_version()
    commit = _git_short_commit()
    if base and commit:
        return f"{base}+{commit}"
    return base or commit


@lru_cache(maxsize=1)
def _host_name() -> str | None:
    try:
        value = socket.gethostname().strip()
    except OSError:
        return None
    return value or None


@lru_cache(maxsize=1)
def _os_type() -> str | None:
    value = (platform.system() or sys.platform).strip().lower()
    return value or None


def _windows_memory_usage() -> int | None:
    try:
        import ctypes
    except ImportError:
        return None

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_: ClassVar[list[tuple[str, Any]]] = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return None
    kernel32 = windll.kernel32
    handle = kernel32.GetCurrentProcess()
    if not kernel32.K32GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
        return None
    return int(counters.WorkingSetSize)


def _memory_usage_bytes() -> int | None:
    """Process resident memory, or ``None`` when the platform cannot report it."""
    if sys.platform == "win32":
        return _windows_memory_usage()
    try:
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        with open("/proc/self/statm", encoding="ascii") as handle:
            fields = handle.read().split()
        if len(fields) < 2:
            return None
        return int(fields[1]) * page_size
    except OSError, ValueError, AttributeError:
        return None


def _rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _ensure_spool_schema(db: sqlite3.Connection) -> None:
    db.executescript("""
        CREATE TABLE IF NOT EXISTS installation (id TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            priority INTEGER NOT NULL,
            body TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'log'
        );
        CREATE TABLE IF NOT EXISTS dead_letters (
            id INTEGER PRIMARY KEY, reason TEXT NOT NULL, body TEXT NOT NULL
        );
        """)
    columns = {row[1] for row in db.execute("PRAGMA table_info(events)")}
    with db:
        if "kind" not in columns:
            db.execute("ALTER TABLE events ADD COLUMN kind TEXT NOT NULL DEFAULT 'log'")
        db.execute("CREATE INDEX IF NOT EXISTS events_priority ON events(priority, id)")
        db.execute("CREATE INDEX IF NOT EXISTS events_kind ON events(kind, id)")


class SentinelExporter:
    def __init__(
        self,
        url: str,
        key: str,
        environment: str,
        spool: Path,
        application: str = DEFAULT_APPLICATION,
        *,
        request_logs: str = "errors",
        trace_sample_rate: float = _DEFAULT_TRACE_SAMPLE_RATE,
        slow_request_ms: float = _DEFAULT_SLOW_REQUEST_MS,
        metrics_enabled: bool = True,
    ) -> None:
        self.url = url.rstrip("/")
        self._key = key
        self.environment = environment
        self.application = application
        self.spool = spool
        self.session_id = uuid.uuid4().hex
        self.started = time.monotonic()
        self.request_logs = request_logs if request_logs in _REQUEST_LOG_MODES else "errors"
        self.trace_sample_rate = min(1.0, max(0.0, float(trace_sample_rate)))
        self.slow_request_ms = max(0.0, float(slow_request_ms))
        self.metrics_enabled = bool(metrics_enabled)
        self._pending: queue.Queue[tuple[int, str, str]] = queue.Queue(maxsize=1024)
        self._queue_dropped = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="sentinel-exporter", daemon=True)
        self._opener = build_opener(_NoRedirect())
        self._resource_cache: dict[str, dict[str, Any]] = {}
        self._metrics_lock = threading.Lock()
        self._counters: dict[_SeriesKey, float] = {}
        self._histograms: dict[_SeriesKey, _HistogramState] = {}
        self._gauges: dict[str, tuple[str, Callable[[], float | int | None]]] = {}

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

        request_logs = (
            os.environ.get("PYGITHOST_SENTINEL_REQUEST_LOGS", "errors").strip().lower() or "errors"
        )
        if request_logs not in _REQUEST_LOG_MODES:
            logger.warning("Ignoring invalid PYGITHOST_SENTINEL_REQUEST_LOGS value")
            request_logs = "errors"
        trace_sample_rate = _env_float(
            "PYGITHOST_SENTINEL_TRACE_SAMPLE_RATE",
            _DEFAULT_TRACE_SAMPLE_RATE,
            minimum=0.0,
            maximum=1.0,
        )
        slow_request_ms = _env_float(
            "PYGITHOST_SENTINEL_SLOW_REQUEST_MS",
            _DEFAULT_SLOW_REQUEST_MS,
            minimum=0.0,
        )
        metrics = os.environ.get("PYGITHOST_SENTINEL_METRICS", "on").strip().lower() or "on"
        if metrics not in _METRIC_MODES:
            logger.warning("Ignoring invalid PYGITHOST_SENTINEL_METRICS value")
            metrics = "on"

        # Spooled events embed the application name, so each one gets its own spool.
        target = f"{url.rstrip('/')}\n{environment}"
        if application != DEFAULT_APPLICATION:
            target += f"\n{application}"
        destination = hashlib.sha256(target.encode()).hexdigest()[:16]
        spool = Path(db_path).expanduser().with_suffix(f".sentinel-{destination}.sqlite3")
        return cls(
            url,
            key,
            environment,
            spool,
            application,
            request_logs=request_logs,
            trace_sample_rate=trace_sample_rate,
            slow_request_ms=slow_request_ms,
            metrics_enabled=metrics == "on",
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)

    def _enqueue(self, priority: int, kind: str, body: str) -> None:
        try:
            self._pending.put_nowait((priority, body, kind))
        except queue.Full:
            self._queue_dropped += 1
            logger.debug("Fuente Sentinel in-memory queue is full", extra={"kind": kind})

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
        self._enqueue(int(level in {"Warning", "Error"}), "log", json.dumps(event))

    # -- metrics ---------------------------------------------------------

    def count(self, name: str, value: float, attributes: dict[str, Any] | None) -> None:
        """Add ``value`` to a delta counter series."""
        if not self.metrics_enabled:
            return
        if not _valid_metric_name(name):
            logger.debug("Dropping invalid metric name", extra={"metric": str(name)[:64]})
            return
        try:
            number = float(value)
        except TypeError, ValueError:
            return
        if not math.isfinite(number) or number < 0:
            return
        cleaned = _clean_attributes(attributes)
        key: _SeriesKey = (name, _attribute_key(cleaned))
        with self._metrics_lock:
            if key not in self._counters and self._series_count() >= _MAX_METRIC_SERIES:
                logger.debug("Fuente Sentinel metric series cap reached", extra={"metric": name})
                return
            self._counters[key] = self._counters.get(key, 0.0) + number

    def observe(self, name: str, value_ms: float, attributes: dict[str, Any] | None) -> None:
        """Record one duration in milliseconds into a delta histogram series."""
        if not self.metrics_enabled:
            return
        if not _valid_metric_name(name):
            logger.debug("Dropping invalid metric name", extra={"metric": str(name)[:64]})
            return
        try:
            number = float(value_ms)
        except TypeError, ValueError:
            return
        if not math.isfinite(number):
            return
        number = max(0.0, number)
        cleaned = _clean_attributes(attributes)
        key: _SeriesKey = (name, _attribute_key(cleaned))
        with self._metrics_lock:
            state = self._histograms.get(key)
            if state is None:
                if self._series_count() >= _MAX_METRIC_SERIES:
                    logger.debug(
                        "Fuente Sentinel metric series cap reached", extra={"metric": name}
                    )
                    return
                state = _HistogramState()
                self._histograms[key] = state
            bucket = bisect.bisect_left(_HISTOGRAM_BOUNDS, number)
            state.counts[bucket] += 1
            state.count += 1
            state.total += number
            state.minimum = min(state.minimum, number)
            state.maximum = max(state.maximum, number)

    def register_gauge(
        self, name: str, unit: str, callback: Callable[[], float | int | None]
    ) -> None:
        """Register a cheap callback sampled at every metric flush."""
        if not _valid_metric_name(name):
            logger.debug("Dropping invalid gauge name", extra={"metric": str(name)[:64]})
            return
        with self._metrics_lock:
            self._gauges[name] = (unit, callback)

    def _series_count(self) -> int:
        return len(self._counters) + len(self._histograms)

    def _drain_metrics(
        self,
    ) -> tuple[list[str], list[tuple[str, str, Callable[[], float | int | None]]]]:
        timestamp = datetime.now(UTC).isoformat()
        bodies: list[str] = []
        with self._metrics_lock:
            counters = self._counters
            histograms = self._histograms
            gauges = [(name, unit, callback) for name, (unit, callback) in self._gauges.items()]
            self._counters = {}
            self._histograms = {}
        for (name, attributes), value in counters.items():
            bodies.append(
                json.dumps(
                    {
                        "measurement_id": str(uuid.uuid4()),
                        "timestamp": timestamp,
                        "name": name,
                        "type": "counter",
                        "unit": "{event}",
                        "value": value,
                        "temporality": "delta",
                        "attributes": dict(attributes),
                    }
                )
            )
        for (name, attributes), state in histograms.items():
            bodies.append(
                json.dumps(
                    {
                        "measurement_id": str(uuid.uuid4()),
                        "timestamp": timestamp,
                        "name": name,
                        "type": "histogram",
                        "unit": "ms",
                        "bounds": list(_HISTOGRAM_BOUNDS),
                        "bucket_counts": list(state.counts),
                        "count": state.count,
                        "sum": state.total,
                        "min": state.minimum,
                        "max": state.maximum,
                        "temporality": "delta",
                        "attributes": dict(attributes),
                    }
                )
            )
        return bodies, gauges

    def _gauge_bodies(
        self,
        spool_pending: int,
        gauges: list[tuple[str, str, Callable[[], float | int | None]]],
    ) -> list[str]:
        timestamp = datetime.now(UTC).isoformat()
        values: list[tuple[str, str, float | int]] = []
        memory = _memory_usage_bytes()
        if memory is not None:
            values.append(("process.memory.usage", "By", memory))
        values.append(("sentinel.spool.pending", "{event}", spool_pending))
        for name, unit, callback in gauges:
            try:
                value = callback()
            except Exception:
                logger.debug("Fuente Sentinel gauge callback failed", exc_info=True)
                continue
            if isinstance(value, bool) or not isinstance(value, int | float):
                continue
            if not math.isfinite(float(value)):
                continue
            values.append((name, unit, value))
        bodies: list[str] = []
        for name, unit, value in values:
            bodies.append(
                json.dumps(
                    {
                        "measurement_id": str(uuid.uuid4()),
                        "timestamp": timestamp,
                        "name": name,
                        "type": "gauge",
                        "unit": unit,
                        "value": value,
                        "attributes": {},
                    }
                )
            )
        return bodies

    def _flush_metrics(self, db: sqlite3.Connection) -> int:
        if not self.metrics_enabled:
            return 0
        bodies, gauges = self._drain_metrics()
        dropped = 0
        with db:
            if bodies:
                db.executemany(
                    "INSERT INTO events(priority, body, kind) VALUES (0, ?, 'metric')",
                    [(body,) for body in bodies],
                )
            pending = int(db.execute("SELECT count(*) FROM events").fetchone()[0])
            gauge_bodies = self._gauge_bodies(pending, gauges)
            if gauge_bodies:
                db.executemany(
                    "INSERT INTO events(priority, body, kind) VALUES (0, ?, 'metric')",
                    [(body,) for body in gauge_bodies],
                )
            if bodies or gauge_bodies:
                dropped = self._enforce_cap(db)
        return dropped

    # -- spans -----------------------------------------------------------

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
        if not _valid_hex_id(trace_id, 32):
            logger.debug("Dropping span with an invalid trace ID")
            return
        if not _valid_hex_id(span_id, 16):
            logger.debug("Dropping span with an invalid span ID")
            return
        if parent_span_id is not None and (
            not _valid_hex_id(parent_span_id, 16) or parent_span_id.lower() == span_id.lower()
        ):
            logger.debug("Dropping span with an invalid parent span ID")
            return
        if start.tzinfo is None or end.tzinfo is None or end < start:
            logger.debug("Dropping span with invalid timestamps")
            return
        span_kind = kind.lower()
        span_status = status.lower()
        if span_kind not in _SPAN_KINDS or span_status not in _SPAN_STATUSES:
            logger.debug("Dropping span with an invalid kind or status")
            return
        span_name = name.strip()[:_MAX_SPAN_NAME]
        if not span_name:
            logger.debug("Dropping span without a name")
            return
        payload: dict[str, Any] = {
            "trace_id": trace_id.lower(),
            "span_id": span_id.lower(),
            "name": span_name,
            "kind": span_kind,
            "start_time": _rfc3339(start),
            "end_time": _rfc3339(end),
            "status": span_status,
            "attributes": _clean_attributes(attributes),
        }
        if parent_span_id is not None:
            payload["parent_span_id"] = parent_span_id.lower()
        if status_message:
            payload["status_message"] = status_message[:_MAX_STATUS_MESSAGE]
        self._enqueue(1 if span_status == "error" else 0, "span", json.dumps(payload))

    # -- request telemetry ----------------------------------------------

    def record_request(
        self,
        method: str,
        route_group: str,
        status: int,
        duration_ms: float,
        *,
        error_type: str | None = None,
        request_id: str | None = None,
    ) -> None:
        """Record one finished HTTP request without any raw URL or body data."""
        duration = max(0.0, float(duration_ms))
        is_error = status >= 500 or error_type is not None
        slow = duration >= self.slow_request_ms
        status_class = f"{status // 100}xx"
        metric_attributes: dict[str, Any] = {
            "route_group": route_group,
            "status_class": status_class,
        }
        if self.metrics_enabled:
            self.count("http.server.request.count", 1, metric_attributes)
            self.observe("http.server.request.duration", duration, metric_attributes)

        trace_id: str | None = None
        span_id: str | None = None
        should_trace = is_error or slow
        if not should_trace and self.trace_sample_rate > 0:
            should_trace = random.random() < self.trace_sample_rate
        if should_trace:
            trace_id = new_trace_id()
            span_id = new_span_id()
            end = datetime.now(UTC)
            start = end - timedelta(milliseconds=duration)
            self.span(
                f"{method} {route_group}",
                start,
                end,
                trace_id=trace_id,
                span_id=span_id,
                parent_span_id=None,
                kind="server",
                status="error" if is_error else "ok",
                status_message="Request failed" if is_error else None,
                attributes={
                    "route_group": route_group,
                    "http.response.status_code": status,
                },
            )

        should_log = self.request_logs == "all" or (self.request_logs == "errors" and is_error)
        if should_log:
            log_attributes: dict[str, str | int | float] = {
                "route_group": route_group,
                "status": status,
                "duration_ms": round(duration, 3),
            }
            if error_type is not None:
                log_attributes["error_type"] = error_type
            self.emit(
                "request_failure" if error_type else "http_request",
                "Error" if is_error else "Information",
                attributes=log_attributes,
                correlation_id=request_id,
                trace_id=trace_id,
                span_id=span_id,
            )
        if slow and self.request_logs != "off":
            self.emit(
                "slow_request",
                "Warning",
                attributes={
                    "route_group": route_group,
                    "status": status,
                    "duration_ms": round(duration, 3),
                },
                correlation_id=request_id,
                trace_id=trace_id,
                span_id=span_id,
            )

    # -- worker ----------------------------------------------------------

    def _resource(self, client_id: str) -> dict[str, Any]:
        cached = self._resource_cache.get(client_id)
        if cached is not None:
            return cached
        resource: dict[str, Any] = {
            "service.name": self.application,
            "client.id": client_id,
            "deployment.environment.name": self.environment,
            "process.pid": os.getpid(),
            "session.id": self.session_id,
        }
        version = _service_version()
        if version:
            resource["service.version"] = version
        host = _host_name()
        if host:
            resource["host.name"] = host
        os_type = _os_type()
        if os_type:
            resource["os.type"] = os_type
        self._resource_cache[client_id] = resource
        return resource

    def _heartbeat_payload(
        self,
        client_id: str,
        uptime_seconds: int,
        spool_pending: int,
        dropped_events: int,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "application": self.application,
            "client_id": client_id,
            "environment": self.environment,
            "session_id": self.session_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "uptime_seconds": max(0, uptime_seconds),
        }
        version = _service_version()
        if version:
            payload["application_version"] = version
        host = _host_name()
        if host:
            payload["machine"] = host
        os_type = _os_type()
        if os_type:
            payload["operating_system"] = os_type
        payload["process_id"] = os.getpid()
        attributes: dict[str, Any] = {
            "spool_pending": max(0, spool_pending),
            "dropped_events": max(0, dropped_events),
        }
        memory = _memory_usage_bytes()
        if memory is not None:
            attributes["memory_usage_bytes"] = memory
        payload["attributes"] = attributes
        return payload

    def _enforce_cap(self, db: sqlite3.Connection) -> int:
        overflow = int(
            db.execute("SELECT max(count(*) - ?, 0) FROM events", (_BUFFER_SIZE,)).fetchone()[0]
        )
        if overflow:
            db.execute(
                "DELETE FROM events WHERE id IN "
                "(SELECT id FROM events ORDER BY priority, id LIMIT ?)",
                (overflow,),
            )
        return overflow

    def _run(self) -> None:
        pending: list[tuple[int, str, str]] = []
        while True:
            try:
                with closing(sqlite3.connect(self.spool, timeout=1)) as db:
                    _ensure_spool_schema(db)
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

    def _work(
        self, db: sqlite3.Connection, client_id: str, pending: list[tuple[int, str, str]]
    ) -> None:
        next_send = 0.0
        next_heartbeat = 0.0
        next_metrics = 0.0
        backoff = 1.0
        batch_size = _BATCH_SIZE
        dropped_reported = 0
        spool_dropped = 0
        kind_index = 0
        flushed_on_stop = False
        while True:
            stopping = self._stop.is_set()
            while len(pending) < 1024:
                try:
                    pending.append(self._pending.get_nowait())
                except queue.Empty:
                    break
            if pending:
                with db:
                    db.executemany(
                        "INSERT INTO events(priority, body, kind) VALUES (?, ?, ?)", pending
                    )
                    dropped = self._enforce_cap(db)
                pending.clear()
                spool_dropped += dropped
            if stopping and not flushed_on_stop:
                spool_dropped += self._flush_metrics(db)
                flushed_on_stop = True
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
                spool_pending = int(db.execute("SELECT count(*) FROM events").fetchone()[0])
                status, retry, _ = self._post(
                    "/api/v1/clients/heartbeat",
                    self._heartbeat_payload(
                        client_id,
                        int(now - self.started),
                        spool_pending,
                        dropped_total,
                    ),
                )
                next_heartbeat = time.monotonic() + max(
                    _HEARTBEAT_INTERVAL,
                    retry,
                    _CONFIGURATION_BACKOFF if status in {401, 403} else 0,
                )
                continue
            if now >= next_metrics:
                spool_dropped += self._flush_metrics(db)
                next_metrics = time.monotonic() + _METRIC_INTERVAL
                continue
            if now >= next_send:
                rows: list[tuple[int, str]] | None = None
                selected_kind: str | None = None
                for offset in range(len(_KINDS)):
                    kind = _KINDS[(kind_index + offset) % len(_KINDS)]
                    candidate = db.execute(
                        "SELECT id, body FROM events WHERE kind = ? ORDER BY id LIMIT ?",
                        (kind, batch_size),
                    ).fetchall()
                    if candidate:
                        rows = candidate
                        selected_kind = kind
                        kind_index = (kind_index + offset + 1) % len(_KINDS)
                        break
                if rows and selected_kind is not None:
                    delay, split = self._send_batch(db, client_id, rows, selected_kind)
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
        self,
        db: sqlite3.Connection,
        client_id: str,
        rows: list[tuple[int, str]],
        kind: str = "log",
    ) -> tuple[float | None, bool]:
        endpoint, envelope_key = _BATCH_TARGETS.get(kind, _BATCH_TARGETS["log"])
        events = [json.loads(body) for _, body in rows]
        status, retry, response = self._post(
            endpoint,
            {
                "schema_version": 1,
                "resource": self._resource(client_id),
                envelope_key: events,
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
                if endpoint.endswith("/batch") and response.status == 200:
                    body = response.read(256 * 1024 + 1)
                    if len(body) <= 256 * 1024:
                        return 200, 0, json.loads(body)
                return response.status, 0, None
        except HTTPError as exc:
            with exc:
                return exc.code, _retry_after(exc.headers.get("Retry-After")), None
        except HTTPException, OSError, ValueError:
            return 0, 0, None


def _env_float(name: str, default: float, *, minimum: float, maximum: float | None = None) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("Ignoring invalid %s value", name)
        return default
    if not math.isfinite(value) or value < minimum or (maximum is not None and value > maximum):
        logger.warning("Ignoring out-of-range %s value", name)
        return default
    return value


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
