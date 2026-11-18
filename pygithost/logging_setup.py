"""Structured application, access and audit logging for PyGitHost.

The server is dependency-free, so this module only uses the standard library.
Log records are emitted as one JSON object per line by default, which keeps
them easy to ship to a collector while staying readable with ``jq``.  An
optional plain-text format is available for interactive terminals.

Only metadata is logged: request bodies, ``Authorization``/``Cookie`` headers,
query strings and form values never reach the log.  Callers must therefore use
:func:`safe_target` when logging request targets and must not add secrets as
``extra`` fields.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ACCESS_LOGGER = "pygithost.access"

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
LOG_FORMATS = ("json", "text")

# Fields promoted to top-level JSON keys.  Everything else that arrives through
# ``extra=`` is included only when it is a JSON primitive, which prevents
# accidental serialization of request objects or driver connections.
EXTRA_FIELDS = (
    "event",
    "request_id",
    "method",
    "path",
    "status",
    "duration_ms",
    "ip",
    "user",
    "size",
    "protocol",
    "error_type",
    "actor",
    "action",
    "target",
    "outcome",
    "detail",
    "port",
    "platform",
    "delivery",
)

_RESERVED = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
    "message",
    "asctime",
}
_HANDLER_MARK = "_pygithost_handler"
_TARGET_LIMIT = 512
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class JsonFormatter(logging.Formatter):
    """One JSON object per record, safe for line-oriented collectors."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in EXTRA_FIELDS:
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        for key, value in record.__dict__.items():
            if key in _RESERVED or key in payload or key.startswith("_"):
                continue
            if isinstance(value, (str, int, float, bool)) or value is None:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class TextFormatter(logging.Formatter):
    """Human-readable single line with the same metadata as JSON output."""

    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)s %(name)s %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        extras = [
            f"{key}={getattr(record, key)}"
            for key in EXTRA_FIELDS
            if getattr(record, key, None) is not None
        ]
        if extras:
            line += " " + " ".join(extras)
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def safe_target(target: object) -> str:
    """Return only the path component of a request target.

    Query strings may contain search terms, reset links or tokens, so they are
    always discarded.  Control characters are stripped to keep one record per
    line and the path is bounded to avoid log flooding from a crafted URL.
    """

    text = str(target or "")
    try:
        path = urlsplit(text).path or "/"
    except ValueError:
        path = text.split("?", 1)[0].split("#", 1)[0]
    path = _CONTROL.sub("", path)[:_TARGET_LIMIT]
    return path or "/"


def _validate(level: str, log_format: str, max_bytes: int, backup_count: int) -> None:
    if level not in LOG_LEVELS:
        raise ValueError(f"log_level must be one of {', '.join(LOG_LEVELS)}")
    if log_format not in LOG_FORMATS:
        raise ValueError(f"log_format must be one of {', '.join(LOG_FORMATS)}")
    if type(max_bytes) is not int or max_bytes < 1024:
        raise ValueError("log_max_bytes must be an integer of at least 1024")
    if type(backup_count) is not int or not 0 <= backup_count <= 100:
        raise ValueError("log_backup_count must be between 0 and 100")


def configure_logging(
    *,
    level: str = "INFO",
    log_file: str | None = None,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    log_format: str = "json",
    console: bool = True,
) -> str | None:
    """Install console and rotating-file handlers on the root logger.

    Safe to call repeatedly (tests and embedded use): handlers installed by a
    previous call are closed and replaced, while handlers owned by an embedding
    application are left untouched.  Returns the active log file, if any.
    """

    level = str(level).strip().upper()
    log_format = str(log_format).strip().lower()
    _validate(level, log_format, max_bytes, backup_count)

    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, _HANDLER_MARK, False):
            root.removeHandler(handler)
            try:
                handler.close()
            except Exception:  # pragma: no cover - closing is best effort
                pass

    formatter: logging.Formatter = JsonFormatter() if log_format == "json" else TextFormatter()
    root.setLevel(level)

    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        setattr(stream, _HANDLER_MARK, True)
        root.addHandler(stream)

    path: str | None = None
    if log_file:
        destination = Path(log_file).expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        rotating = logging.handlers.RotatingFileHandler(
            destination,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        rotating.setFormatter(formatter)
        setattr(rotating, _HANDLER_MARK, True)
        root.addHandler(rotating)
        path = str(destination)

    # The runner module configures itself when used standalone; keep third-party
    # debug output out of the server log unless the operator asked for DEBUG.
    if level != "DEBUG":
        logging.getLogger("asyncio").setLevel(logging.WARNING)
    return path


def access(
    *,
    method: str,
    target: object,
    status: int | None,
    duration_ms: float,
    ip: str,
    user: str | None = None,
    size: int | None = None,
    protocol: str = "HTTP/1.1",
    request_id: str | None = None,
    level: int | None = None,
) -> None:
    """Emit one HTTP access record without bodies, headers or query strings."""

    code = 499 if status is None else int(status)
    if level is None:
        level = logging.WARNING if code >= 500 else logging.INFO
    logging.getLogger(ACCESS_LOGGER).log(
        level,
        "request",
        extra={
            "event": "http_request",
            "method": method,
            "path": safe_target(target),
            "status": code,
            "duration_ms": round(duration_ms, 3),
            "ip": ip,
            "user": user,
            "size": size,
            "protocol": protocol,
            "request_id": request_id,
        },
    )
