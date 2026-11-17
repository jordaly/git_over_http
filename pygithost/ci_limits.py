"""Shared source-transfer limit validation; no fixed upper size ceiling."""

DEFAULT_SOURCE_LIMIT_MB = 100
MIB = 1024 * 1024
LIMIT_DEFAULTS = {
    "log_mb": 1, "artifact_mb": 16, "artifact_uncompressed_mb": 20,
    "artifact_files": 1000, "source_timeout_seconds": 60, "transfer_timeout_seconds": 60,
    "image_pull_timeout_seconds": 600,
}


def execution_limits(raw=None):
    raw = {} if raw is None else raw
    if not isinstance(raw, dict) or set(raw) - set(LIMIT_DEFAULTS):
        raise ValueError("Unknown execution.limits fields.")
    result = {**LIMIT_DEFAULTS, **raw}
    for key, value in result.items():
        if type(value) is not int or value <= 0:
            raise ValueError(f"execution.limits.{key} must be a positive whole number.")
    return result


def progress_bytes(limits=None):
    # Combined and per-step output may duplicate logs. Worst-case JSON escaping
    # expands each byte to six ASCII characters, plus bounded step metadata.
    return execution_limits(limits)["log_mb"] * MIB * 12 + MIB


def completion_bytes(limits=None):
    limits = execution_limits(limits)
    return progress_bytes(limits) + 4 * ((limits["artifact_mb"] * MIB + 2) // 3) + 1024


def source_limit_mb(value=DEFAULT_SOURCE_LIMIT_MB):
    if type(value) is not int or value <= 0:
        raise ValueError("source_limit_mb must be a positive whole number of MiB.")
    return value


def source_limit_bytes(value=DEFAULT_SOURCE_LIMIT_MB):
    return source_limit_mb(value) * MIB


def source_response_bytes(value=DEFAULT_SOURCE_LIMIT_MB):
    # Base64 expands each three input bytes into four characters. Allow the
    # small JSON envelope as well, without imposing another hidden size ceiling.
    size = source_limit_bytes(value)
    return 4 * ((size + 2) // 3) + 1024
