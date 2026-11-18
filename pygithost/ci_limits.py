"""Shared source-transfer limit validation; no fixed upper size ceiling."""

DEFAULT_SOURCE_LIMIT_MB = 100
MIB = 1024 * 1024
LIMIT_DEFAULTS: dict[str, int] = {
    "log_mb": 1,
    "artifact_mb": 16,
    "artifact_uncompressed_mb": 20,
    "artifact_files": 1000,
    "source_timeout_seconds": 60,
    "transfer_timeout_seconds": 60,
    "image_pull_timeout_seconds": 600,
}


def execution_limits(raw: object = None) -> dict[str, int]:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict) or set(raw) - set(LIMIT_DEFAULTS):
        raise ValueError("Unknown execution.limits fields.")
    result = dict(LIMIT_DEFAULTS)
    for key, value in raw.items():
        if type(value) is not int or value <= 0:
            raise ValueError(f"execution.limits.{key} must be a positive whole number.")
        result[key] = value
    return result


def progress_bytes(limits: object = None) -> int:
    # Combined and per-step output may duplicate logs. Worst-case JSON escaping
    # expands each byte to six ASCII characters, plus bounded step metadata.
    return execution_limits(limits)["log_mb"] * MIB * 12 + MIB


def completion_bytes(limits: object = None) -> int:
    parsed = execution_limits(limits)
    return progress_bytes(parsed) + 4 * ((parsed["artifact_mb"] * MIB + 2) // 3) + 1024


def source_limit_mb(value: object = DEFAULT_SOURCE_LIMIT_MB) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("source_limit_mb must be a positive whole number of MiB.")
    return value


def source_limit_bytes(value: object = DEFAULT_SOURCE_LIMIT_MB) -> int:
    return source_limit_mb(value) * MIB


def source_response_bytes(value: object = DEFAULT_SOURCE_LIMIT_MB) -> int:
    # Base64 expands each three input bytes into four characters. Allow the
    # small JSON envelope as well, without imposing another hidden size ceiling.
    size = source_limit_bytes(value)
    return 4 * ((size + 2) // 3) + 1024
