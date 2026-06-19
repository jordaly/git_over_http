"""Configuration loading and validation.

This module has no server side effects.  Configuration is represented by an
immutable value object so callers and tests do not need to patch module globals.
"""

from __future__ import annotations

import json
import platform
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Mapping


CONFIG_SCHEMA_VERSION = 1
DEFAULT_CONFIG_FILENAME = "pygithost.config.json"


def _static_root() -> str:
    return str(Path(__file__).resolve().parent.parent / "static")


def _platform_paths(target: str) -> dict[str, object]:
    if target == "Windows":
        return {
            "git_project_root": r"C:\Servidor_Git",
            "git_http_backend": r"C:\Program Files\Git\mingw64\libexec\git-core\git-http-backend.exe",
            "trace_log": r"C:\temp\git-http-backend.log",
            "db_path": r"C:\temp\pygithost.db",
        }
    if target == "Linux":
        return {
            "git_project_root": str(Path.home() / "git_repos"),
            "git_http_backend": "/usr/lib/git-core/git-http-backend",
            "trace_log": None,
            "db_path": str(Path.home() / ".local/share/pygithost/pygithost.db"),
        }
    if target == "Darwin":
        return {
            "git_project_root": str(Path.home() / "git"),
            "git_http_backend": "/opt/homebrew/opt/git/libexec/git-core/git-http-backend",
            "trace_log": "/tmp/git-http-backend.log",
            "db_path": str(Path.home() / ".local/share/pygithost/pygithost.db"),
        }
    raise NotImplementedError(target)


@dataclass(frozen=True, slots=True)
class AppConfig:
    schema_version: int
    platform: str
    host: str
    port: int
    git_project_root: str
    git_http_backend: str
    trace_log: str | None
    db_path: str
    url_prefix: str
    allowed_client_ips: tuple[str, ...]
    require_auth: bool
    filter_ips: bool
    realm: str
    flat_owner_ui: str
    pr_patch_max_bytes: int
    prism_diff_highlight_max_bytes: int
    max_header_bytes: int
    read_chunk: int
    session_cookie_name: str
    session_ttl_seconds: int
    session_cookie_secure: bool
    login_path: str
    static_url_prefix: str
    static_root: str
    static_cache_seconds: int
    static_requires_auth: bool

    @classmethod
    def default_for_platform(cls, target: str | None = None) -> AppConfig:
        target = target or platform.system()
        return cls(
            schema_version=CONFIG_SCHEMA_VERSION,
            platform=target,
            host="",
            port=8000,
            **_platform_paths(target),
            url_prefix="/git",
            allowed_client_ips=(
                "192.168.16.75", "192.168.16.162", "192.168.16.164",
                "192.168.16.198", "192.168.16.77", "192.168.16.76",
                "127.0.0.1", "192.168.19.222",
            ),
            require_auth=False,
            filter_ips=True,
            realm="Git Repositories",
            flat_owner_ui="root",
            pr_patch_max_bytes=800_000,
            prism_diff_highlight_max_bytes=250_000,
            max_header_bytes=64 * 1024,
            read_chunk=64 * 1024,
            session_cookie_name="pygithost_session",
            session_ttl_seconds=12 * 60 * 60,
            session_cookie_secure=False,
            login_path="/login",
            static_url_prefix="/static",
            static_root=_static_root(),
            static_cache_seconds=60 * 60,
            static_requires_auth=False,
        )

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> AppConfig:
        target = str(raw.get("platform") or platform.system())
        values = cls.default_for_platform(target).to_dict()
        known = {item.name for item in fields(cls)}
        values.update({key: value for key, value in raw.items() if key in known})

        ips = values["allowed_client_ips"]
        if isinstance(ips, str):
            ips = [part.strip() for part in ips.split(",") if part.strip()]
        if not isinstance(ips, (list, tuple)):
            raise ValueError("allowed_client_ips must be an array or comma-separated string")
        values["allowed_client_ips"] = tuple(str(ip).strip() for ip in ips if str(ip).strip())

        for key in (
            "schema_version", "port", "pr_patch_max_bytes",
            "prism_diff_highlight_max_bytes", "max_header_bytes", "read_chunk",
            "session_ttl_seconds", "static_cache_seconds",
        ):
            values[key] = int(values[key])
        for key in ("require_auth", "filter_ips", "session_cookie_secure", "static_requires_auth"):
            values[key] = bool(values[key])

        if not 0 <= values["port"] <= 65535:
            raise ValueError("port must be between 0 and 65535")
        if not str(values["url_prefix"]).startswith("/"):
            raise ValueError("url_prefix must start with '/'")
        if not str(values["static_url_prefix"]).startswith("/"):
            raise ValueError("static_url_prefix must start with '/'")
        return cls(**values)

    @classmethod
    def from_file(cls, path: str | Path) -> AppConfig:
        with Path(path).expanduser().open("r", encoding="utf-8") as stream:
            raw = json.load(stream)
        if not isinstance(raw, dict):
            raise ValueError("The config file root must be a JSON object")
        return cls.from_mapping(raw)

    def to_dict(self) -> dict[str, Any]:
        values = asdict(self)
        values["allowed_client_ips"] = list(self.allowed_client_ips)
        return values

    def write(self, path: str | Path, *, overwrite: bool = False) -> Path:
        destination = Path(path).expanduser()
        if destination.exists() and not overwrite:
            raise FileExistsError(f"Config file already exists: {destination}. Use --overwrite to replace it.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8") as stream:
            json.dump(self.to_dict(), stream, indent=4)
            stream.write("\n")
        return destination
