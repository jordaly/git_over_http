"""Pure-Python replacement for ``git-http-backend``.

Used automatically when the configured ``git_http_backend`` executable is not
present. It is a drop-in CGI program: the server launches it with the same
environment (``GIT_PROJECT_ROOT``, ``PATH_INFO``, ``QUERY_STRING``,
``REQUEST_METHOD``, ``CONTENT_TYPE``, ``REMOTE_USER``, ``HTTP_*`` ...) and the
same decoded request body on stdin, and parses the same CGI headers from stdout.
Everything around it (authentication, write scopes, push locks, branch
protection hooks, CI triggers, tracing) therefore behaves identically.

Like ``git-http-backend`` itself, the pack protocol is delegated to
``git upload-pack`` / ``git receive-pack`` in ``--stateless-rpc`` mode. The
module mirrors the routes, headers and access rules of git's http-backend.c:

* Smart HTTP: ``info/refs?service=...``, ``git-upload-pack``,
  ``git-receive-pack`` (protocol v0, v1 and v2; gzip request bodies).
* Dumb HTTP (read-only): ``HEAD``, ``info/refs``, ``objects/info/*``, loose
  objects and pack files, unless ``http.getanyfile`` is false.
* ``http.uploadpack`` (default on) and ``http.receivepack`` (default on only
  when ``REMOTE_USER`` is set) are honoured per repository.

The module only uses the standard library so it can run as a plain script.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import time
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

CHUNK = 65536
GIT = os.environ.get("PYGITHOST_GIT", "git")

_NO_CACHE = [
    ("Expires", "Fri, 01 Jan 1980 00:00:00 GMT"),
    ("Pragma", "no-cache"),
    ("Cache-Control", "no-cache, max-age=0, must-revalidate"),
]
_ONE_YEAR = 31536000
_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def http_date(timestamp: float) -> str:
    """RFC 2822 date as git-http-backend writes it (locale independent, +0000)."""
    t = time.gmtime(timestamp)
    return (
        f"{_DAYS[t.tm_wday]}, {t.tm_mday:02d} {_MONTHS[t.tm_mon - 1]} {t.tm_year} "
        f"{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} +0000"
    )


def cache_forever() -> list[tuple[str, str]]:
    now = time.time()
    return [
        ("Date", http_date(now)),
        ("Expires", http_date(now + _ONE_YEAR)),
        ("Cache-Control", f"public, max-age={_ONE_YEAR}"),
    ]


_SERVICES = {"upload-pack": ("uploadpack", True), "receive-pack": ("receivepack", None)}

_HEX = "[0-9a-f]"
# (method set, regex on the path suffix, handler name)
_ROUTES: list[tuple[frozenset[str], re.Pattern[str], str]] = [
    (frozenset({"GET", "HEAD"}), re.compile(r"/HEAD$"), "head"),
    (frozenset({"GET", "HEAD"}), re.compile(r"/info/refs$"), "info_refs"),
    (frozenset({"GET", "HEAD"}), re.compile(r"/objects/info/alternates$"), "text_file"),
    (frozenset({"GET", "HEAD"}), re.compile(r"/objects/info/http-alternates$"), "text_file"),
    (frozenset({"GET", "HEAD"}), re.compile(r"/objects/info/packs$"), "info_packs"),
    (
        frozenset({"GET", "HEAD"}),
        re.compile(rf"/objects/{_HEX}{{2}}/(?:{_HEX}{{38}}|{_HEX}{{62}})$"),
        "loose_object",
    ),
    (
        frozenset({"GET", "HEAD"}),
        re.compile(rf"/objects/pack/pack-(?:{_HEX}{{40}}|{_HEX}{{64}})\.pack$"),
        "pack_file",
    ),
    (
        frozenset({"GET", "HEAD"}),
        re.compile(rf"/objects/pack/pack-(?:{_HEX}{{40}}|{_HEX}{{64}})\.idx$"),
        "idx_file",
    ),
    (frozenset({"POST"}), re.compile(r"/git-upload-pack$"), "service_rpc"),
    (frozenset({"POST"}), re.compile(r"/git-receive-pack$"), "service_rpc"),
]


class HttpError(Exception):
    def __init__(self, status: int, reason: str, message: str = "") -> None:
        super().__init__(message or reason)
        self.status = status
        self.reason = reason
        self.message = message or reason


def pkt_line(text: str) -> bytes:
    data = text.encode("utf-8")
    return f"{len(data) + 4:04x}".encode("ascii") + data


class Backend:
    """One CGI request, mirroring git's http-backend.c."""

    def __init__(
        self,
        environ: dict[str, str],
        stdin: BinaryIO,
        stdout: BinaryIO,
        runner: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    ) -> None:
        self.env = environ
        self.stdin = stdin
        self.stdout = stdout
        self.runner = runner
        self.method = environ.get("REQUEST_METHOD", "GET").upper()
        self.headers_sent = False

    # ---------- CGI output ----------
    def send_headers(
        self, status: int = 200, reason: str = "OK", headers: list[tuple[str, str]] | None = None
    ) -> None:
        lines = [] if status == 200 else [f"Status: {status} {reason}"]
        lines += [f"{name}: {value}" for name, value in headers or []]
        self.stdout.write(("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1"))
        self.stdout.flush()
        self.headers_sent = True

    def write(self, data: bytes) -> None:
        if self.method != "HEAD":
            self.stdout.write(data)

    def fail(self, error: HttpError) -> None:
        if self.headers_sent:
            return
        self.send_headers(
            error.status, error.reason, [("Content-Type", "text/plain; charset=utf-8"), *_NO_CACHE]
        )
        self.write((error.message.rstrip("\n") + "\n").encode("utf-8"))
        self.stdout.flush()

    # ---------- repository resolution ----------
    def resolve(self, path_info: str, suffix: str) -> Path:
        root_value = self.env.get("GIT_PROJECT_ROOT")
        if not root_value:
            raise HttpError(500, "Internal Server Error", "GIT_PROJECT_ROOT is not set")
        repo_part = path_info[: len(path_info) - len(suffix)]
        segments = [segment for segment in repo_part.split("/") if segment]
        if not segments or any(seg in (".", "..") or "\\" in seg for seg in segments):
            raise HttpError(404, "Not Found", "Repository not found")
        root = Path(root_value).resolve()
        repo = root.joinpath(*segments).resolve()
        if repo != root and root not in repo.parents:
            raise HttpError(404, "Not Found", "Repository not found")
        if not (repo / "HEAD").is_file() or not (repo / "objects").is_dir():
            raise HttpError(404, "Not Found", "Repository not found")
        export_all = bool(self.env.get("GIT_HTTP_EXPORT_ALL"))
        if not export_all and not (repo / "git-daemon-export-ok").is_file():
            raise HttpError(404, "Not Found", "Repository not exported")
        return repo

    def git_env(self) -> dict[str, str]:
        env = dict(self.env)
        protocol = self.env.get("HTTP_GIT_PROTOCOL")
        if protocol:
            env["GIT_PROTOCOL"] = protocol
        user = self.env.get("REMOTE_USER")
        if user:
            env.setdefault("GIT_COMMITTER_NAME", user)
            env.setdefault("GIT_COMMITTER_EMAIL", f"{user}@http.{self.env.get('REMOTE_ADDR', '')}")
        return env

    def config_bool(self, repo: Path, key: str) -> bool | None:
        result = subprocess.run(
            [GIT, f"--git-dir={repo}", "config", "--bool", "--get", key],
            capture_output=True,
            env=self.git_env(),
            check=False,
        )
        value = result.stdout.decode("utf-8", "replace").strip()
        if result.returncode != 0 or not value:
            return None
        return value == "true"

    def service_enabled(self, repo: Path, service: str) -> None:
        key, default = _SERVICES[service]
        enabled = self.config_bool(repo, f"http.{key}")
        if enabled is None:
            enabled = default if default is not None else bool(self.env.get("REMOTE_USER"))
        if not enabled:
            raise HttpError(403, "Forbidden", f"Service not enabled: '{service}'")

    def require_any_file(self, repo: Path) -> None:
        if self.config_bool(repo, "http.getanyfile") is False:
            raise HttpError(403, "Forbidden", "Unsupported service: getanyfile")

    # ---------- routing ----------
    def run(self) -> int:
        try:
            path_info = self.env.get("PATH_INFO", "")
            for methods, pattern, handler in _ROUTES:
                match = pattern.search(path_info)
                if not match:
                    continue
                if self.method not in methods:
                    allow = ", ".join(sorted(methods))
                    raise HttpError(405, "Method Not Allowed", f"Method not allowed; use {allow}")
                repo = self.resolve(path_info, match.group(0))
                getattr(self, "route_" + handler)(repo, match.group(0))
                self.stdout.flush()
                return 0
            raise HttpError(404, "Not Found", "Request not supported")
        except HttpError as error:
            self.fail(error)
            return 0
        except BrokenPipeError:
            return 1

    # ---------- dumb protocol ----------
    def send_file(
        self,
        path: Path,
        content_type: str,
        cache: list[tuple[str, str]],
        *,
        last_modified: bool = True,
    ) -> None:
        try:
            handle = path.open("rb")
        except OSError as exc:
            raise HttpError(404, "Not Found", "File not found") from exc
        with handle:
            stat = os.fstat(handle.fileno())
            headers = [
                *cache,
                ("Content-Type", content_type),
                ("Content-Length", str(stat.st_size)),
            ]
            if last_modified:
                headers.append(("Last-Modified", http_date(stat.st_mtime)))
            self.send_headers(headers=headers)
            while chunk := handle.read(CHUNK):
                self.write(chunk)

    def route_head(self, repo: Path, _suffix: str) -> None:
        self.require_any_file(repo)
        # git-http-backend sends HEAD as generated text without cache headers.
        self.send_file(repo / "HEAD", "text/plain", [], last_modified=False)

    def route_text_file(self, repo: Path, suffix: str) -> None:
        self.require_any_file(repo)
        self.send_file(repo / suffix.lstrip("/"), "text/plain", _NO_CACHE)

    def route_loose_object(self, repo: Path, suffix: str) -> None:
        self.require_any_file(repo)
        self.send_file(repo / suffix.lstrip("/"), "application/x-git-loose-object", cache_forever())

    def route_pack_file(self, repo: Path, suffix: str) -> None:
        self.require_any_file(repo)
        self.send_file(
            repo / suffix.lstrip("/"), "application/x-git-packed-objects", cache_forever()
        )

    def route_idx_file(self, repo: Path, suffix: str) -> None:
        self.require_any_file(repo)
        self.send_file(
            repo / suffix.lstrip("/"), "application/x-git-packed-objects-toc", cache_forever()
        )

    def route_info_packs(self, repo: Path, _suffix: str) -> None:
        self.require_any_file(repo)
        pack_dir = repo / "objects" / "pack"
        names = sorted(p.name for p in pack_dir.glob("pack-*.pack")) if pack_dir.is_dir() else []
        body = "".join(f"P {name}\n" for name in names) + "\n"
        self.send_headers(headers=[("Content-Type", "text/plain; charset=utf-8"), *_NO_CACHE])
        self.write(body.encode("utf-8"))

    def route_info_refs(self, repo: Path, _suffix: str) -> None:
        query = self.env.get("QUERY_STRING", "")
        service = next(
            (
                value[len("git-") :]
                for key, _, value in (part.partition("=") for part in query.split("&"))
                if key == "service" and value.startswith("git-")
            ),
            None,
        )
        if service is None:
            return self.dumb_info_refs(repo)
        if service not in _SERVICES:
            raise HttpError(403, "Forbidden", f"Unsupported service: 'git-{service}'")
        self.service_enabled(repo, service)
        env = self.git_env()
        v2 = service == "upload-pack" and "version=2" in env.get("GIT_PROTOCOL", "")
        self.send_headers(
            headers=[("Content-Type", f"application/x-git-{service}-advertisement"), *_NO_CACHE]
        )
        if not v2:
            self.write(pkt_line(f"# service=git-{service}\n") + b"0000")
        self.stdout.flush()
        self.run_service(service, repo, ["--stateless-rpc", "--advertise-refs"], env, None)

    def dumb_info_refs(self, repo: Path) -> None:
        self.require_any_file(repo)
        result = subprocess.run(
            [
                GIT,
                f"--git-dir={repo}",
                "for-each-ref",
                "--format=%(objectname) %(refname) %(*objectname)",
            ],
            capture_output=True,
            env=self.git_env(),
            check=False,
        )
        if result.returncode != 0:
            raise HttpError(500, "Internal Server Error", "Cannot list references")
        lines: list[str] = []
        for row in result.stdout.decode("utf-8", "replace").splitlines():
            parts = row.split(" ")
            if len(parts) < 2:
                continue
            lines.append(f"{parts[0]}\t{parts[1]}\n")
            if len(parts) > 2 and parts[2]:
                lines.append(f"{parts[2]}\t{parts[1]}^{{}}\n")
        self.send_headers(headers=[("Content-Type", "text/plain"), *_NO_CACHE])
        self.write("".join(lines).encode("utf-8"))

    # ---------- smart protocol ----------
    def route_service_rpc(self, repo: Path, suffix: str) -> None:
        service = suffix.rsplit("/git-", 1)[1]
        self.service_enabled(repo, service)
        content_type = self.env.get("CONTENT_TYPE", "").split(";", 1)[0].strip()
        if content_type != f"application/x-git-{service}-request":
            raise HttpError(415, "Unsupported Media Type", "Unsupported Media Type")
        encoding = self.env.get("HTTP_CONTENT_ENCODING", "").strip().lower()
        if encoding not in ("", "identity", "gzip", "x-gzip"):
            raise HttpError(415, "Unsupported Media Type", f"Unsupported encoding: {encoding}")
        self.send_headers(
            headers=[("Content-Type", f"application/x-git-{service}-result"), *_NO_CACHE]
        )
        self.run_service(
            service, repo, ["--stateless-rpc"], self.git_env(), encoding in ("gzip", "x-gzip")
        )

    def run_service(
        self, service: str, repo: Path, args: list[str], env: dict[str, str], gzip: bool | None
    ) -> None:
        """Run git <service>; stream stdin (when gzip is not None) and stdout."""
        proc = self.runner(
            [GIT, service, *args, str(repo)],
            stdin=subprocess.PIPE if gzip is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            env=env,
        )
        feeder: threading.Thread | None = None
        if gzip is not None and proc.stdin is not None:
            feeder = threading.Thread(target=self._feed, args=(proc.stdin, gzip), daemon=True)
            feeder.start()
        assert proc.stdout is not None
        output = proc.stdout.fileno()
        try:
            while chunk := os.read(output, CHUNK):
                self.write(chunk)
                self.stdout.flush()
        finally:
            proc.stdout.close()
            if feeder is not None:
                feeder.join()
            proc.wait()

    def _feed(self, target: BinaryIO, gzip: bool) -> None:
        """Copy the request body to git's stdin, inflating gzip bodies."""
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS) if gzip else None
        try:
            while chunk := self.stdin.read(CHUNK):
                if inflater is not None:
                    chunk = inflater.decompress(chunk)
                if chunk:
                    target.write(chunk)
            if inflater is not None:
                tail = inflater.flush()
                if tail:
                    target.write(tail)
        except OSError, zlib.error:
            # git exited early or the body is corrupt; git reports the protocol error.
            pass
        finally:
            try:
                target.close()
            except OSError:
                pass


def main() -> int:
    stdin = getattr(sys.stdin, "buffer", sys.stdin)
    stdout = getattr(sys.stdout, "buffer", sys.stdout)
    return Backend(dict(os.environ), stdin, stdout).run()  # type: ignore[arg-type]


if __name__ == "__main__":
    sys.exit(main())
