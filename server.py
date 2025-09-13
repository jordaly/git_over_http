import os
import sys
import threading
import subprocess
import ipaddress
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse

# ---- CONFIG: adjust to your machine ----
HOST = ""            # bind all interfaces
PORT = 8000

# Linux defaults
GIT_PROJECT_ROOT = "/srv/git"  # e.g., put bare repos in /srv/git/*.git
GIT_HTTP_BACKEND = "/usr/lib/git-core/git-http-backend"
TRACE_LOG = None  # set to a path (e.g. "/tmp/git-http-backend.log") to log backend stderr

# ON WINDOWS CHANGE CONSTANTS TO SOMETHING LIKE:
# GIT_PROJECT_ROOT = r"C:\Servidor_Git"
# GIT_HTTP_BACKEND = r"C:\Program Files\Git\mingw64\libexec\git-core\git-http-backend.exe"
# TRACE_LOG = r"C:\temp\git-http-backend.log"

URL_PREFIX = "/git"  # URL prefix that maps to git-http-backend

ALLOWED_CLIENT_IPS = {
    "127.0.0.1",
    # You may add CIDRs like "192.168.16.0/24" or "::1/128"
}

# ----------------------------------------


def _ip_allowed(ip: str, allow: set[str]) -> bool:
    """Allow exact IPs or CIDRs; handles IPv4/IPv6. Empty allowlist denies all."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not allow:
        return False
    for item in allow:
        try:
            # CIDR (e.g., "192.168.1.0/24", "::1/128")
            if addr in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            # Single IP string
            try:
                if ipaddress.ip_address(item) == addr:
                    return True
            except ValueError:
                if item == ip:  # literal fallback
                    return True
    return False


def _write_request_body_to_stdin(handler: BaseHTTPRequestHandler, proc: subprocess.Popen, content_len: int):
    """Stream request body into backend stdin without buffering the whole thing."""
    remaining = content_len
    CHUNK = 65536
    try:
        while remaining > 0:
            to_read = CHUNK if remaining > CHUNK else remaining
            data = handler.rfile.read(to_read)
            if not data:
                break
            proc.stdin.write(data)
            remaining -= len(data)
        proc.stdin.flush()
    except Exception:
        pass
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass


class GitHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # important: keep 1.1

    # -------- small helpers --------
    def _client_ip(self) -> str:
        ip = self.client_address[0]
        # normalize IPv6 loopback to IPv4 for simple allowlists
        if ip == "::1":
            return "127.0.0.1"
        return ip

    def _allowlist(self) -> set[str]:
        # Prefer per-server allowlist if present, else module default
        return getattr(self.server, "allowlist", ALLOWED_CLIENT_IPS)

    # -------- response helpers --------
    def _forbidden(self, msg=b"403 Forbidden\n"):
        self.send_response(403, "Forbidden")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(msg)
            self.wfile.flush()
        except Exception:
            pass
        self.close_connection = True

    def _not_found(self):
        self.send_response(404, "Not Found")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(b"404 Not Found\n")
            self.wfile.flush()
        except Exception:
            pass
        self.close_connection = True

    # -------- main handler --------
    def _handle_git(self):
        # Map /git/... to CGI PATH_INFO for git-http-backend
        if not self.path.startswith(URL_PREFIX + "/"):
            return self._not_found()

        parsed = urlparse(self.path)
        path_info = parsed.path[len(URL_PREFIX):]  # keep leading slash before repo
        query = parsed.query or ""

        # Build CGI-like env for git-http-backend
        env = os.environ.copy()
        env["GIT_PROJECT_ROOT"] = GIT_PROJECT_ROOT
        env["GIT_HTTP_EXPORT_ALL"] = "1"

        # Helpful while debugging:
        # env["GIT_TRACE"] = "1"
        # env["GIT_TRACE_PACKET"] = "1"

        # Standard CGI vars `git-http-backend` expects
        env["REQUEST_METHOD"] = self.command
        env["GIT_COMMITTER_NAME"] = env.get("GIT_COMMITTER_NAME", "git-http")
        env["GIT_COMMITTER_EMAIL"] = env.get("GIT_COMMITTER_EMAIL", "git-http@localhost")
        env["PATH_INFO"] = path_info
        env["QUERY_STRING"] = query
        env["SCRIPT_NAME"] = URL_PREFIX
        env["REMOTE_ADDR"] = self._client_ip()
        env["SERVER_PROTOCOL"] = self.request_version
        env["SERVER_SOFTWARE"] = "PyGitHTTP/1.0"

        ctype = self.headers.get("Content-Type")
        if ctype:
            env["CONTENT_TYPE"] = ctype
        clen = int(self.headers.get("Content-Length") or 0)
        if clen:
            env["CONTENT_LENGTH"] = str(clen)

        # Launch backend
        stderr_target = open(TRACE_LOG, "ab", buffering=0) if TRACE_LOG else subprocess.DEVNULL
        proc = subprocess.Popen(
            [GIT_HTTP_BACKEND],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr_target,
            env=env,
            bufsize=0
        )

        # If there's a request body, stream it into backend stdin in a separate thread
        if clen > 0:
            t = threading.Thread(target=_write_request_body_to_stdin, args=(self, proc, clen), daemon=True)
            t.start()

        # Read backend CGI response headers first
        header_bytes = bytearray()
        while True:
            b = proc.stdout.read(1)
            if not b:
                break
            header_bytes.extend(b)
            if header_bytes.endswith(b"\r\n\r\n") or header_bytes.endswith(b"\n\n"):
                break

        header_text = header_bytes.decode("iso-8859-1", errors="replace")
        status_code = 200
        reason = "OK"
        extra_headers = []

        for line in header_text.splitlines():
            if not line.strip():
                continue
            if line.lower().startswith("status:"):
                try:
                    _, rest = line.split(":", 1)
                    rest = rest.strip()
                    code_str, _, reason_part = rest.partition(" ")
                    status_code = int(code_str)
                    if reason_part:
                        reason = reason_part.strip()
                except Exception:
                    pass
            else:
                if ":" in line:
                    k, v = line.split(":", 1)
                    extra_headers.append((k.strip(), v.strip()))

        # Send status & headers to client
        self.send_response(status_code, reason)
        for k, v in extra_headers:
            if k.lower() in ("status", "content-length"):
                continue
            self.send_header(k, v)
        if not any(k.lower() == "connection" for k, _ in extra_headers):
            self.send_header("Connection", "close")
        self.end_headers()

        # Stream the rest of stdout to the client
        try:
            CHUNK = 65536
            while True:
                chunk = proc.stdout.read(CHUNK)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except Exception:
            pass
        finally:
            # Close backend stdout to avoid ResourceWarning
            try:
                if hasattr(proc.stdout, "close_reader"):
                    proc.stdout.close_reader()
                elif hasattr(proc.stdout, "close"):
                    proc.stdout.close()
            except Exception:
                pass
            # ensure process ends
            try:
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

            if TRACE_LOG and hasattr(stderr_target, "flush"):
                try:
                    stderr_target.flush()
                    stderr_target.close()
                except Exception:
                    pass

    # Route only /git/* to backend; apply allowlist EARLY
    def do_GET(self):
        if not _ip_allowed(self._client_ip(), self._allowlist()):
            self._forbidden(b"403 Forbidden: IP not allowed.\n")
            return
        if self.path.startswith(URL_PREFIX + "/"):
            return self._handle_git()
        return self._not_found()

    def do_POST(self):
        if not _ip_allowed(self._client_ip(), self._allowlist()):
            self._forbidden(b"403 Forbidden: IP not allowed.\n")
            return
        if self.path.startswith(URL_PREFIX + "/"):
            return self._handle_git()
        return self._not_found()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Per-instance allowlist; tests (or callers) can override this safely.
        self.allowlist = ALLOWED_CLIENT_IPS


def main():
    # If you enable TRACE_LOG with a path, create its directory
    if TRACE_LOG:
        os.makedirs(os.path.dirname(TRACE_LOG), exist_ok=True)
    if not os.path.exists(GIT_HTTP_BACKEND):
        print(f"ERROR: backend not found: {GIT_HTTP_BACKEND}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(GIT_PROJECT_ROOT):
        print(f"ERROR: GIT_PROJECT_ROOT does not exist: {GIT_PROJECT_ROOT}", file=sys.stderr)
        sys.exit(1)

    # Ensure environment is ready for backend
    os.environ["GIT_PROJECT_ROOT"] = GIT_PROJECT_ROOT
    os.environ["GIT_HTTP_EXPORT_ALL"] = "1"

    httpd = ThreadedHTTPServer((HOST, PORT), GitHTTPHandler)
    print("=" * 60)
    print(f"Git Smart HTTP server on port {PORT}")
    print(f"URL prefix: {URL_PREFIX}")
    print(f"GIT_PROJECT_ROOT: {GIT_PROJECT_ROOT}")
    print("=" * 60)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

