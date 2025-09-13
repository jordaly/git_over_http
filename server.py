import os
import sys
import threading
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse

# ---- CONFIG: adjust to your machine ----
HOST = ""            # bind all interfaces
PORT = 8000


GIT_PROJECT_ROOT = r"/srv/git"  # e.g., put bare repos in /srv/git/*.git
GIT_HTTP_BACKEND = r"/usr/lib/git-core/git-http-backend"

# Optional debug (backend stderr goes to this file)
TRACE_LOG = "/tmp/git-http-backend.log"   # or set to None to disable logging

# ON WINDOWS CHANGE CONSTANTS TO SOMETHING LIKE
# GIT_PROJECT_ROOT = r"C:\Servidor_Git"
# GIT_HTTP_BACKEND = r"C:\Program Files\Git\mingw64\libexec\git-core\git-http-backend.exe"
# TRACE_LOG = r"C:\temp\git-http-backend.log"


URL_PREFIX = "/git"  # URL prefix that maps to git-http-backend

ALLOWED_CLIENT_IPS = {
    "127.0.0.1",
}

# ----------------------------------------


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

    def _handle_git(self):
        # IP allowlist
        client_ip = self.client_address[0]
        if client_ip not in ALLOWED_CLIENT_IPS:
            return self._forbidden(b"403 Forbidden: IP not allowed.\n")

        # Map /git/... to CGI PATH_INFO for git-http-backend
        # e.g. /git/sql_history.git/git-receive-pack
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
        env["REMOTE_ADDR"] = client_ip
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

        # Read backend CGI response headers first, then stream body to client
        # Git backend writes CGI headers like: "Status: 200 OK\r\nContent-Type: ...\r\n\r\n"
        # We parse until the blank line.
        header_bytes = bytearray()
        # Read headers byte-by-byte to reliably detect end-of-headers for any line endings
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
                # e.g. "Status: 200 OK"
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
                # Regular header line "Key: Value"
                if ":" in line:
                    k, v = line.split(":", 1)
                    extra_headers.append((k.strip(), v.strip()))

        # Send status & headers to client
        self.send_response(status_code, reason)
        # Use close-delimited body (no Content-Length) to keep it simple and streaming
        sent_te = False
        for k, v in extra_headers:
            # Avoid sending backend's own "Status" again
            if k.lower() == "status":
                continue
            # We'll avoid re-sending Content-Length and let connection: close delimit the body
            if k.lower() == "content-length":
                continue
            if k.lower() == "transfer-encoding":
                sent_te = True
            self.send_header(k, v)

        # Ensure the client doesn't expect keepalive if backend doesn't provide lengths
        if not any(k.lower() == "connection" for k, _ in extra_headers):
            self.send_header("Connection", "close")
        self.end_headers()

        # Stream the remaining already-read buffer (if any body bytes were read past header)
        remaining = proc.stdout.read1 if hasattr(proc.stdout, "read1") else proc.stdout.read
        # Anything after the header terminator may already be in header_bytes; extract the tail
        # Find split point
        split_at = header_text.encode("iso-8859-1", errors="replace")
        # Not perfect but fine: we already consumed up to \r\n\r\n in header_bytes, so nothing to replay.

        # Now stream the rest of stdout to the client
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
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

            if TRACE_LOG:
                try:
                    stderr_target.flush()
                    stderr_target.close()
                except Exception:
                    pass

    # Route only /git/* to backend; anything else is 404 or can serve a simple index if you want
    def do_GET(self):
        if self.path.startswith(URL_PREFIX + "/"):
            return self._handle_git()
        return self._not_found()

    def do_POST(self):
        if self.path.startswith(URL_PREFIX + "/"):
            return self._handle_git()
        return self._not_found()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def main():
    os.makedirs(os.path.dirname(TRACE_LOG), exist_ok=True) if TRACE_LOG else None
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

