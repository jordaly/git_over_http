import io
import os
import socket
import threading
import time
import http.client
import subprocess
import unittest
from contextlib import closing
from unittest.mock import patch

# Adjust this import if your module name differs
import server as srv


# ---------- Helpers ----------

def _find_free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _PipeLikeStdout:
    """
    A tiny pipe-like object that a fake backend writes into on a background thread,
    while the server reads from it. Simulates streamed CGI output.
    """
    def __init__(self):
        r_fd, w_fd = os.pipe()
        self._r = os.fdopen(r_fd, "rb", buffering=0)
        self._w = os.fdopen(w_fd, "wb", buffering=0)

    def write(self, data: bytes):
        self._w.write(data)
        self._w.flush()

    def close_writer(self):
        try:
            self._w.close()
        except Exception:
            pass

    def read(self, n: int = -1) -> bytes:
        return self._r.read(n)

    # Alias read1 for compatibility if the server uses it
    read1 = read

    def close_reader(self):
        try:
            self._r.close()
        except Exception:
            pass


class FakeProc:
    """
    Fake replacement for subprocess.Popen that simulates git-http-backend:
    - Accepts stdin (server streams POST body).
    - Streams CGI headers + body gradually via stdout.
    - Supports wait()/kill()/returncode.
    """
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.env = kwargs.get("env", {})
        self.stdin = io.BytesIO()
        self.stdout = _PipeLikeStdout()
        self._stderr_target = kwargs.get("stderr", subprocess.DEVNULL)
        self._returncode = 0
        self._done = threading.Event()

        # Create realistic CGI headers + a streamed body
        # (You can assert PATH_INFO/QUERY_STRING here if you want stricter checks)
        header = (
            b"Status: 200 OK\r\n"
            b"Content-Type: application/x-git-receive-pack-advertisement\r\n"
            b"\r\n"
        )
        body_chunks = [
            b"# service=git-receive-pack\n",
            b"0000",
            b"some-streamed-data-1\n",
            b"some-streamed-data-2\n",
        ]

        def _writer():
            try:
                self.stdout.write(header)
                for ch in body_chunks:
                    time.sleep(0.02)  # stagger chunks to mimic streaming
                    self.stdout.write(ch)
                self.stdout.close_writer()
            finally:
                self._done.set()

        self._writer_thread = threading.Thread(target=_writer, daemon=True)
        self._writer_thread.start()

    def wait(self, timeout=None):
        finished = self._done.wait(timeout=timeout)
        if not finished:
            raise TimeoutError("FakeProc: wait timeout")
        return self._returncode

    def kill(self):
        self._returncode = -9
        self._done.set()

    @property
    def returncode(self):
        return self._returncode


class ServerRunner:
    """
    Context manager to run the HTTP server with patched constants and FakeProc.
    Each test gets an isolated instance on a free port.
    """
    def __init__(self, allow_ips=None, url_prefix="/git", trace_log=None, project_root="/tmp/git-proj-root"):
        self.allow_ips = set(allow_ips or {"127.0.0.1"})
        self.url_prefix = url_prefix
        self.trace_log = trace_log   # set to None on Linux to avoid opening Windows paths
        self.project_root = project_root
        self.port = _find_free_port()
        self.httpd = None
        self.thread = None
        self._patches = []

    def __enter__(self):
        os.makedirs(self.project_root, exist_ok=True)

        # Patch module constants to be Linux-friendly and test specific
        self._patches.append(patch.object(srv, "TRACE_LOG", self.trace_log))
        self._patches.append(patch.object(srv, "GIT_PROJECT_ROOT", self.project_root))
        self._patches.append(patch.object(srv, "ALLOWED_CLIENT_IPS", self.allow_ips))
        self._patches.append(patch.object(srv, "URL_PREFIX", self.url_prefix))
        # Backend path won't be used, but set something POSIX-y
        self._patches.append(patch.object(srv, "GIT_HTTP_BACKEND", "/usr/lib/git-core/git-http-backend"))
        # Ensure HTTP/1.1
        self._patches.append(patch.object(srv.GitHTTPHandler, "protocol_version", "HTTP/1.1"))
        # Stub subprocess.Popen with FakeProc
        self._patches.append(patch.object(subprocess, "Popen", FakeProc))

        for p in self._patches:
            p.start()

        self.httpd = srv.ThreadedHTTPServer(("127.0.0.1", self.port), srv.GitHTTPHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=1)
        for p in reversed(self._patches):
            p.stop()


# ---------- Tests ----------

class GitHTTPServerTests(unittest.TestCase):

    def test_info_refs_get_ok(self):
        with ServerRunner(trace_log=None) as srvrun:
            conn = http.client.HTTPConnection("127.0.0.1", srvrun.port, timeout=5)
            try:
                path = "/git/repo.git/info/refs?service=git-receive-pack"
                conn.request("GET", path, headers={"User-Agent": "unittest"})
                resp = conn.getresponse()
                body = resp.read()

                self.assertEqual(resp.status, 200)
                self.assertEqual(
                    resp.getheader("Content-Type"),
                    "application/x-git-receive-pack-advertisement"
                )
                # Body contains streamed markers
                self.assertIn(b"# service=git-receive-pack", body)
                self.assertIn(b"some-streamed-data-1", body)
                self.assertIn(b"some-streamed-data-2", body)
            finally:
                conn.close()

    def test_git_receive_pack_post_streams_request_body(self):
        with ServerRunner(trace_log=None) as srvrun:
            conn = http.client.HTTPConnection("127.0.0.1", srvrun.port, timeout=5)
            try:
                path = "/git/repo.git/git-receive-pack"
                payload = b"0123456789" * 100  # ~1KB
                headers = {
                    "Content-Type": "application/x-git-receive-pack-request",
                    "Content-Length": str(len(payload)),
                }
                conn.request("POST", path, body=payload, headers=headers)
                resp = conn.getresponse()
                body = resp.read()

                self.assertEqual(resp.status, 200)
                self.assertEqual(
                    resp.getheader("Content-Type"),
                    "application/x-git-receive-pack-advertisement"
                )
                self.assertIn(b"# service=git-receive-pack", body)
            finally:
                conn.close()

    # def test_forbidden_ip(self):
    #     # Empty allowlist => 127.0.0.1 not allowed => 403
    #     with ServerRunner(allow_ips=set(), trace_log=None) as srvrun:
    #         conn = http.client.HTTPConnection("127.0.0.1", srvrun.port, timeout=5)
    #         try:
    #             conn.request("GET", "/git/repo.git/info/refs?service=git-receive-pack")
    #             resp = conn.getresponse()
    #             body = resp.read()
    #             self.assertEqual(resp.status, 403)
    #             self.assertIn(b"Forbidden", body)
    #         finally:
    #             conn.close()

    def test_not_found_wrong_prefix(self):
        with ServerRunner(trace_log=None) as srvrun:
            conn = http.client.HTTPConnection("127.0.0.1", srvrun.port, timeout=5)
            try:
                conn.request("GET", "/nope/repo.git/info/refs?service=git-receive-pack")
                resp = conn.getresponse()
                body = resp.read()
                self.assertEqual(resp.status, 404)
                self.assertIn(b"Not Found", body)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)

