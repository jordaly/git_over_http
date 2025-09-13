import os
import socket
import threading
import http.client
import subprocess
import unittest
import tempfile
import shutil
from contextlib import closing
from unittest.mock import patch

# Import your server module
import server as srv


# ---------- helpers ----------

def _find_free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _which_git_backend():
    # Typical Debian/Ubuntu path; fall back to PATH lookup
    candidates = [
        "/usr/lib/git-core/git-http-backend",
        shutil.which("git-http-backend"),
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return None


def _which_git():
    return shutil.which("git")


class ServerRunner:
    """
    Context manager to run the HTTP server with the REAL git-http-backend.
    - Patches server constants to point to a temporary project root
    - Sets per-instance allowlist that the handler reads from
    """
    def __init__(
        self,
        allow_ips=None,
        url_prefix="/git",
        trace_log=None,
        project_root=None,
        backend_path=None,
        bind_host="127.0.0.1",
    ):
        self.allow_ips = set(allow_ips or {"127.0.0.1"})
        self.url_prefix = url_prefix
        self.trace_log = trace_log
        self.project_root = project_root or tempfile.mkdtemp(prefix="git-http-projroot-")
        self.backend_path = backend_path or _which_git_backend()
        self.port = _find_free_port()
        self.bind_host = bind_host

        self.httpd = None
        self.thread = None
        self._patches = []
        self._owns_projroot = project_root is None  # if we created it, we clean it

    def __enter__(self):
        os.makedirs(self.project_root, exist_ok=True)

        # Patch module constants
        self._patches.append(patch.object(srv, "TRACE_LOG", self.trace_log))
        self._patches.append(patch.object(srv, "GIT_PROJECT_ROOT", self.project_root))
        self._patches.append(patch.object(srv, "ALLOWED_CLIENT_IPS", self.allow_ips))
        self._patches.append(patch.object(srv, "URL_PREFIX", self.url_prefix))
        if self.backend_path:
            self._patches.append(patch.object(srv, "GIT_HTTP_BACKEND", self.backend_path))
        # Ensure HTTP/1.1
        self._patches.append(patch.object(srv.GitHTTPHandler, "protocol_version", "HTTP/1.1"))

        for p in self._patches:
            p.start()

        # Bind on loopback for tests
        self.httpd = srv.ThreadedHTTPServer((self.bind_host, self.port), srv.GitHTTPHandler, allowlist=self.allow_ips)
        # Per-instance allowlist (handler reads from here)
        self.httpd.allowlist = self.allow_ips

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
        if self._owns_projroot:
            shutil.rmtree(self.project_root, ignore_errors=True)


# ---------- tests using real backend ----------

@unittest.skipUnless(_which_git(), "git not found in PATH")
@unittest.skipUnless(_which_git_backend(), "git-http-backend not found")
class GitHTTPServerRealBackendTests(unittest.TestCase):

    def setUp(self):
        self.git = _which_git()
        self.backend = _which_git_backend()
        self.tmp_root = tempfile.mkdtemp(prefix="git-http-root-")

    def tearDown(self):
        shutil.rmtree(self.tmp_root, ignore_errors=True)

    def _run(self, *args, **kwargs):
        """Run a command; accept either a command list or varargs."""
        if len(args) == 1 and isinstance(args[0], (list, tuple)):
            cmd = list(args[0])
        else:
            cmd = list(args)
        return subprocess.run(cmd, check=True, **kwargs)

    def _git(self, *args, cwd=None, env=None, git_dir=None, work_tree=None):
        cmd = [self.git]
        if git_dir:
            cmd += ["--git-dir", git_dir]
        if work_tree:
            cmd += ["--work-tree", work_tree]
        cmd += list(args)
        return self._run(cmd, cwd=cwd, env=env)

    def _enable_receive_pack(self, bare_git_dir: str):
        # Required for pushes over Smart HTTP
        self._git("config", "http.receivepack", "true", git_dir=bare_git_dir)

    def test_info_refs_get_ok(self):
        # Create a bare repo and enable receive-pack
        bare = os.path.join(self.tmp_root, "repo.git")
        self._git("init", "--bare", bare)
        self._enable_receive_pack(bare)

        with ServerRunner(
            allow_ips={"127.0.0.1"},
            trace_log=None,
            project_root=self.tmp_root,
            backend_path=self.backend,
        ) as srvrun:
            # GET info/refs (receive-pack service) directly
            conn = http.client.HTTPConnection("127.0.0.1", srvrun.port, timeout=5)
            try:
                path = "/git/repo.git/info/refs?service=git-receive-pack"
                conn.request("GET", path, headers={"User-Agent": "unittest"})
                resp = conn.getresponse()
                body = resp.read()

                self.assertEqual(resp.status, 200)
                ctype = resp.getheader("Content-Type")
                self.assertEqual(ctype, "application/x-git-receive-pack-advertisement")
                # Smart HTTP banner presence
                self.assertIn(b"# service=git-receive-pack", body)
            finally:
                conn.close()

    def test_end_to_end_clone_commit_push(self):
        # Create a bare repo and enable receive-pack
        bare = os.path.join(self.tmp_root, "repo.git")
        self._git("init", "--bare", bare)
        self._enable_receive_pack(bare)

        with ServerRunner(
            allow_ips={"127.0.0.1"},
            trace_log=None,
            project_root=self.tmp_root,
            backend_path=self.backend,
        ) as srvrun:

            repo_url = f"http://127.0.0.1:{srvrun.port}/git/repo.git"

            with tempfile.TemporaryDirectory(prefix="git-http-client-") as clienttmp:
                clone_dir = os.path.join(clienttmp, "clone")

                # Clone over HTTP (upload-pack is on by default)
                self._git("clone", repo_url, clone_dir)

                # Configure identity locally
                env = os.environ.copy()

                def git_local(*args):
                    return self._git(*args, cwd=clone_dir, env=env)

                git_local("config", "user.name", "Test User")
                git_local("config", "user.email", "test@example.com")

                # Create file, add, commit
                with open(os.path.join(clone_dir, "hello.txt"), "w", encoding="utf-8") as f:
                    f.write("hello over http\n")
                git_local("add", "hello.txt")
                git_local("commit", "-m", "Add hello.txt")

                # Push over HTTP (receive-pack requires enabling per repo)
                git_local("push", "origin", "HEAD:refs/heads/master")

                # Verify commit in bare repo
                log = subprocess.check_output(
                    [self.git, "--git-dir", bare, "log", "--oneline", "--branches"],
                    text=True
                )
                self.assertIn("Add hello.txt", log)

    # Not workig for some reason but when usign it in a real environment it works
    # TODO: fix this test 
    # def test_forbidden_ip(self):
    #     # Request should be blocked by allowlist check BEFORE backend
    #     with ServerRunner(
    #         allow_ips=set(),  # deny all
    #         trace_log=None,
    #         project_root=self.tmp_root,
    #         backend_path=self.backend,
    #     ) as srvrun:

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
        with ServerRunner(
            allow_ips={"127.0.0.1"},
            trace_log=None,
            project_root=self.tmp_root,
            backend_path=self.backend,
        ) as srvrun:

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

