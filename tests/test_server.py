import os
import socket
import asyncio
import threading
import http.client
import subprocess
import unittest
import tempfile
import shutil
from contextlib import closing
from dataclasses import replace

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
        self.allow_ips = set({"127.0.0.1"} if allow_ips is None else allow_ips)
        self.url_prefix = url_prefix
        self.trace_log = trace_log
        self.project_root = project_root or tempfile.mkdtemp(
            prefix="git-http-projroot-"
        )
        self.backend_path = backend_path or _which_git_backend()
        self.port = None
        self.bind_host = bind_host

        self.httpd = None
        self.thread = None
        self.loop = None
        self.stop_event = None
        self.ready = threading.Event()
        self.start_error = None
        self._owns_projroot = project_root is None  # if we created it, we clean it

    def __enter__(self):
        os.makedirs(self.project_root, exist_ok=True)

        config = replace(
            srv.AppConfig.default_for_platform(),
            host=self.bind_host,
            port=0,
            git_project_root=self.project_root,
            git_http_backend=self.backend_path,
            trace_log=self.trace_log,
            db_path=os.path.join(self.project_root, "test.db"),
            url_prefix=self.url_prefix,
            allowed_client_ips=tuple(self.allow_ips),
            require_auth=False,
            filter_ips=True,
        )
        app = srv.AsyncGitServer(srv.AppContext(config), allowlist=self.allow_ips)

        async def serve():
            self.loop = asyncio.get_running_loop()
            self.stop_event = asyncio.Event()
            try:
                self.httpd = await asyncio.start_server(
                    app.handle_client, self.bind_host, 0
                )
                self.port = self.httpd.sockets[0].getsockname()[1]
                self.ready.set()
                await self.stop_event.wait()
                self.httpd.close()
                await self.httpd.wait_closed()
            except BaseException as exc:
                self.start_error = exc
                self.ready.set()

        self.thread = threading.Thread(
            target=lambda: asyncio.run(serve()), daemon=True
        )
        self.thread.start()
        if not self.ready.wait(timeout=5):
            raise RuntimeError("Async test server did not start")
        if self.start_error:
            raise self.start_error
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.loop and self.stop_event:
            self.loop.call_soon_threadsafe(self.stop_event.set)
        if self.thread:
            self.thread.join(timeout=5)
        if self._owns_projroot:
            shutil.rmtree(self.project_root, ignore_errors=True)


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
                with open(
                    os.path.join(clone_dir, "hello.txt"), "w", encoding="utf-8"
                ) as f:
                    f.write("hello over http\n")
                git_local("add", "hello.txt")
                git_local("commit", "-m", "Add hello.txt")

                # Push over HTTP (receive-pack requires enabling per repo)
                git_local("push", "origin", "HEAD:refs/heads/master")

                # Verify commit in bare repo
                log = subprocess.check_output(
                    [self.git, "--git-dir", bare, "log", "--oneline", "--branches"],
                    text=True,
                )
                self.assertIn("Add hello.txt", log)

    def test_forbidden_ip(self):
        # Request should be blocked by allowlist check BEFORE backend
        with ServerRunner(
            allow_ips=set(),  # deny all
            trace_log=None,
            project_root=self.tmp_root,
            backend_path=self.backend,
        ) as srvrun:

            conn = http.client.HTTPConnection("127.0.0.1", srvrun.port, timeout=5)
            try:
                conn.request("GET", "/git/repo.git/info/refs?service=git-receive-pack")
                resp = conn.getresponse()
                body = resp.read()
                self.assertEqual(resp.status, 403)
                self.assertIn(b"Forbidden", body)
            finally:
                conn.close()

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
