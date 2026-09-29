import os
import socket
import asyncio
import threading
import http.client
import subprocess
import unittest
import tempfile
import shutil
import json
from contextlib import closing
from dataclasses import replace

# Import your server module
import server as srv
from pygithost import database


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
        require_auth=False,
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
        self.require_auth = require_auth

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
            require_auth=self.require_auth,
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

    def test_repo_page_displays_highlighted_root_readme_when_present(self):
        repo = os.path.join(self.tmp_root, "repo")
        self._git("init", "-b", "main", repo)
        with open(os.path.join(repo, "README.md"), "w", encoding="utf-8") as readme:
            readme.write("# Project\n\n<script>alert('unsafe')</script>\n")
        with open(os.path.join(repo, "source.txt"), "w", encoding="utf-8") as source:
            source.write("project source\n")
        self._git("-C", repo, "config", "user.name", "Test User")
        self._git("-C", repo, "config", "user.email", "test@example.com")
        self._git("-C", repo, "add", "README.md", "source.txt")
        self._git("-C", repo, "commit", "-m", "Add README")

        with ServerRunner(
            allow_ips={"127.0.0.1"},
            trace_log=None,
            project_root=self.tmp_root,
            backend_path=self.backend,
        ) as srvrun:
            conn = http.client.HTTPConnection("127.0.0.1", srvrun.port, timeout=5)
            try:
                conn.request("GET", "/r/root/repo")
                response = conn.getresponse()
                body = response.read().decode("utf-8")

                self.assertEqual(response.status, 200)
                self.assertIn('class="language-markdown"', body)
                self.assertIn("# Project", body)
                self.assertIn("prism-markdown.min.js", body)
                self.assertIn("&lt;script&gt;alert(&#x27;unsafe&#x27;)&lt;/script&gt;", body)
                self.assertNotIn("<script>alert('unsafe')</script>", body)
                self.assertIn('data-path="/git/repo.git"', body)
                self.assertIn('data-credentials=""', body)
                self.assertNotIn("USERNAME:PASSWORD", body)
                self.assertNotIn("TOKEN_VALUE", body)
                self.assertIn('href="/r/root/repo/blob/main/source.txt"', body)
                self.assertLess(body.index(">Files</h2>"), body.index(">README.md</h2>"))
            finally:
                conn.close()

    def test_repo_page_omits_missing_root_readme(self):
        repo = os.path.join(self.tmp_root, "repo")
        self._git("init", "-b", "main", repo)
        with open(os.path.join(repo, "file.txt"), "w", encoding="utf-8") as source:
            source.write("source\n")
        self._git("-C", repo, "config", "user.name", "Test User")
        self._git("-C", repo, "config", "user.email", "test@example.com")
        self._git("-C", repo, "add", "file.txt")
        self._git("-C", repo, "commit", "-m", "Add source")

        with ServerRunner(
            allow_ips={"127.0.0.1"},
            trace_log=None,
            project_root=self.tmp_root,
            backend_path=self.backend,
        ) as srvrun:
            conn = http.client.HTTPConnection("127.0.0.1", srvrun.port, timeout=5)
            try:
                conn.request("GET", "/r/root/repo")
                response = conn.getresponse()
                body = response.read().decode("utf-8")

                self.assertEqual(response.status, 200)
                self.assertNotIn('id="readmeSource"', body)
                self.assertNotIn("prism-markdown.min.js", body)
            finally:
                conn.close()

    def test_repo_page_shows_clone_formats_for_auth_config_and_custom_prefix(self):
        repo = os.path.join(self.tmp_root, "owner", "repo")
        self._git("init", "-b", "main", repo)
        with open(os.path.join(repo, "file.txt"), "w", encoding="utf-8") as source:
            source.write("source\n")
        self._git("-C", repo, "config", "user.name", "Test User")
        self._git("-C", repo, "config", "user.email", "test@example.com")
        self._git("-C", repo, "add", "file.txt")
        self._git("-C", repo, "commit", "-m", "Add source")

        with ServerRunner(
            allow_ips={"127.0.0.1"},
            url_prefix="/custom/git",
            trace_log=None,
            project_root=self.tmp_root,
            backend_path=self.backend,
            require_auth=True,
        ) as srvrun:
            database._db_init()
            conn = database._db_connect()
            try:
                cursor = conn.execute(
                    "INSERT INTO users(username, pass_salt, pass_hash) VALUES(?,?,?)",
                    ("clone-test", b"", b""),
                )
                user_id = cursor.lastrowid
            finally:
                conn.close()
            session = database.db_create_session(user_id)
            conn = http.client.HTTPConnection("127.0.0.1", srvrun.port, timeout=5)
            try:
                conn.request("GET", "/r/owner/repo", headers={"Cookie": f"pygithost_session={session}"})
                response = conn.getresponse()
                body = response.read().decode("utf-8")

                self.assertEqual(response.status, 200)
                self.assertIn('data-path="/custom/git/owner/repo.git"', body)
                self.assertIn('data-credentials="USERNAME:PASSWORD@"', body)
                self.assertIn('data-credentials="USERNAME:TOKEN@"', body)
                self.assertIn('data-credentials="token:TOKEN_VALUE@"', body)
                self.assertIn('data-credentials=""', body)
                self.assertIn('window.location.protocol + "//"', body)
                self.assertIn("window.location.host", body)
                self.assertNotIn("SECRET", body)
            finally:
                conn.close()

    def test_commits_page_loads_additional_commits_in_batches(self):
        repo = os.path.join(self.tmp_root, "repo")
        self._git("init", "-b", "main", repo)
        self._git("-C", repo, "config", "user.name", "Test User")
        self._git("-C", repo, "config", "user.email", "test@example.com")
        for index in range(51):
            self._git("-C", repo, "commit", "--allow-empty", "-m", f"Commit {index}")

        with ServerRunner(
            allow_ips={"127.0.0.1"},
            trace_log=None,
            project_root=self.tmp_root,
            backend_path=self.backend,
        ) as srvrun:
            conn = http.client.HTTPConnection("127.0.0.1", srvrun.port, timeout=5)
            try:
                conn.request("GET", "/r/root/repo/commits?ref=main")
                response = conn.getresponse()
                body = response.read().decode("utf-8")

                self.assertEqual(response.status, 200)
                self.assertIn('id="loadMoreCommits"', body)
                self.assertEqual(body.count("<tr>"), 50)

                conn.request("GET", "/r/root/repo/commits?ref=main&skip=50&partial=1")
                response = conn.getresponse()
                page = json.loads(response.read().decode("utf-8"))

                self.assertEqual(response.status, 200)
                self.assertEqual(len(page["commits"]), 1)
                self.assertEqual(page["commits"][0]["subject"], "Commit 0")
                self.assertFalse(page["has_more"])
                self.assertEqual(page["next_skip"], 51)
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
