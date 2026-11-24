"""End-to-end tests for the pure-Python git-http-backend fallback."""

import gzip
import http.client
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from pygithost import application
from pygithost.ci import validate_config
from pygithost.git_http_fallback import Backend, pkt_line
from tests.ci_fixtures import commit_legacy_config
from tests.git_http_backends import isolate_git_config, restore_git_config
from tests.test_server import ServerRunner, _which_git, _which_git_backend

MISSING_BACKEND = "/nonexistent/git-http-backend"


def _git(*args, cwd=None, env=None):
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True
    ).stdout


def _client_env():
    env = os.environ.copy()
    env.update(
        GIT_TERMINAL_PROMPT="0",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_AUTHOR_NAME="Test",
        GIT_AUTHOR_EMAIL="t@example.com",
        GIT_COMMITTER_NAME="Test",
        GIT_COMMITTER_EMAIL="t@example.com",
    )
    return env


class BackendSelectionTests(unittest.TestCase):
    def test_missing_executable_selects_python_fallback(self):
        with mock.patch.object(application, "GIT_HTTP_BACKEND", MISSING_BACKEND):
            command = application._git_backend_command()
        self.assertEqual(command[0], application.sys.executable)
        self.assertTrue(command[-1].endswith("git_http_fallback.py"))
        self.assertTrue(os.path.isfile(command[-1]))

    def test_builtin_keyword_forces_python_fallback(self):
        for value in ("builtin", "python", ""):
            with self.subTest(value=value):
                with mock.patch.object(application, "GIT_HTTP_BACKEND", value):
                    self.assertTrue(application._git_backend_uses_fallback())

    @unittest.skipUnless(_which_git_backend(), "git-http-backend not found")
    def test_existing_executable_is_preferred(self):
        backend = _which_git_backend()
        with mock.patch.object(application, "GIT_HTTP_BACKEND", backend):
            self.assertEqual(application._git_backend_command(), [backend])


@unittest.skipUnless(_which_git(), "git not found in PATH")
class FallbackCGITests(unittest.TestCase):
    """Drive the CGI program directly, without the HTTP server."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="git-fallback-cgi-")
        self.bare = os.path.join(self.root, "repo.git")
        _git("init", "--bare", "-b", "main", self.bare)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def cgi(self, method, path_info, query="", body=b"", **extra):
        env = {
            **os.environ,
            "GIT_PROJECT_ROOT": self.root,
            "GIT_HTTP_EXPORT_ALL": "1",
            "REQUEST_METHOD": method,
            "PATH_INFO": path_info,
            "QUERY_STRING": query,
            **extra,
        }
        out = io.BytesIO()
        Backend(env, io.BytesIO(body), out).run()
        head, _, payload = out.getvalue().partition(b"\r\n\r\n")
        headers = {}
        status = 200
        for line in head.decode("iso-8859-1").splitlines():
            name, _, value = line.partition(":")
            if name.lower() == "status":
                status = int(value.split()[0])
            else:
                headers[name.strip().lower()] = value.strip()
        return status, headers, payload

    def test_smart_info_refs_has_service_banner_and_no_cache(self):
        status, headers, body = self.cgi("GET", "/repo.git/info/refs", "service=git-upload-pack")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/x-git-upload-pack-advertisement")
        self.assertIn("no-cache", headers["cache-control"])
        self.assertTrue(body.startswith(pkt_line("# service=git-upload-pack\n") + b"0000"))

    def test_protocol_v2_omits_service_banner(self):
        status, _, body = self.cgi(
            "GET",
            "/repo.git/info/refs",
            "service=git-upload-pack",
            HTTP_GIT_PROTOCOL="version=2",
        )
        self.assertEqual(status, 200)
        self.assertNotIn(b"# service=", body)
        self.assertIn(b"version 2", body)

    def test_receive_pack_needs_config_or_remote_user(self):
        status, _, body = self.cgi("GET", "/repo.git/info/refs", "service=git-receive-pack")
        self.assertEqual(status, 403)
        self.assertIn(b"receive-pack", body)
        status, _, _ = self.cgi(
            "GET", "/repo.git/info/refs", "service=git-receive-pack", REMOTE_USER="alice"
        )
        self.assertEqual(status, 200)
        _git("--git-dir", self.bare, "config", "http.receivepack", "false")
        status, _, _ = self.cgi(
            "GET", "/repo.git/info/refs", "service=git-receive-pack", REMOTE_USER="alice"
        )
        self.assertEqual(status, 403)

    def test_upload_pack_can_be_disabled(self):
        _git("--git-dir", self.bare, "config", "http.uploadpack", "false")
        status, _, _ = self.cgi("GET", "/repo.git/info/refs", "service=git-upload-pack")
        self.assertEqual(status, 403)

    def test_rpc_rejects_wrong_content_type(self):
        status, _, _ = self.cgi(
            "POST", "/repo.git/git-upload-pack", CONTENT_TYPE="application/octet-stream"
        )
        self.assertEqual(status, 415)

    def test_wrong_method_and_unknown_paths(self):
        self.assertEqual(self.cgi("POST", "/repo.git/info/refs")[0], 405)
        self.assertEqual(self.cgi("GET", "/repo.git/git-upload-pack")[0], 405)
        self.assertEqual(self.cgi("GET", "/repo.git/config")[0], 404)
        self.assertEqual(self.cgi("GET", "/missing.git/HEAD")[0], 404)

    def test_path_traversal_is_rejected(self):
        outside = tempfile.mkdtemp(prefix="git-fallback-outside-")
        try:
            _git("init", "--bare", os.path.join(outside, "secret.git"))
            rel = os.path.relpath(os.path.join(outside, "secret.git"), self.root)
            self.assertEqual(self.cgi("GET", f"/{rel}/HEAD")[0], 404)
            self.assertEqual(self.cgi("GET", "/../repo.git/HEAD")[0], 404)
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_export_requires_flag_or_marker(self):
        env_root = {"GIT_HTTP_EXPORT_ALL": ""}
        self.assertEqual(self.cgi("GET", "/repo.git/HEAD", **env_root)[0], 404)
        open(os.path.join(self.bare, "git-daemon-export-ok"), "w").close()
        self.assertEqual(self.cgi("GET", "/repo.git/HEAD", **env_root)[0], 200)

    def test_dumb_routes_and_getanyfile(self):
        status, headers, body = self.cgi("GET", "/repo.git/HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ref: refs/heads/main\n")
        self.assertEqual(headers["content-type"], "text/plain")
        status, _, body = self.cgi("GET", "/repo.git/objects/info/packs")
        self.assertEqual((status, body), (200, b"\n"))
        _git("--git-dir", self.bare, "config", "http.getanyfile", "false")
        self.assertEqual(self.cgi("GET", "/repo.git/HEAD")[0], 403)

    def test_head_request_sends_no_body(self):
        status, headers, body = self.cgi("HEAD", "/repo.git/HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-length"], str(len("ref: refs/heads/main\n")))
        self.assertEqual(body, b"")


@unittest.skipUnless(_which_git(), "git not found in PATH")
class FallbackEndToEndTests(unittest.TestCase):
    """Real git clients against the server using only the Python backend."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="git-fallback-root-")
        self.client = tempfile.mkdtemp(prefix="git-fallback-client-")
        self.bare = os.path.join(self.root, "repo.git")
        _git("init", "--bare", "-b", "main", self.bare)
        _git("--git-dir", self.bare, "config", "http.receivepack", "true")
        self.env = _client_env()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.client, ignore_errors=True)

    def server(self):
        return ServerRunner(project_root=self.root, backend_path=MISSING_BACKEND)

    def push_commit(self, url, name="hello.txt", content="hello\n", branch="main"):
        work = os.path.join(self.client, "work")
        if not os.path.isdir(work):
            _git("clone", url, work, env=self.env)
        with open(os.path.join(work, name), "w", encoding="utf-8") as handle:
            handle.write(content)
        _git("-C", work, "add", name, env=self.env)
        _git("-C", work, "commit", "-m", f"Add {name}", env=self.env)
        _git("-C", work, "push", "origin", f"HEAD:refs/heads/{branch}", env=self.env)
        return work

    def test_clone_push_fetch_round_trip_with_protocol_v0_v1_v2(self):
        with self.server() as srvrun:
            url = f"http://127.0.0.1:{srvrun.port}/git/repo.git"
            self.push_commit(url)
            self.assertIn("Add hello.txt", _git("--git-dir", self.bare, "log", "--oneline"))
            for version in ("0", "1", "2"):
                with self.subTest(protocol=version):
                    target = os.path.join(self.client, f"clone-v{version}")
                    _git("-c", f"protocol.version={version}", "clone", url, target, env=self.env)
                    with open(os.path.join(target, "hello.txt"), encoding="utf-8") as handle:
                        self.assertEqual(handle.read(), "hello\n")

    def test_large_push_and_incremental_fetch(self):
        with self.server() as srvrun:
            url = f"http://127.0.0.1:{srvrun.port}/git/repo.git"
            # ~3 MB of incompressible data forces a multi-chunk, gzip-free push body.
            work = self.push_commit(url, "blob.bin", os.urandom(1_500_000).hex())
            mirror = os.path.join(self.client, "mirror")
            _git("clone", url, mirror, env=self.env)
            self.push_commit(url, "second.txt", "two\n")
            _git("-C", mirror, "pull", "--ff-only", env=self.env)
            self.assertTrue(os.path.isfile(os.path.join(mirror, "second.txt")))
            self.assertEqual(
                _git("-C", mirror, "rev-parse", "HEAD"), _git("-C", work, "rev-parse", "HEAD")
            )

    def test_gzip_encoded_upload_pack_request(self):
        # Many-ref negotiations make git gzip the request; send one explicitly too.
        with self.server() as srvrun:
            url = f"http://127.0.0.1:{srvrun.port}/git/repo.git"
            self.push_commit(url)
            head = _git("--git-dir", self.bare, "rev-parse", "main").strip()
            request = pkt_line(f"want {head} no-progress\n") + b"0000" + pkt_line("done\n")
            conn = http.client.HTTPConnection("127.0.0.1", srvrun.port, timeout=10)
            try:
                conn.request(
                    "POST",
                    "/git/repo.git/git-upload-pack",
                    body=gzip.compress(request),
                    headers={
                        "Content-Type": "application/x-git-upload-pack-request",
                        "Content-Encoding": "gzip",
                    },
                )
                response = conn.getresponse()
                body = response.read()
            finally:
                conn.close()
            self.assertEqual(response.status, 200)
            self.assertEqual(
                response.getheader("Content-Type"), "application/x-git-upload-pack-result"
            )
            self.assertIn(b"PACK", body)

    def test_dumb_http_clone(self):
        with self.server() as srvrun:
            url = f"http://127.0.0.1:{srvrun.port}/git/repo.git"
            self.push_commit(url)
            _git("--git-dir", self.bare, "repack", "-a", "-d")
            # GIT_SMART_HTTP=0 makes the client use the dumb protocol.
            env = {**self.env, "GIT_SMART_HTTP": "0"}
            target = os.path.join(self.client, "dumb")
            _git("clone", url, target, env=env)
            self.assertTrue(os.path.isfile(os.path.join(target, "hello.txt")))

    def test_protected_branch_hook_still_rejects_pushes(self):
        with self.server() as srvrun:
            url = f"http://127.0.0.1:{srvrun.port}/git/repo.git"
            work = self.push_commit(url)
            protected = commit_legacy_config(
                self.bare,
                validate_config({"block_direct_pushes": True, "protected_branches": "main"}),
            )
            _git("-C", work, "pull", "--ff-only", env=self.env)
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                self.push_commit(url, "blocked.txt", "no\n")
            self.assertIn("protected branch main", raised.exception.stderr)
            self.assertEqual(_git("--git-dir", self.bare, "rev-parse", "main").strip(), protected)
            # Other branches are still writable through the fallback.
            self.push_commit(url, "feature.txt", "ok\n", branch="feature")
            self.assertIn("feature", _git("--git-dir", self.bare, "branch"))

    @unittest.skipUnless(_which_git_backend(), "git-http-backend not found")
    def test_advertisement_matches_real_git_http_backend(self):
        with self.server() as srvrun:
            self.push_commit(f"http://127.0.0.1:{srvrun.port}/git/repo.git")
        bodies = []
        for backend in (MISSING_BACKEND, _which_git_backend()):
            with ServerRunner(project_root=self.root, backend_path=backend) as srvrun:
                conn = http.client.HTTPConnection("127.0.0.1", srvrun.port, timeout=10)
                try:
                    conn.request("GET", "/git/repo.git/info/refs?service=git-upload-pack")
                    response = conn.getresponse()
                    bodies.append(
                        (response.status, response.getheader("Content-Type"), response.read())
                    )
                finally:
                    conn.close()
        self.assertEqual(bodies[0], bodies[1])


def setUpModule() -> None:
    isolate_git_config()


def tearDownModule() -> None:
    restore_git_config()


if __name__ == "__main__":
    unittest.main()
