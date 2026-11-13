import asyncio
import base64
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from pygithost import application, database
from pygithost.api.errors import APIError
from pygithost.api.policy import RateLimiter
from pygithost.api.schema import specification
from tests.test_server import ServerRunner, _which_git_backend


@unittest.skipUnless(shutil.which("git") and _which_git_backend(), "requires Git HTTP backend")
class APITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="api-")
        self.root = Path(self.temp.name)
        self.old_db = database.DB_PATH
        self.source = self.root / "source"
        self.git("init", "-b", "main", self.source)
        self.git("-C", self.source, "config", "user.name", "API author")
        self.git("-C", self.source, "config", "user.email", "api@example.test")
        (self.source / "README.md").write_text("API fixture\n")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Initial API fixture", "-m", "Multiline\ncommit body")
        self.sha = self.git("-C", self.source, "rev-parse", "HEAD")
        for owner in ("alice", "bob"):
            (self.root / owner).mkdir()
            self.git("clone", "--bare", self.source, self.root / owner / "project.git")
        self.bare = self.root / "alice/project.git"
        self.git("--git-dir", self.bare, "branch", "feature/api", "main")
        self.git("clone", "--bare", self.source, self.root / "flat.git")
        self.git("init", "--bare", "-b", "main", self.root / "alice/empty.git")
        self.server = ServerRunner(project_root=str(self.root))
        self.server.__enter__()
        self.alice = self.user("alice")
        self.bob = self.user("bob")
        self.admin = self.user("operator", admin=True)
        self.token = database.db_create_token(self.alice, "test", "read")
        self.bob_token = database.db_create_token(self.bob, "test", "read")
        self.admin_token = database.db_create_token(self.admin, "test", "read")
        self.base = "/api/v1/repos/alice/project"
        self.issue = database.db_issue_create("alice", "project", "Issue one", "Body", self.alice)
        self.comment = database.db_issue_comment_add(self.issue, self.alice, "Comment one")
        self.pull = database.db_pr_create("alice", "project", "PR one", "PR body", "feature/api", "main", self.alice)
        database.db_pr_comment_add(self.pull, self.alice, "PR comment")
        self.run = database.db_ci_run_create("alice", "project", "manual", "main", self.sha,
            json.dumps({"pipeline_id": "checks", "secret_payload": "DO_NOT_EXPOSE"}),
            json.dumps({"env": {"SECRET": "DO_NOT_EXPOSE"}}))

    def tearDown(self):
        self.server.__exit__(None, None, None)
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *map(str, args)], stderr=subprocess.PIPE, text=True).strip()

    def user(self, name, admin=False):
        conn = database._db_connect()
        try:
            return conn.execute(
                "INSERT INTO users(username,pass_salt,pass_hash,is_admin) VALUES(?,?,?,?)",
                (name, b"test", b"test", int(admin))).lastrowid
        finally:
            conn.close()

    def request(self, path, *, method="GET", token=True, headers=None, body=None, decode=True):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=30)
        try:
            request_headers = {} if token is None else {
                "Authorization": "Bearer " + (self.token if token is True else token)}
            request_headers.update(headers or {})
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            content = response.read()
            return response.status, dict(response.getheaders()), json.loads(content) if decode and content else content
        finally:
            connection.close()

    def test_identity_and_bearer_required_even_when_web_auth_disabled(self):
        status, headers, value = self.request("/api/v1/user")
        self.assertEqual(status, 200)
        self.assertEqual(value, {"id": self.alice, "login": "alice", "is_admin": False, "scopes": ["read"]})
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        for path in ("/api/v1", "/api/v1/user", "/api/v1/openapi.json", self.base):
            with self.subTest(path=path):
                status, headers, value = self.request(path, token=None)
                self.assertEqual(status, 401)
                self.assertEqual(value["request_id"], headers["X-Request-ID"])
                self.assertIn("Bearer", headers["WWW-Authenticate"])
                self.assertNotIn("Location", headers)
        session = database.db_create_session(self.alice)
        basic = base64.b64encode(b"alice:password").decode()
        for header in ({"Cookie": application.SESSION_COOKIE_NAME + "=" + session},
                       {"Authorization": "Basic " + basic}, {"Authorization": "Bearer invalid"}):
            self.assertEqual(self.request("/api/v1/user", token=None, headers=header)[0], 401)
        self.assertEqual(self.request("/api/v1/user?token=" + self.token, token=None)[0], 401)

    def test_expired_revoked_disabled_and_insufficient_scope_tokens(self):
        conn = database._db_connect()
        try:
            for field, value in (("expires_at", "2000-01-01 00:00:00"), ("is_active", 0),
                                 ("revoked_at", "2020-01-01 00:00:00")):
                with self.subTest(field=field):
                    conn.execute(f"UPDATE tokens SET {field}=? WHERE user_id=?", (value, self.alice))
                    self.assertEqual(self.request("/api/v1/user")[0], 401)
                    conn.execute(f"UPDATE tokens SET {field}=? WHERE user_id=?",
                                 (1 if field == "is_active" else None, self.alice))
            conn.execute("UPDATE users SET is_active=0 WHERE id=?", (self.alice,))
            self.assertEqual(self.request("/api/v1/user")[0], 401)
            conn.execute("UPDATE users SET is_active=1 WHERE id=?", (self.alice,))
        finally:
            conn.close()
        admin_only = database.db_create_token(self.admin, "admin-only", "admin")
        self.assertEqual(self.request("/api/v1/user", token=admin_only)[0], 403)
        self.assertEqual(self.request("/api/v1/user", token=self.admin_token)[0], 200)

    def test_repository_access_is_scoped_and_admin_can_read_flat_layout(self):
        status, _headers, rows = self.request("/api/v1/repos")
        self.assertEqual(status, 200)
        self.assertEqual([r["full_name"] for r in rows], ["alice/empty", "alice/project"])
        self.assertEqual(self.request(self.base, token=self.bob_token)[0], 404)
        self.assertEqual(self.request("/api/v1/repos/bob/missing")[0], 404)
        self.assertEqual(self.request("/api/v1/repos/bob/project")[0], 404)
        flat = "/api/v1/repos/" + application.FLAT_OWNER_UI + "/flat"
        self.assertEqual(self.request(flat)[0], 404)
        self.assertEqual(self.request(flat, token=self.admin_token)[0], 200)
        value = self.request(self.base)[2]
        self.assertEqual(value["default_branch"], "main")
        self.assertNotIn(str(self.root), json.dumps(value))
        self.assertEqual(self.request("/api/v1/repos/%2e%2e/project", token=self.admin_token)[0], 404)
        self.assertEqual(self.request("/api/v1/repos/alice%2Fbob/project", token=self.admin_token)[0], 404)
        self.assertEqual(self.request("/api/v1/repos/alice/.", token=self.admin_token)[0], 404)
        self.assertEqual(self.request("/api/v1/repos/alice/.git", token=self.admin_token)[0], 404)
        self.assertEqual(self.request("/api/v1/repos/alice/project%0a", token=self.admin_token)[0], 404)

    @unittest.skipUnless(os.name == "posix", "symlinks")
    def test_repository_symlink_outside_root_is_hidden(self):
        with tempfile.TemporaryDirectory(prefix="api-external-") as external:
            target = Path(external) / "external.git"
            self.git("clone", "--bare", self.source, target)
            (self.root / "alice/external.git").symlink_to(target)
            self.assertEqual(self.request("/api/v1/repos/alice/external")[0], 404)
            self.assertNotIn("alice/external", [r["full_name"] for r in self.request("/api/v1/repos")[2]])
        (self.root / "alice/alias.git").symlink_to(self.root / "bob/project.git")
        self.assertEqual(self.request("/api/v1/repos/alice/alias")[0], 404)
        self.assertNotIn("alice/alias", [r["full_name"] for r in self.request("/api/v1/repos")[2]])

    def test_pagination_and_validation(self):
        status, headers, rows = self.request("/api/v1/repos?per_page=1")
        self.assertEqual(status, 200)
        self.assertEqual(len(rows), 1)
        self.assertIn('rel="next"', headers["Link"])
        self.assertEqual(headers["X-Page"], "1")
        status, headers, rows = self.request("/api/v1/repos?per_page=1&page=2")
        self.assertEqual(status, 200)
        self.assertEqual(rows[0]["name"], "project")
        self.assertIn('rel="prev"', headers["Link"])
        self.assertNotIn('rel="next"', headers["Link"])
        for query in ("page=0", "per_page=101", "page=abc", "page=1&page=2",
                      "unknown=1", "page=10000&per_page=100", "per_page=", "&".join("x=1" for _ in range(21))):
            with self.subTest(query=query):
                self.assertEqual(self.request("/api/v1/repos?" + query)[0], 400)
        self.assertEqual(self.request(self.base + "/issues?state=invalid")[0], 400)

    def test_branches_commits_and_empty_repositories(self):
        status, _headers, rows = self.request(self.base + "/branches")
        self.assertEqual(status, 200)
        self.assertEqual([r["name"] for r in rows], ["feature/api", "main"])
        status, _headers, row = self.request(self.base + "/branches/feature%2Fapi")
        self.assertEqual(status, 200)
        self.assertEqual(row["commit"]["sha"], self.sha)
        status, _headers, rows = self.request(self.base + "/commits?ref=feature%2Fapi")
        self.assertEqual(status, 200)
        self.assertEqual(rows[0]["sha"], self.sha)
        self.assertEqual(rows[0]["commit"]["message"], "Initial API fixture\n\nMultiline\ncommit body")
        self.assertTrue(rows[0]["commit"]["author"]["date"].endswith("Z"))
        self.assertEqual(self.request(self.base + "/commits/" + self.sha)[2], rows[0])
        self.assertEqual(self.request(self.base + "/commits?ref=--all")[0], 400)
        self.assertEqual(self.request(self.base + "/commits?ref=main~1")[0], 400)
        self.assertEqual(self.request(self.base + "/branches/missing")[0], 404)
        self.assertEqual(self.request(self.base + "/commits?ref=missing")[0], 404)
        for resource in ("branches", "commits"):
            status, _headers, rows = self.request("/api/v1/repos/alice/empty/" + resource)
            self.assertEqual(status, 200)
            self.assertEqual(rows, [])

    def test_issue_pull_and_comment_reads_are_repository_scoped(self):
        for resource, identity, title, comment in (
            ("issues", self.issue, "Issue one", "Comment one"),
            ("pulls", self.pull, "PR one", "PR comment"),
        ):
            with self.subTest(resource=resource):
                status, _headers, rows = self.request(self.base + "/" + resource)
                self.assertEqual(status, 200)
                self.assertEqual(rows[0]["title"], title)
                self.assertEqual(rows[0]["user"]["login"], "alice")
                self.assertTrue(rows[0]["created_at"].endswith("Z"))
                status, _headers, row = self.request(self.base + f"/{resource}/{identity}")
                self.assertEqual(status, 200)
                self.assertEqual(row, rows[0])
                status, _headers, comments = self.request(self.base + f"/{resource}/{identity}/comments")
                self.assertEqual(status, 200)
                self.assertEqual(comments[0]["body"], comment)
                wrong = f"/api/v1/repos/bob/project/{resource}/{identity}"
                self.assertEqual(self.request(wrong, token=self.bob_token)[0], 404)
                self.assertEqual(self.request(wrong + "/comments", token=self.bob_token)[0], 404)
        database.db_issue_close(self.issue)
        self.assertEqual(self.request(self.base + "/issues")[2], [])
        self.assertEqual(len(self.request(self.base + "/issues?state=closed")[2]), 1)

    def test_ci_summaries_do_not_expose_config_payload_or_logs(self):
        status, _headers, runs = self.request(self.base + "/ci/runs")
        self.assertEqual(status, 200)
        self.assertEqual(runs[0]["id"], self.run)
        self.assertEqual(runs[0]["pipeline"], "checks")
        self.assertEqual(self.request(self.base + f"/ci/runs/{self.run}")[2], runs[0])
        self.assertEqual(self.request(self.base + "/ci/runs?status=success")[2], [])
        self.assertEqual(self.request(self.base + "/ci/runs?branch=missing")[2], [])
        self.assertEqual(self.request(self.base + "/ci/runs?status=invalid")[0], 400)
        self.assertNotIn("DO_NOT_EXPOSE", json.dumps(runs))
        self.assertNotIn("config", runs[0])
        self.assertNotIn("output", runs[0])
        self.assertEqual(self.request(f"/api/v1/repos/bob/project/ci/runs/{self.run}", token=self.bob_token)[0], 404)
        status, _headers, pipelines = self.request(self.base + "/ci/pipelines")
        self.assertEqual(status, 200)
        self.assertEqual(pipelines[0]["repository_file"], "ci/config.json")
        self.assertNotIn("env", pipelines[0])

    def test_methods_head_errors_and_ip_allowlist(self):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                status, headers, value = self.request(self.base + "/issues", method=method, body="{}")
                self.assertEqual(status, 403)
                self.assertEqual(value["code"], "insufficient_scope")
        self.assertEqual(self.request(self.base, method="OPTIONS")[0], 405)
        status, headers, content = self.request("/api/v1/user", method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(content, b"")
        self.assertGreater(int(headers["Content-Length"]), 0)
        self.assertEqual(self.request(self.base, body="unexpected")[0], 400)
        self.assertEqual(self.request("/api/v2/user")[0], 404)
        self.assertEqual(self.request("/api/v1/user", headers={
            "Transfer-Encoding": "chunked"}, body="0\r\n\r\n")[0], 400)
        with mock.patch.object(self.server.app, "allowlist", set()):
            status, _headers, value = self.request("/api/v1/user")
            self.assertEqual(status, 403)
            self.assertEqual(value["code"], "forbidden")

    def test_duplicate_authorization_headers_are_rejected(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=10)
        try:
            connection.putrequest("GET", "/api/v1/user")
            connection.putheader("Authorization", "Bearer " + self.token)
            connection.putheader("Authorization", "Bearer " + self.admin_token)
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            self.assertEqual(json.loads(response.read())["code"], "unauthorized")
        finally:
            connection.close()

    def test_response_limits_and_timeouts_are_json_errors(self):
        with mock.patch("pygithost.api.git.MAX_OUTPUT", 5):
            status, headers, value = self.request(self.base + "/branches")
        self.assertEqual(status, 413)
        self.assertEqual(value["code"], "response_too_large")
        self.assertEqual(value["request_id"], headers["X-Request-ID"])
        with mock.patch("pygithost.api.git.branches", side_effect=TimeoutError):
            self.assertEqual(self.request(self.base + "/branches")[0], 504)
        with mock.patch("pygithost.api.router.MAX_RESPONSE", 300):
            status, _headers, value = self.request("/api/v1/openapi.json")
        self.assertEqual(status, 413)
        self.assertEqual(value["code"], "response_too_large")

    def test_rate_limit_and_internal_errors_are_safe(self):
        self.server.app.api_limiter.limit = 1
        self.assertEqual(self.request("/api/v1/user")[0], 200)
        status, headers, value = self.request("/api/v1/user")
        self.assertEqual(status, 429)
        self.assertGreater(int(headers["Retry-After"]), 0)
        self.server.app.api_limiter.limit = 120
        with mock.patch("pygithost.api.data.issues", side_effect=RuntimeError("SECRET_ERROR")):
            status, headers, value = self.request(self.base + "/issues")
        self.assertEqual(status, 500)
        self.assertNotIn("SECRET_ERROR", json.dumps(value))
        self.assertEqual(value["request_id"], headers["X-Request-ID"])

    def test_openapi_and_in_page_documentation(self):
        status, _headers, schema = self.request("/api/v1/openapi.json")
        self.assertEqual(status, 200)
        self.assertEqual(schema["openapi"], "3.1.0")
        self.assertEqual(schema["security"], [{"bearerAuth": []}])
        self.assertIn("/repos/{owner}/{repo}/ci/runs", schema["paths"])
        self.assertFalse(self.request("/api/v1/")[2]["read_only"])
        status, headers, page = self.request("/api/docs", token=None, decode=False)
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"Implemented endpoints", page)
        self.assertIn(b"Idempotency-Key", page)
        with mock.patch.object(application, "REQUIRE_AUTH", True):
            self.assertEqual(self.request("/api/v1/user")[0], 200)
        home = self.request("/", token=None, decode=False)[2]
        self.assertIn(b'href="/api/docs"', home)


class APIFoundationTests(unittest.TestCase):
    def test_rate_limiter_is_bounded_and_expires(self):
        limiter = RateLimiter(limit=1, window=60, max_keys=2)
        with mock.patch("pygithost.api.policy.time.monotonic", return_value=100):
            limiter.check("first")
            with self.assertRaises(APIError):
                limiter.check("first")
            limiter.check("second")
            limiter.check("third")
            self.assertEqual(len(limiter.windows), 2)
        with mock.patch("pygithost.api.policy.time.monotonic", return_value=161):
            limiter.check("third")

    def test_specification_has_unique_operation_ids(self):
        schema = specification()
        ids = []
        for methods in schema["paths"].values():
            self.assertTrue(set(methods) <= {"get", "head", "post", "put", "patch", "delete"})
            ids.extend(operation["operationId"] for operation in methods.values())
        self.assertEqual(len(ids), len(set(ids)))


class APIGitProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_git_read_kills_and_reaps_subprocess(self):
        from pygithost.api.git import git
        started = asyncio.Event()

        async def read(_size):
            started.set()
            await asyncio.Future()

        process = mock.Mock()
        process.returncode = None
        process.stdout.read = mock.AsyncMock(side_effect=read)
        process.wait = mock.AsyncMock(return_value=-9)
        process.communicate = mock.AsyncMock(return_value=(b"", b""))
        with mock.patch("pygithost.api.git.asyncio.create_subprocess_exec", mock.AsyncMock(return_value=process)):
            task = asyncio.create_task(git("/unused", "log"))
            await started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        process.kill.assert_called_once()
        process.communicate.assert_awaited_once()
