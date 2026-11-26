"""Regression tests for the security audit fixes (CSRF, traversal, limits, redirects)."""

import http.client
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

from pygithost import application, database
from pygithost.api.preflight import inspect
from pygithost.ci import render_command
from tests.test_server import ServerRunner, _which_git_backend, csrf_token, with_csrf


def git(*args):
    return subprocess.check_output(
        ["git", *map(str, args)], stderr=subprocess.PIPE, text=True
    ).strip()


class PureFunctionTests(unittest.TestCase):
    def test_next_url_rejects_off_site_targets(self):
        for value in (
            "//evil.example",
            "/\\evil.example",
            "/\t/evil.example",
            "/\n/evil.example",
            "https://evil.example",
            "/\x7f/evil.example",
        ):
            with self.subTest(value=value):
                self.assertEqual(application._safe_next_url(value), "/")
        self.assertEqual(application._safe_next_url("/r/root/x?tab=1"), "/r/root/x?tab=1")

    def test_git_paths_allow_only_plain_segments(self):
        safe = application._git_path_info_is_safe
        for value in ("/repo.git/info/refs", "/owner/repo/git-upload-pack", "/r.git/objects/ab/cd"):
            self.assertTrue(safe(value), value)
        for value in (
            "/a.git/..\\b.git/info/refs",
            "/a.git/../b.git/info/refs",
            "/a.git/./info/refs",
            "/C:/x.git/info/refs",
            "/a.git/%2e%2e/b.git",
            "/a.git/\x00/info/refs",
            "repo.git/info/refs",
        ):
            self.assertFalse(safe(value), value)

    def test_branch_placeholders_refuse_shell_syntax(self):
        env = {"PYGITHOST_BRANCH": "feature/x-1", "PYGITHOST_HEAD_BRANCH": "x;`id`", "N": "a;b"}
        self.assertEqual(render_command("echo {{ env.PYGITHOST_BRANCH }}", env), "echo feature/x-1")
        with self.assertRaisesRegex(ValueError, "unsafe in a shell command"):
            render_command("echo {{ env.PYGITHOST_HEAD_BRANCH }}", env)
        # Administrator-defined variables keep their existing (literal) behaviour.
        self.assertEqual(render_command("echo {{ env.N }}", env), "echo a;b")

    def test_preflight_never_touches_remote_or_untrusted_script_paths(self):
        with mock.patch("pathlib.Path.resolve", side_effect=AssertionError("touched")):
            for path in ("\\\\attacker\\share\\x.ps1", "//attacker/share/x.sh"):
                result = inspect({"deploy_script": path}, "/repo")
                names = {c["name"]: c["ok"] for c in result["checks"]}
                self.assertFalse(names["script_local"])
            result = inspect(
                {"deploy_script": "/etc/passwd", "_repository_config_error": "untrusted"}, "/repo"
            )
            self.assertFalse({c["name"]: c["ok"] for c in result["checks"]}["script_checked"])


@unittest.skipUnless(shutil.which("git") and _which_git_backend(), "requires Git HTTP backend")
class ServerAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="audit-")
        outer = Path(self.temp.name)
        self.root = outer / "repos"
        self.root.mkdir()
        self.old_db = database.DB_PATH
        source = outer / "source"
        git("init", "-q", "-b", "main", source)
        git(
            "-C",
            source,
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.test",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "init",
        )
        git("clone", "-q", "--bare", source, self.root / "project.git")
        # A repository next to (outside) the project root.
        self.secret = outer / "secret.git"
        git("clone", "-q", "--bare", source, self.secret)
        git("--git-dir", self.secret, "branch", "victim", "main")
        self.server = ServerRunner(project_root=str(self.root))
        self.server.__enter__()
        self.base = f"/r/{application.FLAT_OWNER_UI}/project"

    def tearDown(self):
        self.server.__exit__(None, None, None)
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def request(self, path, *, method="GET", body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=30)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode()
        finally:
            connection.close()

    def post(self, path, fields, *, token=True):
        fields = with_csrf(self.server, fields) if token else fields
        return self.request(
            path,
            method="POST",
            body=urlencode(fields),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def refs(self, git_dir):
        return git("--git-dir", git_dir, "for-each-ref", "--format=%(refname)")

    def test_post_without_or_with_wrong_token_is_rejected(self):
        for fields in ({}, {"csrf": "wrong"}):
            status, _, body = self.post(
                self.base + "/branches/create",
                {**fields, "new_branch": "nope", "from_ref": "main"},
                token=False,
            )
            self.assertEqual(status, 403)
            self.assertIn("form expired", body)
        self.assertNotIn("refs/heads/nope", self.refs(self.root / "project.git"))
        status, _, _ = self.post(
            self.base + "/branches/create", {"new_branch": "yes", "from_ref": "main"}
        )
        self.assertEqual(status, 200)
        self.assertIn("refs/heads/yes", self.refs(self.root / "project.git"))

    def test_pages_embed_the_token_in_every_post_form(self):
        _, _, page = self.request(self.base + "/branches")
        token = csrf_token(self.server)
        self.assertIn(f'<input type="hidden" name="csrf" value="{token}">', page)
        forms = page.count('method="POST"')
        self.assertGreater(forms, 0)
        self.assertGreaterEqual(page.count(f'value="{token}"'), forms)

    def test_csrf_secret_survives_restarts(self):
        first = self.server.app.settings_csrf_secret
        again = application.AsyncGitServer(self.server.app.context, allowlist={"127.0.0.1"})
        self.assertEqual(again.settings_csrf_secret, first)

    def test_repository_routes_cannot_escape_the_project_root(self):
        before = self.refs(self.secret)
        for action, fields in (
            ("delete", {"branch": "victim"}),
            ("create", {"new_branch": "planted", "from_ref": "main"}),
        ):
            status, _, _ = self.post(f"/r/%2e%2e/secret/branches/{action}", fields)
            self.assertEqual(status, 404)
        self.assertEqual(self.refs(self.secret), before)

    def test_option_like_from_ref_is_refused(self):
        status, _, body = self.post(
            self.base + "/branches/create", {"new_branch": "x", "from_ref": "--all"}
        )
        self.assertEqual(status, 200)
        self.assertIn("Could not resolve", body)

    def test_oversized_and_malformed_form_bodies(self):
        for path in ("/login", self.base + "/branches/create"):
            with self.subTest(path=path):
                connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=10)
                try:
                    connection.putrequest("POST", path)
                    connection.putheader("Content-Type", "application/x-www-form-urlencoded")
                    connection.putheader("Content-Length", str(64 * 1024 * 1024))
                    if getattr(self, "cookie", None):
                        connection.putheader("Cookie", self.cookie)
                    connection.endheaders()
                    self.assertEqual(connection.getresponse().status, 413)
                finally:
                    connection.close()
        status, _, _ = self.request(
            self.base + "/branches/create",
            method="POST",
            body="x=1",
            headers={"Content-Type": "application/x-www-form-urlencoded", "Content-Length": "3x"},
        )
        self.assertEqual(status, 400)

    def test_alias_of_a_repository_is_mapped_to_its_real_name_for_pushes(self):
        # Stand-in for NTFS case-insensitivity: another spelling of the same directory
        # that the repository scan never lists.
        (self.root / "sub").mkdir()
        alias = self.root / "sub" / ".." / "project.git"
        self.assertEqual(
            application._canonical_repo_for_git_dir(alias),
            (application.FLAT_OWNER_UI, "project"),
        )
        self.assertIsNone(application._canonical_repo_for_git_dir(self.secret))


@unittest.skipUnless(shutil.which("git") and _which_git_backend(), "requires Git HTTP backend")
class SignedInAuditTests(ServerAuditTests):
    def setUp(self):
        super().setUp()
        self.old_auth = application.REQUIRE_AUTH
        application.REQUIRE_AUTH = True
        database.db_create_user("tester", "s3cret-pass", True)
        user = database.db_get_user_by_username("tester")[0]
        self.session = database.db_create_session(user)
        self.cookie = application.SESSION_COOKIE_NAME + "=" + self.session

    def tearDown(self):
        application.REQUIRE_AUTH = self.old_auth
        super().tearDown()

    def request(self, path, *, method="GET", body=None, headers=None):
        return super().request(
            path, method=method, body=body, headers={"Cookie": self.cookie, **(headers or {})}
        )

    def post(self, path, fields, *, token=True):
        fields = with_csrf(self.server, fields, self.cookie) if token else fields
        return self.request(
            path,
            method="POST",
            body=urlencode(fields),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def test_pages_embed_the_token_in_every_post_form(self):
        _, _, page = self.request(self.base + "/branches")
        token = csrf_token(self.server, self.cookie)
        self.assertIn(f'<input type="hidden" name="csrf" value="{token}">', page)

    def test_logout_requires_post_with_token(self):
        status, _, page = self.request("/logout")
        self.assertEqual(status, 200)
        self.assertIn('action="/logout"', page)
        self.assertIsNotNone(database.db_verify_session(self.session))
        status, _, _ = self.post("/logout", {}, token=False)
        self.assertEqual(status, 403)
        self.assertIsNotNone(database.db_verify_session(self.session))
        status, headers, _ = self.post("/logout", {})
        self.assertEqual(status, 303)
        self.assertIn("loggedout=1", headers["Location"])
        self.assertIsNone(database.db_verify_session(self.session))

    def test_login_redirect_stays_on_site(self):
        body = urlencode(
            {"username": "tester", "password": "s3cret-pass", "next": "/\\evil.example"}
        )
        status, headers, _ = super().request(
            "/login",
            method="POST",
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual((status, headers["Location"]), (303, "/"))


@unittest.skipUnless(shutil.which("git") and _which_git_backend(), "requires Git HTTP backend")
class APIAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="audit-api-")
        self.root = Path(self.temp.name)
        self.old_db = database.DB_PATH
        (self.root / "alice").mkdir()
        for name in ("project", "other"):
            git("init", "-q", "--bare", "-b", "main", self.root / "alice" / f"{name}.git")
        self.server = ServerRunner(project_root=str(self.root))
        self.server.__enter__()
        conn = database._db_connect()
        try:
            self.alice = conn.execute(
                "INSERT INTO users(username,pass_salt,pass_hash,is_admin) VALUES('alice',?,?,0)",
                (b"x", b"x"),
            ).lastrowid
        finally:
            conn.close()

    def tearDown(self):
        self.server.__exit__(None, None, None)
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def mutate(self, path, document, token, key):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=30)
        try:
            connection.request(
                "POST",
                path,
                body=json.dumps(document),
                headers={
                    "Authorization": "Bearer " + token,
                    "Content-Type": "application/json",
                    "Idempotency-Key": key,
                },
            )
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_rejected_repository_creation_leaves_no_owner_directory(self):
        conn = database._db_connect()
        try:
            carol = conn.execute(
                "INSERT INTO users(username,pass_salt,pass_hash,is_admin) VALUES('carol',?,?,0)",
                (b"x", b"x"),
            ).lastrowid
        finally:
            conn.close()
        token = database.db_create_token(carol, "t", "read,write")
        status, _ = self.mutate(
            "/api/v1/user/repos", {"name": "x", "default_branch": "-x"}, token, "k1"
        )
        self.assertEqual(status, 422)
        self.assertFalse((self.root / "carol").exists())

    def test_bound_tokens_have_separate_idempotency_keys(self):
        first = database.db_create_token(self.alice, "a", "read,write", None, ("alice", "project"))
        second = database.db_create_token(self.alice, "b", "read,write", None, ("alice", "other"))
        for token, repo in ((first, "project"), (second, "other")):
            status, body = self.mutate(
                f"/api/v1/repos/alice/{repo}/issues", {"title": "Same key"}, token, "shared-key"
            )
            self.assertEqual(status, 201, body)


if __name__ == "__main__":
    unittest.main()
