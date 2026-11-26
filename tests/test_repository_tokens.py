"""Personal access tokens bound to a single repository."""

import base64
import http.client
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from pygithost import application, database
from tests.test_server import ServerRunner, _which_git_backend, with_csrf


def git(*args):
    return subprocess.check_output(
        ["git", *map(str, args)], stderr=subprocess.PIPE, text=True
    ).strip()


@unittest.skipUnless(shutil.which("git") and _which_git_backend(), "requires Git HTTP backend")
class RepositoryTokenTests(unittest.TestCase):
    require_auth = True

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="repo-tokens-")
        self.root = Path(self.temp.name)
        self.old_db = database.DB_PATH
        source = self.root / "source"
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
        for owner in ("alice", "bob"):
            (self.root / owner).mkdir()
            git("clone", "-q", "--bare", source, self.root / owner / "project.git")
        git("clone", "-q", "--bare", source, self.root / "flat.git")
        git("clone", "-q", "--bare", source, self.root / "alice" / "other.git")
        shutil.rmtree(source)
        self.server = ServerRunner(project_root=str(self.root), require_auth=self.require_auth)
        self.server.__enter__()
        self.old_require_auth = application.REQUIRE_AUTH
        application.REQUIRE_AUTH = self.require_auth
        self.alice = self.user("alice")
        self.admin = self.user("operator", admin=True)

    def tearDown(self):
        application.REQUIRE_AUTH = self.old_require_auth
        self.server.__exit__(None, None, None)
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def user(self, name, admin=False):
        conn = database._db_connect()
        try:
            return conn.execute(
                "INSERT INTO users(username,pass_salt,pass_hash,is_admin) VALUES(?,?,?,?)",
                (name, b"test", b"test", int(admin)),
            ).lastrowid
        finally:
            conn.close()

    def request(self, path, *, method="GET", headers=None, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=30)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def api(self, path, token):
        status, body = self.request(path, headers={"Authorization": "Bearer " + token})
        return status, json.loads(body) if body else None

    def git_refs(self, path, token, service="git-upload-pack"):
        basic = base64.b64encode(f"token:{token}".encode()).decode()
        status, _ = self.request(
            f"/git/{path}/info/refs?service={service}",
            headers={"Authorization": "Basic " + basic},
        )
        return status

    # ---------------- database ----------------
    def test_token_records_and_reports_its_repository(self):
        token = database.db_create_token(self.alice, "ci", "read", None, ("alice", "project"))
        info = database.db_verify_token_any_user(token)
        self.assertEqual(info["repository"], ("alice", "project"))
        legacy = database.db_create_token(self.alice, "old", "read")
        self.assertIsNone(database.db_verify_token_any_user(legacy)["repository"])
        rows = {row[1]: row for row in database.db_list_tokens_for_user(self.alice)}
        self.assertEqual(rows["ci"][8:], ("alice", "project"))
        self.assertEqual(rows["old"][8:], (None, None))
        with self.assertRaises(ValueError):
            database.db_create_token(self.alice, "bad", "read", None, ("alice", " "))

    def test_archiving_a_repository_revokes_its_tokens(self):
        bound = database.db_create_token(self.alice, "ci", "read", None, ("alice", "project"))
        other = database.db_create_token(self.alice, "ci", "read", None, ("alice", "other"))
        counts = database.db_repository_archive(
            "alice", "project", str(self.root / "archive.sqlite3")
        )
        self.assertEqual(counts["tokens_revoked"], 1)
        self.assertIsNone(database.db_verify_token_any_user(bound))
        self.assertIsNotNone(database.db_verify_token_any_user(other))

    # ---------------- REST API ----------------
    def test_api_only_reaches_the_bound_repository(self):
        token = database.db_create_token(self.alice, "ci", "read", None, ("alice", "project"))
        status, user = self.api("/api/v1/user", token)
        self.assertEqual((status, user["repository"]), (200, "alice/project"))
        self.assertEqual(self.api("/api/v1/repos/alice/project", token)[0], 200)
        self.assertEqual(self.api("/api/v1/repos/alice/other", token)[0], 404)
        status, repos = self.api("/api/v1/repos", token)
        self.assertEqual([r["full_name"] for r in repos], ["alice/project"])

    def test_admin_token_bound_to_flat_repository_cannot_read_others(self):
        token = database.db_create_token(self.admin, "ci", "read", None, ("root", "flat"))
        self.assertEqual(self.api("/api/v1/repos/root/flat", token)[0], 200)
        self.assertEqual(self.api("/api/v1/repos/alice/project", token)[0], 404)
        status, repos = self.api("/api/v1/repos", token)
        self.assertEqual([r["full_name"] for r in repos], ["root/flat"])

    def test_bound_token_cannot_create_repositories(self):
        token = database.db_create_token(self.alice, "ci", "read,write", None, ("alice", "project"))
        status, body = self.request(
            "/api/v1/user/repos",
            method="POST",
            body=json.dumps({"name": "escaped"}),
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
                "Idempotency-Key": "create-escaped",
            },
        )
        self.assertEqual(status, 403, body)
        self.assertFalse((self.root / "alice" / "escaped.git").exists())

    def test_binding_does_not_widen_owner_namespace_rules(self):
        token = database.db_create_token(self.alice, "ci", "read", None, ("bob", "project"))
        self.assertEqual(self.api("/api/v1/repos/bob/project", token)[0], 404)

    # ---------------- Git over HTTP ----------------
    def test_git_only_serves_the_bound_repository(self):
        token = database.db_create_token(self.alice, "ci", "read", None, ("alice", "project"))
        self.assertEqual(self.git_refs("alice/project.git", token), 200)
        self.assertEqual(self.git_refs("alice/project", token), 200)
        for path in (
            "alice/other.git",
            "bob/project.git",
            "flat.git",
            "alice/project.git/../other.git",
            "alice/project.git/..\\other.git",
            "alice/project.git/..%5Cother.git",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.git_refs(path, token), 404)

    def test_bound_admin_token_needs_write_scope_to_push(self):
        reader = database.db_create_token(self.admin, "r", "read", None, ("root", "flat"))
        writer = database.db_create_token(self.admin, "w", "read,write", None, ("root", "flat"))
        self.assertEqual(self.git_refs("flat.git", reader, "git-receive-pack"), 403)
        self.assertEqual(self.git_refs("flat.git", writer, "git-receive-pack"), 200)

    def test_legacy_token_still_reaches_every_repository(self):
        token = database.db_create_token(self.alice, "old", "read")
        self.assertEqual(self.git_refs("alice/other.git", token), 200)
        self.assertEqual(self.git_refs("bob/project.git", token), 200)


class RepositoryTokenPageWithoutAuthTests(RepositoryTokenTests):
    """The Tokens page while web authentication is disabled (IP allowlist only)."""

    require_auth = False

    def create(self, **form):
        status, body = self.request(
            "/tokens/create",
            method="POST",
            body=urlencode(with_csrf(self.server, form)),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        return status, body.decode()

    def test_page_creates_tokens_owned_by_the_first_administrator(self):
        status, page = self.create(name="ci", scopes="read,write", repository="root/flat")
        self.assertEqual(status, 200)
        self.assertIn("Token created.", page)
        self.assertIn("/git/flat.git", page)
        token = re.search(r"<pre><code>([^<]+)</code></pre>", page)[1]
        info = database.db_verify_token_any_user(token)
        self.assertEqual((info["user_id"], info["repository"]), (self.admin, ("root", "flat")))
        status, listing = self.request("/tokens")
        self.assertIn("<code>root/flat</code>", listing.decode())

    def test_page_requires_an_existing_repository(self):
        for repository in ("", "root/missing", "alice"):
            with self.subTest(repository=repository):
                _, page = self.create(name="ci", scopes="read", repository=repository)
                self.assertIn("Choose a repository for the token.", page)

    def test_page_preselects_repository_from_query(self):
        _, page = self.request("/tokens?repo=alice/other")
        self.assertIn('<option value="alice/other" selected>', page.decode())

    # Git requests are not token-checked without authentication; the IP allowlist
    # is the boundary, so the Git/API binding tests above do not apply here.
    test_git_only_serves_the_bound_repository = None
    test_bound_admin_token_needs_write_scope_to_push = None
    test_legacy_token_still_reaches_every_repository = None


if __name__ == "__main__":
    unittest.main()
