import http.client
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from unittest import mock
from urllib.parse import urlencode

from pygithost import database
from pygithost.application import FLAT_OWNER_UI
from tests.test_server import ServerRunner, _which_git_backend


@unittest.skipUnless(shutil.which("git") and _which_git_backend(), "requires Git HTTP backend")
class RepositoryUITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="repository-ui-")
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.bare = self.root / "project.git"
        self.old_db = database.DB_PATH
        self.git("init", "-b", "main", self.source)
        self.git("-C", self.source, "config", "user.name", "UI author")
        self.git("-C", self.source, "config", "user.email", "ui@example.test")
        (self.source / "README.md").write_text("Repository fixture\n")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Initial UI fixture")
        self.git("clone", "--bare", self.source, self.bare)
        self.sha = self.git("--git-dir", self.bare, "rev-parse", "main")
        for branch in ("feature/api", "release/1"):
            self.git("--git-dir", self.bare, "branch", branch, "main")
        self.server = ServerRunner(project_root=str(self.root))
        self.server.__enter__()
        self.base = f"/r/{FLAT_OWNER_UI}/project"
        database.db_ci_config_set(FLAT_OWNER_UI, "project", json.dumps({
            "block_direct_pushes": True, "protected_branches": "release/*"}))

    def tearDown(self):
        self.server.__exit__(None, None, None)
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *map(str, args)], stderr=subprocess.PIPE, text=True).strip()

    def request(self, path, fields=None, *, binary=False):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=10)
        try:
            connection.request("GET" if fields is None else "POST", path,
                body=None if fields is None else urlencode(fields),
                headers={} if fields is None else {"Content-Type": "application/x-www-form-urlencoded"})
            response = connection.getresponse()
            body = response.read()
            return response.status, body if binary else body.decode()
        finally:
            connection.close()

    def test_home_search_is_case_insensitive_and_has_empty_state(self):
        self.git("init", "--bare", self.root / "unrelated.git")
        status, page = self.request("/?q=PROJECT")
        self.assertEqual(status, 200)
        self.assertIn(self.base + '\">', page)
        self.assertNotIn(f'/r/{FLAT_OWNER_UI}/unrelated', page)
        self.assertIn("Clear search", page)
        status, page = self.request("/?q=" + FLAT_OWNER_UI)
        self.assertEqual(status, 200)
        self.assertIn("unrelated", page)
        _, page = self.request("/?q=does-not-exist")
        self.assertIn("No matching repositories", page)
        _, page = self.request("/?" + urlencode({"q": '\"><script>alert(1)</script>'}))
        self.assertNotIn("<script>alert(1)</script>", page)

    def test_branches_show_metadata_filters_and_safe_actions(self):
        status, page = self.request(self.base + "/branches")
        self.assertEqual(status, 200)
        self.assertIn('aria-current="page">Branches', page)
        self.assertIn("Default branch", page)
        self.assertIn("Initial UI fixture", page)
        self.assertIn("UI author", page)
        self.assertIn('name="branch" value="feature/api"', page)
        self.assertNotIn('name="branch" value="release/1"', page)
        self.assertNotIn('name="branch" value="main"', page)
        self.assertIn('onsubmit="return confirm(', page)
        self.assertIn("source=feature%2Fapi", page)
        _, page = self.request(self.base + "/branches?q=FEATURE&sort=name")
        articles = page.split('<article class="repo-branch-row">')[1:]
        self.assertEqual(len(articles), 1)
        self.assertIn("feature/api", articles[0])
        _, page = self.request(self.base + "/branches?view=protected")
        articles = page.split('<article class="repo-branch-row">')[1:]
        self.assertEqual(len(articles), 1)
        self.assertIn("release/1", articles[0])
        _, page = self.request(self.base + "/branches?q=missing")
        self.assertIn("No matching branches", page)
        with mock.patch("pygithost.application._has_write_scope", return_value=False):
            _, page = self.request(self.base + "/branches")
        self.assertNotIn('action="' + self.base + '/branches/delete"', page)
        self.assertNotIn('action="' + self.base + '/branches/create"', page)

    def test_branch_to_pr_prefills_source_and_target(self):
        status, page = self.request(self.base + "/pulls?source=feature%2Fapi&target=main")
        self.assertEqual(status, 200)
        self.assertIn('id="new-pull-request"', page)
        self.assertIn('<option value="feature/api" selected>', page)
        self.assertIn('aria-current="page">Pull requests', page)

    def test_delete_rejects_changed_protected_and_default_branches(self):
        self.git("-C", self.source, "commit", "--allow-empty", "-m", "New branch work")
        new_sha = self.git("-C", self.source, "rev-parse", "HEAD")
        self.git("--git-dir", self.bare, "fetch", self.source, "main:refs/heads/feature/api")
        _, page = self.request(self.base + "/branches/delete", {"branch": "feature/api", "expected_commit": self.sha})
        self.assertIn("Branch changed", page)
        self.assertEqual(self.git("--git-dir", self.bare, "rev-parse", "feature/api"), new_sha)
        _, page = self.request(self.base + "/branches/delete", {"branch": "release/1", "expected_commit": self.sha})
        self.assertIn("Protected branches cannot be deleted", page)
        _, page = self.request(self.base + "/branches/delete", {"branch": "main", "expected_commit": self.sha})
        self.assertIn("Default branch is protected", page)
        _, page = self.request(self.base + "/branches/delete", {"branch": "feature/api", "expected_commit": new_sha})
        self.assertIn("Branch deleted", page)

    def test_repository_navigation_available_on_code_views(self):
        for path in ("", "/commits?ref=main", "/tree/main/", "/blob/main/README.md", "/commit/" + self.sha):
            with self.subTest(path=path):
                status, page = self.request(self.base + path)
                self.assertEqual(status, 200)
                self.assertIn('aria-label="Repository navigation"', page)
                self.assertIn('aria-current="page">Code', page)

    def test_repository_header_is_identical_and_precedes_tab_content(self):
        headers = []
        for path in ("", "/branches", "/pulls", "/ci", "/ci/config", "/ci/docs", "/artifacts",
                     "/commits?ref=main", "/tree/main/", "/blob/main/README.md"):
            with self.subTest(path=path):
                status, page = self.request(self.base + path)
                self.assertEqual(status, 200)
                header = page.split('<header class="repo-header">', 1)[1].split("</header>", 1)[0]
                headers.append(header)
                main = page.split('<main class="', 1)[1].split(">", 1)[1]
                self.assertTrue(main.startswith('<div class="repo-navigation">') or
                                main.startswith('<div class="repo-ci-navigation">'))
                self.assertLess(page.index('<header class="repo-header">'),
                                page.index('aria-label="Repository navigation"'))
        self.assertTrue(all(header == headers[0] for header in headers))

    def test_code_dropdown_uses_current_ref_and_no_redundant_all_repos_button(self):
        for path, ref in (("", "main"), ("/tree/feature%2Fapi/", "feature%2Fapi"),
                          ("/commit/" + self.sha, self.sha), ("/blob/main/README.md", "main")):
            with self.subTest(path=path):
                status, page = self.request(self.base + path)
                self.assertEqual(status, 200)
                self.assertIn('class="repo-code-menu"', page)
                self.assertIn(f'/archive.zip?ref={ref}', page)
                self.assertIn('aria-label="Repository clone URL"', page)
                self.assertIn('data-path="/git/project.git"', page)
                self.assertNotIn("All repos</a>", page)
                self.assertNotIn("USERNAME:PASSWORD@", page)

    def test_source_zip_exports_exact_branch_or_commit_without_git_history(self):
        (self.source / "new.txt").write_text("New branch file")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Feature snapshot")
        new_sha = self.git("-C", self.source, "rev-parse", "HEAD")
        self.git("--git-dir", self.bare, "fetch", self.source, "main:refs/heads/feature/api")
        for ref, sha, has_new in (("main", self.sha, False), ("feature/api", new_sha, True),
                                  (self.sha, self.sha, False)):
            with self.subTest(ref=ref):
                status, archive = self.request(self.base + "/archive.zip?" + urlencode({"ref": ref}), binary=True)
                self.assertEqual(status, 200)
                with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
                    prefix = f"project-{sha[:8]}/"
                    self.assertEqual(zipped.read(prefix + "README.md"), b"Repository fixture\n")
                    self.assertEqual(prefix + "new.txt" in zipped.namelist(), has_new)
                    self.assertFalse(any(".git" in name.split("/") for name in zipped.namelist()))
        for ref in ("", "--help", "bad\r\nref"):
            status, _ = self.request(self.base + "/archive.zip?" + urlencode({"ref": ref}))
            self.assertEqual(status, 400)
        status, _ = self.request(self.base + "/archive.zip?ref=missing")
        self.assertEqual(status, 404)
