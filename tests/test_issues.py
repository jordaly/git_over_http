import http.client
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from urllib.parse import urlencode

from pygithost import database
from pygithost.application import FLAT_OWNER_UI
from tests.test_server import ServerRunner, _which_git_backend


class IssuesTests(unittest.TestCase):
    def setUp(self):
        if not (subprocess.run(["git", "--version"], capture_output=True).returncode == 0 and _which_git_backend()):
            self.skipTest("requires Git HTTP backend")
        self.temp = tempfile.TemporaryDirectory(prefix="issues-")
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.bare = self.root / "project.git"
        self.old_db = database.DB_PATH
        self.git("init", "-b", "main", self.source)
        self.git("-C", self.source, "config", "user.name", "Reporter")
        self.git("-C", self.source, "config", "user.email", "r@example.test")
        (self.source / "app.py").write_text("print('hi')\n")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Initial")
        self.git("clone", "--bare", self.source, self.bare)
        self.server = ServerRunner(project_root=str(self.root))
        self.server.__enter__()
        self.base = f"/r/{FLAT_OWNER_UI}/project"

    def tearDown(self):
        self.server.__exit__(None, None, None)
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *map(str, args)], stderr=subprocess.PIPE, text=True).strip()

    def request(self, path, fields=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=10)
        try:
            connection.request("GET" if fields is None else "POST", path,
                body=None if fields is None else urlencode(fields),
                headers={} if fields is None else {"Content-Type": "application/x-www-form-urlencoded"})
            response = connection.getresponse()
            body = response.read()
            return response.status, body.decode()
        finally:
            connection.close()

    def create_issue(self, title="Broken link", body="**bold** detail"):
        status, page = self.request(self.base + "/issues/create", {"title": title, "body": body})
        self.assertEqual(status, 303, page)
        issue = database.db_issue_list(FLAT_OWNER_UI, "project")[0]
        self.assertEqual(issue[1], title)
        return issue[0]

    def test_repo_tabs_link_issues_and_list_page(self):
        status, page = self.request(self.base)
        self.assertIn('href="' + self.base + '/issues"', page)
        status, page = self.request(self.base + "/issues")
        self.assertEqual(status, 200, page)
        self.assertIn('id="issues-tab-open"', page)
        self.assertIn('id="issues-tab-closed"', page)
        self.assertIn("No issues.", page)
        self.assertIn('href="' + self.base + '/issues/new"', page)

    def test_create_list_and_view_issue(self):
        issue_id = self.create_issue("Broken link", "**bold** body")
        status, page = self.request(self.base + "/issues?status=open")
        self.assertEqual(status, 200, page)
        self.assertIn(f"Issue #{issue_id}: Broken link", page)
        self.assertIn("pill-open", page)
        status, page = self.request(self.base + f"/issues/{issue_id}")
        self.assertEqual(status, 200, page)
        # GitHub-style first-post block and the markdown body container.
        self.assertIn("issue-first-post", page)
        self.assertIn('class="pr-comment-body md-body"', page)
        self.assertIn("/static/vendor/tui-editor/toastui-editor-all.min.js", page)
        self.assertIn('data-markdown', page)
        self.assertIn("Close issue", page)
        self.assertIn('maxlength="1000000"', page)

    def test_close_reopen_and_tabs(self):
        issue_id = self.create_issue("Regression", "steps…")
        status, page = self.request(self.base + f"/issues/{issue_id}/close", {})
        self.assertEqual(status, 200, page)
        self.assertEqual(database.db_issue_get(issue_id)[7], "closed")
        self.assertIn("Issue closed.", page)
        status, page = self.request(self.base + "/issues?status=closed")
        self.assertIn(f"Issue #{issue_id}: Regression", page)
        status, page = self.request(self.base + "/issues?status=open")
        self.assertNotIn(f"Issue #{issue_id}: Regression", page)
        status, page = self.request(self.base + f"/issues/{issue_id}/reopen", {})
        self.assertEqual(status, 200, page)
        self.assertEqual(database.db_issue_get(issue_id)[7], "open")
        self.assertIn("Issue reopened.", page)

    def test_comments_add_counts_and_management(self):
        issue_id = self.create_issue("Title only", "")
        status, page = self.request(self.base + f"/issues/{issue_id}/comments", {"body": "First comment"})
        self.assertEqual(status, 200, page)
        self.assertIn("First comment", page)
        comments = database.db_issue_comment_list(issue_id)
        self.assertEqual(len(comments), 1)
        self.assertIsNone(comments[0][1])  # anonymous author preserved
        status, page = self.request(self.base + f"/issues/{issue_id}/comments", {"body": ""})
        self.assertIn("required", page)
        cid = comments[0][0]
        status, _ = self.request(self.base + f"/issues/{issue_id}/comments/{cid}/delete", {})
        self.assertEqual(status, 200)
        self.assertEqual(database.db_issue_comment_count(issue_id), 0)
        status, _ = self.request(self.base + "/issues/999/comments", {"body": "hi"})
        self.assertEqual(status, 404)

    def test_unknown_issue_404_and_new_issue_gates(self):
        status, _ = self.request(self.base + "/issues/999")
        self.assertEqual(status, 404)
        status, _ = self.request(self.base + "/issues/new")
        self.assertEqual(status, 200)  # anonymous fixture has write scope
        status, _ = self.request(self.base + "/issues/new?status=weird")
        self.assertEqual(status, 200)

    def test_markdown_body_wrapped_in_md_body(self):
        issue_id = self.create_issue("MD", "# Heading\n\n**bold**")
        status, page = self.request(self.base + f"/issues/{issue_id}")
        self.assertIn('class="pr-comment-body md-body"', page)
        self.assertIn('# Heading', page)  # raw markdown escaped server-side; rendered client-side

    def test_long_inline_image_comment_is_stored_intact(self):
        # Regression: bodies were clipped at 50,000 characters, cutting a
        # data-URL image in half. The viewer then showed raw base64 instead of
        # the image (the editor preview had looked fine before submitting).
        issue_id = self.create_issue("Image comment", "")
        data_url = "data:image/png;base64," + ("A" * 120000)
        body = "Before\n\n![logo](" + data_url + ")\n\nAfter"
        status, page = self.request(self.base + f"/issues/{issue_id}/comments", {"body": body})
        self.assertEqual(status, 200, page)
        stored = database.db_issue_comment_list(issue_id)[0][3]
        self.assertEqual(stored, body)
        self.assertIn("![logo](" + data_url + ")", page)

    def test_clip_markdown_never_splits_an_inline_image(self):
        from pygithost.application import MARKDOWN_BODY_LIMIT, _clip_markdown
        body = "x" * (MARKDOWN_BODY_LIMIT - 20) + "![logo](data:image/png;base64," + "A" * 100
        clipped = _clip_markdown(body)
        self.assertLessEqual(len(clipped), MARKDOWN_BODY_LIMIT)
        self.assertNotIn("data:image", clipped)
        self.assertNotIn("![logo]", clipped)
        self.assertTrue(clipped.startswith("x"))
        # A body under the cap is untouched.
        self.assertEqual(_clip_markdown("hello"), "hello")
