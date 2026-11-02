import http.client
from pathlib import Path
import subprocess
import tempfile
import unittest
from urllib.parse import urlencode

from pygithost import database
from pygithost.application import FLAT_OWNER_UI
from tests.test_server import ServerRunner, _which_git_backend


class DiscussionsTests(unittest.TestCase):
    def setUp(self):
        if not (subprocess.run(["git", "--version"], capture_output=True).returncode == 0 and _which_git_backend()):
            self.skipTest("requires Git HTTP backend")
        self.temp = tempfile.TemporaryDirectory(prefix="discussions-")
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.bare = self.root / "project.git"
        self.old_db = database.DB_PATH
        self.git("init", "-b", "main", self.source)
        self.git("-C", self.source, "config", "user.name", "Discussant")
        self.git("-C", self.source, "config", "user.email", "d@example.test")
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

    def create_discussion(self, category="Q&A", title="How do I?", body="Steps **here**"):
        status, page = self.request(self.base + "/discussions/create",
                                    {"category": category, "title": title, "body": body})
        self.assertEqual(status, 303, page)
        discussion = database.db_discussion_list(FLAT_OWNER_UI, "project")[0]
        self.assertEqual(discussion[2], category)
        return discussion[0]

    def test_tabs_link_and_list_page(self):
        status, page = self.request(self.base)
        self.assertIn('href="' + self.base + "/discussions\"", page)
        status, page = self.request(self.base + "/discussions")
        self.assertEqual(status, 200, page)
        self.assertIn('id="discussions-tab-all"', page)
        self.assertIn('id="discussions-tab-Announcements"', page)
        self.assertIn("No discussions.", page)
        self.assertIn('href="' + self.base + '/discussions/new"', page)

    def test_create_list_categories_and_view(self):
        discussion_id = self.create_discussion("Q&A", "How do I deploy?", "Explain the pipeline")
        status, page = self.request(self.base + "/discussions?category=Q%26A")
        self.assertIn("How do I deploy?", page)
        status, page = self.request(self.base + "/discussions?category=Announcements")
        self.assertNotIn("How do I deploy?", page)
        status, page = self.request(self.base + f"/discussions/{discussion_id}")
        self.assertEqual(status, 200, page)
        self.assertIn('<span class="pill">Q&amp;A</span>', page)
        self.assertIn("Lock", page)
        self.assertIn("/static/vendor/tui-editor/toastui-editor-all.min.js", page)
        status, _ = self.request(self.base + "/discussions/new")
        self.assertEqual(status, 200)

    def test_replies_lock_and_answer_flow(self):
        discussion_id = self.create_discussion("Q&A", "How do tests work?", "unsure")
        status, page = self.request(self.base + f"/discussions/{discussion_id}/comments", {"body": "Run the suite"})
        self.assertIn("Run the suite", page)
        comment = database.db_discussion_comment_list(discussion_id)[0]
        cid = comment[0]
        status, _ = self.request(self.base + f"/discussions/{discussion_id}/comments", {"body": ""})
        self.assertIn("required", page)
        # Mark the answer, badge appears, row is stored on the discussion.
        status, page = self.request(self.base + f"/discussions/{discussion_id}/answer/{cid}", {})
        self.assertEqual(status, 200, page)
        self.assertIn("✓ Answer", page)
        self.assertEqual(database.db_discussion_get(discussion_id)[10], cid)
        # Deleting the answer clears the pointer.
        status, page = self.request(self.base + f"/discussions/{discussion_id}/unanswer/{cid}", {})
        self.assertEqual(database.db_discussion_get(discussion_id)[10], None)
        self.request(self.base + f"/discussions/{discussion_id}/answer/{cid}", {})
        # Locking disables replies but keeps management actions.
        status, page = self.request(self.base + f"/discussions/{discussion_id}/lock", {})
        self.assertEqual(status, 200, page)
        self.assertEqual(database.db_discussion_get(discussion_id)[8], 1)
        status, page = self.request(self.base + f"/discussions/{discussion_id}/comments", {"body": "nope"})
        self.assertIn("locked", page)
        self.assertEqual(database.db_discussion_comment_count(discussion_id), 1)
        status, page = self.request(self.base + f"/discussions/{discussion_id}/unlock", {})
        self.assertEqual(database.db_discussion_get(discussion_id)[8], 0)
        self.assertIn("Discussion unlocked.", page)
        # Answer on non-Q&A categories is refused.
        other = self.create_discussion("Ideas", "New feature", "idea")
        status, page = self.request(self.base + f"/discussions/{other}/comments", {"body": "comment"})
        ocid = database.db_discussion_comment_list(other)[0][0]
        status, page = self.request(self.base + f"/discussions/{other}/answer/{ocid}", {})
        self.assertIn("discussions can have a marked answer", page)

    def test_unknown_discussion_404_and_update(self):
        status, _ = self.request(self.base + "/discussions/999")
        self.assertEqual(status, 404)
        discussion_id = self.create_discussion("General", "Old title", "old")
        status, page = self.request(self.base + f"/discussions/{discussion_id}/update",
                                    {"category": "Announcements", "title": "New title", "body": "new body"})
        self.assertEqual(status, 200, page)
        row = database.db_discussion_get(discussion_id)
        self.assertEqual(row[3], "Announcements")
        self.assertEqual(row[4], "New title")
        self.assertIn("New title", page)
