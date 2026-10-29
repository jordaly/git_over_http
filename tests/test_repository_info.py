import asyncio
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from pygithost import database
from pygithost.readme import render_readme
from pygithost.repository_info import repository_overview


class ReadmeTests(unittest.TestCase):
    def test_readme_formats_common_markdown_without_executing_html(self):
        rendered = str(render_readme('# Project\n\nA **small** `server`.\n\n- One\n- Two\n\n```python\nprint("hello")\n```\n\n<script>bad()</script>'))
        self.assertIn("<h2>Project</h2>", rendered)
        self.assertIn("<strong>small</strong>", rendered)
        self.assertIn("<code>server</code>", rendered)
        self.assertIn("<ul><li>One</li><li>Two</li></ul>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn("<script>", rendered)

    def test_readme_rejects_unsafe_and_malformed_link_targets(self):
        rendered = str(render_readme('[Unsafe](javascript:alert) [Broken](http://[bad) [Safe](https://example.test)'))
        self.assertNotIn('href="javascript:', rendered)
        self.assertNotIn('href="http://[bad', rendered)
        self.assertIn('href="https://example.test"', rendered)


@unittest.skipUnless(shutil.which("git"), "requires Git")
class RepositoryOverviewTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="repo-overview-")
        self.root = Path(self.temp.name)
        self.old_db = database.DB_PATH
        database.DB_PATH = str(self.root / "test.db")
        database._db_init()

    def tearDown(self):
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *map(str, args)], stderr=subprocess.PIPE, text=True).strip()

    async def test_file_and_folder_history_is_correct_and_cached_per_commit(self):
        source = self.root / "source"
        self.git("init", "-b", "main", source)
        self.git("-C", source, "config", "user.name", "Alice")
        self.git("-C", source, "config", "user.email", "alice@example.test")
        (source / "src").mkdir()
        (source / "src" / "example.py").write_text("print('hello')\n")
        (source / "README.md").write_text("Initial documentation")
        self.git("-C", source, "add", ".")
        self.git("-C", source, "commit", "-m", "Initial source")
        (source / "README.md").write_text("Updated documentation")
        self.git("-C", source, "add", ".")
        self.git("-C", source, "-c", "user.name=Bob", "-c", "user.email=bob@example.test", "commit", "-m", "Readme edit")
        sha = self.git("-C", source, "rev-parse", "HEAD")
        bare = self.root / "repo.git"
        self.git("clone", "--bare", source, bare)
        entries = [("tree", "src"), ("blob", "README.md")]
        result = await repository_overview("owner", "repo", str(bare), sha, entries)
        self.assertEqual(result["latest"]["subject"], "Readme edit")
        self.assertEqual(result["latest"]["author"], "Bob")
        self.assertEqual(result["entries"]["src"]["subject"], "Initial source")
        self.assertEqual(result["entries"]["README.md"]["subject"], "Readme edit")
        self.assertEqual(result["commit_count"], 2)
        nested = await repository_overview("owner", "repo", str(bare), sha,
                                           [("blob", "example.py")], subpath="src")
        self.assertEqual(nested["entries"]["example.py"]["subject"], "Initial source")
        self.assertEqual(nested["latest"]["subject"], "Initial source")
        self.assertEqual({item["name"] for item in result["contributors"]}, {"Alice", "Bob"})
        with mock.patch.object(asyncio, "create_subprocess_exec", side_effect=AssertionError("Expected cached metadata")):
            self.assertEqual(await repository_overview("owner", "repo", str(bare), sha, entries), result)
            self.assertEqual(await repository_overview("owner", "repo", str(bare), sha,
                [("blob", "example.py")], subpath="src"), nested)
        self.assertIsNone(database.db_repository_overview_get("other", "repo", sha))
        self.assertEqual((await repository_overview("owner", "empty", str(bare), None, []))["commit_count"], 0)
