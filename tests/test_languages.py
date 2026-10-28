import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from pygithost import database
from pygithost.languages import language_totals, repository_languages


def entry(path, size, mode="100644", kind="blob"):
    return f"{mode} {kind} {'a' * 40} {size}\t{path}\0".encode()


class LanguageDetectionTests(unittest.TestCase):
    def test_source_sizes_group_extensions_and_exclude_dependencies(self):
        tree = b"".join([
            entry("src/Foo.cs", 300), entry("src/test.PY", 100),
            entry("src/Generated.Designer.cs", 10000), entry("node_modules/test.js", 10000),
            entry("packages/Package/test.cs", 10000), entry("bin/test.cs", 10000),
            entry("obj/test.cs", 10000), entry("static/assets/prismjs/prism.js", 10000),
            entry("main.min.js", 10000), entry("README.md", 10000),
            entry("image.png", 10000), entry("empty.py", 0),
            entry("link.py", 3000, mode="120000"), entry("submodule", "-", mode="160000", kind="commit"),
        ])
        result = language_totals(tree)
        self.assertEqual([item["name"] for item in result], ["C#", "Python"])
        self.assertEqual([item["percentage"] for item in result], [75, 25])
        self.assertEqual([item["files"] for item in result], [1, 1])

    def test_extensionless_files_and_unusual_paths(self):
        tree = entry("src/tab\tname\nfile.py", 100) + entry("Dockerfile", 50) + entry("Makefile", 50)
        result = language_totals(tree)
        self.assertEqual({item["name"] for item in result}, {"Python", "Dockerfile", "Makefile"})
        self.assertEqual(sum(item["percentage"] for item in result), 100)
        self.assertEqual(language_totals(b"invalid\0"), [])


@unittest.skipUnless(shutil.which("git"), "requires Git")
class LanguageCacheTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="languages-")
        self.root = Path(self.temp.name)
        self.old_db = database.DB_PATH
        database.DB_PATH = str(self.root / "db.sqlite")
        database._db_init()

    def tearDown(self):
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *map(str, args)], stderr=subprocess.PIPE, text=True).strip()

    async def test_cache_is_per_repository_and_commit_and_avoids_repeat_scans(self):
        source = self.root / "source"
        bare = self.root / "repo.git"
        self.git("init", "-b", "main", source)
        self.git("-C", source, "config", "user.name", "Test")
        self.git("-C", source, "config", "user.email", "test@example.test")
        (source / "main.py").write_text("print('hello')\n")
        self.git("-C", source, "add", ".")
        self.git("-C", source, "commit", "-m", "Python")
        self.git("clone", "--bare", source, bare)
        first = self.git("-C", source, "rev-parse", "HEAD")
        stats = await repository_languages("owner", "repo", str(bare), first)
        self.assertEqual(stats[0]["name"], "Python")
        with mock.patch("pygithost.languages.asyncio.create_subprocess_exec", side_effect=AssertionError("Cache must avoid Git")):
            self.assertEqual(await repository_languages("owner", "repo", str(bare), first), stats)
        self.assertIsNone(database.db_repository_languages_get("other", "repo", first))
        (source / "main.cs").write_text("class Example {}\n" * 10)
        self.git("-C", source, "add", ".")
        self.git("-C", source, "commit", "-m", "C sharp")
        self.git("--git-dir", bare, "fetch", source, "main")
        second = self.git("-C", source, "rev-parse", "HEAD")
        stats = await repository_languages("owner", "repo", str(bare), second)
        self.assertEqual(stats[0]["name"], "C#")
        self.assertEqual(len(stats), 2)
        self.assertIsNotNone(database.db_repository_languages_get("owner", "repo", first))

    async def test_empty_repository_and_failed_scan(self):
        self.assertEqual(await repository_languages("owner", "repo", "missing", None), [])
        self.assertIsNone(await repository_languages("owner", "repo", "missing", "a" * 40))
        self.assertIsNone(database.db_repository_languages_get("owner", "repo", "a" * 40))

    def test_cache_keeps_ten_recent_commits(self):
        for index in range(12):
            database.db_repository_languages_set("owner", "repo", str(index), json.dumps([]))
        self.assertIsNone(database.db_repository_languages_get("owner", "repo", "0"))
        self.assertEqual(database.db_repository_languages_get("owner", "repo", "11"), "[]")
