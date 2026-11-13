import asyncio
import io
import os
import shutil
import unittest
from unittest import mock
from urllib.parse import urlencode
import zipfile

from pygithost import database
from pygithost.api import browsing
from tests import test_api as read_tests
from tests.test_server import _which_git_backend


@unittest.skipUnless(shutil.which("git") and _which_git_backend(), "requires Git HTTP backend")
class APIBrowsingTests(unittest.TestCase):
    git = read_tests.APITests.git
    user = read_tests.APITests.user
    request = read_tests.APITests.request
    tearDown = read_tests.APITests.tearDown

    def setUp(self):
        read_tests.APITests.setUp(self)
        self.initial_commit = self.sha
        (self.source / "src").mkdir()
        (self.source / "src/a.txt").write_text("Needle literal.*\nsecond line\n")
        (self.source / "src/space name.txt").write_text("Needle with space\n")
        (self.source / "unicode-漢.txt").write_text("漢字 text\n", encoding="utf-8")
        (self.source / "binary.bin").write_bytes(b"\0Needle binary")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Browsing base")
        self.base_commit = self.git("-C", self.source, "rev-parse", "HEAD")
        self.git("-C", self.source, "checkout", "-b", "feature/browse")
        (self.source / "src/a.txt").write_text("Needle literal.*\nsecond line\nfeature content\n")
        (self.source / "new.txt").write_text("Needle feature\n")
        self.git("-C", self.source, "mv", "src/space name.txt", "moved name.txt")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Feature changes")
        self.head_commit = self.git("-C", self.source, "rev-parse", "HEAD")
        self.git("-C", self.source, "push", self.bare, "feature/browse")
        self.git("-C", self.source, "checkout", "main")
        (self.source / "target-only.txt").write_text("Only on target\n")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Target changes")
        self.target_commit = self.git("-C", self.source, "rev-parse", "HEAD")
        self.git("-C", self.source, "push", self.bare, "main")
        self.comparison = urlencode({"base": self.base_commit, "head": self.head_commit})
        self.browsing_pull = database.db_pr_create(
            "alice", "project", "Browsing PR", "", "feature/browse", "main", self.alice)

    def test_tree_lists_metadata_and_paginates_with_commit_header(self):
        status, headers, rows = self.request(self.base + "/tree")
        self.assertEqual(status, 200, rows)
        self.assertEqual(headers["X-Commit-SHA"], self.target_commit)
        entries = {row["path"]: row for row in rows}
        self.assertEqual(entries["src"]["type"], "tree")
        self.assertIsNone(entries["src"]["size"])
        self.assertEqual(entries["README.md"]["type"], "blob")
        self.assertEqual(entries["README.md"]["mode"], "100644")
        status, headers, rows = self.request(self.base + "/tree?per_page=1")
        self.assertEqual(status, 200)
        self.assertEqual(len(rows), 1)
        self.assertIn('rel="next"', headers["Link"])

    def test_nested_and_recursive_trees_preserve_unicode_paths(self):
        status, _headers, rows = self.request(self.base + "/tree?path=src")
        self.assertEqual(status, 200, rows)
        self.assertEqual({row["path"] for row in rows}, {"src/a.txt", "src/space name.txt"})
        rows = self.request(self.base + "/tree?recursive=true")[2]
        self.assertIn("src/a.txt", {row["path"] for row in rows})
        self.assertIn("unicode-漢.txt", {row["path"] for row in rows})
        rows = self.request(self.base + "/tree?ref=" + self.head_commit)[2]
        self.assertIn("new.txt", {row["path"] for row in rows})
        self.assertNotIn("target-only.txt", {row["path"] for row in rows})

    def test_tree_rejects_traversal_invalid_refs_and_non_directories(self):
        for query in ("path=../outside", "path=.git", "recursive=yes", "ref=--all", "ref=main~1"):
            with self.subTest(query=query):
                self.assertEqual(self.request(self.base + "/tree?" + query)[0], 400)
        for query in ("path=missing", "path=README.md"):
            self.assertEqual(self.request(self.base + "/tree?" + query)[0], 404)
        self.assertEqual(self.request("/api/v1/repos/alice/empty/tree")[0], 404)

    def test_search_is_literal_case_controlled_and_skips_binary_files(self):
        status, headers, rows = self.request(self.base + "/search?" + urlencode({"q": "Needle", "path": "src"}))
        self.assertEqual(status, 200, rows)
        self.assertEqual(len(rows), 2)
        self.assertEqual(headers["X-Commit-SHA"], self.target_commit)
        self.assertTrue(all(row["line_number"] == 1 for row in rows))
        self.assertEqual(self.request(self.base + "/search?q=needle")[2], [])
        rows = self.request(self.base + "/search?q=needle&ignore_case=true")[2]
        self.assertEqual({row["path"] for row in rows}, {"src/a.txt", "src/space name.txt"})
        self.assertEqual(len(self.request(self.base + "/search?" + urlencode({"q": ".*"}))[2]), 1)
        self.assertEqual(self.request(self.base + "/search?" + urlencode({"q": "^.*$"}))[2], [])
        unicode = self.request(self.base + "/search?" + urlencode({"q": "漢"}))[2]
        self.assertEqual(unicode[0]["path"], "unicode-漢.txt")

    def test_search_pagination_pinned_ref_and_invalid_queries(self):
        status, headers, rows = self.request(self.base + "/search?q=Needle&per_page=1")
        self.assertEqual(status, 200)
        self.assertEqual(len(rows), 1)
        self.assertIn('rel="next"', headers["Link"])
        rows = self.request(self.base + "/search?" + urlencode({"q": "feature", "ref": self.head_commit}))[2]
        self.assertEqual({row["path"] for row in rows}, {"new.txt", "src/a.txt"})
        for query in ("", "q=", "q=%0A", "q=x&path=../outside", "q=x&ignore_case=1"):
            with self.subTest(query=query):
                self.assertEqual(self.request(self.base + "/search?" + query)[0], 400)
        self.assertEqual(self.request(self.base + "/search?q=--help")[2], [])

    def test_compare_lists_changes_statistics_and_rename_as_add_delete(self):
        status, headers, rows = self.request(self.base + "/compare/files?" + self.comparison)
        self.assertEqual(status, 200, rows)
        self.assertEqual(headers["X-Base-SHA"], self.base_commit)
        entries = {row["path"]: row for row in rows}
        self.assertEqual(entries["src/a.txt"]["status"], "M")
        self.assertEqual(entries["src/a.txt"]["additions"], 1)
        self.assertEqual(entries["src/a.txt"]["deletions"], 0)
        self.assertEqual(entries["moved name.txt"]["status"], "A")
        self.assertEqual(entries["src/space name.txt"]["status"], "D")
        self.assertEqual(entries["new.txt"]["additions"], 1)
        self.assertEqual(len(self.request(self.base + "/compare/files?" + self.comparison + "&per_page=1")[2]), 1)

    def test_compare_patch_and_commit_diff_include_pinned_shas(self):
        status, _headers, result = self.request(self.base + "/compare/diff?" + self.comparison)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["base_sha"], self.base_commit)
        self.assertEqual(result["head_sha"], self.head_commit)
        self.assertIn("+feature content", result["patch"])
        view = self.request(self.base + "/commits/" + self.head_commit + "/diff")[2]
        self.assertEqual(view, result)
        self.assertEqual(self.request(self.base + "/commits/feature%2Fbrowse/diff")[2], result)
        self.assertEqual(self.request(self.base + "/compare/files?head=" + self.head_commit)[0], 400)

    def test_root_commit_files_and_patch_do_not_require_an_existing_parent(self):
        status, _headers, rows = self.request(self.base + "/commits/" + self.initial_commit + "/files")
        self.assertEqual(status, 200, rows)
        self.assertEqual(rows, [{"path": "README.md", "status": "A", "additions": 1, "deletions": 0}])
        view = self.request(self.base + "/commits/" + self.initial_commit + "/diff")[2]
        self.assertIsNone(view["base_sha"])
        self.assertIn("+API fixture", view["patch"])

    def test_pr_files_use_merge_base_and_commits_exclude_target_only_history(self):
        base = self.base + f"/pulls/{self.browsing_pull}"
        status, _headers, rows = self.request(base + "/files")
        self.assertEqual(status, 200, rows)
        self.assertNotIn("target-only.txt", {row["path"] for row in rows})
        result = self.request(base + "/diff")[2]
        self.assertEqual(result["base_sha"], self.base_commit)
        self.assertEqual(result["head_sha"], self.head_commit)
        self.assertNotIn("target-only", result["patch"])
        commits = self.request(base + "/commits")[2]
        self.assertEqual([row["sha"] for row in commits], [self.head_commit])
        direct = self.request(self.base + "/compare/files?" +
                              urlencode({"base": self.target_commit, "head": self.head_commit}))[2]
        self.assertIn("target-only.txt", {row["path"] for row in direct})

    def test_read_access_and_pr_ownership_are_enforced_on_every_view(self):
        for suffix in ("tree", "search?q=Needle", "compare/files?" + self.comparison, "archive",
                       f"pulls/{self.browsing_pull}/files", f"pulls/{self.browsing_pull}/commits"):
            with self.subTest(suffix=suffix):
                self.assertEqual(self.request(self.base + "/" + suffix, token=None)[0], 401)
                self.assertEqual(self.request(self.base + "/" + suffix, token=self.bob_token)[0], 404)
        for resource in ("files", "diff", "commits"):
            self.assertEqual(self.request(
                f"/api/v1/repos/bob/project/pulls/{self.browsing_pull}/{resource}",
                token=self.admin_token)[0], 404)

    def test_source_archive_is_original_zip_and_head_reports_same_size(self):
        path = self.base + "/archive?ref=" + self.head_commit
        status, headers, content = self.request(path, decode=False)
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/zip")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        prefix = "project-" + self.head_commit[:12] + "/"
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            self.assertIn(prefix + "new.txt", archive.namelist())
            self.assertNotIn(prefix + "target-only.txt", archive.namelist())
            self.assertEqual(archive.read(prefix + "src/a.txt"), b"Needle literal.*\nsecond line\nfeature content\n")
        status, head_headers, body = self.request(path, method="HEAD", decode=False)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertEqual(head_headers["Content-Length"], str(len(content)))
        self.assertIn(self.head_commit[:12], head_headers["Content-Disposition"])

    def test_source_archive_and_other_git_output_limits_return_json_errors(self):
        # A large incompressible member exercises kill/reap with buffered stdout,
        # not just a tiny ZIP that already exited before the size check.
        (self.source / "large.bin").write_bytes(os.urandom(2 * 1024 * 1024))
        self.git("-C", self.source, "add", "large.bin")
        self.git("-C", self.source, "commit", "-m", "Exercise bounded archive output")
        self.git("-C", self.source, "push", self.bare, "main")
        with mock.patch.object(browsing, "MAX_SOURCE_ARCHIVE_BYTES", 1):
            status, _headers, result = self.request(self.base + "/archive")
        self.assertEqual(status, 413, result)
        self.assertEqual(result["code"], "response_too_large")
        with mock.patch("pygithost.api.git.MAX_OUTPUT", 80):
            self.assertEqual(self.request(self.base + "/tree?recursive=true")[0], 413)
        async def verify_slots():
            slots = self.server.app.api_download_slots
            async with asyncio.timeout(2):
                await slots.acquire()
                try:
                    await slots.acquire()
                    slots.release()
                finally:
                    slots.release()
        asyncio.run_coroutine_threadsafe(verify_slots(), self.server.loop).result(timeout=5)

    def test_binary_diff_statistics_are_null_not_misleading_line_counts(self):
        (self.source / "binary.bin").write_bytes(b"\0Changed binary")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Binary change")
        commit = self.git("-C", self.source, "rev-parse", "HEAD")
        self.git("-C", self.source, "push", self.bare, "main")
        rows = self.request(self.base + "/compare/files?" +
                            urlencode({"base": self.target_commit, "head": commit}))[2]
        self.assertEqual(rows, [{"path": "binary.bin", "status": "M", "additions": None, "deletions": None}])

    def test_unrelated_pr_histories_return_conflict_not_internal_error(self):
        tree = self.git("-C", self.source, "rev-parse", "HEAD^{tree}")
        orphan = self.git("-C", self.source, "commit-tree", tree, "-m", "Unrelated root")
        self.git("-C", self.source, "update-ref", "refs/heads/unrelated", orphan)
        self.git("-C", self.source, "push", self.bare, "unrelated")
        identity = database.db_pr_create("alice", "project", "Unrelated", "", "unrelated", "main", self.alice)
        for view in ("files", "diff"):
            status, _headers, result = self.request(self.base + f"/pulls/{identity}/{view}")
            self.assertEqual(status, 409, result)
            self.assertEqual(result["code"], "unrelated_histories")

    @unittest.skipUnless(os.name == "posix", "symlinks")
    def test_tree_exposes_symlink_metadata_without_reading_host_target(self):
        secret = self.root / "host-file"
        secret.write_text("PRIVATE_HOST_CONTENT")
        (self.source / "link").symlink_to(secret)
        self.git("-C", self.source, "add", "link")
        self.git("-C", self.source, "commit", "-m", "Tracked symbolic link")
        self.git("-C", self.source, "push", self.bare, "main")
        rows = self.request(self.base + "/tree")[2]
        link = next(row for row in rows if row["path"] == "link")
        self.assertEqual(link["mode"], "120000")
        self.assertEqual(link["type"], "blob")
        self.assertEqual(self.request(self.base + "/tree?path=link")[0], 404)
        self.assertEqual(self.request(self.base + "/contents/link")[0], 422)
        self.assertEqual(self.request(self.base + "/search?q=PRIVATE_HOST_CONTENT")[2], [])

    def test_submodule_tree_entries_are_not_recursed_or_fetched(self):
        self.git("-C", self.source, "update-index", "--add", "--cacheinfo",
                 "160000," + self.initial_commit + ",vendor/module")
        self.git("-C", self.source, "commit", "-m", "Record gitlink without a checkout")
        self.git("-C", self.source, "push", self.bare, "main")
        rows = self.request(self.base + "/tree?recursive=true")[2]
        module = next(row for row in rows if row["path"] == "vendor/module")
        self.assertEqual(module["mode"], "160000")
        self.assertEqual(module["type"], "commit")
        self.assertIsNone(module["size"])
        self.assertFalse(any(row["path"].startswith("vendor/module/") for row in rows))

    def test_repository_color_settings_do_not_pollute_search_or_diff_metadata(self):
        self.git("--git-dir", self.bare, "config", "color.grep", "always")
        self.git("--git-dir", self.bare, "config", "color.diff", "always")
        rows = self.request(self.base + "/search?q=Needle")[2]
        self.assertEqual({row["path"] for row in rows}, {"src/a.txt", "src/space name.txt"})
        self.assertTrue(all("\x1b" not in row["text"] for row in rows))
        files = self.request(self.base + "/compare/files?" + self.comparison)[2]
        self.assertTrue(all(row["status"] in ("A", "D", "M") for row in files))
        self.assertNotIn("\x1b", self.request(self.base + "/compare/diff?" + self.comparison)[2]["patch"])

    def test_schema_and_in_page_documentation_cover_browsing_without_claiming_full_parity(self):
        schema = self.request("/api/v1/openapi.json")[2]
        base = "/repos/{owner}/{repo}"
        for tail in ("/tree", "/search", "/compare/files", "/compare/diff", "/archive",
                     "/commits/{ref}/files", "/commits/{ref}/diff", "/pulls/{id}/files",
                     "/pulls/{id}/diff", "/pulls/{id}/commits"):
            self.assertIn("get", schema["paths"][base + tail])
        self.assertIn("application/zip", schema["paths"][base + "/archive"]["get"]["responses"]["200"]["content"])
        self.assertNotIn("content", schema["paths"][base + "/archive"]["head"]["responses"]["200"])
        status, _headers, page = self.request("/api/docs", token=None, decode=False)
        self.assertEqual(status, 200)
        for anchor in ("repository-browsing-and-comparisons", "remaining-api-coverage-gaps"):
            self.assertIn(f'href="#{anchor}"'.encode(), page)
            self.assertIn(f'id="{anchor}"'.encode(), page)
        self.assertIn(b"Multi-file commits", page)
        self.assertIn(b"merge base", page)
        self.assertIn(b"tests.test_api_browsing tests.test_api_discussions", page)

    @unittest.skipUnless(os.name == "posix", "external diff script")
    def test_comparison_never_executes_configured_external_diff(self):
        marker = self.root / "diff-must-not-run"
        script = self.root / "external-diff"
        script.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\necho PRIVATE_DIFF_COMMAND\n")
        script.chmod(0o700)
        self.git("--git-dir", self.bare, "config", "diff.external", str(script))
        result = self.request(self.base + "/compare/diff?" + self.comparison)[2]
        self.assertIn("+feature content", result["patch"])
        self.assertNotIn("PRIVATE_DIFF_COMMAND", result["patch"])
        self.assertFalse(marker.exists())
