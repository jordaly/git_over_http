import asyncio
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

from pygithost import application, database
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

    def fixture_user(self):
        conn = database._db_connect()
        try:
            return conn.execute("INSERT INTO users(username,pass_salt,pass_hash) VALUES('pagination-user',?,?)", (b"salt", b"unused-test-hash")).lastrowid
        finally:
            conn.close()

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

    def test_home_filesystem_scan_does_not_block_the_request_loop(self):
        def scan(_root):
            with self.assertRaises(RuntimeError):
                asyncio.get_running_loop()
            return [(FLAT_OWNER_UI, "project", "project.git")]
        with mock.patch("pygithost.application._scan_repos", side_effect=scan):
            status, page = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(self.base, page)

    def test_repository_page_reads_independent_metadata_concurrently(self):
        original = application._run_git
        active, peak = 0, 0
        async def tracked(*args, **kwargs):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            try:
                await asyncio.sleep(0.01)
                return await original(*args, **kwargs)
            finally:
                active -= 1
        with mock.patch("pygithost.application._run_git", side_effect=tracked):
            status, page = self.request(self.base)
        self.assertEqual(status, 200)
        self.assertIn("README.md", page)
        self.assertIn("Last commit message", page)
        self.assertGreaterEqual(peak, 3)

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

    def test_home_pagination_preserves_search(self):
        repos = [("owner", f"app-{index:02}", f"app-{index:02}.git") for index in range(30)]
        with mock.patch("pygithost.application._scan_repos", return_value=repos):
            status, first = self.request("/?q=app")
            self.assertEqual(status, 200)
            self.assertIn("Page 1", first)
            self.assertIn('rel="next"', first)
            self.assertNotIn('href="/r/owner/app-25"', first)
            _, second = self.request("/?q=app&page=2")
            self.assertIn("Page 2", second)
            self.assertIn('href="/r/owner/app-25"', second)
            self.assertIn('href="/?q=app&amp;page=1&amp;per_page=25"', second)
            self.assertNotIn('rel="next"', second)

    def test_first_last_and_page_size_work_across_lists(self):
        repos = [("owner", f"app-{index:02}", f"app-{index:02}.git") for index in range(35)]
        with mock.patch("pygithost.application._scan_repos", return_value=repos):
            _, first = self.request("/?q=app&per_page=10")
            self.assertIn('aria-label="Go to last page"', first)
            self.assertIn("page=4&amp;per_page=10", first)
            self.assertIn("Showing 1–10 of 35", first)
            _, last = self.request("/?q=app&per_page=10&page=4")
            self.assertIn('href="/r/owner/app-34"', last)
            self.assertIn("Showing 31–35 of 35", last)
            self.assertIn('aria-label="Go to first page"', last)
            self.assertNotIn('aria-label="Go to last page"', last)
        database.db_ci_config_set(FLAT_OWNER_UI, "project", json.dumps({"run_retention_count": 0}))
        for index in range(35):
            commit = f"{index:040x}"
            run_id = database.db_ci_run_create(FLAT_OWNER_UI, "project", "push", "main", commit, "{}")
            database.db_ci_run_update(run_id, status="success")
            database.db_deployment_claim(run_id, FLAT_OWNER_UI, "project", commit)
            database.db_deployment_finish(run_id, "success", "")
        for suffix in ("/ci?status=success", "/ci/deployments?"):
            _, first = self.request(self.base + suffix + "&per_page=10")
            _, last = self.request(self.base + suffix + "&per_page=10&page=4")
            self.assertIn("page=4&amp;per_page=10", first)
            self.assertIn("Showing 31–35 of 35", last)
            self.assertIn('aria-label="Go to first page"', last)

    def test_tokens_and_users_tables_are_paginated(self):
        tokens = [(index, f"token-{index:02}", "read", True, "2026-01-01", None, None, "active") for index in range(30)]
        with mock.patch("pygithost.application.db_list_tokens_for_user", return_value=tokens):
            _, first = self.request("/tokens")
            _, second = self.request("/tokens?page=2")
        self.assertIn("token-00", first)
        self.assertNotIn("token-25", first)
        self.assertIn("token-25", second)
        self.assertNotIn("token-00", second)
        self.assertIn('rel="prev"', second)
        users = [(index, f"person-{index:02}", False, True, "2026-01-01") for index in range(30)]
        with mock.patch("pygithost.application._require_admin", return_value=True), mock.patch("pygithost.application.db_list_users", return_value=users):
            _, page = self.request("/admin/users?page=2")
        table = page.split("All users</h2><table>", 1)[1].split("</table>", 1)[0]
        self.assertIn("person-25", table)
        self.assertNotIn("person-00", table)
        self.assertIn('value="0">person-00</option>', page)  # Reset form still covers all users.

    def test_root_and_tree_show_all_files_while_commit_files_remain_paginated(self):
        (self.source / "src").mkdir()
        for index in range(30):
            (self.source / f"file-{index:02}.txt").write_text("root")
            (self.source / "src" / f"nested-{index:02}.txt").write_text("nested")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Many files")
        sha = self.git("-C", self.source, "rev-parse", "HEAD")
        self.git("-C", self.source, "push", self.bare, "main")
        for suffix, first_name, last_name in [
            ("", "file-00.txt", "file-29.txt"),
            ("/tree/main/src/", "nested-00.txt", "nested-29.txt"),
        ]:
            _, first = self.request(self.base + suffix)
            _, second = self.request(self.base + suffix + "?page=2")
            table = first.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
            self.assertIn(first_name, table)
            self.assertIn(last_name, table)
            self.assertNotIn('aria-label="Pagination"', first)
            table = second.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
            self.assertIn(last_name, table)
            self.assertIn(first_name, table)
            self.assertIn("Many files", table)
            self.assertNotIn('aria-label="Pagination"', second)
        _, first = self.request(self.base + "/commit/" + sha)
        _, second = self.request(self.base + "/commit/" + sha + "?page=2")
        self.assertIn('rel="next"', first)
        self.assertIn('rel="prev"', second)
        _, expanded = self.request(self.base + "?per_page=100")
        table = expanded.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
        self.assertIn("file-00.txt", table)
        self.assertIn("file-29.txt", table)
        self.assertEqual(table.count('class="repo-entry-message"><a'), 32)

    def test_pull_requests_and_artifacts_are_paginated(self):
        database.db_ci_config_set(FLAT_OWNER_UI, "project", json.dumps({"run_retention_count": 0, "artifact_retention_days": 0}))
        user_id = self.fixture_user()
        for index in range(30):
            database.db_pr_create(FLAT_OWNER_UI, "project", f"Request {index:02}", "", "feature/api", "main", user_id)
            run_id = database.db_ci_run_create(FLAT_OWNER_UI, "project", "push", "main", self.sha, "{}")
            database.db_ci_artifact_set(run_id, b"zip")
            database.db_ci_run_update(run_id, status="success")
        for suffix in ("/pulls?status=open", "/artifacts?"):
            _, first = self.request(self.base + suffix)
            _, second = self.request(self.base + suffix + "&page=2")
            self.assertIn('rel="next"', first)
            self.assertIn('rel="prev"', second)
            self.assertNotIn('rel="next"', second)
        _, second = self.request(self.base + "/pulls?status=open&page=2")
        self.assertIn("Request 00", second)
        self.assertNotIn("Request 29", second)
        self.assertIn("status=open&amp;page=1", second)

    def test_branch_pagination_preserves_sort_and_filter(self):
        for index in range(30):
            self.git("--git-dir", self.bare, "branch", f"topic-{index:02}", "main")
        _, first = self.request(self.base + "/branches?q=topic&sort=name")
        _, second = self.request(self.base + "/branches?q=topic&sort=name&page=2")
        self.assertIn("topic-00", first)
        self.assertNotIn('data-branch="topic-29"', first)
        self.assertIn("topic-29", second)
        self.assertIn("q=topic&amp;sort=name&amp;page=1", second)

    def test_pull_request_commit_pagination_and_history_page_links(self):
        self.git("-C", self.source, "commit", "--allow-empty", "-m", "Feature commit")
        self.git("-C", self.source, "push", self.bare, "HEAD:feature/api")
        user_id = self.fixture_user()
        pr_id = database.db_pr_create(FLAT_OWNER_UI, "project", "Paged PR", "", "feature/api", "main", user_id)
        commits = [{"hash": f"{index:040x}", "subject": f"Paged commit {index:02}",
                    "author_name": "Test", "date": "2026-01-01T12:00:00+00:00"} for index in range(60)]
        async def git_commits(_bare, _ref, limit=100, skip=0, **_kwargs):
            return commits[skip:skip + limit]
        with mock.patch("pygithost.application._git_list_commits", side_effect=git_commits), mock.patch("pygithost.application._git_commit_count", new=mock.AsyncMock(return_value=60)):
            _, first = self.request(self.base + f"/pulls/{pr_id}")
            _, second = self.request(self.base + f"/pulls/{pr_id}?page=2")
            self.assertIn("Paged commit 00", first)
            self.assertNotIn("Paged commit 25", first)
            self.assertIn("Paged commit 25", second)
            self.assertNotIn("Paged commit 00", second)
            self.assertIn('rel="prev"', second)
            _, history = self.request(self.base + "/commits?ref=main&page=2")
            self.assertIn("Paged commit 50", history)
            self.assertNotIn("Paged commit 00", history)
            self.assertIn('rel="prev"', history)
            self.assertEqual(history.count('aria-label="Pagination"'), 2)
            self.assertIn('rel="prev"', history.split('<tbody id="commitRows">', 1)[0])

    def test_run_and_deployment_pagination(self):
        database.db_ci_config_set(FLAT_OWNER_UI, "project", json.dumps({"run_retention_count": 0}))
        ids = []
        for index in range(28):
            commit = f"{index:040x}"
            run_id = database.db_ci_run_create(FLAT_OWNER_UI, "project", "push", "main", commit, "{}")
            database.db_ci_run_update(run_id, status="success")
            database.db_deployment_claim(run_id, FLAT_OWNER_UI, "project", commit)
            database.db_deployment_finish(run_id, "success", "done")
            ids.append(run_id)
        for suffix in ("/ci?status=success", "/ci/deployments?"):
            status, first = self.request(self.base + suffix)
            self.assertEqual(status, 200)
            self.assertIn("Page 1", first)
            self.assertIn('rel="next"', first)
            _, second = self.request(self.base + suffix + "&page=2")
            self.assertIn("Page 2", second)
            self.assertIn('rel="prev"', second)
            self.assertNotIn('rel="next"', second)
        _, page = self.request(self.base + "/ci?status=success&page=2")
        self.assertIn("status=success&amp;page=1", page)

    def test_run_warning_badges_filters_pagination_and_details(self):
        database.db_ci_config_set(FLAT_OWNER_UI, "project", json.dumps({"run_retention_count": 0}))
        warning_ids = []
        for _ in range(28):
            run_id = database.db_ci_run_create(FLAT_OWNER_UI, "project", "push", "main", self.sha, "{}")
            database.db_ci_run_update(run_id, status="success", warnings="Cleanup failed: <script>unsafe</script>", reason="Deployment skipped: example")
            warning_ids.append(run_id)
        clean = database.db_ci_run_create(FLAT_OWNER_UI, "project", "push", "main", self.sha, "{}")
        database.db_ci_run_update(clean, status="success")
        _, first = self.request(self.base + "/ci?warnings=yes&status=success")
        self.assertIn('class="ci-warning-badge"', first)
        self.assertIn("warnings=yes", first)
        self.assertIn("of 28", first)
        self.assertNotIn(f'class="ci-run-link" href="{self.base}/ci/runs/{clean}"', first)
        _, second = self.request(self.base + "/ci?warnings=yes&status=success&page=2&partial=1")
        self.assertIn("Page 2", second)
        self.assertIn("warnings=yes", second)
        _, without = self.request(self.base + "/ci?warnings=no")
        self.assertNotIn('class="ci-warning-badge"', without)
        self.assertIn(f'class="ci-run-link" href="{self.base}/ci/runs/{clean}"', without)
        _, detail = self.request(self.base + f"/ci/runs/{warning_ids[0]}")
        self.assertIn('id="ci-run-warnings"', detail)
        self.assertIn("Deployment skipped: example", detail)
        self.assertIn("&lt;script&gt;unsafe&lt;/script&gt;", detail)
        self.assertNotIn("<script>unsafe</script>", detail)

    def test_retention_settings_are_saved_from_website(self):
        status, page = self.request(self.base + "/ci/config", {
            "command": "echo test", "artifact_retention_days": "0",
            "artifact_retention_count": "12", "run_retention_count": "0"})
        self.assertEqual(status, 200)
        self.assertIn("CI settings saved", page)
        saved = json.loads(database.db_ci_config_get(FLAT_OWNER_UI, "project"))
        self.assertEqual(saved["artifact_retention_days"], 0)
        self.assertEqual(saved["artifact_retention_count"], 12)
        self.assertEqual(saved["run_retention_count"], 0)
        self.assertIn('<p class="warn" role="note"><strong>Retention changes can permanently delete data.', page)
        self.assertIn("Retention changes apply to existing data immediately.", page)
        self.assertIn('window.confirm("These retention limits may permanently delete', page)

    def test_pasted_deployment_script_with_blank_path_saves_in_json_mode(self):
        content = 'import sys\nprint("deploying", sys.argv[1])\n'
        for mode in ("json", "command", "steps"):
            status, page = self.request(self.base + "/ci/config", {
                "pipeline_mode": mode,
                "pipeline_json": json.dumps({"version": 1, "command": "echo tests"}),
                "command": "echo tests" if mode == "command" else "",
                "steps": json.dumps([{"name": "Test", "run": "echo tests"}]),
                "deploy_enabled": "on", "deploy_script": "",
                "deploy_interpreter": "python", "deploy_script_content": content,
            })
            self.assertEqual(status, 200)
            self.assertIn("CI settings saved", page, mode)
            saved = json.loads(database.db_ci_config_get(FLAT_OWNER_UI, "project"))
            self.assertTrue(saved["deploy_enabled"])
            self.assertEqual(saved["deploy_script"], "")
            self.assertEqual(saved["deploy_script_content"], content)
            _, reopened = self.request(self.base + "/ci/config")
            editor = reopened.split('id="deploy-script-content"', 1)[1].split("</textarea>", 1)[0]
            self.assertIn('print(&quot;deploying&quot;, sys.argv[1])', editor)

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

    def test_ci_run_details_have_commit_title_and_compact_disclosures(self):
        config = {"command": "echo saved command", "runner": "host", "image": "python:3.14-slim"}
        run_id = database.db_ci_run_create(FLAT_OWNER_UI, "project", "push", "main", self.sha, "{}", json.dumps(config))
        database.db_ci_run_update(run_id, status="success", output="raw-output-marker\n" * 100,
            return_code=0, started_at="2026-01-01T12:00:00+00:00", finished_at="2026-01-01T12:00:10+00:00")
        path = self.base + f"/ci/runs/{run_id}"
        status, page = self.request(path)
        self.assertEqual(status, 200)
        self.assertIn('id="ci-run-title">Initial UI fixture</h2>', page)
        self.assertIn(f"Run #{run_id}", page)
        self.assertIn('class="ci-run-summary"', page)
        self.assertIn('<details id="ci-run-metadata" class="ci-run-disclosure">', page)
        self.assertIn('<details id="ci-run-config" class="ci-run-disclosure">', page)
        self.assertIn('<details id="ci-run-output" class="box ci-run-output" open>', page)
        self.assertIn("saved command", page)
        self.assertIn("raw-output-marker", page)
        steps = [{"name": "Tests", "status": "success", "duration": "10s", "return_code": 0,
                  "started_at": "2026-01-01T12:00:00+00:00", "finished_at": "2026-01-01T12:00:10+00:00",
                  "output": "step-output-marker"}]
        database.db_ci_steps_set(run_id, json.dumps(steps))
        _, page = self.request(path)
        self.assertIn("Combined run log", page)
        self.assertIn('<details id="ci-run-output" class="box ci-run-output">', page)
        self.assertIn('<details id="ci-step-0" class="ci-step">', page)
        self.assertIn("step-output-marker", page)
        self.assertIn('expanded.has(item.id)', page)
        self.assertIn('positions.get(item.id)', page)
        _, fragment = self.request(path + "?partial=1")
        self.assertIn('id="ci-run-result"', fragment)
        self.assertNotIn('id="ci-run-title"', fragment)
        self.assertNotIn('class="app-header"', fragment)

    def test_ci_run_title_falls_back_when_commit_is_unavailable(self):
        run_id = database.db_ci_run_create(FLAT_OWNER_UI, "project", "manual", "main", "a" * 40, "{}")
        _, page = self.request(self.base + f"/ci/runs/{run_id}")
        self.assertIn('id="ci-run-title">Manual run on main</h2>', page)

    def test_file_view_has_read_only_actions_breadcrumbs_and_line_links(self):
        status, page = self.request(self.base + "/blob/main/README.md")
        self.assertEqual(status, 200)
        for label in ("Raw</a>", "Download</a>", "Copy contents</button>", "Permalink</a>", "History</a>"):
            self.assertIn(label, page)
        self.assertIn('aria-label="File path"', page)
        self.assertIn('id="L1" href="#L1"', page)
        self.assertIn(f'/blob/{self.sha}/README.md?raw=1', page)
        self.assertIn(f'path=README.md', page)
        self.assertIn('id="repo-file-source"', page)
        self.assertIn('id="repo-file-viewport"', page)
        self.assertIn('aria-label="Scrollable file contents"', page)
        self.assertIn('id="repo-file-horizontal"', page)
        self.assertIn('aria-label="Scroll file horizontally"', page)
        self.assertIn('horizontalScroll.scrollLeft = fileViewport.scrollLeft', page)

    def test_file_raw_and_download_preserve_bytes_and_have_safe_headers(self):
        content = b'<script>alert("file contents")</script>\r\n'
        (self.source / "example.html").write_bytes(content)
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "HTML fixture")
        self.git("--git-dir", self.bare, "fetch", self.source, "main:refs/heads/main")
        for mode in ("raw", "download"):
            connection = http.client.HTTPConnection("127.0.0.1", self.server.port)
            try:
                connection.request("GET", self.base + f"/blob/main/example.html?{mode}=1")
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), content)
                self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
                self.assertIn("sandbox", response.getheader("Content-Security-Policy"))
                self.assertIn("attachment" if mode == "download" else "inline", response.getheader("Content-Disposition"))
                self.assertNotIn("text/html", response.getheader("Content-Type"))
            finally:
                connection.close()
        _, page = self.request(self.base + "/blob/main/example.html")
        self.assertNotIn('<script>alert("file contents")</script>', page)
        self.assertIn("&lt;script&gt;", page)

    def test_file_history_excludes_unrelated_commits(self):
        (self.source / "other.txt").write_text("unrelated")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Unrelated file change")
        (self.source / "README.md").write_text("Updated documentation\n")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Update README fixture")
        self.git("--git-dir", self.bare, "fetch", self.source, "main:refs/heads/main")
        status, page = self.request(self.base + "/commits?ref=main&path=README.md")
        self.assertEqual(status, 200)
        self.assertIn("Update README fixture", page)
        self.assertIn("Initial UI fixture", page)
        self.assertNotIn("Unrelated file change", page)
        _, response = self.request(self.base + "/commits?ref=main&path=README.md&partial=1")
        history = json.loads(response)["commits"]
        self.assertEqual(len(history), 2)

    def test_binary_file_view_avoids_text_preview(self):
        (self.source / "binary.bin").write_bytes(b"\0\xff\x01")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Binary fixture")
        self.git("--git-dir", self.bare, "fetch", self.source, "main:refs/heads/main")
        _, page = self.request(self.base + "/blob/main/binary.bin")
        self.assertIn("Binary file", page)
        self.assertNotIn('id="repo-file-source"', page)
        self.assertNotIn('id="repo-copy-file"', page)

    def test_large_files_skip_highlighting_but_keep_line_numbers_and_raw_download(self):
        for name, content in (("large.py", "x" * (100 * 1024 + 1)),
                              ("many-lines.py", 'print("line")\n' * 2001)):
            with self.subTest(name=name):
                (self.source / name).write_text(content)
                self.git("-C", self.source, "add", ".")
                self.git("-C", self.source, "commit", "-m", "Large file fixture")
                self.git("--git-dir", self.bare, "fetch", self.source, "main:refs/heads/main")
                status, page = self.request(self.base + "/blob/main/" + name)
                self.assertEqual(status, 200)
                self.assertIn('class="language-none"', page)
                self.assertNotIn("Enable highlighting anyway?", page)
                self.assertNotIn("temporarily unresponsive", page)
                self.assertIn('id="repo-highlight-file"', page)
                self.assertIn('id="L1"', page)
                self.assertIn('if (true) { updateFileScroll(); return; }', page)
                _, raw = self.request(self.base + "/blob/main/" + name + "?raw=1")
                self.assertEqual(raw, content)

    def test_file_view_has_no_line_or_byte_preview_cutoff(self):
        fixtures = (("long.py", 'print("row")\n' * 6000 + "LAST_LINE_MARKER\n"),
                    ("wide.py", "x" * (1024 * 1024 + 1) + "\nLAST_BYTE_MARKER\n"))
        for name, content in fixtures:
            with self.subTest(name=name):
                (self.source / name).write_text(content)
                self.git("-C", self.source, "add", ".")
                self.git("-C", self.source, "commit", "-m", "Complete file fixture")
                self.git("--git-dir", self.bare, "fetch", self.source, "main:refs/heads/main")
                status, page = self.request(self.base + "/blob/main/" + name)
                self.assertEqual(status, 200)
                self.assertIn(content.splitlines()[-1], page)
                self.assertNotIn("Preview limited", page)
                self.assertIn('class="language-none"', page)
                self.assertNotIn('role="note"', page)
                if name == "long.py":
                    self.assertIn('id="L6001"', page)

    def test_folder_and_file_views_share_clickable_breadcrumbs(self):
        folder = self.source / "CapaNegocio" / "Inventario"
        folder.mkdir(parents=True)
        (folder / "Productos_Datos.cs").write_text("class Productos_Datos {}\n")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Nested source fixture")
        self.git("--git-dir", self.bare, "fetch", self.source, "main:refs/heads/main")
        for kind, path in (("tree", "CapaNegocio/Inventario/"),
                           ("blob", "CapaNegocio/Inventario/Productos_Datos.cs")):
            with self.subTest(kind=kind):
                status, page = self.request(self.base + f"/{kind}/main/{path}")
                self.assertEqual(status, 200)
                label = "Folder path" if kind == "tree" else "File path"
                breadcrumb = page.split(f'aria-label="{label}">', 1)[1].split("</nav>", 1)[0]
                self.assertIn(f'href="{self.base}/tree/main/"', breadcrumb)
                self.assertIn(f'href="{self.base}/tree/main/CapaNegocio/"', breadcrumb)
                self.assertIn("Inventario", breadcrumb)
                if kind == "blob":
                    self.assertIn(f'href="{self.base}/tree/main/CapaNegocio/Inventario/"', breadcrumb)
                    self.assertIn('aria-current="page">Productos_Datos.cs', breadcrumb)
                else:
                    self.assertIn('aria-current="page">Inventario', breadcrumb)

    def test_repository_language_sidebar_uses_default_branch(self):
        (self.source / "Example.cs").write_text("class Example {}\n")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Language fixture")
        self.git("--git-dir", self.bare, "fetch", self.source, "main:refs/heads/main")
        status, page = self.request(self.base)
        self.assertEqual(status, 200)
        self.assertIn('id="repo-languages-title">Languages', page)
        self.assertIn("C#", page)
        self.assertIn("100.0%", page)
        self.assertIn('class="repo-language-bar"', page)
        self.assertIn('class="repo-sidebar"', page)

    def test_code_page_shows_commit_metadata_readme_license_and_real_tags(self):
        (self.source / "src").mkdir()
        (self.source / "src" / "main.py").write_text("pass\n")
        (self.source / "LICENSE").write_text("MIT License\nPermission is hereby granted, free of charge\n")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Add package and license")
        (self.source / "README.md").write_text("# Project\n\nA **useful** repository.\n")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Update overview docs")
        self.git("--git-dir", self.bare, "fetch", self.source, "main:refs/heads/main")
        self.git("--git-dir", self.bare, "tag", "v1.0", "main")
        status, page = self.request(self.base)
        self.assertEqual(status, 200)
        self.assertIn('class="repo-latest-commit"', page)
        self.assertIn("Last commit message", page)
        self.assertIn("Last commit date", page)
        self.assertIn("Add package and license", page)
        self.assertIn("Update overview docs", page)
        self.assertIn("UI author", page)
        self.assertIn('aria-label="Repository files navigation"', page)
        self.assertIn('href="#repo-readme">README', page)
        self.assertIn('href="#repo-license">MIT license', page)
        self.assertIn("<strong>useful</strong>", page)
        self.assertIn("3 commits", page)
        self.assertIn("v1.0", page)
        self.assertIn("Contributors", page)

    def test_contributors_can_expand_beyond_first_five(self):
        people = [{"name": f"Contributor {index}", "commits": 10 - index} for index in range(7)]
        database.db_repository_overview_set(FLAT_OWNER_UI, "project", self.sha,
            json.dumps({"latest": None, "entries": {}, "commit_count": 49, "contributors": people}))
        status, page = self.request(self.base)
        self.assertEqual(status, 200)
        self.assertIn('class="repo-contributors-more"', page)
        self.assertIn("Show all 7 contributors", page)
        expanded = page.split('<details class="repo-contributors-more">', 1)[1].split("</details>", 1)[0]
        self.assertIn("Contributor 5", expanded)
        self.assertIn("Contributor 6", expanded)
        self.assertNotIn("Contributor 0", expanded)

    def test_commits_are_grouped_by_date_with_pagination_metadata(self):
        commits = [{"hash": str(index) * 40, "author_name": "UI author", "author_email": "ui@example.test",
                    "date": date, "subject": f"Grouped commit {index}"}
                   for index, date in ((1, "2026-10-28 13:00:00 +0000"),
                                       (2, "2026-10-28 10:00:00 +0000"),
                                       (3, "2026-10-27 12:00:00 +0000"))]
        with mock.patch("pygithost.application._git_list_commits", new=mock.AsyncMock(return_value=commits)):
            status, page = self.request(self.base + "/commits?ref=main")
            self.assertEqual(status, 200)
            self.assertEqual(page.count('data-date-heading="2026-10-28"'), 1)
            self.assertEqual(page.count('data-date-heading="2026-10-27"'), 1)
            self.assertEqual(page.count('data-commit-date="2026-10-28"'), 2)
            self.assertIn("Commits on Oct 28, 2026", page)
            self.assertLess(page.index('data-date-heading="2026-10-28"'), page.index('data-date-heading="2026-10-27"'))
            _, body = self.request(self.base + "/commits?ref=main&partial=1")
            payload = json.loads(body)
            self.assertEqual(payload["commits"][0]["date_key"], "2026-10-28")
            self.assertEqual(payload["commits"][2]["date_key"], "2026-10-27")
