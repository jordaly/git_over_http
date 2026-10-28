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
