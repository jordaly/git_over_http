import json
from html import unescape
import os
import re
import subprocess
import tempfile
import unittest
from unittest import mock
from urllib.parse import urlencode

from pygithost import application, webide
from tests import test_repository_ui as ui


class WebIDETests(unittest.TestCase):
    def setUp(self):
        self.fixture = ui.RepositoryUITests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.base = self.fixture.base + "/ide"
        status, page = self.fixture.request(self.base)
        self.assertEqual(status, 200)
        self.token = re.search(r'data-csrf="([^"]+)"', page)[1]

    def api(self, action, params=None, payload=None, token=None):
        url = self.base + "/" + action
        if params:
            url += "?" + urlencode(params)
        fields = None if payload is None else {"csrf": self.token if token is None else token, "payload": json.dumps(payload)}
        status, body = self.fixture.request(url, fields)
        return status, json.loads(body)

    def payload(self, **overrides):
        return dict(branch="main", base=self.fixture.sha,
                    changes={"README.md": "Browser edit\n", "folder/new.py": "print('hi')\n"},
                    message="Edit from browser", **overrides)

    def test_snapshot_file_and_local_vendor(self):
        status, snapshot = self.api("snapshot", {"branch": "feature/api"})
        self.assertEqual(status, 200)
        self.assertEqual(snapshot["commit"], self.fixture.sha)
        self.assertEqual(snapshot["files"][0]["path"], "README.md")
        status, result = self.api("file", {"branch": "main", "commit": self.fixture.sha, "path": "README.md"})
        self.assertEqual((status, result["content"]), (200, "Repository fixture\n"))
        status, source = self.fixture.request("/static/vendor/monaco/vs/loader.js")
        self.assertEqual(status, 200)
        self.assertIn("Copyright", source)

    def test_gitlab_style_entry_points_keep_branch_and_file_context(self):
        for suffix in ("", "/tree/feature%2Fapi/"):
            status, page = self.fixture.request(self.fixture.base + suffix)
            self.assertEqual(status, 200)
            self.assertIn("Open in Web IDE", page)
        status, page = self.fixture.request(self.fixture.base + "/blob/feature%2Fapi/README.md")
        self.assertEqual(status, 200)
        page = unescape(page)
        query = "?" + urlencode({"branch": "feature/api", "path": "README.md"})
        self.assertIn(self.fixture.base + "/edit" + query, page)
        self.assertIn(self.base + query, page)
        self.assertIn("Edit single file", page)
        status, page = self.fixture.request(self.fixture.base + "/edit" + query)
        self.assertEqual(status, 200)
        self.assertIn('data-mode="single"', page)
        self.assertIn('data-path="README.md"', page)
        self.assertIn('value="feature/api" selected', page)
        status, page = self.fixture.request(self.base + query)
        self.assertEqual(status, 200)
        self.assertIn('data-mode="workspace"', page)
        for label in ("Explorer", "Source Control", "Open files", "Go to file", "Back to repository", "New file", "New folder"):
            self.assertIn(label, page)

    def test_immutable_refs_and_read_only_users_have_no_edit_actions(self):
        status, page = self.fixture.request(self.fixture.base + "/blob/" + self.fixture.sha + "/README.md")
        self.assertEqual(status, 200)
        self.assertNotIn("Edit single file", page)
        self.assertNotIn("Open in Web IDE", page)
        for route in ("/ide", "/edit"):
            status, _ = self.fixture.request(self.fixture.base + route + "?" + urlencode({"branch": self.fixture.sha, "path": "README.md"}))
            self.assertEqual(status, 400)  # Never silently edit the default branch instead.
        with mock.patch.object(application, "_has_write_scope", return_value=False):
            status, page = self.fixture.request(self.fixture.base + "/blob/main/README.md")
            self.assertEqual(status, 200)
            self.assertNotIn("Edit single file", page)
            self.assertNotIn("Open in Web IDE", page)
            status, _ = self.fixture.request(self.fixture.base + "/edit?branch=main&path=README.md")
            self.assertEqual(status, 403)

    def test_commit_add_modify_delete_and_queue_push(self):
        with mock.patch.object(application.AsyncGitServer, "_queue_push_changes", new_callable=mock.AsyncMock) as queue:
            status, result = self.api("commit", payload=self.payload())
            self.assertEqual(status, 200, result)
            queue.assert_awaited_once()
        commit = result["commit"]
        git = self.fixture.git
        self.assertEqual(git("--git-dir", self.fixture.bare, "show", commit + ":README.md"), "Browser edit")
        self.assertEqual(git("--git-dir", self.fixture.bare, "show", commit + ":folder/new.py"), "print('hi')")
        self.assertEqual(git("--git-dir", self.fixture.bare, "rev-parse", commit + "^"), self.fixture.sha)
        payload = self.payload()
        payload.update(base=commit, changes={"folder/new.py": None})
        status, result = self.api("commit", payload=payload)
        self.assertEqual(status, 200, result)
        self.assertNotIn("folder/new.py", git("--git-dir", self.fixture.bare, "ls-tree", "-r", "--name-only", "main"))

    def test_content_search_is_literal_case_insensitive_and_validated(self):
        params = {"branch": "main", "commit": self.fixture.sha, "q": "REPOSITORY"}
        status, result = self.api("search", params)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["results"], [{"path": "README.md", "line": 1, "text": "Repository fixture"}])
        self.assertFalse(result["truncated"])
        for query in (".*", "--help", "no such text"):
            status, result = self.api("search", dict(params, q=query))
            self.assertEqual((status, result["results"]), (200, []))
        for query in ("", "a\nb", "a" * 201):
            status, _ = self.api("search", dict(params, q=query))
            self.assertEqual(status, 400)
        status, _ = self.api("search", dict(params, commit="--help"))
        self.assertEqual(status, 400)

    def test_content_search_bounds_results_and_long_lines(self):
        commit = webide.commit_changes(str(self.fixture.bare), "main", self.fixture.sha,
            {"many.txt": "needle\n" * 250, "long.txt": "long-match" + "x" * (300 * 1024) + "\n"}, "Search fixtures", "test")
        status, result = self.api("search", {"branch": "main", "commit": commit, "q": "needle"})
        self.assertEqual(status, 200)
        self.assertEqual(len(result["results"]), 200)
        self.assertTrue(result["truncated"])
        status, result = self.api("search", {"branch": "main", "commit": commit, "q": "long-match"})
        self.assertEqual(status, 200)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(json.dumps(result)), 256 * 1024)

    def test_csrf_permissions_and_protected_branch(self):
        status, _ = self.api("commit", payload=self.payload(), token="wrong")
        self.assertEqual(status, 403)
        payload = self.payload()
        payload["branch"] = "release/1"
        status, _ = self.api("commit", payload=payload)
        self.assertEqual(status, 403)
        with mock.patch.object(application, "_has_write_scope", return_value=False):
            status, _ = self.fixture.request(self.base)
            self.assertEqual(status, 403)
            status, _ = self.fixture.request(self.base + "/commit", {"csrf": self.token, "payload": json.dumps(self.payload())})
            self.assertEqual(status, 403)
        self.assertEqual(self.fixture.git("--git-dir", self.fixture.bare, "rev-parse", "main"), self.fixture.sha)

    def test_conflict_invalid_paths_and_noop_leave_branch_unchanged(self):
        for changes in ({"../escape": "bad"}, {".git/config": "bad"}, {"a\\b": "bad"},
                        {"README.md": "Repository fixture\n"}, {"binary": "\0"}, {"missing": None},
                        {"big": "x" * (webide.MAX_FILE + 1)}):
            payload = self.payload()
            payload["changes"] = changes
            with self.subTest(changes=list(changes)):
                status, _ = self.api("commit", payload=payload)
                self.assertEqual(status, 409)
        payload = self.payload()
        payload["base"] = "0" * 40
        status, _ = self.api("commit", payload=payload)
        self.assertEqual(status, 409)
        self.assertEqual(self.fixture.git("--git-dir", self.fixture.bare, "rev-parse", "main"), self.fixture.sha)

    def test_executable_mode_and_symlink_safety(self):
        source = self.fixture.source
        (source / "run.sh").write_text("echo old\n")
        (source / "run.sh").chmod(0o755)
        (source / "link").symlink_to("README.md")
        (source / "binary").write_bytes(b"a\0b")
        self.fixture.git("-C", source, "add", ".")
        self.fixture.git("-C", source, "commit", "-m", "Special files")
        self.fixture.git("-C", source, "push", str(self.fixture.bare), "main")
        base = webide.head(str(self.fixture.bare), "main")
        for filename in ("link", "binary"):
            with self.assertRaises(webide.IDEError):
                webide.read_file(str(self.fixture.bare), "main", base, filename)
            with self.assertRaises(webide.IDEError):
                webide.commit_changes(str(self.fixture.bare), "main", base, {filename: "bad"}, "bad", "user")
        commit = webide.commit_changes(str(self.fixture.bare), "main", base, {"run.sh": "echo new\n"}, "Executable", "user")
        self.assertEqual(webide.tree(str(self.fixture.bare), commit)["run.sh"]["mode"], "100755")

    def test_server_checkout_is_not_overwritten(self):
        repo = str(self.fixture.source / ".git")
        with self.assertRaisesRegex(webide.IDEError, "checked out"):
            webide.commit_changes(repo, "main", webide.head(repo, "main"), {"README.md": "bad"}, "bad", "user")
        self.assertEqual((self.fixture.source / "README.md").read_text(), "Repository fixture\n")

    @unittest.skipUnless(os.name == "posix", "requires executable shell hooks")
    def test_repository_receive_hook_can_reject_browser_commit(self):
        hook = self.fixture.bare / "hooks" / "pre-receive"
        hook.write_text("#!/bin/sh\necho 'Rejected by repository policy' >&2\nexit 1\n")
        hook.chmod(0o755)
        status, result = self.api("commit", payload=self.payload())
        self.assertEqual(status, 409, result)
        self.assertIn("Rejected by repository policy", result["error"])
        self.assertEqual(webide.head(str(self.fixture.bare), "main"), self.fixture.sha)

    def test_ci_scheduling_failure_still_confirms_successful_commit(self):
        with mock.patch.object(application.AsyncGitServer, "_queue_push_changes", new_callable=mock.AsyncMock,
                               side_effect=RuntimeError("CI unavailable")):
            status, result = self.api("commit", payload=self.payload())
        self.assertEqual(status, 200, result)
        self.assertIn("warning", result)
        self.assertEqual(webide.head(str(self.fixture.bare), "main"), result["commit"])


@unittest.skipUnless(os.environ.get("PYGITHOST_TEST_BROWSER"), "set PYGITHOST_TEST_BROWSER to Chromium")
class WebIDEBrowserTests(unittest.TestCase):
    def run_browser(self, fixture, script, path):
        original = application._html_page

        def page(title, body):
            result = original(title, body)
            return result.replace(b"</body>", script.encode() + b"</body>") if title == "Web IDE" else result

        with tempfile.TemporaryDirectory(prefix="webide-browser-", dir="/tmp/opencode") as profile:
            with mock.patch.object(application, "_html_page", side_effect=page):
                result = subprocess.run([os.environ["PYGITHOST_TEST_BROWSER"], "--headless", "--no-sandbox", "--disable-gpu",
                    "--no-first-run", "--no-default-browser-check", "--disable-dev-shm-usage", "--window-size=1440,1000",
                    "--user-data-dir=" + profile, "--dump-dom", "--virtual-time-budget=15000",
                    f"http://127.0.0.1:{fixture.server.port}{fixture.base}{path}"],
                    capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        error = re.search(r'data-webide-error="([^"]*)"', result.stdout)
        self.assertTrue('data-webide-test="passed"' in result.stdout,
                        unescape(error[1]) if error else result.stderr[-2000:])

    def test_edit_diff_discard_and_commit_in_real_browser(self):
        fixture = ui.RepositoryUITests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        webide.commit_changes(str(fixture.bare), "main", fixture.sha, {
            "a-root.txt": "root\n", "z-folder/a.txt": "nested\n",
            "z-folder/z-nested/code.py": "print('fixture')\n", "z-root.txt": "root\n"
        }, "Explorer ordering fixture", "test")
        script = r'''<script>
(async function () {
 const sleep = () => new Promise(resolve => setTimeout(resolve, 50));
 async function wait(test) { for (let i = 0; i < 180; i++) { if (test()) return; await sleep(); } throw Error("Timed out: " + document.getElementById("ide-status").textContent); }
 const el = id => document.getElementById("ide-" + id);
 const ready = () => !el("new").disabled;
 const model = () => monaco.editor.getModels().find(m => m.uri.toString().endsWith("/README.md"));
 window.confirm = () => true;
 function checkExplorer(parent) {
  let sawFile = false;
  for (const node of parent.children) {
   if (node.tagName === "DETAILS") {
    if (sawFile) throw Error("Folder appears after a file");
    if (!node.querySelector(":scope > summary > svg.ide-icon-folder")) throw Error("Missing folder icon");
    checkExplorer(node);
   } else if (node.tagName === "BUTTON") {
    sawFile = true;
    if (!node.querySelector('svg.ide-file-icon[aria-hidden="true"]')) throw Error("Missing file icon");
   }
  }
 }
 try {
  await wait(() => window.monaco && el("files").querySelector("button") && ready());
  checkExplorer(el("files"));
  if (!el("files").querySelector("svg.ide-icon-code")) throw Error("Missing code-file icon");
  for (const folder of el("files").querySelectorAll("details")) folder.open = true;
  await sleep();
  el("collapse").click();
  if (el("files").querySelector("details[open]")) throw Error("Collapse all left open folders");
  el("filter").value = "z-folder"; el("filter").dispatchEvent(new Event("input"));
  checkExplorer(el("files"));
  el("filter").value = ""; el("filter").dispatchEvent(new Event("input"));
  [...el("files").querySelectorAll("button")].find(b => b.textContent === "README.md").click();
  await wait(() => model() && ready());
  model().setValue("Discard me\n");
  if (!el("changes").textContent.includes("README.md")) throw Error("Missing dirty file");
  el("search-view").click();
  el("search-input").value = "discard me"; el("search-form").requestSubmit();
  await wait(() => el("search-results").querySelector("button") && ready());
  if (!el("search-results").textContent.includes("README.md:1")) throw Error("Search missed pending edits");
  el("search-results").querySelector("button").click();
  await wait(() => el("filename").textContent === "README.md" && ready());
  el("search-input").value = "Repository fixture"; el("search-form").requestSubmit();
  await wait(() => el("search-status").textContent.includes("0 matching") && ready());
  el("search-input").value = "print"; el("search-form").requestSubmit();
  await wait(() => el("search-results").querySelector("button") && ready());
  el("search-results").querySelector("button").click();
  await wait(() => el("filename").textContent === "z-folder/z-nested/code.py" && ready());
  if (!el("cursor").textContent.includes("Ln 1")) throw Error("Search did not jump to matching line");
  const codeModel = monaco.editor.getModels().find(m => m.uri.toString().endsWith("/z-folder/z-nested/code.py"));
  const savedCode = codeModel.getValue();
  codeModel.setValue("print('changed')\n");
  const input = document.querySelector("#ide-editor textarea.inputarea");
  input.focus();
  const focused = document.activeElement;
  for (const modifier of ["ctrlKey", "metaKey"]) {
   const event = new KeyboardEvent("keydown", {key:"s", [modifier]:true, bubbles:true, cancelable:true});
   input.dispatchEvent(event);
   if (!event.defaultPrevented || el("sidebar").dataset.view !== "search" || document.activeElement !== focused || el("filename").textContent !== "z-folder/z-nested/code.py") throw Error("Save switched panel, file or focus");
  }
  el("source-view").click();
  [...el("changes").querySelectorAll("button")].find(b => b.textContent === "M z-folder/z-nested/code.py").click();
  await wait(() => document.querySelector(".monaco-diff-editor") && ready());
  const original = monaco.editor.getModels().find(m => m.uri.authority === "webide-original");
  if (!original || original.getLanguageId() !== "python" || original.getLanguageId() !== codeModel.getLanguageId()) throw Error("Diff languages do not match");
  await wait(() => new Set([...document.querySelectorAll(".monaco-diff-editor .original .view-line span[class*='mtk']")].map(n => getComputedStyle(n).color)).size > 1);
  await wait(() => new Set([...document.querySelectorAll(".monaco-diff-editor .modified .view-line span[class*='mtk']")].map(n => getComputedStyle(n).color)).size > 1);
  document.dispatchEvent(new KeyboardEvent("keydown", {key:"s", ctrlKey:true, bubbles:true, cancelable:true}));
  if (!document.querySelector(".monaco-diff-editor") || el("sidebar").dataset.view !== "source") throw Error("Save left the current diff");
  el("write").click(); await wait(() => !document.querySelector(".monaco-diff-editor") && ready());
  codeModel.setValue(savedCode);
  el("explorer-view").click();
  [...el("files").querySelectorAll("button")].find(b => b.dataset.path === "README.md").click();
  await wait(() => el("filename").textContent === "README.md" && ready());
  el("review").click();
  await wait(() => document.querySelector(".monaco-diff-editor") && ready());
  el("review").click();
  await wait(() => !document.querySelector(".monaco-diff-editor") && ready());
  el("discard-file").click();
  await wait(() => model().getValue() === "Repository fixture\n" && ready());
  if (el("changes").textContent) throw Error("Discard left dirty files");
  window.prompt = () => "z-new-folder";
  el("new-folder").click();
  await wait(() => el("filename").textContent === "z-new-folder/.gitkeep" && ready());
  if (!el("changes").textContent.includes("A z-new-folder/.gitkeep")) throw Error("New folder has no pending placeholder");
  checkExplorer(el("files"));
  window.prompt = () => "nested/browser.js";
  el("explorer-new").click(); await wait(() => el("filename").textContent === "nested/browser.js" && ready());
  checkExplorer(el("files"));
  el("discard").click(); await wait(() => !el("changes").textContent && ready());
  if (el("files").textContent.includes("browser.js")) throw Error("Discard left new file");
  if (el("files").textContent.includes("z-new-folder")) throw Error("Discard left new folder");
  [...el("files").querySelectorAll("button")].find(b => b.textContent === "README.md").click();
  await wait(() => model() && ready());
  el("delete").click(); await wait(() => el("changes").textContent.includes("D README.md") && ready());
  el("discard-file").click(); await wait(() => !el("changes").textContent && ready());
  model().setValue("Committed in real Chromium\n");
  el("source-view").click();
  if (!el("message").getBoundingClientRect().height) throw Error("Source Control not visible");
  el("message").value = "Browser integration commit";
  el("submit").click();
  await wait(() => el("status").textContent.startsWith("Committed ") && ready());
  if (el("changes").textContent) throw Error("Commit left dirty files");
  document.documentElement.dataset.webideTest = "passed";
 } catch (error) {
  document.documentElement.dataset.webideTest = "failed";
  document.documentElement.dataset.webideError = error.message;
 }
})();</script>'''
        self.run_browser(fixture, script, "/ide?branch=main")
        self.assertEqual(fixture.git("--git-dir", fixture.bare, "show", "main:README.md"), "Committed in real Chromium")

    def test_single_file_commit_then_expand_preserves_edits_tabs_and_quick_open(self):
        fixture = ui.RepositoryUITests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        script = r'''<script>
(async function () {
 const sleep = () => new Promise(resolve => setTimeout(resolve, 50));
 const el = id => document.getElementById("ide-" + id);
 const root = document.getElementById("webide");
 const ready = () => !el("new").disabled;
 const model = name => monaco.editor.getModels().find(m => m.uri.toString().endsWith("/" + name));
 async function wait(test) { for (let i = 0; i < 180; i++) { if (test()) return; await sleep(); } throw Error("Timed out: " + el("status").textContent); }
 window.confirm = () => true;
 try {
  await wait(() => window.monaco && model("README.md") && ready());
  if (root.dataset.mode !== "single" || el("branch").value !== "feature/api") throw Error("Lost single-file context");
  if (el("files").getBoundingClientRect().height || !el("message").getBoundingClientRect().height) throw Error("Incorrect single-file layout");
  model("README.md").setValue("Single-file commit\n");
  el("review").click(); await wait(() => document.querySelector(".monaco-diff-editor") && ready());
  el("write").click(); await wait(() => !document.querySelector(".monaco-diff-editor") && ready());
  el("message").value = "Quick single-file change"; el("submit").click();
  await wait(() => el("status").textContent.startsWith("Committed ") && ready());
  const sameModel = model("README.md");
  sameModel.setValue("Preserved when opening full IDE\n");
  el("expand").click();
  await wait(() => root.dataset.mode === "workspace" && getComputedStyle(root).position === "fixed");
  if (!location.pathname.endsWith("/ide") || model("README.md") !== sameModel) throw Error("Expansion lost model or URL");
  if (!el("changes").textContent.includes("README.md")) throw Error("Expansion lost edits");
  window.prompt = () => "nested/second.py";
  el("new").click(); await wait(() => model("nested/second.py") && ready());
  model("nested/second.py").setValue("print('two files')\n");
  if (el("tabs").querySelectorAll('[role="tab"]').length !== 2) throw Error("Missing open-file tabs");
  el("tabs").querySelector('[aria-label="Close README.md"]').click();
  if (!el("changes").textContent.includes("README.md")) throw Error("Closing tab discarded work");
  el("quick-open").click();
  if (!el("picker").open) throw Error("Quick open did not appear");
  el("picker-input").value = "readme"; el("picker-input").dispatchEvent(new Event("input"));
  el("picker-input").dispatchEvent(new KeyboardEvent("keydown", {key:"Enter", bubbles:true, cancelable:true}));
  await wait(() => el("filename").textContent === "README.md" && ready());
  if (model("README.md").getValue() !== "Preserved when opening full IDE\n") throw Error("Tab reopened without edits");
  if (el("tabs").querySelectorAll('[role="tab"]').length !== 2) throw Error("Tab was not reopened");
  window.prompt = () => "empty-folder";
  el("new-folder").click();
  await wait(() => el("filename").textContent === "empty-folder/.gitkeep" && ready());
  el("source-view").click();
  if (!el("message").getBoundingClientRect().height || el("source-count").textContent !== "3") throw Error("Source Control is incorrect");
  el("changes").querySelector("button").click();
  await wait(() => document.querySelector(".monaco-diff-editor") && ready());
  el("message").value = "Multi-file workbench commit"; el("submit").click();
  await wait(() => el("status").textContent.startsWith("Committed ") && ready());
  if (!document.querySelector(".monaco-diff-editor") || el("sidebar").dataset.view !== "source") throw Error("Commit switched the current diff or panel");
  if (el("changes").textContent || el("tabs").querySelectorAll('[role="tab"]').length !== 3) throw Error("Commit failed to keep clean tabs");
  document.documentElement.dataset.webideTest = "passed";
 } catch (error) { document.documentElement.dataset.webideTest = "failed"; document.documentElement.dataset.webideError = error.message; }
})();</script>'''
        self.run_browser(fixture, script, "/edit?" + urlencode({"branch": "feature/api", "path": "README.md"}))
        self.assertEqual(fixture.git("--git-dir", fixture.bare, "show", "feature/api:README.md"), "Preserved when opening full IDE")
        self.assertEqual(fixture.git("--git-dir", fixture.bare, "show", "feature/api:nested/second.py"), "print('two files')")
        self.assertEqual(fixture.git("--git-dir", fixture.bare, "show", "feature/api:empty-folder/.gitkeep"), "")
        self.assertEqual(fixture.git("--git-dir", fixture.bare, "rev-parse", "main"), fixture.sha)
        self.assertEqual(fixture.git("--git-dir", fixture.bare, "log", "-1", "--format=%s", "feature/api^"), "Quick single-file change")
