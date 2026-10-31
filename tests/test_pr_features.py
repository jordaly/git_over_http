import asyncio
import http.client
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import unittest.mock
from urllib.parse import quote, urlencode

from pygithost import application, database
from pygithost.application import FLAT_OWNER_UI
from tests.test_server import ServerRunner, _which_git_backend


@unittest.skipUnless(True, "runs with local git")
class PullRequestFeaturesTests(unittest.TestCase):
    def setUp(self):
        if not (subprocess.run(["git", "--version"], capture_output=True).returncode == 0 and _which_git_backend()):
            self.skipTest("requires Git HTTP backend")
        self.temp = tempfile.TemporaryDirectory(prefix="pr-features-")
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.bare = self.root / "project.git"
        self.old_db = database.DB_PATH
        self.git("init", "-b", "main", self.source)
        self.git("-C", self.source, "config", "user.name", "PR author")
        self.git("-C", self.source, "config", "user.email", "pr@example.test")
        (self.source / "app.py").write_text("one\ntwo\nthree\nfour\nfive\n")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Initial")
        self.git("clone", "--bare", self.source, self.bare)
        self.server = ServerRunner(project_root=str(self.root))
        self.server.__enter__()
        self.base = f"/r/{FLAT_OWNER_UI}/project"
        # Advance main so the feature PR has content and a differing target tip.
        (self.source / "notes.md").write_text("unrelated main change\n")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Main change")
        self.git("-C", self.source, "push", self.bare, "main:main")
        self.git("-C", self.source, "checkout", "-q", "-b", "feature/pr")
        (self.source / "app.py").write_text("one\ntwo\nthree-edited\nfour\nfive\nsix\n")
        (self.source / "new.txt").write_text("brand new file\n")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Feature edits")
        self.git("-C", self.source, "push", self.bare, "feature/pr:feature/pr")
        status, page = self.request(self.base + "/pulls/create", {
            "title": "Feature PR", "body": "A useful change",
            "source_branch": "feature/pr", "target_branch": "main"})
        self.assertEqual(status, 303, page)
        pr = database.db_pr_list(FLAT_OWNER_UI, "project")[0]
        self.pr = pr[0]

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

    def page(self, query=""):
        status, page = self.request(self.base + f"/pulls/{self.pr}" + query)
        self.assertEqual(status, 200, page)
        return page

    def test_file_filter_shows_pill_link_not_escaped_html(self):
        page = self.page(quote("?file=" + "app.py", safe="=?&"))
        self.assertIn('Diff — <code>app.py</code> <a class="pill" href="/r/root/project/pulls/' + str(self.pr) + '#diff">All files</a>', page)
        self.assertNotIn("&lt;a", page)

    def test_pr_shows_merge_base_diff_excluding_target_changes(self):
        page = self.page()
        self.assertIn("Feature edits", page)
        self.assertIn("three-edited", page)
        self.assertIn("+six", page)
        self.assertNotIn("unrelated main change", page)
        self.assertIn("Changed files (2)", page)
        self.assertIn("app.py", page)
        self.assertIn("new.txt", page)
        self.assertIn('<span class="add">+3</span>', page)
        self.assertIn('<span class="del">−1</span>', page)
        file_filter = quote("?file=" + "app.py", safe="=?&")
        status, page = self.request(self.base + f"/pulls/{self.pr}" + file_filter)
        self.assertEqual(status, 200)
        self.assertIn("Changed files (2)", page)
        self.assertIn("three-edited", page)
        self.assertNotIn("brand new file", page)

    def test_discussion_add_edit_delete_and_permissions(self):
        page = self.page()
        self.assertIn("No comments yet.", page)
        self.assertIn('action="' + self.base + f'/pulls/{self.pr}/comments"', page)
        with unittest.mock.patch.object(application, "_has_write_scope", return_value=False):
            page = self.page()
            self.assertIn("Write scope is required to comment.", page)
            status, page = self.request(self.base + f"/pulls/{self.pr}/comments", {"body": "nope"})
            self.assertEqual(status, 403)
            self.assertEqual(database.db_pr_comment_count(self.pr), 0)
        status, page = self.request(self.base + f"/pulls/{self.pr}/comments", {"body": "First comment"})
        self.assertEqual(status, 200)
        self.assertIn("First comment", page)
        comments = database.db_pr_comment_list(self.pr)
        self.assertEqual(len(comments), 1)
        self.assertIsNone(comments[0][1])  # anonymous author preserved
        cid = comments[0][0]
        status, page = self.request(self.base + f"/pulls/{self.pr}/comments/{cid}/edit", {"body": "Edited comment"})
        self.assertEqual(status, 200)
        self.assertIn("Edited comment", page)
        self.assertIn("(edited)", page)
        status, page = self.request(self.base + f"/pulls/{self.pr}/comments", {"body": ""})
        self.assertIn("required", page)
        self.assertEqual(database.db_pr_comment_count(self.pr), 1)
        status, page = self.request(self.base + f"/pulls/{self.pr}/comments/{cid}/delete", {})
        self.assertEqual(status, 200)
        self.assertEqual(database.db_pr_comment_count(self.pr), 0)
        self.assertIn("No comments yet.", page)
        status, _ = self.request(self.base + f"/pulls/{self.pr}/comments/999/delete", {})
        self.assertEqual(status, 404)

    def test_edit_title_and_description(self):
        status, page = self.request(self.base + f"/pulls/{self.pr}/update", {
            "title": "Renamed PR", "body": "Updated description"})
        self.assertEqual(status, 200)
        self.assertIn("Renamed PR", page)
        self.assertIn("Updated description", page)
        self.assertEqual(database.db_pr_get(self.pr)[3], "Renamed PR")
        status, page = self.request(self.base + f"/pulls/{self.pr}/update", {"title": "", "body": ""})
        self.assertIn("Title is required.", page)
        self.assertEqual(database.db_pr_get(self.pr)[3], "Renamed PR")

    def test_merge_conflict_is_detected_in_merge_panel(self):
        # Make target diverge in a way that conflicts with the PR edit to app.py.
        other = self.root / "second-clone"
        self.git("clone", "-q", self.bare, other)
        self.git("-C", other, "checkout", "-q", "main")
        (other / "app.py").write_text("conflicting\n")
        self.git("-C", other, "add", "-A")
        self.git("-C", other, "commit", "-m", "Conflicting main edit")
        self.git("-C", other, "push", "-q", "origin", "main:main")
        page = self.page()
        self.assertIn("Merge conflict:", page)
        self.assertIn("feature/pr", page)

    def test_pulls_list_shows_tabs_counts_and_comment_counts(self):
        database.db_pr_comment_add(self.pr, None, "row count")
        status, page = self.request(self.base + "/pulls")
        self.assertEqual(status, 200, page)
        self.assertIn(">Open 1<", page)
        self.assertIn(">All 1<", page)
        self.assertIn('href="' + self.base + '/pulls/new"', page)
        self.assertIn("💬 1", page)
        self.assertIn("just now", page)
        self.assertIn("pill-open", page)
        status, page = self.request(self.base + "/pulls?status=all")
        self.assertIn('>All 1</a', page)
        status, page = self.request(self.base + "/pulls/999/comments", {"body": "hi"})
        self.assertEqual(status, 404)
        # Creation moved to its own page.
        self.assertNotIn("Open a pull request", page)
        status, page = self.request(self.base + "/pulls/new")
        self.assertEqual(status, 200, page)
        self.assertIn('action="' + self.base + '/pulls/create"', page)
        self.assertIn("Source branch", page)
        self.assertIn("fast-forward only", page)

    def test_conflict_warning_links_straight_to_web_ide(self):
        self._make_conflict()
        page = self.page()
        self.assertIn("Merge conflict:", page)
        self.assertIn(self.base + f"/pulls/{self.pr}/resolve/ide", page)
        self.assertIn("Resolve conflicts in the web IDE", page)


    def test_deleted_author_keeps_comments_readable(self):
        conn = database._db_connect()
        try:
            uid = conn.execute("INSERT INTO users(username,pass_salt,pass_hash) VALUES('commenter',?,?)", (b"s", b"h")).lastrowid
        finally:
            conn.close()
        database.db_pr_comment_add(self.pr, uid, "User comment")
        conn = database._db_connect()
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("DELETE FROM users WHERE id=?", (uid,))
        finally:
            conn.close()
        page = self.page()
        self.assertIn("User comment", page)
        self.assertIn("anonymous", page)

    def test_comment_routes_reject_unknown_pr(self):
        status, _ = self.request(self.base + "/pulls/999/comments", {"body": "hi"})
        self.assertEqual(status, 404)

    def _make_conflict(self):
        """Advance main in a way that conflicts with the PR's app.py edit."""
        other = self.root / "conflict-clone"
        self.git("clone", "-q", self.bare, other)
        self.git("-C", other, "checkout", "-q", "main")
        (other / "app.py").write_text("conflicting target line\n")
        self.git("-C", other, "add", "-A")
        self.git("-C", other, "commit", "-m", "Conflicting main edit")
        self.git("-C", other, "push", "-q", "origin", "main:main")

    def test_resolve_page_lists_conflict_markers(self):
        self._make_conflict()
        status, page = self.request(self.base + f"/pulls/{self.pr}/resolve")
        self.assertEqual(status, 200, page)
        self.assertIn("Resolve conflicts", page)
        self.assertIn("app.py", page)
        # Conflict markers arrive escaped inside the textarea.
        self.assertIn("&lt;&lt;&lt;&lt;&lt;&lt;&lt; HEAD (feature/pr)", page)
        self.assertIn("&gt;&gt;&gt;&gt;&gt;&gt;&gt; target (main)", page)
        self.assertIn("Apply resolution", page)

    def test_resolve_ide_page_and_commit_endpoint(self):
        self._make_conflict()
        import json as jsonlib
        status, page = self.request(self.base + f"/pulls/{self.pr}/resolve/ide")
        self.assertEqual(status, 200, page)
        self.assertIn('data-mode="resolve"', page)
        self.assertIn('data-conflicts="[&quot;app.py&quot;]"', page)
        self.assertIn("Resolve PR #", page)
        self.assertIn("Apply resolution", page)
        token = re.search(r'data-csrf="([^"]+)"', page).group(1)
        commit_before = self.git("--git-dir", str(self.bare), "rev-parse", "refs/heads/feature/pr")
        # Conflicted content (with markers) is served by the IDE conflict action.
        status, body = self.request(self.base + f"/ide/conflict?branch=feature/pr&path=app.py&pr={self.pr}")
        self.assertEqual(status, 200, body)
        data = jsonlib.loads(body)
        self.assertEqual(data["kind"], "conflicts")
        self.assertIn("<<<<<<< HEAD (feature/pr)", data["content"])
        # Wrong branch is refused; unknown PR pages 404.
        payload = {"branch": "main", "base": commit_before, "message": "x", "changes": {"app.py": "resolved\n"}}
        status, body = self.request(self.base + f"/pulls/{self.pr}/resolve/ide/commit",
                                    {"csrf": token, "payload": jsonlib.dumps(payload)})
        self.assertEqual(status, 403)
        status, _ = self.request(self.base + "/pulls/999/resolve/ide")
        self.assertEqual(status, 404)
        payload["branch"] = "feature/pr"
        status, body = self.request(self.base + f"/pulls/{self.pr}/resolve/ide/commit",
                                    {"csrf": token, "payload": jsonlib.dumps(payload)})
        self.assertEqual(status, 200, body)
        body_json = jsonlib.loads(body)
        commit = body_json["commit"]
        self.assertEqual(self.git("--git-dir", str(self.bare), "rev-parse", "refs/heads/feature/pr"), commit)
        self.assertIn("warning", body_json)  # no pipelines configured in this fixture
        main_tip = self.git("--git-dir", str(self.bare), "rev-parse", "refs/heads/main")
        self.assertEqual(self.git("--git-dir", str(self.bare), "merge-base", "main", "feature/pr"), main_tip)
        self.assertEqual(database.db_pr_comment_count(self.pr), 1)
        self.assertIn("web IDE", database.db_pr_comment_list(self.pr)[0][3])
        status, page = self.request(self.base + f"/pulls/{self.pr}")
        self.assertIn("Merge (ff-only)", page)

    def test_resolve_apply_creates_merge_commit_then_ff_merge(self):
        self._make_conflict()
        name = self.git("--git-dir", self.bare, "rev-parse", "refs/heads/feature/pr")
        status, page = self.request(self.base + f"/pulls/{self.pr}/resolve", {
            "conflict_count": "1", "path_0": "app.py", "delete_0": "",
            "content_0": "one\ntwo\nthree-edited\nfour\nfive\nsix\nconflicting target line\n",
            "message": "Merge main into feature/pr"})
        self.assertEqual(status, 200, page)
        self.assertIn("Merge conflicts resolved", page)
        new_tip = self.git("--git-dir", str(self.bare), "rev-parse", "refs/heads/feature/pr")
        self.assertNotEqual(new_tip, name)
        main_tip = self.git("--git-dir", str(self.bare), "rev-parse", "refs/heads/main")
        self.assertEqual(self.git("--git-dir", str(self.bare), "merge-base", "main", "feature/pr"), main_tip)
        self.assertEqual(database.db_pr_comment_count(self.pr), 1)
        # The integrated branch can now be merged by the ff-only policy.
        status, page = self.request(self.base + f"/pulls/{self.pr}/merge", {})
        self.assertEqual(status, 200, page)
        pr = database.db_pr_get(self.pr)
        self.assertEqual(pr[8], "merged")
        self.assertEqual(self.git("--git-dir", str(self.bare), "rev-parse", "refs/heads/main"), pr[13])

    def test_resolve_apply_validates_paths_and_unknown_pr(self):
        self._make_conflict()
        status, page = self.request(self.base + f"/pulls/{self.pr}/resolve", {
            "conflict_count": "1", "path_0": "app.py", "content_0": "resolved\n", "message": "x"})
        # The stale one-row resolution misses nothing else, but an unknown PR or
        # bad path must not commit anything.
        name = self.git("--git-dir", str(self.bare), "rev-parse", "refs/heads/feature/pr")
        self.assertEqual(name, self.git("--git-dir", str(self.bare), "rev-parse", "refs/heads/feature/pr"))
        status, _ = self.request(self.base + "/pulls/999/resolve")
        self.assertEqual(status, 404)

    def test_resolver_unit_conflict_flow_and_race(self):
        from pygithost import pr_resolver as resolver
        import shutil
        import tempfile as tempmod
        root = Path(tempmod.mkdtemp(prefix="resolver-unit-"))
        try:
            work = root / "repo"
            subprocess.run(["git", "init", str(work)], capture_output=True, check=True)
            def run(*args):
                result = subprocess.run(["git", "-C", str(work), *map(str, args)], capture_output=True, text=True, check=True)
                return result.stdout.strip()
            run("config", "user.name", "t"); run("config", "user.email", "t@t")
            (work / "app.py").write_text("base\n")
            run("add", "-A"); run("commit", "-qm", "base")
            run("checkout", "-qb", "feature")
            (work / "app.py").write_text("base\nsrc-side\n")
            run("commit", "-qam", "src")
            run("checkout", "-qb", "maint", "master")
            (work / "app.py").write_text("base\ntgt-side\n")
            run("commit", "-qam", "tgt")
            repo_git = str(work / ".git")  # plumbing against the raw git dir
            mb = run("merge-base", "feature", "maint")
            src = run("rev-parse", "feature")
            tgt = run("rev-parse", "maint")
            conflicts = resolver.list_conflicts(repo_git, mb, src, tgt)
            self.assertEqual([c["path"] for c in conflicts], ["app.py"])
            text, kind = resolver.preview(repo_git, conflicts[0], "feature", "maint")
            self.assertEqual(kind, "conflicts")
            self.assertIn("<<<<<<< HEAD (feature)", text.decode())
            self.assertIn(">>>>>>> target (maint)", text.decode())
            commit = resolver.apply_resolution(repo_git, mb, src, tgt, "feature",
                [("app.py", "base\nboth sides\n", False)], "integrated", "tester")
            self.assertEqual(run("rev-parse", "feature"), commit)
            # Race: the branch advanced after the page was opened.
            advanced = run("commit-tree", src + "^{tree}", "-p", src, "-m", "advanced")
            run("update-ref", "refs/heads/feature", advanced, commit)
            from pygithost import pr_resolver as resolver
            with self.assertRaises(resolver.ResolverError) as ctx:
                resolver.apply_resolution(repo_git, mb, src, tgt, "feature",
                    [("app.py", "x", False)], "stale", "tester")
            self.assertIn("changed", str(ctx.exception))
            self.assertEqual(run("rev-parse", "feature"), advanced)
        finally:
            shutil.rmtree(root, ignore_errors=True)

