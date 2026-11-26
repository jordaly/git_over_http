"""Black-box regression tests for pull request reviews, merge rules and the PR pages.

Every test drives a real server (``ServerRunner``) over HTTP against real Git
repositories created in a temporary directory: the REST API under
``/api/v1/repos/{owner}/{repo}/pulls/...`` and the web UI under ``/r/...``.
"""

import http.client
import json
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from pygithost import application, database, pull_store
from pygithost.application import FLAT_OWNER_UI
from tests.ci_fixtures import commit_file
from tests.test_server import ServerRunner, _which_git_backend, with_csrf

HAS_GIT = bool(shutil.which("git") and _which_git_backend())
APP_LINES = [f"line {number}" for number in range(1, 11)]
REVIEW_TABLES = ("pr_reviews", "pr_review_threads", "pr_review_comments", "pr_events")


def text_of(lines):
    return "\n".join(lines) + "\n"


def with_line(lines, number, value):
    """Copy of ``lines`` with 1-based line ``number`` replaced by ``value``."""
    changed = list(lines)
    changed[number - 1] = value
    return changed


def run_git(*args, cwd=None):
    return subprocess.check_output(
        ["git", *map(str, args)], cwd=cwd, stderr=subprocess.PIPE, text=True
    ).strip()


def make_user(name, *, admin=False):
    conn = database._db_connect()
    try:
        return conn.execute(
            "INSERT INTO users(username,pass_salt,pass_hash,is_admin) VALUES(?,?,?,?)",
            (name, b"test", b"test", int(admin)),
        ).lastrowid
    finally:
        conn.close()


def build_source(root, policies=None):
    """A working repository with ``main`` (advanced past the fork point) and ``feature``.

    ``feature`` changes line 5 of ``app.py`` and adds ``new.txt``; ``main`` then
    gets an unrelated commit (``other.txt``), so the PR is behind its base.
    """
    source = root / "source"
    run_git("init", "-q", "-b", "main", source)
    run_git("-C", source, "config", "user.name", "Base Author")
    run_git("-C", source, "config", "user.email", "base@example.test")
    (source / "app.py").write_text(text_of(APP_LINES))
    (source / "README.md").write_text("fixture\n")
    if policies is not None:
        (source / "ci").mkdir()
        document = {"version": 1, "pipelines": [], "policies": policies}
        (source / "ci" / "config.json").write_text(json.dumps(document))
    run_git("-C", source, "add", ".")
    run_git("-C", source, "commit", "-q", "-m", "Initial")
    run_git("-C", source, "checkout", "-q", "-b", "feature")
    run_git("-C", source, "config", "user.name", "Feature Dev")
    run_git("-C", source, "config", "user.email", "dev@example.test")
    (source / "app.py").write_text(text_of(with_line(APP_LINES, 5, "line 5 feature")))
    (source / "new.txt").write_text("brand new file\n")
    run_git("-C", source, "add", ".")
    run_git("-C", source, "commit", "-q", "-m", "Feature change")
    run_git("-C", source, "checkout", "-q", "main")
    run_git("-C", source, "config", "user.name", "Base Author")
    run_git("-C", source, "config", "user.email", "base@example.test")
    (source / "other.txt").write_text("unrelated main change\n")
    run_git("-C", source, "add", ".")
    run_git("-C", source, "commit", "-q", "-m", "Main advance")
    return source


# ====================================================================== REST API


@unittest.skipUnless(HAS_GIT, "requires Git HTTP backend")
class _APIFixture(unittest.TestCase):
    POLICIES = None

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="pull-reviews-api-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.addCleanup(setattr, database, "DB_PATH", database.DB_PATH)
        self.source = build_source(self.root, self.POLICIES)
        (self.root / "alice").mkdir()
        self.bare = self.root / "alice" / "project.git"
        run_git("clone", "-q", "--bare", self.source, self.bare)
        run_git("--git-dir", self.bare, "config", "http.receivepack", "true")
        self.server = ServerRunner(project_root=str(self.root))
        self.server.__enter__()
        self.addCleanup(self.server.__exit__, None, None, None)
        self.alice = make_user("alice")  # repository owner and PR author (not an admin)
        self.rev = make_user("rev", admin=True)
        self.rev2 = make_user("rev2", admin=True)
        self.alice_token = database.db_create_token(self.alice, "t")
        self.rev_token = database.db_create_token(self.rev, "t")
        self.rev2_token = database.db_create_token(self.rev2, "t")
        self.base = "/api/v1/repos/alice/project"

    # ------------------------------------------------------------- helpers

    def api(self, method, path, document=None, *, token=None):
        headers = {"Authorization": "Bearer " + (token or self.alice_token)}
        body = None
        if method != "GET":
            headers["Content-Type"] = "application/json"
            headers["Idempotency-Key"] = secrets.token_hex(16)
            body = json.dumps(document if document is not None else {})
        connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=30)
        try:
            connection.request(method, self.base + path, body=body, headers=headers)
            response = connection.getresponse()
            content = response.read()
            return response.status, json.loads(content) if content else None
        finally:
            connection.close()

    def ok(self, method, path, document=None, *, token=None, status=None):
        code, result = self.api(method, path, document, token=token)
        if status is None:
            self.assertLess(code, 300, (method, path, result))
        else:
            self.assertEqual(code, status, (method, path, result))
        return result

    def fails(self, method, path, document=None, *, token=None, status, code=None):
        got, result = self.api(method, path, document, token=token)
        self.assertEqual(got, status, (method, path, result))
        if code is not None:
            self.assertEqual(result["code"], code, result)
        return result

    def create_pr(self, head="feature", base="main", *, draft=False, title="Feature PR"):
        document = {"title": title, "head": head, "base": base, "body": "Body"}
        if draft:
            document["draft"] = True
        result = self.ok("POST", "/pulls", document, status=201)
        self.assertEqual(result["draft"], draft)
        return result["id"]

    def sha(self, ref):
        return run_git("--git-dir", self.bare, "rev-parse", ref)

    def branch_exists(self, name):
        return (
            subprocess.run(
                ["git", "--git-dir", str(self.bare), "rev-parse", "--verify", "-q", name],
                capture_output=True,
            ).returncode
            == 0
        )

    def new_branch(self, name, start="main"):
        run_git("--git-dir", self.bare, "branch", name, start)

    def commit(self, branch, path, content, message="Fixture change"):
        return commit_file(self.bare, path, content, branch=branch, message=message)

    def thread(self, pr, line, body, *, token=None, mode="single", path="app.py", **extra):
        document = {"path": path, "line": line, "body": body, "mode": mode, **extra}
        result = self.ok("POST", f"/pulls/{pr}/threads", document, token=token, status=201)
        return result["thread_id"], result["comment_id"]

    def threads(self, pr, *, token=None):
        return self.ok("GET", f"/pulls/{pr}/threads", token=token)

    def thread_by_id(self, pr, thread_id, *, token=None):
        return self.ok("GET", f"/pulls/{pr}/threads/{thread_id}", token=token)

    def review(self, pr, event, body="", *, token=None, comments=None, status=201):
        document = {"event": event, "body": body}
        if comments is not None:
            document["comments"] = comments
        return self.ok("POST", f"/pulls/{pr}/reviews", document, token=token, status=status)

    def merge_status(self, pr, *, token=None):
        return self.ok("GET", f"/pulls/{pr}/merge-status", token=token)

    def events(self, pr):
        return [item["event"] for item in self.ok("GET", f"/pulls/{pr}/events")]

    def push(self, refspec, *, force=False):
        url = f"http://127.0.0.1:{self.server.port}/git/alice/project.git"
        args = ["-C", self.source, "push", "-q"] + (["--force"] if force else [])
        run_git(*args, url, refspec)

    def wait_for_event(self, pr, kind, timeout=10.0):
        deadline = time.monotonic() + timeout
        while True:
            kinds = self.events(pr)
            if kind in kinds or time.monotonic() > deadline:
                return kinds
            time.sleep(0.1)


class PullLifecycleAPITests(_APIFixture):
    def test_patch_can_hide_whitespace_only_changes(self):
        pr = self.create_pr()
        self.commit("feature", "README.md", "  fixture\n")
        path = f"/pulls/{pr}/diff"
        self.assertIn("README.md", self.ok("GET", path)["patch"])
        patch = self.ok("GET", path + "?ignore_whitespace=true")["patch"]
        self.assertNotIn("README.md", patch)
        self.assertIn("app.py", patch)

    def test_draft_blocks_merge_until_ready_for_review(self):
        pr = self.create_pr(draft=True)
        status = self.merge_status(pr)
        self.assertTrue(status["draft"])
        self.assertIn("draft", status["blocked_codes"])
        self.assertFalse(status["can_merge"])
        self.fails("PUT", f"/pulls/{pr}/merge", {}, status=409, code="draft")
        self.assertEqual(
            self.ok("PATCH", f"/pulls/{pr}", {"draft": False}),
            {"id": pr, "draft": False, "base": "main"},
        )
        self.assertTrue(self.merge_status(pr)["can_merge"])
        result = self.ok("PUT", f"/pulls/{pr}/merge", {}, status=200)
        self.assertTrue(result["merged"])
        kinds = self.events(pr)
        self.assertIn("ready_for_review", kinds)
        self.assertIn("merged", kinds)
        self.assertEqual(self.ok("GET", f"/pulls/{pr}")["state"], "merged")
        # A merged PR cannot be turned back into a draft.
        self.fails("PATCH", f"/pulls/{pr}", {"draft": True}, status=409, code="not_open")

    def test_draft_flag_must_be_boolean(self):
        pr = self.create_pr()
        self.fails("PATCH", f"/pulls/{pr}", {"draft": "yes"}, status=422)
        self.fails(
            "POST",
            "/pulls",
            {"title": "x", "head": "feature", "base": "main", "draft": 1},
            status=422,
        )

    def test_change_base_and_reject_invalid_base(self):
        self.new_branch("develop")
        pr = self.create_pr()
        result = self.ok("PATCH", f"/pulls/{pr}", {"base": "develop"})
        self.assertEqual(result["base"], "develop")
        self.assertEqual(self.ok("GET", f"/pulls/{pr}")["base"]["ref"], "develop")
        self.assertIn("base_changed", self.events(pr))
        for bad in ("does-not-exist", "feature", "../main", "-x", ""):
            with self.subTest(base=bad):
                self.fails("PATCH", f"/pulls/{pr}", {"base": bad}, status=422)
        self.assertEqual(self.ok("GET", f"/pulls/{pr}")["base"]["ref"], "develop")

    def test_merge_commit_has_two_parents(self):
        pr = self.create_pr()
        head, base = self.sha("feature"), self.sha("main")
        result = self.ok("PUT", f"/pulls/{pr}/merge", {"merge_method": "merge"}, status=200)
        self.assertEqual(result["merge_method"], "merge")
        self.assertEqual(self.sha("main"), result["sha"])
        parents = run_git("--git-dir", self.bare, "log", "-1", "--format=%P", "main").split()
        self.assertEqual(parents, [base, head])
        subject = run_git("--git-dir", self.bare, "log", "-1", "--format=%s", "main")
        self.assertEqual(subject, f"Merge pull request #{pr} from feature")
        pull = self.ok("GET", f"/pulls/{pr}")
        self.assertEqual((pull["state"], pull["merge_method"]), ("merged", "merge"))
        self.assertEqual(pull["merge_commit_sha"], result["sha"])

    def test_squash_creates_single_parent_titled_commit(self):
        pr = self.create_pr(title="Squash me")
        base = self.sha("main")
        result = self.ok("PUT", f"/pulls/{pr}/merge", {"merge_method": "squash"}, status=200)
        parents = run_git("--git-dir", self.bare, "log", "-1", "--format=%P", "main").split()
        self.assertEqual(parents, [base])
        subject = run_git("--git-dir", self.bare, "log", "-1", "--format=%s", result["sha"])
        self.assertEqual(subject, f"Squash me (#{pr})")
        body = run_git("--git-dir", self.bare, "log", "-1", "--format=%b", result["sha"])
        self.assertIn("* Feature change", body)
        content = run_git("--git-dir", self.bare, "show", "main:app.py")
        self.assertIn("line 5 feature", content)

    def test_rebase_is_linear_and_preserves_authors(self):
        self.commit("feature", "second.txt", "two\n", message="Second feature commit")
        pr = self.create_pr()
        base = self.sha("main")
        result = self.ok("PUT", f"/pulls/{pr}/merge", {"merge_method": "rebase"}, status=200)
        log = run_git(
            "--git-dir", self.bare, "log", "--format=%P|%an|%s", f"{base}..{result['sha']}"
        ).splitlines()
        self.assertEqual(len(log), 2)
        for entry in log:
            self.assertEqual(len(entry.split("|")[0].split()), 1, "rebase must not merge")
        self.assertEqual(
            [entry.split("|", 1)[1] for entry in log],
            ["CI fixture|Second feature commit", "Feature Dev|Feature change"],
        )
        oldest_parent = log[-1].split("|")[0]
        self.assertEqual(oldest_parent, base)

    def test_fast_forward_moves_base_to_head(self):
        self.new_branch("ahead")
        head = self.commit("ahead", "ahead.txt", "ahead\n")
        pr = self.create_pr(head="ahead")
        self.assertTrue(self.merge_status(pr)["fast_forward"])
        result = self.ok("PUT", f"/pulls/{pr}/merge", {"merge_method": "ff"}, status=200)
        self.assertEqual(result["sha"], head)
        self.assertEqual(self.sha("main"), head)

    def test_fast_forward_refused_for_diverged_branches(self):
        pr = self.create_pr()
        self.assertFalse(self.merge_status(pr)["fast_forward"])
        before = self.sha("main")
        self.fails("PUT", f"/pulls/{pr}/merge", {"merge_method": "ff"}, status=422)
        self.assertEqual(self.sha("main"), before)
        self.assertEqual(self.ok("GET", f"/pulls/{pr}")["state"], "open")

    def test_stale_head_sha_conflicts_and_unknown_method_rejected(self):
        pr = self.create_pr()
        before = self.sha("main")
        self.fails("PUT", f"/pulls/{pr}/merge", {"sha": "0" * 40}, status=409, code="stale")
        self.fails(
            "PUT", f"/pulls/{pr}/merge", {"expected_base_sha": "1" * 40}, status=409, code="stale"
        )
        self.fails("PUT", f"/pulls/{pr}/merge", {"sha": "main"}, status=422)
        self.fails(
            "PUT",
            f"/pulls/{pr}/merge",
            {"merge_method": "octopus"},
            status=422,
            code="method_not_allowed",
        )
        self.assertEqual(self.sha("main"), before)
        result = self.ok("PUT", f"/pulls/{pr}/merge", {"sha": self.sha("feature")}, status=200)
        self.assertTrue(result["merged"])
        self.fails("PUT", f"/pulls/{pr}/merge", {}, status=409, code="not_open")

    def test_delete_branch_on_merge_then_restore(self):
        pr = self.create_pr()
        head = self.sha("feature")
        result = self.ok("PUT", f"/pulls/{pr}/merge", {"delete_branch": True}, status=200)
        self.assertTrue(result.get("branch_deleted"), result)
        self.assertFalse(self.branch_exists("refs/heads/feature"))
        self.assertIn("head_ref_deleted", self.events(pr))
        self.fails("DELETE", f"/pulls/{pr}/head-branch", {}, status=409, code="missing_branch")
        self.assertEqual(
            self.ok("POST", f"/pulls/{pr}/head-branch/restore", {}, status=201), {"restored": True}
        )
        self.assertEqual(self.sha("feature"), head)
        self.assertIn("head_ref_restored", self.events(pr))
        self.fails("POST", f"/pulls/{pr}/head-branch/restore", {}, status=409)

    def test_head_branch_cannot_be_deleted_while_open(self):
        pr = self.create_pr()
        self.fails("DELETE", f"/pulls/{pr}/head-branch", {}, status=409, code="open")
        self.assertTrue(self.branch_exists("refs/heads/feature"))

    def test_update_branch_merges_base_into_head(self):
        pr = self.create_pr()
        head, base = self.sha("feature"), self.sha("main")
        result = self.ok("PUT", f"/pulls/{pr}/update-branch", {}, status=202)
        self.assertEqual(self.sha("feature"), result["sha"])
        parents = run_git("--git-dir", self.bare, "log", "-1", "--format=%P", "feature").split()
        self.assertEqual(parents, [head, base])
        self.assertEqual(self.sha("main"), base)
        self.fails("PUT", f"/pulls/{pr}/update-branch", {}, status=409, code="up_to_date")
        self.fails(
            "PUT",
            f"/pulls/{pr}/update-branch",
            {"expected_head_sha": head},
            status=409,
            code="stale",
        )

    def test_update_branch_conflict(self):
        pr = self.create_pr()
        self.commit("main", "app.py", text_of(with_line(APP_LINES, 5, "line 5 main")))
        head = self.sha("feature")
        status = self.merge_status(pr)
        self.assertEqual(status["mergeable"], "conflict")
        self.assertIn("app.py", status["conflicts"])
        self.fails("PUT", f"/pulls/{pr}/update-branch", {}, status=409, code="conflict")
        self.fails("PUT", f"/pulls/{pr}/merge", {}, status=409, code="merge_conflict")
        self.assertEqual(self.sha("feature"), head)

    def test_mutations_require_write_scope(self):
        pr = self.create_pr()
        reader = database.db_create_token(self.rev, "reader", "read")
        self.fails("PUT", f"/pulls/{pr}/merge", {}, token=reader, status=403)
        self.fails("PUT", f"/pulls/{pr}/update-branch", {}, token=reader, status=403)
        self.assertEqual(self.ok("GET", f"/pulls/{pr}")["state"], "open")


class PullMergeMethodPolicyTests(_APIFixture):
    POLICIES = {"merge_methods": ["squash", "rebase"]}

    def test_default_is_first_allowed_and_disallowed_method_rejected(self):
        pr = self.create_pr()
        status = self.merge_status(pr)
        self.assertEqual(status["allowed_methods"], ["squash", "rebase"])
        self.assertEqual(status["default_method"], "squash")
        self.assertEqual(status["blocked_codes"], [])
        before = self.sha("main")
        for method in ("merge", "ff"):
            with self.subTest(method=method):
                self.fails(
                    "PUT",
                    f"/pulls/{pr}/merge",
                    {"merge_method": method},
                    status=422,
                    code="method_not_allowed",
                )
        self.assertEqual(self.sha("main"), before)
        result = self.ok("PUT", f"/pulls/{pr}/merge", {}, status=200)
        self.assertEqual(result["merge_method"], "squash")
        parents = run_git("--git-dir", self.bare, "log", "-1", "--format=%P", "main").split()
        self.assertEqual(parents, [before])


class PullReviewAPITests(_APIFixture):
    def setUp(self):
        super().setUp()
        self.pr = self.create_pr()
        self.p = f"/pulls/{self.pr}"

    def test_single_comment_is_visible_to_everyone(self):
        thread_id, comment_id = self.thread(self.pr, 5, "Looks odd", token=self.rev_token)
        for token in (self.alice_token, self.rev_token, self.rev2_token):
            items = self.threads(self.pr, token=token)
            self.assertEqual([t["id"] for t in items], [thread_id])
        item = self.thread_by_id(self.pr, thread_id)
        self.assertEqual(
            {k: item[k] for k in ("path", "side", "line", "original_line", "outdated", "resolved")},
            {
                "path": "app.py",
                "side": "RIGHT",
                "line": 5,
                "original_line": 5,
                "outdated": False,
                "resolved": False,
            },
        )
        self.assertEqual(item["original_commit_id"], self.sha("feature"))
        comment = item["comments"][0]
        self.assertEqual(comment["id"], comment_id)
        self.assertEqual(comment["user"], {"id": self.rev, "login": "rev"})
        self.assertEqual((comment["body"], comment["pending"]), ("Looks odd", False))
        self.assertIn("review_comment", self.events(self.pr))
        reply = self.ok(
            "POST", f"{self.p}/threads/{thread_id}/replies", {"body": "Fixed"}, status=201
        )
        item = self.thread_by_id(self.pr, thread_id, token=self.rev_token)
        self.assertEqual([c["id"] for c in item["comments"]], [comment_id, reply["comment_id"]])
        self.assertEqual(item["comments"][1]["user"]["login"], "alice")
        self.fails("GET", f"{self.p}/threads/999999", status=404)

    def test_thread_validation(self):
        bad = [
            {"path": "app.py", "line": 0, "body": "x"},
            {"path": "app.py", "line": 500, "body": "x"},
            {"path": "missing.py", "line": 1, "body": "x"},
            {"path": "../etc/passwd", "line": 1, "body": "x"},
            {"path": "app.py", "line": 2, "body": "   "},
            {"path": "app.py", "line": 2, "body": "x", "side": "MIDDLE"},
            {"path": "app.py", "line": 2, "start_line": 3, "body": "x"},
            {"path": "app.py", "line": 2, "body": "x", "mode": "later"},
        ]
        for document in bad:
            with self.subTest(document=document):
                self.fails("POST", f"{self.p}/threads", document, status=422)
        self.assertEqual(self.threads(self.pr), [])
        # A LEFT comment anchors to the merge-base version of the file.
        thread_id, _ = self.thread(self.pr, 5, "old line", side="LEFT")
        self.assertEqual(self.thread_by_id(self.pr, thread_id)["side"], "LEFT")
        # A multi-line RIGHT range keeps its start line.
        thread_id, _ = self.thread(self.pr, 6, "range", start_line=4)
        item = self.thread_by_id(self.pr, thread_id)
        self.assertEqual((item["start_line"], item["line"]), (4, 6))

    def test_pending_review_is_private_until_submitted(self):
        thread_id, comment_id = self.thread(
            self.pr, 5, "Draft remark", token=self.rev_token, mode="review"
        )
        mine = self.thread_by_id(self.pr, thread_id, token=self.rev_token)
        self.assertTrue(mine["comments"][0]["pending"])
        for token in (self.alice_token, self.rev2_token):
            self.assertNotIn(thread_id, [t["id"] for t in self.threads(self.pr, token=token)])
            self.fails("GET", f"{self.p}/threads/{thread_id}", token=token, status=404)
            states = [r["state"] for r in self.ok("GET", f"{self.p}/reviews", token=token)]
            self.assertNotIn("PENDING", states)
        reviews = self.ok("GET", f"{self.p}/reviews", token=self.rev_token)
        self.assertEqual([r["state"] for r in reviews], ["PENDING"])
        pending_id = reviews[0]["id"]
        # Another user cannot edit, reply to or delete a comment they cannot see.
        self.fails("PATCH", f"{self.p}/review-comments/{comment_id}", {"body": "x"}, status=404)
        self.fails("POST", f"{self.p}/threads/{thread_id}/replies", {"body": "x"}, status=404)
        # A second review-mode comment joins the same pending review.
        self.thread(self.pr, 2, "Second remark", token=self.rev_token, mode="review")
        review = self.review(self.pr, "COMMENT", "", token=self.rev_token)
        self.assertEqual((review["id"], review["state"]), (pending_id, "COMMENTED"))
        self.assertIsNotNone(review["submitted_at"])
        self.assertEqual(len(self.threads(self.pr, token=self.alice_token)), 2)
        item = self.thread_by_id(self.pr, thread_id, token=self.alice_token)
        self.assertFalse(item["comments"][0]["pending"])
        self.assertEqual(item["comments"][0]["review_id"], pending_id)

    def test_review_events_and_inline_comments(self):
        review = self.review(
            self.pr,
            "REQUEST_CHANGES",
            "Please fix",
            token=self.rev_token,
            comments=[
                {"path": "app.py", "line": 5, "body": "Here"},
                {"path": "new.txt", "line": 1, "body": "And here"},
            ],
        )
        self.assertEqual(review["state"], "CHANGES_REQUESTED")
        self.assertEqual(review["user"], {"id": self.rev, "login": "rev"})
        self.assertEqual(review["commit_id"], self.sha("feature"))
        items = self.threads(self.pr, token=self.alice_token)
        self.assertEqual(sorted(t["path"] for t in items), ["app.py", "new.txt"])
        self.assertTrue(all(t["comments"][0]["review_id"] == review["id"] for t in items))
        status = self.merge_status(self.pr)
        self.assertEqual(status["changes_requested_by"], ["rev"])
        approve = self.review(self.pr, "APPROVE", "", token=self.rev_token)
        self.assertEqual(approve["state"], "APPROVED")
        status = self.merge_status(self.pr)
        self.assertEqual((status["approvals"], status["approved_by"]), (1, ["rev"]))
        self.assertEqual(status["changes_requested_by"], [])
        # A later plain comment does not replace the approval.
        self.review(self.pr, "COMMENT", "Nit", token=self.rev_token)
        self.assertEqual(self.merge_status(self.pr)["approved_by"], ["rev"])
        reviews = self.ok("GET", f"{self.p}/reviews")
        self.assertEqual(
            [r["state"] for r in reviews], ["CHANGES_REQUESTED", "APPROVED", "COMMENTED"]
        )
        single = self.ok("GET", f"{self.p}/reviews/{approve['id']}")
        self.assertEqual(single, approve)
        self.fails("GET", f"{self.p}/reviews/999999", status=404)

    def test_review_validation(self):
        self.fails(
            "POST", f"{self.p}/reviews", {"event": "APPROVE"}, status=422, code="validation_error"
        )
        self.fails(
            "POST", f"{self.p}/reviews", {"event": "REQUEST_CHANGES", "body": "x"}, status=422
        )
        self.fails(
            "POST", f"{self.p}/reviews", {"event": "COMMENT"}, token=self.rev_token, status=422
        )
        self.fails(
            "POST",
            f"{self.p}/reviews",
            {"event": "COMMENT", "body": "  "},
            token=self.rev_token,
            status=422,
        )
        self.fails("POST", f"{self.p}/reviews", {"event": "LGTM"}, token=self.rev_token, status=422)
        self.fails(
            "POST",
            f"{self.p}/reviews",
            {"event": "APPROVE", "commit_id": "a" * 40},
            token=self.rev_token,
            status=409,
            code="stale",
        )
        self.fails(
            "POST",
            f"{self.p}/reviews",
            {"event": "COMMENT", "comments": [{"path": "app.py", "body": "no line"}]},
            token=self.rev_token,
            status=422,
        )
        self.assertEqual(self.ok("GET", f"{self.p}/reviews", token=self.rev_token), [])
        # The author may leave a plain comment review on their own PR.
        self.assertEqual(self.review(self.pr, "COMMENT", "Context")["state"], "COMMENTED")

    def test_discard_pending_review_removes_its_comments(self):
        thread_id, _ = self.thread(self.pr, 5, "Pending", token=self.rev_token, mode="review")
        kept, _ = self.thread(self.pr, 6, "Published", token=self.rev_token)
        self.assertEqual(
            self.ok("DELETE", f"{self.p}/reviews/pending", token=self.rev_token), {"deleted": True}
        )
        ids = [t["id"] for t in self.threads(self.pr, token=self.rev_token)]
        self.assertEqual(ids, [kept])
        self.assertNotIn(thread_id, ids)
        self.assertEqual(self.ok("GET", f"{self.p}/reviews", token=self.rev_token), [])
        self.fails("DELETE", f"{self.p}/reviews/pending", token=self.rev_token, status=404)
        # Without a pending review an empty COMMENT is still refused.
        self.fails(
            "POST", f"{self.p}/reviews", {"event": "COMMENT"}, token=self.rev_token, status=422
        )

    def test_pending_review_submitted_without_event_stays_pending(self):
        result = self.ok(
            "POST",
            f"{self.p}/reviews",
            {"comments": [{"path": "app.py", "line": 5, "body": "Later"}]},
            token=self.rev_token,
            status=201,
        )
        self.assertEqual(result["state"], "PENDING")
        self.assertEqual(self.threads(self.pr, token=self.alice_token), [])
        submitted = self.review(self.pr, "APPROVE", token=self.rev_token)
        self.assertEqual(submitted["id"], result["id"])
        self.assertEqual(len(self.threads(self.pr, token=self.alice_token)), 1)

    def test_dismissals_by_writer(self):
        approval = self.review(self.pr, "APPROVE", "ok", token=self.rev_token)
        comment = self.review(self.pr, "COMMENT", "fyi", token=self.rev2_token)
        path = f"{self.p}/reviews/{approval['id']}/dismissals"
        self.fails("PUT", path, {"message": ""}, status=422)
        reader = database.db_create_token(self.alice, "reader", "read")
        self.fails("PUT", path, {"message": "no"}, token=reader, status=403)
        self.fails(
            "PUT", f"{self.p}/reviews/{comment['id']}/dismissals", {"message": "x"}, status=404
        )
        self.assertEqual(
            self.ok("PUT", path, {"message": "Outdated approval"}), {"dismissed": True}
        )
        dismissed = self.ok("GET", f"{self.p}/reviews/{approval['id']}")
        self.assertEqual(dismissed["state"], "DISMISSED")
        self.assertEqual(dismissed["dismissal_message"], "Outdated approval")
        self.assertIsNotNone(dismissed["dismissed_at"])
        self.assertEqual(self.merge_status(self.pr)["approvals"], 0)
        events = self.ok("GET", f"{self.p}/events")
        dismissal = next(e for e in events if e["event"] == "review_dismissed")
        self.assertEqual(dismissal["data"]["reviewer"], "rev")
        self.assertEqual(dismissal["data"]["reason"], "Outdated approval")
        self.fails("PUT", path, {"message": "again"}, status=404)

    def test_read_endpoint_shapes(self):
        self.ok(
            "POST", f"/pulls/{self.pr}/requested_reviewers", {"reviewers": ["rev2"]}, status=201
        )
        self.thread(self.pr, 5, "note", token=self.rev_token)
        self.review(self.pr, "APPROVE", "LGTM", token=self.rev_token)
        status = self.merge_status(self.pr)
        for key in (
            "state",
            "allowed_methods",
            "default_method",
            "mergeable",
            "conflicts",
            "fast_forward",
            "rebase_clean",
            "protected",
            "required_approvals",
            "approvals",
            "approved_by",
            "changes_requested_by",
            "unresolved_threads",
            "ci",
            "draft",
            "blocked_reasons",
            "blocked_codes",
            "can_merge",
        ):
            self.assertIn(key, status)
        self.assertEqual(status["mergeable"], "clean")
        self.assertEqual(status["allowed_methods"], ["merge", "squash", "rebase", "ff"])
        self.assertEqual(status["unresolved_threads"], 1)
        self.assertTrue(status["protected"])
        self.assertEqual(status["required_approvals"], 0)
        self.assertTrue(status["can_merge"])
        timeline = self.ok("GET", f"{self.p}/timeline")
        types = {item["type"] for item in timeline}
        self.assertEqual(types, {"review", "event"})
        stamps = [item["created_at"] for item in timeline]
        self.assertEqual(stamps, sorted(stamps))
        review = next(item for item in timeline if item["type"] == "review")
        self.assertEqual((review["state"], review["body"]), ("approved", "LGTM"))
        events = self.ok("GET", f"{self.p}/events")
        self.assertTrue(all(item["type"] == "event" for item in events))
        self.assertEqual([e["event"] for e in events], ["review_requested", "review_comment"])
        self.assertEqual(events[0]["data"], {"reviewer": "rev2"})
        self.assertEqual(
            self.ok("GET", f"{self.p}/requested_reviewers"),
            {"users": [{"id": self.rev2, "login": "rev2"}]},
        )
        self.fails("GET", "/pulls/999999/merge-status", status=404)
        self.fails("GET", "/pulls/999999/threads", status=404)

    def test_requested_reviewers(self):
        path = f"{self.p}/requested_reviewers"
        result = self.ok("POST", path, {"reviewers": ["rev", "rev2"]}, status=201)
        self.assertEqual(sorted(result["requested"]), ["rev", "rev2"])
        # Requesting again adds nobody new.
        self.assertEqual(self.ok("POST", path, {"reviewers": ["rev"]}, status=201)["requested"], [])
        self.fails("POST", path, {"reviewers": ["ghost"]}, status=422)
        self.fails("POST", path, {"reviewers": ["alice"]}, status=422)
        self.fails("POST", path, {"reviewers": []}, status=422)
        self.fails("POST", path, {"reviewers": "rev"}, status=422)
        logins = lambda: sorted(u["login"] for u in self.ok("GET", path)["users"])  # noqa: E731
        self.assertEqual(logins(), ["rev", "rev2"])
        self.assertEqual(self.ok("DELETE", path, {"reviewers": ["rev2"]}), {"removed": ["rev2"]})
        self.fails("DELETE", path, {"reviewers": ["rev2"]}, status=404)
        self.assertEqual(logins(), ["rev"])
        # Submitting any review fulfils the reviewer's request.
        self.review(self.pr, "COMMENT", "Seen", token=self.rev_token)
        self.assertEqual(logins(), [])
        kinds = self.events(self.pr)
        self.assertEqual(kinds.count("review_requested"), 2)
        self.assertIn("review_request_removed", kinds)

    def test_edit_and_delete_review_comment_permissions(self):
        thread_id, comment_id = self.thread(self.pr, 5, "Original", token=self.rev_token)
        path = f"{self.p}/review-comments/{comment_id}"
        # alice is a writer but neither the comment author nor an administrator.
        self.fails("PATCH", path, {"body": "Hijacked"}, status=403, code="forbidden")
        self.fails("DELETE", path, {}, status=403, code="forbidden")
        self.ok("PATCH", path, {"body": "Edited"}, token=self.rev_token)
        item = self.thread_by_id(self.pr, thread_id)
        self.assertEqual(item["comments"][0]["body"], "Edited")
        self.assertIsNotNone(item["comments"][0]["edited_at"])
        self.fails("PATCH", path, {"body": ""}, token=self.rev_token, status=422)
        # rev2 is an administrator.
        self.ok("PATCH", path, {"body": "Moderated"}, token=self.rev2_token)
        self.ok("DELETE", path, {}, token=self.rev2_token)
        self.fails("DELETE", path, {}, token=self.rev2_token, status=404)
        self.assertNotIn(thread_id, [t["id"] for t in self.threads(self.pr)])

    def test_resolve_and_unresolve_threads(self):
        thread_id, _ = self.thread(self.pr, 5, "Resolve me", token=self.rev_token)
        path = f"{self.p}/threads/{thread_id}/resolution"
        self.fails("PUT", path, {"resolved": "yes"}, status=422)
        self.assertEqual(self.ok("PUT", path, {"resolved": True}), {"resolved": True})
        item = self.thread_by_id(self.pr, thread_id)
        self.assertTrue(item["resolved"])
        self.assertEqual(item["resolved_by"], "alice")
        self.assertEqual(self.merge_status(self.pr)["unresolved_threads"], 0)
        self.ok("PUT", path, {"resolved": False}, token=self.rev_token)
        self.assertFalse(self.thread_by_id(self.pr, thread_id)["resolved"])
        self.fails("PUT", f"{self.p}/threads/999999/resolution", {"resolved": True}, status=404)

    def test_outdated_detection(self):
        changed, _ = self.thread(self.pr, 5, "On the changed line")
        below, _ = self.thread(self.pr, 8, "Further down")
        left, _ = self.thread(self.pr, 2, "Base side", side="LEFT")
        # Insert a line at the top: line 8 shifts to 9 and stays current.
        lines = ["inserted"] + with_line(APP_LINES, 5, "line 5 feature")
        self.commit("feature", "app.py", text_of(lines))
        item = self.thread_by_id(self.pr, below)
        self.assertEqual((item["outdated"], item["line"], item["original_line"]), (False, 9, 8))
        item = self.thread_by_id(self.pr, changed)
        self.assertEqual((item["outdated"], item["line"]), (False, 6))
        # Now rewrite the commented line itself.
        lines = ["inserted"] + with_line(APP_LINES, 5, "line 5 rewritten")
        self.commit("feature", "app.py", text_of(lines))
        item = self.thread_by_id(self.pr, changed)
        self.assertEqual((item["outdated"], item["line"], item["original_line"]), (True, None, 5))
        self.assertFalse(self.thread_by_id(self.pr, below)["outdated"])
        # The merge base did not move, so the LEFT comment is still current.
        self.assertFalse(self.thread_by_id(self.pr, left)["outdated"])

    def test_outdated_multi_line_range(self):
        ranged, _ = self.thread(self.pr, 7, "Lines 6-7", start_line=6)
        self.commit("feature", "app.py", text_of(with_line(APP_LINES, 6, "line 6 changed")))
        item = self.thread_by_id(self.pr, ranged)
        self.assertTrue(item["outdated"])
        self.assertIsNone(item["start_line"])

    def test_apply_suggestion_commits_and_resolves(self):
        body = "Better:\n```suggestion\nline 5 suggested\n```\n"
        thread_id, comment_id = self.thread(self.pr, 5, body, token=self.rev_token)
        before = self.sha("feature")
        result = self.ok(
            "POST",
            f"{self.p}/review-comments/{comment_id}/apply-suggestion",
            {"expected_head_sha": before},
            status=201,
        )
        self.assertEqual(self.sha("feature"), result["sha"])
        parents = run_git("--git-dir", self.bare, "log", "-1", "--format=%P", "feature").split()
        self.assertEqual(parents, [before])
        content = run_git("--git-dir", self.bare, "show", "feature:app.py").splitlines()
        self.assertEqual(content, with_line(APP_LINES, 5, "line 5 suggested"))
        item = self.thread_by_id(self.pr, thread_id)
        self.assertTrue(item["resolved"])
        self.assertEqual(item["resolved_by"], "alice")
        # Applying it again is refused: the suggested lines are already there.
        self.fails(
            "POST",
            f"{self.p}/review-comments/{comment_id}/apply-suggestion",
            {"expected_head_sha": before},
            status=409,
            code="stale",
        )

    def test_apply_multi_line_suggestion(self):
        body = "```suggestion\nsix\nseven\nseven and a half\n```"
        _, comment_id = self.thread(self.pr, 7, body, start_line=6)
        self.ok("POST", f"{self.p}/review-comments/{comment_id}/apply-suggestion", {}, status=201)
        content = run_git("--git-dir", self.bare, "show", "feature:app.py").splitlines()
        expected = with_line(APP_LINES, 5, "line 5 feature")
        expected[5:7] = ["six", "seven", "seven and a half"]
        self.assertEqual(content, expected)

    def test_apply_suggestion_refusals(self):
        suggestion = "```suggestion\nreplacement\n```"
        _, outdated_comment = self.thread(self.pr, 6, suggestion)
        _, pending_comment = self.thread(
            self.pr, 8, suggestion, token=self.rev_token, mode="review"
        )
        _, plain_comment = self.thread(self.pr, 9, "No suggestion here")
        self.commit(
            "feature",
            "app.py",
            text_of(with_line(with_line(APP_LINES, 5, "line 5 feature"), 6, "line 6 moved on")),
        )
        head = self.sha("feature")
        base = f"{self.p}/review-comments"
        self.fails(
            "POST", f"{base}/{outdated_comment}/apply-suggestion", {}, status=409, code="outdated"
        )
        self.fails(
            "POST",
            f"{base}/{pending_comment}/apply-suggestion",
            {},
            token=self.rev_token,
            status=404,
        )
        self.fails(
            "POST", f"{base}/{plain_comment}/apply-suggestion", {}, status=422, code="no_suggestion"
        )
        reader = database.db_create_token(self.rev, "reader", "read")
        self.fails("POST", f"{base}/{plain_comment}/apply-suggestion", {}, token=reader, status=403)
        self.assertEqual(self.sha("feature"), head)

    def test_viewed_files_are_per_viewer_and_reset_on_change(self):
        path = f"{self.p}/viewed-files"
        self.assertEqual(self.ok("GET", path, token=self.rev_token), {"paths": []})
        self.ok("PUT", path, {"path": "app.py", "viewed": True}, token=self.rev_token)
        self.ok("PUT", path, {"path": "new.txt", "viewed": True}, token=self.rev_token)
        self.assertEqual(
            self.ok("GET", path, token=self.rev_token), {"paths": ["app.py", "new.txt"]}
        )
        self.assertEqual(self.ok("GET", path, token=self.alice_token), {"paths": []})
        self.fails("PUT", path, {"path": "app.py", "viewed": "1"}, status=422)
        self.commit("feature", "app.py", text_of(with_line(APP_LINES, 5, "line 5 again")))
        self.assertEqual(self.ok("GET", path, token=self.rev_token), {"paths": ["new.txt"]})
        self.ok("PUT", path, {"path": "new.txt", "viewed": False}, token=self.rev_token)
        self.assertEqual(self.ok("GET", path, token=self.rev_token), {"paths": []})

    def test_repository_archive_moves_review_rows(self):
        self.thread(self.pr, 5, "single", token=self.rev_token)
        self.thread(self.pr, 6, "pending", token=self.rev_token, mode="review")
        self.review(self.pr, "APPROVE", "ok", token=self.rev2_token)
        self.ok("POST", f"{self.p}/requested_reviewers", {"reviewers": ["rev"]}, status=201)

        def counts(conn, schema="main"):
            return {
                table: conn.execute(
                    f"SELECT COUNT(*) FROM {schema}.{table} WHERE pr_id=?", (self.pr,)
                ).fetchone()[0]
                for table in REVIEW_TABLES
            }

        conn = database._db_connect()
        try:
            before = counts(conn)
        finally:
            conn.close()
        self.assertTrue(all(before.values()), before)
        archive = str(self.root / "archive.sqlite3")
        result = database.db_repository_archive("alice", "project", archive)
        for table in REVIEW_TABLES:
            self.assertEqual(result[table], before[table], table)
        conn = database._db_connect()
        try:
            self.assertEqual(set(counts(conn).values()), {0})
        finally:
            conn.close()
        archived = sqlite3.connect(archive)
        try:
            self.assertEqual(
                {
                    table: archived.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in REVIEW_TABLES
                },
                before,
            )
        finally:
            archived.close()


class PullRulesAPITests(_APIFixture):
    POLICIES = {
        "protected_branches": ["main"],
        "required_approvals": 1,
        "dismiss_stale_approvals": True,
        "block_on_changes_requested": True,
        "require_conversation_resolution": True,
    }

    def setUp(self):
        super().setUp()
        self.pr = self.create_pr()
        self.p = f"/pulls/{self.pr}"

    def test_policy_is_reported(self):
        status = self.merge_status(self.pr)
        self.assertTrue(status["protected"])
        self.assertEqual(status["required_approvals"], 1)
        self.assertTrue(status["block_on_changes_requested"])
        self.assertTrue(status["require_conversation_resolution"])
        self.assertEqual(status["blocked_codes"], ["approvals_required"])

    def test_required_approvals_block_until_another_user_approves(self):
        self.fails("PUT", f"{self.p}/merge", {}, status=409, code="approvals_required")
        # The author's own approval is refused and never counts.
        self.fails("POST", f"{self.p}/reviews", {"event": "APPROVE"}, status=422)
        self.review(self.pr, "COMMENT", "just a comment", token=self.rev_token)
        self.fails("PUT", f"{self.p}/merge", {}, status=409, code="approvals_required")
        self.review(self.pr, "APPROVE", token=self.rev_token)
        status = self.merge_status(self.pr)
        self.assertEqual((status["approvals"], status["blocked_codes"]), (1, []))
        self.assertTrue(status["can_merge"])
        self.assertTrue(self.ok("PUT", f"{self.p}/merge", {}, status=200)["merged"])

    def test_unprotected_base_ignores_review_rules(self):
        self.new_branch("develop", "main~1")
        pr = self.create_pr(base="develop")
        status = self.merge_status(pr)
        self.assertFalse(status["protected"])
        self.assertEqual((status["required_approvals"], status["blocked_codes"]), (0, []))
        self.thread(pr, 5, "unresolved", token=self.rev_token)
        self.review(pr, "REQUEST_CHANGES", "no", token=self.rev_token)
        self.assertTrue(self.ok("PUT", f"/pulls/{pr}/merge", {}, status=200)["merged"])

    def test_changes_requested_block_until_dismissed(self):
        self.review(self.pr, "REQUEST_CHANGES", "Fix it", token=self.rev_token)
        self.review(self.pr, "APPROVE", token=self.rev2_token)
        status = self.merge_status(self.pr)
        self.assertEqual(status["blocked_codes"], ["changes_requested"])
        self.assertEqual(status["changes_requested_by"], ["rev"])
        self.fails("PUT", f"{self.p}/merge", {}, status=409, code="changes_requested")
        review_id = self.ok("GET", f"{self.p}/reviews")[0]["id"]
        self.ok("PUT", f"{self.p}/reviews/{review_id}/dismissals", {"message": "Addressed"})
        self.assertEqual(self.merge_status(self.pr)["blocked_codes"], [])
        self.assertTrue(self.ok("PUT", f"{self.p}/merge", {}, status=200)["merged"])

    def test_changes_requested_cleared_by_later_approval(self):
        self.review(self.pr, "REQUEST_CHANGES", "Fix it", token=self.rev_token)
        self.fails("PUT", f"{self.p}/merge", {}, status=409, code="approvals_required")
        self.review(self.pr, "APPROVE", token=self.rev_token)
        self.assertEqual(self.merge_status(self.pr)["blocked_codes"], [])

    def test_conversation_resolution_required(self):
        thread_id, _ = self.thread(self.pr, 5, "Please explain", token=self.rev_token)
        self.review(self.pr, "APPROVE", token=self.rev_token)
        status = self.merge_status(self.pr)
        self.assertEqual(status["blocked_codes"], ["unresolved_conversations"])
        self.assertEqual(status["unresolved_threads"], 1)
        self.fails("PUT", f"{self.p}/merge", {}, status=409, code="unresolved_conversations")
        self.ok("PUT", f"{self.p}/threads/{thread_id}/resolution", {"resolved": True})
        self.assertEqual(self.merge_status(self.pr)["blocked_codes"], [])
        self.assertTrue(self.ok("PUT", f"{self.p}/merge", {}, status=200)["merged"])

    def test_pending_comments_do_not_count_as_unresolved(self):
        self.thread(self.pr, 5, "draft", token=self.rev2_token, mode="review")
        self.review(self.pr, "APPROVE", token=self.rev_token)
        self.assertEqual(self.merge_status(self.pr)["blocked_codes"], [])

    def test_push_over_http_dismisses_stale_approval(self):
        approval = self.review(self.pr, "APPROVE", token=self.rev_token)
        self.assertEqual(self.merge_status(self.pr)["approvals"], 1)
        run_git("-C", self.source, "checkout", "-q", "feature")
        (self.source / "pushed.txt").write_text("pushed over http\n")
        run_git("-C", self.source, "add", ".")
        run_git("-C", self.source, "commit", "-q", "-m", "Pushed commit")
        self.push("feature:feature")
        kinds = self.wait_for_event(self.pr, "committed")
        self.assertIn("committed", kinds)
        event = next(e for e in self.ok("GET", f"{self.p}/events") if e["event"] == "committed")
        self.assertEqual(event["data"]["after"], self.sha("feature"))
        review = self.ok("GET", f"{self.p}/reviews/{approval['id']}")
        self.assertEqual(review["state"], "DISMISSED")
        status = self.merge_status(self.pr)
        self.assertEqual(status["approvals"], 0)
        self.assertIn("approvals_required", status["blocked_codes"])
        # An approval of the new head counts again.
        self.review(self.pr, "APPROVE", token=self.rev_token)
        self.assertEqual(self.merge_status(self.pr)["approvals"], 1)
        # A force push is recorded as such (and also dismisses the approval).
        run_git("-C", self.source, "commit", "-q", "--amend", "-m", "Rewritten commit")
        self.push("feature:feature", force=True)
        kinds = self.wait_for_event(self.pr, "head_ref_force_pushed")
        self.assertIn("head_ref_force_pushed", kinds)
        self.assertEqual(self.merge_status(self.pr)["approvals"], 0)

    def test_update_branch_dismisses_stale_approval(self):
        self.review(self.pr, "APPROVE", token=self.rev_token)
        self.ok("PUT", f"{self.p}/update-branch", {}, status=202)
        self.assertIn("committed", self.wait_for_event(self.pr, "committed"))
        self.assertEqual(self.merge_status(self.pr)["approvals"], 0)

    def test_approval_of_previous_head_does_not_count_before_push_is_recorded(self):
        self.review(self.pr, "APPROVE", token=self.rev_token)
        self.assertEqual(self.merge_status(self.pr)["approvals"], 1)
        self.commit("feature", "extra.txt", "changed head\n")
        self.fails("PUT", f"{self.p}/merge", {}, status=409, code="approvals_required")


# ====================================================================== web UI


class _UIFixture(unittest.TestCase):
    def post(self, path, fields, *, csrf=True, cookie=None):
        if csrf:
            fields = with_csrf(self.server, fields, cookie)
        return self.http("POST", path, urlencode(fields), cookie=cookie)

    def get(self, path, *, cookie=None):
        return self.http("GET", path, None, cookie=cookie)

    def http(self, method, path, body, *, cookie=None):
        headers = {}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie:
            headers["Cookie"] = cookie
        connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=30)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode()
        finally:
            connection.close()

    def page(self, query="", *, cookie=None):
        status, _, body = self.get(self.pr_url + query, cookie=cookie)
        self.assertEqual(status, 200, body[-2000:])
        return body

    def redirected(self, action, fields, *, cookie=None):
        status, headers, body = self.post(self.pr_url + "/" + action, fields, cookie=cookie)
        self.assertEqual(status, 303, body[-3000:])
        location = headers["Location"]
        self.assertTrue(location.startswith(self.pr_url + "?"), location)
        return location


@unittest.skipUnless(HAS_GIT, "requires Git HTTP backend")
class PullPagesTests(_UIFixture):
    """Sign-in disabled: every visitor is the anonymous local user (an administrator)."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="pull-reviews-ui-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.addCleanup(setattr, database, "DB_PATH", database.DB_PATH)
        self.source = build_source(self.root)
        run_git("-C", self.source, "checkout", "-q", "feature")
        (self.source / 'a"<b>.txt').write_text("hostile name\n")
        (self.source / "ws.txt").write_text("alpha\n")
        run_git("-C", self.source, "add", ".")
        run_git("-C", self.source, "commit", "-q", "-m", "Hostile file name")
        run_git("-C", self.source, "checkout", "-q", "main")
        self.bare = self.root / "project.git"
        run_git("clone", "-q", "--bare", self.source, self.bare)
        self.server = ServerRunner(project_root=str(self.root))
        self.server.__enter__()
        self.addCleanup(self.server.__exit__, None, None, None)
        self.base = f"/r/{FLAT_OWNER_UI}/project"
        status, _, body = self.post(
            self.base + "/pulls/create",
            {"title": "UI PR", "body": "", "source_branch": "feature", "target_branch": "main"},
        )
        self.assertEqual(status, 303, body[-2000:])
        self.pr = database.db_pr_list(FLAT_OWNER_UI, "project")[0][0]
        self.pr_url = f"{self.base}/pulls/{self.pr}"

    def test_files_tab_renders_commentable_diff(self):
        page = self.page("?tab=files")
        self.assertIn('class="diff-file diff-file-', page)
        self.assertIn('data-path="app.py"', page)
        self.assertIn('class="diff-add-comment" data-side="RIGHT" data-line="5"', page)
        self.assertIn('data-side="LEFT" data-line="5"', page)
        self.assertIn('<template id="diff-comment-template">', page)
        self.assertIn(f'data-comment-url="{self.pr_url}/review-comments"', page)
        self.assertIn('data-mode="unified"', page)
        self.assertIn("diff-table diff-unified", page)
        self.assertIn(f'action="{self.pr_url}/reviews"', page)
        self.assertIn('name="event" value="APPROVE"', page)
        self.assertIn('name="event" value="REQUEST_CHANGES"', page)
        split = self.page("?tab=files&diff=split")
        self.assertIn('data-mode="split"', split)
        self.assertIn("diff-table diff-split", split)
        self.assertIn('class="btn btn-sm diff-mode-link active" href', split)

    def test_whitespace_toggle_hides_whitespace_only_changes(self):
        commit_file(self.bare, "ws.txt", "alpha   \n", branch="feature")
        page = self.page("?tab=files")
        self.assertIn('data-path="ws.txt"', page)
        self.assertIn("Hide whitespace", page)
        hidden = self.page("?tab=files&w=1")
        self.assertIn("Show whitespace", hidden)
        self.assertIn('data-path="app.py"', hidden)
        # ws.txt is a new file, so it still appears; but app.py's diff must not change.
        self.assertIn("line 5 feature", hidden)

    def test_review_comment_post_requires_csrf_and_shows_on_files_tab(self):
        fields = {"path": "app.py", "side": "RIGHT", "line": "5", "body": "UI inline remark"}
        status, _, _ = self.post(self.pr_url + "/review-comments", fields, csrf=False)
        self.assertEqual(status, 403)
        self.assertEqual(pull_store.list_threads(self.pr, None, False), [])
        location = self.redirected("review-comments", fields)
        query = parse_qs(urlparse(location).query)
        self.assertEqual(query["tab"], ["files"])
        thread_id = pull_store.list_threads(self.pr, None, False)[0]["id"]
        self.assertTrue(location.endswith(f"#thread-{thread_id}"), location)
        page = self.page("?tab=files")
        self.assertIn(f'id="thread-{thread_id}"', page)
        self.assertIn("UI inline remark", page)
        self.assertIn('class="diff-thread-row" data-side="RIGHT" data-line="5"', page)
        conversation = self.page()
        self.assertIn("UI inline remark", conversation)
        # Reply, resolve and invalid input.
        self.redirected(f"threads/{thread_id}/replies", {"body": "UI reply"})
        self.redirected(f"threads/{thread_id}/resolve", {})
        self.assertTrue(pull_store.list_threads(self.pr, None, False)[0]["resolved"])
        status, _, body = self.post(
            self.pr_url + "/review-comments", {"path": "app.py", "line": "999", "body": "x"}
        )
        self.assertEqual(status, 422)
        self.assertIn("That line is not part of the file.", body)

    def test_review_submit_and_pending_review_flow(self):
        self.redirected(
            "review-comments",
            {"path": "app.py", "line": "5", "body": "Pending UI remark", "mode": "review"},
        )
        files = self.page("?tab=files")
        self.assertIn("Finish your review (1)", files)
        self.assertIn('class="pill pill-pending">Pending', files)
        self.assertIn(f'action="{self.pr_url}/reviews/discard"', files)
        location = self.redirected("reviews", {"event": "COMMENT", "body": "Overall fine"})
        self.assertIn("msg=review", location)
        conversation = self.page()
        self.assertIn("Overall fine", conversation)
        self.assertIn("Pending UI remark", conversation)
        self.assertNotIn("Finish your review", self.page("?tab=files"))
        status, _, body = self.post(self.pr_url + "/reviews", {"event": "COMMENT", "body": ""})
        self.assertEqual(status, 422)
        self.assertIn("Write a comment or add review comments.", body)

    def test_merge_form_and_merge(self):
        page = self.page()
        self.assertIn('id="merge-form"', page)
        self.assertIn(f'action="{self.pr_url}/merge"', page)
        self.assertIn('name="merge_method" value="merge" checked', page)
        for method in ("squash", "rebase", "ff"):
            self.assertIn(f'name="merge_method" value="{method}"', page)
        self.assertIn('name="delete_branch" value="1"', page)
        status, _, body = self.post(
            self.pr_url + "/merge", {"merge_method": "squash", "expected_head": "0" * 40}
        )
        self.assertEqual(status, 409)
        self.assertIn("The head branch changed", body)
        location = self.redirected("merge", {"merge_method": "squash", "delete_branch": "1"})
        self.assertIn("msg=merged", location)
        row = database.db_pr_get(self.pr)
        self.assertEqual((row[8], row[12]), ("merged", "squash"))
        page = self.page()
        self.assertIn("Pull request successfully merged and closed", page)
        self.assertIn(f'action="{self.pr_url}/head-branch/restore"', page)

    def test_sidebar_reviewer_request_and_removal(self):
        database.db_create_user("reviewer1", "s3cret-pass", False)
        page = self.page()
        self.assertIn(f'action="{self.pr_url}/reviewers/add"', page)
        self.assertIn('<option value="reviewer1">reviewer1</option>', page)
        self.redirected("reviewers/add", {"reviewer": "reviewer1"})
        page = self.page()
        self.assertIn("<span>reviewer1</span>", page)
        self.assertIn("review-state-pending", page)
        self.assertIn('aria-label="Remove reviewer1"', page)
        status, _, body = self.post(self.pr_url + "/reviewers/add", {"reviewer": "nobody"})
        self.assertEqual(status, 422)
        self.assertIn("Unknown reviewers: nobody", body)
        self.redirected("reviewers/remove", {"reviewer": "reviewer1"})
        self.assertNotIn("<span>reviewer1</span>", self.page())

    def test_draft_toggle(self):
        page = self.page()
        self.assertIn("Convert to draft", page)
        self.redirected("draft", {"draft": "1"})
        page = self.page()
        self.assertIn("Draft pull requests cannot be merged.", page)
        self.assertIn("Ready for review", page)
        self.assertNotIn('id="merge-form"', page)
        status, _, _ = self.post(self.pr_url + "/merge", {"merge_method": "merge"})
        self.assertEqual(status, 409)
        self.redirected("draft", {"draft": "0"})
        self.assertIn('id="merge-form"', self.page())

    def test_hostile_comment_bodies_and_paths_are_escaped(self):
        hostile = '<script>alert("x")</script><img src=x onerror=alert(1)>'
        self.redirected("review-comments", {"path": "app.py", "line": "5", "body": hostile})
        self.redirected(
            "review-comments", {"path": 'a"<b>.txt', "line": "1", "body": "on hostile file"}
        )
        for query in ("", "?tab=files", "?tab=files&diff=split"):
            with self.subTest(query=query):
                page = self.page(query)
                self.assertNotIn("<script>alert", page)
                self.assertNotIn("<img src=x", page)
                self.assertNotIn('a"<b>.txt', page)
                self.assertIn("&lt;script&gt;alert(", page)
        files = self.page("?tab=files")
        self.assertIn(
            'data-path="a&#34;&lt;b&gt;.txt"'.replace("&#34;", _quote_entity(files)), files
        )
        self.assertIn("on hostile file", files)

    def test_suggestion_ui_commit_button(self):
        body = "```suggestion\nline 5 from ui\n```"
        self.redirected("review-comments", {"path": "app.py", "line": "5", "body": body})
        comment = pull_store.list_threads(self.pr, None, False)[0]["comments"][0]
        page = self.page("?tab=files")
        action = f"{self.pr_url}/review-comments/{comment['id']}/apply-suggestion"
        self.assertIn(f'action="{action}"', page)
        self.assertIn("Commit suggestion", page)
        self.redirected(f"review-comments/{comment['id']}/apply-suggestion", {})
        content = run_git("--git-dir", self.bare, "show", "feature:app.py")
        self.assertIn("line 5 from ui", content)


def _quote_entity(page):
    """The entity the page's escaper uses for a double quote."""
    return "&quot;" if "&quot;" in page else "&#34;"


@unittest.skipUnless(HAS_GIT, "requires Git HTTP backend")
class SignedInPullPagesTests(_UIFixture):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="pull-reviews-auth-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.addCleanup(setattr, database, "DB_PATH", database.DB_PATH)
        self.source = build_source(self.root)
        (self.root / "alice").mkdir()
        self.bare = self.root / "alice" / "project.git"
        run_git("clone", "-q", "--bare", self.source, self.bare)
        self.server = ServerRunner(project_root=str(self.root))
        self.server.__enter__()
        self.addCleanup(self.server.__exit__, None, None, None)
        self.addCleanup(setattr, application, "REQUIRE_AUTH", application.REQUIRE_AUTH)
        application.REQUIRE_AUTH = True
        database.db_create_user("alice", "s3cret-pass", False)
        database.db_create_user("root", "s3cret-pass", True)
        database.db_create_user("carol", "s3cret-pass", True)
        self.alice = database.db_get_user_by_username("alice")[0]
        self.admin = database.db_get_user_by_username("root")[0]
        self.alice_cookie = (
            application.SESSION_COOKIE_NAME + "=" + database.db_create_session(self.alice)
        )
        self.admin_cookie = (
            application.SESSION_COOKIE_NAME + "=" + database.db_create_session(self.admin)
        )
        self.pr = pull_store.create_pull(
            "alice", "project", "Signed-in PR", "", "feature", "main", self.alice, False
        )
        self.pr_url = f"/r/alice/project/pulls/{self.pr}"

    def comment(self, cookie, body, line="5"):
        self.redirected(
            "review-comments", {"path": "app.py", "line": line, "body": body}, cookie=cookie
        )
        threads = pull_store.list_threads(self.pr, None, False)
        return threads[-1]["comments"][0]["id"]

    def test_anonymous_visitor_is_sent_to_login(self):
        status, headers, _ = self.get(self.pr_url)
        self.assertIn(status, (302, 303, 401))

    def test_reviewer_state_badges_in_sidebar(self):
        self.redirected("reviewers/add", {"reviewer": "carol"}, cookie=self.alice_cookie)
        self.redirected(
            "reviews", {"event": "APPROVE", "body": "Ship it"}, cookie=self.admin_cookie
        )
        page = self.page(cookie=self.alice_cookie)
        sidebar = page[page.index('class="review-sidebar') :]
        self.assertRegex(
            sidebar, r"<span>root</span><span class=\"review-state review-state-approved\""
        )
        self.assertRegex(
            sidebar, r"<span>carol</span><span class=\"review-state review-state-pending\""
        )
        # The author cannot approve their own pull request; the form disables the choice.
        files = self.page("?tab=files", cookie=self.alice_cookie)
        self.assertIn('name="event" value="APPROVE" disabled', files)
        status, _, body = self.post(
            self.pr_url + "/reviews", {"event": "APPROVE"}, cookie=self.alice_cookie
        )
        self.assertEqual(status, 422)
        self.assertIn("You cannot approve your own pull request.", body)
        self.redirected(
            "reviews", {"event": "REQUEST_CHANGES", "body": "Wait"}, cookie=self.admin_cookie
        )
        sidebar = self.page(cookie=self.alice_cookie)
        self.assertIn("review-state-changes", sidebar)

    def test_comment_edit_and_delete_permissions(self):
        admin_comment = self.comment(self.admin_cookie, "Admin remark")
        alice_comment = self.comment(self.alice_cookie, "Alice remark", line="6")
        page = self.page("?tab=files", cookie=self.alice_cookie)
        self.assertIn(f'action="{self.pr_url}/review-comments/{alice_comment}/edit"', page)
        self.assertNotIn(f'action="{self.pr_url}/review-comments/{admin_comment}/edit"', page)
        status, _, _ = self.post(
            f"{self.pr_url}/review-comments/{admin_comment}/edit",
            {"body": "Hijacked"},
            cookie=self.alice_cookie,
        )
        self.assertEqual(status, 403)
        status, _, _ = self.post(
            f"{self.pr_url}/review-comments/{admin_comment}/delete", {}, cookie=self.alice_cookie
        )
        self.assertEqual(status, 403)
        bodies = [t["comments"][0]["body"] for t in pull_store.list_threads(self.pr, None, False)]
        self.assertEqual(bodies, ["Admin remark", "Alice remark"])
        # An administrator may moderate anyone's comment.
        admin_page = self.page("?tab=files", cookie=self.admin_cookie)
        self.assertIn(f'action="{self.pr_url}/review-comments/{alice_comment}/edit"', admin_page)
        self.redirected(
            f"review-comments/{alice_comment}/edit", {"body": "Moderated"}, cookie=self.admin_cookie
        )
        self.redirected(f"review-comments/{admin_comment}/delete", {}, cookie=self.admin_cookie)
        bodies = [t["comments"][0]["body"] for t in pull_store.list_threads(self.pr, None, False)]
        self.assertEqual(bodies, ["Moderated"])
        # The author edits their own comment.
        self.redirected(
            f"review-comments/{alice_comment}/edit",
            {"body": "Mine again"},
            cookie=self.alice_cookie,
        )
        bodies = [t["comments"][0]["body"] for t in pull_store.list_threads(self.pr, None, False)]
        self.assertEqual(bodies, ["Mine again"])

    def test_pending_review_hidden_from_other_signed_in_user(self):
        self.redirected(
            "review-comments",
            {"path": "app.py", "line": "5", "body": "Secret draft", "mode": "review"},
            cookie=self.admin_cookie,
        )
        self.assertIn("Secret draft", self.page("?tab=files", cookie=self.admin_cookie))
        self.assertNotIn("Secret draft", self.page("?tab=files", cookie=self.alice_cookie))
        self.assertNotIn("Secret draft", self.page(cookie=self.alice_cookie))


if __name__ == "__main__":
    unittest.main()
