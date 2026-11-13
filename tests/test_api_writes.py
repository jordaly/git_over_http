import asyncio
import base64
import hashlib
import json
import os
import secrets
import shutil
import unittest
from unittest import mock

from pygithost import database
from pygithost.api import mutations
from tests import test_api as read_tests
from tests.test_server import _which_git_backend


@unittest.skipUnless(shutil.which("git") and _which_git_backend(), "requires Git HTTP backend")
class APIWriteTests(unittest.TestCase):
    # Reuse the HTTP/Git fixture without inheriting its read-only test methods.
    git = read_tests.APITests.git
    user = read_tests.APITests.user
    request = read_tests.APITests.request
    tearDown = read_tests.APITests.tearDown

    def setUp(self):
        read_tests.APITests.setUp(self)
        self.write_token = database.db_create_token(self.alice, "writer", "write")
        self.admin_write_token = database.db_create_token(self.admin, "writer", "write")

    def mutate(self, path, document, *, method="POST", key=None, token=None):
        return self.request(path, method=method, token=token or self.write_token,
            headers={"Content-Type": "application/json", "Idempotency-Key": key or secrets.token_hex(16)},
            body=json.dumps(document))

    def test_write_scope_required_even_for_administrators(self):
        for token in (self.token, self.admin_token):
            status, _headers, result = self.mutate(self.base + "/issues", {"title": "Denied"}, token=token)
            self.assertEqual(status, 403)
            self.assertEqual(result["code"], "insufficient_scope")
        status, _headers, _result = self.mutate("/api/v1/repos/bob/project/issues", {"title": "Denied"})
        self.assertEqual(status, 404)
        self.assertEqual(database.db_issue_count("alice", "project"), 1)

    def test_issue_creation_idempotency_conflicts_and_audit(self):
        path, key = self.base + "/issues", "create-issue-once"
        status, _headers, result = self.mutate(path, {"title": "API issue", "body": "From API"}, key=key)
        self.assertEqual(status, 201, result)
        self.assertEqual(result["user"]["id"], self.alice)
        status, headers, replay = self.mutate(path, {"body": "From API", "title": "API issue"}, key=key)
        self.assertEqual(status, 201)
        self.assertEqual(result, replay)
        self.assertEqual(headers["X-Idempotent-Replay"], "true")
        self.assertEqual(database.db_issue_count("alice", "project"), 2)
        status, _headers, value = self.mutate(path, {"title": "Different"}, key=key)
        self.assertEqual(status, 409)
        self.assertEqual(value["code"], "idempotency_conflict")
        conn = database._db_connect()
        try:
            row = conn.execute("SELECT method,path,state,status,key_hash FROM api_mutations WHERE user_id=?",
                               (self.alice,)).fetchone()
            self.assertEqual(row[:4], ("POST", path, "completed", 201))
            self.assertNotEqual(row[4], key)
        finally:
            conn.close()

    def test_issue_edits_check_revision_and_web_edits(self):
        path = self.base + f"/issues/{self.issue}"
        old = self.request(path)[2]
        status, _headers, result = self.mutate(path, {
            "title": "Changed", "state": "closed", "expected_revision": old["revision"]}, method="PATCH")
        self.assertEqual(status, 200, result)
        self.assertEqual(result["state"], "closed")
        self.assertNotEqual(result["revision"], old["revision"])
        status, _headers, value = self.mutate(path, {
            "title": "Stale", "expected_revision": old["revision"]}, method="PATCH")
        self.assertEqual(status, 409)
        self.assertEqual(value["code"], "revision_conflict")
        database.db_issue_update_text(self.issue, "Web edit", "New body")
        self.assertEqual(self.mutate(path, {"body": "Lost update", "expected_revision": result["revision"]},
                                    method="PATCH")[0], 409)
        self.assertEqual(self.request(path)[2]["title"], "Web edit")

    def test_comments_create_edit_delete_and_author_permissions(self):
        parent = self.base + f"/issues/{self.issue}/comments"
        status, _headers, comment = self.mutate(parent, {"body": "API comment"})
        self.assertEqual(status, 201, comment)
        path = parent + "/" + str(comment["id"])
        self.assertEqual(self.request(path)[2], comment)
        status, _headers, updated = self.mutate(path, {
            "body": "Edited", "expected_revision": comment["revision"]}, method="PATCH")
        self.assertEqual(status, 200, updated)
        self.assertEqual(updated["body"], "Edited")
        self.assertEqual(self.mutate(path, {"expected_revision": comment["revision"]}, method="DELETE")[0], 409)
        self.assertEqual(self.mutate(path, {"expected_revision": updated["revision"]}, method="DELETE")[0], 200)
        self.assertEqual(self.mutate(path, {"expected_revision": updated["revision"]}, method="DELETE")[0], 404)
        foreign = database.db_issue_comment_add(self.issue, self.bob, "Bob's comment")
        row = next(c for c in self.request(parent)[2] if c["id"] == foreign)
        foreign_path = parent + "/" + str(foreign)
        self.assertEqual(self.mutate(foreign_path, {"expected_revision": row["revision"]}, method="DELETE")[0], 403)
        self.assertEqual(self.mutate(foreign_path, {"expected_revision": row["revision"]},
                                    method="DELETE", token=self.admin_write_token)[0], 200)
        wrong = f"/api/v1/repos/bob/project/issues/{self.issue}/comments/{foreign}"
        self.assertEqual(self.mutate(wrong, {"expected_revision": row["revision"]},
                                    method="DELETE", token=self.admin_write_token)[0], 404)

    def test_branch_create_delete_protection_and_cas(self):
        status, _headers, result = self.mutate(self.base + "/branches", {"name": "api/new", "sha": self.sha})
        self.assertEqual(status, 201, result)
        self.assertEqual(self.request(self.base + "/branches/api%2Fnew")[0], 200)
        path = self.base + "/branches/api%2Fnew"
        self.assertEqual(self.mutate(path, {"expected_head": "f" * 40}, method="DELETE")[0], 409)
        self.assertEqual(self.mutate(path, {"expected_head": self.sha}, method="DELETE")[0], 200)
        self.assertEqual(self.mutate(self.base + "/branches/main",
                                    {"expected_head": self.sha}, method="DELETE")[0], 403)
        database.db_ci_config_set("alice", "project", json.dumps({
            "block_direct_pushes": True, "protected_branches": "release/*"}))
        self.assertEqual(self.mutate(self.base + "/branches", {"name": "release/prod", "sha": self.sha})[0], 403)
        self.assertEqual(self.mutate(self.base + "/branches", {"name": "bad\nname", "sha": self.sha})[0], 422)
        self.assertEqual(self.mutate(self.base + "/branches", {"name": "ok", "sha": "main"})[0], 422)

    def test_repository_create_is_owned_and_does_not_overwrite(self):
        document = {"name": "created", "default_branch": "trunk"}
        status, _headers, result = self.mutate("/api/v1/user/repos", document, key="repo-once")
        self.assertEqual(status, 201, result)
        self.assertEqual(result["full_name"], "alice/created")
        self.assertEqual(self.request("/api/v1/repos/alice/created")[2]["default_branch"], "trunk")
        self.assertEqual(self.mutate("/api/v1/user/repos", document, key="repo-once")[0], 201)
        self.assertEqual(self.mutate("/api/v1/user/repos", document)[0], 409)
        self.assertEqual(self.mutate("/api/v1/user/repos", {"name": "../bad"})[0], 422)
        self.assertEqual(self.mutate("/api/v1/user/repos", {"name": "bad", "owner": "bob"})[0], 422)

    def test_file_read_write_delete_and_stale_branch_rejection(self):
        status, _headers, old = self.request(self.base + "/contents/README.md?branch=main")
        self.assertEqual(status, 200, old)
        self.assertEqual(base64.b64decode(old["content"]), b"API fixture\n")
        content = base64.b64encode(b"Changed through API\n").decode()
        doc = {"branch": "main", "expected_head": self.sha, "message": "API edit", "content": content}
        status, _headers, result = self.mutate(self.base + "/contents/README.md", doc, method="PUT", key="file-once")
        self.assertEqual(status, 200, result)
        self.assertNotEqual(result["commit"]["sha"], self.sha)
        self.assertEqual(self.mutate(self.base + "/contents/README.md", doc, method="PUT", key="file-once")[0], 200)
        self.assertEqual(self.mutate(self.base + "/contents/README.md", doc, method="PUT")[0], 409)
        current = self.request(self.base + "/contents/README.md")[2]
        self.assertEqual(base64.b64decode(current["content"]), b"Changed through API\n")
        status, _headers, result = self.mutate(self.base + "/contents/README.md",
            {"branch": "main", "expected_head": current["commit_sha"], "message": "Remove file"}, method="DELETE")
        self.assertEqual(status, 200, result)
        self.assertEqual(self.request(self.base + "/contents/README.md")[0], 404)

    def test_file_safety_and_protections(self):
        doc = {"branch": "main", "expected_head": self.sha, "message": "Write",
               "content": base64.b64encode(b"new text").decode()}
        for filename in ("../outside", ".git/config", "safe/../../outside"):
            self.assertEqual(self.mutate(self.base + "/contents/" + filename, doc, method="PUT")[0], 422)
        invalid = {**doc, "content": "not base64!"}
        self.assertEqual(self.mutate(self.base + "/contents/new.txt", invalid, method="PUT")[0], 422)
        invalid["content"] = base64.b64encode(b"\0binary").decode()
        self.assertEqual(self.mutate(self.base + "/contents/new.txt", invalid, method="PUT")[0], 422)
        database.db_ci_config_set("alice", "project", json.dumps({
            "block_direct_pushes": True, "protected_branches": "main"}))
        self.assertEqual(self.mutate(self.base + "/contents/new.txt", doc, method="PUT")[0], 403)

    def test_new_file_creation_and_ci_scheduling_failure_are_not_repeated(self):
        path = self.base + "/contents/ci/test.sh"
        doc = {"branch": "main", "expected_head": self.sha, "message": "Add helper",
               "content": base64.b64encode(b"echo tests\n").decode()}
        with mock.patch.object(self.server.app, "_queue_push_changes", side_effect=RuntimeError("SCHEDULER_SECRET")):
            status, _headers, result = self.mutate(path, doc, method="PUT", key="new-file")
        self.assertEqual(status, 201, result)
        self.assertIn("warnings", result)
        self.assertNotIn("SCHEDULER_SECRET", json.dumps(result))
        current = self.request(path)[2]
        self.assertEqual(base64.b64decode(current["content"]), b"echo tests\n")
        self.assertEqual(self.mutate(path, doc, method="PUT", key="new-file")[0], 201)
        self.assertEqual(self.request(path)[2]["commit_sha"], current["commit_sha"])

    def test_pull_create_update_merge_and_idempotency(self):
        self.git("-C", self.source, "checkout", "-b", "new-feature")
        (self.source / "new.txt").write_text("Feature\n")
        self.git("-C", self.source, "add", ".")
        self.git("-C", self.source, "commit", "-m", "Feature")
        source_sha = self.git("-C", self.source, "rev-parse", "HEAD")
        self.git("-C", self.source, "push", self.bare, "new-feature")
        status, _headers, pull = self.mutate(self.base + "/pulls", {
            "title": "API PR", "head": "new-feature", "base": "main"})
        self.assertEqual(status, 201, pull)
        path = self.base + f"/pulls/{pull['id']}"
        status, _headers, pull = self.mutate(path, {
            "body": "Updated", "expected_revision": pull["revision"]}, method="PATCH")
        self.assertEqual(status, 200, pull)
        merge_path = path + "/merge"
        doc = {"sha": source_sha, "expected_base_sha": self.sha}
        self.assertEqual(self.mutate(merge_path, {**doc, "sha": "f" * 40}, method="PUT")[0], 409)
        status, _headers, result = self.mutate(merge_path, doc, method="PUT", key="merge-once")
        self.assertEqual(status, 200, result)
        self.assertTrue(result["merged"])
        self.assertEqual(self.git("--git-dir", self.bare, "rev-parse", "main"), source_sha)
        self.assertEqual(self.request(path)[2]["state"], "merged")
        self.assertEqual(self.mutate(merge_path, doc, method="PUT", key="merge-once")[0], 200)
        self.assertEqual(self.mutate(path, {"state": "open", "expected_revision": self.request(path)[2]["revision"]},
                                    method="PATCH")[0], 409)

    def test_merge_ci_gate_and_closed_pull_rejection(self):
        path = self.base + f"/pulls/{self.pull}/merge"
        database.db_ci_config_set("alice", "project", json.dumps({"require_ci": True}))
        doc = {"sha": self.sha, "expected_base_sha": self.sha}
        status, _headers, result = self.mutate(path, doc, method="PUT")
        self.assertEqual(status, 409, result)
        self.assertEqual(result["code"], "ci_required")
        database.db_pr_close(self.pull)
        self.assertEqual(self.mutate(path, doc, method="PUT")[0], 409)

    def test_json_validation_and_idempotency_key_requirement(self):
        path = self.base + "/issues"
        for raw in ('{"title":"one","title":"two"}', '{"title":NaN}', '{"title":1e999}', "[]", '{"title":"\\ud800"}'):
            status, _headers, _result = self.request(path, method="POST", token=self.write_token, body=raw,
                headers={"Content-Type": "application/json", "Idempotency-Key": secrets.token_hex(8)})
            self.assertIn(status, (400, 422))
        self.assertEqual(self.request(path, method="POST", token=self.write_token, body='{"title":"ok"}',
                                      headers={"Content-Type": "application/json"})[0], 422)
        self.assertEqual(self.request(path, method="POST", token=self.write_token, body="{}",
            headers={"Content-Type": "text/plain", "Idempotency-Key": "type"})[0], 415)
        self.assertEqual(self.mutate(path, {"title": "OK", "user_id": self.bob})[0], 422)
        self.assertEqual(self.mutate(path, {"title": ""})[0], 422)
        self.assertEqual(self.request(path, method="POST", token=self.write_token, body="{}",
            headers={"Content-Type": "application/json", "Idempotency-Key": "oversized",
                     "Content-Length": "2097153"})[0], 413)

    def test_pending_claim_is_not_reexecuted_and_replay_rechecks_access(self):
        key = "pending"
        path, document = self.base + "/issues", {"title": "Pending"}
        fingerprint = hashlib.sha256(("POST\n" + path + "\n" +
            json.dumps(document, sort_keys=True, ensure_ascii=True)).encode()).hexdigest()
        mutations.claim(self.alice, key, fingerprint, "request", "POST", path)
        status, _headers, result = self.mutate(path, document, key=key)
        self.assertEqual(status, 409)
        self.assertEqual(result["code"], "operation_pending")
        status, _headers, created = self.mutate(self.base + "/issues", {"title": "Once"}, key="permission")
        self.assertEqual(status, 201, created)
        conn = database._db_connect()
        try:
            conn.execute("UPDATE users SET is_active=0 WHERE id=?", (self.alice,))
        finally:
            conn.close()
        self.assertEqual(self.mutate(self.base + "/issues", {"title": "Once"}, key="permission")[0], 401)
        bob_path = "/api/v1/repos/bob/project/issues"
        self.assertEqual(self.mutate(bob_path, {"title": "Administrator write"},
                                    key="admin-access", token=self.admin_write_token)[0], 201)
        conn = database._db_connect()
        try:
            conn.execute("UPDATE users SET is_admin=0 WHERE id=?", (self.admin,))
        finally:
            conn.close()
        self.assertEqual(self.mutate(bob_path, {"title": "Administrator write"},
                                    key="admin-access", token=self.admin_write_token)[0], 404)

    def test_success_before_cache_failure_is_never_automatically_reexecuted(self):
        path, doc, key = self.base + "/issues", {"title": "Created before failure"}, "uncertain"
        with mock.patch("pygithost.api.mutations.complete", side_effect=RuntimeError("FAILURE_SECRET")):
            status, _headers, result = self.mutate(path, doc, key=key)
        self.assertEqual(status, 500, result)
        self.assertNotIn("FAILURE_SECRET", json.dumps(result))
        self.assertEqual(database.db_issue_count("alice", "project"), 2)
        status, _headers, result = self.mutate(path, doc, key=key)
        self.assertEqual(status, 409)
        self.assertEqual(result["code"], "operation_pending")
        self.assertEqual(database.db_issue_count("alice", "project"), 2)

    def test_response_timeout_does_not_cancel_mutation(self):
        from pygithost.api import writes
        original = writes.route
        release = asyncio.Event()
        path, doc, key = self.base + "/issues", {"title": "Finish after timeout"}, "detached"

        async def delayed(api, target):
            await release.wait()
            return await original(api, target)

        with mock.patch("pygithost.api.router.RESPONSE_TIMEOUT", 0.1), mock.patch(
                "pygithost.api.writes.route", side_effect=delayed):
            status, _headers, result = self.mutate(path, doc, key=key)
        self.assertEqual(status, 504, result)
        self.server.loop.call_soon_threadsafe(release.set)

        async def drain():
            await asyncio.gather(*tuple(self.server.app.push_finalizers))

        asyncio.run_coroutine_threadsafe(drain(), self.server.loop).result(timeout=10)
        status, headers, result = self.mutate(path, doc, key=key)
        self.assertEqual(status, 201, result)
        self.assertEqual(headers["X-Idempotent-Replay"], "true")
        self.assertEqual(database.db_issue_count("alice", "project"), 2)

    @unittest.skipUnless(os.name == "posix", "executable receive hook")
    def test_file_writes_honor_receive_hooks_and_leave_branch_unchanged(self):
        hook = self.bare / "hooks/pre-receive"
        hook.write_text("#!/bin/sh\necho PRIVATE_HOOK_FAILURE >&2\nexit 1\n")
        hook.chmod(0o700)
        doc = {"branch": "main", "expected_head": self.sha, "message": "Blocked",
               "content": base64.b64encode(b"Should not commit").decode()}
        status, _headers, result = self.mutate(self.base + "/contents/README.md", doc, method="PUT")
        self.assertEqual(status, 409, result)
        self.assertNotIn("PRIVATE_HOOK_FAILURE", json.dumps(result))
        self.assertEqual(self.git("--git-dir", self.bare, "rev-parse", "main"), self.sha)

    def test_file_edits_reject_checked_out_server_branch(self):
        self.git("--git-dir", self.bare, "worktree", "add", self.root / "checkout", "main")
        doc = {"branch": "main", "expected_head": self.sha, "message": "Blocked",
               "content": base64.b64encode(b"Should not commit").decode()}
        status, _headers, result = self.mutate(self.base + "/contents/README.md", doc, method="PUT")
        self.assertEqual(status, 409, result)
        self.assertEqual(self.git("--git-dir", self.bare, "rev-parse", "main"), self.sha)

    def test_openapi_describes_safe_writes_and_revision_fields(self):
        schema = self.request("/api/v1/openapi.json")[2]
        paths = schema["paths"]
        self.assertIn("post", paths["/user/repos"])
        base = "/repos/{owner}/{repo}"
        self.assertIn("put", paths[base + "/contents/{path}"])
        self.assertIn("patch", paths[base + "/issues/{id}"])
        operation = paths[base + "/pulls/{id}/merge"]["put"]
        self.assertTrue(any(p["name"] == "Idempotency-Key" and p["required"] for p in operation["parameters"]))
        self.assertEqual(set(operation["requestBody"]["content"]["application/json"]["schema"]["required"]),
                         {"sha", "expected_base_sha"})
        self.assertIn("revision", schema["components"]["schemas"]["Issue"]["required"])
