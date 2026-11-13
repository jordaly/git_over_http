import shutil
import unittest

from pygithost import database
from tests import test_api as read_tests
from tests import test_api_writes as write_tests
from tests.test_server import _which_git_backend


@unittest.skipUnless(shutil.which("git") and _which_git_backend(), "requires Git HTTP backend")
class APIDiscussionTests(unittest.TestCase):
    git = read_tests.APITests.git
    user = read_tests.APITests.user
    request = read_tests.APITests.request
    tearDown = read_tests.APITests.tearDown
    mutate = write_tests.APIWriteTests.mutate

    def setUp(self):
        read_tests.APITests.setUp(self)
        self.write_token = database.db_create_token(self.alice, "Discussion writer", "write")
        self.admin_write_token = database.db_create_token(self.admin, "Discussion writer", "write")
        self.discussion = database.db_discussion_create("alice", "project", "Q&A", "Question", "Original body", self.alice)
        self.comment = database.db_discussion_comment_add(self.discussion, self.alice, "Original answer")
        self.discussions = self.base + "/discussions"
        self.path = self.discussions + "/" + str(self.discussion)
        self.comments = self.path + "/comments"

    def update(self, path=None, **changes):
        path = path or self.path
        current = self.request(path)[2]
        return self.mutate(path, {"expected_revision": current["revision"], **changes}, method="PATCH")

    def test_categories_and_filtered_paginated_discussion_reads(self):
        status, _headers, categories = self.request(self.discussions + "/categories")
        self.assertEqual(status, 200)
        self.assertEqual(len(categories), 5)
        self.assertTrue(next(c for c in categories if c["name"] == "Q&A")["accepts_answers"])
        database.db_discussion_create("alice", "project", "General", "Another topic", "", None)
        status, headers, rows = self.request(self.discussions + "?per_page=1")
        self.assertEqual(status, 200)
        self.assertIn('rel="next"', headers["Link"])
        self.assertIsNone(rows[0]["user"])
        rows = self.request(self.discussions + "?category=Q%26A")[2]
        self.assertEqual([r["id"] for r in rows], [self.discussion])
        self.assertTrue(rows[0]["created_at"].endswith("Z"))
        self.assertEqual(self.request(self.discussions + "?locked=true")[2], [])
        self.assertEqual(self.request(self.discussions + "?category=Unknown")[0], 400)
        self.assertEqual(self.request(self.discussions + "?locked=1")[0], 400)

    def test_create_discussion_records_actor_and_replays_idempotently(self):
        doc = {"title": "API discussion", "category": "Ideas", "body": "New idea"}
        status, _headers, created = self.mutate(self.discussions, doc, key="discussion-once")
        self.assertEqual(status, 201, created)
        self.assertEqual(created["user"]["id"], self.alice)
        self.assertFalse(created["locked"])
        self.assertIsNone(created["answered_comment_id"])
        status, headers, replay = self.mutate(self.discussions, doc, key="discussion-once")
        self.assertEqual(status, 201)
        self.assertEqual(headers["X-Idempotent-Replay"], "true")
        self.assertEqual(replay, created)
        self.assertEqual(database.db_discussion_count("alice", "project"), 2)
        self.assertEqual(self.request(self.discussions + "/" + str(created["id"]))[2], created)

    def test_create_defaults_and_strict_validation(self):
        created = self.mutate(self.discussions, {"title": "Default category"})[2]
        self.assertEqual(created["category"], "General")
        self.assertEqual(created["body"], "")
        for doc in ({"title": ""}, {"title": "x", "category": "unknown"}, {"title": "x", "author_user_id": self.bob},
                    {"title": False}, {"title": "x" * 257}):
            self.assertEqual(self.mutate(self.discussions, doc)[0], 422)

    def test_edits_require_current_revision_including_web_edits(self):
        previous = self.request(self.path)[2]
        status, _headers, edited = self.update(title="Edited title", body="New body")
        self.assertEqual(status, 200, edited)
        self.assertEqual(edited["title"], "Edited title")
        self.assertNotEqual(edited["revision"], previous["revision"])
        self.assertEqual(self.mutate(self.path, {
            "title": "Stale edit", "expected_revision": previous["revision"]}, method="PATCH")[0], 409)
        database.db_discussion_update_text(self.discussion, "Q&A", "Web edit", "Changed in the UI")
        self.assertEqual(self.mutate(self.path, {
            "title": "Another stale edit", "expected_revision": edited["revision"]}, method="PATCH")[0], 409)
        self.assertEqual(self.request(self.path)[2]["title"], "Web edit")

    def test_lock_blocks_new_replies_even_for_admin_and_unlock_restores_them(self):
        status, _headers, locked = self.update(locked=True)
        self.assertEqual(status, 200, locked)
        self.assertTrue(locked["locked"])
        self.assertEqual(locked["locked_by"], self.alice)
        self.assertEqual(len(self.request(self.discussions + "?locked=true")[2]), 1)
        for token in (self.write_token, self.admin_write_token):
            status, _headers, result = self.mutate(self.comments, {"body": "Blocked reply"}, token=token)
            self.assertEqual(status, 409)
            self.assertEqual(result["code"], "discussion_locked")
        self.assertEqual(database.db_discussion_comment_count(self.discussion), 1)
        status, _headers, unlocked = self.update(locked=False)
        self.assertEqual(status, 200)
        self.assertFalse(unlocked["locked"])
        self.assertIsNone(unlocked["locked_by"])
        self.assertEqual(self.mutate(self.comments, {"body": "Allowed again"})[0], 201)
        self.assertEqual(self.update(locked=1)[0], 422)

    def test_comments_support_reads_edits_deletes_and_idempotency(self):
        status, _headers, created = self.mutate(self.comments, {"body": "New comment"}, key="reply-once")
        self.assertEqual(status, 201, created)
        self.assertEqual(self.mutate(self.comments, {"body": "New comment"}, key="reply-once")[2], created)
        path = self.comments + "/" + str(created["id"])
        self.assertEqual(self.request(path)[2], created)
        status, _headers, edited = self.update(path, body="Edited comment")
        self.assertEqual(status, 200, edited)
        self.assertEqual(edited["body"], "Edited comment")
        self.assertEqual(self.mutate(path, {"expected_revision": created["revision"]}, method="DELETE")[0], 409)
        status, _headers, deleted = self.mutate(path, {"expected_revision": edited["revision"]}, method="DELETE")
        self.assertEqual(status, 200, deleted)
        self.assertTrue(deleted["deleted"])
        self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.request(self.comments + "?per_page=1")[2][0]["id"], self.comment)

    def test_only_comment_author_or_admin_can_edit_or_delete(self):
        foreign = database.db_discussion_comment_add(self.discussion, self.bob, "Bob's answer")
        path = self.comments + "/" + str(foreign)
        current = self.request(path)[2]
        for method in ("PATCH", "DELETE"):
            doc = {"expected_revision": current["revision"]}
            if method == "PATCH":
                doc["body"] = "Unauthorized edit"
            self.assertEqual(self.mutate(path, doc, method=method)[0], 403)
        status, _headers, result = self.mutate(path, {
            "body": "Admin edit", "expected_revision": current["revision"]}, method="PATCH", token=self.admin_write_token)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["body"], "Admin edit")
        self.assertEqual(self.mutate(path, {"expected_revision": result["revision"]},
                                    method="DELETE", token=self.admin_write_token)[0], 200)

    def test_accepted_answer_can_be_set_unset_and_cleared_on_deletion(self):
        status, _headers, answered = self.update(answered_comment_id=self.comment)
        self.assertEqual(status, 200, answered)
        self.assertEqual(answered["answered_comment_id"], self.comment)
        self.assertIsNone(self.update(answered_comment_id=None)[2]["answered_comment_id"])
        self.update(answered_comment_id=self.comment)
        path = self.comments + "/" + str(self.comment)
        comment = self.request(path)[2]
        self.assertEqual(self.mutate(path, {"expected_revision": comment["revision"]}, method="DELETE")[0], 200)
        self.assertIsNone(self.request(self.path)[2]["answered_comment_id"])

    def test_deleting_another_reply_does_not_clear_the_current_answer(self):
        self.update(answered_comment_id=self.comment)
        other = self.mutate(self.comments, {"body": "Another reply"})[2]
        path = self.comments + "/" + str(other["id"])
        self.assertEqual(self.mutate(path, {"expected_revision": other["revision"]}, method="DELETE")[0], 200)
        self.assertEqual(self.request(self.path)[2]["answered_comment_id"], self.comment)

    def test_comment_web_edit_invalidates_api_revision(self):
        path = self.comments + "/" + str(self.comment)
        original = self.request(path)[2]
        database.db_discussion_comment_update(self.comment, "Edited through web helpers")
        status, _headers, result = self.mutate(path, {
            "body": "Stale API edit", "expected_revision": original["revision"]}, method="PATCH")
        self.assertEqual(status, 409, result)
        self.assertEqual(self.request(path)[2]["body"], "Edited through web helpers")

    def test_answers_must_belong_to_same_q_and_a_discussion(self):
        other = database.db_discussion_create("alice", "project", "Q&A", "Other", "", self.alice)
        foreign = database.db_discussion_comment_add(other, self.alice, "Different discussion's answer")
        self.assertEqual(self.update(answered_comment_id=foreign)[0], 404)
        self.assertEqual(self.update(answered_comment_id=True)[0], 422)
        self.update(answered_comment_id=self.comment)
        status, _headers, general = self.update(category="General")
        self.assertEqual(status, 200, general)
        self.assertIsNone(general["answered_comment_id"])
        self.assertEqual(self.update(answered_comment_id=self.comment)[0], 409)

    def test_locked_discussion_still_allows_existing_comment_author_to_edit(self):
        self.update(locked=True)
        path = self.comments + "/" + str(self.comment)
        self.assertEqual(self.update(path, body="Fixed existing answer")[0], 200)
        self.assertEqual(self.request(path)[2]["body"], "Fixed existing answer")

    def test_scope_repository_and_comment_parent_isolation(self):
        foreign = database.db_discussion_create("bob", "project", "Q&A", "Private Bob question", "", self.bob)
        comment = database.db_discussion_comment_add(foreign, self.bob, "Private answer")
        for suffix in ("", "/categories", f"/{self.discussion}", f"/{self.discussion}/comments"):
            self.assertEqual(self.request(self.discussions + suffix, token=None)[0], 401)
            self.assertEqual(self.request(self.discussions + suffix, token=self.bob_token)[0], 404)
        self.assertEqual(self.mutate(self.discussions, {"title": "Read-only"}, token=self.token)[0], 403)
        self.assertEqual(self.request(self.comments + "/" + str(comment), token=self.admin_token)[0], 404)
        self.assertEqual(self.request(f"/api/v1/repos/bob/project/discussions/{self.discussion}",
                                      token=self.bob_token)[0], 404)
        self.assertEqual(self.update(answered_comment_id=comment)[0], 404)

    def test_revision_and_unknown_fields_fail_without_modifying_parent(self):
        before = self.request(self.path)[2]
        for doc in ({"title": "No revision"}, {"expected_revision": "invalid", "body": "x"},
                    {"expected_revision": before["revision"]},
                    {"expected_revision": before["revision"], "locked_by": self.bob}):
            self.assertEqual(self.mutate(self.path, doc, method="PATCH")[0], 422)
        self.assertEqual(self.request(self.path)[2], before)
        self.assertEqual(self.mutate(self.path, {"expected_revision": before["revision"]}, method="DELETE")[0], 405)

    def test_discussion_openapi_and_in_page_examples_describe_lock_and_answer_rules(self):
        schema = self.request("/api/v1/openapi.json")[2]
        base = "/repos/{owner}/{repo}/discussions"
        self.assertIn("post", schema["paths"][base])
        patch = schema["paths"][base + "/{id}"]["patch"]
        fields = patch["requestBody"]["content"]["application/json"]["schema"]["properties"]
        self.assertIn("locked", fields)
        self.assertIn("answered_comment_id", fields)
        self.assertEqual(fields["locked"]["type"], "boolean")
        self.assertIn("delete", schema["paths"][base + "/{id}/comments/{comment_id}"])
        status, _headers, page = self.request("/api/docs", token=None, decode=False)
        self.assertEqual(status, 200)
        self.assertIn(b'href="#discussions"', page)
        self.assertIn(b'id="discussions"', page)
        self.assertIn(b"answered_comment_id", page)
        self.assertIn(b"same Q&amp;A discussion", page)
