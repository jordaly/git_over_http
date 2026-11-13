import shutil
import unittest
from concurrent.futures import ThreadPoolExecutor

from pygithost import database
from tests import test_api as read_tests
from tests import test_api_writes as write_tests
from tests.test_server import _which_git_backend


@unittest.skipUnless(shutil.which("git") and _which_git_backend(), "requires Git HTTP backend")
class APISettingsTests(unittest.TestCase):
    git = read_tests.APITests.git
    user = read_tests.APITests.user
    request = read_tests.APITests.request
    tearDown = read_tests.APITests.tearDown
    mutate = write_tests.APIWriteTests.mutate

    def setUp(self):
        read_tests.APITests.setUp(self)
        self.write_token = database.db_create_token(self.alice, "writer", "write")
        self.admin_write_token = database.db_create_token(self.admin, "writer", "write")
        self.path = self.base + "/ci/settings"

    def current(self):
        status, _, result = self.request(self.path, token=self.admin_token)
        self.assertEqual(status, 200, result)
        return result

    def save(self, document, **kwargs):
        return self.mutate(self.path, document, method="PUT", token=self.admin_write_token, **kwargs)

    def document(self):
        return {"expected_revision": self.current()["revision"],
                "configuration": {"version": 1, "pipelines": {
                    "tests": {"steps": [{"name": "Tests", "run": "echo SETTINGS_PRIVATE_PAYLOAD"}]}}}}

    def test_authorization_for_reads_and_writes(self):
        self.assertEqual(self.request(self.path, token=None)[0], 401)
        self.assertEqual(self.request(self.path)[0], 403)
        self.assertEqual(self.request(self.path, token=self.bob_token)[0], 404)
        doc = self.document()
        for token in (self.write_token, self.admin_token):
            self.assertEqual(self.mutate(self.path, doc, method="PUT", token=token)[0], 403)

    def test_round_trip_idempotency_audit_and_no_secret_response_cache(self):
        doc = self.document()
        status, _, saved = self.save(doc, key="settings-save")
        self.assertEqual(status, 200, saved)
        self.assertNotEqual(saved["revision"], doc["expected_revision"])
        self.assertEqual(set(saved), {"revision"})
        current = self.current()
        self.assertIn("SETTINGS_PRIVATE_PAYLOAD", str(current["configuration"]))
        status, headers, replay = self.save(doc, key="settings-save")
        self.assertEqual(status, 200)
        self.assertEqual(replay, saved)
        self.assertEqual(headers["X-Idempotent-Replay"], "true")
        conn = database._db_connect()
        try:
            row = conn.execute("SELECT method,path,state,status,response_json FROM api_mutations "
                               "WHERE path=?", (self.path,)).fetchone()
            self.assertEqual(row[:4], ("PUT", self.path, "completed", 200))
            self.assertNotIn("SETTINGS_PRIVATE_PAYLOAD", row[4])
        finally:
            conn.close()

    def test_invalid_configuration_does_not_save_and_errors_do_not_echo_payload(self):
        before = database.db_ci_config_get("alice", "project")
        for configuration in ([], {"version": 99}, {"PRIVATE_INVALID_FIELD": "SECRET_VALUE"}):
            doc = {"expected_revision": self.current()["revision"], "configuration": configuration}
            status, _, result = self.save(doc)
            self.assertEqual(status, 422, result)
            self.assertNotIn("SECRET_VALUE", str(result))
            self.assertEqual(database.db_ci_config_get("alice", "project"), before)
        doc = self.document()
        doc["expected_revision"] = "invalid"
        self.assertEqual(self.save(doc)[0], 422)

    def test_stale_revision_and_concurrent_replacements(self):
        doc = self.document()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.save(doc)[0], range(2)))
        self.assertEqual(sorted(results), [200, 409])
        self.assertEqual(self.save(doc)[0], 409)

    def test_web_configuration_change_invalidates_revision(self):
        doc = self.document()
        raw = database.db_ci_config_get("alice", "project")
        database.db_ci_config_set("alice", "project", raw or "{}")
        # Ensure a different persisted configuration, using the same UI helper.
        import asyncio
        asyncio.run_coroutine_threadsafe(self.server.app.ci_manager.save_document(
            "alice", "project", {"version": 1, "pipelines": {
                "web": {"steps": [{"name": "Web", "run": "echo web"}]}}}),
            self.server.loop).result(timeout=10)
        self.assertEqual(self.save(doc)[0], 409)

    def test_schema_and_in_page_documentation(self):
        schema = self.request("/api/v1/openapi.json")[2]
        route = schema["paths"]["/repos/{owner}/{repo}/ci/settings"]
        self.assertIn("get", route)
        self.assertIn("put", route)
        self.assertIn("Administrator", route["put"]["description"])
        page = self.request("/api/docs", token=None, decode=False)[2]
        self.assertIn(b"CI and deployment settings API", page)

    def test_deployment_configuration_round_trip_without_starting_deployment(self):
        doc = self.document()
        doc["configuration"]["pipelines"]["tests"]["deployment"] = {
            "enabled": True, "branch": "main", "script_content": "echo reviewed-deployment",
            "run_with": "sh", "timeout_seconds": 60}
        status, _, result = self.save(doc)
        self.assertEqual(status, 200, result)
        self.assertIn("reviewed-deployment", str(self.current()["configuration"]))
        # The returned editor document must be valid input to the same API.
        current = self.current()
        status, _, result = self.save({"configuration": current["configuration"],
                                      "expected_revision": current["revision"]})
        self.assertEqual(status, 200, result)

    def test_replay_rechecks_administrator_role(self):
        doc = self.document()
        self.assertEqual(self.save(doc, key="admin-before-revocation")[0], 200)
        conn = database._db_connect()
        try:
            conn.execute("UPDATE users SET is_admin=0 WHERE id=?", (self.admin,))
            conn.commit()
        finally:
            conn.close()
        # Revocation also removes access to Alice's repository.
        self.assertEqual(self.save(doc, key="admin-before-revocation")[0], 404)

    def test_method_and_oversize_validation(self):
        doc = self.document()
        self.assertEqual(self.mutate(self.path, doc, token=self.admin_write_token)[0], 405)
        doc["configuration"]["padding"] = "x" * 262145
        self.assertEqual(self.save(doc)[0], 413)
