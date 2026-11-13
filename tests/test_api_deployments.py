import json
import shutil
import unittest

from pygithost import database
from tests import test_api as read_tests
from tests.test_server import _which_git_backend


@unittest.skipUnless(shutil.which("git") and _which_git_backend(), "requires Git HTTP backend")
class APIDeploymentTests(unittest.TestCase):
    git = read_tests.APITests.git
    user = read_tests.APITests.user
    request = read_tests.APITests.request
    tearDown = read_tests.APITests.tearDown

    def setUp(self):
        read_tests.APITests.setUp(self)
        self.path = self.base + "/deployments"
        database.db_deployment_claim(99999, "alice", "project", self.sha, json.dumps({
            "deployment_name": "production", "pipeline_id": "checks", "deploy_branch": "main",
            "deploy_script_content": "PRIVATE_SCRIPT", "env": {"KEY": "PRIVATE_SECRET"}}))
        database.db_deployment_progress(99999, "production", "A漢B\n", json.dumps([
            {"name": "Prepare", "run": "PRIVATE_COMMAND", "status": "failed", "output": "A漢B\n"},
            {"name": "Release", "run": "PRIVATE_COMMAND", "status": "skipped", "output": ""}]))
        database.db_deployment_finish(99999, "failed", "A漢B\n", "production")
        self.identity = database.db_deployments_list("alice", "project")[0][0]
        self.detail = self.path + "/" + str(self.identity)

    def test_history_detail_survive_ci_retention_without_exposing_configuration(self):
        status, _, result = self.request(self.path)
        self.assertEqual(status, 200, result)
        self.assertEqual(result[0]["id"], self.identity)
        self.assertFalse(result[0]["run_retained"])
        self.assertEqual(result[0]["name"], "production")
        self.assertTrue(result[0]["started_at"].endswith("Z"))
        self.assertEqual(self.request(self.detail)[2], result[0])
        self.assertNotIn("PRIVATE", str(result))

    def test_steps_do_not_expose_commands_or_unbounded_output(self):
        status, headers, result = self.request(self.detail + "/steps?per_page=1")
        self.assertEqual(status, 200, result)
        self.assertEqual(result[0]["index"], 0)
        self.assertEqual(result[0]["status"], "failed")
        self.assertEqual(result[0]["log_size_in_bytes"], 6)
        self.assertIn('rel="next"', headers["Link"])
        self.assertNotIn("PRIVATE", str(result))
        self.assertNotIn("output", result[0])

    def test_utf8_logs_and_step_logs(self):
        for suffix in ("/logs", "/steps/0/logs"):
            status, _, result = self.request(self.detail + suffix + "?limit=4")
            self.assertEqual(status, 200, result)
            self.assertEqual(result["content"], "A漢")
            self.assertEqual(result["next_offset"], 4)
            self.assertTrue(result["has_more"])
            self.assertFalse(result["complete"])
            result = self.request(self.detail + suffix + "?offset=4")[2]
            self.assertEqual(result["content"], "B\n")
            self.assertTrue(result["complete"])
            self.assertEqual(self.request(self.detail + suffix + "?offset=2")[0], 400)
            self.assertEqual(self.request(self.detail + suffix + "?offset=999")[0], 400)
            self.assertEqual(self.request(self.detail + suffix + "?limit=65537")[0], 400)
        self.assertEqual(self.request(self.detail + "/steps/1/logs")[2]["content"], "")
        self.assertEqual(self.request(self.detail + "/steps/9/logs")[0], 404)

    def test_access_checks_on_each_endpoint_and_no_cross_repository_ids(self):
        for suffix in ("", f"/{self.identity}", f"/{self.identity}/steps",
                       f"/{self.identity}/logs", f"/{self.identity}/steps/0/logs"):
            self.assertEqual(self.request(self.path + suffix, token=None)[0], 401)
            self.assertEqual(self.request(self.path + suffix, token=self.bob_token)[0], 404)
        self.assertEqual(self.request(f"/api/v1/repos/bob/project/deployments/{self.identity}",
                                      token=self.admin_token)[0], 404)

    def test_running_logs_are_not_complete_and_head_has_no_body(self):
        conn = database._db_connect()
        try:
            conn.execute("UPDATE ci_deployments SET status='running' WHERE id=?", (self.identity,))
            conn.commit()
        finally:
            conn.close()
        self.assertFalse(self.request(self.detail + "/logs")[2]["complete"])
        status, _, body = self.request(self.detail + "/logs", method="HEAD", decode=False)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")

    def test_preflight_requires_admin_and_does_not_execute_scripts(self):
        from pygithost.ci import default_config
        marker = self.root / "preflight-must-not-run"
        config = {**default_config(), "deploy_enabled": True,
                  "deploy_script_content": "#!/bin/sh\ntouch " + str(marker),
                  "deploy_interpreter": "missing-pygithost-runtime"}
        database.db_ci_config_set("alice", "project", json.dumps(config))
        self.assertEqual(self.request(self.path + "/preflight")[0], 403)
        status, _, result = self.request(self.path + "/preflight", token=self.admin_token)
        self.assertEqual(status, 200, result)
        self.assertFalse(result["ok"])
        self.assertTrue(result["advisory"])
        self.assertFalse(marker.exists())

    def test_schema_and_documentation(self):
        schema = self.request("/api/v1/openapi.json")[2]
        for suffix in ("", "/{id}", "/{id}/steps", "/{id}/logs",
                       "/{id}/steps/{step_index}/logs", "/preflight"):
            self.assertIn("get", schema["paths"]["/repos/{owner}/{repo}/deployments" + suffix])
        page = self.request("/api/docs", token=None, decode=False)[2]
        self.assertIn(b"Deployment diagnostics and preflight", page)
