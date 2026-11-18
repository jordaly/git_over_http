import shutil
import unittest

from pygithost import database
from tests import test_api as read_tests
from tests import test_api_writes as write_tests
from tests.ci_fixtures import commit_ci_config
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
        return self.mutate(
            self.path, document, method="PUT", token=self.admin_write_token, **kwargs
        )

    def document(self):
        return {
            "expected_revision": self.current()["revision"],
            "configuration": {
                "version": 1,
                "pipelines": {
                    "tests": {"steps": [{"name": "Tests", "run": "echo SETTINGS_PRIVATE_PAYLOAD"}]}
                },
            },
        }

    def test_authorization_for_reads_and_writes(self):
        self.assertEqual(self.request(self.path, token=None)[0], 401)
        self.assertEqual(self.request(self.path)[0], 403)
        self.assertEqual(self.request(self.path, token=self.bob_token)[0], 404)
        doc = self.document()
        for token in (self.write_token, self.admin_token):
            self.assertEqual(self.mutate(self.path, doc, method="PUT", token=token)[0], 403)
        status, _headers, result = self.mutate(
            self.path, doc, method="PUT", token=self.admin_write_token
        )
        self.assertEqual(status, 410, result)

    def test_read_uses_repository_ci_configuration_and_keeps_secrets_separate(self):
        commit_ci_config(
            self.bare,
            {
                "version": 1,
                "pipelines": [
                    {
                        "name": "checks",
                        "execution": {"runner": "docker"},
                        "steps": [{"name": "Tests", "run": "echo repository-owned"}],
                    }
                ],
                "deployments": [],
            },
        )
        database.db_ci_preferences_set(
            {"env": {"API_SECRET": "DO_NOT_RETURN_FROM_CONFIG"}}, "alice", "project"
        )
        current = self.current()
        self.assertIn("echo repository-owned", str(current["configuration"]))
        self.assertTrue(current["revision"])
        self.assertNotIn("DO_NOT_RETURN_FROM_CONFIG", str(current["configuration"]))

    def test_put_is_gone_and_does_not_replace_repository_configuration(self):
        commit_ci_config(
            self.bare,
            {
                "version": 1,
                "steps": [{"name": "Tests", "run": "echo repository-owned"}],
            },
        )
        before_config = database.db_ci_config_get("alice", "project")
        before = self.current()
        status, _headers, result = self.save(self.document())
        self.assertEqual(status, 410, result)
        self.assertEqual(result["code"], "gone")
        self.assertIn("ci/config.json", result["message"])
        self.assertEqual(self.current(), before)
        self.assertEqual(database.db_ci_config_get("alice", "project"), before_config)

    def test_put_does_not_validate_or_echo_replaced_payloads(self):
        doc = {
            "expected_revision": "invalid",
            "configuration": {
                "version": 1,
                "pipelines": {"tests": {"steps": [{"name": "Tests", "run": "echo SECRET"}]}},
            },
        }
        status, _headers, result = self.save(doc)
        self.assertEqual(status, 410, result)
        self.assertNotIn("SECRET", str(result))

    def test_method_validation_and_read_only_schema(self):
        doc = self.document()
        self.assertEqual(self.mutate(self.path, doc, token=self.admin_write_token)[0], 405)
        schema = self.request("/api/v1/openapi.json")[2]
        route = schema["paths"]["/repos/{owner}/{repo}/ci/settings"]
        self.assertIn("get", route)
        self.assertNotIn("put", route)
        description = route["get"]["description"]
        self.assertIn("ci/config.json", description)
        self.assertIn("read-only", description)
        self.assertIn("Secrets", description)
