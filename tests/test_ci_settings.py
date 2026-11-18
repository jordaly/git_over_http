import asyncio
import json
import os
import re
import unittest
from unittest import mock

from pygithost import application, database
from pygithost.ci import CIManager
from tests import test_repository_ui as ui
from tests.ci_fixtures import commit_ci_config


class AutomaticCISettingsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ui.RepositoryUITests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        conn = database._db_connect()
        try:
            conn.execute("DELETE FROM ci_configs")
            conn.commit()
        finally:
            conn.close()
        self.owner = application.FLAT_OWNER_UI
        self.base = self.fixture.base
        self.manager = CIManager(lambda *_: str(self.fixture.bare))

    def csrf(self, page):
        match = re.search(r'name="csrf" value="([^"]+)"', page)
        self.assertIsNotNone(match)
        return match[1]

    def variables(self, rows, count=None):
        fields = {"env_count": str(len(rows) if count is None else count)}
        for index, (name, value, pipeline) in enumerate(rows):
            fields.update(
                {
                    f"env_name_{index}": name,
                    f"env_value_{index}": value,
                    f"env_pipeline_{index}": pipeline,
                }
            )
        return fields

    def test_settings_page_has_environment_form_but_no_json_editor(self):
        status, page = self.fixture.request(self.base + "/ci/config")
        self.assertEqual(status, 200)
        self.assertIn("ci/config.json", page)
        self.assertIn("Project pipelines", page)
        self.assertIn("Environment variables", page)
        self.assertIn('action="' + self.base + '/ci/preferences"', page)
        self.assertIn('name="env_name_0"', page)
        self.assertIn('name="env_pipeline_0"', page)
        self.assertIn('name="csrf"', page)
        for removed in (
            'id="ci-config-editor"',
            'id="ci-config-json"',
            'name="configuration_json"',
            'src="/static/ci-settings.js"',
            'src="/static/vendor/monaco/vs/loader.js"',
            "Monaco",
            'name="run_retention_count"',
            'name="artifact_retention_days"',
            'name="confirm_retention"',
            "Runs and artifacts",
        ):
            self.assertNotIn(removed, page)

    def test_admin_server_defaults_keep_retention_and_environment_forms(self):
        status, page = self.fixture.request("/admin/settings")
        self.assertEqual(status, 200)
        self.assertIn("Runs and artifacts", page)
        self.assertIn('name="run_retention_count"', page)
        self.assertIn('name="confirm_retention" value="yes" required', page)
        self.assertIn("Environment variables", page)
        self.assertIn('action="/admin/settings"', page)

    def test_old_configuration_post_is_gone_and_preserves_stored_configuration(self):
        stored = json.dumps(
            {
                "env": {"LEGACY_SECRET": "legacy"},
                "pipelines": [{"pipeline_id": "ci", "env": {"PIPELINE_SECRET": "pipeline"}}],
            }
        )
        database.db_ci_config_set(self.owner, "project", stored)
        status, page = self.fixture.request(
            self.base + "/ci/config",
            {"configuration_json": json.dumps({"version": 1, "steps": []})},
        )
        self.assertEqual(status, 410)
        self.assertIn("repository-owned", page)
        self.assertIn("ci/config.json", page)
        self.assertEqual(database.db_ci_config_get(self.owner, "project"), stored)

    def test_old_configuration_post_keeps_existing_admin_auth_check(self):
        with (
            mock.patch.object(application, "REQUIRE_AUTH", True),
            mock.patch.object(application, "_require_admin", return_value=False),
            mock.patch.object(
                application.GitHTTPHandler,
                "_require_session_auth",
                new_callable=mock.AsyncMock,
                return_value=True,
            ),
        ):
            status, _page = self.fixture.request(
                self.base + "/ci/config", {"configuration_json": "{}"}
            )
        self.assertEqual(status, 403)

    def test_legacy_environment_is_shown_and_can_be_migrated_to_preferences(self):
        commit_ci_config(
            self.fixture.bare,
            {
                "version": 1,
                "pipelines": [
                    {
                        "name": "ci",
                        "execution": {"runner": "docker"},
                        "steps": [{"name": "Tests", "run": "echo repository"}],
                    }
                ],
                "deployments": [],
            },
        )
        stored = json.dumps(
            {
                "env": {"LEGACY_SECRET": "legacy"},
                "pipelines": [{"pipeline_id": "ci", "env": {"PIPELINE_SECRET": "pipeline"}}],
            }
        )
        database.db_ci_config_set(self.owner, "project", stored)

        status, page = self.fixture.request(self.base + "/ci/config")
        self.assertEqual(status, 200)
        self.assertIn('value="LEGACY_SECRET"', page)
        self.assertIn('value="legacy"', page)
        self.assertIn('value="PIPELINE_SECRET"', page)
        self.assertIn('value="pipeline"', page)

        fields = {
            "action": "ci_environment",
            "csrf": self.csrf(page),
            **self.variables(
                [
                    ("LEGACY_SECRET", "rotated", ""),
                    ("NEW_SECRET", "s3cr3t", ""),
                    ("PIPELINE_SECRET", "scoped", "ci"),
                ]
            ),
        }
        status, page = self.fixture.request(self.base + "/ci/preferences", fields)
        self.assertEqual(status, 200)
        self.assertIn("Repository settings saved", page)
        self.assertEqual(
            database.db_ci_preferences_get(self.owner, "project")[1],
            {
                "env": {"LEGACY_SECRET": "rotated", "NEW_SECRET": "s3cr3t"},
                "pipeline_env": {"ci": {"PIPELINE_SECRET": "scoped"}},
            },
        )
        # Migrating secrets into the page-managed form never deletes the legacy
        # configuration row that may still be needed by older installations.
        self.assertEqual(database.db_ci_config_get(self.owner, "project"), stored)

        config = asyncio.run(self.manager.config(self.owner, "project"))
        pipeline = next(
            item for item in self.manager.pipelines(config) if item["pipeline_id"] == "ci"
        )
        self.assertEqual(
            pipeline["env"],
            {
                "LEGACY_SECRET": "rotated",
                "NEW_SECRET": "s3cr3t",
                "PIPELINE_SECRET": "scoped",
            },
        )
        self.assertEqual(pipeline["steps"][0]["run"], "echo repository")

    def test_project_retention_and_other_preferences_are_rejected(self):
        _status, page = self.fixture.request(self.base + "/ci/config")
        token = self.csrf(page)
        status, body = self.fixture.request(
            self.base + "/ci/preferences",
            {
                "action": "ci_retention",
                "csrf": token,
                "run_retention_count": "1",
                "confirm_retention": "yes",
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("environment variables", body)
        self.assertEqual(database.db_ci_preferences_get(self.owner, "project")[1], {})
        status, _body = self.fixture.request(
            self.base + "/ci/preferences",
            {"action": "ci_environment", "csrf": "wrong", "env_count": "0"},
        )
        self.assertEqual(status, 403)

    def test_invalid_repository_config_shows_safe_warning_without_content(self):
        commit_ci_config(
            self.fixture.bare,
            raw='{"version":1,"steps":[{"name":"Tests","run":"echo INVALID_SECRET"',
        )
        status, page = self.fixture.request(self.base + "/ci/config")
        self.assertEqual(status, 200)
        self.assertIn("invalid", page.lower())
        self.assertIn("ci/config.json", page)
        self.assertNotIn("INVALID_SECRET", page)

    def test_blocked_repository_execution_shows_safe_authorization_warning(self):
        commit_ci_config(
            self.fixture.bare,
            {
                "version": 1,
                "pipelines": [
                    {
                        "name": "ci",
                        "execution": {"runner": "host"},
                        "steps": [{"name": "Tests", "run": "echo BLOCKED_SECRET"}],
                    }
                ],
            },
        )
        with mock.patch.dict(os.environ, {"PYGITHOST_CI_TRUSTED_REPOSITORIES": ""}):
            status, page = self.fixture.request(self.base + "/ci/config")
        self.assertEqual(status, 200)
        self.assertIn("blocked", page.lower())
        self.assertIn("administrator authorization", page.lower())
        self.assertNotIn("BLOCKED_SECRET", page)

    def test_manual_run_reports_missing_repository_config(self):
        # The shared UI fixture adds a CI definition in a separate commit.
        # Point main at its original commit to exercise a repository without it.
        parent = self.fixture.git("--git-dir", self.fixture.bare, "rev-parse", "main^")
        self.fixture.git("--git-dir", self.fixture.bare, "update-ref", "refs/heads/main", parent)
        status, page = self.fixture.request(self.base + "/ci")
        self.assertEqual(status, 200)
        self.assertIn('<option value="ci">ci</option>', page)
        status, page = self.fixture.request(
            self.base + "/ci/run", {"pipeline": "ci", "branch": "main"}
        )
        self.assertEqual(status, 200)
        self.assertIn("Add ci/config.json", page)
        self.assertEqual(database.db_ci_runs_list(self.owner, "project"), [])
        self.assertIsNone(database.db_ci_config_get(self.owner, "project"))
