import copy
import os
import re
import unittest
from unittest import mock

from pygithost import application, database
from pygithost.ci import CIManager
from pygithost.ci_preferences import page_environment, validate
from tests import test_repository_ui as ui

UNMERGED_EVENTS = (
    "pull_request",
    "pull_request_updated",
    "pull_request_reopened",
)


class PageEnvironmentScopeTests(unittest.TestCase):
    def setUp(self):
        self.global_values = {"env": {"SERVER": "server", "SHARED": "server-shared"}}
        self.repository_values = {
            "env": {"SHARED": "repository-shared", "ORDINARY": "ordinary"},
            "pipeline_env": {"ci": {"PIPELINE": "pipeline"}},
            "env_scopes": {
                "": {"PROTECTED": "protected", "DEPLOYMENT": "deployment"},
                "ci": {"PIPELINE": "deployment"},
            },
        }
        self.repository_values["env"].update(PROTECTED="protected", DEPLOYMENT="deployment")

    def test_unmerged_pull_requests_deny_every_page_value(self):
        for event in UNMERGED_EVENTS:
            with self.subTest(event=event):
                self.assertEqual(
                    page_environment(
                        self.global_values,
                        self.repository_values,
                        "ci",
                        event=event,
                        protected=True,
                        deployment=True,
                    ),
                    {},
                )

    def test_missing_metadata_defaults_to_ordinary_non_pr_runs(self):
        values = {"env": {"OLD": "existing"}}
        self.assertEqual(page_environment({}, values, "ci", event="push"), {"OLD": "existing"})
        self.assertEqual(
            page_environment({}, values, "ci", event="manual", protected=True),
            {"OLD": "existing"},
        )
        self.assertEqual(
            page_environment({}, values, "ci", event="pull_request_merged"),
            {"OLD": "existing"},
        )
        self.assertEqual(page_environment({}, values, "ci", event="push", deployment=True), {})

    def test_scopes_are_independent_and_pipeline_values_are_scoped(self):
        ordinary = page_environment({}, self.repository_values, "ci", event="push")
        self.assertEqual(ordinary, {"SHARED": "repository-shared", "ORDINARY": "ordinary"})

        protected = page_environment({}, self.repository_values, "ci", event="push", protected=True)
        self.assertEqual(
            protected,
            {
                "SHARED": "repository-shared",
                "ORDINARY": "ordinary",
                "PROTECTED": "protected",
            },
        )

        deployment = page_environment(
            {},
            self.repository_values,
            "ci",
            event="push",
            protected=True,
            deployment=True,
        )
        # A protected value does not authorize a deployment, and ordinary values
        # are not reused during the deployment phase.
        self.assertEqual(deployment, {"DEPLOYMENT": "deployment", "PIPELINE": "pipeline"})

        self.assertEqual(
            page_environment({}, self.repository_values, "lint", event="push", deployment=True),
            {"DEPLOYMENT": "deployment"},
        )

    def test_restricted_override_does_not_fall_back_to_a_broader_value(self):
        global_values = {"env": {"TOKEN": "server"}}
        repository_values = {
            "env": {"TOKEN": "repository"},
            "env_scopes": {"": {"TOKEN": "protected"}},
        }
        self.assertEqual(page_environment(global_values, repository_values, "ci", event="push"), {})
        self.assertEqual(
            page_environment(global_values, repository_values, "ci", event="push", protected=True),
            {"TOKEN": "repository"},
        )

    def test_server_values_are_not_reused_during_deployment(self):
        self.assertEqual(
            page_environment(self.global_values, {}, "ci", event="push", deployment=True),
            {},
        )
        self.assertEqual(
            page_environment(self.global_values, {}, "ci", event="push", protected=True),
            {"SERVER": "server", "SHARED": "server-shared"},
        )

    def test_helper_is_pure(self):
        global_values = copy.deepcopy(self.global_values)
        repository_values = copy.deepcopy(self.repository_values)
        page_environment(
            global_values,
            repository_values,
            "ci",
            event="push",
            protected=True,
            deployment=True,
        )
        self.assertEqual(global_values, self.global_values)
        self.assertEqual(repository_values, self.repository_values)


class ScopeValidationTests(unittest.TestCase):
    def test_valid_scope_metadata_is_preserved(self):
        values = {
            "env": {"TOKEN": "value"},
            "pipeline_env": {"ci": {"PIPELINE_TOKEN": "pipeline-value"}},
            "env_scopes": {
                "": {"TOKEN": "protected"},
                "ci": {"PIPELINE_TOKEN": "deployment"},
            },
        }
        self.assertEqual(validate(values), values)

    def test_invalid_scope_metadata_is_rejected(self):
        for scopes in (
            {"": {"TOKEN": "always"}},
            {"bad/name": {"TOKEN": "protected"}},
            {"": {"1TOKEN": "protected"}},
            {"": {"TOKEN": []}},
            [],
        ):
            with self.subTest(scopes=scopes):
                with self.assertRaises(ValueError):
                    validate({"env": {"TOKEN": "value"}, "env_scopes": scopes})


class SecretScopeSettingsTests(unittest.TestCase):
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

    def csrf(self, page):
        match = re.search(r'name="csrf" value="([^"]+)"', page)
        self.assertIsNotNone(match)
        return match[1]

    def variables(self, rows):
        fields = {"env_count": str(len(rows))}
        for index, (name, value, pipeline, access) in enumerate(rows):
            fields.update(
                {
                    f"env_name_{index}": name,
                    f"env_value_{index}": value,
                    f"env_pipeline_{index}": pipeline,
                    f"env_access_{index}": access,
                }
            )
        return fields

    def save(self, rows):
        _status, page = self.fixture.request(self.base + "/ci/config")
        return self.fixture.request(
            self.base + "/ci/preferences",
            {
                "action": "ci_environment",
                "csrf": self.csrf(page),
                **self.variables(rows),
            },
        )

    def test_repository_page_has_scope_controls_and_admin_page_does_not(self):
        _status, admin = self.fixture.request("/admin/settings")
        self.assertIn("Environment variables", admin)
        self.assertNotIn('name="env_access_0"', admin)
        self.assertNotIn('name="env_scope_0"', admin)

        status, page = self.fixture.request(self.base + "/ci/config")
        self.assertEqual(status, 200)
        self.assertIn('name="env_access_0"', page)
        self.assertIn('name="env_scope_0"', page)
        for label in (
            "Ordinary non-PR runs",
            "Protected branches",
            "Deployment only",
        ):
            self.assertIn(label, page)
        self.assertIn("Unmerged pull requests never receive", page)

    def test_saving_scopes_persists_only_nonordinary_metadata_and_reloads(self):
        status, page = self.save(
            [
                ("PUBLIC", "public", "", "ordinary"),
                ("PROTECTED", "protected", "", "protected"),
                ("DEPLOY", "deploy", "", "deployment"),
                ("PIPELINE", "pipeline", "ci", "deployment"),
            ]
        )
        self.assertEqual(status, 200)
        self.assertIn("Repository settings saved", page)
        self.assertEqual(
            database.db_ci_preferences_get(self.owner, "project")[1],
            {
                "env": {
                    "PUBLIC": "public",
                    "PROTECTED": "protected",
                    "DEPLOY": "deploy",
                },
                "pipeline_env": {"ci": {"PIPELINE": "pipeline"}},
                "env_scopes": {
                    "": {"PROTECTED": "protected", "DEPLOY": "deployment"},
                    "ci": {"PIPELINE": "deployment"},
                },
            },
        )

        _status, page = self.fixture.request(self.base + "/ci/config")
        self.assertIn('<option value="protected" selected>Protected branches</option>', page)
        self.assertIn('<option value="deployment" selected>Deployment only</option>', page)

    def test_changing_every_scope_back_to_ordinary_removes_metadata(self):
        self.assertEqual(self.save([("TOKEN", "value", "", "protected")])[0], 200)
        self.assertIn(
            "env_scopes",
            database.db_ci_preferences_get(self.owner, "project")[1],
        )
        status, _page = self.save([("TOKEN", "value", "", "ordinary")])
        self.assertEqual(status, 200)
        stored = database.db_ci_preferences_get(self.owner, "project")[1]
        self.assertNotIn("env_scopes", stored)
        self.assertEqual(stored["env"], {"TOKEN": "value"})

    def test_invalid_scope_is_rejected_without_saving(self):
        _status, page = self.fixture.request(self.base + "/ci/config")
        status, body = self.fixture.request(
            self.base + "/ci/preferences",
            {
                "action": "ci_environment",
                "csrf": self.csrf(page),
                **self.variables([("TOKEN", "value", "", "always")]),
            },
        )
        self.assertEqual(status, 200)
        self.assertIn("availability scope", body)
        self.assertEqual(database.db_ci_preferences_get(self.owner, "project")[1], {})

    def test_existing_unscoped_values_remain_ordinary(self):
        database.db_ci_preferences_set({"env": {"OLD": "value"}}, self.owner, "project")
        _status, page = self.fixture.request(self.base + "/ci/config")
        self.assertIn('<option value="ordinary" selected>Ordinary non-PR runs</option>', page)
        global_values, repository_values = database.db_ci_preferences_get(self.owner, "project")
        self.assertEqual(
            page_environment(global_values, repository_values, "ci", event="push"),
            {"OLD": "value"},
        )
        self.assertEqual(
            page_environment(global_values, repository_values, "ci", event="push", deployment=True),
            {},
        )


class ExecutionEnvironmentScopeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.manager = CIManager(lambda *_: "/tmp")
        self.commit = "a" * 40
        self.repository_values = {
            "env": {
                "ORDINARY": "ordinary",
                "PROTECTED": "protected",
                "DEPLOYMENT": "deployment",
            },
            "env_scopes": {
                "": {
                    "PROTECTED": "protected",
                    "DEPLOYMENT": "deployment",
                }
            },
        }

    def row(self, event):
        return (1, "owner", "repo", event, "main", self.commit, "{}")

    async def test_live_environment_uses_only_values_allowed_for_the_phase(self):
        with mock.patch.object(
            self.manager,
            "secret_preferences",
            return_value=({}, self.repository_values),
        ):
            ordinary = await self.manager.execution_environment(
                self.row("manual"), "ci", {"GIT": "git"}
            )
            deployment = await self.manager.execution_environment(
                self.row("manual"), "ci", {"GIT": "git"}, deployment=True
            )
        self.assertEqual(ordinary, {"GIT": "git", "ORDINARY": "ordinary"})
        self.assertEqual(deployment, {"GIT": "git", "DEPLOYMENT": "deployment"})

    async def test_protected_scope_requires_a_server_authorized_tip(self):
        policy = {
            "_configuration_status": "valid",
            "block_direct_pushes": True,
            "protected_branches": "main",
        }
        with (
            mock.patch.object(
                self.manager,
                "secret_preferences",
                return_value=({}, self.repository_values),
            ),
            mock.patch.object(
                self.manager, "config", new_callable=mock.AsyncMock, return_value=policy
            ),
            mock.patch("pygithost.repository_ci.resolve_commit", return_value=self.commit),
            mock.patch.dict(
                os.environ,
                {"PYGITHOST_CI_PROTECTED_SECRET_BRANCHES": "owner/repo:main"},
            ),
        ):
            environment = await self.manager.execution_environment(self.row("push"), "ci", {})
        self.assertEqual(environment, {"ORDINARY": "ordinary", "PROTECTED": "protected"})

    async def test_unmerged_pull_request_never_reads_page_values(self):
        with mock.patch.object(
            self.manager,
            "secret_preferences",
            return_value=({"env": {"SERVER": "server"}}, self.repository_values),
        ) as secrets:
            environment = await self.manager.execution_environment(
                self.row("pull_request_updated"),
                "ci",
                {"GIT": "git"},
                deployment=True,
            )
        self.assertEqual(environment, {"GIT": "git"})
        secrets.assert_not_called()


if __name__ == "__main__":
    unittest.main()
