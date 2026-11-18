import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pygithost import database
from pygithost.ci import CIManager, validate_config


class ExecutionSecretsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="ci-execution-secrets-")
        self.addCleanup(directory.cleanup)
        self.addCleanup(setattr, database, "DB_PATH", database.DB_PATH)
        database.DB_PATH = str(Path(directory.name) / "ci.db")
        database._db_init()
        self.manager = CIManager(lambda *_: directory.name)
        self.commit = "a" * 40
        self.secrets = {"env": {"TOKEN": "page-value"}}

    async def test_queue_keeps_git_variables_but_not_secrets_and_records_config_commit(self):
        config = validate_config(
            {"runner": "remote-docker", "command": "echo test", "env": {"PUBLIC": "git-value"}}
        )
        config["_configuration_commit"] = self.commit
        self.manager.started = True
        with mock.patch.object(self.manager, "config", return_value=config) as read:
            run = await self.manager.enqueue("owner", "repo", "manual", "main", self.commit)
        read.assert_awaited_once_with("owner", "repo", self.commit, include_secrets=False)
        metadata = database.db_ci_run_metadata("owner", "repo", run)
        self.assertEqual(json.loads(metadata["config"])["env"], {"PUBLIC": "git-value"})
        self.assertEqual(json.loads(metadata["payload"])["configuration_commit"], self.commit)

    async def test_remote_job_resolves_current_secrets_not_stored_page_values(self):
        config = validate_config({"runner": "remote-docker", "command": "echo test"})
        config.update(env={"PUBLIC": "git-value"}, _page_environment_live=True)
        run = database.db_ci_run_create(
            "owner", "repo", "manual", "main", self.commit, "{}", json.dumps(config)
        )
        with (
            mock.patch.object(self.manager, "secret_preferences", return_value=({}, self.secrets)),
            mock.patch.object(self.manager, "config", return_value={}),
            mock.patch("pygithost.remote_ci.execute_remote") as remote,
        ):
            await self.manager._execute((run, "owner", "repo", "manual", "main", self.commit, "{}"))
        self.assertEqual(
            remote.call_args.args[2]["env"], {"PUBLIC": "git-value", "TOKEN": "page-value"}
        )
        self.assertNotIn("TOKEN", database.db_ci_run_metadata("owner", "repo", run)["config"])

    async def test_unmerged_pr_never_reads_page_values_or_replays_legacy_credentials(self):
        config = validate_config(
            {"runner": "remote-docker", "command": "echo test", "env": {"TOKEN": "old-page-value"}}
        )
        event = "pull_request_updated"
        run = database.db_ci_run_create(
            "owner", "repo", event, "main", self.commit, "{}", json.dumps(config)
        )
        with (
            mock.patch.object(self.manager, "secret_preferences") as read,
            mock.patch("pygithost.remote_ci.execute_remote") as remote,
        ):
            await self.manager._execute((run, "owner", "repo", event, "main", self.commit, "{}"))
        read.assert_not_called()
        self.assertEqual(remote.call_args.args[2]["env"], {})

    async def test_protected_scope_requires_server_grant_and_tip_match(self):
        row = (1, "owner", "repo", "manual", "main", self.commit, "{}")
        policy = {
            "_configuration_status": "valid",
            "block_direct_pushes": True,
            "protected_branches": "main",
        }
        with (
            mock.patch.object(self.manager, "secret_preferences", return_value=({}, self.secrets)),
            mock.patch.object(self.manager, "config", return_value=policy),
            mock.patch(
                "pygithost.repository_ci.resolve_commit", return_value=self.commit
            ) as resolve,
            mock.patch("pygithost.ci_preferences.page_environment", return_value={}) as scoped,
            mock.patch.dict("os.environ", {"PYGITHOST_CI_PROTECTED_SECRET_BRANCHES": ""}),
        ):
            await self.manager.execution_environment(row, "tests", {})
            self.assertFalse(scoped.call_args.kwargs["protected"])
            resolve.assert_not_called()
            with mock.patch.dict(
                "os.environ", {"PYGITHOST_CI_PROTECTED_SECRET_BRANCHES": "owner/repo:main"}
            ):
                await self.manager.execution_environment(row, "tests", {})
                self.assertTrue(scoped.call_args.kwargs["protected"])
                resolve.return_value = "b" * 40
                await self.manager.execution_environment(row, "tests", {})
                self.assertFalse(scoped.call_args.kwargs["protected"])
