import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from pygithost import database
from pygithost.ci import CIManager, validate_config
from pygithost.docker_profile import authorize, policy
from pygithost.runner import execute_with_image


class RunnerImageTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "worker.db")
        database._db_init()
        self.config = validate_config({"runner": "docker", "image": "example/test:1", "command": "true"})
        self.run = database.db_ci_run_create("root", "project", "manual", "main", "a" * 40, "{}", "{}")
        self.row = (self.run, "root", "project", "manual", "main", "a" * 40, "{}")
        self.manager = CIManager(lambda *_: "")
        self.manager.docker_policy = policy()
        self.manager._execute = mock.AsyncMock()

    async def asyncTearDown(self):
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def stored(self):
        return database.db_ci_run_get("root", "project", self.run)

    async def test_cached_image_is_reused_without_download(self):
        self.manager._capture_process = mock.AsyncMock(return_value=0)
        await execute_with_image(self.manager, self.row, self.config)
        commands = [call.args[0] for call in self.manager._capture_process.await_args_list]
        self.assertEqual(commands, [["docker", "image", "inspect", "--format={{.Id}}", "example/test:1"]])
        self.manager._execute.assert_awaited_once()
        self.assertIn(b"Using cached Docker image", self.manager._execute.await_args.kwargs["initial_output"])

    async def test_missing_image_downloads_before_execution_with_live_bounded_logs(self):
        async def capture(command, **kwargs):
            if command[1] == "image":
                return 1
            self.assertEqual(command, ["docker", "pull", "--quiet", "example/test:1"])
            self.manager._execute.assert_not_awaited()
            self.assertGreater(kwargs["timeout"], 0)
            self.assertLessEqual(kwargs["timeout"], 600)
            self.assertEqual(kwargs["max_output"], 1024 * 1024)
            kwargs["output"].extend(b"Downloaded image digest\n")
            await kwargs["on_output"]()
            self.assertIn("Downloaded image digest", self.stored()[5])
            return 0
        self.manager._capture_process = mock.AsyncMock(side_effect=capture)
        await execute_with_image(self.manager, self.row, self.config)
        self.assertEqual(self.manager._capture_process.await_count, 2)
        self.assertIn(b"Downloaded image digest", self.manager._execute.await_args.kwargs["initial_output"])
        self.assertTrue(self.manager._execute.await_args.kwargs["started_at"])

    async def test_always_policy_downloads_even_without_inspecting_cache(self):
        self.manager.docker_policy = policy({"image_pull": "always"})
        self.manager._capture_process = mock.AsyncMock(return_value=0)
        await execute_with_image(self.manager, self.row, self.config)
        self.assertEqual(self.manager._capture_process.await_args.args[0],
                         ["docker", "pull", "--quiet", "example/test:1"])
        self.assertEqual(self.manager._capture_process.await_count, 1)

    async def test_offline_policy_fails_missing_image_without_download_or_execution(self):
        self.manager.docker_policy = policy({"image_pull": "never"})
        self.manager._capture_process = mock.AsyncMock(return_value=1)
        await execute_with_image(self.manager, self.row, self.config)
        self.assertEqual(self.manager._capture_process.await_count, 1)
        self.manager._execute.assert_not_awaited()
        self.assertEqual(self.stored()[4], "failed")
        self.assertIn("policy forbids image downloads", self.stored()[5])
        self.assertEqual(database.db_ci_run_metadata("root", "project", self.run)["phase"], "image")

    async def test_failed_pull_does_not_start_the_job(self):
        self.manager._capture_process = mock.AsyncMock(return_value=1)
        await execute_with_image(self.manager, self.row, self.config)
        self.manager._execute.assert_not_awaited()
        self.assertEqual(self.stored()[4], "failed")
        self.assertIn("Docker image download failed", self.stored()[5])

    async def test_pull_timeout_is_reported_and_does_not_start_the_job(self):
        self.manager.docker_policy = policy({"image_pull": "always"})
        self.manager._capture_process = mock.AsyncMock(side_effect=asyncio.TimeoutError)
        await execute_with_image(self.manager, self.row, self.config)
        self.manager._execute.assert_not_awaited()
        self.assertEqual(self.stored()[4], "timed_out")
        self.assertIn("provisioning timed out", self.stored()[5])

    async def test_cancelling_image_preparation_does_not_start_the_job(self):
        self.manager._capture_process = mock.AsyncMock(side_effect=asyncio.CancelledError)
        with self.assertRaises(asyncio.CancelledError):
            await execute_with_image(self.manager, self.row, self.config)
        self.manager._execute.assert_not_awaited()

    def test_policy_validates_download_modes_and_timeout_ceiling(self):
        self.assertEqual(policy()["image_pull"], "missing")
        for value in ("sometimes", True, ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy({"image_pull": value})
        with self.assertRaisesRegex(ValueError, "Image pull timeout"):
            authorize({}, image_pull_timeout=601)
        authorize({}, {"max_image_pull_timeout_seconds": 1200}, image_pull_timeout=900)

    def test_documentation_describes_host_downloads_without_container_network_access(self):
        from pygithost.ci_docs import manual_content
        for guide in ("docker-profiles", "http-runner", "runner-setup"):
            with self.subTest(guide=guide):
                rendered = str(manual_content(guide, None, "/r/root/example/ci/docs"))
                self.assertIn("image_pull", rendered)
                self.assertIn("missing", rendered)
                self.assertIn("--pull=never", rendered)
        self.assertIn("image_pull_timeout_seconds",
                      str(manual_content("ci-limits", None, "/r/root/example/ci/docs")))
