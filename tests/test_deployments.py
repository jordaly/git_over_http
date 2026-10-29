import asyncio
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from pygithost import database
from pygithost.ci import CIManager, default_config, pipeline_config, validate_config


class DeploymentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "test.db")
        database._db_init()
        self.manager = CIManager(lambda *_: str(Path(self.temp.name) / "repo.git"))
        self.script = Path(self.temp.name) / "deploy.sh"
        self.script.write_text("#!/bin/sh\necho deployed\n")
        self.script.chmod(0o700)
        self.commit = "a" * 40
        self.config = {**default_config(), "deploy_enabled": True,
                       "deploy_script": str(self.script)}

    def tearDown(self):
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    async def run_record(self, event="push", branch="main", status="success"):
        await self.manager.save_config("owner", "repo", self.config)
        run_id = database.db_ci_run_create("owner", "repo", event, branch,
            self.commit, "{}", json.dumps(validate_config(self.config)))
        database.db_ci_run_update(run_id, status=status)
        return (run_id, "owner", "repo", event, branch, self.commit, "{}")

    def capture(self, *, tip=None, code=0, error=None):
        async def execute(command, **kwargs):
            if command[0] == "git":
                kwargs["output"].extend(((tip or self.commit) + "\n").encode())
                return 0
            if error:
                raise error
            self.assertEqual(command, [str(self.script), self.commit])
            self.assertEqual(kwargs["env"]["PYGITHOST_COMMIT"], self.commit)
            kwargs["output"].extend(b"deployed\n")
            return code
        self.manager._capture_process = AsyncMock(side_effect=execute)

    async def test_success_and_duplicate_protection(self):
        row = await self.run_record()
        self.capture()
        await self.manager._deploy(row)
        self.assertEqual(database.db_deployment_get(row[0]), ("success", "deployed\n"))
        second = await self.run_record()
        await self.manager._deploy(second)
        self.assertIsNone(database.db_deployment_get(second[0]))
        self.assertEqual(self.manager._capture_process.await_count, 3)

    async def test_conditions_exclude_pr_manual_wrong_branch_and_failure(self):
        self.capture()
        for args in [("manual", "main", "success"), ("pull_request", "main", "success"),
                     ("push", "other", "success"), ("push", "main", "failed")]:
            row = await self.run_record(*args)
            await self.manager._deploy(row)
            self.assertIsNone(database.db_deployment_get(row[0]))
        self.manager._capture_process.assert_not_awaited()

    async def test_stale_commit_does_not_deploy(self):
        row = await self.run_record()
        self.capture(tip="b" * 40)
        await self.manager._deploy(row)
        self.assertIsNone(database.db_deployment_get(row[0]))

    async def test_disabling_prevents_pending_deployment(self):
        row = await self.run_record()
        await self.manager.save_config("owner", "repo", {**self.config, "deploy_enabled": False})
        self.capture()
        await self.manager._deploy(row)
        self.manager._capture_process.assert_not_awaited()

    async def test_failure_and_timeout_do_not_change_ci_result(self):
        for index, error in enumerate([None, asyncio.TimeoutError()]):
            self.commit = str(index) * 40
            row = await self.run_record()
            self.capture(code=1, error=error)
            await self.manager._deploy(row)
            self.assertEqual(database.db_deployment_get(row[0])[0], "failed" if error is None else "timed_out")
            self.assertEqual(database.db_ci_run_get("owner", "repo", row[0])[4], "success")

    async def test_recovery_does_not_allow_repeated_attempt(self):
        row = await self.run_record()
        self.assertTrue(database.db_deployment_claim(row[0], "owner", "repo", self.commit))
        database.db_deployment_recover()
        self.assertEqual(database.db_deployment_get(row[0])[0], "interrupted")
        self.assertFalse(database.db_deployment_claim(row[0], "owner", "repo", self.commit))

    async def test_uploaded_script_stored_and_executable(self):
        content = "#!/bin/sh\r\nprintf '%s' \"$1\"\r\n"
        saved = await self.manager.save_config("owner", "repo", {
            **self.config, "deploy_script": "", "deploy_script_content": content})
        path = Path(saved["deploy_script"])
        self.assertEqual(path.parent.name, "deployment-scripts")
        self.assertEqual(path.read_text(), content.replace("\r\n", "\n"))
        self.assertNotIn("deploy_script_content", saved)
        if os.name == "posix":
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            process = await asyncio.create_subprocess_exec(str(path), self.commit,
                stdout=asyncio.subprocess.PIPE)
            output, _ = await process.communicate()
            self.assertEqual(output.decode(), self.commit)
        again = await self.manager.save_config("owner", "repo", {
            **self.config, "deploy_script_content": content})
        self.assertEqual(again["deploy_script"], str(path))

    async def test_invalid_upload_not_saved(self):
        for content in ["#!/bin/sh\n" + "x" * 65536, "#!/bin/sh\n\0"]:
            with self.assertRaises(ValueError):
                await self.manager.save_config("owner", "repo", {
                    **self.config, "deploy_script_content": content})
        self.assertIsNone(database.db_ci_config_get("owner", "repo"))

    @unittest.skipUnless(os.name == "posix", "POSIX executable script")
    async def test_real_ci_then_uploaded_deployment(self):
        bare = Path(self.temp.name) / "repo.git"
        source = Path(self.temp.name) / "source"
        source.mkdir()
        def git(*args):
            return subprocess.check_output(["git", *map(str, args)], stderr=subprocess.DEVNULL).decode().strip()
        git("init", "-b", "main", source)
        git("-C", source, "-c", "user.name=Test", "-c", "user.email=test@example.com",
            "commit", "--allow-empty", "-m", "Initial")
        self.commit = git("-C", source, "rev-parse", "HEAD")
        git("clone", "--bare", source, bare)
        config = await self.manager.save_config("owner", "repo", {
            **self.config, "command": "echo tests passed", "events": {"push": True},
            "deploy_script_content": '#!/bin/sh\nprintf "deployed %s" "$1"\n'})
        run_id = await self.manager.enqueue("owner", "repo", "push", "main", self.commit)
        try:
            await asyncio.wait_for(self.manager.wait_idle(), timeout=15)
            self.assertEqual(database.db_ci_run_get("owner", "repo", run_id)[4], "success")
            self.assertEqual(database.db_deployment_get(run_id),
                             ("success", "deployed " + self.commit))
            self.assertTrue(Path(config["deploy_script"]).is_file())
        finally:
            await self.manager.stop()

    def test_repository_pipeline_cannot_configure_deployment(self):
        with self.assertRaises(ValueError):
            pipeline_config({"version": 1, "command": "true", "deploy_enabled": True}, default_config())

    def test_invalid_config(self):
        for values in [{"deploy_timeout": 0}, {"deploy_script": "relative.sh"},
                       {"deploy_branch": "main; branch"}, {"deploy_enabled": "yes"}]:
            with self.assertRaises(ValueError):
                validate_config({**default_config(), **values})
