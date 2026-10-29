import asyncio
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from pygithost import database
from pygithost.ci import CIManager, default_config, deployment_prefix, pipeline_config, validate_config
from pygithost.ci_documentation import ci_configuration_guide


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
        self.assertIn("branch tip", database.db_ci_run_metadata("owner", "repo", row[0])["reason"])

    async def test_disabling_prevents_pending_deployment(self):
        row = await self.run_record()
        await self.manager.save_config("owner", "repo", {**self.config, "deploy_enabled": False})
        self.capture()
        await self.manager._deploy(row)
        self.manager._capture_process.assert_not_awaited()
        self.assertIn("enabled", database.db_ci_run_metadata("owner", "repo", row[0])["reason"])

    async def test_changed_database_script_is_not_deployed_from_old_run(self):
        self.config.update(deploy_interpreter="python", deploy_script_content='print("old")\n', deploy_script="")
        row = await self.run_record()
        await self.manager.save_config("owner", "repo", {**self.config, "deploy_script_content": 'print("new")\n'})
        self.capture()
        await self.manager._deploy(row)
        self.manager._capture_process.assert_not_awaited()
        self.assertIn("settings changed", database.db_ci_run_metadata("owner", "repo", row[0])["reason"])

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
        self.assertEqual(saved["deploy_script"], "")
        self.assertEqual(saved["deploy_script_content"], content.replace("\r\n", "\n"))
        self.assertFalse((Path(self.temp.name) / "deployment-scripts").exists())
        self.assertEqual(json.loads(database.db_ci_config_get("owner", "repo"))["deploy_script_content"], saved["deploy_script_content"])
        again = await self.manager.save_config("owner", "repo", {
            **self.config, "deploy_script_content": content})
        self.assertEqual(again["deploy_script"], "")
        self.assertEqual(await self.manager.deployment_script_content("owner", "repo", saved), content.replace("\r\n", "\n"))
        self.assertEqual(await self.manager.deployment_script_content("owner", "repo", {"deploy_script": str(self.script)}), "")

    async def test_invalid_upload_not_saved(self):
        for content in ["#!/bin/sh\n" + "x" * 65536, "#!/bin/sh\n\0"]:
            with self.assertRaises(ValueError):
                await self.manager.save_config("owner", "repo", {
                    **self.config, "deploy_script_content": content})
        self.assertIsNone(database.db_ci_config_get("owner", "repo"))

    async def test_python_upload_without_shebang(self):
        content = 'import sys\nprint("deployed " + sys.argv[1])\n'
        saved = await self.manager.save_config("owner", "repo", {
            **self.config, "deploy_interpreter": "python", "deploy_script_content": content})
        self.config = saved
        row = await self.run_record()
        original = self.manager._capture_process
        paths = []
        async def capture(command, **kwargs):
            if command[0] == "git":
                kwargs["output"].extend((self.commit + "\n").encode())
                return 0
            self.assertEqual(command[0], sys.executable)
            self.assertEqual(command[2], self.commit)
            path = Path(command[1])
            paths.append(path)
            self.assertEqual(path.read_text(), content)
            self.assertEqual(path.suffix, ".py")
            return await original(command, **kwargs)
        self.manager._capture_process = capture
        await self.manager._deploy(row)
        self.assertEqual(database.db_deployment_get(row[0]),
                         ("success", "deployed " + self.commit + "\n"))
        self.assertFalse(paths[0].exists())

    async def test_direct_upload_still_requires_shebang_on_posix(self):
        if os.name != "nt":
            with self.assertRaisesRegex(ValueError, "shebang"):
                await self.manager.save_config("owner", "repo", {
                    **self.config, "deploy_script_content": 'print("hello")'})

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
            self.assertEqual(config["deploy_script"], "")
            self.assertIn("deploy_script_content", config)
        finally:
            await self.manager.stop()

    def test_repository_pipeline_cannot_configure_deployment(self):
        with self.assertRaises(ValueError):
            pipeline_config({"version": 1, "command": "true", "deploy_enabled": True}, default_config())

    def test_invalid_config(self):
        for values in [{"deploy_interpreter": '"unclosed'}, {"deploy_timeout": 0}, {"deploy_script": "relative.sh"},
                       {"deploy_branch": "main; branch"}, {"deploy_enabled": "yes"}]:
            with self.assertRaises(ValueError):
                validate_config({**default_config(), **values})

    def test_arbitrary_runner_and_arguments(self):
        for command, expected in [
            ("node", ["node"]), ("bash -e", ["bash", "-e"]),
            ("pwsh -NoProfile -File", ["pwsh", "-NoProfile", "-File"]),
            ('"C:/Program Files/Python/python.exe" -u', ["C:/Program Files/Python/python.exe", "-u"]),
            ("", []), ("python", [sys.executable]),
        ]:
            self.assertEqual(deployment_prefix(command), expected)

    async def test_history_pagination_scoping_and_pruned_run(self):
        row = await self.run_record()
        database.db_deployment_claim(row[0], "owner", "repo", self.commit, json.dumps(self.config))
        database.db_deployment_finish(row[0], "success", "deployment output")
        history = database.db_deployments_list("owner", "repo")
        self.assertEqual(len(history), 1)
        identity = history[0][0]
        self.assertEqual(history[0][8], row[0])
        self.assertEqual(database.db_deployments_list("owner", "repo", identity), [])
        self.assertEqual(database.db_deployments_list("other", "repo"), [])
        self.assertIsNone(database.db_deployment_detail("other", "repo", identity))
        connection = database._db_connect()
        try:
            connection.execute("DELETE FROM ci_runs WHERE id=?", (row[0],))
        finally:
            connection.close()
        detail = database.db_deployment_detail("owner", "repo", identity)
        self.assertIsNone(detail[8])
        self.assertEqual(detail[9], "deployment output")

    async def test_explicit_runner_does_not_require_shebang(self):
        saved = await self.manager.save_config("owner", "repo", {
            **self.config, "deploy_interpreter": "node", "deploy_script_content": "console.log(process.argv[2]);"})
        self.assertEqual(saved["deploy_interpreter"], "node")

    async def test_deployment_email_modes_and_duplicate_protection(self):
        for index, (mode, status, sends) in enumerate([
            ("off", "failed", False), ("failures", "success", False),
            ("failures", "failed", True), ("all", "success", True),
            ("failures", "timed_out", True), ("failures", "interrupted", True),
        ]):
            self.commit = f"{index:040x}"
            self.config.update(email_mode=mode, email_recipients="deploy@example.com")
            row = await self.run_record()
            database.db_deployment_claim(row[0], "owner", "repo", self.commit, json.dumps(self.config))
            database.db_deployment_finish(row[0], status, "SECRET output")
            with patch("pygithost.ci.send_notification") as send, patch("pygithost.ci.load_settings", return_value={}):
                await self.manager._deliver_deployment_notification(row)
                await self.manager._deliver_deployment_notification(row)
                self.assertEqual(send.call_count, int(sends))
                if sends:
                    args = send.call_args.args
                    self.assertEqual(args[2][1], "deployment")
                    self.assertEqual(args[2][4], status)
                    self.assertNotIn("SECRET", str(args))

    async def test_deployment_email_failure_preserves_result(self):
        self.config.update(email_mode="all", email_recipients="deploy@example.com")
        row = await self.run_record()
        database.db_deployment_claim(row[0], "owner", "repo", self.commit, json.dumps(self.config))
        database.db_deployment_finish(row[0], "success", "done")
        with patch("pygithost.ci.send_notification", side_effect=OSError("secret password")), patch("pygithost.ci.load_settings", return_value={}):
            await self.manager._deliver_deployment_notification(row)
        record = database.db_deployment_email_record(row[0])
        self.assertEqual(record[4], "success")
        self.assertTrue(record[6].startswith("failed (OSError"))
        self.assertNotIn("secret", record[6])

    async def test_deployment_recovery_email(self):
        self.config.update(email_mode="recovery", email_recipients="deploy@example.com")
        first = await self.run_record()
        database.db_deployment_claim(first[0], "owner", "repo", self.commit, json.dumps(self.config))
        database.db_deployment_finish(first[0], "failed", "")
        self.commit = "b" * 40
        row = await self.run_record()
        database.db_deployment_claim(row[0], "owner", "repo", self.commit, json.dumps(self.config))
        database.db_deployment_finish(row[0], "success", "")
        with patch("pygithost.ci.send_notification") as send, patch("pygithost.ci.load_settings", return_value={}):
            await self.manager._deliver_deployment_notification(row)
            send.assert_called_once()

    def test_deployment_documentation_is_rendered(self):
        guide = str(ci_configuration_guide())
        for text in ['id="ci-guide-deployment"', 'href="#ci-guide-deployment"',
                     "Or upload a deployment script", "PYGITHOST_COMMIT",
                     "at most one deployment attempt", "not secret-redacted",
                     "Source checkouts and CI artifacts are not automatically passed"]:
            self.assertIn(text, guide)
