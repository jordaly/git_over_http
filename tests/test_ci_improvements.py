import asyncio
import json
import os
import shutil
import smtplib
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from unittest.mock import AsyncMock

from pygithost import database
from pygithost.application import AsyncGitServer, GitHTTPHandler
from pygithost.ci import CIManager, default_config, docker_command, runner_environment, validate_config
from pygithost.ci_email import send_notification, validate_recipients


class CIImprovementsTests(unittest.IsolatedAsyncioTestCase):
    def test_timeout_configuration(self):
        self.assertEqual(validate_config({})["timeout_seconds"], 1800)
        self.assertEqual(validate_config({"timeout_seconds": "3600"})["timeout_seconds"], 3600)
        for value in (0, -1, True, 1.5, "", "1.5", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_config({"timeout_seconds": value})

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ci-improvements-")
        self.old_db = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "ci.db")
        database._db_init()
        self.managers = []

    async def asyncTearDown(self):
        for manager in self.managers:
            await manager.stop()
            if manager.notification_tasks:
                await asyncio.gather(*tuple(manager.notification_tasks), return_exceptions=True)
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def manager(self, bare=""):
        manager = CIManager(lambda *_: str(bare))
        self.managers.append(manager)
        return manager

    def configured_run(self, config=None, status="queued", event="manual", branch="main", payload=None):
        config = validate_config(config or {"command": "echo hello"})
        run_id = database.db_ci_run_create("owner", "repo", event, branch, "a" * 40, json.dumps(payload or {}), json.dumps(config))
        database.db_ci_run_update(run_id, status=status)
        return (run_id, "owner", "repo", event, branch, "a" * 40, json.dumps(payload or {}))

    def repository(self):
        source = Path(self.temp.name) / "source"
        bare = Path(self.temp.name) / "repo.git"
        subprocess.run(["git", "init", "-b", "main", str(source)], check=True, capture_output=True)
        (source / "fixture.txt").write_text("hello\n")
        subprocess.run(["git", "-C", str(source), "add", "."], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(source), "-c", "user.name=CI", "-c", "user.email=ci@test", "commit", "-m", "initial"], check=True, capture_output=True)
        subprocess.run(["git", "clone", "--bare", str(source), str(bare)], check=True, capture_output=True)
        commit = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        return bare, commit

    async def test_only_one_scheduler_can_own_database_and_lock_is_released(self):
        first, second = self.manager(), self.manager()
        await first.start()
        with self.assertRaisesRegex(RuntimeError, "Another CI scheduler"):
            await second.start()
        await first.stop()
        await second.start()
        self.assertTrue(second.started)

    async def test_database_migration_is_idempotent_and_preserves_old_runs(self):
        run_id = database.db_ci_run_create("owner", "repo", "manual", "main", "a" * 40, "{}")
        with sqlite3.connect(database.DB_PATH) as connection:
            for column in ("config_json", "phase", "reason", "notification"):
                connection.execute(f"ALTER TABLE ci_runs DROP COLUMN {column}")
        database._db_init()
        database._db_init()
        self.assertEqual(database.db_ci_run_get("owner", "repo", run_id)[3], "a" * 40)
        self.assertEqual(database.db_ci_run_metadata("owner", "repo", run_id)["config"], "")

    async def test_cleanup_failure_is_a_warning_not_a_test_failure(self):
        manager = self.manager()
        row = self.configured_run()
        manager._capture_process = AsyncMock(return_value=0)
        with mock.patch("pygithost.ci.shutil.rmtree", side_effect=OSError("cleanup denied")):
            # Keep the test's simulated checkout inside the test-owned directory.
            with mock.patch("pygithost.ci.tempfile.mkdtemp", return_value=str(Path(self.temp.name) / "job")):
                await manager._execute(row)
        self.assertEqual(database.db_ci_run_get("owner", "repo", row[0])[4], "success")
        self.assertIn("cleanup denied", database.db_ci_run_metadata("owner", "repo", row[0])["reason"])

    async def test_checkout_and_command_failures_have_different_phases(self):
        manager = self.manager()
        for returns, phase, exit_code in (([128], "checkout", 128), ([0, 0, 0, 7], "command", 7)):
            row = self.configured_run()
            manager._capture_process = AsyncMock(side_effect=returns)
            await manager._execute(row)
            run = database.db_ci_run_get("owner", "repo", row[0])
            meta = database.db_ci_run_metadata("owner", "repo", row[0])
            self.assertEqual((run[4], run[7], meta["phase"]), ("failed", exit_code, phase))

    async def test_failed_email_can_be_retried_without_rerunning_job(self):
        row = self.configured_run({"command": "echo hi", "email_mode": "all", "email_recipients": "dev@example.test"}, status="success")
        database.db_ci_run_update(row[0], notification="failed (SMTP)")
        manager = self.manager()
        with mock.patch("pygithost.ci.send_notification") as send:
            await manager.retry_email("owner", "repo", row[0])
            await asyncio.gather(*tuple(manager.notification_tasks))
            send.assert_called_once()
        self.assertEqual(database.db_ci_run_metadata("owner", "repo", row[0])["notification"], "sent")
        self.assertEqual(database.db_ci_run_get("owner", "repo", row[0])[4], "success")
        self.assertEqual(len(database.db_ci_runs_list("owner", "repo")), 1)
        with self.assertRaises(ValueError):
            await manager.retry_email("owner", "repo", row[0])

    async def test_queued_run_snapshots_configuration_and_reruns_exact_payload(self):
        manager = self.manager()
        manager.started = True  # Hold dispatch while examining queued records.
        config = {"command": "echo original", "events": {"manual": True}}
        await manager.save_config("owner", "repo", config)
        run_id = await manager.enqueue("owner", "repo", "manual", "main", "b" * 40, {"test": "payload"})
        await manager.save_config("owner", "repo", {"command": "echo changed"})
        rerun_id = await manager.rerun("owner", "repo", run_id)
        meta = database.db_ci_run_metadata("owner", "repo", rerun_id)
        self.assertEqual(json.loads(meta["config"])["command"], "echo original")
        self.assertEqual(json.loads(meta["payload"]), {"test": "payload"})
        self.assertEqual(database.db_ci_run_get("owner", "repo", rerun_id)[3], "b" * 40)

    async def test_queue_limit_records_rejection_without_losing_existing_jobs(self):
        manager = self.manager()
        manager.started, manager.queue_limit = True, 1
        await manager.save_config("owner", "repo", {"command": "echo hi", "events": {"manual": True}})
        first = await manager.enqueue("owner", "repo", "manual", "main", "a" * 40)
        second = await manager.enqueue("owner", "repo", "manual", "main", "b" * 40)
        self.assertEqual(list(manager.pending), [first])
        self.assertEqual(database.db_ci_run_get("owner", "repo", second)[4], "failed")
        self.assertIn("queue is full", database.db_ci_run_metadata("owner", "repo", second)["reason"])

    async def test_cancel_pending_checks_repository_and_supersedes_only_same_pr(self):
        manager = self.manager()
        manager.started = True
        await manager.save_config("owner", "repo", {"command": "echo hi", "events": {"pr_updated": True}, "cancel_superseded": True})
        first = await manager.enqueue("owner", "repo", "pull_request_updated", "main", "a" * 40, {"pr_number": 1})
        other = await manager.enqueue("owner", "repo", "pull_request_updated", "main", "a" * 40, {"pr_number": 2})
        self.assertFalse(await manager.cancel("owner", "wrong", first))
        latest = await manager.enqueue("owner", "repo", "pull_request_updated", "main", "b" * 40, {"pr_number": 1})
        self.assertEqual(database.db_ci_run_get("owner", "repo", first)[4], "cancelled")
        self.assertEqual(set(manager.pending), {other, latest})

    @unittest.skipUnless(os.name == "posix" and shutil.which("git"), "requires POSIX and Git")
    async def test_live_logs_snapshot_and_independent_checkout(self):
        bare, commit = self.repository()
        manager = self.manager(bare)
        config = {"command": 'test -z "$PYGITHOST_SMTP_PASSWORD" || exit 8; printf "live-marker\\n"; sleep 2; git remote; git update-ref -d refs/heads/main; test -f .git/objects/info/alternates && exit 9; printf "finished\\n"'}
        row = list(self.configured_run(config))
        row[5] = commit
        await manager.save_config("owner", "repo", {"command": "echo WRONG"})
        with mock.patch.dict(os.environ, {"PYGITHOST_SMTP_PASSWORD": "server-secret"}):
            task = asyncio.create_task(manager._execute(tuple(row)))
            try:
                for _ in range(100):
                    run = database.db_ci_run_get("owner", "repo", row[0])
                    if "live-marker" in run[5]:
                        break
                    await asyncio.sleep(0.02)
                else:
                    self.fail("logs were not persisted while the job was running")
                self.assertEqual(run[4], "running")
                await task
            finally:
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
        run = database.db_ci_run_get("owner", "repo", row[0])
        self.assertEqual(run[4], "success", run[5])
        self.assertIn("finished", run[5])
        self.assertNotIn("WRONG", run[5])
        self.assertNotIn("origin", run[5])
        self.assertEqual(subprocess.check_output(["git", "--git-dir", str(bare), "rev-parse", "main"], text=True).strip(), commit)

    @unittest.skipUnless(shutil.which("git"), "requires Git")
    async def test_pr_merge_conflict_does_not_execute_command(self):
        bare, _initial = self.repository()
        source = str(Path(self.temp.name) / "source")

        def git(*args):
            return subprocess.check_output(["git", "-C", source, "-c", "user.name=CI", "-c", "user.email=ci@test", *args], stderr=subprocess.STDOUT, text=True).strip()

        git("checkout", "-b", "feature")
        Path(source, "fixture.txt").write_text("head change\n")
        git("commit", "-am", "head")
        head = git("rev-parse", "HEAD")
        git("checkout", "main")
        Path(source, "fixture.txt").write_text("base change\n")
        git("commit", "-am", "base")
        base = git("rev-parse", "HEAD")
        git("push", str(bare), "main", "feature")
        row = list(self.configured_run({"command": "echo must-not-run"}, event="pull_request_updated", payload={"head_commit": head, "base_commit": base, "pr_number": 1}))
        row[5] = base
        await self.manager(bare)._execute(tuple(row))
        run = database.db_ci_run_get("owner", "repo", row[0])
        meta = database.db_ci_run_metadata("owner", "repo", row[0])
        self.assertEqual((run[4], meta["phase"]), ("failed", "merge"))
        self.assertIn("CONFLICT", run[5])
        self.assertNotIn("must-not-run", run[5])

    @unittest.skipUnless(os.name == "posix" and os.environ.get("PYGITHOST_TEST_DOCKER_IMAGE"), "set PYGITHOST_TEST_DOCKER_IMAGE to a local Linux image for Docker integration")
    async def test_real_docker_runner_isolated_environment_and_cleanup(self):
        bare, commit = self.repository()
        manager = self.manager(bare)
        row = list(self.configured_run({"runner": "docker", "image": os.environ["PYGITHOST_TEST_DOCKER_IMAGE"],
            "command": 'test -f fixture.txt && test -z "$PYGITHOST_SMTP_PASSWORD" && printf "docker-ok\\n"'}))
        row[5] = commit
        with mock.patch.dict(os.environ, {"PYGITHOST_SMTP_PASSWORD": "must-not-inherit"}):
            await manager._execute(tuple(row))
        run = database.db_ci_run_get("owner", "repo", row[0])
        self.assertEqual(run[4], "success", run[5])
        self.assertIn("docker-ok", run[5])
        result = subprocess.run(["docker", "inspect", f"pygithost-ci-{os.getpid()}-{row[0]}"], capture_output=True)
        self.assertNotEqual(result.returncode, 0, "CI container was not removed")

    @unittest.skipUnless(os.name == "posix" and os.environ.get("PYGITHOST_TEST_DOCKER_IMAGE"), "set PYGITHOST_TEST_DOCKER_IMAGE to a local Linux image for Docker integration")
    async def test_real_docker_timeout_removes_running_container(self):
        bare, commit = self.repository()
        manager = self.manager(bare)
        row = list(self.configured_run({"runner": "docker", "image": os.environ["PYGITHOST_TEST_DOCKER_IMAGE"],
            "command": "printf 'container-started\\n'; sleep 30"}))
        row[5] = commit
        with mock.patch("pygithost.ci.JOB_TIMEOUT", 3):
            await manager._execute(tuple(row))
        run = database.db_ci_run_get("owner", "repo", row[0])
        self.assertEqual(run[4], "timed_out", run[5])
        self.assertIn("container-started", run[5])
        result = subprocess.run(["docker", "inspect", f"pygithost-ci-{os.getpid()}-{row[0]}"], capture_output=True)
        self.assertNotEqual(result.returncode, 0, "Timed-out container was not removed")

    @unittest.skipUnless(os.name == "posix" and shutil.which("git"), "requires POSIX and Git")
    async def test_cancel_active_job_keeps_partial_output_and_removes_checkout(self):
        bare, commit = self.repository()
        manager = self.manager(bare)
        await manager.save_config("owner", "repo", {"command": "printf 'started\\n'; sleep 20", "events": {"manual": True}})
        run_id = await manager.enqueue("owner", "repo", "manual", "main", commit)
        for _ in range(150):
            run = database.db_ci_run_get("owner", "repo", run_id)
            if "started" in run[5]:
                break
            await asyncio.sleep(0.02)
        else:
            self.fail("job did not start")
        await asyncio.wait_for(manager.cancel("owner", "repo", run_id), timeout=5)
        run = database.db_ci_run_get("owner", "repo", run_id)
        self.assertEqual(run[4], "cancelled")
        self.assertIn("started", run[5])
        self.assertNotIn(run_id, manager.active)

    async def test_cancel_before_task_starts_does_not_leave_active_slot(self):
        manager = self.manager()
        row = self.configured_run()
        task = asyncio.create_task(manager._run_one(row))
        manager.active[row[0]] = (row, task)
        await manager.cancel("owner", "repo", row[0])
        self.assertFalse(manager.active)
        self.assertEqual(database.db_ci_run_get("owner", "repo", row[0])[4], "cancelled")

    async def test_email_modes_and_delivery_errors_do_not_change_run_result(self):
        manager = self.manager()
        for mode, status, expected in (("off", "failed", False), ("failures", "failed", True), ("failures", "success", False), ("all", "success", True), ("all", "cancelled", False), ("recovery", "failed", True)):
            with self.subTest(mode=mode, status=status):
                row = self.configured_run({"command": "echo hi", "email_mode": mode, "email_recipients": "dev@example.test"}, status=status)
                with mock.patch("pygithost.ci.send_notification") as send:
                    await manager._notify(row)
                self.assertEqual(send.called, expected)
        row = self.configured_run({"command": "echo hi", "email_mode": "all", "email_recipients": "dev@example.test"}, status="success")
        with mock.patch("pygithost.ci.send_notification", side_effect=OSError("private credential")):
            await manager._notify(row)
        self.assertEqual(database.db_ci_run_get("owner", "repo", row[0])[4], "success")
        meta = database.db_ci_run_metadata("owner", "repo", row[0])
        self.assertIn("failed", meta["notification"])
        self.assertNotIn("private credential", meta["notification"])

    async def test_recovery_email_uses_same_pr_across_event_types(self):
        manager = self.manager()
        config = {"command": "echo hi", "email_mode": "recovery", "email_recipients": "dev@example.test"}
        self.configured_run(config, "failed", event="pull_request", payload={"pr_number": 1})
        self.configured_run(config, "success", event="pull_request_updated", payload={"pr_number": 2})
        row = self.configured_run(config, "success", event="pull_request_updated", payload={"pr_number": 1})
        with mock.patch("pygithost.ci.send_notification") as send:
            await manager._notify(row)
            send.assert_called_once()

    async def test_queued_notification_resumes_after_restart_but_uncertain_delivery_is_not_duplicated(self):
        config = {"command": "echo hi", "email_mode": "all", "email_recipients": "dev@example.test"}
        row = self.configured_run(config, "success")
        uncertain = self.configured_run(config, "success")
        database.db_ci_run_update(row[0], notification="queued")
        database.db_ci_run_update(uncertain[0], notification="sending")
        manager = self.manager()
        with mock.patch("pygithost.ci.send_notification") as send:
            await manager.start()
            await manager.stop()
            send.assert_called_once()
        self.assertEqual(database.db_ci_run_metadata("owner", "repo", row[0])["notification"], "sent")
        self.assertIn("unknown", database.db_ci_run_metadata("owner", "repo", uncertain[0])["notification"])

    async def test_target_branch_update_triggers_pr_check(self):
        server = object.__new__(AsyncGitServer)
        server.ci_manager = SimpleNamespace(enqueue=AsyncMock())
        server._branch_refs = AsyncMock(return_value={"main": "b" * 40, "feature": "c" * 40})
        with (
            mock.patch("pygithost.application.db_prs_for_source", return_value=[]),
            mock.patch("pygithost.application.db_prs_for_target", return_value=[(7, "feature")]),
            mock.patch("pygithost.application._git_resolve_commit", new=AsyncMock(return_value="c" * 40)),
        ):
            await server._queue_push_changes("owner", "repo", {"main": "a" * 40, "feature": "c" * 40})
        calls = server.ci_manager.enqueue.await_args_list
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1].args[2:5], ("pull_request_updated", "main", "b" * 40))
        self.assertEqual(calls[1].args[5]["head_commit"], "c" * 40)

    async def test_simultaneous_source_and_target_update_does_not_duplicate_pr_check(self):
        server = object.__new__(AsyncGitServer)
        server.ci_manager = SimpleNamespace(enqueue=AsyncMock())
        server._branch_refs = AsyncMock(return_value={"main": "b" * 40, "feature": "d" * 40})
        with (
            mock.patch("pygithost.application.db_prs_for_source", side_effect=lambda _o, _r, branch: [(7, "main")] if branch == "feature" else []),
            mock.patch("pygithost.application.db_prs_for_target", side_effect=lambda _o, _r, branch: [(7, "feature")] if branch == "main" else []),
            mock.patch("pygithost.application._git_resolve_commit", new=AsyncMock(return_value="b" * 40)),
        ):
            await server._queue_push_changes("owner", "repo", {"main": "a" * 40, "feature": "c" * 40})
        checks = [call for call in server.ci_manager.enqueue.await_args_list if call.args[2] == "pull_request_updated"]
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0].args[5]["head_commit"], "d" * 40)

    async def test_invalid_settings_preserve_all_submitted_values(self):
        handler = object.__new__(GitHTTPHandler)
        handler.server = SimpleNamespace(ci_manager=self.manager())
        handler.request = SimpleNamespace()
        handler.remote_is_admin = True
        handler._read_form_urlencoded = AsyncMock(return_value={"command": "echo unsaved", "env": "invalid entry", "event_manual": "on", "email_recipients": "invalid", "runner": "docker", "image": "custom:tag"})
        with (
            mock.patch("pygithost.application._repo_bare_path", return_value=self.temp.name),
            mock.patch("pygithost.application._send_html", new_callable=AsyncMock) as send,
        ):
            await handler._ui_ci_config_save("owner", "repo")
        page = send.await_args.args[2].decode()
        for value in ("echo unsaved", "invalid entry", "custom:tag", 'class="warn"', 'role="alert"'):
            self.assertIn(value, page)
        self.assertIsNone(database.db_ci_config_get("owner", "repo"))

    async def test_actions_require_write_scope_and_logs_are_repository_scoped(self):
        handler = object.__new__(GitHTTPHandler)
        handler.server = SimpleNamespace(ci_manager=self.manager())
        handler.request = SimpleNamespace()
        handler._forbidden = AsyncMock()
        handler._not_found = AsyncMock()
        row = self.configured_run()
        with (
            mock.patch("pygithost.application._repo_bare_path", return_value=self.temp.name),
            mock.patch("pygithost.application.REQUIRE_AUTH", True),
        ):
            await handler._ui_ci_action("owner", "repo", row[0], "cancel")
            handler._forbidden.assert_awaited_once()
            await handler._ui_ci_log("owner", "other", row[0])
            handler._not_found.assert_awaited_once()

    async def test_summary_queries_exclude_logs_and_support_cursor(self):
        first = self.configured_run()[0]
        second = self.configured_run()[0]
        database.db_ci_run_update(first, output="searchable output")
        results = database.db_ci_runs_list("owner", "repo", query="searchable", summary=True, before=second)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], first)
        self.assertEqual(results[0][5], "")

    async def test_configurable_retention_preserves_pending(self):
        pending = self.configured_run()[0]
        with mock.patch.dict(os.environ, {"PYGITHOST_CI_RETENTION": "2"}):
            for _ in range(3):
                self.configured_run(status="success")
        self.assertEqual(len(database.db_ci_runs_list("owner", "repo")), 3)
        self.assertEqual(database.db_ci_run_get("owner", "repo", pending)[4], "queued")


class CIConfigurationAndSMTPTests(unittest.TestCase):
    def test_environment_does_not_inherit_credentials_or_execution_hooks(self):
        with mock.patch.dict(os.environ, {"PYGITHOST_SMTP_PASSWORD": "secret", "AWS_SECRET_ACCESS_KEY": "secret", "PYTHONPATH": "bad", "GIT_CONFIG": "bad"}):
            env = runner_environment("/isolated")
        for key in ("PYGITHOST_SMTP_PASSWORD", "AWS_SECRET_ACCESS_KEY", "PYTHONPATH", "GIT_CONFIG"):
            self.assertNotIn(key, env)
        self.assertEqual(env["HOME"], "/isolated")
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")

    def test_docker_arguments_are_restricted_and_do_not_embed_credentials(self):
        patches = [mock.patch("pygithost.ci.os.getuid", return_value=1000, create=True), mock.patch("pygithost.ci.os.getgid", return_value=1000, create=True)]
        with patches[0], patches[1]:
            command = docker_command("ci-test", "/checkout", "/private/env", default_config())
        for flag in ("--network=none", "--memory=1g", "--cpus=1", "--pids-limit=128", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges"):
            self.assertIn(flag, command)
        self.assertNotIn("/var/run/docker.sock", " ".join(command))
        self.assertIn("--entrypoint", command)
        self.assertEqual(command[-2:], ["-c", ""])

    def test_notification_validation_rejects_header_injection_and_invalid_modes(self):
        for value in ("dev@example.test\r\nBcc: attacker@example.test", "bad address", "a@b;other@c"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_recipients(value)
        with self.assertRaises(ValueError):
            validate_config({"email_mode": "all"})
        with self.assertRaises(ValueError):
            validate_config({"runner": "docker", "env": {"MULTI": "a\nb"}})
        self.assertEqual(validate_recipients("a@b,a@b"), ["a@b"])

    def test_smtp_uses_tls_auth_and_metadata_only(self):
        run = (9, "manual", "main", "a" * 40, "success", "secret log", 0, 0, "", "", "")
        env = {"PYGITHOST_SMTP_HOST": "smtp.example.test", "PYGITHOST_SMTP_FROM": "ci@example.test", "PYGITHOST_SMTP_USERNAME": "ci", "PYGITHOST_SMTP_PASSWORD": "password", "PYGITHOST_PUBLIC_URL": "https://git.example.test/prefix"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch("pygithost.ci_email.smtplib.SMTP") as smtp:
            smtp.return_value.send_message.return_value = {}
            send_notification("owner", "repo", run, ["dev@example.test"])
            smtp.return_value.starttls.assert_called_once()
            smtp.return_value.login.assert_called_once_with("ci", "password")
            message = smtp.return_value.send_message.call_args.args[0]
        plain = message.get_body(preferencelist=("plain",)).get_content()
        html = message.get_body(preferencelist=("html",)).get_content()
        self.assertIn("https://git.example.test/prefix/r/owner/repo/ci/runs/9", plain)
        self.assertIn("View run", html)
        self.assertIn("Run passed", html)
        self.assertNotIn("secret log", plain + html)
        self.assertNotIn("password", str(message))

    def test_smtp_ssl_and_refused_recipients(self):
        run = (9, "manual", "main", "a" * 40, "failed", "", 0, 1)
        env = {"PYGITHOST_SMTP_HOST": "smtp.example.test", "PYGITHOST_SMTP_FROM": "ci@example.test", "PYGITHOST_SMTP_TLS": "ssl"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch("pygithost.ci_email.smtplib.SMTP_SSL") as smtp:
            smtp.return_value.send_message.return_value = {"dev@example.test": (550, "refused")}
            with self.assertRaises(smtplib.SMTPException):
                send_notification("owner", "repo", run, ["dev@example.test"])
            smtp.assert_called_once()
            smtp.return_value.starttls.assert_not_called()

    def test_smtp_never_authenticates_when_tls_negotiation_fails(self):
        run = (9, "manual", "main", "a" * 40, "success", "", 0, 0)
        env = {"PYGITHOST_SMTP_HOST": "smtp.example.test", "PYGITHOST_SMTP_FROM": "ci@example.test", "PYGITHOST_SMTP_USERNAME": "ci", "PYGITHOST_SMTP_PASSWORD": "password"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch("pygithost.ci_email.smtplib.SMTP") as smtp:
            smtp.return_value.starttls.side_effect = smtplib.SMTPNotSupportedError("TLS unavailable")
            with self.assertRaises(smtplib.SMTPNotSupportedError):
                send_notification("owner", "repo", run, ["dev@example.test"])
            smtp.return_value.login.assert_not_called()
            smtp.return_value.send_message.assert_not_called()


if __name__ == "__main__":
    unittest.main()
