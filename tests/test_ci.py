import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from unittest.mock import AsyncMock

from pygithost import database
from pygithost.application import AsyncGitServer, GitHTTPHandler, Headers, FLAT_OWNER_UI
from pygithost.config import AppConfig
from pygithost.context import AppContext
from pygithost.ci import CIManager


class CICoreTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pygithost-ci-test-")
        self.old_db_path = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "ci.db")
        database._db_init()

    def tearDown(self):
        database.DB_PATH = self.old_db_path
        self.temp.cleanup()

    def _queued_run(self, repo, event="manual"):
        return database.db_ci_run_create("owner", repo, event, "main", "a" * 40, "{}")

    def _run_status(self, repo, run_id):
        return database.db_ci_run_get("owner", repo, run_id)[4]

    async def test_retention_keeps_pending_jobs_and_caps_completed_history(self):
        pending_id = self._queued_run("retention")
        finished_ids = []
        for _ in range(105):
            run_id = self._queued_run("retention")
            finished_ids.append(run_id)
            database.db_ci_run_update(run_id, status="success", return_code=0)

        self.assertIsNotNone(database.db_ci_run_get("owner", "retention", pending_id))
        completed = [
            row
            for row in database.db_ci_runs_list("owner", "retention", 200)
            if row[4] == "success"
        ]
        self.assertEqual(len(completed), 100)

    async def test_scheduler_skips_busy_repo_and_preserves_waiting_jobs_on_stop(self):
        first_a = self._queued_run("repo_a")
        second_a = self._queued_run("repo_a")
        first_b = self._queued_run("repo_b")
        started = asyncio.Queue()
        hold = asyncio.Event()

        async def hold_run(row):
            database.db_ci_run_update(row[0], status="running")
            await started.put(row[0])
            await hold.wait()
            database.db_ci_run_update(row[0], status="success", return_code=0)

        manager = CIManager(lambda *_: "")
        manager._execute = hold_run
        await manager.start()
        started_ids = {
            await asyncio.wait_for(started.get(), timeout=1) for _ in range(2)
        }
        self.assertEqual(started_ids, {first_a, first_b})
        self.assertEqual(self._run_status("repo_a", second_a), "queued")

        await manager.stop()
        self.assertEqual(self._run_status("repo_a", first_a), "interrupted")
        self.assertEqual(self._run_status("repo_b", first_b), "interrupted")
        self.assertEqual(self._run_status("repo_a", second_a), "queued")

        async def finish_run(row):
            database.db_ci_run_update(row[0], status="success", return_code=0)

        resumed = CIManager(lambda *_: "")
        resumed._execute = finish_run
        await resumed.start()
        for _ in range(100):
            if self._run_status("repo_a", second_a) == "success":
                break
            await asyncio.sleep(0.01)
        await resumed.stop()
        self.assertEqual(self._run_status("repo_a", second_a), "success")

    async def test_dispatcher_survives_enqueue_and_finishing_active_runs(self):
        rows = []
        for repo in ("repo_a", "repo_b", "repo_c"):
            run_id = self._queued_run(repo)
            rows.append((run_id, "owner", repo, "manual", "main", "a" * 40, "{}"))
        started = asyncio.Queue()
        releases = {row[0]: asyncio.Event() for row in rows}

        async def controlled_run(row):
            database.db_ci_run_update(row[0], status="running")
            await started.put(row[0])
            await releases[row[0]].wait()
            database.db_ci_run_update(row[0], status="success", return_code=0)

        manager = CIManager(lambda *_: "")
        manager._execute = controlled_run
        await manager.start()
        try:
            first = {await asyncio.wait_for(started.get(), timeout=1) for _ in range(2)}
            self.assertEqual(first, {rows[0][0], rows[1][0]})
            releases[rows[0][0]].set()
            third = await asyncio.wait_for(started.get(), timeout=1)
            self.assertEqual(third, rows[2][0])
            self.assertEqual(self._run_status("repo_b", rows[1][0]), "running")
            releases[rows[1][0]].set()
            releases[rows[2][0]].set()
            await asyncio.wait_for(manager.wait_idle(), timeout=1)
        finally:
            for release in releases.values():
                release.set()
            await manager.stop()
        self.assertTrue(
            all(self._run_status(row[2], row[0]) == "success" for row in rows)
        )

    async def test_push_finalizer_queues_added_and_updated_refs_only(self):
        server = object.__new__(AsyncGitServer)
        calls = []

        async def record_enqueue(*args):
            calls.append(args)

        class Manager:
            enqueue = staticmethod(record_enqueue)

        server.ci_manager = Manager()

        async def refs(_owner, _repo):
            return {"main": "b" * 40, "new": "c" * 40}

        server._branch_refs = refs

        await server._queue_push_changes(
            "owner", "repo", {"main": "a" * 40, "deleted": "d" * 40}
        )
        self.assertEqual(
            [(call[2], call[3], call[4]) for call in calls],
            [("push", "main", "b" * 40), ("push", "new", "c" * 40)],
        )

    @unittest.skipUnless(
        os.name == "posix" and shutil.which("git"), "requires POSIX and Git"
    )
    async def test_push_finalizer_failure_still_releases_repository_lock(self):
        root = Path(self.temp.name)
        bare = root / "repo.git"
        subprocess.run(
            ["git", "init", "--bare", str(bare)], check=True, capture_output=True
        )
        backend = root / "git-http-backend"
        backend.write_text(
            "#!/bin/sh\nprintf 'Status: 200 OK\\r\\n\\r\\n'\n", encoding="utf-8"
        )
        backend.chmod(0o755)
        config = AppConfig.from_mapping(
            {
                **AppConfig.default_for_platform().to_dict(),
                "git_project_root": str(root),
                "git_http_backend": str(backend),
                "db_path": database.DB_PATH,
            }
        )
        app = AsyncGitServer(AppContext(config), allowlist={"127.0.0.1"})

        class Writer:
            def write(self, _data):
                pass

            async def drain(self):
                pass

        def make_handler():
            reader = asyncio.StreamReader()
            reader.feed_eof()
            request = SimpleNamespace(
                target="/git/repo.git/git-receive-pack",
                method="POST",
                version="HTTP/1.1",
                headers=Headers(
                    [
                        ("Content-Length", "0"),
                        ("Content-Type", "application/x-git-receive-pack"),
                    ]
                ),
                reader=reader,
                writer=Writer(),
                peer_ip="127.0.0.1",
            )
            return GitHTTPHandler(request, app)

        handler = make_handler()

        async def fail_finalizer(*_args):
            raise RuntimeError("database unavailable")

        app._queue_push_changes = fail_finalizer
        with self.assertRaisesRegex(RuntimeError, "database unavailable"):
            await handler._handle_git()
        lock = app.push_locks[(FLAT_OWNER_UI, "repo")]
        self.assertFalse(lock.locked())
        self.assertFalse(app.push_requests)

        entered = asyncio.Event()
        finish = asyncio.Event()

        async def wait_finalizer(*_args):
            entered.set()
            await finish.wait()

        app._queue_push_changes = wait_finalizer
        task = asyncio.create_task(make_handler()._handle_git())
        await asyncio.wait_for(entered.wait(), timeout=2)
        task.cancel()
        finish.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(lock.locked())
        self.assertFalse(app.push_requests)
        await app.shutdown()

    @unittest.skipUnless(
        os.name == "posix" and shutil.which("git"), "requires POSIX and Git"
    )
    async def test_push_ref_change_is_queued_when_response_client_disconnects(self):
        root = Path(self.temp.name)
        source, bare = root / "source", root / "repo.git"
        source.mkdir()
        subprocess.run(
            ["git", "init", "-b", "main", str(source)], check=True, capture_output=True
        )
        subprocess.run(
            ["git", "-C", str(source), "config", "user.name", "CI test"], check=True
        )
        subprocess.run(
            ["git", "-C", str(source), "config", "user.email", "ci@example.test"],
            check=True,
        )
        (source / "fixture.txt").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(source), "add", "fixture.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(source), "commit", "-m", "fixture"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "clone", "--bare", str(source), str(bare)],
            check=True,
            capture_output=True,
        )
        (source / "next.txt").write_text("next\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(source), "add", "next.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(source), "commit", "-m", "next"],
            check=True,
            capture_output=True,
        )
        next_commit = subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
        ).strip()
        subprocess.run(
            ["git", "--git-dir", str(bare), "fetch", str(source), "main"],
            check=True,
            capture_output=True,
        )
        backend = root / "fake-git-backend"
        backend.write_text(
            "#!/bin/sh\n"
            f'git --git-dir="$GIT_PROJECT_ROOT/repo.git" update-ref refs/heads/main {next_commit}\n'
            "printf 'Status: 200 OK\\r\\nContent-Type: application/octet-stream\\r\\n\\r\\nbackend output'\n",
            encoding="utf-8",
        )
        backend.chmod(0o755)
        config = AppConfig.from_mapping(
            {
                **AppConfig.default_for_platform().to_dict(),
                "git_project_root": str(root),
                "git_http_backend": str(backend),
                "db_path": database.DB_PATH,
            }
        )
        app = AsyncGitServer(AppContext(config), allowlist={"127.0.0.1"})
        database.db_ci_config_set(
            FLAT_OWNER_UI,
            "repo",
            json.dumps(
                {
                    "command": "true",
                    "env": {},
                    "events": {"push": True},
                    "push_branches": "",
                    "pr_branches": "",
                }
            ),
        )

        class DisconnectedWriter:
            def write(self, _data):
                pass

            async def drain(self):
                raise ConnectionResetError

        reader = asyncio.StreamReader()
        request = SimpleNamespace(
            target="/git/repo.git/git-receive-pack",
            method="POST",
            version="HTTP/1.1",
            headers=Headers(
                [
                    ("Content-Length", "0"),
                    ("Content-Type", "application/x-git-receive-pack"),
                ]
            ),
            reader=reader,
            writer=DisconnectedWriter(),
            peer_ip="127.0.0.1",
        )
        handler = GitHTTPHandler(request, app)

        async def disconnected(_data):
            return False

        handler._write_git_response = disconnected
        await handler._handle_git()
        for _ in range(100):
            runs = await asyncio.to_thread(
                database.db_ci_runs_list, FLAT_OWNER_UI, "repo", 10
            )
            if runs and runs[0][4] == "success":
                break
            await asyncio.sleep(0.01)
        await app.shutdown()
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0][1:5], ("push", "main", next_commit, "success"))

    async def test_ci_results_poll_without_replacing_settings_form(self):
        handler = object.__new__(GitHTTPHandler)
        handler.server = SimpleNamespace(ci_manager=CIManager(lambda *_: ""))
        handler.request = SimpleNamespace()
        handler.remote_is_admin = False

        async def branches(_repo):
            return ["main"]

        with (
            mock.patch(
                "pygithost.application._repo_bare_path", return_value=self.temp.name
            ),
            mock.patch(
                "pygithost.application._git_list_branches", side_effect=branches
            ),
            mock.patch(
                "pygithost.application._send_html", new_callable=AsyncMock
            ) as send_html,
            mock.patch(
                "pygithost.application._send_response", new_callable=AsyncMock
            ) as send_response,
        ):
            await handler._ui_ci("owner", "repo")
            full_page = send_html.await_args.args[2].decode("utf-8")
            self.assertIn('name="command"', full_page)
            self.assertIn("setInterval(update, 5000)", full_page)
            self.assertIn("current.outerHTML = fragment", full_page)
            self.assertNotIn('http-equiv="refresh"', full_page)

            await handler._ui_ci("owner", "repo", partial=True)
            fragment, headers = send_response.await_args.args[2:4]
            self.assertIn('id="ci-results"', fragment.decode("utf-8"))
            self.assertNotIn('name="command"', fragment.decode("utf-8"))
            self.assertIn(("Cache-Control", "no-store"), headers)

    @unittest.skipUnless(
        os.name == "posix" and shutil.which("git"), "requires POSIX and Git"
    )
    async def test_timed_out_command_keeps_output_and_removes_worktree(self):
        root = Path(self.temp.name)
        source = root / "source"
        bare = root / "repo.git"
        source.mkdir()
        subprocess.run(
            ["git", "init", "-b", "main", str(source)], check=True, capture_output=True
        )
        subprocess.run(
            ["git", "-C", str(source), "config", "user.name", "CI test"], check=True
        )
        subprocess.run(
            ["git", "-C", str(source), "config", "user.email", "ci@example.test"],
            check=True,
        )
        (source / "fixture.txt").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(source), "add", "fixture.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(source), "commit", "-m", "fixture"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "clone", "--bare", str(source), str(bare)],
            check=True,
            capture_output=True,
        )
        commit = subprocess.check_output(
            ["git", "--git-dir", str(bare), "rev-parse", "refs/heads/main"], text=True
        ).strip()
        config = {
            "command": "printf 'started'; sleep 10",
            "env": {},
            "events": {},
            "push_branches": "",
            "pr_branches": "",
        }
        database.db_ci_config_set("owner", "timeout", json.dumps(config))
        run_id = self._queued_run("timeout")
        row = (run_id, "owner", "timeout", "manual", "main", commit, "{}")
        manager = CIManager(lambda *_: str(bare))
        with mock.patch("pygithost.ci.JOB_TIMEOUT", 0.2):
            await manager._execute(row)

        result = database.db_ci_run_get("owner", "timeout", run_id)
        self.assertEqual(result[4], "timed_out")
        self.assertIn("started", result[5])
        worktrees = subprocess.check_output(
            ["git", "--git-dir", str(bare), "worktree", "list", "--porcelain"],
            text=True,
        )
        self.assertEqual(worktrees.count("worktree "), 1)

    @unittest.skipUnless(
        os.name == "posix" and Path("/proc").is_dir(), "requires POSIX /proc"
    )
    async def test_timeout_kills_descendant_when_shell_exits_first(self):
        manager = CIManager(lambda *_: "")
        output, truncated = bytearray(), [False]
        with self.assertRaises(asyncio.TimeoutError):
            await manager._capture_process(
                "sleep 30 & echo $!; echo started",
                shell=True,
                cwd=self.temp.name,
                env=os.environ.copy(),
                output=output,
                truncated=truncated,
                timeout=0.2,
            )
        self.assertIn(b"started", output)
        child_pid = int(output.splitlines()[0])
        proc_stat = Path(f"/proc/{child_pid}/stat")
        for _ in range(100):
            try:
                state = proc_stat.read_text(encoding="ascii").split()[2]
            except (FileNotFoundError, ProcessLookupError):
                break
            if state == "Z":
                break
            await asyncio.sleep(0.01)
        else:
            self.fail("the background child was still running after the timeout")

    @unittest.skipUnless(os.name == "nt", "requires native Windows process management")
    async def test_windows_launcher_terminates_command_tree_on_timeout(self):
        manager = CIManager(lambda *_: "")
        output, truncated = bytearray(), [False]
        child_pid_file = Path(self.temp.name) / "child.pid"
        child_code = (
            "import subprocess,sys,time; "
            f"child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
            f"open({str(child_pid_file)!r},'w').write(str(child.pid)); "
            "print('started', flush=True); time.sleep(30)"
        )
        with self.assertRaises(asyncio.TimeoutError):
            await manager._capture_process(
                f'"{sys.executable}" -c "{child_code}"',
                shell=True,
                cwd=self.temp.name,
                env=os.environ.copy(),
                output=output,
                truncated=truncated,
                timeout=0.2,
            )
        self.assertIn(b"started", output)
        child_pid = int(child_pid_file.read_text(encoding="ascii"))
        with self.assertRaises(OSError):
            os.kill(child_pid, 0)

    @unittest.skipUnless(os.name == "nt", "requires native Windows process management")
    async def test_windows_launcher_preserves_environment_cwd_and_exit_code(self):
        manager = CIManager(lambda *_: "")
        output, truncated = bytearray(), [False]
        env = os.environ.copy()
        env["PYGITHOST_LAUNCHER_TEST"] = "working"
        code = "import os; print(os.getcwd()); print(os.environ['PYGITHOST_LAUNCHER_TEST'])"
        result = await manager._capture_process(
            f'"{sys.executable}" -c "{code}"',
            shell=True,
            cwd=self.temp.name,
            env=env,
            output=output,
            truncated=truncated,
            timeout=10,
        )
        self.assertEqual(result, 0)
        self.assertIn(self.temp.name.encode(), output)
        self.assertIn(b"working", output)

        output.clear()
        result = await manager._capture_process(
            f'"{sys.executable}" -c "raise SystemExit(7)"',
            shell=True,
            cwd=self.temp.name,
            env=env,
            output=output,
            truncated=truncated,
            timeout=10,
        )
        self.assertEqual(result, 7)


if __name__ == "__main__":
    unittest.main()
