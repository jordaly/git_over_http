"""Per-repository asynchronous CI jobs."""

import asyncio
import contextlib
import fnmatch
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import database

MAX_OUTPUT = 1024 * 1024
JOB_TIMEOUT = 30 * 60
BUILTINS = {
    "CI",
    "PYGITHOST_OWNER",
    "PYGITHOST_REPO",
    "PYGITHOST_REPOSITORY",
    "PYGITHOST_EVENT",
    "PYGITHOST_REF",
    "PYGITHOST_BRANCH",
    "PYGITHOST_COMMIT",
    "PYGITHOST_OLD_COMMIT",
    "PYGITHOST_PR_NUMBER",
    "PYGITHOST_BASE_BRANCH",
    "PYGITHOST_HEAD_BRANCH",
    "PYGITHOST_BASE_COMMIT",
    "PYGITHOST_WORKTREE",
}


def _thread_call(func, *args, **kwargs):
    """Return a non-None result so executor completion is reliable on all runtimes."""
    return (func(*args, **kwargs),)


async def _db_call(func, *args, **kwargs):
    (result,) = await asyncio.to_thread(_thread_call, func, *args, **kwargs)
    return result


def default_config():
    return {
        "command": "",
        "env": {},
        "events": {
            "push": False,
            "pr_opened": False,
            "pr_updated": False,
            "pr_reopened": False,
            "pr_merged": False,
            "manual": False,
        },
        "push_branches": "",
        "pr_branches": "",
    }


def validate_config(raw):
    command = raw.get("command", "")
    if not isinstance(command, str) or len(command) > 8192 or "\0" in command:
        raise ValueError("Command must be text up to 8192 characters.")
    env = raw.get("env", {})
    if not isinstance(env, dict) or len(env) > 64:
        raise ValueError("Environment must be a mapping with at most 64 entries.")
    for key, value in env.items():
        if (
            not isinstance(key, str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
            or key in BUILTINS
        ):
            raise ValueError(f"Invalid or reserved environment variable: {key}")
        if not isinstance(value, str) or "\0" in value or len(value) > 8192:
            raise ValueError(f"Invalid value for {key}.")
    defaults = default_config()
    events = raw.get("events", {})
    if not isinstance(events, dict):
        raise ValueError("Events must be a mapping.")
    defaults.update(
        command=command,
        env=env,
        events={k: bool(events.get(k, False)) for k in defaults["events"]},
        push_branches=str(raw.get("push_branches", ""))[:2048],
        pr_branches=str(raw.get("pr_branches", ""))[:2048],
    )
    return defaults


class CIManager:
    def __init__(self, repo_path):
        self.repo_path = repo_path
        self.pending = {}
        self.active = {}
        self.dispatcher = None
        self.wakeup = asyncio.Event()
        self.lifecycle_lock = asyncio.Lock()
        self.started = False
        self.stopping = False

    async def start(self):
        async with self.lifecycle_lock:
            if self.started:
                return
            await _db_call(database.db_ci_recover_runs)
            rows = await _db_call(database.db_ci_queued_runs)
            self.pending = {row[0]: row for row in rows}
            self.stopping = False
            self.started = True
            self.dispatcher = asyncio.create_task(self._dispatch())

    async def stop(self):
        async with self.lifecycle_lock:
            if not self.started:
                return
            self.stopping = True
            if self.dispatcher:
                self.dispatcher.cancel()
            active = list(self.active.values())
            tasks = [task for _row, task in active]
            for task in tasks:
                task.cancel()
            await asyncio.gather(
                *(tasks + ([self.dispatcher] if self.dispatcher else [])),
                return_exceptions=True,
            )
            self.active.clear()
            self.pending.clear()
            self.dispatcher = None
            self.started = False

    async def wait_idle(self):
        while self.active:
            await asyncio.gather(
                *(task for _row, task in tuple(self.active.values())),
                return_exceptions=True,
            )

    async def config(self, owner, repo):
        raw = await _db_call(database.db_ci_config_get, owner, repo)
        return validate_config(json.loads(raw)) if raw else default_config()

    async def save_config(self, owner, repo, config):
        config = validate_config(config)
        await _db_call(database.db_ci_config_set, owner, repo, json.dumps(config))
        return config

    @staticmethod
    def _matches(filters, branch):
        patterns = [line.strip() for line in filters.splitlines() if line.strip()]
        return not patterns or any(
            fnmatch.fnmatchcase(branch, pattern) for pattern in patterns
        )

    async def enqueue(self, owner, repo, event, branch="", commit="", payload=None):
        config = await self.config(owner, repo)
        key = {
            "push": "push",
            "pull_request": "pr_opened",
            "pull_request_updated": "pr_updated",
            "pull_request_reopened": "pr_reopened",
            "pull_request_merged": "pr_merged",
            "manual": "manual",
        }.get(event, event)
        if not config["command"] or not config["events"].get(key, False):
            return None
        if event == "push" and not self._matches(config["push_branches"], branch):
            return None
        if event.startswith("pull_request") and not self._matches(
            config["pr_branches"], (payload or {}).get("base_branch", branch)
        ):
            return None
        if not self.started:
            await self.start()
        if self.stopping:
            return None
        payload = payload or {}
        run_id = await _db_call(
            database.db_ci_run_create,
            owner,
            repo,
            event,
            branch,
            commit,
            json.dumps(payload),
        )
        row = (run_id, owner, repo, event, branch, commit, json.dumps(payload))
        self.pending[run_id] = row
        self.wakeup.set()
        return run_id

    async def _dispatch(self):
        while True:
            active_repos = {(row[1], row[2]) for row, _task in self.active.values()}
            for run_id, row in sorted(tuple(self.pending.items())):
                if len(self.active) >= 2:
                    break
                repository = (row[1], row[2])
                if repository in active_repos:
                    continue
                self.pending.pop(run_id, None)
                task = asyncio.create_task(self._run_one(row))
                self.active[run_id] = (row, task)
                active_repos.add(repository)
            self.wakeup.clear()
            await self.wakeup.wait()

    async def _run_one(self, row):
        try:
            await self._execute(row)
        except asyncio.CancelledError:
            await _db_call(
                database.db_ci_run_update,
                row[0],
                status="interrupted",
                finished_at=datetime.now(timezone.utc).isoformat(),
            )
            raise
        except Exception as exc:
            await _db_call(
                database.db_ci_run_update,
                row[0],
                status="failed",
                output=str(exc)[:MAX_OUTPUT],
                finished_at=datetime.now(timezone.utc).isoformat(),
            )
        finally:
            self.active.pop(row[0], None)
            self.wakeup.set()

    async def _capture_process(
        self, command, *, shell, cwd, env, output, truncated, timeout
    ):
        if timeout <= 0:
            raise asyncio.TimeoutError
        if os.name == "nt":
            launcher = str(Path(__file__).with_name("ci_windows_launcher.py"))
            invocation = (
                [sys.executable, launcher, "--shell", command]
                if shell
                else [sys.executable, launcher, "--exec", *command]
            )
            process = await asyncio.create_subprocess_exec(
                *invocation,
                cwd=cwd,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
        elif shell:
            process = await asyncio.create_subprocess_shell(
                command,
                cwd=cwd,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )
        else:
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=cwd,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )

        async def drain_and_wait():
            while True:
                chunk = await process.stdout.read(65536)
                if not chunk:
                    break
                available = MAX_OUTPUT - len(output)
                if available > 0:
                    output.extend(chunk[:available])
                if len(chunk) > available:
                    truncated[0] = True
            return await process.wait()

        try:
            return await asyncio.wait_for(drain_and_wait(), timeout=timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            if os.name == "nt":
                if process.returncode is None:
                    process.kill()  # Killing the launcher closes its Job Object and its child tree.
            else:
                # The shell may have exited while a descendant still holds stdout open.
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
            if process.returncode is None:
                await process.wait()
            raise

    async def _execute(self, row):
        run_id, owner, repo, event, branch, commit, payload_json = row
        payload = json.loads(payload_json or "{}")
        config = await self.config(owner, repo)
        if not config["command"]:
            await _db_call(
                database.db_ci_run_update,
                run_id,
                status="failed",
                output="No CI command is configured.",
                return_code=1,
                finished_at=datetime.now(timezone.utc).isoformat(),
            )
            return
        if not commit and branch:
            commit = payload.get("commit", "")
        await _db_call(
            database.db_ci_run_update,
            run_id,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        output = bytearray()
        truncated = [False]
        temp_root = tempfile.mkdtemp(prefix="pygithost-ci-")
        worktree = str(Path(temp_root) / "checkout")
        bare = self.repo_path(owner, repo)
        rc, status, cancelled = -1, "failed", False
        deadline = asyncio.get_running_loop().time() + JOB_TIMEOUT
        try:
            git_dir = ["git", "--git-dir", bare]
            rc = await self._capture_process(
                [*git_dir, "worktree", "add", "--detach", worktree, commit],
                shell=False,
                cwd=None,
                env=os.environ.copy(),
                output=output,
                truncated=truncated,
                timeout=deadline - asyncio.get_running_loop().time(),
            )
            if (
                rc == 0
                and event.startswith("pull_request")
                and payload.get("head_commit")
            ):
                rc = await self._capture_process(
                    [
                        "git",
                        "-C",
                        worktree,
                        "merge",
                        "--no-commit",
                        "--no-ff",
                        payload["head_commit"],
                    ],
                    shell=False,
                    cwd=None,
                    env=os.environ.copy(),
                    output=output,
                    truncated=truncated,
                    timeout=deadline - asyncio.get_running_loop().time(),
                )
            if rc == 0:
                env = os.environ.copy()
                env.update(
                    {
                        "CI": "true",
                        "PYGITHOST_OWNER": owner,
                        "PYGITHOST_REPO": repo,
                        "PYGITHOST_REPOSITORY": f"{owner}/{repo}",
                        "PYGITHOST_EVENT": event,
                        "PYGITHOST_REF": f"refs/heads/{branch}" if branch else "",
                        "PYGITHOST_BRANCH": branch,
                        "PYGITHOST_COMMIT": commit,
                        "PYGITHOST_OLD_COMMIT": payload.get("old_commit", ""),
                        "PYGITHOST_PR_NUMBER": str(payload.get("pr_number", "")),
                        "PYGITHOST_BASE_BRANCH": payload.get("base_branch", ""),
                        "PYGITHOST_HEAD_BRANCH": payload.get("head_branch", branch),
                        "PYGITHOST_BASE_COMMIT": payload.get("base_commit", ""),
                        "PYGITHOST_WORKTREE": worktree,
                    }
                )
                env.update(config["env"])
                rc = await self._capture_process(
                    config["command"],
                    shell=True,
                    cwd=worktree,
                    env=env,
                    output=output,
                    truncated=truncated,
                    timeout=deadline - asyncio.get_running_loop().time(),
                )
            status = "success" if rc == 0 else "failed"
        except asyncio.TimeoutError:
            rc, status = -1, "timed_out"
            output.extend(
                b"CI execution exceeded the 30 minute limit.\n"[
                    : MAX_OUTPUT - len(output)
                ]
            )
        except asyncio.CancelledError:
            rc, status, cancelled = -1, "interrupted", True
        except Exception as exc:
            rc, status = -1, "failed"
            message = (str(exc) + "\n").encode("utf-8", "replace")
            output.extend(message[: MAX_OUTPUT - len(output)])
        finally:
            cleanup_error = None
            if os.path.isdir(worktree):
                try:
                    remove_rc = await self._capture_process(
                        [
                            "git",
                            "--git-dir",
                            bare,
                            "worktree",
                            "remove",
                            "--force",
                            worktree,
                        ],
                        shell=False,
                        cwd=None,
                        env=os.environ.copy(),
                        output=output,
                        truncated=truncated,
                        timeout=30,
                    )
                    if remove_rc:
                        cleanup_error = "Git worktree removal failed."
                except Exception as exc:
                    cleanup_error = f"Git worktree removal failed: {exc}"
            try:
                await asyncio.wait_for(
                    _db_call(shutil.rmtree, temp_root, True), timeout=30
                )
            except Exception as exc:
                cleanup_error = f"Temporary directory cleanup failed: {exc}"
            if cleanup_error:
                output.extend(
                    (cleanup_error + "\n").encode()[: MAX_OUTPUT - len(output)]
                )
                if status == "success":
                    status = "failed"
        await _db_call(
            database.db_ci_run_update,
            run_id,
            status=status,
            output=bytes(output).decode("utf-8", "replace"),
            truncated=int(truncated[0]),
            return_code=rc,
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        if cancelled:
            raise asyncio.CancelledError
