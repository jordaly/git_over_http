"""Per-repository asynchronous CI jobs."""

import asyncio
import fnmatch
import json
import os
import re
import signal
import shutil
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
        self.queue = asyncio.Queue()
        self.workers = []
        self.started = False
        self.repo_locks = {}

    async def start(self):
        if self.started:
            return
        self.started = True
        await asyncio.to_thread(database.db_ci_recover_runs)
        for row in await asyncio.to_thread(database.db_ci_queued_runs):
            await self.queue.put(row)
        self.workers = [asyncio.create_task(self._worker()) for _ in range(2)]

    async def stop(self):
        for worker in self.workers:
            worker.cancel()
        if self.workers:
            await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers.clear()
        self.started = False

    async def config(self, owner, repo):
        raw = await asyncio.to_thread(database.db_ci_config_get, owner, repo)
        return validate_config(json.loads(raw)) if raw else default_config()

    async def save_config(self, owner, repo, config):
        config = validate_config(config)
        await asyncio.to_thread(
            database.db_ci_config_set, owner, repo, json.dumps(config)
        )
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
        payload = payload or {}
        run_id = await asyncio.to_thread(
            database.db_ci_run_create,
            owner,
            repo,
            event,
            branch,
            commit,
            json.dumps(payload),
        )
        row = (run_id, owner, repo, event, branch, commit, json.dumps(payload))
        await self.queue.put(row)
        return run_id

    async def _worker(self):
        while True:
            row = await self.queue.get()
            try:
                lock = self.repo_locks.setdefault((row[1], row[2]), asyncio.Lock())
                async with lock:
                    await self._execute(row)
            except asyncio.CancelledError:
                await asyncio.to_thread(
                    database.db_ci_run_update,
                    row[0],
                    status="interrupted",
                    finished_at=datetime.now(timezone.utc).isoformat(),
                )
                raise
            except Exception as exc:
                await asyncio.to_thread(
                    database.db_ci_run_update,
                    row[0],
                    status="failed",
                    output=str(exc)[:MAX_OUTPUT],
                    finished_at=datetime.now(timezone.utc).isoformat(),
                )
            finally:
                self.queue.task_done()

    async def _execute(self, row):
        run_id, owner, repo, event, branch, commit, payload_json = row
        payload = json.loads(payload_json or "{}")
        config = await self.config(owner, repo)
        if not config["command"]:
            await asyncio.to_thread(
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
        await asyncio.to_thread(
            database.db_ci_run_update,
            run_id,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        output = bytearray()
        truncated = False
        temp_root = tempfile.mkdtemp(prefix="pygithost-ci-")
        worktree = str(Path(temp_root) / "checkout")
        bare = self.repo_path(owner, repo)
        rc, status = -1, "failed"
        try:
            # Build a detached temporary checkout. Avoid importing repository values into shell source.
            proc = await asyncio.create_subprocess_exec(
                "git",
                "--git-dir",
                bare,
                "worktree",
                "add",
                "--detach",
                worktree,
                commit,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            checkout = await proc.stdout.read() if proc.stdout else b""
            rc = await proc.wait()
            if rc:
                output.extend(checkout[:MAX_OUTPUT])
                truncated = len(checkout) > MAX_OUTPUT
            else:
                if event.startswith("pull_request") and payload.get("head_commit"):
                    merge = await asyncio.create_subprocess_exec(
                        "git",
                        "-C",
                        worktree,
                        "merge",
                        "--no-commit",
                        "--no-ff",
                        payload["head_commit"],
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    merge_output = await merge.stdout.read() if merge.stdout else b""
                    merge_rc = await merge.wait()
                    output.extend(merge_output[:MAX_OUTPUT])
                    truncated = len(merge_output) > MAX_OUTPUT
                    if merge_rc:
                        rc, status = merge_rc, "failed"
                    else:
                        rc = None
                else:
                    rc = None
                if rc is None:
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
                    process = await asyncio.create_subprocess_shell(
                        config["command"],
                        cwd=worktree,
                        env=env,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                        start_new_session=(os.name != "nt"),
                    )
                    try:

                        async def capture():
                            nonlocal truncated
                            while True:
                                chunk = await process.stdout.read(65536)
                                if not chunk:
                                    break
                                available = MAX_OUTPUT - len(output)
                                if available > 0:
                                    output.extend(chunk[:available])
                                if len(chunk) > available:
                                    truncated = True

                        async def capture_and_wait():
                            await capture()
                            return await process.wait()

                        rc = await asyncio.wait_for(
                            capture_and_wait(), timeout=JOB_TIMEOUT
                        )
                        status = "success" if rc == 0 else "failed"
                    except asyncio.TimeoutError:
                        if os.name != "nt":
                            os.killpg(process.pid, signal.SIGKILL)
                        else:
                            process.kill()
                        await process.wait()
                        rc, status = -1, "timed_out"
                    except asyncio.CancelledError:
                        if process.returncode is None:
                            if os.name != "nt":
                                os.killpg(process.pid, signal.SIGKILL)
                            else:
                                process.kill()
                            await process.wait()
                        raise
        finally:
            if os.path.isdir(worktree):
                remove = await asyncio.create_subprocess_exec(
                    "git",
                    "--git-dir",
                    bare,
                    "worktree",
                    "remove",
                    "--force",
                    worktree,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await remove.wait()
            shutil.rmtree(temp_root, ignore_errors=True)
        await asyncio.to_thread(
            database.db_ci_run_update,
            run_id,
            status=status,
            output=bytes(output).decode("utf-8", "replace"),
            truncated=1 if truncated else 0,
            return_code=rc,
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
