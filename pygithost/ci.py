"""Per-repository asynchronous CI jobs."""

import asyncio
import contextlib
import fnmatch
import json
import logging
import os
import re
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import database
from .ci_email import load_settings, send_notification, validate_recipients

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
        "timeout_seconds": JOB_TIMEOUT,
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
        "runner": "host",
        "image": "python:3.14-slim",
        "email_recipients": "",
        "email_mode": "off",
        "cancel_superseded": False,
    }


def validate_config(raw):
    if not isinstance(raw, dict):
        raise ValueError("CI configuration must be a mapping.")
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
    timeout = raw.get("timeout_seconds", JOB_TIMEOUT)
    if isinstance(timeout, str) and timeout.isascii() and timeout.isdecimal():
        timeout = int(timeout)
    if type(timeout) is not int or timeout <= 0:
        raise ValueError("Timeout must be a positive whole number of seconds.")
    runner = raw.get("runner", "host")
    image = raw.get("image", "python:3.14-slim")
    mode = raw.get("email_mode", "off")
    if runner not in ("host", "docker"):
        raise ValueError("Runner must be host or docker.")
    if not isinstance(image, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,255}", image):
        raise ValueError("Enter a valid Docker image name.")
    if mode not in ("off", "failures", "all", "recovery"):
        raise ValueError("Invalid email notification mode.")
    recipients = validate_recipients(raw.get("email_recipients", ""))
    if mode != "off" and not recipients:
        raise ValueError("Email notifications require at least one recipient.")
    if runner == "docker" and any("\n" in value or "\r" in value for value in env.values()):
        raise ValueError("Docker environment values cannot contain newlines.")
    events = raw.get("events", {})
    if not isinstance(events, dict):
        raise ValueError("Events must be a mapping.")
    if any(not isinstance(value, bool) for value in events.values()):
        raise ValueError("Event settings must be true or false.")
    for name in ("push_branches", "pr_branches"):
        value = raw.get(name, "")
        if not isinstance(value, str) or len(value) > 2048 or "\0" in value:
            raise ValueError("Branch filters must be text up to 2048 characters.")
    defaults.update(
        command=command,
        timeout_seconds=timeout,
        env=env,
        events={k: bool(events.get(k, False)) for k in defaults["events"]},
        push_branches=raw.get("push_branches", ""),
        pr_branches=raw.get("pr_branches", ""),
        runner=runner, image=image, email_mode=mode,
        email_recipients="\n".join(recipients),
        cancel_superseded=bool(raw.get("cancel_superseded", False)),
    )
    return defaults


def runner_environment(home):
    """Do not pass server credentials, Python hooks, or Git overrides to jobs."""
    allowed = ("PATH", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL")
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    env.update(HOME=home, USERPROFILE=home, TMPDIR=home, TMP=home, TEMP=home,
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT="0", GIT_AUTHOR_NAME="CI", GIT_AUTHOR_EMAIL="ci@localhost",
               GIT_COMMITTER_NAME="CI", GIT_COMMITTER_EMAIL="ci@localhost")
    return env


def docker_command(name, worktree, env_file, config):
    command = ["docker", "run", "--name", name, "--init", "--network=none", "--pull=never", "--log-driver=none",
               "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=1g",
               "--cpus=1", "--pids-limit=128", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
               "--mount", f"type=bind,src={worktree},dst=/workspace", "--workdir", "/workspace",
               "--env-file", env_file, "--entrypoint", "/bin/sh"]
    if os.name == "posix":
        if os.getuid() == 0:
            raise ValueError("Run the Docker CI server as an unprivileged user, not root.")
        command += ["--user", f"{os.getuid()}:{os.getgid()}"]
    return [*command, config["image"], "-c", config["command"]]


def remove_checkout(path):
    def writable(func, target, error):
        if os.name != "nt" or not isinstance(error, PermissionError):
            raise error
        # Git objects can have the Windows read-only attribute. Do not follow
        # checkout symlinks when clearing it.
        os.chmod(target, stat.S_IWRITE, follow_symlinks=False)
        func(target)

    shutil.rmtree(path, onexc=writable)


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
        self.enqueue_lock = asyncio.Lock()
        self.cancelled = set()
        self.notification_tasks = set()
        self.notification_slots = asyncio.Semaphore(2)
        self.runner_lock = None
        self.max_concurrency = max(1, int(os.environ.get("PYGITHOST_CI_CONCURRENCY", "2")))
        self.queue_limit = max(1, int(os.environ.get("PYGITHOST_CI_QUEUE_LIMIT", "100")))

    async def start(self):
        async with self.lifecycle_lock:
            if self.started:
                return
            self._acquire_runner_lock()
            try:
                await _db_call(database.db_ci_recover_runs)
                rows = await _db_call(database.db_ci_queued_runs)
                notifications = await _db_call(database.db_ci_pending_notifications)
            except BaseException:
                self._release_runner_lock()
                raise
            self.pending = {row[0]: row for row in rows}
            self.stopping = False
            self.started = True
            self.dispatcher = asyncio.create_task(self._dispatch())
            for row in notifications:
                self._schedule_notification(row)

    def _acquire_runner_lock(self):
        """One scheduler per database; OS releases the lock after a crash."""
        path = Path(str(database.DB_PATH) + ".ci.lock")
        handle = path.open("a+b")
        try:
            if os.name == "nt":
                import msvcrt
                if handle.tell() == 0:
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            raise RuntimeError("Another CI scheduler already owns this database.") from exc
        self.runner_lock = handle

    def _release_runner_lock(self):
        if self.runner_lock:
            self.runner_lock.close()
            self.runner_lock = None

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
            if self.notification_tasks:
                _done, pending = await asyncio.wait(tuple(self.notification_tasks), timeout=20)
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
            self.pending.clear()
            self.dispatcher = None
            self.started = False
            self._release_runner_lock()

    async def wait_idle(self):
        while self.active or self.pending:
            if not self.active:
                await asyncio.sleep(0.01)
                continue
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
        async with self.enqueue_lock:
            return await self._enqueue(owner, repo, event, branch, commit, payload)

    async def _enqueue(self, owner, repo, event, branch="", commit="", payload=None, snapshot=None):
        config = snapshot or await self.config(owner, repo)
        key = {
            "push": "push",
            "pull_request": "pr_opened",
            "pull_request_updated": "pr_updated",
            "pull_request_reopened": "pr_reopened",
            "pull_request_merged": "pr_merged",
            "manual": "manual",
        }.get(event, event)
        if not config["command"] or (snapshot is None and not config["events"].get(key, False)):
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
        if config["cancel_superseded"] and event != "manual":
            for old in list(self.pending.values()) + [r for r, _ in self.active.values()]:
                old_payload = json.loads(old[6] or "{}")
                if old[1:5] == (owner, repo, event, branch) and old_payload.get("pr_number") == (payload or {}).get("pr_number"):
                    await self._cancel(owner, repo, old[0])
        queue_full = len(self.pending) >= self.queue_limit
        payload = payload or {}
        run_id = await _db_call(
            database.db_ci_run_create,
            owner,
            repo,
            event,
            branch,
            commit,
            json.dumps(payload),
            json.dumps(config),
            "queued" if config["email_mode"] != "off" else "",
        )
        row = (run_id, owner, repo, event, branch, commit, json.dumps(payload))
        if queue_full:
            await _db_call(database.db_ci_run_update, run_id, status="failed", phase="queue",
                reason="CI queue is full; retry after a job finishes.", return_code=-1,
                finished_at=datetime.now(timezone.utc).isoformat())
            self._schedule_notification(row)
            return run_id
        self.pending[run_id] = row
        self.wakeup.set()
        return run_id

    async def rerun(self, owner, repo, run_id):
        async with self.enqueue_lock:
            run = await _db_call(database.db_ci_run_get, owner, repo, run_id)
            meta = await _db_call(database.db_ci_run_metadata, owner, repo, run_id)
            if not run or not meta or not meta["config"]:
                raise ValueError("This run has no configuration snapshot; queue a new run instead.")
            return await self._enqueue(owner, repo, run[1], run[2], run[3], json.loads(meta["payload"]), validate_config(json.loads(meta["config"])))

    async def cancel(self, owner, repo, run_id):
        async with self.enqueue_lock:
            return await self._cancel(owner, repo, run_id)

    async def retry_email(self, owner, repo, run_id):
        async with self.enqueue_lock:
            run = await _db_call(database.db_ci_run_get, owner, repo, run_id)
            meta = await _db_call(database.db_ci_run_metadata, owner, repo, run_id)
            if not run or not meta or not meta["notification"].startswith(("failed", "delivery unknown")):
                raise ValueError("Only failed or uncertain email deliveries can be retried.")
            await _db_call(database.db_ci_run_update, run_id, notification="queued")
            self._schedule_notification((run_id, owner, repo, run[1], run[2], run[3], meta["payload"]))

    async def _cancel(self, owner, repo, run_id):
        row = self.pending.get(run_id)
        active = self.active.get(run_id)
        if row is None and active:
            row = active[0]
        if row is None or row[1:3] != (owner, repo):
            return False
        self.cancelled.add(run_id)
        if active:
            active[1].cancel()
            await asyncio.gather(active[1], return_exceptions=True)
            # A task cancelled before its first instruction never enters its finally block.
            self.active.pop(run_id, None)
            await _db_call(database.db_ci_run_update, run_id, status="cancelled", reason="Cancelled by user or superseded.", finished_at=datetime.now(timezone.utc).isoformat())
        else:
            self.pending.pop(run_id, None)
            await _db_call(database.db_ci_run_update, run_id, status="cancelled", reason="Cancelled by user or superseded.", finished_at=datetime.now(timezone.utc).isoformat())
            self.cancelled.discard(run_id)
            self._schedule_notification(row)
        self.cancelled.discard(run_id)
        self.wakeup.set()
        return True

    async def _dispatch(self):
        while True:
            active_repos = {(row[1], row[2]) for row, _task in self.active.values()}
            for run_id, row in sorted(tuple(self.pending.items())):
                if len(self.active) >= self.max_concurrency:
                    break
                repository = (row[1], row[2])
                if repository in active_repos:
                    continue
                self.pending.pop(run_id, None)
                task = asyncio.create_task(self._run_one(row))
                self.active[run_id] = (row, task)
                active_repos.add(repository)
            self.wakeup.clear()
            try:
                await asyncio.wait_for(self.wakeup.wait(), timeout=5)
            except asyncio.TimeoutError:
                try:
                    async with self.enqueue_lock:
                        for row in await _db_call(database.db_ci_queued_runs):
                            if row[0] not in self.active:
                                self.pending.setdefault(row[0], row)
                except Exception:
                    logging.getLogger(__name__).exception("CI queue reconciliation failed")

    async def _run_one(self, row):
        try:
            await self._execute(row)
        except asyncio.CancelledError:
            await _db_call(
                database.db_ci_run_update,
                row[0],
                status="cancelled" if row[0] in self.cancelled else "interrupted",
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
            self.cancelled.discard(row[0])
            self.active.pop(row[0], None)
            self.wakeup.set()
            self._schedule_notification(row)

    def _schedule_notification(self, row):
        task = asyncio.create_task(self._notify(row))
        self.notification_tasks.add(task)
        task.add_done_callback(self.notification_tasks.discard)

    async def _notify(self, row):
        async with self.notification_slots:
            await self._deliver_notification(row)

    async def _deliver_notification(self, row):
        try:
            meta = await _db_call(database.db_ci_run_metadata, row[1], row[2], row[0])
            if not meta:
                return  # A retained-history limit may have removed an old run.
            config = json.loads(meta["config"] or "{}")
            mode = config.get("email_mode", "off")
            if mode == "off":
                return
            run = await _db_call(database.db_ci_run_get, row[1], row[2], row[0])
            if not run or run[4] in ("queued", "running", "cancelled", "interrupted"):
                await _db_call(database.db_ci_run_update, row[0], notification="skipped")
                return
            previous = await _db_call(database.db_ci_previous_result, row[1], row[2], run[2], run[1], run[0], json.loads(meta["payload"]).get("pr_number"))
            if mode != "all" and run[4] == "success" and not (mode == "recovery" and previous in ("failed", "timed_out")):
                await _db_call(database.db_ci_run_update, row[0], notification="skipped")
                return
            await _db_call(database.db_ci_run_update, row[0], notification="sending")
            settings = await _db_call(load_settings)
            await _db_call(send_notification, row[1], row[2], run, validate_recipients(config["email_recipients"]), settings)
            await _db_call(database.db_ci_run_update, row[0], notification="sent")
        except Exception as exc:
            error_type = type(exc).__name__
            logging.getLogger(__name__).warning("CI email delivery failed for run #%s (%s); check SMTP configuration and server connectivity", row[0], error_type)
            # Never leak SMTP credentials or turn a passing build into a failure.
            with contextlib.suppress(Exception):
                await _db_call(database.db_ci_run_update, row[0], notification=f"failed ({error_type}; check server SMTP settings)")

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
        meta = await _db_call(database.db_ci_run_metadata, owner, repo, run_id)
        config = validate_config(json.loads(meta["config"])) if meta and meta["config"] else await self.config(owner, repo)
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
        deadline = asyncio.get_running_loop().time() + config["timeout_seconds"]
        phase = "checkout"
        container = None
        env = runner_environment(temp_root)

        logs_done = asyncio.Event()

        async def flush_logs():
            previous = None
            warned = False
            while not logs_done.is_set():
                try:
                    await asyncio.wait_for(logs_done.wait(), timeout=0.5)
                    return
                except asyncio.TimeoutError:
                    pass
                state = (len(output), truncated[0], phase)
                if state == previous:
                    continue
                try:
                    await _db_call(database.db_ci_run_update, run_id,
                        output=bytes(output).decode("utf-8", "replace"), truncated=int(truncated[0]), phase=phase)
                    previous, warned = state, False
                except Exception as exc:
                    if not warned:
                        logging.getLogger(__name__).warning("Cannot persist live CI logs for run #%s (%s); will retry", run_id, type(exc).__name__)
                        warned = True

        logger = asyncio.create_task(flush_logs())
        try:
            rc = await self._capture_process(
                ["git", "clone", "--no-hardlinks", "--no-checkout", "--", bare, worktree],
                shell=False,
                cwd=None,
                env=env,
                output=output,
                truncated=truncated,
                timeout=deadline - asyncio.get_running_loop().time(),
            )
            if rc == 0:
                rc = await self._capture_process(
                    ["git", "-C", worktree, "checkout", "--detach", commit], shell=False,
                    cwd=None, env=env, output=output, truncated=truncated,
                    timeout=deadline - asyncio.get_running_loop().time())
            if rc == 0:
                rc = await self._capture_process(
                    ["git", "-C", worktree, "remote", "remove", "origin"], shell=False,
                    cwd=None, env=env, output=output, truncated=truncated,
                    timeout=deadline - asyncio.get_running_loop().time())
            if (
                rc == 0
                and event.startswith("pull_request")
                and payload.get("head_commit")
            ):
                phase = "merge"
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
                    env=env,
                    output=output,
                    truncated=truncated,
                    timeout=deadline - asyncio.get_running_loop().time(),
                )
            if rc == 0:
                phase = "command"
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
                command, shell = config["command"], True
                if config["runner"] == "docker":
                    container = f"pygithost-ci-{os.getpid()}-{run_id}"
                    if any("\n" in value or "\r" in value for value in config["env"].values()):
                        raise ValueError("Docker environment values cannot contain newlines.")
                    container_env = {key: value for key, value in env.items() if key in BUILTINS or key in config["env"]}
                    container_env.update(PYGITHOST_WORKTREE="/workspace", HOME="/tmp", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
                    env_file = str(Path(temp_root) / "container.env")
                    Path(env_file).write_text("\n".join(f"{key}={value}" for key, value in container_env.items()), encoding="utf-8")
                    command, shell = docker_command(container, worktree, env_file, config), False
                rc = await self._capture_process(
                    command,
                    shell=shell,
                    cwd=worktree,
                    env=os.environ.copy() if not shell else env,
                    output=output,
                    truncated=truncated,
                    timeout=deadline - asyncio.get_running_loop().time(),
                )
            status = "success" if rc == 0 else "failed"
        except asyncio.TimeoutError:
            rc, status = -1, "timed_out"
            output.extend(
                f"CI execution exceeded the {config['timeout_seconds']} second limit.\n".encode()[
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
            if container:
                try:
                    remove_rc = await self._capture_process(
                        ["docker", "rm", "--force", container],
                        shell=False,
                        cwd=None,
                        env=os.environ.copy(),
                        output=output,
                        truncated=truncated,
                        timeout=30,
                    )
                    if remove_rc:
                        cleanup_error = "Container cleanup failed; check the Docker daemon."
                except Exception as exc:
                    cleanup_error = f"Container cleanup failed: {exc}"
            try:
                await asyncio.wait_for(
                    _db_call(remove_checkout, temp_root), timeout=30
                )
            except Exception as exc:
                cleanup_error = f"Temporary directory cleanup failed: {exc}"
            if cleanup_error:
                output.extend(
                    (cleanup_error + "\n").encode()[: MAX_OUTPUT - len(output)]
                )
            logs_done.set()
            await asyncio.gather(logger, return_exceptions=True)
        await _db_call(
            database.db_ci_run_update,
            run_id,
            status=status,
            output=bytes(output).decode("utf-8", "replace"),
            truncated=int(truncated[0]),
            return_code=rc,
            finished_at=datetime.now(timezone.utc).isoformat(),
            phase=phase,
            reason=("Cancelled by user or superseded." if cancelled and run_id in self.cancelled else
                    f"Interrupted during {phase}." if cancelled else
                    f"Timed out during {phase}." if status == "timed_out" else
                    f"{phase.capitalize()} failed (exit {rc})." if status == "failed" else
                    cleanup_error or ""),
        )
        if cancelled:
            raise asyncio.CancelledError
