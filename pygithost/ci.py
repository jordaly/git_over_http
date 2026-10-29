"""Per-repository asynchronous CI jobs."""

import asyncio
import contextlib
import fnmatch
import hashlib
import json
import logging
import os
import re
import signal
import shutil
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import io
import zipfile
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


def deployment_prefix(value):
    """Parse an administrator-controlled runner without using a command shell."""
    if not isinstance(value, str) or len(value) > 4096 or any(c in value for c in ("\0", "\n", "\r")):
        raise ValueError("Run with must be a single command line up to 4096 characters.")
    if value.strip() in ("", "direct"):
        return []
    # Retain the existing portable Python shortcut.
    if value.strip() == "python":
        return [sys.executable]
    try:
        parts = shlex.split(value)
    except ValueError as exc:
        raise ValueError(f"Invalid Run with quoting: {exc}") from exc
    if not parts or not parts[0]:
        raise ValueError("Run with requires an executable name or path.")
    return parts


def default_config():
    return {
        "command": "",
        "deploy_enabled": False,
        "deploy_branch": "main",
        "deploy_script": "",
        "deploy_interpreter": "direct",
        "deploy_timeout": 600,
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
        "repository_config": False,
        "require_ci": False,
        "block_direct_pushes": False,
        "protected_branches": "main",
        "steps": [],
        "artifacts": {"paths": [], "when": "always"},
        "artifact_retention_days": 7,
        "artifact_retention_count": 0,
        "run_retention_count": max(0, min(10000, int(os.environ.get("PYGITHOST_CI_RETENTION", "100")))),
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
    for key, maximum in (("artifact_retention_days", 36500), ("artifact_retention_count", 1000000), ("run_retention_count", 1000000)):
        value = raw.get(key, defaults[key])
        if isinstance(value, str) and value.isascii() and value.isdecimal():
            value = int(value)
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError(f"{key} must be a whole number from 0 to {maximum}; 0 means unlimited.")
        defaults[key] = value
    if type(raw.get("deploy_enabled", False)) is not bool:
        raise ValueError("Deployment enabled must be true or false.")
    script = raw.get("deploy_script", "")
    interpreter = raw.get("deploy_interpreter", "direct")
    deployment_prefix(interpreter)
    content = raw.get("deploy_script_content", "")
    if not isinstance(content, str) or "\0" in content or len(content.encode("utf-8")) > 65536:
        raise ValueError("Deployment script must be UTF-8 text up to 64 KiB without NUL bytes.")
    if content:
        content = content.replace("\r\n", "\n")
        if os.name != "nt" and not deployment_prefix(interpreter) and not content.startswith("#!"):
            raise ValueError("Uploaded deployment scripts require a shebang, for example #!/bin/sh.")
        # Pipeline-form validation must carry unsaved contents through to save_config.
        defaults["deploy_script_content"] = content
    branch = raw.get("deploy_branch", "main")
    if not isinstance(script, str) or "\0" in script or len(script) > 4096 or (script and not os.path.isabs(script)):
        raise ValueError("Deployment script must be an absolute path outside the repository.")
    if not isinstance(branch, str) or not branch or len(branch) > 255 or re.search(r"[\s~^:?*\[\\\x00-\x1f]", branch) or ".." in branch or "@{" in branch or branch.startswith(("-", "/")) or branch.endswith(("/", ".", ".lock")):
        raise ValueError("Enter a single valid deployment branch name.")
    deploy_timeout = raw.get("deploy_timeout", 600)
    if isinstance(deploy_timeout, str) and deploy_timeout.isascii() and deploy_timeout.isdecimal():
        deploy_timeout = int(deploy_timeout)
    if type(deploy_timeout) is not int or not 1 <= deploy_timeout <= 86400:
        raise ValueError("Deployment timeout must be 1–86400 seconds.")
    if raw.get("deploy_enabled", False) and not script and not content:
        raise ValueError("Automatic deployment requires a script path or new script contents.")
    defaults.update(deploy_enabled=raw.get("deploy_enabled", False), deploy_branch=branch,
                    deploy_script=script, deploy_timeout=deploy_timeout, deploy_interpreter=interpreter)
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
    for key in ("repository_config", "require_ci", "block_direct_pushes"):
        if type(raw.get(key, False)) is not bool:
            raise ValueError(f"{key} must be true or false.")
        defaults[key] = raw.get(key, False)
    protected = raw.get("protected_branches", "main")
    if not isinstance(protected, str) or len(protected) > 2048 or "\0" in protected:
        raise ValueError("Protected branches must be newline-separated patterns.")
    if defaults["block_direct_pushes"] and not protected.strip():
        raise ValueError("Specify at least one protected branch pattern.")
    defaults["protected_branches"] = protected
    steps = raw.get("steps", [])
    if not isinstance(steps, list) or len(steps) > 64:
        raise ValueError("Steps must be a list of at most 64 named commands.")
    for step in steps:
        if not isinstance(step, dict) or set(step) != {"name", "run"}:
            raise ValueError("Each step requires only name and run fields.")
        if not isinstance(step["name"], str) or not 1 <= len(step["name"].strip()) <= 120:
            raise ValueError("Step names must contain 1–120 characters.")
        if not isinstance(step["run"], str) or not step["run"].strip() or len(step["run"]) > 8192 or "\0" in step["run"]:
            raise ValueError("Step commands must contain 1–8192 characters.")
    if steps and command:
        raise ValueError("Use either command or steps, not both.")
    defaults["steps"] = steps
    mode = raw.get("pipeline_mode") or ("steps" if steps else "command")
    if mode not in ("command", "steps", "json"):
        raise ValueError("Choose single command, named steps, or JSON in page.")
    defaults["pipeline_mode"] = mode
    artifacts = raw.get("artifacts", {"paths": [], "when": "always"})
    if not isinstance(artifacts, dict) or set(artifacts) - {"paths", "when"}:
        raise ValueError("Artifacts accepts only paths and when.")
    paths = artifacts.get("paths", [])
    if not isinstance(paths, list) or len(paths) > 32:
        raise ValueError("Artifact paths must be a list of at most 32 patterns.")
    for path in paths:
        if not isinstance(path, str) or not path or len(path) > 256 or "\\" in path or "\0" in path or ":" in path or path.startswith("/") or any(part in ("..", ".git") for part in path.split("/")):
            raise ValueError("Artifact patterns must stay inside the checkout and exclude .git.")
    when = artifacts.get("when", "always")
    if when not in ("always", "success", "failure"):
        raise ValueError("Artifact when must be always, success, or failure.")
    defaults["artifacts"] = {"paths": paths, "when": when}
    return defaults


def pipeline_config(raw, config, *, enforce_timeout=True):
    """Validate the shared pipeline format without accepting server policy fields."""
    allowed = {"version", "command", "steps", "env", "artifacts", "timeout_seconds"}
    if not isinstance(raw, dict) or set(raw) - allowed or type(raw.get("version", 1)) is not int or raw.get("version", 1) != 1:
        raise ValueError("Pipeline version must be 1; only command, steps, env, artifacts and timeout_seconds are allowed.")
    merged = {**config, "command": "", "steps": [], **{key: value for key, value in raw.items() if key != "version"}}
    merged = validate_config(merged)
    if enforce_timeout and merged["timeout_seconds"] > config["timeout_seconds"]:
        raise ValueError("Repository timeout exceeds the server-configured limit.")
    if not merged["command"] and not merged["steps"]:
        raise ValueError("Pipeline requires command or steps.")
    return merged


def render_command(command, env):
    """Single-pass {{ env.NAME }} substitution, without expression evaluation."""
    reference = re.compile(r"\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")

    def replace(match):
        name = match.group(1)
        if name not in env:
            raise ValueError(f"Undefined CI environment variable: {name}")
        return env[name]

    # Validate the original template before insertion, so values containing
    # template-like text are always treated literally and never expanded again.
    for expression in re.finditer(r"\{\{\s*env\b.*?\}\}", command, re.DOTALL):
        if not reference.fullmatch(expression.group()):
            raise ValueError("CI templates support only {{ env.NAME }} references; expressions and filters are not supported.")
    if re.search(r"\{\{\s*env\b", reference.sub("", command)):
        raise ValueError("Invalid CI environment placeholder; use {{ env.NAME }}.")
    return reference.sub(replace, command)


def protected_branch(config, branch):
    return config.get("block_direct_pushes", False) and any(
        fnmatch.fnmatchcase(branch, pattern.strip())
        for pattern in config.get("protected_branches", "main").splitlines() if pattern.strip()
    )


def collect_artifacts(worktree, patterns):
    """Collect regular, non-symlink files only; never follow paths outside checkout."""
    root = Path(worktree)
    files, total, visited = {}, 0, 0
    for pattern in patterns:
        for path in root.glob(pattern):
            visited += 1
            if visited > 10000:
                raise ValueError("Artifact patterns match too many entries.")
            relative = path.relative_to(root)
            if ".git" in relative.parts or any(part.is_symlink() or part.is_junction() for part in (path, *path.parents)):
                continue
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                continue
            files[str(relative)] = path
            if len(files) > 1000:
                raise ValueError("Artifacts exceed the 1000-file limit.")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, path in sorted(files.items()):
            # O_NOFOLLOW closes the final-component symlink race on POSIX.
            if os.name == "posix":
                # Walk with directory descriptors so replacing a parent with a
                # symlink cannot redirect collection outside the checkout.
                directory = os.open(root.absolute().anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    for part in root.absolute().parts[1:]:
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                        os.close(directory)
                        directory = child
                    parts = Path(name).parts
                    for part in parts[:-1]:
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                        os.close(directory)
                        directory = child
                    fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                finally:
                    os.close(directory)
            else:
                if any(part.is_symlink() or part.is_junction() for part in (path, *path.parents)):
                    raise ValueError("Artifact path changed during collection.")
                fd = os.open(path, os.O_RDONLY)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("Artifact is not a regular private file.")
                data = stream.read(20 * 1024 * 1024 - total + 1)
            total += len(data)
            if total > 20 * 1024 * 1024:
                raise ValueError("Artifacts exceed the 20 MiB limit.")
            archive.writestr(name.replace(os.sep, "/"), data)
    return buffer.getvalue() if files else None


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

    # Windows scanners and recently exited processes can briefly retain handles.
    for attempt in range(6):
        try:
            shutil.rmtree(path, onexc=writable)
            return
        except FileNotFoundError:
            if not os.path.lexists(path):
                return
            raise
        except OSError as exc:
            if os.name != "nt" or getattr(exc, "winerror", None) not in (5, 32, 33, 145) or attempt == 5:
                raise
            time.sleep(0.1 * (attempt + 1))


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
                await _db_call(database.db_deployment_recover)
                rows = await _db_call(database.db_ci_queued_runs)
                notifications = await _db_call(database.db_ci_pending_notifications)
                deployment_notifications = await _db_call(database.db_deployment_email_pending)
            except BaseException:
                self._release_runner_lock()
                raise
            self.pending = {row[0]: row for row in rows}
            self.stopping = False
            self.started = True
            self.dispatcher = asyncio.create_task(self._dispatch())
            for row in notifications:
                self._schedule_notification(row)
            for run_id, owner, repo in deployment_notifications:
                if run_id not in {row[0] for row in notifications}:
                    self._schedule_notification((run_id, owner, repo))

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
        if config.get("deploy_script_content"):
            config = {**config, "deploy_script": ""}
        config = validate_config(config)
        await _db_call(database.db_ci_config_set, owner, repo, json.dumps(config))
        return config

    async def deployment_script_content(self, owner, repo, config):
        """Return database-backed contents, or a verified legacy upload."""
        if config.get("deploy_script_content"):
            return config["deploy_script_content"]
        directory = Path(database.DB_PATH).resolve().parent / "deployment-scripts"
        path = Path(config.get("deploy_script", ""))
        if path.parent != directory or not re.fullmatch(r"[0-9a-f]{64}", path.name):
            return ""

        def read_script():
            try:
                if path.is_symlink() or not path.is_file():
                    return ""
                with path.open("rb") as handle:
                    data = handle.read(65537)
                if len(data) > 65536:
                    return ""
                content = data.decode("utf-8")
                expected = hashlib.sha256((owner + "/" + repo + "\0" + content).encode()).hexdigest()
                return content if expected == path.name else ""
            except (OSError, UnicodeError):
                return ""
        return await asyncio.to_thread(read_script)

    async def repository_pipeline(self, owner, repo, commit, config):
        """Read a bounded blob at an immutable SHA, never from the working tree."""
        if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit):
            raise ValueError("Repository pipeline requires an exact commit SHA.")
        async def git(*args):
            process = await asyncio.create_subprocess_exec(
                "git", "--git-dir", self.repo_path(owner, repo), *args,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env=runner_environment(tempfile.gettempdir()))
            try:
                stdout, _stderr = await asyncio.wait_for(process.communicate(), 10)
            except BaseException:
                if process.returncode is None:
                    process.kill()
                await process.wait()
                raise
            if process.returncode:
                raise ValueError("Cannot read .pygithost-ci.json at the recorded commit.")
            return stdout
        tree = (await git("ls-tree", commit, "--", ".pygithost-ci.json")).decode().split()
        if len(tree) < 3 or tree[0] not in ("100644", "100755") or tree[1] != "blob":
            raise ValueError("Missing regular .pygithost-ci.json file.")
        blob = tree[2]
        if int((await git("cat-file", "-s", blob)).strip()) > 65536:
            raise ValueError("Repository pipeline exceeds 64 KiB.")
        raw = json.loads(await git("cat-file", "blob", blob))
        return pipeline_config(raw, config)

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
        if (not config["command"] and not config["steps"] and not config["repository_config"]) or (snapshot is None and not config["events"].get(key, False)):
            return None
        if event == "push" and not self._matches(config["push_branches"], branch):
            return None
        if event.startswith("pull_request") and not self._matches(
            config["pr_branches"], (payload or {}).get("base_branch", branch)
        ):
            return None
        config_error = ""
        if snapshot is None and config["repository_config"]:
            try:
                # PR code cannot change its own pipeline before review/merge.
                config = await self.repository_pipeline(owner, repo, commit, config)
            except (ValueError, UnicodeError, OSError, RecursionError, asyncio.TimeoutError) as exc:
                config_error = f"Repository pipeline configuration: {exc}"
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
            "" if config_error else json.dumps(config),
            "queued" if config["email_mode"] != "off" else "",
        )
        row = (run_id, owner, repo, event, branch, commit, json.dumps(payload))
        if config_error:
            await _db_call(database.db_ci_run_update, run_id, status="failed", phase="configuration",
                output=config_error, reason=config_error, return_code=-1,
                finished_at=datetime.now(timezone.utc).isoformat())
            self._schedule_notification(row)
            return run_id
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
            completed = await _db_call(database.db_ci_run_get, owner, repo, run_id)
            active[1].cancel()
            await asyncio.gather(active[1], return_exceptions=True)
            # A task cancelled before its first instruction never enters its finally block.
            self.active.pop(run_id, None)
            if not completed or completed[4] != "success":
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
        ci_finished = False
        try:
            await self._execute(row)
            ci_finished = True
            await self._deploy(row)
        except asyncio.CancelledError:
            if not ci_finished:
                await _db_call(
                    database.db_ci_run_update,
                    row[0],
                    status="cancelled" if row[0] in self.cancelled else "interrupted",
                    finished_at=datetime.now(timezone.utc).isoformat(),
                )
            raise
        except Exception as exc:
            if ci_finished:
                logging.getLogger(__name__).exception("Deployment processing failed for run #%s", row[0])
                return
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

    async def _deploy(self, row):
        """Run a trusted external script, never repository-controlled commands."""
        run_id, owner, repo, event, branch, commit, _payload = row
        run = await _db_call(database.db_ci_run_get, owner, repo, run_id)
        config = await self.config(owner, repo)
        meta = await _db_call(database.db_ci_run_metadata, owner, repo, run_id)
        snapshot = json.loads(meta["config"] or "{}") if meta else {}
        if not run or run[4] != "success" or not (config["deploy_enabled"] or snapshot.get("deploy_enabled")):
            return
        async def skip(reason):
            await _db_call(database.db_ci_run_update, run_id, reason="Deployment skipped: " + reason)
        if event not in ("push", "pull_request_merged"):
            await skip("only Push and PR merged runs deploy; manual runs and PR checks do not.")
            return
        if not config["deploy_enabled"] or not snapshot.get("deploy_enabled"):
            await skip("deployment must be enabled both when the run is queued and when it finishes.")
            return
        if branch != config["deploy_branch"]:
            await skip(f"branch {branch!r} does not match deployment branch {config['deploy_branch']!r}.")
            return
        if any(config.get(k, "") != snapshot.get(k, "direct" if k == "deploy_interpreter" else "") for k in ("deploy_branch", "deploy_script", "deploy_script_content", "deploy_timeout", "deploy_interpreter")):
            await skip("deployment settings changed since this run was queued; push a new commit with the saved settings.")
            return
        output, truncated = bytearray(), [False]
        claimed = False
        try:
            with tempfile.TemporaryDirectory(prefix="pygithost-deploy-") as home:
                env = runner_environment(home)
                bare = str(Path(self.repo_path(owner, repo)).resolve())
                rc = await self._capture_process(
                    ["git", "--git-dir", bare, "rev-parse", "--verify", f"refs/heads/{branch}"],
                    shell=False, cwd=None, env=env, output=output, truncated=truncated, timeout=30)
                if rc or output.decode().strip() != commit:
                    await skip("the tested commit is no longer the branch tip, or the branch cannot be resolved.")
                    return
                output.clear()
                claimed = await _db_call(database.db_deployment_claim, run_id, owner, repo, commit, json.dumps(config))
                if not claimed:
                    await skip("this repository/commit already has a deployment attempt; see Deployments.")
                    return
                if config.get("deploy_script_content"):
                    prefix = deployment_prefix(config["deploy_interpreter"])
                    runtime = Path(prefix[0]).stem.lower() if prefix else ""
                    suffix = ".py" if "python" in runtime else ".ps1" if runtime in ("pwsh", "powershell") else ".js" if runtime in ("node", "nodejs") else ".sh"
                    script = Path(home) / ("deployment" + suffix)
                    descriptor = os.open(script, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
                    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                        handle.write(snapshot["deploy_script_content"])
                else:
                    script = Path(config["deploy_script"]).resolve()
                    if script.is_relative_to(Path(bare)) or not script.is_file():
                        raise ValueError("Deployment script must exist outside the repository.")
                env.update(PYGITHOST_OWNER=owner, PYGITHOST_REPO=repo,
                    PYGITHOST_BRANCH=branch, PYGITHOST_COMMIT=commit, CI="true")
                command = deployment_prefix(config["deploy_interpreter"]) + [str(script), commit]
                rc = await self._capture_process(command, shell=False,
                    cwd=home, env=env, output=output, truncated=truncated,
                    timeout=config["deploy_timeout"])
                status = "success" if rc == 0 else "failed"
        except asyncio.CancelledError:
            if claimed:
                await _db_call(database.db_deployment_finish, run_id, "interrupted", output.decode("utf-8", "replace"))
            raise
        except Exception as exc:
            status = "timed_out" if isinstance(exc, asyncio.TimeoutError) else "failed"
            output.extend((f"\nDeployment error: {exc}\n").encode()[:MAX_OUTPUT - len(output)])
            if not claimed:
                claimed = await _db_call(database.db_deployment_claim, run_id, owner, repo, commit, json.dumps(config))
        if claimed:
            await _db_call(database.db_deployment_finish, run_id, status, output.decode("utf-8", "replace"))

    async def _notify(self, row):
        async with self.notification_slots:
            await self._deliver_notification(row)
            await self._deliver_deployment_notification(row)

    async def _deliver_deployment_notification(self, row):
        record = await _db_call(database.db_deployment_email_record, row[0])
        if not record or record[6] != "queued" or record[4] == "running":
            return
        run_id, owner, repo, commit, status, raw, _notification, started, finished = record
        config = json.loads(raw or "{}")
        mode = config.get("email_mode", "off")
        previous = await _db_call(database.db_deployment_previous_result, owner, repo, run_id)
        if mode == "off" or (status == "success" and mode != "all" and not
                (mode == "recovery" and previous in ("failed", "timed_out", "interrupted"))):
            await _db_call(database.db_deployment_email_update, run_id, "skipped")
            return
        if not await _db_call(database.db_deployment_email_update, run_id, "sending", True):
            return
        try:
            run = (run_id, "deployment", config.get("deploy_branch", ""), commit,
                   status, "", 0, None, started, started, finished)
            settings = await _db_call(load_settings)
            await _db_call(send_notification, owner, repo, run,
                validate_recipients(config.get("email_recipients", "")), settings)
            await _db_call(database.db_deployment_email_update, run_id, "sent")
        except Exception as exc:
            logging.getLogger(__name__).warning("Deployment email failed for run #%s (%s)", run_id, type(exc).__name__)
            await _db_call(database.db_deployment_email_update, run_id, f"failed ({type(exc).__name__}; check server SMTP settings)")

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
        if not config["command"] and not config["steps"]:
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
        step_states = [dict(name=step["name"], status="pending", started_at=None,
                            finished_at=None, return_code=None, output="", duration="—")
                       for step in config["steps"]]
        current_step = None
        step_start = 0

        async def save_steps():
            if current_step is not None:
                current_step["output"] = bytes(output[step_start:]).decode("utf-8", "replace")
            if step_states:
                await _db_call(database.db_ci_steps_set, run_id, json.dumps(step_states))

        await save_steps()

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
                    await save_steps()
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
                if config["runner"] == "docker":
                    if any("\n" in value or "\r" in value for value in config["env"].values()):
                        raise ValueError("Docker environment values cannot contain newlines.")
                    container_env = {key: value for key, value in env.items() if key in BUILTINS or key in config["env"]}
                    container_env.update(PYGITHOST_WORKTREE="/workspace", HOME="/tmp", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
                    env_file = str(Path(temp_root) / "container.env")
                    Path(env_file).write_text("\n".join(f"{key}={value}" for key, value in container_env.items()), encoding="utf-8")
                commands = config["steps"] or [{"name": "Command", "run": config["command"]}]
                for index, step in enumerate(commands):
                    current_step = step_states[index] if step_states else None
                    step_start = len(output)
                    step_clock = asyncio.get_running_loop().time()
                    if current_step is not None:
                        phase = f"step {index + 1}: {step['name']}"
                        current_step.update(status="running", started_at=datetime.now(timezone.utc).isoformat())
                        await save_steps()
                    command, shell = render_command(step["run"],
                        {key: value for key, value in env.items() if key in BUILTINS or key in config["env"]}), True
                    if config["runner"] == "docker":
                        container = f"pygithost-ci-{os.getpid()}-{run_id}-{index}"
                        command, shell = docker_command(container, worktree, env_file, {**config, "command": command}), False
                    rc = await self._capture_process(
                        command, shell=shell, cwd=worktree,
                        env=os.environ.copy() if not shell else env.copy(),
                        output=output, truncated=truncated,
                        timeout=deadline - asyncio.get_running_loop().time())
                    if current_step is not None:
                        current_step.update(status="success" if rc == 0 else "failed", return_code=rc,
                            finished_at=datetime.now(timezone.utc).isoformat(),
                            duration=f"{asyncio.get_running_loop().time() - step_clock:.2f}s")
                        await save_steps()
                        current_step = None
                    if container and index < len(commands) - 1 and rc == 0:
                        remove_rc = await self._capture_process(["docker", "rm", "--force", container], shell=False,
                            cwd=None, env=os.environ.copy(), output=output, truncated=truncated, timeout=30)
                        if remove_rc:
                            raise ValueError("Container cleanup failed between steps.")
                        container = None
                    if rc != 0:
                        break
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
            if current_step is not None:
                current_step.update(status="cancelled" if cancelled and run_id in self.cancelled else status,
                    return_code=rc, finished_at=datetime.now(timezone.utc).isoformat(),
                    duration=f"{asyncio.get_running_loop().time() - step_clock:.2f}s")
            for step in step_states:
                if step["status"] == "pending":
                    step["status"] = "skipped"
            try:
                await save_steps()
            except Exception as exc:
                cleanup_error = f"Step metadata could not be saved: {exc}"
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
            artifacts = config["artifacts"]
            if artifacts["paths"] and not cancelled and (artifacts["when"] == "always" or
                    (artifacts["when"] == "success") == (status == "success")):
                try:
                    archive = await _db_call(collect_artifacts, worktree, artifacts["paths"])
                    if archive:
                        await _db_call(database.db_ci_artifact_set, run_id, archive)
                except Exception as exc:
                    status, rc, phase = "failed", -1, "artifacts"
                    output.extend(f"Artifact collection failed: {exc}\n".encode()[:MAX_OUTPUT - len(output)])
            try:
                await asyncio.wait_for(
                    _db_call(remove_checkout, temp_root), timeout=120
                )
            except Exception as exc:
                detail = ("cleanup exceeded the 120 second limit" if isinstance(exc, asyncio.TimeoutError)
                          else f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__)
                cleanup_error = (f"Temporary directory cleanup failed: {detail}. Directory: {temp_root}. "
                                 "Check for processes holding files open and server account permissions; "
                                 "remove this job directory only after its processes have stopped.")
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
            warnings=cleanup_error or "",
            reason=("Cancelled by user or superseded." if cancelled and run_id in self.cancelled else
                    f"Interrupted during {phase}." if cancelled else
                    f"Timed out during {phase}." if status == "timed_out" else
                    f"{phase.capitalize()} failed (exit {rc})." if status == "failed" else
                    cleanup_error or ""),
        )
        if cancelled:
            raise asyncio.CancelledError
