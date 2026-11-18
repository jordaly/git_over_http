"""Run with ``python -m pygithost.runner --help`` on a dedicated Linux worker."""

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Coroutine, Mapping
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from typing import IO, Any, TypeVar

from . import database
from .ci import CIManager, _db_call, remove_checkout, runner_environment, validate_config
from .ci_limits import (
    DEFAULT_SOURCE_LIMIT_MB,
    MIB,
    execution_limits,
    source_limit_bytes,
    source_response_bytes,
)
from .remote_ci import create_token
from .runner_types import ProgressSnapshot, RunnerJob, RunRow

_T = TypeVar("_T")

logger = logging.getLogger(__name__)


def cleanup_attempt(fingerprint: str) -> None:
    if not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
        raise ValueError("Invalid attempt fingerprint.")
    # A killed worker must also disconnect its daemon build request. Match only
    # this attempt's Docker build CLI, never unrelated processes/containers.
    for entry in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            args = entry.read_bytes().split(b"\0")
            if (
                len(args) > 2
                and Path(os.fsdecode(args[0])).name == "docker"
                and args[1] == b"build"
                and ("pygithost.http-attempt=" + fingerprint).encode() in args
            ):
                os.kill(int(entry.parent.name), signal.SIGTERM)
        except OSError, ValueError:
            pass
    result = subprocess.run(
        ["docker", "ps", "-aq", "--filter", "label=pygithost.http-attempt=" + fingerprint],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    containers = result.stdout.split()
    if any(not re.fullmatch(r"[a-f0-9]{12,64}", item) for item in containers):
        raise ValueError("Invalid Docker container identity.")
    if containers:
        subprocess.run(
            ["docker", "rm", "--force", *containers],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )


def watchdog(fingerprint: str, parent: int, seconds: float) -> None:
    """A detached monitor also cleans containers if the worker process is killed."""
    deadline = time.monotonic() + seconds
    while os.getppid() == parent and time.monotonic() < deadline:
        time.sleep(1)
    cleanup_attempt(fingerprint)


class Client:
    def __init__(self, url: str, token: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ValueError("Use an HTTP(S) server origin without credentials or a path.")
        self.url, self.token = url.rstrip("/"), token

        # Never follow redirects with a runner credential.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(
                self,
                req: urllib.request.Request,
                fp: IO[bytes],
                code: int,
                msg: str,
                headers: Message,
                newurl: str,
            ) -> urllib.request.Request | None:
                return None

        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(
        self,
        action: str,
        document: Mapping[str, Any],
        *,
        source_limit_mb: int = DEFAULT_SOURCE_LIMIT_MB,
        timeout: float = 30,
    ) -> dict[str, Any]:
        maximum = source_response_bytes(source_limit_mb) if action == "source" else 46 * 1024 * 1024
        headers = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"}
        if type(document.get("run_id")) is int:
            headers["X-Runner-Run-ID"] = str(document["run_id"])
        req = urllib.request.Request(
            self.url + "/api/runner/v1/" + action,
            data=json.dumps(document).encode(),
            headers={**headers},
            method="POST",
        )
        with self.opener.open(req, timeout=timeout) as response:
            raw = bytearray()
            while True:
                chunk = response.read(min(65536, maximum + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > maximum:
                    raise ValueError("Runner response exceeds this operation's configured limit.")
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError("Runner response must be a JSON object.")
        return result


class JobStopped(Exception):
    pass


async def execute_with_image(manager: CIManager, row: RunRow, config: Mapping[str, Any]) -> None:
    """Provision on the worker host, never grant network/Docker access to jobs."""
    if config.get("image_build"):
        return await manager._execute(row)
    run_id = row[0]
    limits = execution_limits(config.get("limits"))
    maximum = limits["log_mb"] * MIB
    output, truncated = bytearray(), [False]
    started = datetime.now(timezone.utc).isoformat()
    deadline = asyncio.get_running_loop().time() + limits["image_pull_timeout_seconds"]

    async def publish() -> None:
        await _db_call(
            database.db_ci_run_update,
            run_id,
            output=output.decode("utf-8", "replace"),
            truncated=int(truncated[0]),
            phase="image",
        )

    await _db_call(
        database.db_ci_run_update, run_id, status="running", started_at=started, phase="image"
    )
    try:
        mode = manager.docker_policy["image_pull"]
        inspect_output = bytearray()
        if mode != "always":
            cached = await manager._capture_process(
                ["docker", "image", "inspect", "--format={{.Id}}", config["image"]],
                shell=False,
                cwd=None,
                env=os.environ.copy(),
                output=inspect_output,
                truncated=[False],
                timeout=deadline - asyncio.get_running_loop().time(),
                max_output=maximum,
            )
            if cached == 0:
                output.extend(b"Using cached Docker image.\n")
            elif mode == "never":
                raise ValueError(
                    "Docker image is not available locally; worker policy forbids image downloads."
                )
        if mode == "always" or not output:
            output.extend(b"Downloading Docker image on the worker host.\n"[:maximum])
            await publish()
            result = await manager._capture_process(
                ["docker", "pull", "--quiet", config["image"]],
                shell=False,
                cwd=None,
                env=os.environ.copy(),
                output=output,
                truncated=truncated,
                on_output=publish,
                timeout=deadline - asyncio.get_running_loop().time(),
                max_output=maximum,
            )
            if result:
                raise ValueError(
                    "Docker image download failed; check registry access and worker credentials."
                )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        reason = (
            "Docker image provisioning timed out."
            if isinstance(exc, asyncio.TimeoutError)
            else str(exc)
            if isinstance(exc, ValueError)
            else "Docker image provisioning failed (" + type(exc).__name__ + ")."
        )
        message = ("\n" + reason + "\n").encode()
        output.extend(message[: max(0, maximum - len(output))])
        await _db_call(
            database.db_ci_run_update,
            run_id,
            status="timed_out" if isinstance(exc, asyncio.TimeoutError) else "failed",
            output=output.decode("utf-8", "replace"),
            truncated=int(truncated[0]),
            return_code=-1,
            phase="image",
            reason=reason,
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        return
    await manager._execute(
        row, initial_output=bytes(output), initial_truncated=truncated[0], started_at=started
    )


async def transfer_with_heartbeats(
    client: Client, identity: Mapping[str, Any], awaitable: Coroutine[Any, Any, _T]
) -> _T:
    """Source preparation/uploads must not expire the job lease while busy."""

    async def heartbeat() -> None:
        last_contact = time.monotonic()
        while True:
            try:
                response = await asyncio.to_thread(client.request, "heartbeat", identity)
                if response.get("cancel"):
                    return
                last_contact = time.monotonic()
            except OSError, ValueError, urllib.error.URLError:
                if time.monotonic() - last_contact > 45:
                    return
            await asyncio.sleep(5)

    work = asyncio.create_task(awaitable)
    monitor = asyncio.create_task(heartbeat())
    try:
        done, _ = await asyncio.wait({work, monitor}, return_when=asyncio.FIRST_COMPLETED)
        if work in done:
            return await work
        raise JobStopped("Job cancelled or disconnected during transfer.")
    finally:
        for task in (work, monitor):
            if not task.done():
                task.cancel()
        await asyncio.gather(work, monitor, return_exceptions=True)


async def run_job(
    client: Client,
    job: RunnerJob,
    root: str | os.PathLike[str],
    worker_policy: Mapping[str, Any] | None = None,
) -> None:
    """Reuse the local Docker executor; its database is private to this worker."""
    run_id, attempt = job["run_id"], job["attempt"]
    identity = {"run_id": run_id, "attempt": attempt}
    workspace = Path(tempfile.mkdtemp(prefix="job-", dir=root))
    task: asyncio.Task[None] | None = None
    monitor: subprocess.Popen[bytes] | None = None
    fingerprint = hashlib.sha256(attempt.encode()).hexdigest()
    try:
        from .docker_profile import authorize

        try:
            configuration = validate_config(job["config"])
            job["config"] = configuration
            row = job["row"]
            if configuration.get("runner") != "docker":
                raise ValueError("HTTP runners only accept Docker jobs.")
            maximum_source = source_limit_bytes(
                configuration.get("source_limit_mb", DEFAULT_SOURCE_LIMIT_MB)
            )
            limits = execution_limits(configuration.get("limits"))
            authorize(
                configuration.get("docker"),
                worker_policy,
                timeout=configuration["timeout_seconds"],
                repository=f"{row[1]}/{row[2]}",
                event=row[3],
                image_pull_timeout=limits["image_pull_timeout_seconds"],
            )
            from .docker_profile import policy
            from .image_build import authorize as authorize_build

            authorize_build(
                configuration.get("image_build"),
                policy(worker_policy),
                f"{row[1]}/{row[2]}",
                row[3],
            )
        except ValueError as exc:
            await asyncio.to_thread(
                client.request,
                "complete",
                dict(
                    identity,
                    progress={
                        "status": "failed",
                        "return_code": -1,
                        "phase": "runner policy",
                        "reason": str(exc),
                        "output": "Runner policy rejected this job: " + str(exc),
                        "finished_at": datetime.now(timezone.utc).isoformat(),
                        "truncated": 0,
                        "steps": [],
                    },
                ),
            )
            return
        response = await transfer_with_heartbeats(
            client,
            identity,
            asyncio.to_thread(
                client.request,
                "source",
                identity,
                timeout=limits["transfer_timeout_seconds"],
                source_limit_mb=configuration.get("source_limit_mb", DEFAULT_SOURCE_LIMIT_MB),
            ),
        )
        if response.get("cancel"):
            return
        source = base64.b64decode(response["bundle"], validate=True)
        if len(source) > maximum_source:
            raise ValueError("Source bundle exceeds this run's configured limit.")
        bundle = workspace / "source.bundle"
        bundle.write_bytes(source)
        bare = workspace / "repo.git"

        def clone() -> None:
            subprocess.run(
                ["git", "clone", "--bare", "--", str(bundle), str(bare)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=limits["source_timeout_seconds"],
                env=runner_environment(str(workspace)),
            )

        await transfer_with_heartbeats(client, identity, asyncio.to_thread(clone))
        # Paths/configuration are never taken directly from repository code.
        row = job["row"]
        _, owner, repo, event, branch, commit, payload = row
        config = job["config"]
        if config.get("runner") != "docker":
            raise ValueError("HTTP runners only accept Docker jobs.")
        database.DB_PATH = str(workspace / "runner.db")
        await _db_call(database._db_init)
        local_id = await _db_call(
            database.db_ci_run_create,
            owner,
            repo,
            event,
            branch,
            commit,
            payload,
            json.dumps(config),
        )
        local_row = (local_id, owner, repo, event, branch, commit, payload)
        manager = CIManager(lambda _owner, _repo: str(bare))
        manager.http_attempt = fingerprint
        from .docker_profile import policy

        manager.docker_policy = policy(worker_policy)
        monitor = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "pygithost.runner",
                "_watchdog",
                "--attempt",
                fingerprint,
                "--parent",
                str(os.getpid()),
                "--seconds",
                str(
                    config["timeout_seconds"]
                    + limits["image_pull_timeout_seconds"]
                    + (config.get("image_build") or {}).get("timeout_seconds", 0)
                    + 10
                ),
            ],
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        task = asyncio.create_task(execute_with_image(manager, local_row, config))
        last_contact = time.monotonic()
        while not task.done():
            try:
                progress = await snapshot(owner, repo, local_id)
                response = await asyncio.to_thread(
                    client.request,
                    "heartbeat",
                    dict(identity, progress=progress),
                    timeout=limits["transfer_timeout_seconds"],
                )
                last_contact = time.monotonic()
                if response.get("cancel"):
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    return
            except OSError, ValueError, urllib.error.URLError:
                # Fail closed before the server's lease expires.
                if time.monotonic() - last_contact > 45:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    return
            await asyncio.wait({task}, timeout=5)
        await task
        progress = await snapshot(owner, repo, local_id, final=True)
        artifact = await _db_call(database.db_ci_artifact_get, owner, repo, local_id, content=True)
        if artifact and len(artifact) > limits["artifact_mb"] * MIB:
            progress = {
                **progress,
                "status": "failed",
                "return_code": -1,
                "reason": "Remote artifact exceeds this run's configured limit.",
            }
            artifact = None
        completion = dict(
            identity,
            progress=progress,
            artifact=base64.b64encode(artifact).decode() if artifact else "",
        )
        # Completion is safe to repeat: the server applies one terminal result.
        for _ in range(6):
            try:
                await transfer_with_heartbeats(
                    client,
                    identity,
                    asyncio.to_thread(
                        client.request,
                        "complete",
                        completion,
                        timeout=limits["transfer_timeout_seconds"],
                    ),
                )
                return
            except OSError, ValueError, urllib.error.URLError:
                await asyncio.sleep(5)
        raise RuntimeError("Unable to report completion; job will be interrupted, not replayed.")
    except JobStopped:
        return
    finally:
        if task and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if monitor:
            try:
                await asyncio.to_thread(cleanup_attempt, fingerprint)
            finally:
                monitor.terminate()
                await asyncio.to_thread(monitor.wait)
        await asyncio.to_thread(remove_checkout, str(workspace))


async def snapshot(owner: str, repo: str, run_id: int, final: bool = False) -> ProgressSnapshot:
    row = await _db_call(database.db_ci_run_get, owner, repo, run_id)
    meta = await _db_call(database.db_ci_run_metadata, owner, repo, run_id)
    if row is None or meta is None:
        raise RuntimeError("Local CI run metadata is unavailable for this worker job.")
    result: ProgressSnapshot = {
        "output": row[5],
        "truncated": row[6],
        "phase": meta["phase"],
        "steps": json.loads(await _db_call(database.db_ci_steps_get, run_id)),
    }
    if final:
        result["status"] = row[4]
        result["return_code"] = row[7]
        result["started_at"] = row[9] or ""
        result["finished_at"] = row[10] or ""
        result["reason"] = meta["reason"]
        result["warnings"] = meta["warnings"]
    return result


async def serve(
    client: Client,
    root: str | os.PathLike[str],
    once: bool = False,
    worker_policy: Mapping[str, Any] | None = None,
) -> None:
    """One execution at a time; a private lock prevents competing worker processes."""
    import fcntl

    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.stat().st_mode & 0o077 or root.stat().st_uid != os.getuid():
        raise ValueError("Worker directory must be private and owned by the runner account.")
    with (root / "runner.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # A persisted receipt prevents replay after a worker crash.
        receipt = root / "attempt.json"
        if receipt.exists():
            await asyncio.to_thread(cleanup_attempt, receipt.read_text())
        while True:
            try:
                response = await asyncio.to_thread(client.request, "claim", {})
                job = response.get("job")
                if job:
                    fingerprint = hashlib.sha256(job["attempt"].encode()).hexdigest()
                    if receipt.exists() and receipt.read_text() == fingerprint:
                        logger.warning(
                            "Previous attempt is uncertain; refusing to execute it again."
                        )
                        if once:
                            return
                        await asyncio.sleep(10)
                        continue
                    with receipt.open("w") as handle:
                        handle.write(fingerprint)
                        handle.flush()
                        os.fsync(handle.fileno())
                    await run_job(client, job, root, worker_policy)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Never log URLs, payloads, credentials, or exception messages.
                logger.error("Runner operation failed (%s)", type(exc).__name__)
            if once:
                return
            await asyncio.sleep(5)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    monitor = commands.add_parser("_watchdog", help=argparse.SUPPRESS)
    monitor.add_argument("--attempt", required=True)
    monitor.add_argument("--parent", required=True, type=int)
    monitor.add_argument("--seconds", required=True, type=int)
    token = commands.add_parser(
        "create-token", help="Run locally on the GitHost host as its administrator."
    )
    token.add_argument("--db", required=True)
    token.add_argument("--name", required=True)
    token.add_argument(
        "--repository", action="append", required=True, help="Exact owner/repo; repeatable."
    )
    revoke = commands.add_parser("revoke-token", help="Revoke runner access immediately by name.")
    revoke.add_argument("--db", required=True)
    revoke.add_argument("--name", required=True)
    run = commands.add_parser("run", help="Poll GitHost and execute Docker jobs on Linux.")
    run.add_argument("--server", required=True)
    run.add_argument("--token-file", required=True)
    run.add_argument("--work-dir", required=True)
    run.add_argument(
        "--allow-http", action="store_true", help="Explicitly accept unencrypted transport."
    )
    run.add_argument("--once", action="store_true")
    run.add_argument(
        "--policy-file", help="Administrator-managed JSON Docker ceilings and named secrets."
    )
    prune = commands.add_parser(
        "prune-images",
        help="Remove only old, unused runner-built images; refuse while build jobs are active.",
    )
    prune.add_argument("--older-than-hours", type=int, default=168)
    prune.add_argument("--cache-dir", help="Same private cache directory as the worker account.")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    if args.command == "_watchdog":
        watchdog(args.attempt, args.parent, args.seconds)
        return
    if args.command == "prune-images":
        import fcntl

        from .image_build import cache_directory

        if args.older_than_hours < 1:
            parser.error("--older-than-hours must be positive.")
        root = cache_directory(args.cache_dir)
        with (root / "prune.lock").open("a") as guard:
            try:
                fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                parser.error("Build jobs are active; cache pruning refused.")
            subprocess.run(
                [
                    "docker",
                    "image",
                    "prune",
                    "--all",
                    "--force",
                    "--filter",
                    "label=pygithost.build-cache=1",
                    "--filter",
                    f"until={args.older_than_hours}h",
                ],
                check=True,
                timeout=300,
            )
        return
    if args.command in ("create-token", "revoke-token"):
        if not Path(args.db).is_file():
            parser.error("--db must identify the existing GitHost database.")
        database.DB_PATH = args.db
        if args.command == "create-token":
            print(create_token(args.name, args.repository))
        else:
            from .remote_ci import connect

            conn = connect()
            try:
                conn.execute("DELETE FROM ci_runner_tokens WHERE name=?", (args.name,))
            finally:
                conn.close()
        return
    if os.name != "posix" or os.getuid() == 0:
        parser.error("Run the worker as an unprivileged Linux user with Docker access.")
    if args.server.startswith("http:") and not args.allow_http:
        parser.error("Plain HTTP requires --allow-http; credentials and jobs are unencrypted.")
    token_file = Path(args.token_file)
    if (
        token_file.is_symlink()
        or token_file.stat().st_mode & 0o077
        or token_file.stat().st_uid != os.getuid()
    ):
        parser.error("Token file must be private, owned by the runner account, and not a symlink.")
    client = Client(args.server, token_file.read_text().strip())
    from .docker_profile import policy

    worker_policy = policy()
    if args.policy_file:
        path = Path(args.policy_file)
        if (
            path.is_symlink()
            or path.stat().st_mode & 0o027
            or path.stat().st_uid not in (0, os.getuid())
            or path.stat().st_size > 65536
        ):
            parser.error(
                "Policy file must be administrator-owned/private, not group-writable, and at most 64 KiB."
            )
        try:
            worker_policy = policy(json.loads(path.read_text()))
        except ValueError, UnicodeError:
            parser.error("Invalid Docker policy JSON.")

    async def start() -> None:
        task = asyncio.create_task(serve(client, args.work_dir, args.once, worker_policy))
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, task.cancel)
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(start())


if __name__ == "__main__":
    main()
