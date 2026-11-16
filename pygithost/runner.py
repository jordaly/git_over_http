"""Run with ``python -m pygithost.runner --help`` on a dedicated Linux worker."""

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import re
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from . import database
from .ci import CIManager, _db_call, remove_checkout, runner_environment
from .remote_ci import MAX_ARTIFACT, MAX_SOURCE, create_token

logger = logging.getLogger(__name__)


def cleanup_attempt(fingerprint):
    if not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
        raise ValueError("Invalid attempt fingerprint.")
    result = subprocess.run(["docker", "ps", "-aq", "--filter",
                             "label=pygithost.http-attempt=" + fingerprint],
                            capture_output=True, text=True, check=True, timeout=15)
    containers = result.stdout.split()
    if any(not re.fullmatch(r"[a-f0-9]{12,64}", item) for item in containers):
        raise ValueError("Invalid Docker container identity.")
    if containers:
        subprocess.run(["docker", "rm", "--force", *containers], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def watchdog(fingerprint, parent, seconds):
    """A detached monitor also cleans containers if the worker process is killed."""
    deadline = time.monotonic() + seconds
    while os.getppid() == parent and time.monotonic() < deadline:
        time.sleep(1)
    cleanup_attempt(fingerprint)


class Client:
    def __init__(self, url, token):
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme not in ("http", "https") or not parsed.netloc
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/")):
            raise ValueError("Use an HTTP(S) server origin without credentials or a path.")
        self.url, self.token = url.rstrip("/"), token
        # Never follow redirects with a runner credential.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, action, document):
        req = urllib.request.Request(self.url + "/api/runner/v1/" + action,
            data=json.dumps(document).encode(), headers={
                "Authorization": "Bearer " + self.token, "Content-Type": "application/json"},
            method="POST")
        with self.opener.open(req, timeout=30) as response:
            raw = response.read(46 * 1024 * 1024 + 1)
        if len(raw) > 46 * 1024 * 1024:
            raise ValueError("Runner response exceeds limit.")
        return json.loads(raw)


async def run_job(client, job, root, worker_policy=None):
    """Reuse the local Docker executor; its database is private to this worker."""
    run_id, attempt = job["run_id"], job["attempt"]
    identity = {"run_id": run_id, "attempt": attempt}
    workspace = Path(tempfile.mkdtemp(prefix="job-", dir=root))
    task = None
    monitor = None
    fingerprint = hashlib.sha256(attempt.encode()).hexdigest()
    try:
        from .docker_profile import authorize
        try:
            configuration = job["config"]
            row = job["row"]
            if configuration.get("runner") != "docker":
                raise ValueError("HTTP runners only accept Docker jobs.")
            authorize(configuration.get("docker"), worker_policy,
                      timeout=configuration["timeout_seconds"],
                      repository=f"{row[1]}/{row[2]}", event=row[3])
        except ValueError as exc:
            await asyncio.to_thread(client.request, "complete", dict(identity, progress={
                "status": "failed", "return_code": -1, "phase": "runner policy",
                "reason": str(exc), "output": "Runner policy rejected this job: " + str(exc),
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "truncated": 0, "steps": []}))
            return
        response = await asyncio.to_thread(client.request, "source", identity)
        if response.get("cancel"):
            return
        source = base64.b64decode(response["bundle"], validate=True)
        if len(source) > MAX_SOURCE:
            raise ValueError("Source bundle exceeds limit.")
        bundle = workspace / "source.bundle"
        bundle.write_bytes(source)
        bare = workspace / "repo.git"
        def clone():
            subprocess.run(["git", "clone", "--bare", "--", str(bundle), str(bare)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60,
                           env=runner_environment(str(workspace)))
        await asyncio.to_thread(clone)
        # Paths/configuration are never taken directly from repository code.
        row = job["row"]
        _, owner, repo, event, branch, commit, payload = row
        config = job["config"]
        if config.get("runner") != "docker":
            raise ValueError("HTTP runners only accept Docker jobs.")
        database.DB_PATH = str(workspace / "runner.db")
        await _db_call(database._db_init)
        local_id = await _db_call(database.db_ci_run_create, owner, repo, event, branch, commit,
                                 payload, json.dumps(config))
        local_row = (local_id, owner, repo, event, branch, commit, payload)
        manager = CIManager(lambda _owner, _repo: str(bare))
        manager.http_attempt = fingerprint
        from .docker_profile import policy
        manager.docker_policy = policy(worker_policy)
        monitor = subprocess.Popen([
            sys.executable, "-m", "pygithost.runner", "_watchdog",
            "--attempt", fingerprint, "--parent", str(os.getpid()),
            "--seconds", str(config["timeout_seconds"] + 10)],
            start_new_session=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        task = asyncio.create_task(manager._execute(local_row))
        last_contact = time.monotonic()
        while not task.done():
            try:
                progress = await snapshot(owner, repo, local_id)
                response = await asyncio.to_thread(client.request, "heartbeat",
                                                  dict(identity, progress=progress))
                last_contact = time.monotonic()
                if response.get("cancel"):
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    return
            except (OSError, ValueError, urllib.error.URLError):
                # Fail closed before the server's lease expires.
                if time.monotonic() - last_contact > 45:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    return
            await asyncio.wait({task}, timeout=5)
        await task
        progress = await snapshot(owner, repo, local_id, final=True)
        artifact = await _db_call(database.db_ci_artifact_get, owner, repo, local_id, content=True)
        if artifact and len(artifact) > MAX_ARTIFACT:
            progress.update(status="failed", return_code=-1, reason="Remote artifact exceeds 16 MiB.")
            artifact = None
        completion = dict(identity, progress=progress,
                          artifact=base64.b64encode(artifact).decode() if artifact else "")
        # Completion is safe to repeat: the server applies one terminal result.
        for _ in range(6):
            try:
                await asyncio.to_thread(client.request, "complete", completion)
                return
            except (OSError, ValueError, urllib.error.URLError):
                await asyncio.sleep(5)
        raise RuntimeError("Unable to report completion; job will be interrupted, not replayed.")
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


async def snapshot(owner, repo, run_id, final=False):
    row = await _db_call(database.db_ci_run_get, owner, repo, run_id)
    meta = await _db_call(database.db_ci_run_metadata, owner, repo, run_id)
    result = dict(output=row[5], truncated=row[6], phase=meta["phase"],
                  steps=json.loads(await _db_call(database.db_ci_steps_get, run_id)))
    if final:
        result.update(status=row[4], return_code=row[7], started_at=row[9] or "",
                      finished_at=row[10] or "", reason=meta["reason"], warnings=meta["warnings"])
    return result


async def serve(client, root, once=False, worker_policy=None):
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
                        logger.warning("Previous attempt is uncertain; refusing to execute it again.")
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    monitor = commands.add_parser("_watchdog", help=argparse.SUPPRESS)
    monitor.add_argument("--attempt", required=True)
    monitor.add_argument("--parent", required=True, type=int)
    monitor.add_argument("--seconds", required=True, type=int)
    token = commands.add_parser("create-token", help="Run locally on the GitHost host as its administrator.")
    token.add_argument("--db", required=True)
    token.add_argument("--name", required=True)
    token.add_argument("--repository", action="append", required=True, help="Exact owner/repo; repeatable.")
    revoke = commands.add_parser("revoke-token", help="Revoke runner access immediately by name.")
    revoke.add_argument("--db", required=True)
    revoke.add_argument("--name", required=True)
    run = commands.add_parser("run", help="Poll GitHost and execute Docker jobs on Linux.")
    run.add_argument("--server", required=True)
    run.add_argument("--token-file", required=True)
    run.add_argument("--work-dir", required=True)
    run.add_argument("--allow-http", action="store_true", help="Explicitly accept unencrypted transport.")
    run.add_argument("--once", action="store_true")
    run.add_argument("--policy-file", help="Administrator-managed JSON Docker ceilings and named secrets.")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    if args.command == "_watchdog":
        watchdog(args.attempt, args.parent, args.seconds)
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
    if (token_file.is_symlink() or token_file.stat().st_mode & 0o077
            or token_file.stat().st_uid != os.getuid()):
        parser.error("Token file must be private, owned by the runner account, and not a symlink.")
    client = Client(args.server, token_file.read_text().strip())
    from .docker_profile import policy
    worker_policy = policy()
    if args.policy_file:
        path = Path(args.policy_file)
        if (path.is_symlink() or path.stat().st_mode & 0o027
                or path.stat().st_uid not in (0, os.getuid()) or path.stat().st_size > 65536):
            parser.error("Policy file must be administrator-owned/private, not group-writable, and at most 64 KiB.")
        try:
            worker_policy = policy(json.loads(path.read_text()))
        except (ValueError, UnicodeError):
            parser.error("Invalid Docker policy JSON.")
    async def start():
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
