import base64
import asyncio
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from unittest import mock

from pygithost import database
from pygithost.api.errors import APIError
from pygithost.ci import validate_config
from pygithost.remote_ci import connect, create_token, operation, source_bundle
from pygithost.runner import Client
from tests import test_api as read_tests


class RemoteProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "test.db")
        database._db_init()
        self.token = create_token("ubuntu", ["alice/project"])
        self.digest = hashlib.sha256(self.token.encode()).hexdigest()
        self.repositories = ["alice/project"]

    def tearDown(self):
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def enqueue(self, owner="alice", repo="project"):
        run = database.db_ci_run_create(owner, repo, "push", "main", "a" * 40, "{}", "{}")
        conn = connect()
        try:
            conn.execute("INSERT INTO ci_remote_jobs(run_id,owner,repo,document,source) VALUES(?,?,?,?,?)",
                         (run, owner, repo, json.dumps({"row": [run, owner, repo]}), b"bundle"))
        finally:
            conn.close()
        return run

    def call(self, action, document=None, digest=None, repositories=None):
        return operation(digest or self.digest, repositories or self.repositories, action, document or {})

    def claim(self):
        job = self.call("claim")["job"]
        return {"run_id": job["run_id"], "attempt": job["attempt"]}

    def test_token_hashes_and_repository_restrictions(self):
        conn = connect()
        try:
            self.assertNotIn(self.token, str(conn.execute("SELECT * FROM ci_runner_tokens").fetchall()))
        finally:
            conn.close()
        self.enqueue("bob")
        run = self.enqueue()
        identity = self.claim()
        self.assertEqual(identity["run_id"], run)
        self.assertEqual(self.call("claim")["job"]["attempt"], identity["attempt"])
        self.assertIsNone(self.call("claim", digest="other", repositories=["charlie/project"])["job"])

    def test_claim_has_single_owner(self):
        self.enqueue()
        identity = self.claim()
        self.assertIsNone(self.call("claim", digest="other")["job"])
        with self.assertRaises(APIError):
            self.call("heartbeat", identity, digest="other")
        self.assertEqual(self.call("source", identity)["bundle"], base64.b64encode(b"bundle").decode())

    def test_heartbeat_completion_and_duplicate_completion(self):
        run = self.enqueue()
        identity = self.claim()
        self.call("heartbeat", dict(identity, progress={"output": "live", "truncated": 0, "phase": "command"}))
        self.assertEqual(database.db_ci_run_get("alice", "project", run)[5], "live")
        result = {"status": "success", "return_code": 0, "output": "done"}
        self.call("complete", dict(identity, progress=result))
        self.assertTrue(self.call("complete", dict(identity, progress={"invalid": True}))["accepted"])
        conn = connect()
        try:
            self.assertEqual(json.loads(conn.execute("SELECT result FROM ci_remote_jobs").fetchone()[0]), result)
        finally:
            conn.close()

    def test_expired_attempt_is_not_replayed_and_cannot_finish(self):
        self.enqueue()
        identity = self.claim()
        conn = connect()
        try:
            conn.execute("UPDATE ci_remote_jobs SET heartbeat=?", (time.time() - 100,))
        finally:
            conn.close()
        self.assertTrue(self.call("complete", dict(identity, progress={}))["cancel"])
        self.assertIsNone(self.call("claim", digest="other")["job"])

    def test_cancelled_and_recovered_runs_cannot_be_claimed(self):
        run = self.enqueue()
        database.db_ci_run_update(run, status="interrupted")
        self.assertIsNone(self.call("claim")["job"])

    def test_coordinator_restart_interrupts_unclaimed_and_claimed_jobs(self):
        from pygithost.remote_ci import recover_jobs
        claimed = self.enqueue()
        identity = self.claim()
        queued = self.enqueue()
        recover_jobs()
        for run in (claimed, queued):
            self.assertEqual(database.db_ci_run_get("alice", "project", run)[4], "interrupted")
        self.assertIsNone(self.call("claim")["job"])
        self.assertTrue(self.call("heartbeat", identity)["cancel"])

    def test_wrong_attempt_and_invalid_results_rejected(self):
        self.enqueue()
        identity = self.claim()
        with self.assertRaises(APIError):
            self.call("source", dict(identity, attempt="wrong"))
        for result in ({"status": "success", "return_code": 1},
                       {"status": "success", "return_code": 0, "steps": [1]},
                       {"status": "success", "return_code": 0, "owner": "bob"}):
            with self.assertRaises(APIError):
                self.call("complete", dict(identity, progress=result))

    def test_artifact_validation(self):
        self.enqueue()
        identity = self.claim()
        result = dict(identity, progress={"status": "success", "return_code": 0})
        with self.assertRaises(APIError):
            self.call("complete", dict(result, artifact=base64.b64encode(b"invalid").decode()))
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("result.txt", "passed")
        self.assertTrue(self.call("complete", dict(result, artifact=base64.b64encode(buffer.getvalue()).decode()))["accepted"])

    def test_remote_configuration_and_client_url_validation(self):
        self.assertEqual(validate_config({"runner": "remote-docker"})["runner"], "remote-docker")
        for url in ("ftp://host", "http://user:pass@host", "http://host/path", "http://host?token=x"):
            with self.assertRaises(ValueError):
                Client(url, "secret")
        self.assertEqual(Client("http://192.168.16.16:8000", "secret").url,
                         "http://192.168.16.16:8000")

    def test_bundle_contains_exact_commit_and_pr_head(self):
        root = Path(self.temp.name)
        repo = root / "source"
        def git(*args):
            return subprocess.check_output(["git", *map(str, args)], stderr=subprocess.DEVNULL).decode().strip()
        git("init", "-b", "main", repo)
        git("-C", repo, "-c", "user.name=Test", "-c", "user.email=test@example.com",
            "commit", "--allow-empty", "-m", "base")
        commit = git("-C", repo, "rev-parse", "HEAD")
        git("-C", repo, "-c", "user.name=Test", "-c", "user.email=test@example.com",
            "commit", "--allow-empty", "-m", "head")
        head = git("-C", repo, "rev-parse", "HEAD")
        bundle = root / "test.bundle"
        bundle.write_bytes(source_bundle(repo, commit, head))
        clone = root / "clone"
        git("clone", "--bare", bundle, clone)
        self.assertEqual(git("--git-dir", clone, "rev-parse", "ci-base"), commit)
        self.assertEqual(git("--git-dir", clone, "rev-parse", "ci-head"), head)
        with self.assertRaises(ValueError):
            source_bundle(repo, "--all", "")


class RunnerHTTPTests(unittest.TestCase):
    git = read_tests.APITests.git
    user = read_tests.APITests.user
    request = read_tests.APITests.request
    setUp = read_tests.APITests.setUp
    tearDown = read_tests.APITests.tearDown

    def post(self, action, body, token):
        return self.request("/api/runner/v1/" + action, method="POST", token=token,
                            body=json.dumps(body), headers={"Content-Type": "application/json"})

    def test_runner_tokens_are_separate_and_revocable(self):
        token = create_token("worker", ["alice/project"])
        self.assertEqual(self.post("claim", {}, self.token)[0], 401)
        self.assertEqual(self.post("claim", {}, None)[0], 401)
        self.assertEqual(self.post("claim", {}, token)[2], {"job": None})
        self.assertEqual(self.request("/api/v1/user", token=token)[0], 401)
        status, _, specification = self.request("/api/runner/v1/openapi.json", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(set(specification["paths"]), {"/claim", "/source", "/heartbeat", "/complete"})
        conn = connect()
        try:
            conn.execute("DELETE FROM ci_runner_tokens")
        finally:
            conn.close()
        self.assertEqual(self.post("claim", {}, token)[0], 401)

    def test_real_http_execution_bridge_and_secret_filtering(self):
        from pygithost.ci import CIManager
        from pygithost.remote_ci import execute_remote
        config = validate_config({"runner": "remote-docker", "command": "true",
                                  "deploy_script_content": "#!/bin/sh\nPRIVATE_DEPLOYMENT",
                                  "deploy_enabled": False})
        run = database.db_ci_run_create("alice", "project", "push", "main", self.sha, "{}",
                                       json.dumps(config))
        manager = CIManager(lambda owner, repo: str(self.bare))
        row = (run, "alice", "project", "push", "main", self.sha, "{}")
        task = asyncio.run_coroutine_threadsafe(execute_remote(manager, row, config), self.server.loop)
        token = create_token("worker", ["alice/project"])
        client = Client(f"http://127.0.0.1:{self.server.port}", token)
        deadline = time.monotonic() + 10
        job = None
        while job is None and time.monotonic() < deadline:
            job = client.request("claim", {})["job"]
            time.sleep(0.02)
        self.assertIsNotNone(job)
        self.assertNotIn("PRIVATE_DEPLOYMENT", json.dumps(job))
        self.assertEqual(job["config"]["runner"], "docker")
        identity = {"run_id": run, "attempt": job["attempt"]}
        source = client.request("source", identity)
        self.assertTrue(base64.b64decode(source["bundle"]).startswith(b"# v"))
        client.request("heartbeat", dict(identity, progress={"output": "running"}))
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("result.txt", "passed")
        result = dict(identity, progress={"status": "success", "return_code": 0, "output": "passed"},
                      artifact=base64.b64encode(buffer.getvalue()).decode())
        self.assertTrue(client.request("complete", result)["accepted"])
        task.result(timeout=10)
        run_row = database.db_ci_run_get("alice", "project", run)
        self.assertEqual(run_row[4:6], ("success", "passed"))
        self.assertEqual(database.db_ci_artifact_get("alice", "project", run, content=True), buffer.getvalue())
        self.assertTrue(client.request("heartbeat", identity)["cancel"])

    def test_bridge_cancellation_closes_remote_attempt(self):
        from pygithost.ci import CIManager
        from pygithost.remote_ci import execute_remote
        config = validate_config({"runner": "remote-docker", "command": "true"})
        run = database.db_ci_run_create("alice", "project", "push", "main", self.sha, "{}", json.dumps(config))
        row = (run, "alice", "project", "push", "main", self.sha, "{}")
        task = asyncio.run_coroutine_threadsafe(
            execute_remote(CIManager(lambda owner, repo: str(self.bare)), row, config), self.server.loop)
        token = create_token("worker", ["alice/project"])
        client = Client(f"http://127.0.0.1:{self.server.port}", token)
        job = None
        deadline = time.monotonic() + 10
        while job is None and time.monotonic() < deadline:
            job = client.request("claim", {})["job"]
            time.sleep(0.02)
        self.assertIsNotNone(job)
        task.cancel()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            response = client.request("heartbeat", {"run_id": run, "attempt": job["attempt"]})
            if response.get("cancel"):
                break
            time.sleep(0.05)
        self.assertTrue(response["cancel"])

    @unittest.skipUnless(os.name == "posix" and os.getuid() != 0, "worker requires unprivileged Linux")
    def test_worker_process_checkout_steps_logs_and_artifacts_over_http(self):
        from pygithost.ci import CIManager
        from pygithost.remote_ci import execute_remote
        # A Docker CLI stand-in exercises the real runner process and protocol
        # without requiring a Docker daemon in the unit-test environment.
        tools = self.root / "tools"
        tools.mkdir()
        docker = tools / "docker"
        docker.write_text(f"""#!{sys.executable}
import os, subprocess, sys
args = sys.argv[1:]
if args[0] == 'run':
    mount = args[args.index('--mount') + 1]
    worktree = mount.split('src=', 1)[1].split(',dst=', 1)[0]
    os.chdir(worktree)
    raise SystemExit(subprocess.call(['/bin/sh', '-c', args[-1]]))
""")
        docker.chmod(0o700)
        config = validate_config({
            "runner": "remote-docker",
            "steps": [{"name": "Read exact source", "run": "cat README.md"},
                      {"name": "Produce artifact", "run": "printf passed > result.txt"}],
            "artifacts": {"paths": ["result.txt"], "when": "always"}})
        run = database.db_ci_run_create("alice", "project", "push", "main", self.sha, "{}", json.dumps(config))
        task = asyncio.run_coroutine_threadsafe(execute_remote(
            CIManager(lambda owner, repo: str(self.bare)),
            (run, "alice", "project", "push", "main", self.sha, "{}"), config), self.server.loop)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            conn = connect()
            try:
                exists = conn.execute("SELECT 1 FROM ci_remote_jobs WHERE run_id=?", (run,)).fetchone()
            finally:
                conn.close()
            if exists:
                break
            time.sleep(0.02)
        token_path = self.root / "runner.token"
        token_path.write_text(create_token("worker", ["alice/project"]))
        token_path.chmod(0o600)
        result = subprocess.run([
            sys.executable, "-m", "pygithost.runner", "run",
            "--server", f"http://127.0.0.1:{self.server.port}",
            "--token-file", str(token_path), "--work-dir", str(self.root / "worker"),
            "--allow-http", "--once"], env={**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"]},
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        task.result(timeout=10)
        row = database.db_ci_run_get("alice", "project", run)
        self.assertEqual(row[4], "success", row[5])
        self.assertIn("API fixture", row[5])
        steps = json.loads(database.db_ci_steps_get(run))
        self.assertEqual([step["status"] for step in steps], ["success", "success"])
        artifact = database.db_ci_artifact_get("alice", "project", run, content=True)
        with zipfile.ZipFile(io.BytesIO(artifact)) as archive:
            self.assertEqual(archive.read("result.txt"), b"passed")
        self.assertFalse(list((self.root / "worker").glob("job-*")))
