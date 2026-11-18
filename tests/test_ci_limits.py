import asyncio
import base64
import io
import json
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from pygithost import database
from pygithost.api.errors import APIError
from pygithost.ci import CIManager, collect_artifacts, validate_config
from pygithost.ci_config import compile_document
from pygithost.ci_limits import (
    DEFAULT_SOURCE_LIMIT_MB,
    MIB,
    completion_bytes,
    execution_limits,
    source_limit_bytes,
    source_response_bytes,
)
from pygithost.remote_ci import assigned_limits, source_bundle, validate_progress
from pygithost.runner import Client, JobStopped, transfer_with_heartbeats
from tests import test_remote_ci as protocol_tests


class LimitConfigurationTests(unittest.TestCase):
    def test_default_source_is_100_mib_and_has_no_hard_upper_ceiling(self):
        self.assertEqual(DEFAULT_SOURCE_LIMIT_MB, 100)
        self.assertEqual(validate_config({})["source_limit_mb"], 100)
        self.assertEqual(source_limit_bytes(1_000_000), 1_000_000 * MIB)
        self.assertGreater(source_response_bytes(100), 100 * MIB)

    def test_invalid_limits_and_unknown_fields_are_rejected(self):
        for value in (0, -1, True, 1.5, "100", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_config({"source_limit_mb": value})
        for key in execution_limits():
            for value in (0, -1, True, 1.5, "10"):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    execution_limits({key: value})
        with self.assertRaises(ValueError):
            execution_limits({"unlimited": True})

    def test_named_pipeline_limits_survive_snapshot_roundtrip(self):
        config = compile_document(
            {
                "version": 1,
                "pipelines": [
                    {
                        "name": "first",
                        "execution": {
                            "runner": "remote-docker",
                            "source_limit_mb": 500,
                            "limits": {"log_mb": 8, "artifact_mb": 80},
                        },
                        "steps": [{"name": "Test", "run": "true"}],
                    },
                    {
                        "name": "second",
                        "execution": {
                            "source_limit_mb": 1000,
                            "limits": {"source_timeout_seconds": 900},
                        },
                        "steps": [{"name": "Test", "run": "true"}],
                    },
                ],
            }
        )
        config = validate_config(json.loads(json.dumps(config)))
        self.assertEqual(config["source_limit_mb"], 500)
        self.assertEqual(config["limits"]["log_mb"], 8)
        self.assertEqual(config["pipelines"][0]["source_limit_mb"], 1000)
        self.assertEqual(config["pipelines"][0]["limits"]["source_timeout_seconds"], 900)

    def test_documented_limit_example_compiles_and_is_rendered(self):
        from pygithost.ci_docs import manual_content

        text = (Path(__file__).resolve().parents[1] / "docs/ci-limits.md").read_text()
        document = json.loads(text.split("```json\n", 1)[1].split("```", 1)[0])
        config = compile_document(document)
        self.assertEqual(config["source_limit_mb"], 500)
        self.assertEqual(config["limits"]["artifact_files"], 5000)
        rendered = str(manual_content("ci-limits", None, "/r/root/project"))
        self.assertIn("100 MiB", rendered)
        self.assertIn("No hidden fixed transfer ceiling", rendered)

    def test_bundle_accepts_exact_limit_and_rejects_one_byte_over(self):
        def git(command, **kwargs):
            if "bundle" in command and "create" in command:
                Path(command[command.index("create") + 1]).write_bytes(payload)
            self.assertGreater(kwargs["timeout"], 0)

        for size, accepted in ((MIB, True), (MIB + 1, False)):
            payload = b"x" * size
            with mock.patch("pygithost.remote_ci.subprocess.run", side_effect=git):
                if accepted:
                    self.assertEqual(len(source_bundle("/fake", "a" * 40, "", 1, 120)), MIB)
                else:
                    with self.assertRaisesRegex(ValueError, "configured 1 MiB"):
                        source_bundle("/fake", "a" * 40, "", 1)

    def test_worker_can_receive_source_above_old_32_and_46_mib_caps(self):
        client = Client("http://example.test", "secret")
        payload = b"x" * (36 * MIB)
        response = json.dumps({"bundle": base64.b64encode(payload).decode()}).encode()
        self.assertGreater(len(response), 46 * MIB)
        client.opener = mock.Mock()
        client.opener.open.side_effect = lambda *a, **kw: io.BytesIO(response)
        result = client.request("source", {"run_id": 1}, source_limit_mb=40, timeout=120)
        self.assertEqual(len(base64.b64decode(result["bundle"])), len(payload))
        self.assertEqual(client.opener.open.call_args.kwargs["timeout"], 120)
        with self.assertRaisesRegex(ValueError, "configured limit"):
            client.request("source", {"run_id": 1}, source_limit_mb=1)

    def test_artifact_count_uncompressed_and_compressed_limits(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            for index in range(1001):
                (root / f"{index}.txt").write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "1000-file"):
                collect_artifacts(root, ["*.txt"])
            self.assertIsNotNone(collect_artifacts(root, ["*.txt"], {"artifact_files": 1001}))
            # Deflate shrinks this, so exercise the uncompressed limit separately.
            (root / "large.bin").write_bytes(b"x" * (2 * MIB))
            with self.assertRaisesRegex(ValueError, "1 MiB"):
                collect_artifacts(root, ["large.bin"], {"artifact_uncompressed_mb": 1})
            archive = collect_artifacts(root, ["large.bin"], {"artifact_uncompressed_mb": 2})
            self.assertIsNotNone(archive)
            import os

            (root / "random.bin").write_bytes(os.urandom(2 * MIB))
            with self.assertRaisesRegex(ValueError, "ZIP exceeds"):
                collect_artifacts(root, ["random.bin"], {"artifact_mb": 1})
            self.assertIsNotNone(collect_artifacts(root, ["random.bin"], {"artifact_mb": 3}))

    def test_log_validation_uses_configured_budget(self):
        progress = {"output": "x" * (MIB + 1)}
        with self.assertRaises(APIError):
            validate_progress(progress, final=False)
        self.assertEqual(validate_progress(progress, final=False, limits={"log_mb": 2}), progress)
        self.assertGreater(completion_bytes({"artifact_mb": 100}), 100 * MIB)


class AssignmentLimitTests(unittest.TestCase):
    setUp = protocol_tests.RemoteProtocolTests.setUp
    tearDown = protocol_tests.RemoteProtocolTests.tearDown
    enqueue = protocol_tests.RemoteProtocolTests.enqueue
    call = protocol_tests.RemoteProtocolTests.call
    claim = protocol_tests.RemoteProtocolTests.claim

    def test_upload_bounds_are_taken_from_token_owned_snapshot(self):
        from pygithost.remote_ci import connect

        run = self.enqueue()
        identity = self.claim()
        conn = connect()
        try:
            conn.execute(
                "UPDATE ci_remote_jobs SET document=? WHERE run_id=?",
                (
                    json.dumps(
                        {
                            "config": {
                                "source_limit_mb": 1,
                                "limits": {"log_mb": 2, "artifact_mb": 80},
                            }
                        }
                    ),
                    run,
                ),
            )
        finally:
            conn.close()
        self.assertEqual(
            assigned_limits(self.digest, self.repositories, str(run))["artifact_mb"], 80
        )
        with self.assertRaises(APIError):
            assigned_limits("other-token", self.repositories, str(run))
        with self.assertRaises(APIError):
            assigned_limits(self.digest, ["other/project"], str(run))
        self.call("heartbeat", dict(identity, progress={"output": "x" * (MIB + 1)}))

    def test_server_source_delivery_rechecks_the_snapshot_limit(self):
        from pygithost.remote_ci import connect

        run = self.enqueue()
        identity = self.claim()
        conn = connect()
        try:
            conn.execute(
                "UPDATE ci_remote_jobs SET document=?,source=? WHERE run_id=?",
                (json.dumps({"config": {"source_limit_mb": 1}}), b"x" * (MIB + 1), run),
            )
        finally:
            conn.close()
        with self.assertRaises(APIError) as error:
            self.call("source", identity)
        self.assertEqual(error.exception.status, 413)

    def test_artifact_api_download_limit_uses_run_snapshot(self):
        from pygithost.api.ci_operations import artifact_limits

        run = self.enqueue()
        conn = database._db_connect()
        try:
            conn.execute(
                "UPDATE ci_runs SET config_json=? WHERE id=?",
                (
                    json.dumps({"limits": {"artifact_mb": 128, "transfer_timeout_seconds": 180}}),
                    run,
                ),
            )
        finally:
            conn.close()
        self.assertEqual(artifact_limits("alice", "project", run), (128 * MIB, 180))


class ProcessLimitTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancellation_during_phase_write_closes_inserted_assignment(self):
        from pygithost.remote_ci import connect, execute_remote

        with tempfile.TemporaryDirectory() as root:
            old_db = database.DB_PATH
            database.DB_PATH = str(Path(root) / "test.db")
            try:
                database._db_init()
                run = database.db_ci_run_create(
                    "alice", "project", "push", "main", "a" * 40, "{}", "{}"
                )
                row = (run, "alice", "project", "push", "main", "a" * 40, "{}")
                with (
                    mock.patch("pygithost.remote_ci.source_bundle", return_value=b"source"),
                    mock.patch.object(
                        database, "db_ci_run_update", side_effect=asyncio.CancelledError
                    ),
                ):
                    with self.assertRaises(asyncio.CancelledError):
                        await execute_remote(
                            CIManager(lambda *_: root),
                            row,
                            validate_config({"runner": "remote-docker"}),
                        )
                conn = connect()
                try:
                    self.assertEqual(
                        conn.execute(
                            "SELECT state FROM ci_remote_jobs WHERE run_id=?", (run,)
                        ).fetchone()[0],
                        "closed",
                    )
                finally:
                    conn.close()
            finally:
                database.DB_PATH = old_db

    async def test_process_capture_truncates_at_requested_budget(self):
        manager = CIManager(lambda *_: "")
        for maximum, truncated in ((MIB, True), (2 * MIB, False)):
            output, state = bytearray(), [False]
            result = await manager._capture_process(
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * (1024 * 1024 + 1))"],
                shell=False,
                cwd=None,
                env=None,
                output=output,
                truncated=state,
                timeout=15,
                max_output=maximum,
            )
            self.assertEqual(result, 0)
            self.assertEqual(len(output), min(maximum, MIB + 1))
            self.assertEqual(state[0], truncated)

    async def test_transfers_stop_on_server_cancellation_without_replaying_work(self):
        class Client:
            def request(self, action, identity):
                return {"cancel": True}

        work_cancelled = asyncio.Event()

        async def work():
            try:
                await asyncio.Event().wait()
            finally:
                work_cancelled.set()

        with self.assertRaises(JobStopped):
            await transfer_with_heartbeats(Client(), {"run_id": 1}, work())
        self.assertTrue(work_cancelled.is_set())


class LargeHTTPTransferTests(unittest.TestCase):
    git = protocol_tests.RunnerHTTPTests.git
    user = protocol_tests.RunnerHTTPTests.user
    request = protocol_tests.RunnerHTTPTests.request
    setUp = protocol_tests.RunnerHTTPTests.setUp
    tearDown = protocol_tests.RunnerHTTPTests.tearDown

    def test_real_http_logs_artifact_upload_and_api_download_exceed_old_caps(self):
        from pygithost.remote_ci import create_token, execute_remote

        config = validate_config(
            {
                "runner": "remote-docker",
                "command": "true",
                "limits": {"log_mb": 2, "artifact_mb": 40, "artifact_uncompressed_mb": 40},
            }
        )
        run = database.db_ci_run_create(
            "alice", "project", "push", "main", self.sha, "{}", json.dumps(config)
        )
        row = (run, "alice", "project", "push", "main", self.sha, "{}")
        task = asyncio.run_coroutine_threadsafe(
            execute_remote(CIManager(lambda *_: str(self.bare)), row, config), self.server.loop
        )
        client = Client(
            f"http://127.0.0.1:{self.server.port}", create_token("large-worker", ["alice/project"])
        )
        job = None
        deadline = time.monotonic() + 15
        while job is None and time.monotonic() < deadline:
            job = client.request("claim", {})["job"]
            time.sleep(0.02)
        self.assertIsNotNone(job)
        identity = {"run_id": run, "attempt": job["attempt"]}
        self.assertTrue(
            client.request("heartbeat", dict(identity, progress={"output": "x" * (MIB + 1)}))[
                "accepted"
            ]
        )
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("large.bin", b"x" * (33 * MIB))
        self.assertGreater(len(buffer.getvalue()), 32 * MIB)
        result = dict(
            identity,
            progress={"status": "success", "return_code": 0, "output": "done"},
            artifact=base64.b64encode(buffer.getvalue()).decode(),
        )
        self.assertTrue(client.request("complete", result, timeout=120)["accepted"])
        task.result(timeout=30)
        self.assertEqual(database.db_ci_run_get("alice", "project", run)[4], "success")
        status, _, listing = self.request(self.base + f"/ci/runs/{run}/artifacts")
        self.assertEqual(status, 200)
        self.assertTrue(listing[0]["downloadable"])
        status, _, download = self.request(
            self.base + f"/ci/runs/{run}/artifacts/download", decode=False
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(download), len(buffer.getvalue()))
