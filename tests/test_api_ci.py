import asyncio
from concurrent.futures import ThreadPoolExecutor
import io
import json
import os
import shlex
import shutil
import sys
import threading
import unittest
from unittest import mock
import zipfile

from pygithost import database
from pygithost.api import ci_operations, data
from pygithost.ci_config import compile_document
from tests import test_api as read_tests
from tests import test_api_writes as write_tests
from tests.test_server import _which_git_backend


@unittest.skipUnless(shutil.which("git") and _which_git_backend(), "requires Git HTTP backend")
class APICITests(unittest.TestCase):
    git = read_tests.APITests.git
    user = read_tests.APITests.user
    request = read_tests.APITests.request
    tearDown = read_tests.APITests.tearDown
    mutate = write_tests.APIWriteTests.mutate

    def setUp(self):
        read_tests.APITests.setUp(self)
        self.write_token = database.db_create_token(self.alice, "CI writer", "write")
        self.admin_write_token = database.db_create_token(self.admin, "CI writer", "write")
        self.manager = self.server.app.ci_manager
        self.start_patch = mock.patch.object(self.manager, "start", side_effect=self.paused_start)
        self.start_patch.start()
        self.addCleanup(self.start_patch.stop)
        self.ci_base = self.base + "/ci"

    async def paused_start(self):
        # Real enqueue/cancel/rerun logic without a worker racing queued assertions.
        self.manager.started = True

    def save_pipeline(self, **overrides):
        config = {"runner": "host", "steps": [{"name": "Checks", "run": "echo api-ci"}],
                  "events": {"manual": False}, **overrides}
        database.db_ci_config_set("alice", "project", json.dumps(config))
        return config

    def trigger(self, *, key=None, **document):
        return self.mutate(self.ci_base + "/runs",
            {"pipeline": "default", "branch": "main", **document}, key=key)

    def archive(self, identity=None):
        target = io.BytesIO()
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("report.txt", "API artifact")
        content = target.getvalue()
        database.db_ci_artifact_set(identity or self.run, content)
        return content

    def test_trigger_manual_run_is_selected_snapshotted_and_idempotent(self):
        self.save_pipeline(env={"PRIVATE_SETTING": "DO_NOT_EXPOSE"})
        status, _headers, result = self.trigger(sha=self.sha, key="trigger-once")
        self.assertEqual(status, 202, result)
        self.assertEqual(result["event"], "manual")
        self.assertEqual(result["pipeline"], "default")
        self.assertEqual(result["head_sha"], self.sha)
        self.assertEqual(result["status"], "queued")
        self.assertNotIn("DO_NOT_EXPOSE", json.dumps(result))
        metadata = database.db_ci_run_metadata("alice", "project", result["id"])
        self.assertEqual(json.loads(metadata["config"])["env"]["PRIVATE_SETTING"], "DO_NOT_EXPOSE")
        self.assertEqual(self.manager.pending[result["id"]][3], "manual")
        status, headers, replay = self.trigger(sha=self.sha, key="trigger-once")
        self.assertEqual(status, 202)
        self.assertEqual(replay, result)
        self.assertEqual(headers["X-Idempotent-Replay"], "true")
        self.assertEqual(len(self.manager.pending), 1)

    def test_trigger_one_named_pipeline_without_fanout(self):
        config = compile_document({"version": 1, "pipelines": [
            {"name": "checks", "steps": [{"name": "Checks", "run": "echo checks"}]},
            {"name": "build", "steps": [{"name": "Build", "run": "echo build"}]},
        ], "deployments": []})
        database.db_ci_config_set("alice", "project", json.dumps(config))
        status, _headers, result = self.trigger(pipeline="build")
        self.assertEqual(status, 202, result)
        self.assertEqual(result["pipeline"], "build")
        self.assertEqual(len(self.manager.pending), 1)
        self.assertEqual(self.trigger(pipeline="unknown")[0], 404)
        self.assertEqual(self.trigger(pipeline="../unsafe")[0], 422)

    def test_concurrent_trigger_retries_create_exactly_one_run(self):
        self.save_pipeline()
        entered, release = threading.Event(), asyncio.Event()
        enqueue = self.manager.enqueue

        async def blocked(*args, **kwargs):
            entered.set()
            await release.wait()
            return await enqueue(*args, **kwargs)

        with mock.patch.object(self.manager, "enqueue", side_effect=blocked) as queued:
            with ThreadPoolExecutor(max_workers=1) as pool:
                first = pool.submit(self.trigger, key="concurrent-trigger")
                try:
                    self.assertTrue(entered.wait(timeout=10), "First trigger never reached the scheduler")
                    status, _headers, result = self.trigger(key="concurrent-trigger")
                    self.assertEqual(status, 409, result)
                    self.assertEqual(result["code"], "operation_pending")
                finally:
                    self.server.loop.call_soon_threadsafe(release.set)
                status, _headers, created = first.result(timeout=10)
                self.assertEqual(status, 202, created)
            self.assertEqual(queued.await_count, 1)
        status, headers, replay = self.trigger(key="concurrent-trigger")
        self.assertEqual(status, 202)
        self.assertEqual(replay["id"], created["id"])
        self.assertEqual(headers["X-Idempotent-Replay"], "true")
        self.assertEqual(len(self.manager.pending), 1)
        self.assertEqual(database.db_ci_runs_count("alice", "project"), 2)

    def test_trigger_supports_slash_branches_and_rejects_changed_idempotent_body(self):
        self.save_pipeline()
        status, _headers, created = self.trigger(branch="feature/api", key="branch-trigger")
        self.assertEqual(status, 202, created)
        self.assertEqual(created["branch"], "feature/api")
        self.assertEqual(created["head_sha"], self.sha)
        rows = self.request(self.ci_base + "/runs?branch=feature%2Fapi")[2]
        self.assertEqual([row["id"] for row in rows], [created["id"]])
        status, _headers, result = self.trigger(branch="main", key="branch-trigger")
        self.assertEqual(status, 409)
        self.assertEqual(result["code"], "idempotency_conflict")
        self.assertEqual(len(self.manager.pending), 1)

    def test_scheduler_error_is_private_and_uncertain_request_is_not_reexecuted(self):
        self.save_pipeline()
        with mock.patch.object(self.manager, "enqueue", side_effect=RuntimeError("PRIVATE_SCHEDULER_ERROR")):
            status, headers, result = self.trigger(key="scheduler-error")
        self.assertEqual(status, 500, result)
        self.assertEqual(result["request_id"], headers["X-Request-ID"])
        self.assertNotIn("PRIVATE_SCHEDULER_ERROR", json.dumps(result))
        self.assertEqual(database.db_ci_runs_count("alice", "project"), 1)
        status, _headers, result = self.trigger(key="scheduler-error")
        self.assertEqual(status, 409)
        self.assertEqual(result["code"], "operation_pending")
        self.assertEqual(self.manager.pending, {})
        self.assertEqual(self.trigger(key="new-scheduler-attempt")[0], 202)

    def test_invalid_repository_pipeline_creates_failed_run_without_execution_override(self):
        (self.source / "ci").mkdir()
        (self.source / "ci/config.json").write_text(json.dumps({
            "version": 1, "runner": "host",
            "steps": [{"name": "Forbidden override", "run": "echo PRIVATE_COMMAND"}],
        }))
        self.git("-C", self.source, "add", "ci/config.json")
        self.git("-C", self.source, "commit", "-m", "Invalid repository CI execution override")
        self.git("-C", self.source, "push", self.bare, "main")
        status, _headers, created = self.trigger(pipeline="ci")
        self.assertEqual(status, 202, created)
        self.assertEqual(created["status"], "failed")
        self.assertEqual(self.manager.pending, {})
        metadata = database.db_ci_run_metadata("alice", "project", created["id"])
        self.assertEqual(metadata["config"], "")
        logs = self.request(self.ci_base + f"/runs/{created['id']}/logs")[2]
        self.assertEqual(logs["phase"], "configuration")
        self.assertTrue(logs["complete"])
        self.assertNotIn("PRIVATE_COMMAND", logs["content"])

    def test_trigger_validation_and_missing_repository_config(self):
        self.save_pipeline()
        self.assertEqual(self.trigger(sha="f" * 40)[0], 409)
        self.assertEqual(self.trigger(sha="main")[0], 422)
        self.assertEqual(self.trigger(branch="missing")[0], 404)
        for override in ({"env": {"X": "value"}}, {"runner": "host"}, {"event": "push"},
                         {"steps": []}, {"deploy_enabled": True}, {"payload": {"pr_number": 1}}):
            with self.subTest(override=override):
                self.assertEqual(self.trigger(**override)[0], 422)
        self.assertEqual(self.mutate(self.ci_base + "/runs", {"branch": "main"})[0], 422)
        database.db_ci_config_set("alice", "project", json.dumps({}))
        self.assertEqual(self.trigger()[0], 409)
        conn = database._db_connect()
        try:
            conn.execute("DELETE FROM ci_configs WHERE owner='alice' AND repo='project'")
        finally:
            conn.close()
        self.assertEqual(self.trigger(pipeline="ci")[0], 409)  # no ci/config.json
        self.assertEqual(self.manager.pending, {})

    def test_queue_failure_is_visible_in_accepted_run(self):
        self.save_pipeline()
        self.manager.queue_limit = 0
        status, _headers, result = self.trigger()
        self.assertEqual(status, 202, result)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(database.db_ci_run_metadata("alice", "project", result["id"])["phase"], "queue")
        logs = self.request(self.ci_base + f"/runs/{result['id']}/logs")[2]
        self.assertEqual(logs["phase"], "queue")
        self.assertIn("queue is full", logs["reason"])
        self.assertEqual(self.manager.pending, {})

    def test_cancel_queued_run_and_replay_without_duplicate_actions(self):
        self.save_pipeline()
        created = self.trigger()[2]
        path = self.ci_base + f"/runs/{created['id']}/cancel"
        status, _headers, result = self.mutate(path, {}, key="cancel-once")
        self.assertEqual(status, 200, result)
        self.assertEqual(result["status"], "cancelled")
        self.assertNotIn(created["id"], self.manager.pending)
        self.assertEqual(self.mutate(path, {})[0], 200)
        self.assertEqual(self.mutate(path, {}, key="cancel-once")[2], result)
        database.db_ci_run_update(self.run, status="success")
        self.assertEqual(self.mutate(self.ci_base + f"/runs/{self.run}/cancel", {})[0], 409)
        self.assertEqual(self.mutate(self.ci_base + "/runs/999999/cancel", {})[0], 404)
        self.assertEqual(self.mutate(path, {"force": True})[0], 422)

    def test_cancel_running_job_uses_manager_cleanup(self):
        async def prepare():
            self.manager.started = True
            task = asyncio.create_task(asyncio.Event().wait())
            self.manager.active[self.run] = ((self.run, "alice", "project", "manual", "main", self.sha, "{}"), task)
            return task
        task = asyncio.run_coroutine_threadsafe(prepare(), self.server.loop).result(timeout=10)
        database.db_ci_run_update(self.run, status="running")
        status, _headers, result = self.mutate(self.ci_base + f"/runs/{self.run}/cancel", {})
        self.assertEqual(status, 200, result)
        self.assertEqual(result["status"], "cancelled")
        self.assertTrue(task.cancelled())
        self.assertNotIn(self.run, self.manager.active)

    def test_cancellation_racing_success_never_rewrites_success_as_cancelled(self):
        for accepted in (False, True):
            with self.subTest(accepted=accepted):
                database.db_ci_run_update(self.run, status="running")

                async def finish_before_cancel(*_args, **_kwargs):
                    await asyncio.to_thread(database.db_ci_run_update, self.run, status="success")
                    return accepted

                with mock.patch.object(self.manager, "cancel", side_effect=finish_before_cancel):
                    status, _headers, result = self.mutate(self.ci_base + f"/runs/{self.run}/cancel", {})
                self.assertEqual(status, 200 if accepted else 409, result)
                self.assertEqual(database.db_ci_run_get("alice", "project", self.run)[4], "success")
                if accepted:
                    self.assertEqual(result["status"], "success")

    def test_trigger_replay_after_run_retention_does_not_queue_replacement(self):
        self.save_pipeline()
        created = self.trigger(key="retained-trigger")[2]
        self.mutate(self.ci_base + f"/runs/{created['id']}/cancel", {})
        conn = database._db_connect()
        try:
            conn.execute("DELETE FROM ci_runs WHERE id=?", (created["id"],))
        finally:
            conn.close()
        status, headers, replay = self.trigger(key="retained-trigger")
        self.assertEqual(status, 202, replay)
        self.assertEqual(replay, created)
        self.assertEqual(headers["X-Idempotent-Replay"], "true")
        self.assertEqual(self.request(self.ci_base + f"/runs/{created['id']}")[0], 404)
        self.assertEqual(self.manager.pending, {})
        self.assertEqual(database.db_ci_runs_count("alice", "project"), 1)

    def test_rerun_uses_old_snapshot_event_commit_and_idempotency(self):
        original = self.save_pipeline(env={"SNAPSHOT": "original"})
        database.db_ci_run_update(self.run, status="failed")
        conn = database._db_connect()
        try:
            conn.execute("UPDATE ci_runs SET event='push',config_json=?,payload_json='{}' WHERE id=?",
                         (json.dumps(original), self.run))
        finally:
            conn.close()
        self.save_pipeline(env={"SNAPSHOT": "changed"}, steps=[{"name": "Changed", "run": "echo new"}])
        path = self.ci_base + f"/runs/{self.run}/rerun"
        status, _headers, result = self.mutate(path, {}, key="rerun-once")
        self.assertEqual(status, 202, result)
        self.assertNotEqual(result["id"], self.run)
        self.assertEqual(result["event"], "push")
        self.assertEqual(result["head_sha"], self.sha)
        snapshot = json.loads(database.db_ci_run_metadata("alice", "project", result["id"])["config"])
        self.assertEqual(snapshot["env"]["SNAPSHOT"], "original")
        self.assertEqual(snapshot["steps"], original["steps"])
        self.assertEqual(self.mutate(path, {}, key="rerun-once")[2], result)
        self.assertEqual(len(self.manager.pending), 1)
        self.assertEqual(self.mutate(self.ci_base + f"/runs/{result['id']}/rerun", {})[0], 409)
        self.assertEqual(self.mutate(path, {"env": {"BAD": "override"}})[0], 422)

    def test_rerun_requires_terminal_run_and_usable_snapshot(self):
        path = self.ci_base + f"/runs/{self.run}/rerun"
        self.assertEqual(self.mutate(path, {})[0], 409)
        database.db_ci_run_update(self.run, status="failed")
        conn = database._db_connect()
        try:
            conn.execute("UPDATE ci_runs SET config_json='' WHERE id=?", (self.run,))
        finally:
            conn.close()
        status, _headers, result = self.mutate(path, {})
        self.assertEqual(status, 409)
        self.assertEqual(result["code"], "snapshot_unavailable")

    def test_corrupt_snapshot_error_is_cached_until_a_new_rerun_key_is_used(self):
        original = self.save_pipeline()
        database.db_ci_run_update(self.run, status="failed")
        conn = database._db_connect()
        try:
            conn.execute("UPDATE ci_runs SET config_json='PRIVATE_INVALID_SNAPSHOT' WHERE id=?", (self.run,))
        finally:
            conn.close()
        path = self.ci_base + f"/runs/{self.run}/rerun"
        with mock.patch.object(self.manager, "rerun", wraps=self.manager.rerun) as rerun:
            status, _headers, result = self.mutate(path, {}, key="bad-snapshot")
            self.assertEqual(status, 409)
            self.assertEqual(result["code"], "snapshot_unavailable")
            self.assertNotIn("PRIVATE_INVALID_SNAPSHOT", json.dumps(result))
            conn = database._db_connect()
            try:
                conn.execute("UPDATE ci_runs SET config_json=? WHERE id=?", (json.dumps(original), self.run))
            finally:
                conn.close()
            status, headers, result = self.mutate(path, {}, key="bad-snapshot")
            self.assertEqual(status, 409)
            self.assertEqual(headers["X-Idempotent-Replay"], "true")
            self.assertEqual(rerun.await_count, 1)
        self.assertEqual(self.mutate(path, {}, key="repaired-snapshot")[0], 202)
        self.assertEqual(len(self.manager.pending), 1)

    def test_write_scope_and_repository_isolation_for_actions_and_reads(self):
        self.save_pipeline()
        self.archive()
        for token in (self.token, self.admin_token):
            for tail, document in (("/runs", {"branch": "main", "pipeline": "default"}),
                                   (f"/runs/{self.run}/cancel", {}), (f"/runs/{self.run}/rerun", {})):
                with self.subTest(token=token, tail=tail):
                    self.assertEqual(self.mutate(self.ci_base + tail, document, token=token)[0], 403)
        bob_base = "/api/v1/repos/bob/project/ci"
        for suffix in ("logs", "artifacts", "artifacts/download"):
            self.assertEqual(self.request(f"{bob_base}/runs/{self.run}/{suffix}",
                                          token=self.bob_token)[0], 404)
            self.assertEqual(self.request(f"{bob_base}/runs/{self.run}/{suffix}",
                                          token=self.admin_token)[0], 404)
        for action in ("cancel", "rerun"):
            self.assertEqual(self.mutate(f"{bob_base}/runs/{self.run}/{action}", {},
                                          token=self.admin_write_token)[0], 404)
        self.assertEqual(self.mutate(bob_base + "/runs",
                                    {"branch": "main", "pipeline": "default"})[0], 404)

    def test_logs_and_archives_require_fresh_bearer_authentication(self):
        self.archive()
        paths = [self.ci_base + "/artifacts", *[
            self.ci_base + f"/runs/{self.run}/" + suffix
            for suffix in ("logs", "artifacts", "artifacts/download")]]
        for path in paths:
            for token in (None, "invalid-token"):
                with self.subTest(path=path, token=token):
                    status, headers, result = self.request(path, token=token)
                    self.assertEqual(status, 401)
                    self.assertEqual(result["code"], "unauthorized")
                    self.assertIn("Bearer", headers["WWW-Authenticate"])
        read_token = next(row[0] for row in database.db_list_tokens_for_user(self.alice) if row[1] == "test")
        self.assertTrue(database.db_revoke_token(self.alice, read_token))
        for path in paths:
            self.assertEqual(self.request(path)[0], 401)
        status, _headers, content = self.request(paths[-1], method="HEAD", token=None)
        self.assertEqual(status, 401)
        self.assertEqual(content, b"")

    def test_log_chunks_are_byte_bounded_utf8_safe_and_handle_nul(self):
        database.db_ci_run_update(self.run, status="success", output="Aé😀\0Z", truncated=1)
        path = self.ci_base + f"/runs/{self.run}/logs"
        status, _headers, first = self.request(path + "?limit=4")
        self.assertEqual(status, 200, first)
        self.assertEqual(first["content"], "Aé")
        self.assertEqual(first["next_offset"], 3)
        self.assertEqual(first["size_in_bytes"], 9)
        self.assertTrue(first["has_more"])
        self.assertTrue(first["truncated"])
        second = self.request(path + "?limit=4&offset=3")[2]
        self.assertEqual(second["content"], "😀")
        self.assertEqual(second["next_offset"], 7)
        last = self.request(path + "?limit=4&offset=7")[2]
        self.assertEqual(last["content"], "\0Z")
        self.assertFalse(last["has_more"])
        self.assertTrue(last["complete"])
        self.assertNotIn("DO_NOT_EXPOSE", json.dumps(first))
        for query in ("offset=2", "offset=10", "offset=-1", "offset=2147483648",
                      "limit=1", "limit=65537", "limit=4&limit=8"):
            with self.subTest(query=query):
                self.assertEqual(self.request(path + "?" + query)[0], 400)
        self.assertEqual(self.request(path + "?offset=9")[2]["content"], "")
        self.assertEqual(self.request(self.ci_base + "/runs/999999/logs")[0], 404)

    def test_logs_are_pollable_and_read_in_sql_instead_of_loading_whole_output(self):
        database.db_ci_run_update(self.run, status="running", output="x" * (3 * 1024 * 1024))
        path = self.ci_base + f"/runs/{self.run}/logs"
        with mock.patch.object(database, "db_ci_run_get", side_effect=AssertionError("Must slice in SQL")):
            status, _headers, result = self.request(path + "?limit=65536")
        self.assertEqual(status, 200, result)
        self.assertEqual(len(result["content"].encode()), 65536)
        self.assertEqual(result["size_in_bytes"], 3 * 1024 * 1024)
        self.assertFalse(result["complete"])
        database.db_ci_run_update(self.run, output="")
        empty = self.request(path)[2]
        self.assertEqual(empty["next_offset"], 0)
        self.assertFalse(empty["has_more"])
        self.assertFalse(empty["complete"])

    def test_log_cursor_round_trips_mixed_unicode_and_control_characters(self):
        original = ('\0"\\\né😀漢\r\tZ\u2028e\u0301' * 3).encode("utf-8")
        database.db_ci_run_update(self.run, status="success", output=original.decode())
        path = self.ci_base + f"/runs/{self.run}/logs"
        for limit in (4, 5, 7, 13, 32, 65536):
            with self.subTest(limit=limit):
                offset, collected = 0, bytearray()
                while True:
                    status, _headers, result = self.request(path + f"?offset={offset}&limit={limit}")
                    self.assertEqual(status, 200, result)
                    encoded = result["content"].encode("utf-8")
                    self.assertLessEqual(len(encoded), limit)
                    self.assertEqual(encoded, original[offset:result["next_offset"]])
                    self.assertGreater(result["next_offset"], offset)
                    collected.extend(encoded)
                    offset = result["next_offset"]
                    if not result["has_more"]:
                        self.assertTrue(result["complete"])
                        break
                self.assertEqual(bytes(collected), original)
                self.assertEqual(offset, len(original))

    def test_log_cursor_recovers_after_output_replacement_and_diagnostics_are_bounded(self):
        path = self.ci_base + f"/runs/{self.run}/logs"
        database.db_ci_run_update(self.run, status="running", output="old output")
        previous = self.request(path)[2]
        database.db_ci_run_update(self.run, output="new", reason="R" * 5000, phase="command")
        status, _headers, result = self.request(path + "?offset=" + str(previous["next_offset"]))
        self.assertEqual(status, 400)
        self.assertEqual(result["code"], "invalid_offset")
        current = self.request(path)[2]
        self.assertEqual(current["content"], "new")
        self.assertEqual(current["reason"], "R" * 4096)
        self.assertFalse(current["complete"])
        database.db_ci_run_update(self.run, status="failed")
        final = self.request(path + "?offset=" + str(current["next_offset"]))[2]
        self.assertEqual(final["content"], "")
        self.assertTrue(final["complete"])

    def test_log_head_has_json_headers_without_exposing_output(self):
        database.db_ci_run_update(self.run, status="success", output="PRIVATE_LOG_LINE")
        path = self.ci_base + f"/runs/{self.run}/logs"
        status, get_headers, body = self.request(path, decode=False)
        self.assertEqual(status, 200)
        status, headers, content = self.request(path, method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(content, b"")
        self.assertEqual(headers["Content-Length"], str(len(body)))
        self.assertEqual(headers["Content-Type"], get_headers["Content-Type"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertNotIn("PRIVATE_LOG_LINE", json.dumps(headers))

    def test_artifact_metadata_download_and_head(self):
        archive = self.archive()
        status, _headers, items = self.request(self.ci_base + "/artifacts")
        self.assertEqual(status, 200, items)
        self.assertEqual(len(items), 1)
        artifact = items[0]
        self.assertEqual(artifact["size_in_bytes"], len(archive))
        self.assertTrue(artifact["downloadable"])
        self.assertEqual(self.request(self.ci_base + f"/runs/{self.run}/artifacts")[2], items)
        status, headers, content = self.request(artifact["download_url"], decode=False)
        self.assertEqual(status, 200)
        self.assertEqual(content, archive)
        self.assertEqual(headers["Content-Type"], "application/zip")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn(f"ci-{self.run}-artifacts.zip", headers["Content-Disposition"])
        with mock.patch("pygithost.api.data.artifact_content", wraps=data.artifact_content) as read:
            status, headers, content = self.request(artifact["download_url"], method="HEAD", decode=False)
        self.assertEqual(status, 200)
        self.assertEqual(content, b"")
        self.assertEqual(int(headers["Content-Length"]), len(archive))
        self.assertTrue(read.call_args.kwargs["head"])

    def test_artifact_size_limit_without_fetching_oversized_blob(self):
        archive = self.archive()
        self.assertEqual(data.artifact_content("alice", "project", self.run, 1), (len(archive), None))
        with mock.patch.object(ci_operations, "MAX_ARTIFACT_BYTES", 1):
            self.assertFalse(self.request(self.ci_base + "/artifacts")[2][0]["downloadable"])
            path = self.ci_base + f"/runs/{self.run}/artifacts/download"
            status, _headers, result = self.request(path)
            self.assertEqual(status, 413)
            self.assertEqual(result["code"], "artifact_too_large")
            self.assertEqual(self.request(path, method="HEAD")[0], 413)
        async def permits_available():
            slots = self.server.app.api_download_slots
            async with asyncio.timeout(1):
                await slots.acquire()
                try:
                    await slots.acquire()
                    slots.release()
                finally:
                    slots.release()
        asyncio.run_coroutine_threadsafe(permits_available(), self.server.loop).result(timeout=5)

    def test_artifact_expiry_missing_run_and_empty_list(self):
        path = self.ci_base + f"/runs/{self.run}/artifacts"
        self.assertEqual(self.request(path)[2], [])
        self.assertEqual(self.request(path + "/download")[0], 404)
        self.assertEqual(self.request(self.ci_base + "/runs/999999/artifacts")[0], 404)
        self.archive()
        conn = database._db_connect()
        try:
            conn.execute("UPDATE ci_artifacts SET created_at=datetime('now','-8 days') WHERE run_id=?", (self.run,))
        finally:
            conn.close()
        self.assertEqual(self.request(self.ci_base + "/artifacts")[2], [])
        self.assertEqual(self.request(path + "/download")[0], 404)

    def test_artifact_download_accepts_exact_limit_and_rejects_one_byte_over(self):
        archive = self.archive()
        path = self.ci_base + f"/runs/{self.run}/artifacts/download"
        with mock.patch.object(ci_operations, "MAX_ARTIFACT_BYTES", len(archive)):
            self.assertTrue(self.request(self.ci_base + "/artifacts")[2][0]["downloadable"])
            status, _headers, content = self.request(path, decode=False)
            self.assertEqual(status, 200)
            self.assertEqual(content, archive)
            self.assertEqual(self.request(path, method="HEAD")[0], 200)
        with mock.patch.object(ci_operations, "MAX_ARTIFACT_BYTES", len(archive) - 1):
            self.assertFalse(self.request(self.ci_base + "/artifacts")[2][0]["downloadable"])
            self.assertEqual(self.request(path)[0], 413)

    def test_artifact_retention_can_be_disabled_then_reenabled(self):
        database.db_ci_config_set("alice", "project", json.dumps({"artifact_retention_days": 0}))
        archive = self.archive()
        conn = database._db_connect()
        try:
            conn.execute("UPDATE ci_artifacts SET created_at='2000-01-01 00:00:00' WHERE run_id=?", (self.run,))
        finally:
            conn.close()
        item = self.request(self.ci_base + "/artifacts")[2][0]
        self.assertEqual(item["created_at"], "2000-01-01T00:00:00Z")
        self.assertIsNone(item["expires_at"])
        self.assertEqual(self.request(item["download_url"], decode=False)[2], archive)
        database.db_ci_config_set("alice", "project", json.dumps({"artifact_retention_days": 1}))
        self.assertEqual(self.request(self.ci_base + "/artifacts")[2], [])
        self.assertEqual(self.request(item["download_url"])[0], 404)

    def test_artifact_count_retention_is_repository_scoped(self):
        database.db_ci_config_set("alice", "project", json.dumps({
            "artifact_retention_days": 0, "artifact_retention_count": 1}))
        self.archive()
        foreign = database.db_ci_run_create("bob", "project", "manual", "main", self.sha, "{}")
        self.archive(foreign)
        newer = database.db_ci_run_create("alice", "project", "manual", "main", self.sha, "{}")
        self.archive(newer)
        items = self.request(self.ci_base + "/artifacts")[2]
        self.assertEqual([item["run_id"] for item in items], [newer])
        self.assertEqual(self.request(self.ci_base + f"/runs/{self.run}/artifacts/download")[0], 404)
        self.assertEqual(self.request(self.ci_base + f"/runs/{self.run}")[0], 200)
        status, _headers, items = self.request("/api/v1/repos/bob/project/ci/artifacts", token=self.bob_token)
        self.assertEqual(status, 200)
        self.assertEqual([item["run_id"] for item in items], [foreign])

    def test_download_concurrency_limit_is_held_until_transfers_finish(self):
        from pygithost import application
        archive = self.archive()
        path = self.ci_base + f"/runs/{self.run}/artifacts/download"
        waiting, sending, release = threading.Event(), threading.Event(), asyncio.Event()
        original_send = application._send_response
        transfers = 0

        class ObservedSemaphore(asyncio.Semaphore):
            attempts = 0

            async def acquire(slots):
                slots.attempts += 1
                if slots.attempts == 3:
                    waiting.set()
                return await super().acquire()

        self.server.app.api_download_slots = ObservedSemaphore(2)

        async def blocked_send(request, status, body=b"", headers=None, **kwargs):
            nonlocal transfers
            if status == 200 and dict(headers or []).get("Content-Type") == "application/zip":
                transfers += 1
                if transfers == 2:
                    sending.set()
                await release.wait()
            return await original_send(request, status, body, headers, **kwargs)

        with mock.patch.object(application, "_send_response", side_effect=blocked_send), mock.patch(
                "pygithost.api.data.artifact_content", wraps=data.artifact_content) as read:
            with ThreadPoolExecutor(max_workers=3) as pool:
                requests = [pool.submit(self.request, path, decode=False) for _ in range(3)]
                try:
                    self.assertTrue(sending.wait(timeout=10), "Two transfers did not start")
                    self.assertTrue(waiting.wait(timeout=10), "Third transfer did not wait for a permit")
                    self.assertEqual(read.call_count, 2, "Queued download loaded a third archive body")
                finally:
                    self.server.loop.call_soon_threadsafe(release.set)
                for request in requests:
                    status, _headers, content = request.result(timeout=10)
                    self.assertEqual(status, 200)
                    self.assertEqual(content, archive)
            self.assertEqual(read.call_count, 3)

    def test_artifacts_paginate_with_full_hundred_item_page(self):
        archive = self.archive()
        conn = database._db_connect()
        try:
            for _ in range(100):
                identity = conn.execute(
                    "INSERT INTO ci_runs(owner,repo,event) VALUES('alice','project','manual')").lastrowid
                conn.execute("INSERT INTO ci_artifacts(run_id,archive) VALUES(?,?)", (identity, archive))
        finally:
            conn.close()
        status, headers, items = self.request(self.ci_base + "/artifacts?per_page=100")
        self.assertEqual(status, 200)
        self.assertEqual(len(items), 100)
        self.assertIn('rel="next"', headers["Link"])
        status, headers, items = self.request(self.ci_base + "/artifacts?per_page=100&page=2")
        self.assertEqual(status, 200)
        self.assertEqual([item["run_id"] for item in items], [self.run])
        self.assertNotIn('rel="next"', headers["Link"])

    @unittest.skipUnless(os.name == "posix", "real POSIX host runner")
    def test_real_manual_run_produces_logs_artifacts_and_never_deploys(self):
        self.start_patch.stop()
        marker = self.root / "must-not-deploy"
        script = self.root / "deployment.sh"
        script.write_text("#!/bin/sh\ntouch " + shlex.quote(str(marker)) + "\n")
        script.chmod(0o700)
        command = (shlex.quote(sys.executable) +
            ' -c "from pathlib import Path; Path(\'report.txt\').write_text(\'real-api-artifact\'); print(\'real-api-ci-ok\')"')
        self.save_pipeline(steps=[{"name": "Produce report", "run": command}],
            artifacts={"paths": ["report.txt"], "when": "always"},
            deploy_enabled=True, deploy_branch="main", deploy_script=str(script), deploy_interpreter="sh")
        status, _headers, created = self.trigger(key="real-manual")
        self.assertEqual(status, 202, created)
        asyncio.run_coroutine_threadsafe(self.manager.wait_idle(), self.server.loop).result(timeout=30)
        result = self.request(self.ci_base + f"/runs/{created['id']}")[2]
        self.assertEqual(result["status"], "success", database.db_ci_run_get("alice", "project", created["id"]))
        logs = self.request(self.ci_base + f"/runs/{created['id']}/logs")[2]
        self.assertIn("real-api-ci-ok", logs["content"])
        self.assertTrue(logs["complete"])
        status, _headers, archive = self.request(
            self.ci_base + f"/runs/{created['id']}/artifacts/download", decode=False)
        self.assertEqual(status, 200)
        with zipfile.ZipFile(io.BytesIO(archive)) as content:
            self.assertEqual(content.read("report.txt"), b"real-api-artifact")
        self.assertFalse(marker.exists())
        self.assertEqual(database.db_deployments_count("alice", "project"), 0)
        status, _headers, rerun = self.mutate(
            self.ci_base + f"/runs/{created['id']}/rerun", {}, key="real-manual-rerun")
        self.assertEqual(status, 202, rerun)
        self.assertEqual(rerun["event"], "manual")
        asyncio.run_coroutine_threadsafe(self.manager.wait_idle(), self.server.loop).result(timeout=30)
        self.assertEqual(self.request(self.ci_base + f"/runs/{rerun['id']}")[2]["status"], "success")
        self.assertFalse(marker.exists())
        self.assertEqual(database.db_deployments_count("alice", "project"), 0)

    def test_openapi_includes_ci_actions_logs_and_zip_without_webhooks(self):
        schema = self.request("/api/v1/openapi.json")[2]
        paths = schema["paths"]
        base = "/repos/{owner}/{repo}/ci"
        self.assertIn("202", paths[base + "/runs"]["post"]["responses"])
        self.assertIn("post", paths[base + "/runs/{id}/cancel"])
        self.assertIn("post", paths[base + "/runs/{id}/rerun"])
        download = paths[base + "/runs/{id}/artifacts/download"]
        self.assertIn("application/zip", download["get"]["responses"]["200"]["content"])
        self.assertNotIn("content", download["head"]["responses"]["200"])
        self.assertFalse(any("webhook" in path for path in paths))
        status, _headers, page = self.request("/api/docs", token=None, decode=False)
        self.assertEqual(status, 200)
        self.assertIn(b"CI automation", page)
        self.assertIn(b"32 MiB", page)
        self.assertIn(b"webhook", page)

    def test_in_page_documentation_renders_test_coverage_commands_and_navigation(self):
        status, headers, page = self.request("/api/docs", token=None, decode=False)
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b'aria-label="API documentation sections"', page)
        for anchor in ("ci-automation", "ci-api-safety-and-test-coverage", "responses-pagination-and-errors"):
            with self.subTest(anchor=anchor):
                self.assertIn(f'href="#{anchor}"'.encode(), page)
                self.assertIn(f'id="{anchor}"'.encode(), page)
        self.assertIn(b"Concurrent retries", page)
        self.assertIn(b"Archive concurrency", page)
        self.assertIn(b"operation_pending", page)
        self.assertIn(b"python -m unittest tests.test_api_ci -v", page)
        self.assertIn(b"temporary database", page)


class CITimestampTests(unittest.TestCase):
    def test_naive_ci_timestamps_are_utc_not_server_local_time(self):
        self.assertEqual(data.utc_timestamp("2026-11-13 10:20:30"), "2026-11-13T10:20:30Z")
        self.assertEqual(data.utc_timestamp("2026-11-13T12:20:30+02:00"), "2026-11-13T10:20:30Z")
        self.assertIsNone(data.utc_timestamp(None))


class APIDownloadTests(unittest.IsolatedAsyncioTestCase):
    async def test_transfer_timeout_closes_connection_without_second_response(self):
        from pygithost import application
        from pygithost.api.responses import BinaryDownload
        from pygithost.api.router import API
        handler = mock.Mock()
        handler.request.method = "GET"
        api = API(handler)

        async def blocked(*_args, **_kwargs):
            await asyncio.Future()

        with mock.patch.object(application, "_send_response", side_effect=blocked) as send, mock.patch(
                "pygithost.api.router.RESPONSE_TIMEOUT", 0.01):
            with self.assertRaises(application.ClientDisconnected):
                await api.send_download(BinaryDownload(b"zip", 3, "ci-1-artifacts.zip"))
        handler.request.writer.close.assert_called_once()
        handler.request.writer.transport.abort.assert_called_once()
        self.assertEqual(send.call_count, 1)

    async def test_cancelled_transfer_aborts_buffer_and_preserves_cancellation(self):
        from pygithost import application
        from pygithost.api.responses import BinaryDownload
        from pygithost.api.router import API
        handler = mock.Mock()
        handler.request.method = "GET"
        api = API(handler)
        started = asyncio.Event()

        async def blocked(*_args, **_kwargs):
            started.set()
            await asyncio.Future()

        with mock.patch.object(application, "_send_response", side_effect=blocked) as send:
            task = asyncio.create_task(api.send_download(BinaryDownload(b"zip", 3, "ci-1-artifacts.zip")))
            try:
                async with asyncio.timeout(5):
                    await started.wait()
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            finally:
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
        handler.request.writer.close.assert_called_once()
        handler.request.writer.transport.abort.assert_called_once()
        self.assertEqual(send.call_count, 1)
