"""Telemetry call-site tests: every event, metric and span stays privacy-safe."""

import asyncio
import os
import sqlite3
import subprocess
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest import mock
from unittest.mock import AsyncMock

from pygithost import application, database, pull_store, pulls, sentinel
from pygithost.api.errors import APIError
from pygithost.api.router import API
from pygithost.application import AsyncGitServer, GitHTTPHandler, Headers
from pygithost.ci import CIManager
from pygithost.config import AppConfig
from pygithost.context import AppContext
from pygithost.sentinel import SentinelExporter
from tests.ci_fixtures import commit_legacy_config, trusted_ci_repositories


class FakeSentinel:
    """Capture exporter calls without a background worker or network."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.counts: list[dict[str, Any]] = []
        self.observations: list[dict[str, Any]] = []
        self.spans: list[dict[str, Any]] = []

    def emit(
        self,
        name: str,
        level: str,
        *,
        attributes: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        trace_id: str | None = None,
        span_id: str | None = None,
    ) -> None:
        self.events.append(
            {
                "name": name,
                "level": level,
                "attributes": attributes or {},
                "correlation_id": correlation_id,
                "trace_id": trace_id,
                "span_id": span_id,
            }
        )

    def count(self, name: str, value: float, attributes: dict[str, Any] | None) -> None:
        self.counts.append({"name": name, "value": value, "attributes": attributes or {}})

    def observe(self, name: str, value_ms: float, attributes: dict[str, Any] | None) -> None:
        self.observations.append({"name": name, "value": value_ms, "attributes": attributes or {}})

    def span(
        self,
        name: str,
        start: Any,
        end: Any,
        *,
        trace_id: str,
        span_id: str,
        parent_span_id: str | None,
        kind: str,
        status: str,
        status_message: str | None,
        attributes: dict[str, Any] | None,
    ) -> None:
        self.spans.append(
            {
                "name": name,
                "start": start,
                "end": end,
                "trace_id": trace_id,
                "span_id": span_id,
                "parent_span_id": parent_span_id,
                "kind": kind,
                "status": status,
                "status_message": status_message,
                "attributes": attributes or {},
            }
        )


class SentinelTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.fake = FakeSentinel()
        self.previous = sentinel.current()
        sentinel.set_current(cast(SentinelExporter, self.fake))
        self.addCleanup(sentinel.set_current, self.previous)

    def _events(self, name: str) -> list[dict[str, Any]]:
        return [event for event in self.fake.events if event["name"] == name]

    def _counts(self, name: str) -> list[dict[str, Any]]:
        return [item for item in self.fake.counts if item["name"] == name]

    def assert_privacy_safe(self, *forbidden: str) -> None:
        values: list[str] = []
        for item in self.fake.events + self.fake.counts + self.fake.observations:
            values.extend(str(value) for value in item["attributes"].values())
        for item in self.fake.spans:
            values.extend(str(value) for value in item["attributes"].values())
            if item["status_message"]:
                values.append(str(item["status_message"]))
        for value in values:
            for secret in forbidden:
                self.assertNotIn(secret, value)


class AuditTelemetryTests(SentinelTestCase):
    async def test_login_failure_audit_event_is_privacy_safe(self) -> None:
        request = SimpleNamespace(
            peer_ip="10.9.8.7",
            target="/login",
            method="POST",
            version="HTTP/1.1",
            headers=Headers([]),
            reader=asyncio.StreamReader(),
            writer=SimpleNamespace(write=lambda _data: None),
        )
        handler = GitHTTPHandler(request, SimpleNamespace(audit_log=True))
        with mock.patch("pygithost.application.db_audit_append") as append:
            await handler._audit(
                "login",
                "failure",
                actor="alice_secret",
                target="web",
                detail="invalid_credentials",
            )
        append.assert_called_once()

        events = self._events("audit_login")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["level"], "Warning")
        self.assertEqual(
            events[0]["attributes"],
            {"action": "login", "outcome": "failure", "reason": "invalid_credentials"},
        )
        logins = self._counts("auth.login.count")
        self.assertEqual(logins[0]["attributes"], {"outcome": "failure", "method": "web"})
        self.assert_privacy_safe("alice_secret", "10.9.8.7", "/login")

    async def test_free_text_audit_detail_is_not_exported(self) -> None:
        request = SimpleNamespace(
            peer_ip="10.9.8.7",
            target="/admin",
            method="POST",
            version="HTTP/1.1",
            headers=Headers([]),
            reader=asyncio.StreamReader(),
            writer=SimpleNamespace(write=lambda _data: None),
        )
        handler = GitHTTPHandler(request, SimpleNamespace(audit_log=True))
        with mock.patch("pygithost.application.db_audit_append"):
            await handler._audit(
                "repo_delete",
                "failure",
                actor="alice_secret",
                target="owner/secret-repo",
                detail="unsafe path /srv/secret",
            )
        event = self._events("audit_repo_delete")[0]
        self.assertEqual(event["attributes"], {"action": "repo_delete", "outcome": "failure"})
        self.assert_privacy_safe("alice_secret", "10.9.8.7", "/srv/secret", "secret-repo")

    async def test_git_missing_credentials_is_a_challenge_not_a_failure(self) -> None:
        request = SimpleNamespace(
            peer_ip="10.9.8.7",
            target="/git/owner/repo.git/info/refs",
            method="GET",
            version="HTTP/1.1",
            headers=Headers([]),
            reader=asyncio.StreamReader(),
            writer=SimpleNamespace(write=lambda _data: None),
        )
        handler = GitHTTPHandler(request, SimpleNamespace(audit_log=False))
        with (
            mock.patch("pygithost.application.REQUIRE_AUTH", True),
            mock.patch("pygithost.application._send_response", AsyncMock()),
        ):
            allowed = await handler._require_auth()
        self.assertFalse(allowed)
        self.assertEqual(self._events("auth_failure"), [])
        self.assertEqual(self._counts("auth.challenge.count")[0]["attributes"], {"surface": "git"})
        self.assertEqual(self._counts("auth.failure.count"), [])
        self.assert_privacy_safe("10.9.8.7", "owner/repo")

    async def test_git_invalid_credentials_is_an_auth_failure(self) -> None:
        request = SimpleNamespace(
            peer_ip="10.9.8.7",
            target="/git/owner/repo.git/info/refs",
            method="GET",
            version="HTTP/1.1",
            headers=Headers([("Authorization", "Basic not-base64!!")]),
            reader=asyncio.StreamReader(),
            writer=SimpleNamespace(write=lambda _data: None),
        )
        handler = GitHTTPHandler(request, SimpleNamespace(audit_log=False))
        with (
            mock.patch("pygithost.application.REQUIRE_AUTH", True),
            mock.patch("pygithost.application._send_response", AsyncMock()),
        ):
            allowed = await handler._require_auth()
        self.assertFalse(allowed)
        event = self._events("auth_failure")[0]
        self.assertEqual(
            event["attributes"],
            {"surface": "git", "method": "none", "reason": "malformed_credentials"},
        )
        self.assertEqual(
            self._counts("auth.failure.count")[0]["attributes"],
            {"surface": "git", "method": "none"},
        )
        self.assertEqual(self._counts("auth.challenge.count"), [])

    async def test_api_missing_credentials_is_a_challenge_not_a_failure(self) -> None:
        request = SimpleNamespace(headers=Headers([]), request_id="")
        api = API(SimpleNamespace(request=request))
        with self.assertRaises(APIError):
            await api.authenticate()
        self.assertEqual(self._events("auth_failure"), [])
        self.assertEqual(self._counts("auth.challenge.count")[0]["attributes"], {"surface": "api"})
        self.assertEqual(self._counts("auth.failure.count"), [])

    async def test_api_malformed_token_is_an_auth_failure(self) -> None:
        request = SimpleNamespace(headers=Headers([("Authorization", "Bearer")]), request_id="")
        api = API(SimpleNamespace(request=request))
        with self.assertRaises(APIError):
            await api.authenticate()
        event = self._events("auth_failure")[0]
        self.assertEqual(
            event["attributes"],
            {"surface": "api", "method": "none", "reason": "malformed_credentials"},
        )
        self.assertEqual(self._counts("auth.challenge.count"), [])


class FetchTelemetryTests(SentinelTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.temp = tempfile.TemporaryDirectory(prefix="sentinel-fetch-test-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        repo = root / "owner" / "repo.git"
        (repo / "objects").mkdir(parents=True)
        (repo / "refs").mkdir()
        (repo / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        backend = root / "git-backend"
        backend.write_text(
            "#!/bin/sh\nprintf 'Status: 200 OK\\r\\nContent-Type: application/octet-stream\\r\\n\\r\\n'",
            encoding="utf-8",
        )
        backend.chmod(0o755)
        self.old_db_path = database.DB_PATH
        database.DB_PATH = str(root / "fetch.db")
        self.addCleanup(setattr, database, "DB_PATH", self.old_db_path)
        config = AppConfig.from_mapping(
            {
                **AppConfig.default_for_platform().to_dict(),
                "git_project_root": str(root),
                "git_http_backend": str(backend),
                "db_path": database.DB_PATH,
            }
        )
        self.app = AsyncGitServer(AppContext(config), allowlist={"127.0.0.1"})

    def _handler(self, target: str, method: str, *, headers: list[tuple[str, str]] | None = None):
        class Writer:
            def write(self, _data: bytes) -> None:
                pass

            async def drain(self) -> None:
                pass

        reader = asyncio.StreamReader()
        reader.feed_eof()
        request = SimpleNamespace(
            target=target,
            method=method,
            version="HTTP/1.1",
            headers=Headers(headers or [("Content-Length", "0")]),
            reader=reader,
            writer=Writer(),
            peer_ip="127.0.0.1",
        )
        return GitHTTPHandler(request, self.app)

    @unittest.skipUnless(os.name == "posix", "fake backend needs a POSIX shell")
    async def test_fetch_counts_once_after_the_upload_pack_advertisement(self) -> None:
        await self._handler(
            "/git/owner/repo.git/info/refs?service=git-upload-pack", "GET"
        )._handle_git()
        counts = self._counts("git.fetch.count")
        self.assertEqual(len(counts), 1)
        self.assertEqual(counts[0]["attributes"], {"repo": "owner/repo"})

        # The POST that follows the advertisement is part of the same fetch.
        await self._handler("/git/owner/repo.git/git-upload-pack", "POST")._handle_git()
        self.assertEqual(len(self._counts("git.fetch.count")), 1)

        # A missing repository and a token bound to another repository never count.
        await self._handler(
            "/git/owner/missing.git/info/refs?service=git-upload-pack", "GET"
        )._handle_git()
        forbidden = self._handler("/git/owner/repo.git/info/refs?service=git-upload-pack", "GET")
        forbidden.remote_repository = ("other", "repo")
        await forbidden._handle_git()
        self.assertEqual(len(self._counts("git.fetch.count")), 1)

        backend = self._observations("git.backend.duration")
        self.assertEqual(len(backend), 3)
        self.assertEqual({item["attributes"]["service"] for item in backend}, {"upload-pack"})
        self.assertEqual({item["attributes"]["outcome"] for item in backend}, {"success"})

    def _observations(self, name: str) -> list[dict[str, Any]]:
        return [item for item in self.fake.observations if item["name"] == name]


class PushTelemetryTests(SentinelTestCase):
    async def test_push_event_and_counter(self) -> None:
        server = object.__new__(AsyncGitServer)

        class Manager:
            refresh_retention = AsyncMock()

            @staticmethod
            async def enqueue(*_args: Any) -> None:
                return None

        server.ci_manager = Manager()
        server._branch_refs = AsyncMock(return_value={"main": "b" * 40})
        with (
            mock.patch("pygithost.application.db_prs_for_source", return_value=[]),
            mock.patch("pygithost.application.db_prs_for_target", return_value=[]),
        ):
            await server._queue_push_changes("owner", "repo", {"main": "a" * 40})

        event = self._events("git_push")[0]
        self.assertEqual(
            event["attributes"],
            {
                "repo": "owner/repo",
                "refs_updated": 1,
                "outcome": "success",
                "source": "push",
                "branch": "main",
            },
        )
        self.assertEqual(
            self._counts("git.push.count")[0]["attributes"],
            {"repo": "owner/repo", "outcome": "success", "source": "push"},
        )
        self.assert_privacy_safe("alice_secret", "10.9.8.7")

    async def test_pull_request_merge_source_attribute(self) -> None:
        server = object.__new__(AsyncGitServer)

        class Manager:
            refresh_retention = AsyncMock()

            @staticmethod
            async def enqueue(*_args: Any) -> None:
                return None

        server.ci_manager = Manager()
        server._branch_refs = AsyncMock(return_value={"main": "b" * 40})
        with (
            mock.patch("pygithost.application.db_prs_for_source", return_value=[]),
            mock.patch("pygithost.application.db_prs_for_target", return_value=[]),
        ):
            await server._queue_push_changes(
                "owner", "repo", {"main": "a" * 40}, source="pull_request_merge"
            )

        event = self._events("git_push")[0]
        self.assertEqual(event["attributes"]["source"], "pull_request_merge")
        self.assertEqual(
            self._counts("git.push.count")[0]["attributes"],
            {"repo": "owner/repo", "outcome": "success", "source": "pull_request_merge"},
        )


class CITelemetryTests(SentinelTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.temp = tempfile.TemporaryDirectory(prefix="sentinel-ci-test-")
        self.addCleanup(self.temp.cleanup)
        self.old_db_path = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "ci.db")
        self.addCleanup(setattr, database, "DB_PATH", self.old_db_path)
        database._db_init()
        trust = trusted_ci_repositories("owner/repo")
        trust.__enter__()
        self.addCleanup(trust.__exit__, None, None, None)

    async def test_run_lifecycle_events_metrics_and_spans(self) -> None:
        bare = Path(self.temp.name) / "repo.git"
        subprocess.run(
            ["git", "init", "--bare", "-b", "main", str(bare)],
            check=True,
            capture_output=True,
        )
        commit = commit_legacy_config(
            bare, {"command": "true", "events": {}, "timeout_seconds": 30}
        )
        manager = CIManager(lambda *_: str(bare))
        manager.started = True
        run_id = await manager.enqueue("owner", "repo", "manual", "main", commit)
        assert run_id is not None
        row = manager.pending.pop(run_id)
        await manager._run_one(row)
        if manager.notification_tasks:
            await asyncio.gather(*tuple(manager.notification_tasks), return_exceptions=True)

        run = database.db_ci_run_get("owner", "repo", run_id)
        assert run is not None
        self.assertEqual(run[4], "success")

        queued = self._events("ci_run_queued")
        started = self._events("ci_run_started")
        finished = self._events("ci_run_finished")
        self.assertEqual(len(queued), 1)
        self.assertEqual(len(started), 1)
        self.assertEqual(len(finished), 1)
        self.assertEqual(queued[0]["attributes"]["repo"], "owner/repo")
        self.assertEqual(queued[0]["attributes"]["trigger"], "manual")
        self.assertEqual(started[0]["attributes"]["runner"], "local")
        self.assertEqual(finished[0]["attributes"]["status"], "success")
        self.assertEqual(finished[0]["attributes"]["runner"], "local")
        self.assertIsInstance(finished[0]["attributes"]["duration_ms"], float)
        self.assertEqual(started[0]["trace_id"], finished[0]["trace_id"])
        self.assertIsNotNone(started[0]["trace_id"])

        for metric in ("ci.run.duration", "ci.run.queue_wait"):
            observations = [item for item in self.fake.observations if item["name"] == metric]
            self.assertEqual(len(observations), 1)
        self.assertEqual(len(self._counts("ci.run.count")), 1)
        self.assertEqual(
            self._counts("ci.run.count")[0]["attributes"],
            {"repo": "owner/repo", "status": "success"},
        )

        root = next(span for span in self.fake.spans if span["name"] == "ci run")
        self.assertEqual(root["span_id"], finished[0]["span_id"])
        self.assertEqual(root["trace_id"], finished[0]["trace_id"])
        self.assertEqual(root["status"], "ok")
        children = [
            span
            for span in self.fake.spans
            if span["parent_span_id"] == root["span_id"] and span["name"] != "ci run"
        ]
        self.assertTrue(children)
        self.assertIn("checkout", {span["name"] for span in children})
        self.assert_privacy_safe("alice_secret", "10.9.8.7")

    async def test_shutdown_cancellation_is_reported_as_interrupted(self) -> None:
        bare = Path(self.temp.name) / "repo.git"
        subprocess.run(
            ["git", "init", "--bare", "-b", "main", str(bare)],
            check=True,
            capture_output=True,
        )
        commit = commit_legacy_config(
            bare, {"command": "true", "events": {}, "timeout_seconds": 30}
        )
        manager = CIManager(lambda *_: str(bare))
        manager.started = True
        run_id = await manager.enqueue("owner", "repo", "manual", "main", commit)
        assert run_id is not None
        row = manager.pending.pop(run_id)

        with (
            mock.patch.object(manager, "_execute", AsyncMock(side_effect=asyncio.CancelledError)),
            mock.patch.object(manager, "_schedule_notification"),
        ):
            with self.assertRaises(asyncio.CancelledError):
                await manager._run_one(row)

        finished = self._events("ci_run_finished")
        self.assertEqual(finished[-1]["attributes"]["status"], "interrupted")
        self.assertEqual(finished[-1]["level"], "Warning")
        run = database.db_ci_run_get("owner", "repo", run_id)
        assert run is not None
        self.assertEqual(run[4], "interrupted")
        self.assertEqual(self._counts("ci.run.count")[-1]["attributes"]["status"], "interrupted")


class PullRequestTelemetryTests(SentinelTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.temp = tempfile.TemporaryDirectory(prefix="sentinel-pr-test-")
        self.addCleanup(self.temp.cleanup)
        self.old_db_path = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "pr.db")
        self.addCleanup(setattr, database, "DB_PATH", self.old_db_path)
        database._db_init()

    def _context(self) -> pulls.Context:
        server = SimpleNamespace(
            push_locks={},
            ci_manager=SimpleNamespace(enqueue=AsyncMock()),
            _branch_refs=AsyncMock(return_value={"main": "a" * 40}),
            _queue_push_changes=AsyncMock(return_value=None),
        )
        actor = pulls.Actor(
            user_id=None,
            username=None,
            is_admin=True,
            can_write=True,
            known=False,
            viewer="ip:10.9.8.7",
        )
        return pulls.Context(
            server=cast(Any, server),
            owner="owner",
            repo="repo",
            repo_git="",
            actor=actor,
        )

    def _pull(self) -> pulls.PullRequest:
        return {
            "id": 1,
            "owner": "owner",
            "repo": "repo",
            "title": "Feature",
            "body": "",
            "head": "feature",
            "base": "main",
            "author_user_id": None,
            "author": None,
            "state": "open",
            "draft": False,
            "created_at": "",
            "closed_at": None,
            "merged_at": None,
            "merge_method": None,
            "merge_commit": None,
            "head_sha": "b" * 40,
            "base_sha": "a" * 40,
            "merge_base": "a" * 40,
            "head_deleted_sha": None,
        }

    async def test_opened_and_merged_events(self) -> None:
        pr_id = pull_store.create_pull(
            "owner", "repo", "Feature", "", "feature", "main", None, False
        )
        opened = self._events("pull_request_opened")
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0]["attributes"], {"repo": "owner/repo", "pr_number": pr_id})
        self.assertEqual(
            self._counts("pull_request.event.count")[0]["attributes"],
            {"repo": "owner/repo", "action": "opened"},
        )

        ctx = self._context()
        status = {
            "mergeable": "clean",
            "allowed_methods": ["merge"],
            "default_method": "merge",
            "blocked_codes": [],
            "blocked_reasons": [],
        }
        with (
            mock.patch.object(pulls, "load", AsyncMock(return_value=self._pull())),
            mock.patch.object(pulls, "merge_status", AsyncMock(return_value=status)),
            mock.patch.object(pulls, "_commit_subjects", AsyncMock(return_value=["subject"])),
            mock.patch.object(pulls.merging, "merge_pull", return_value="f" * 40),
            mock.patch("pygithost.database.db_pr_mark_merged"),
            mock.patch.object(pulls, "_event"),
        ):
            result = await pulls.merge(ctx, pr_id)
        self.assertTrue(result["merged"])
        ctx.server._queue_push_changes.assert_awaited_once()
        self.assertEqual(
            ctx.server._queue_push_changes.await_args.kwargs["source"], "pull_request_merge"
        )

        merged = self._events("pull_request_merged")
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["attributes"], {"repo": "owner/repo", "pr_number": pr_id})
        self.assertEqual(
            self._counts("pull_request.event.count")[-1]["attributes"],
            {"repo": "owner/repo", "action": "merged"},
        )
        self.assert_privacy_safe("10.9.8.7")

    async def test_mergeability_duration_is_observed(self) -> None:
        ctx = self._context()
        status = {"mergeable": "clean"}
        with mock.patch.object(pulls, "_merge_status", AsyncMock(return_value=status)):
            result = await pulls.merge_status(ctx, self._pull())
        self.assertEqual(result, status)
        observations = [
            item
            for item in self.fake.observations
            if item["name"] == "pull_request.mergeability.duration"
        ]
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["attributes"], {"outcome": "clean"})
        self.assertGreaterEqual(observations[0]["value"], 0)

        ctx = self._context()
        review = {"id": 7, "state": "approved"}
        with (
            mock.patch.object(pulls, "load", AsyncMock(return_value=self._pull())),
            mock.patch.object(pulls.pull_store, "pending_review", return_value=None),
            mock.patch.object(pulls.pull_store, "start_review", return_value=7),
            mock.patch.object(pulls.pull_store, "submit_review", return_value=True),
            mock.patch.object(pulls.pull_store, "get_review", return_value=review),
        ):
            submitted = await pulls.submit_review(ctx, 1, event="APPROVE", body="Looks good")
        self.assertEqual(submitted["state"], "approved")
        event = self._events("pull_request_review")[0]
        self.assertEqual(
            event["attributes"],
            {"repo": "owner/repo", "pr_number": 1, "state": "approved"},
        )
        self.assertEqual(
            self._counts("pull_request.event.count")[-1]["attributes"],
            {"repo": "owner/repo", "action": "review"},
        )


class HealthGaugeTests(unittest.TestCase):
    def test_gauges_are_registered_with_cheap_safe_callbacks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sentinel-gauge-test-") as tmp:
            root = Path(tmp)
            repos = root / "repos"
            repos.mkdir()
            db_path = root / "pygithost.db"
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    "CREATE TABLE sessions (id INTEGER PRIMARY KEY, revoked_at TEXT, "
                    "expires_at TEXT NOT NULL)"
                )
                conn.execute(
                    "INSERT INTO sessions VALUES (1, NULL, datetime('now','localtime','+1 hour'))"
                )
                conn.execute(
                    "INSERT INTO sessions VALUES (2, NULL, datetime('now','localtime','-1 hour'))"
                )
                conn.execute(
                    "CREATE TABLE ci_remote_jobs (run_id INTEGER PRIMARY KEY, heartbeat REAL)"
                )
                conn.execute("INSERT INTO ci_remote_jobs VALUES (1, ?)", (time.time() - 10,))
                conn.commit()
            exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
            fake_app = SimpleNamespace(
                ci_manager=SimpleNamespace(pending={1: None}, active={2: None, 3: None}),
                _active_request_count=lambda: 3,
            )
            config = AppConfig.from_mapping(
                {
                    **AppConfig.default_for_platform().to_dict(),
                    "db_path": str(db_path),
                    "git_project_root": str(repos),
                }
            )
            with (
                mock.patch.object(application, "DB_PATH", str(db_path)),
                mock.patch.object(application, "GIT_PROJECT_ROOT", str(repos)),
            ):
                application._register_health_gauges(fake_app, exporter, config)
                gauges = {
                    name: (unit, callback) for name, (unit, callback) in exporter._gauges.items()
                }

                self.assertEqual(gauges["ci.runs.queued"], ("{run}", mock.ANY))
                self.assertEqual(gauges["ci.runs.queued"][1](), 1)
                self.assertEqual(gauges["ci.runs.active"][1](), 2)
                self.assertEqual(gauges["http.server.active_requests"][1](), 3)
                self.assertEqual(gauges["db.size"][0], "By")
                self.assertEqual(gauges["db.size"][1](), db_path.stat().st_size)
                self.assertEqual(gauges["disk.repositories.free"][0], "By")
                self.assertGreater(gauges["disk.repositories.free"][1](), 0)
                self.assertGreater(gauges["disk.database.free"][1](), 0)
                self.assertEqual(gauges["repositories.count"][1](), 0)
                self.assertEqual(gauges["sessions.active"][1](), 1)
                age = gauges["ci.remote_runner.last_seen_age"][1]()
                assert isinstance(age, float)
                self.assertGreaterEqual(age, 5)
                self.assertLess(age, 120)

    def test_gauge_callbacks_survive_a_missing_database(self) -> None:
        with mock.patch.object(application, "DB_PATH", "/nonexistent/pygithost.db"):
            self.assertIsNone(application._active_session_count())
            self.assertIsNone(application._remote_runner_last_seen_age())
            self.assertIsNone(application._database_size_bytes())

    def test_cached_gauge_recomputes_only_after_the_interval(self) -> None:
        calls: list[int] = []

        def measure() -> int:
            calls.append(1)
            return 7

        gauge = application._CachedGauge(measure)
        self.assertEqual(gauge(), 7)
        self.assertEqual(gauge(), 7)
        self.assertEqual(len(calls), 1)

        broken = application._CachedGauge(lambda: 1 / 0)
        self.assertIsNone(broken())


if __name__ == "__main__":
    unittest.main()
