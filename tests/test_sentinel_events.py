"""Telemetry call-site tests: every event, metric and span stays privacy-safe."""

import asyncio
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest import mock
from unittest.mock import AsyncMock

from pygithost import database, pull_store, pulls, sentinel
from pygithost.application import AsyncGitServer, GitHTTPHandler, Headers
from pygithost.ci import CIManager
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

    async def test_git_authentication_failure_uses_fixed_reason(self) -> None:
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
        event = self._events("auth_failure")[0]
        self.assertEqual(event["level"], "Warning")
        self.assertEqual(
            event["attributes"],
            {"surface": "git", "method": "none", "reason": "missing_credentials"},
        )
        self.assertEqual(
            self._counts("auth.failure.count")[0]["attributes"],
            {"surface": "git", "method": "none"},
        )
        self.assert_privacy_safe("10.9.8.7", "owner/repo")


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
                "branch": "main",
            },
        )
        self.assertEqual(
            self._counts("git.push.count")[0]["attributes"],
            {"repo": "owner/repo", "outcome": "success"},
        )
        self.assert_privacy_safe("alice_secret", "10.9.8.7")


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

        merged = self._events("pull_request_merged")
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["attributes"], {"repo": "owner/repo", "pr_number": pr_id})
        self.assertEqual(
            self._counts("pull_request.event.count")[-1]["attributes"],
            {"repo": "owner/repo", "action": "merged"},
        )
        self.assert_privacy_safe("10.9.8.7")

    async def test_review_event(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
