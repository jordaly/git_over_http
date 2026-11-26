import json
import os
import queue
import sqlite3
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from pygithost.sentinel import (
    _HISTOGRAM_BOUNDS,
    SentinelExporter,
    _ensure_spool_schema,
)


def _database() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    _ensure_spool_schema(db)
    return db


def _success(count: int) -> dict[str, object]:
    return {"accepted": count, "duplicates": 0, "rejected": 0, "errors": []}


def _pending(exporter: SentinelExporter) -> list[tuple[int, str, str]]:
    items: list[tuple[int, str, str]] = []
    while True:
        try:
            items.append(exporter._pending.get_nowait())
        except queue.Empty:
            return items


class SentinelDeliveryTests(unittest.TestCase):
    def test_partial_acknowledgement_retains_configuration_rejection(self) -> None:
        exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
        with closing(sqlite3.connect(":memory:")) as db:
            db.executescript(
                """
                CREATE TABLE events (id INTEGER PRIMARY KEY, body TEXT);
                CREATE TABLE dead_letters (id INTEGER PRIMARY KEY, reason TEXT, body TEXT);
                """
            )
            rows = [(i, json.dumps({"event_id": str(i)})) for i in range(1, 5)]
            db.executemany("INSERT INTO events VALUES (?, ?)", rows)
            reply = {
                "accepted": 1,
                "duplicates": 1,
                "rejected": 2,
                "errors": [
                    {"index": 1, "code": "unknown_application"},
                    {"index": 2, "code": "invalid_timestamp"},
                ],
            }
            with patch.object(exporter, "_post", return_value=(200, 0, reply)):
                delay, split = exporter._send_batch(db, "installation-id", rows)

            self.assertGreater(delay or 0, 0)
            self.assertFalse(split)
            self.assertEqual(db.execute("SELECT * FROM events").fetchall(), [rows[1]])
            self.assertEqual(
                db.execute("SELECT reason, body FROM dead_letters").fetchall(),
                [("invalid_timestamp", rows[2][1])],
            )

    def test_incomplete_acknowledgement_keeps_original_batch(self) -> None:
        exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
        rows = [(1, '{"event_id":"original"}')]
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, body TEXT)")
            db.executemany("INSERT INTO events VALUES (?, ?)", rows)
            reply = {"accepted": 0, "duplicates": 0, "rejected": 0, "errors": []}
            with patch.object(exporter, "_post", return_value=(200, 0, reply)):
                delay, split = exporter._send_batch(db, "installation-id", rows)

            self.assertIsNotNone(delay)
            self.assertFalse(split)
            self.assertEqual(db.execute("SELECT * FROM events").fetchall(), rows)

    def test_each_kind_uses_its_own_endpoint_and_envelope_key(self) -> None:
        exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
        expected = {
            "log": ("/api/v1/logs/batch", "events"),
            "metric": ("/api/v1/metrics/batch", "metrics"),
            "span": ("/api/v1/traces/batch", "spans"),
        }
        for kind, (endpoint, key) in expected.items():
            with self.subTest(kind=kind):
                with closing(_database()) as db:
                    body = json.dumps({"event_id": str(1)})
                    db.execute(
                        "INSERT INTO events(priority, body, kind) VALUES (0, ?, ?)",
                        (body, kind),
                    )
                    rows = db.execute("SELECT id, body FROM events").fetchall()
                    with patch.object(
                        exporter, "_post", return_value=(200, 0, _success(1))
                    ) as post:
                        delay, split = exporter._send_batch(db, "client", rows, kind)

                    self.assertIsNone(delay)
                    self.assertFalse(split)
                    self.assertEqual(post.call_args.args[0], endpoint)
                    payload = post.call_args.args[1]
                    self.assertEqual(payload["schema_version"], 1)
                    self.assertEqual(list(payload[key]), [json.loads(body)])
                    for other_kind, (_, other_key) in expected.items():
                        if other_kind != kind:
                            self.assertNotIn(other_key, payload)

    def test_old_spool_events_table_gains_a_kind_column(self) -> None:
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute(
                "CREATE TABLE events ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, priority INTEGER NOT NULL, body TEXT NOT NULL)"
            )
            db.execute("INSERT INTO events(priority, body) VALUES (0, '{}')")
            _ensure_spool_schema(db)

            columns = {row[1] for row in db.execute("PRAGMA table_info(events)")}
            self.assertIn("kind", columns)
            self.assertEqual(db.execute("SELECT kind FROM events").fetchone(), ("log",))
            _ensure_spool_schema(db)  # idempotent


class SentinelMetricsTests(unittest.TestCase):
    def test_counter_aggregation_and_histogram_buckets(self) -> None:
        exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
        exporter.count("test.events", 2, {"route_group": "api"})
        exporter.count("test.events", 3, {"route_group": "api"})
        exporter.count("test.events", 1, {"route_group": "git"})
        exporter.observe("test.duration", 7, {"route_group": "api"})
        exporter.observe("test.duration", 60, {"route_group": "api"})
        exporter.observe("test.duration", 100_000, {"route_group": "api"})

        with closing(_database()) as db:
            exporter._flush_metrics(db)
            rows = db.execute("SELECT kind, body FROM events").fetchall()

        self.assertTrue(all(kind == "metric" for kind, _ in rows))
        metrics = [json.loads(body) for _, body in rows]
        counters = {
            json.dumps(item["attributes"], sort_keys=True): item
            for item in metrics
            if item["name"] == "test.events"
        }
        self.assertEqual(counters['{"route_group": "api"}']["value"], 5)
        self.assertEqual(counters['{"route_group": "git"}']["value"], 1)
        self.assertEqual(counters['{"route_group": "api"}']["unit"], "{event}")
        self.assertEqual(counters['{"route_group": "api"}']["temporality"], "delta")

        histogram = next(item for item in metrics if item["name"] == "test.duration")
        expected = [0] * (len(_HISTOGRAM_BOUNDS) + 1)
        expected[1] = 1  # 7 ms -> first bound >= 7 is 10
        expected[4] = 1  # 60 ms -> first bound >= 60 is 100
        expected[-1] = 1  # above the highest bound
        self.assertEqual(histogram["bounds"], list(_HISTOGRAM_BOUNDS))
        self.assertEqual(histogram["bucket_counts"], expected)
        self.assertEqual(histogram["count"], 3)
        self.assertEqual(histogram["sum"], 100_067)
        self.assertEqual(histogram["min"], 7)
        self.assertEqual(histogram["max"], 100_000)
        self.assertEqual(histogram["unit"], "ms")
        self.assertEqual(histogram["temporality"], "delta")

        gauge_names = {item["name"] for item in metrics}
        self.assertIn("sentinel.spool.pending", gauge_names)

    def test_counter_series_are_flushed_and_reset(self) -> None:
        exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
        exporter.count("test.events", 4, None)
        with closing(_database()) as db:
            exporter._flush_metrics(db)
            self.assertEqual(exporter._counters, {})
            exporter._flush_metrics(db)
            bodies = [
                json.loads(row[0]) for row in db.execute("SELECT body FROM events").fetchall()
            ]
        values = [item["value"] for item in bodies if item["name"] == "test.events"]
        self.assertEqual(values, [4])

    def test_invalid_metric_names_are_dropped(self) -> None:
        exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
        with self.assertLogs("pygithost.sentinel", level="DEBUG") as captured:
            exporter.count("1invalid", 1, None)
            exporter.observe("also invalid", 1, None)
            exporter.register_gauge("3gauge", "1", lambda: 1)
        self.assertEqual(exporter._counters, {})
        self.assertEqual(exporter._histograms, {})
        self.assertEqual(exporter._gauges, {})
        self.assertTrue(any("invalid" in line.lower() for line in captured.output))

    def test_metric_attributes_are_bounded_and_flat(self) -> None:
        exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
        attributes: dict[str, object] = {f"key{index}": index for index in range(10)}
        attributes["text"] = "x" * 400
        attributes["nested"] = {"not": "allowed"}
        exporter.count("test.events", 1, attributes)

        (((name, attrs), value),) = exporter._counters.items()
        self.assertEqual(name, "test.events")
        self.assertEqual(value, 1)
        self.assertLessEqual(len(attrs), 16)
        self.assertEqual(dict(attrs)["text"], "x" * 256)
        self.assertNotIn("nested", dict(attrs))

    def test_registered_gauges_and_callback_failures(self) -> None:
        exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
        exporter.register_gauge("test.queue.depth", "{event}", lambda: 7)
        exporter.register_gauge("test.broken", "1", lambda: (_ for _ in ()).throw(RuntimeError()))

        with closing(_database()) as db:
            exporter._flush_metrics(db)
            metrics = [
                json.loads(row[0]) for row in db.execute("SELECT body FROM events").fetchall()
            ]

        queue_depth = next(item for item in metrics if item["name"] == "test.queue.depth")
        self.assertEqual(queue_depth["value"], 7)
        self.assertEqual(queue_depth["unit"], "{event}")
        self.assertNotIn("test.broken", {item["name"] for item in metrics})

    def test_metrics_can_be_disabled(self) -> None:
        exporter = SentinelExporter(
            "http://127.0.0.1",
            "unused",
            "test",
            Path(":memory:"),
            metrics_enabled=False,
            trace_sample_rate=0,
        )
        exporter.count("test.events", 1, None)
        exporter.observe("test.duration", 10, None)
        exporter.record_request("GET", "git", 200, 10)
        self.assertEqual(exporter._counters, {})
        self.assertEqual(exporter._histograms, {})
        self.assertEqual(_pending(exporter), [])


class SentinelSpanTests(unittest.TestCase):
    NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)

    def _valid_kwargs(self) -> dict[str, object]:
        return {
            "trace_id": "0af7651916cd43dd8448eb211c80319c",
            "span_id": "b7ad6b7169203331",
            "parent_span_id": "00f067aa0ba902b7",
            "kind": "server",
            "status": "ok",
            "status_message": None,
            "attributes": {"route_group": "api"},
        }

    def _record(self, exporter: SentinelExporter, **overrides: object) -> None:
        kwargs = self._valid_kwargs()
        kwargs.update(overrides)
        exporter.span(
            "GET api",
            self.NOW,
            self.NOW + timedelta(milliseconds=25),
            **kwargs,  # type: ignore[arg-type]
        )

    def test_valid_span_is_enqueued(self) -> None:
        exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
        self._record(exporter)
        priority, body, kind = exporter._pending.get_nowait()
        self.assertEqual((priority, kind), (0, "span"))
        span = json.loads(body)
        self.assertEqual(span["trace_id"], "0af7651916cd43dd8448eb211c80319c")
        self.assertEqual(span["span_id"], "b7ad6b7169203331")
        self.assertEqual(span["parent_span_id"], "00f067aa0ba902b7")
        self.assertEqual(span["kind"], "server")
        self.assertEqual(span["status"], "ok")
        self.assertEqual(span["start_time"], "2026-11-26T12:00:00+00:00")
        self.assertEqual(span["end_time"], "2026-11-26T12:00:00.025000+00:00")
        self.assertEqual(span["attributes"], {"route_group": "api"})

    def test_error_span_is_high_priority(self) -> None:
        exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
        self._record(exporter, status="error", status_message="Request failed")
        priority, _, _ = exporter._pending.get_nowait()
        self.assertEqual(priority, 1)

    def test_invalid_spans_are_dropped(self) -> None:
        invalid = [
            {"trace_id": "0" * 32},
            {"trace_id": "xyz"},
            {"span_id": "0" * 16},
            {"parent_span_id": "b7ad6b7169203331"},
            {"kind": "database"},
            {"status": "failed"},
        ]
        for overrides in invalid:
            with self.subTest(overrides=overrides):
                exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
                self._record(exporter, **overrides)
                self.assertEqual(_pending(exporter), [])

    def test_end_before_start_and_naive_times_are_dropped(self) -> None:
        exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
        kwargs = self._valid_kwargs()
        exporter.span("GET api", self.NOW + timedelta(seconds=1), self.NOW, **kwargs)  # type: ignore[arg-type]
        exporter.span(
            "GET api",
            datetime(2026, 11, 26, 12, 0),
            datetime(2026, 11, 26, 12, 0, 1),
            **kwargs,  # type: ignore[arg-type]
        )
        self.assertEqual(_pending(exporter), [])


class SentinelRequestTests(unittest.TestCase):
    def test_default_errors_mode_sends_no_log_for_success(self) -> None:
        exporter = SentinelExporter(
            "http://127.0.0.1", "unused", "test", Path(":memory:"), trace_sample_rate=0
        )
        exporter.record_request("GET", "git", 200, 10)
        self.assertEqual(_pending(exporter), [])
        self.assertEqual(len(exporter._counters), 1)
        self.assertEqual(len(exporter._histograms), 1)

    def test_error_request_always_traces_and_logs(self) -> None:
        exporter = SentinelExporter(
            "http://127.0.0.1", "unused", "test", Path(":memory:"), trace_sample_rate=0
        )
        exporter.record_request(
            "POST", "api", 500, 30, error_type="ValueError", request_id="request-1"
        )
        items = _pending(exporter)
        spans = [json.loads(body) for priority, body, kind in items if kind == "span"]
        logs = [json.loads(body) for priority, body, kind in items if kind == "log"]
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0]["name"], "POST api")
        self.assertEqual(spans[0]["status"], "error")
        self.assertEqual(spans[0]["kind"], "server")
        self.assertEqual(spans[0]["attributes"]["route_group"], "api")
        self.assertEqual(spans[0]["attributes"]["http.response.status_code"], 500)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["event_name"], "request_failure")
        self.assertEqual(logs[0]["level"], "Error")
        self.assertEqual(logs[0]["correlation_id"], "request-1")
        self.assertEqual(logs[0]["trace_id"], spans[0]["trace_id"])
        self.assertEqual(logs[0]["span_id"], spans[0]["span_id"])
        self.assertEqual(logs[0]["attributes"]["error_type"], "ValueError")

    def test_slow_request_traces_and_warns(self) -> None:
        exporter = SentinelExporter(
            "http://127.0.0.1",
            "unused",
            "test",
            Path(":memory:"),
            trace_sample_rate=0,
            slow_request_ms=100,
        )
        exporter.record_request("GET", "web", 200, 150)
        items = _pending(exporter)
        spans = [json.loads(body) for _, body, kind in items if kind == "span"]
        logs = [json.loads(body) for _, body, kind in items if kind == "log"]
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0]["status"], "ok")
        self.assertEqual([log["event_name"] for log in logs], ["slow_request"])
        self.assertEqual(logs[0]["level"], "Warning")
        self.assertEqual(logs[0]["attributes"]["duration_ms"], 150)

    def test_sampling_rate_one_traces_every_request(self) -> None:
        exporter = SentinelExporter(
            "http://127.0.0.1", "unused", "test", Path(":memory:"), trace_sample_rate=1
        )
        exporter.record_request("GET", "static", 200, 5)
        spans = [json.loads(body) for _, body, kind in _pending(exporter) if kind == "span"]
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0]["name"], "GET static")

    def test_sampling_rate_zero_uses_no_random_trace(self) -> None:
        exporter = SentinelExporter(
            "http://127.0.0.1", "unused", "test", Path(":memory:"), trace_sample_rate=0
        )
        with patch("pygithost.sentinel.random.random", return_value=0.0) as sample:
            exporter.record_request("GET", "static", 200, 5)
        sample.assert_not_called()
        self.assertEqual(_pending(exporter), [])

    def test_request_log_mode_all(self) -> None:
        exporter = SentinelExporter(
            "http://127.0.0.1",
            "unused",
            "test",
            Path(":memory:"),
            request_logs="all",
            trace_sample_rate=0,
        )
        exporter.record_request("GET", "web", 200, 5)
        logs = [json.loads(body) for _, body, kind in _pending(exporter) if kind == "log"]
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["event_name"], "http_request")
        self.assertEqual(logs[0]["level"], "Information")

    def test_request_log_mode_off_suppresses_all_request_logs(self) -> None:
        exporter = SentinelExporter(
            "http://127.0.0.1",
            "unused",
            "test",
            Path(":memory:"),
            request_logs="off",
            trace_sample_rate=0,
            slow_request_ms=100,
        )
        exporter.record_request("POST", "api", 500, 500, error_type="ValueError")
        items = _pending(exporter)
        self.assertEqual([kind for _, _, kind in items], ["span"])
        self.assertEqual(len(exporter._counters), 1)

    def test_request_metrics_use_route_group_and_status_class(self) -> None:
        exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
        exporter.record_request("GET", "git", 204, 12)
        (((name, attrs), value),) = exporter._counters.items()
        self.assertEqual(name, "http.server.request.count")
        self.assertEqual(value, 1)
        self.assertEqual(dict(attrs), {"route_group": "git", "status_class": "2xx"})
        (((hist_name, hist_attrs), state),) = exporter._histograms.items()
        self.assertEqual(hist_name, "http.server.request.duration")
        self.assertEqual(dict(hist_attrs), {"route_group": "git", "status_class": "2xx"})
        self.assertEqual(state.count, 1)


class SentinelHeartbeatTests(unittest.TestCase):
    def test_heartbeat_carries_resource_and_optional_attributes(self) -> None:
        exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
        payload = exporter._heartbeat_payload("client-1", 12, 7, 3)

        self.assertEqual(payload["application"], "PyGitHost")
        self.assertEqual(payload["client_id"], "client-1")
        self.assertEqual(payload["environment"], "test")
        self.assertEqual(payload["session_id"], exporter.session_id)
        self.assertEqual(payload["uptime_seconds"], 12)
        self.assertEqual(payload["process_id"], os.getpid())
        self.assertIn("operating_system", payload)
        self.assertEqual(payload["operating_system"], payload["operating_system"].lower())
        self.assertEqual(payload["attributes"]["spool_pending"], 7)
        self.assertEqual(payload["attributes"]["dropped_events"], 3)

    def test_heartbeat_only_uses_documented_fields(self) -> None:
        exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
        payload = exporter._heartbeat_payload("client-1", 0, 0, 0)
        allowed = {
            "client_id",
            "application",
            "application_version",
            "environment",
            "machine",
            "machine_id",
            "operating_system",
            "process_id",
            "session_id",
            "timestamp",
            "uptime_seconds",
            "attributes",
        }
        self.assertLessEqual(set(payload), allowed)


class SentinelConfigurationTests(unittest.TestCase):
    def test_application_name_comes_from_environment(self) -> None:
        env = {
            "PYGITHOST_SENTINEL_URL": "https://sentinel.example",
            "PYGITHOST_SENTINEL_KEY": "fs_key",
        }
        with patch.dict("os.environ", env, clear=True):
            default = SentinelExporter.from_environment("/tmp/pygithost.db")
        with patch.dict(
            "os.environ", {**env, "PYGITHOST_SENTINEL_APPLICATION": "GitHost"}, clear=True
        ):
            custom = SentinelExporter.from_environment("/tmp/pygithost.db")

        assert default is not None and custom is not None
        self.assertEqual(default.application, "PyGitHost")
        self.assertEqual(custom.application, "GitHost")
        self.assertNotEqual(default.spool, custom.spool)
        self.assertEqual(custom._resource("client")["service.name"], "GitHost")
        custom.emit("server_start", "Information")
        _, body, kind = custom._pending.get_nowait()
        self.assertEqual(kind, "log")
        event = json.loads(body)
        self.assertEqual(event["event_name"], "server_start")
        self.assertNotIn("application", event)

    def test_volume_control_settings_are_parsed_and_validated(self) -> None:
        env = {
            "PYGITHOST_SENTINEL_URL": "https://sentinel.example",
            "PYGITHOST_SENTINEL_KEY": "fs_key",
            "PYGITHOST_SENTINEL_REQUEST_LOGS": "all",
            "PYGITHOST_SENTINEL_TRACE_SAMPLE_RATE": "0.5",
            "PYGITHOST_SENTINEL_SLOW_REQUEST_MS": "250",
            "PYGITHOST_SENTINEL_METRICS": "off",
        }
        with patch.dict("os.environ", env, clear=True):
            exporter = SentinelExporter.from_environment("/tmp/pygithost.db")

        assert exporter is not None
        self.assertEqual(exporter.request_logs, "all")
        self.assertEqual(exporter.trace_sample_rate, 0.5)
        self.assertEqual(exporter.slow_request_ms, 250)
        self.assertFalse(exporter.metrics_enabled)

    def test_invalid_volume_control_settings_fall_back(self) -> None:
        env = {
            "PYGITHOST_SENTINEL_URL": "https://sentinel.example",
            "PYGITHOST_SENTINEL_KEY": "fs_key",
            "PYGITHOST_SENTINEL_REQUEST_LOGS": "sometimes",
            "PYGITHOST_SENTINEL_TRACE_SAMPLE_RATE": "2",
            "PYGITHOST_SENTINEL_SLOW_REQUEST_MS": "-1",
            "PYGITHOST_SENTINEL_METRICS": "maybe",
        }
        with patch.dict("os.environ", env, clear=True):
            with self.assertLogs("pygithost.sentinel", level="WARNING"):
                exporter = SentinelExporter.from_environment("/tmp/pygithost.db")

        assert exporter is not None
        self.assertEqual(exporter.request_logs, "errors")
        self.assertEqual(exporter.trace_sample_rate, 0.01)
        self.assertEqual(exporter.slow_request_ms, 2000)
        self.assertTrue(exporter.metrics_enabled)

    def test_resource_contains_documented_fields(self) -> None:
        exporter = SentinelExporter("http://127.0.0.1", "unused", "test", Path(":memory:"))
        resource = exporter._resource("client-1")
        self.assertEqual(resource["service.name"], "PyGitHost")
        self.assertEqual(resource["client.id"], "client-1")
        self.assertEqual(resource["deployment.environment.name"], "test")
        self.assertEqual(resource["session.id"], exporter.session_id)
        self.assertIsInstance(resource["process.pid"], int)
        self.assertEqual(resource["os.type"], resource["os.type"].lower())


if __name__ == "__main__":
    unittest.main()
