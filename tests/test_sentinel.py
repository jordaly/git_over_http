import json
import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from pygithost.sentinel import SentinelExporter


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
