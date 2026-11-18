"""Regression tests for the typed SQLite database boundary."""

import json
import tempfile
import unittest
from pathlib import Path

from pygithost import database
from pygithost.database_types import decode_json_object


class DatabaseTypingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "test.db")
        database._db_init()

    def tearDown(self):
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def test_preferences_reject_partial_repository_identity(self):
        with self.assertRaisesRegex(ValueError, "owner and repo"):
            database.db_ci_preferences_set({}, owner="owner")
        with self.assertRaisesRegex(ValueError, "owner and repo"):
            database.db_ci_preferences_set({}, repo="repo")

        # Global preferences and complete repository identities remain valid.
        database.db_ci_preferences_set({})
        database.db_ci_preferences_set({}, "owner", "repo")

    def test_decode_json_object_requires_object_root(self):
        self.assertEqual(decode_json_object('{"key": "value"}'), {"key": "value"})
        for raw in ("[]", "null", '"text"', "1"):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, "JSON object"):
                    decode_json_object(raw)
        with self.assertRaises(json.JSONDecodeError):
            decode_json_object("{")

    def test_json_object_guard_is_used_for_persisted_configuration(self):
        with self.assertRaisesRegex(ValueError, "JSON object"):
            database.db_deployment_claim(1, "owner", "repo", "a" * 40, "[]")

        conn = database._db_connect()
        try:
            conn.execute(
                "INSERT INTO ci_retention_policy(owner,repo,policy_json,commit_hash) "
                "VALUES ('owner', 'repo', '[]', '')"
            )
            with self.assertRaisesRegex(ValueError, "JSON object"):
                database._db_ci_retention(conn, "owner", "repo")
        finally:
            conn.close()

    def test_connection_execute_accepts_keyword_parameters(self):
        conn = database._db_connect()
        try:
            row = conn.execute(sql="SELECT ?", parameters=("value",)).fetchone()
            self.assertEqual(row, ("value",))
        finally:
            conn.close()

    def test_ci_run_list_projection_shapes_are_preserved(self):
        run_id = database.db_ci_run_create(
            "owner", "repo", "push", "main", "a" * 40, '{"pipeline_id": "lint"}'
        )
        database.db_ci_run_update(
            run_id, status="success", output="full output", warnings="warning text"
        )

        base = database.db_ci_runs_list("owner", "repo")[0]
        warnings = database.db_ci_runs_list("owner", "repo", include_warnings=True)[0]
        pipeline = database.db_ci_runs_list("owner", "repo", include_pipeline=True)[0]
        both = database.db_ci_runs_list(
            "owner", "repo", include_warnings=True, include_pipeline=True
        )[0]
        summary = database.db_ci_runs_list(
            "owner",
            "repo",
            summary=True,
            include_warnings=True,
            include_pipeline=True,
        )[0]

        self.assertEqual(len(base), 11)
        self.assertEqual(base[5], "full output")
        self.assertEqual(len(warnings), 12)
        self.assertEqual(warnings[11], "warning text")
        self.assertEqual(len(pipeline), 12)
        self.assertEqual(pipeline[11], "lint")
        self.assertEqual(len(both), 13)
        self.assertEqual(both[11], "warning text")
        self.assertEqual(both[12], "lint")
        self.assertEqual(len(summary), 13)
        self.assertEqual(summary[5], "")
        self.assertEqual(summary[11], "warning text")
        self.assertEqual(summary[12], "lint")


if __name__ == "__main__":
    unittest.main()
