import json
from pathlib import Path
import tempfile
import unittest

from pygithost import database
from pygithost.ci import default_config, pipeline_config, validate_config


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "test.db")
        database._db_init()

    def tearDown(self):
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def config(self, **values):
        config = validate_config({**default_config(), **values})
        database.db_ci_config_set("owner", "repo", json.dumps(config))

    def create_run(self, artifacts=True, repo="repo"):
        run_id = database.db_ci_run_create("owner", repo, "push", "main", "a" * 40, "{}")
        if artifacts:
            database.db_ci_artifact_set(run_id, b"archive")
        database.db_ci_run_update(run_id, status="success")
        return run_id

    def age_artifact(self, run_id):
        conn = database._db_connect()
        try:
            conn.execute("UPDATE ci_artifacts SET created_at=datetime('now','-30 days') WHERE run_id=?", (run_id,))
        finally:
            conn.close()

    def test_unlimited_artifacts_and_runs_survive_age_and_restart(self):
        self.config(artifact_retention_days=0, artifact_retention_count=0, run_retention_count=0)
        ids = [self.create_run() for _ in range(4)]
        for run_id in ids:
            self.age_artifact(run_id)
        database._db_init()
        self.assertEqual(len(database.db_ci_runs_list("owner", "repo")), 4)
        self.assertEqual(len(database.db_ci_artifacts_list("owner", "repo")), 4)
        self.assertTrue(all(row[7] is None for row in database.db_ci_artifacts_list("owner", "repo")))

    def test_count_deletes_oldest_bundles_and_preserves_parent_runs(self):
        self.config(artifact_retention_days=0, artifact_retention_count=0, run_retention_count=0)
        ids = [self.create_run() for _ in range(4)]
        newest = self.create_run(artifacts=False)
        self.config(artifact_retention_days=0, artifact_retention_count=2, run_retention_count=1)
        self.assertEqual([row[0] for row in database.db_ci_artifacts_list("owner", "repo")], ids[-2:][::-1])
        self.assertEqual({row[0] for row in database.db_ci_runs_list("owner", "repo")}, {*ids[-2:], newest})

    def test_expiry_is_per_repository_and_policy_applies_immediately(self):
        self.config(artifact_retention_days=0, run_retention_count=0)
        run_id = self.create_run()
        other = self.create_run(repo="other")
        self.age_artifact(run_id)
        self.assertEqual(database.db_ci_artifact_get("owner", "repo", run_id), 7)
        self.config(artifact_retention_days=1, run_retention_count=0)
        self.assertIsNone(database.db_ci_artifact_get("owner", "repo", run_id))
        self.assertEqual(database.db_ci_artifact_get("owner", "other", other), 7)

    def test_run_limit_zero_and_pending_runs(self):
        self.config(run_retention_count=0)
        ids = [self.create_run(artifacts=False) for _ in range(5)]
        pending = database.db_ci_run_create("owner", "repo", "push", "main", "b" * 40, "{}")
        self.config(run_retention_count=2)
        self.assertEqual({row[0] for row in database.db_ci_runs_list("owner", "repo")}, {pending, *ids[-2:]})

    def test_validation_and_repository_file_cannot_override_retention(self):
        for key in ("artifact_retention_days", "artifact_retention_count", "run_retention_count"):
            self.assertEqual(validate_config({key: "0"})[key], 0)
            for value in (-1, True, "never", 1.5):
                with self.assertRaises(ValueError):
                    validate_config({key: value})
            with self.assertRaises(ValueError):
                pipeline_config({"version": 1, "command": "true", key: 0}, default_config())

    def test_database_pagination(self):
        self.config(run_retention_count=0)
        ids = [self.create_run(artifacts=False) for _ in range(6)]
        first = database.db_ci_runs_list("owner", "repo", 3, summary=True)
        second = database.db_ci_runs_list("owner", "repo", 3, summary=True, offset=3)
        self.assertEqual([row[0] for row in first + second], ids[::-1])
        self.assertEqual(database.db_ci_runs_count("owner", "repo", status="success"), 6)
        self.assertEqual(database.db_ci_runs_count("owner", "repo", query="a" * 40), 6)
        self.assertEqual(database.db_ci_runs_count("owner", "repo", query="%"), 0)
        self.assertEqual(database.db_ci_runs_count("owner", "repo", before=ids[2]), 2)

    def test_warning_filters_and_counts_are_independent_of_result(self):
        self.config(run_retention_count=0)
        warning = self.create_run(artifacts=False)
        clean = self.create_run(artifacts=False)
        database.db_ci_run_update(warning, warnings="Temporary directory cleanup failed: locked")
        database.db_ci_run_update(warning, reason="Deployment skipped: manual run")
        self.assertEqual(database.db_ci_runs_count("owner", "repo", status="success", warnings="yes"), 1)
        self.assertEqual(database.db_ci_runs_count("owner", "repo", warnings="no"), 1)
        rows = database.db_ci_runs_list("owner", "repo", warnings="yes", summary=True, include_warnings=True)
        self.assertEqual([row[0] for row in rows], [warning])
        self.assertIn("locked", rows[0][11])
        self.assertEqual([row[0] for row in database.db_ci_runs_list("owner", "repo", warnings="no")], [clean])
        self.assertIn("locked", database.db_ci_run_metadata("owner", "repo", warning)["warnings"])

    def test_existing_cleanup_reasons_migrate_to_warning_field(self):
        run_id = self.create_run(artifacts=False)
        database.db_ci_run_update(run_id, reason="Temporary directory cleanup failed: old warning")
        conn = database._db_connect()
        try:
            conn.execute("DROP INDEX IF EXISTS idx_ci_runs_warnings")
            conn.execute("ALTER TABLE ci_runs DROP COLUMN warnings")
        finally:
            conn.close()
        database._db_init()
        self.assertIn("old warning", database.db_ci_run_metadata("owner", "repo", run_id)["warnings"])
