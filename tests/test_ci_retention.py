import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pygithost import database
from pygithost.ci import default_config, pipeline_config, validate_config

RETENTION_KEYS = ("artifact_retention_days", "artifact_retention_count", "run_retention_count")
FINISHED = {"success", "failed", "timed_out", "interrupted", "cancelled"}


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = database.DB_PATH
        self.old_resolver = database._retention_head_resolver
        database.DB_PATH = str(Path(self.temp.name) / "test.db")
        self.head = "a" * 40
        database.configure_retention_head_resolver(lambda _owner, _repo: self.head)
        database._db_init()
        self.current_config = self.retention_config()

    def tearDown(self):
        database.DB_PATH = self.old_db
        database.configure_retention_head_resolver(self.old_resolver)
        self.temp.cleanup()

    def retention_config(self, **values):
        """Build a historical snapshot; it must not control cleanup."""
        config = validate_config({**default_config(), **values})
        config["_repository_retention"] = {
            key: config[key] for key in RETENTION_KEYS if key in values
        }
        return json.dumps(config)

    def config(self, **values):
        """Update the cached default-branch policy and exercise cleanup."""
        self.current_config = self.retention_config(**values)
        database.db_ci_retention_policy_set("owner", "repo", values, commit=self.head)
        conn = database._db_connect()
        try:
            row = conn.execute(
                """SELECT id,status FROM ci_runs
                   WHERE owner='owner' AND repo='repo' AND config_json<>''
                   ORDER BY id DESC LIMIT 1"""
            ).fetchone()
            if row is None:
                return
        finally:
            conn.close()
        # Completion is when retention is enforced in production.
        if row[1] in FINISHED:
            database.db_ci_run_update(row[0], status=row[1])

    def create_run(self, artifacts=True, repo="repo", config_json=None):
        run_id = database.db_ci_run_create(
            "owner",
            repo,
            "push",
            "main",
            "a" * 40,
            "{}",
            config_json if config_json is not None else self.current_config,
        )
        if artifacts:
            database.db_ci_artifact_set(run_id, b"archive")
        database.db_ci_run_update(run_id, status="success")
        return run_id

    def age_artifact(self, run_id):
        conn = database._db_connect()
        try:
            conn.execute(
                "UPDATE ci_artifacts SET created_at=datetime('now','-30 days') WHERE run_id=?",
                (run_id,),
            )
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
        self.assertTrue(
            all(row[7] is None for row in database.db_ci_artifacts_list("owner", "repo"))
        )

    def test_count_deletes_oldest_bundles_and_preserves_parent_runs(self):
        self.config(artifact_retention_days=0, artifact_retention_count=0, run_retention_count=0)
        ids = [self.create_run() for _ in range(4)]
        newest = self.create_run(artifacts=False)
        self.config(artifact_retention_days=0, artifact_retention_count=2, run_retention_count=1)
        self.assertEqual(
            [row[0] for row in database.db_ci_artifacts_list("owner", "repo")], ids[-2:][::-1]
        )
        self.assertEqual(
            {row[0] for row in database.db_ci_runs_list("owner", "repo")}, {*ids[-2:], newest}
        )

    def test_expiry_is_per_repository_and_policy_applies_immediately(self):
        self.config(artifact_retention_days=0, run_retention_count=0)
        run_id = self.create_run()
        other = self.create_run(repo="other", config_json="")
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
        self.assertEqual(
            {row[0] for row in database.db_ci_runs_list("owner", "repo")}, {pending, *ids[-2:]}
        )

    def test_project_page_retention_is_ignored_and_global_defaults_apply(self):
        self.config(run_retention_count=0)
        database.db_ci_preferences_set({"run_retention_count": 0}, "owner", "repo")
        ids = [self.create_run(artifacts=False) for _ in range(4)]
        self.assertEqual(len(database.db_ci_runs_list("owner", "repo")), 4)
        # New snapshots carry an explicit marker. Live administrator defaults win
        # over the retired project page form, including its "unlimited" setting.
        database.db_ci_preferences_set({"run_retention_count": 2})
        self.assertEqual(
            {row[0] for row in database.db_ci_runs_list("owner", "repo")}, set(ids[-2:])
        )

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
        self.assertEqual(
            database.db_ci_runs_count("owner", "repo", status="success", warnings="yes"), 1
        )
        self.assertEqual(database.db_ci_runs_count("owner", "repo", warnings="no"), 1)
        rows = database.db_ci_runs_list(
            "owner", "repo", warnings="yes", summary=True, include_warnings=True
        )
        self.assertEqual([row[0] for row in rows], [warning])
        self.assertIn("locked", rows[0][11])
        self.assertEqual(
            [row[0] for row in database.db_ci_runs_list("owner", "repo", warnings="no")], [clean]
        )
        self.assertIn("locked", database.db_ci_run_metadata("owner", "repo", warning)["warnings"])

    def test_head_change_without_refresh_pauses_deletion_until_verified(self):
        self.config(artifact_retention_days=0, artifact_retention_count=0, run_retention_count=0)
        ids = [self.create_run() for _ in range(3)]
        for run_id in ids:
            self.age_artifact(run_id)
        # A default-branch switch or an out-of-band ref update moves HEAD
        # without a retention refresh. The cached limits are now unverified.
        self.head = "b" * 40
        database.db_ci_run_update(ids[-1], status="success")
        self.assertEqual(len(database.db_ci_runs_list("owner", "repo")), 3)
        self.assertEqual(len(database.db_ci_artifacts_list("owner", "repo")), 3)
        # The next verified refresh applies its own limits immediately.
        self.config(artifact_retention_days=1, artifact_retention_count=0, run_retention_count=1)
        self.assertEqual(len(database.db_ci_artifacts_list("owner", "repo")), 0)
        self.assertEqual(len(database.db_ci_runs_list("owner", "repo")), 1)

    def test_head_change_during_artifact_cleanup_rolls_back(self):
        self.config(artifact_retention_days=1, artifact_retention_count=0, run_retention_count=0)
        run_id = self.create_run()
        self.age_artifact(run_id)
        calls = 0

        def moving_head(_owner, _repo):
            nonlocal calls
            calls += 1
            if calls == 1:
                return self.head
            return "b" * 40

        database.configure_retention_head_resolver(moving_head)
        # The delete starts under the old HEAD, then the post-check sees a new
        # one and rolls the deletion back.
        self.assertEqual(database.db_ci_artifact_get("owner", "repo", run_id), 7)
        self.assertEqual(database.db_ci_artifact_get("owner", "repo", run_id), 7)

    def test_head_change_during_run_prune_rolls_back(self):
        self.config(artifact_retention_days=0, artifact_retention_count=0, run_retention_count=0)
        ids = [self.create_run(artifacts=False) for _ in range(2)]
        database.db_ci_retention_policy_set(
            "owner", "repo", {"run_retention_count": 1}, commit=self.head
        )
        calls = 0

        def moving_head(_owner, _repo):
            nonlocal calls
            calls += 1
            if calls == 1:
                return self.head
            return "b" * 40

        database.configure_retention_head_resolver(moving_head)
        database.db_ci_run_update(ids[-1], status="success")
        self.assertEqual(len(database.db_ci_runs_list("owner", "repo")), 2)

    def test_unavailable_policy_pauses_cleanup(self):
        self.config(artifact_retention_days=0, artifact_retention_count=0, run_retention_count=0)
        run_id = self.create_run()
        self.age_artifact(run_id)
        database.db_ci_retention_policy_set(
            "owner", "repo", {"unavailable": True}, commit=self.head
        )
        self.assertEqual(database.db_ci_artifact_get("owner", "repo", run_id), 7)

    def test_missing_policy_pauses_cleanup_even_when_defaults_would_expire(self):
        # No cache row is not permission to assume defaults. The default seven
        # days would delete this artifact, but the first cache write may have
        # failed while introducing a different policy.
        run_id = self.create_run()
        self.age_artifact(run_id)
        self.assertEqual(database.db_ci_artifact_get("owner", "repo", run_id), 7)
        self.config(artifact_retention_days=1, artifact_retention_count=0, run_retention_count=0)
        self.assertIsNone(database.db_ci_artifact_get("owner", "repo", run_id))

    def test_missing_policy_pauses_run_prune_until_verified(self):
        with mock.patch.dict(os.environ, {"PYGITHOST_CI_RETENTION": "1"}):
            ids = [self.create_run(artifacts=False) for _ in range(2)]
            self.assertEqual(len(database.db_ci_runs_list("owner", "repo")), 2)
            database.db_ci_retention_policy_set("owner", "repo", {}, commit=self.head)
            database.db_ci_run_update(ids[-1], status="success")
            self.assertEqual(len(database.db_ci_runs_list("owner", "repo")), 1)

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
        self.assertIn(
            "old warning", database.db_ci_run_metadata("owner", "repo", run_id)["warnings"]
        )
