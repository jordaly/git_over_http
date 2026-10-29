from pathlib import Path
import tempfile
import unittest

from pygithost import database


class DatabaseIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "indexed.db")
        database._db_init()

    def tearDown(self):
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def test_history_and_filter_queries_use_indexes(self):
        cases = [
            ("SELECT id FROM ci_runs WHERE owner=? AND repo=? AND branch=? ORDER BY id DESC LIMIT 25", ("o", "r", "main"), "idx_ci_runs_repo_branch"),
            ("SELECT COUNT(*) FROM ci_runs WHERE owner=? AND repo=? AND status=?", ("o", "r", "success"), "idx_ci_runs_repo_result"),
            ("SELECT id FROM ci_runs WHERE owner=? AND repo=? AND event=? ORDER BY id DESC LIMIT 25", ("o", "r", "push"), "idx_ci_runs_repo_event"),
            ("SELECT id FROM ci_runs WHERE owner=? AND repo=? AND warnings!='' ORDER BY id DESC LIMIT 25", ("o", "r"), "idx_ci_runs_warnings"),
            ("SELECT id,owner,repo FROM ci_runs WHERE notification='queued' ORDER BY id", (), "idx_ci_runs_pending_email"),
            ("SELECT id FROM ci_deployments WHERE owner=? AND repo=? ORDER BY id DESC LIMIT 25", ("o", "r"), "idx_deployments_repo_history"),
            ("SELECT status,output FROM ci_deployments WHERE run_id=?", (1,), "idx_deployments_run"),
            ("SELECT run_id,owner,repo FROM ci_deployments WHERE notification='queued'", (), "idx_deployments_pending_email"),
            ("SELECT id FROM pull_requests WHERE owner=? AND repo=? ORDER BY id DESC LIMIT 25", ("o", "r"), "idx_pr_repo_history"),
            ("SELECT id,target_branch FROM pull_requests WHERE owner=? AND repo=? AND source_branch=? AND status='open'", ("o", "r", "main"), "idx_pr_open_source"),
            ("SELECT id,source_branch FROM pull_requests WHERE owner=? AND repo=? AND target_branch=? AND status='open'", ("o", "r", "main"), "idx_pr_open_target"),
            ("SELECT username FROM users ORDER BY username COLLATE NOCASE", (), "idx_users_name_order"),
        ]
        conn = database._db_connect()
        try:
            for query, params, index in cases:
                with self.subTest(index=index):
                    plan = " ".join(row[3] for row in conn.execute("EXPLAIN QUERY PLAN " + query, params))
                    self.assertIn(index, plan)
                    self.assertNotIn("USE TEMP B-TREE", plan)
        finally:
            conn.close()

    def test_index_migration_is_idempotent(self):
        database._db_init()
        database._db_init()
        conn = database._db_connect()
        try:
            names = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")]
            self.assertEqual(len(names), len(set(names)))
            self.assertIn("idx_ci_runs_warnings", names)
            self.assertIn("idx_deployments_run", names)
        finally:
            conn.close()
