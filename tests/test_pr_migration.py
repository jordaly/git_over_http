import sqlite3
import tempfile
import unittest
from pathlib import Path

from pygithost import database


class PullRequestAuthorMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pr-author-migration-")
        self.old_db = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "legacy.db")
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(setattr, database, "DB_PATH", self.old_db)
        database._db_init()
        conn = database._db_connect()
        try:
            ddl = conn.execute("SELECT sql FROM sqlite_master WHERE name='pull_requests'").fetchone()[0]
            conn.execute("DROP TABLE pull_requests")
            conn.execute(ddl.replace("author_user_id INTEGER,", "author_user_id INTEGER NOT NULL,"))
            conn.execute("ALTER TABLE pull_requests ADD COLUMN extra_label TEXT NOT NULL DEFAULT 'retained'")
            conn.execute("ALTER TABLE pull_requests ADD COLUMN derived_title TEXT GENERATED ALWAYS AS (upper(title)) VIRTUAL")
            conn.execute("INSERT INTO users(id,username,pass_salt,pass_hash) VALUES(1,'legacy-author',?,?)", (b"salt", b"hash"))
            conn.execute("CREATE TABLE pr_audit(pr_id INTEGER, title TEXT)")
            conn.execute("CREATE TRIGGER record_pr_insert AFTER INSERT ON pull_requests BEGIN INSERT INTO pr_audit VALUES(NEW.id,NEW.title); END")
            conn.execute("CREATE INDEX custom_pr_label ON pull_requests(extra_label)")
            conn.execute("CREATE TABLE pr_links(pr_id INTEGER REFERENCES pull_requests(id) ON DELETE CASCADE, label TEXT)")
            conn.execute("CREATE VIEW pr_titles AS SELECT id,title,extra_label,derived_title FROM pull_requests")
            for index, status in enumerate(("open", "closed", "merged"), 1):
                conn.execute("""INSERT INTO pull_requests(id,owner,repo,title,body,source_branch,target_branch,
                    author_user_id,status,created_at,closed_at,merged_at,merge_method,merge_commit,extra_label)
                    VALUES(?, 'team','repo',?,'Keep this body','feature','main',1,?,
                    '2026-01-01','2026-01-02','2026-01-03','ff-only',?,?)""",
                    (index, "PR " + status, status, "a" * 40, "label-" + status))
            conn.execute("INSERT INTO pr_links VALUES(1,'keep child reference')")
            conn.execute("INSERT INTO pull_requests(id,owner,repo,title,source_branch,target_branch,author_user_id) VALUES(10000,'team','repo','Deleted high ID','feature','main',1)")
            conn.execute("DELETE FROM pull_requests WHERE id=10000")
            self.rows = conn.execute("SELECT * FROM pull_requests ORDER BY id").fetchall()
            self.audit = conn.execute("SELECT * FROM pr_audit").fetchall()
        finally:
            conn.close()

    def test_startup_migrates_legacy_schema_and_keeps_history_references_and_sequence(self):
        with self.assertRaises(sqlite3.IntegrityError):
            database.db_pr_create("team", "repo", "Before migration", "", "feature", "main", None)
        database._db_init()
        conn = database._db_connect()
        try:
            author = next(row for row in conn.execute("PRAGMA table_info(pull_requests)") if row[1] == "author_user_id")
            self.assertEqual(author[3], 0)
            self.assertEqual(conn.execute("SELECT * FROM pull_requests ORDER BY id").fetchall(), self.rows)
            self.assertEqual(conn.execute("SELECT * FROM pr_audit").fetchall(), self.audit)
            self.assertEqual(conn.execute("SELECT * FROM pr_links").fetchall(), [(1, "keep child reference")])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM pr_titles").fetchone()[0], 3)
            self.assertIsNotNone(conn.execute("SELECT sql FROM sqlite_master WHERE name='custom_pr_label'").fetchone())
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(conn.execute("SELECT seq FROM sqlite_sequence WHERE name='pull_requests'").fetchone()[0], 10000)
        finally:
            conn.close()
        new_id = database.db_pr_create("team", "repo", "Anonymous", "", "feature", "main", None)
        self.assertEqual(new_id, 10001)
        self.assertIsNone(database.db_pr_get(new_id)[7])
        with self.assertRaises(sqlite3.IntegrityError):
            database.db_pr_create("team", "repo", "Invalid user", "", "feature", "main", 999)

    def test_migration_is_idempotent_and_restores_foreign_key_enforcement(self):
        conn = database._db_connect()
        try:
            database._db_migrate_pr_author_nullable(conn)
            self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(conn.execute("PRAGMA legacy_alter_table").fetchone()[0], 0)
            schema = conn.execute("SELECT name,sql FROM sqlite_master ORDER BY name").fetchall()
            database._db_migrate_pr_author_nullable(conn)
            self.assertEqual(conn.execute("SELECT name,sql FROM sqlite_master ORDER BY name").fetchall(), schema)
        finally:
            conn.close()
        database._db_init()
        database._db_init()
        self.assertEqual(database.db_pr_get(1)[7], 1)

    def test_failed_rebuild_rolls_back_without_losing_any_rows(self):
        class FailRename(sqlite3.Connection):
            def execute(self, sql, *args):
                if sql.startswith('ALTER TABLE "__pull_requests_nullable_'):
                    raise sqlite3.OperationalError("Simulated migration failure")
                return super().execute(sql, *args)

        conn = sqlite3.connect(database.DB_PATH, isolation_level=None, factory=FailRename)
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            with self.assertRaisesRegex(sqlite3.OperationalError, "Simulated"):
                database._db_migrate_pr_author_nullable(conn)
            self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(conn.execute("PRAGMA legacy_alter_table").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT * FROM pull_requests ORDER BY id").fetchall(), self.rows)
            self.assertEqual(conn.execute("SELECT * FROM pr_audit").fetchall(), self.audit)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM pr_titles").fetchone()[0], 3)
            author = next(row for row in conn.execute("PRAGMA table_info(pull_requests)") if row[1] == "author_user_id")
            self.assertEqual(author[3], 1)
            self.assertEqual(conn.execute("SELECT name FROM sqlite_master WHERE name LIKE '__pull_requests_nullable_%'").fetchall(), [])
        finally:
            conn.close()
        database._db_init()  # A failed attempt can be safely retried at startup.
        self.assertIsNotNone(database.db_pr_create("team", "repo", "After retry", "", "feature", "main", None))

    def test_deleting_an_author_after_migration_keeps_pull_requests(self):
        database._db_init()
        conn = database._db_connect()
        try:
            conn.execute("DELETE FROM users WHERE id=1")
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM pull_requests").fetchone()[0], 3)
            self.assertEqual(conn.execute("SELECT author_user_id FROM pull_requests").fetchall(), [(None,)] * 3)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM pr_links").fetchone()[0], 1)
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
        finally:
            conn.close()
