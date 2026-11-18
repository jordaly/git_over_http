"""Regression tests for strict typing boundaries around persisted CI JSON."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from pygithost import database
from pygithost.ci_config import compile_document
from pygithost.ci_email import load_settings
from pygithost.ci_preferences import read

_NON_OBJECT_JSON = ("null", "[]", "42", '"text"', "true")


class EmailSettingsDecodeTests(unittest.TestCase):
    """Stored SMTP settings must decode to an object, never a bare JSON value."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "test.db")
        database._db_init()

    def tearDown(self):
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def test_rejects_non_object_roots(self):
        for raw in _NON_OBJECT_JSON:
            with self.subTest(raw=raw):
                database.db_email_settings_set(raw)
                with self.assertRaises(ValueError):
                    load_settings()

    def test_accepts_object_root(self):
        database.db_email_settings_set('{"host": "smtp.example.test"}')
        self.assertEqual(load_settings()["host"], "smtp.example.test")


class PreferencesDecodeTests(unittest.TestCase):
    """Global and repository preference JSON must decode to objects."""

    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute(
            "CREATE TABLE server_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self.conn.execute(
            "CREATE TABLE repository_ci_settings ("
            "owner TEXT NOT NULL, repo TEXT NOT NULL, settings_json TEXT NOT NULL, "
            "PRIMARY KEY(owner, repo))"
        )
        self._set_global("{}")

    def tearDown(self):
        self.conn.close()

    def _set_global(self, raw):
        self.conn.execute("DELETE FROM server_settings")
        self.conn.execute("INSERT INTO server_settings(key,value) VALUES('ci_defaults',?)", (raw,))

    def test_rejects_non_object_global_roots(self):
        for raw in _NON_OBJECT_JSON:
            with self.subTest(raw=raw):
                self._set_global(raw)
                with self.assertRaises(ValueError):
                    read(self.conn)

    def test_rejects_non_object_repository_roots(self):
        for raw in _NON_OBJECT_JSON:
            with self.subTest(raw=raw):
                self.conn.execute("DELETE FROM repository_ci_settings")
                self.conn.execute(
                    "INSERT INTO repository_ci_settings(owner,repo,settings_json) VALUES(?,?,?)",
                    ("owner", "repo", raw),
                )
                with self.assertRaises(ValueError):
                    read(self.conn, "owner", "repo")

    def test_accepts_object_roots(self):
        self._set_global('{"timeout_seconds": 60}')
        self.conn.execute(
            "INSERT INTO repository_ci_settings(owner,repo,settings_json) VALUES(?,?,?)",
            ("owner", "repo", '{"env": {"A": "B"}}'),
        )
        global_values, repository_values = read(self.conn, "owner", "repo")
        self.assertEqual(global_values["timeout_seconds"], 60)
        self.assertEqual(repository_values["env"], {"A": "B"})


class DocumentDecodeTests(unittest.TestCase):
    """Administrator configuration documents require an object root."""

    def test_compile_document_rejects_non_object_roots(self):
        for value in (None, [], 0, "text", True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                compile_document(value)


if __name__ == "__main__":
    unittest.main()
