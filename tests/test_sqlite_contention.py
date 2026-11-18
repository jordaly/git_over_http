import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from pygithost import database
from pygithost.ci import CIManager


class ConnectionContentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "database.db")

    def tearDown(self):
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def test_normal_connection_does_not_try_to_change_journal_mode_under_reader_lock(self):
        real_connect = sqlite3.connect
        setup = real_connect(database.DB_PATH, isolation_level=None)
        setup.execute("CREATE TABLE example(value TEXT)")
        setup.execute("INSERT INTO example VALUES('retained')")
        setup.close()
        reader = real_connect(database.DB_PATH, isolation_level=None)
        reader.execute("BEGIN")
        reader.execute("SELECT * FROM example").fetchall()
        statements = []

        def short_connect(*args, **kwargs):
            kwargs["timeout"] = 0.02
            connection = real_connect(*args, **kwargs)
            connection.set_trace_callback(statements.append)
            return connection

        try:
            with mock.patch.object(database.sqlite3, "connect", side_effect=short_connect):
                connection = database._db_connect()
                try:
                    self.assertEqual(
                        connection.execute("SELECT value FROM example").fetchone()[0], "retained"
                    )
                finally:
                    connection.close()
        finally:
            reader.rollback()
            reader.close()
        self.assertFalse(any("journal_mode" in sql.lower() and "=" in sql for sql in statements))

    def test_initialization_enables_wal_without_runtime_journal_setters(self):
        database._db_init()
        connection = database._db_connect()
        try:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        finally:
            connection.close()

    def test_connection_is_closed_if_connection_setup_fails(self):
        connection = mock.Mock()
        connection.execute.side_effect = sqlite3.OperationalError("database is locked")
        with mock.patch.object(database.sqlite3, "connect", return_value=connection):
            with self.assertRaises(sqlite3.OperationalError):
                database._db_connect()
        connection.close.assert_called_once()

    def test_connection_recovers_from_real_wal_writer_contention(self):
        database._db_init()
        ready, release = threading.Event(), threading.Event()

        def writer():
            conn = sqlite3.connect(database.DB_PATH, isolation_level=None)
            try:
                conn.execute("PRAGMA locking_mode=EXCLUSIVE")
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT INTO users(username,pass_salt,pass_hash) VALUES('lock-holder',X'01',X'02')"
                )
                ready.set()
                release.wait(3)
                conn.rollback()
            finally:
                conn.close()

        thread = threading.Thread(target=writer)
        thread.start()
        self.assertTrue(ready.wait(3))
        real_connect = sqlite3.connect
        attempts = []

        def short_connect(*args, **kwargs):
            kwargs["timeout"] = 0.02
            attempts.append(time.monotonic())
            return real_connect(*args, **kwargs)

        timer = threading.Timer(0.12, release.set)
        timer.start()
        try:
            with mock.patch.object(database.sqlite3, "connect", side_effect=short_connect):
                conn = database._db_connect()
                try:
                    self.assertEqual(conn.execute("SELECT count(*) FROM users").fetchone()[0], 0)
                finally:
                    conn.close()
            self.assertGreater(len(attempts), 1)
        finally:
            release.set()
            thread.join(3)
            timer.join()

    def test_remote_runtime_connections_do_not_run_schema_migrations(self):
        from pygithost.remote_ci import connect

        database._db_init()
        statements = []
        original = database._db_connect

        def traced():
            conn = original()
            conn.set_trace_callback(statements.append)
            return conn

        with mock.patch.object(database, "_db_connect", side_effect=traced):
            conn = connect()
            conn.close()
        self.assertFalse(
            any(sql.lstrip().upper().startswith(("CREATE", "ALTER")) for sql in statements),
            statements,
        )

    def test_persistent_busy_is_bounded_and_closes_every_connection(self):
        error = sqlite3.OperationalError("database is locked")
        error.sqlite_errorcode = sqlite3.SQLITE_BUSY
        connections = [mock.Mock() for _ in range(3)]
        for conn in connections:
            conn.execute.side_effect = error
        with mock.patch.object(database.sqlite3, "connect", side_effect=connections) as opening:
            with mock.patch.object(database.time, "sleep") as waiting:
                with self.assertRaises(sqlite3.OperationalError):
                    database._db_connect()
        self.assertEqual(opening.call_count, 3)
        self.assertEqual(waiting.call_count, 2)
        for conn in connections:
            conn.close.assert_called_once()

    def test_busy_diagnostics_identify_local_transaction_without_values(self):
        database._db_init()
        holder = database._db_connect()
        holder.operation = "known_lock_holder"
        contender = sqlite3.connect(
            database.DB_PATH, timeout=0.02, isolation_level=None, factory=database._Connection
        )
        try:
            holder.execute("BEGIN IMMEDIATE")
            holder.execute(
                "INSERT INTO users(username,pass_salt,pass_hash) VALUES('PRIVATE_VALUE',X'01',X'02')"
            )
            with self.assertLogs("pygithost.database", level="WARNING") as logs:
                with self.assertRaises(sqlite3.OperationalError):
                    contender.execute("BEGIN IMMEDIATE")
            text = " ".join(logs.output)
            self.assertIn("known_lock_holder", text)
            self.assertIn(str(id(holder)), text)
            self.assertNotIn("PRIVATE_VALUE", text)
        finally:
            contender.close()
            holder.rollback()
            holder.close()
        self.assertNotIn(id(holder), database._transactions)


class CoordinatorFailureTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "ci.db")
        database._db_init()
        self.run = database.db_ci_run_create(
            "root", "project", "push", "main", "a" * 40, "{}", "{}"
        )
        database.db_ci_run_update(
            self.run,
            status="running",
            output="Principal progress retained\n",
            phase="step 3: Principal",
            truncated=1,
        )
        database.db_ci_steps_set(
            self.run, '[{"name":"Principal","status":"running","output":"step evidence"}]'
        )
        self.row = (self.run, "root", "project", "push", "main", "a" * 40, "{}")
        self.manager = CIManager(lambda *_: "")
        self.manager._schedule_notification = mock.Mock()
        self.manager._deploy = mock.AsyncMock()

    async def asyncTearDown(self):
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    async def test_database_failure_retains_progress_and_records_unknown_execution(self):
        self.manager._execute = mock.AsyncMock(
            side_effect=sqlite3.OperationalError("database is locked")
        )
        await self.manager._run_one(self.row)
        row = database.db_ci_run_get("root", "project", self.run)
        self.assertEqual(row[4], "interrupted")
        self.assertEqual(row[5], "Principal progress retained\n")
        self.assertEqual(row[6], 1)
        metadata = database.db_ci_run_metadata("root", "project", self.run)
        self.assertEqual(metadata["phase"], "step 3: Principal")
        self.assertIn("uncertain", metadata["reason"])
        self.assertIn("step evidence", database.db_ci_steps_get(self.run))
        self.manager._execute.assert_awaited_once()
        self.manager._deploy.assert_not_awaited()

    async def test_non_database_failure_also_preserves_existing_output(self):
        self.manager._execute = mock.AsyncMock(side_effect=RuntimeError("coordinator error"))
        await self.manager._run_one(self.row)
        row = database.db_ci_run_get("root", "project", self.run)
        self.assertEqual(row[4], "failed")
        self.assertEqual(row[5], "Principal progress retained\n")
        self.assertIn(
            "coordinator",
            database.db_ci_run_metadata("root", "project", self.run)["reason"].lower(),
        )

    async def test_cleanup_error_cannot_overwrite_a_successful_result(self):
        async def executed_then_cleanup_failed(row):
            database.db_ci_run_update(
                self.run, status="success", output="Verified successful result\n", return_code=0
            )
            raise sqlite3.OperationalError("database is locked")

        self.manager._execute = mock.AsyncMock(side_effect=executed_then_cleanup_failed)
        await self.manager._run_one(self.row)
        row = database.db_ci_run_get("root", "project", self.run)
        self.assertEqual(row[4:6], ("success", "Verified successful result\n"))
        self.assertEqual(row[7], 0)
