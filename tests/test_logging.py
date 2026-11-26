"""Structured logging, access records and the SQLite audit trail."""

import http.client
import json
import logging
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import urlencode

from pygithost import database
from pygithost.config import AppConfig
from pygithost.logging_setup import (
    JsonFormatter,
    configure_logging,
    safe_target,
)
from tests.test_server import ServerRunner, _which_git_backend, with_csrf


class FormatterTests(unittest.TestCase):
    def record(self, **extra):
        record = logging.LogRecord(
            "pygithost.test", logging.INFO, __file__, 10, "hello %s", ("world",), None
        )
        for key, value in extra.items():
            setattr(record, key, value)
        return record

    def test_json_record_has_timestamp_level_and_metadata(self):
        payload = json.loads(
            JsonFormatter().format(
                self.record(event="demo", request_id="abc", status=200, user="alice")
            )
        )
        self.assertEqual(payload["level"], "INFO")
        self.assertEqual(payload["message"], "hello world")
        self.assertEqual(payload["event"], "demo")
        self.assertEqual(payload["request_id"], "abc")
        self.assertEqual(payload["status"], 200)
        self.assertEqual(payload["user"], "alice")
        self.assertTrue(payload["ts"].endswith("Z"))

    def test_json_record_omits_unserializable_and_private_extras(self):
        payload = json.loads(
            JsonFormatter().format(
                self.record(private_object=object(), _secret="nope", detail="safe")
            )
        )
        self.assertNotIn("private_object", payload)
        self.assertNotIn("_secret", payload)
        self.assertEqual(payload["detail"], "safe")

    def test_json_record_includes_traceback(self):
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            import sys

            record = logging.LogRecord(
                "pygithost.test", logging.ERROR, __file__, 1, "failed", (), sys.exc_info()
            )
        payload = json.loads(JsonFormatter().format(record))
        self.assertIn("RuntimeError: boom", payload["exception"])

    def test_safe_target_discards_query_tokens_and_control_characters(self):
        self.assertEqual(safe_target("/r/alice/project?token=SECRET#frag"), "/r/alice/project")
        self.assertEqual(safe_target("http://host/a/b?x=1"), "/a/b")
        self.assertEqual(safe_target("/path\nforged"), "/pathforged")
        self.assertEqual(len(safe_target("/" + "a" * 2000)), 512)
        self.assertEqual(safe_target(""), "/")


class ConfigurationTests(unittest.TestCase):
    def mapping(self, **overrides):
        raw = AppConfig.default_for_platform("Linux").to_dict()
        raw.update(overrides)
        return raw

    def test_defaults_are_present_and_json_serializable(self):
        config = AppConfig.from_mapping(self.mapping())
        self.assertEqual(config.log_level, "INFO")
        self.assertEqual(config.log_format, "json")
        self.assertTrue(config.log_file.endswith("pygithost.log"))
        self.assertGreaterEqual(config.log_max_bytes, 1024)
        self.assertTrue(config.access_log)
        self.assertTrue(config.audit_log)
        json.dumps(config.to_dict())

    def test_level_and_format_are_normalized(self):
        config = AppConfig.from_mapping(self.mapping(log_level="debug", log_format="TEXT"))
        self.assertEqual(config.log_level, "DEBUG")
        self.assertEqual(config.log_format, "text")

    def test_invalid_values_are_rejected(self):
        cases = (
            {"log_level": "TRACE"},
            {"log_format": "xml"},
            {"log_max_bytes": 10},
            {"log_backup_count": 1000},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    AppConfig.from_mapping(self.mapping(**overrides))

    def test_empty_log_file_means_stderr_only(self):
        config = AppConfig.from_mapping(self.mapping(log_file="   "))
        self.assertIsNone(config.log_file)


class DocumentationTests(unittest.TestCase):
    def test_logging_example_and_in_page_guide_match_supported_settings(self):
        from pygithost.ci_docs import manual_content

        root = Path(__file__).resolve().parents[1]
        text = (root / "docs/logging.md").read_text(encoding="utf-8")
        example = json.loads(text.split("```json\n", 1)[1].split("```", 1)[0])
        config = AppConfig.from_mapping(example)
        self.assertEqual(config.log_level, "INFO")
        self.assertEqual(config.log_backup_count, 5)
        rendered = str(manual_content("logging", None, "/r/root/project/ci/docs"))
        for expected in (
            "0 disables rotation",
            "not an automatic secret-redaction",
            "Runner-token issuance",
            "source_cleanup_deferred",
            "Git smart-HTTP",
        ):
            self.assertIn(expected, rendered)

    def test_shared_guides_link_to_logging_inside_the_ui(self):
        from pygithost.ci_docs import manual_content

        base = "/r/root/project/ci/docs"
        for guide in ("operations", "getting-started", "settings"):
            with self.subTest(guide=guide):
                rendered = str(manual_content(guide, None, base))
                self.assertIn(base + "?guide=logging", rendered)

    def test_source_storage_and_limits_guides_explain_pending_cleanup_and_buffering(self):
        from pygithost.ci_docs import manual_content

        for guide in ("http-runner", "ci-limits"):
            with self.subTest(guide=guide):
                rendered = str(manual_content(guide, None, "/r/root/project/ci/docs"))
                self.assertIn("ci_remote_source_cleanup", rendered)
                self.assertIn("SQLite stores", rendered)
                self.assertIn("memory", rendered)


class HandlerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pygithost-log-")

    def tearDown(self):
        logging.getLogger().handlers.clear()
        logging.getLogger().setLevel(logging.WARNING)
        self.temp.cleanup()

    def path(self, name):
        return str(Path(self.temp.name) / name)

    def test_level_filters_console_and_writes_json_file(self):
        destination = self.path("server.log")
        configure_logging(level="WARNING", log_file=destination, log_format="json", console=False)
        logger = logging.getLogger("pygithost.test.handlers")
        logger.info("ignored")
        logger.warning("kept", extra={"event": "check"})
        lines = Path(destination).read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        payload = json.loads(lines[0])
        self.assertEqual(payload["message"], "kept")
        self.assertEqual(payload["event"], "check")

    def test_reconfiguration_replaces_owned_handlers_and_closes_previous_file(self):
        first, second = self.path("first.log"), self.path("second.log")
        configure_logging(level="INFO", log_file=first, console=False)
        owned = [h for h in logging.getLogger().handlers if getattr(h, "_pygithost_handler", False)]
        self.assertEqual(len(owned), 1)
        configure_logging(level="INFO", log_file=second, console=False)
        owned = [h for h in logging.getLogger().handlers if getattr(h, "_pygithost_handler", False)]
        self.assertEqual(len(owned), 1)
        logging.getLogger("pygithost.test.handlers").info("second only")
        self.assertFalse(Path(first).read_text(encoding="utf-8").strip())
        self.assertIn("second only", Path(second).read_text(encoding="utf-8"))

    def test_rotation_keeps_bounded_backups(self):
        destination = self.path("rotating.log")
        configure_logging(
            level="INFO", log_file=destination, max_bytes=1024, backup_count=2, console=False
        )
        logger = logging.getLogger("pygithost.test.handlers")
        for index in range(80):
            logger.info("record %03d %s", index, "x" * 80)
        files = sorted(Path(self.temp.name).glob("rotating.log*"))
        self.assertGreaterEqual(len(files), 2)
        self.assertLessEqual(len(files), 3)

    def test_invalid_handler_settings_are_rejected(self):
        with self.assertRaises(ValueError):
            configure_logging(level="LOUD", console=False)
        with self.assertRaises(ValueError):
            configure_logging(level="INFO", max_bytes=10, console=False)


class AuditDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pygithost-audit-")
        self.old_db = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "audit.db")
        database._db_init()

    def tearDown(self):
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def test_append_and_list_are_newest_first_and_bounded(self):
        database.db_audit_append(
            "login",
            "failure",
            actor="mallory",
            target="web",
            detail="invalid_credentials",
            ip="127.0.0.1",
        )
        database.db_audit_append(
            "token_create",
            "success",
            actor="alice",
            actor_user_id=7,
            target="ci",
            detail="scopes=read",
        )
        rows = database.db_audit_list()
        self.assertEqual([row["action"] for row in rows], ["token_create", "login"])
        self.assertEqual(rows[0]["actor_user_id"], 7)
        self.assertEqual(rows[1]["outcome"], "failure")
        self.assertEqual(len(database.db_audit_list(action="login")), 1)

    def test_empty_values_and_nul_bytes_are_safe(self):
        database.db_audit_append("login", "failure", actor=None, target="a\x00b")
        row = database.db_audit_list()[0]
        self.assertIsNone(row["actor"])
        self.assertEqual(row["target"], "ab")


@unittest.skipUnless(shutil.which("git") and _which_git_backend(), "requires Git HTTP backend")
class ServerLoggingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pygithost-serverlog-")
        self.root = Path(self.temp.name)
        self.log_path = self.root / "server.log"
        self.old_db = database.DB_PATH
        self.server = None
        self.start()

    def start(self, **overrides):
        if self.server is not None:
            self.server.__exit__(None, None, None)
        options = {
            "project_root": str(self.root / "repos"),
            "require_auth": False,
            "log_file": str(self.log_path),
            "log_level": "INFO",
        }
        options.update(overrides)
        self.server = ServerRunner(**options)
        self.server.__enter__()

    def tearDown(self):
        if self.server is not None:
            self.server.__exit__(None, None, None)
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def request(self, path, *, method="GET", headers=None, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=30)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def login(self, username, password):
        body = urlencode({"username": username, "password": password})
        return self.request(
            "/login",
            method="POST",
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def records(self, logger_name, count=1):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.log_path.exists():
                rows = [
                    json.loads(line)
                    for line in self.log_path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                selected = [row for row in rows if row.get("logger") == logger_name]
                if len(selected) >= count:
                    return selected
            time.sleep(0.02)
        self.fail(f"no {logger_name} records were written")

    def test_access_log_records_status_and_never_leaks_query_or_headers(self):
        secret = "SUPERSECRET-TOKEN-VALUE"
        self.assertEqual(self.request("/").__getitem__(0), 200)
        self.assertEqual(self.request("/definitely-missing").__getitem__(0), 404)
        status, _headers, _body = self.request(
            "/api/v1/user?access_token=" + secret, headers={"Authorization": "Bearer " + secret}
        )
        self.assertEqual(status, 401)
        rows = self.records("pygithost.access", count=3)
        home = [row for row in rows if row.get("path") == "/"]
        missing = [row for row in rows if row.get("path") == "/definitely-missing"]
        api = [row for row in rows if row.get("path") == "/api/v1/user"]
        self.assertTrue(home and missing and api)
        self.assertEqual(home[-1]["status"], 200)
        self.assertEqual(missing[-1]["status"], 404)
        self.assertEqual(api[-1]["status"], 401)
        self.assertEqual(api[-1]["event"], "http_request")
        self.assertIn("duration_ms", api[-1])
        text = self.log_path.read_text(encoding="utf-8")
        self.assertNotIn(secret, text)
        self.assertNotIn("access_token", text)
        self.assertNotIn("Authorization", text)

    def test_successful_git_responses_are_logged_at_info_with_status_and_body_size(self):
        repository = Path(self.server.project_root) / "access.git"
        subprocess.run(
            ["git", "init", "--bare", str(repository)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        status, _, body = self.request("/git/access.git/info/refs?service=git-upload-pack")
        self.assertEqual(status, 200)
        records = self.records("pygithost.access")
        record = next(row for row in records if row["path"] == "/git/access.git/info/refs")
        self.assertEqual(record["status"], 200)
        self.assertEqual(record["level"], "INFO")
        self.assertEqual(record["size"], len(body))
        self.assertNotIn("service=git-upload-pack", self.log_path.read_text(encoding="utf-8"))

    def test_login_token_and_settings_events_reach_the_audit_trail(self):
        self.start(require_auth=True)
        subprocess.run(
            ["git", "init", "--bare", "-q", str(self.root / "repos" / "audited.git")], check=True
        )
        database.db_create_user("auditor", "s3cret-pass", False)
        database.db_create_user("rootadmin", "s3cret-pass", True)
        connection = database._db_connect()
        try:
            user = connection.execute("SELECT id FROM users WHERE username='auditor'").fetchone()[0]
        finally:
            connection.close()

        self.assertEqual(self.login("auditor", "wrong").__getitem__(0), 200)
        status, headers, _body = self.login("auditor", "s3cret-pass")
        self.assertEqual(status, 303)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.assertTrue(cookie.startswith("pygithost_session="))

        status, _headers, _body = self.request(
            "/tokens/create",
            method="POST",
            body=urlencode(
                with_csrf(
                    self.server,
                    {"name": "ci-token", "scopes": "read", "repository": "root/audited"},
                    cookie,
                )
            ),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        self.assertEqual(status, 200)
        connection = database._db_connect()
        try:
            token_id = connection.execute(
                "SELECT id FROM tokens WHERE user_id=? ORDER BY id DESC", (user,)
            ).fetchone()[0]
        finally:
            connection.close()
        self.request(
            "/tokens/revoke",
            method="POST",
            body=urlencode(with_csrf(self.server, {"token_id": str(token_id)}, cookie)),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )

        _status, admin_headers, _body = self.login("rootadmin", "s3cret-pass")
        admin_cookie = admin_headers["Set-Cookie"].split(";", 1)[0]
        self.request(
            "/admin/users/create",
            method="POST",
            body=urlencode(
                with_csrf(
                    self.server,
                    {"username": "newuser", "password": "another-pass", "is_admin": "0"},
                    admin_cookie,
                )
            ),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": admin_cookie},
        )
        self.request(
            "/admin/settings",
            method="POST",
            body=urlencode(
                with_csrf(
                    self.server, {"action": "appearance", "display_name": "Audit UI"}, admin_cookie
                )
            ),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": admin_cookie},
        )

        rows = database.db_audit_list(limit=50)
        actions = [(row["action"], row["outcome"]) for row in rows]
        for expected in (
            ("login", "failure"),
            ("login", "success"),
            ("token_create", "success"),
            ("token_revoke", "success"),
            ("user_create", "success"),
            ("settings_save", "success"),
        ):
            self.assertIn(expected, actions)
        self.assertTrue(any(row["action"] == "login" and row["actor"] == "auditor" for row in rows))
        serialized = json.dumps(rows)
        self.assertNotIn("s3cret-pass", serialized)
        self.assertNotIn("another-pass", serialized)

    def test_audit_can_be_disabled_without_losing_access_logs(self):
        self.start(require_auth=True, audit_log=False)
        database.db_create_user("nobody", "password", False)
        self.assertEqual(self.login("nobody", "wrong").__getitem__(0), 200)
        self.assertEqual(database.db_audit_list(), [])
        self.assertTrue(self.records("pygithost.access"))

    def test_logging_and_source_cleanup_documentation_are_accessible_in_page(self):
        repository = Path(self.server.project_root) / "example.git"
        subprocess.run(
            ["git", "init", "--bare", str(repository)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for guide, expected in (
            ("logging", "0 disables rotation"),
            ("http-runner", "ci_remote_source_cleanup"),
            ("ci-limits", "SQLite stores"),
        ):
            with self.subTest(guide=guide):
                status, _, body = self.request("/r/root/example/ci/docs?guide=" + guide)
                self.assertEqual(status, 200)
                self.assertIn(expected, body.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
