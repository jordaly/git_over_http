import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from unittest.mock import AsyncMock

from pygithost import database
from pygithost.application import GitHTTPHandler
from pygithost.ci import CIManager, validate_config
from pygithost.ci_email import load_settings, validate_settings


class EmailSettingsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = database.DB_PATH
        database.DB_PATH = str(Path(self.temp.name) / "test.db")
        database._db_init()
        self.handler = object.__new__(GitHTTPHandler)
        self.handler.server = SimpleNamespace()
        self.handler.request = SimpleNamespace()
        self.handler.remote_is_admin = True
        self.handler._forbidden = AsyncMock()
        self.settings = {"host": "smtp.example.test", "port": "587", "tls": "starttls", "sender": "ci@example.test", "username": "ci", "password": "private-password", "public_url": "https://git.example.test"}

    def tearDown(self):
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    async def post(self, form, test=False):
        self.handler._read_form_urlencoded = AsyncMock(return_value={**form, "csrf": self.handler._email_csrf_token()})
        with mock.patch("pygithost.application._send_response", new_callable=AsyncMock) as send:
            await self.handler._ui_admin_email_save(test=test)
        return send.await_args.args[2].decode()

    async def test_save_password_is_write_only_and_blank_preserves_it(self):
        page = await self.post(self.settings)
        self.assertIn("Email settings saved", page)
        self.assertNotIn("private-password", page)
        self.assertEqual(load_settings()["password"], "private-password")
        if os.name == "posix":
            self.assertEqual(Path(database.DB_PATH).stat().st_mode & 0o777, 0o600)
        page = await self.post({**self.settings, "password": "", "host": "new.example.test"})
        self.assertEqual(load_settings()["password"], "private-password")
        self.assertEqual(load_settings()["host"], "new.example.test")
        self.assertNotIn("private-password", page)
        await self.post({**self.settings, "password": "", "clear_password": "on"})
        self.assertEqual(load_settings()["password"], "")

    async def test_invalid_form_preserves_nonsecret_values_and_does_not_save(self):
        page = await self.post({**self.settings, "port": "0"})
        self.assertIn("SMTP port", page)
        self.assertIn("smtp.example.test", page)
        self.assertNotIn("private-password", page)
        self.assertIsNone(database.db_email_settings_get())

    async def test_nonadmins_cannot_view_save_or_send_test_email(self):
        self.handler.remote_is_admin = False
        self.handler._read_form_urlencoded = AsyncMock()
        with mock.patch("pygithost.application.REQUIRE_AUTH", True):
            await self.handler._ui_admin_email()
            await self.handler._ui_admin_email_save()
            await self.handler._ui_admin_email_save(test=True)
        self.assertEqual(self.handler._forbidden.await_count, 3)
        self.handler._read_form_urlencoded.assert_not_awaited()

    async def test_missing_csrf_token_blocks_saving_and_test_delivery(self):
        self.handler._read_form_urlencoded = AsyncMock(return_value=self.settings)
        with mock.patch("pygithost.application.send_notification") as send:
            await self.handler._ui_admin_email_save()
            await self.handler._ui_admin_email_save(test=True)
            send.assert_not_called()
        self.assertEqual(self.handler._forbidden.await_count, 2)
        self.assertIsNone(database.db_email_settings_get())
        self.handler._read_form_urlencoded = AsyncMock(return_value={"csrf": "非ASCII"})
        await self.handler._ui_admin_email_save()
        self.assertEqual(self.handler._forbidden.await_count, 3)

    async def test_web_settings_override_environment_and_initial_password_can_be_preserved(self):
        with mock.patch.dict(os.environ, {"PYGITHOST_SMTP_HOST": "environment.example.test", "PYGITHOST_SMTP_PASSWORD": "environment-password"}):
            self.assertEqual(load_settings()["host"], "environment.example.test")
            await self.post({**self.settings, "password": ""})
            self.assertEqual(load_settings()["host"], "smtp.example.test")
            self.assertEqual(load_settings()["password"], "environment-password")

    async def test_test_email_uses_saved_settings_and_failure_does_not_expose_secrets(self):
        database.db_email_settings_set(json.dumps(self.settings))
        with mock.patch("pygithost.application.send_notification") as send:
            page = await self.post({"recipient": "dev@example.test", "host": "ignored.example.test"}, test=True)
            self.assertIn("accepted by SMTP server", page)
            self.assertEqual(send.call_args.args[-1], self.settings)
            self.assertEqual(send.call_args.args[-2], ["dev@example.test"])
        with mock.patch("pygithost.application.send_notification", side_effect=OSError("private-password")):
            page = await self.post({"recipient": "dev@example.test"}, test=True)
            self.assertIn("Test email failed (OSError)", page)
            self.assertNotIn("private-password", page)

    async def test_admin_page_is_not_cacheable(self):
        database.db_email_settings_set(json.dumps(self.settings))
        with mock.patch("pygithost.application._send_response", new_callable=AsyncMock) as send:
            await self.handler._ui_admin_email()
        self.assertIn(("Cache-Control", "no-store"), send.await_args.args[3])
        self.assertNotIn("private-password", send.await_args.args[2].decode())

    async def test_ci_notification_uses_web_settings_without_restart(self):
        config = validate_config({"command": "echo hello", "email_mode": "all", "email_recipients": "dev@example.test"})
        run_id = database.db_ci_run_create("owner", "repo", "manual", "main", "a" * 40, "{}", json.dumps(config))
        database.db_ci_run_update(run_id, status="success")
        database.db_email_settings_set(json.dumps(self.settings))
        manager = CIManager(lambda *_: "")
        with mock.patch("pygithost.ci.send_notification") as send:
            await manager._notify((run_id, "owner", "repo", "manual", "main", "a" * 40, "{}"))
            self.assertEqual(send.call_args.args[-1], self.settings)
            database.db_email_settings_set(json.dumps({**self.settings, "host": "updated.example.test"}))
            await manager._notify((run_id, "owner", "repo", "manual", "main", "a" * 40, "{}"))
            self.assertEqual(send.call_args.args[-1]["host"], "updated.example.test")

    async def test_validation_rejects_unsafe_values(self):
        for change in ({"host": "smtp://host"}, {"sender": "a@b,b@c"}, {"tls": "none"}, {"port": "65536"}, {"public_url": "https://user:password@host"}, {"public_url": "javascript:alert(1)"}, {"password": "bad\nvalue"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_settings({**self.settings, **change})
