import json
import os
import shutil
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from unittest.mock import AsyncMock

from pygithost import database
from pygithost.application import GitHTTPHandler
from pygithost.ci import CIManager, validate_config
from pygithost.ci_email import load_settings, validate_settings, tls_context, send_notification


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
        self.settings = {"host": "smtp.example.test", "port": "587", "tls": "starttls", "sender": "ci@example.test", "username": "ci", "password": "private-password", "public_url": "https://git.example.test", "ca_cert": ""}

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
        page = await self.post({**self.settings, "password": "", "host": "new.example.test", "port": "2525"})
        self.assertEqual(load_settings()["password"], "private-password")
        self.assertEqual(load_settings()["host"], "new.example.test")
        self.assertEqual(load_settings()["port"], "2525")
        self.assertNotIn("private-password", page)
        await self.post({**self.settings, "password": "", "clear_password": "on"})
        self.assertEqual(load_settings()["password"], "")

    async def test_invalid_form_preserves_nonsecret_values_and_does_not_save(self):
        page = await self.post({**self.settings, "port": "0"})
        self.assertIn("SMTP port", page)
        self.assertIn("smtp.example.test", page)
        self.assertNotIn("private-password", page)
        self.assertIsNone(database.db_email_settings_get())

    async def test_trust_checkbox_is_explicit_persisted_and_can_be_unchecked(self):
        await self.post(self.settings)
        self.assertFalse(load_settings()["trust_server_cert"])
        page = await self.post({**self.settings, "trust_server_cert": "on"})
        self.assertTrue(load_settings()["trust_server_cert"])
        self.assertIn('name="trust_server_cert" checked', page)
        self.assertEqual(load_settings()["ca_cert"], "")
        await self.post(self.settings)
        self.assertFalse(load_settings()["trust_server_cert"])

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
        for change in ({"host": "smtp://host"}, {"sender": "a@b,b@c"}, {"tls": "none"}, {"port": "65536"}, {"public_url": "https://user:password@host"}, {"public_url": "javascript:alert(1)"}, {"password": "bad\nvalue"}, {"ca_cert": "not a certificate"}, {"ca_cert": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"}, {"ca_cert": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_settings({**self.settings, **change})

    async def test_trust_flag_requires_boolean_and_defaults_to_verified_tls(self):
        with self.assertRaises(ValueError):
            validate_settings({**self.settings, "trust_server_cert": "false"})
        context = tls_context(validate_settings(self.settings))
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    async def test_unverified_trust_applies_to_both_smtp_transports_without_pem(self):
        for mode, transport in (("starttls", "SMTP"), ("ssl", "SMTP_SSL")):
            with self.subTest(mode=mode), mock.patch(f"pygithost.ci_email.smtplib.{transport}") as smtp:
                smtp.return_value.send_message.return_value = {}
                settings = {**self.settings, "tls": mode, "trust_server_cert": True}
                send_notification("server", "email-test", (0, "test", "", "", "test", "", 0, None), ["dev@example.test"], settings)
                context = smtp.call_args.kwargs["context"] if mode == "ssl" else smtp.return_value.starttls.call_args.kwargs["context"]
                self.assertEqual(context.verify_mode, ssl.CERT_NONE)
                self.assertFalse(context.check_hostname)


@unittest.skipUnless(shutil.which("openssl"), "requires OpenSSL for a temporary self-signed certificate")
class TrustedCertificateTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.cert = str(Path(cls.temp.name) / "certificate.pem")
        cls.key = str(Path(cls.temp.name) / "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                        "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", cls.key, "-out", cls.cert], check=True, capture_output=True)
        cls.pem = Path(cls.cert).read_text()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def settings(self, **extra):
        return {"host": "localhost", "port": "587", "tls": "starttls", "sender": "ci@example.test", "ca_cert": self.pem, **extra}

    async def test_self_signed_certificate_can_be_trusted_without_disabling_verification(self):
        import asyncio

        context = tls_context(validate_settings(self.settings()))
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertIn(ssl.PEM_cert_to_DER_cert(self.pem), context.get_ca_certs(binary_form=True))
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(self.cert, self.key)

        async def connected(reader, writer):
            writer.write(b"trusted\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(connected, "127.0.0.1", 0, ssl=server_context)
        async with server:
            reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", server.sockets[0].getsockname()[1], ssl=context, server_hostname="localhost"), timeout=5)
            self.assertEqual(await reader.readline(), b"trusted\n")
            writer.close()
            await writer.wait_closed()

    async def test_both_smtp_transports_receive_the_custom_trust_context(self):
        run = (0, "test", "", "", "test", "", 0, None)
        for mode, transport in (("starttls", "SMTP"), ("ssl", "SMTP_SSL")):
            with self.subTest(mode=mode), mock.patch(f"pygithost.ci_email.smtplib.{transport}") as smtp:
                smtp.return_value.send_message.return_value = {}
                port = "2525" if mode == "starttls" else "1465"
                send_notification("server", "email-test", run, ["dev@example.test"], self.settings(tls=mode, port=port))
                self.assertEqual(smtp.call_args.args[1], int(port))
                context = smtp.call_args.kwargs["context"] if mode == "ssl" else smtp.return_value.starttls.call_args.kwargs["context"]
                self.assertTrue(context.check_hostname)
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                self.assertIn(ssl.PEM_cert_to_DER_cert(self.pem), context.get_ca_certs(binary_form=True))
