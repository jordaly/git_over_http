import unittest
from unittest import mock

from pygithost.ci_email import send_notification


class EmailPresentationTests(unittest.TestCase):
    def message(self, run, public_url="https://git.example.test/prefix"):
        settings = {"host": "smtp.example.test", "port": "587", "tls": "starttls",
                    "sender": "ci@example.test", "username": "", "password": "",
                    "public_url": public_url}
        with mock.patch("pygithost.ci_email.smtplib.SMTP") as smtp:
            smtp.return_value.send_message.return_value = {}
            send_notification("owner", "repo", run, ["dev@example.test"], settings)
            return smtp.return_value.send_message.call_args.args[0]

    def test_html_and_plaintext_metadata_only_with_escaped_values(self):
        run = (9, "manual", '<img src=x onerror="alert(1)">', "a" * 40, "success",
               "private log", 0, 0, "", "2026-01-01T12:00:00+00:00", "2026-01-01T12:01:05+00:00")
        message = self.message(run)
        self.assertEqual(message.get_content_type(), "multipart/alternative")
        plain = message.get_body(preferencelist=("plain",)).get_content()
        html = message.get_body(preferencelist=("html",)).get_content()
        self.assertIn("Status: success", plain)
        self.assertIn("Run passed", html)
        self.assertIn("1m 5s", html)
        self.assertIn("&lt;img", html)
        self.assertNotIn("<img", html)
        self.assertNotIn("private log", plain + html)
        self.assertIn('href="https://git.example.test/prefix/r/owner/repo/ci/runs/9"', html)
        self.assertEqual(message["Auto-Submitted"], "auto-generated")

    def test_failure_without_public_url_has_no_broken_button(self):
        message = self.message((9, "manual", "main", "a" * 40, "failed", "", 0, 1), public_url="")
        html = message.get_body(preferencelist=("html",)).get_content()
        self.assertIn("Run failed", html)
        self.assertIn("#b91c1c", html)
        self.assertNotIn("View run", html)
        self.assertIn("Configure a public server URL", html)

    def test_smtp_test_email_uses_same_design_without_fake_run_link(self):
        message = self.message((0, "test", "", "", "test", "", 0, None))
        self.assertEqual(message["Subject"], "[CI] SMTP test email")
        self.assertIn("SMTP settings are working", message.get_body(preferencelist=("plain",)).get_content())
        html = message.get_body(preferencelist=("html",)).get_content()
        self.assertIn("Email is connected", html)
        self.assertNotIn("/ci/runs/0", html)
