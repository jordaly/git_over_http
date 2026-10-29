"""Server-owned SMTP settings; job environments never receive credentials."""

import os
import json
import re
import smtplib
import ssl
from email.message import EmailMessage
from html import escape
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

from . import database


def environment_settings():
    mode = os.environ.get("PYGITHOST_SMTP_TLS", "starttls")
    return {"host": os.environ.get("PYGITHOST_SMTP_HOST", ""),
            "port": os.environ.get("PYGITHOST_SMTP_PORT", "465" if mode == "ssl" else "587"),
            "tls": mode, "sender": os.environ.get("PYGITHOST_SMTP_FROM", ""),
            "username": os.environ.get("PYGITHOST_SMTP_USERNAME", ""),
            "password": os.environ.get("PYGITHOST_SMTP_PASSWORD", ""),
            "public_url": os.environ.get("PYGITHOST_PUBLIC_URL", "")}


def load_settings():
    raw = database.db_email_settings_get()
    return json.loads(raw) if raw else environment_settings()


def validate_settings(raw):
    result = {}
    for key in ("host", "port", "tls", "sender", "username", "password", "public_url"):
        value = raw.get(key, "")
        if not isinstance(value, str) or len(value) > 8192 or any(c in value for c in ("\r", "\n", "\0")):
            raise ValueError(f"Invalid SMTP {key}.")
        result[key] = value if key == "password" else value.strip()
    certificate = raw.get("ca_cert", "")
    if not isinstance(certificate, str) or len(certificate) > 65536 or "\0" in certificate:
        raise ValueError("Trusted SMTP certificate must be PEM text up to 64 KiB.")
    result["ca_cert"] = certificate.strip()
    if result["ca_cert"]:
        if not re.fullmatch(r"(?:\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*)+", result["ca_cert"]):
            raise ValueError("Paste PEM certificates only, never a private key.")
        try:
            tls_context(result)
        except (ssl.SSLError, ValueError) as exc:
            raise ValueError("Trusted SMTP certificate is not a valid PEM certificate.") from exc
    trust_server_cert = raw.get("trust_server_cert", False)
    if not isinstance(trust_server_cert, bool):
        raise ValueError("Trust server certificate must be true or false.")
    result["trust_server_cert"] = trust_server_cert
    if not result["host"] or any(c.isspace() for c in result["host"]) or "://" in result["host"]:
        raise ValueError("Enter an SMTP hostname, not a URL.")
    if result["tls"] not in ("starttls", "ssl"):
        raise ValueError("SMTP TLS must be starttls or ssl.")
    if not result["port"].isascii() or not result["port"].isdigit() or not 1 <= int(result["port"]) <= 65535:
        raise ValueError("SMTP port must be between 1 and 65535.")
    if validate_recipients(result["sender"]) != [result["sender"]]:
        raise ValueError("SMTP sender must be one plain email address.")
    if result["public_url"]:
        url = urlsplit(result["public_url"])
        if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("Public URL must be an HTTP(S) URL without credentials, query, or fragment.")
    return result


def tls_context(settings):
    context = ssl.create_default_context()
    if settings.get("trust_server_cert", False):
        # Explicit admin opt-in, limited to this SMTP connection. TLS remains
        # required but no certificate chain, expiry, or hostname is verified.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if settings.get("ca_cert"):
        context.load_verify_locations(cadata=settings["ca_cert"])
    return context


def validate_recipients(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("Email recipients must be text up to 2048 characters.")
    addresses = [part.strip() for part in value.replace(",", "\n").splitlines() if part.strip()]
    if len(addresses) > 20 or any(not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", address) for address in addresses):
        raise ValueError("Enter at most 20 plain email addresses, one per line.")
    return list(dict.fromkeys(addresses))


def _notification_html(owner, repo, run, url):
    """Self-contained email markup; interpolate escaped metadata only."""
    is_test = run[1] == "test"
    title, color, background = {
        "success": ("Run passed", "#047857", "#ecfdf5"),
        "failed": ("Run failed", "#b91c1c", "#fef2f2"),
        "timed_out": ("Run timed out", "#b45309", "#fffbeb"),
        "interrupted": ("Run interrupted", "#475569", "#f1f5f9"),
        "cancelled": ("Run cancelled", "#475569", "#f1f5f9"),
        "test": ("Email is connected", "#0369a1", "#f0f9ff"),
    }.get(run[4], ("CI run update", "#475569", "#f1f5f9"))
    if run[1] == "deployment":
        title = {"success": "Deployment succeeded", "failed": "Deployment failed",
                 "timed_out": "Deployment timed out", "interrupted": "Deployment interrupted"}.get(run[4], "Deployment update")
    subtitle = "SMTP settings are working. CI notifications are ready to send." if is_test else f"{owner}/{repo} · Run #{run[0]}"
    rows = []
    if not is_test:
        fields = [("Repository", f"{owner}/{repo}"), ("Run", f"#{run[0]}"),
                  ("Branch", run[2] or "—"), ("Commit", run[3] or "—"),
                  ("Event", run[1].replace("_", " ")),
                  ("Exit code", run[7] if run[7] is not None else "—")]
        if len(run) > 10 and run[9] and run[10]:
            try:
                start = datetime.fromisoformat(run[9])
                end = datetime.fromisoformat(run[10])
                if start.tzinfo is None:
                    start = start.replace(tzinfo=timezone.utc)
                if end.tzinfo is None:
                    end = end.replace(tzinfo=timezone.utc)
                seconds = max(0, int((end - start).total_seconds()))
                fields.append(("Duration", f"{seconds // 60}m {seconds % 60}s"))
            except ValueError:
                pass
        for label, value in fields:
            rows.append(f'<tr><th scope="row" align="left" valign="top" style="width:100px;padding:12px 0;border-bottom:1px solid #e2e8f0;color:#64748b;font-size:12px;font-weight:500;">{escape(label)}</th>'
                        f'<td style="padding:12px 0;border-bottom:1px solid #e2e8f0;color:#0f172a;font-size:13px;line-height:1.6;word-break:break-all;">{escape(str(value))}</td></tr>')
    action = ""
    if url and not is_test:
        safe_url = escape(url, quote=True)
        action = f'<p style="margin:28px 0 12px;"><a href="{safe_url}" style="display:inline-block;padding:13px 22px;border-radius:8px;background:#0f172a;color:#ffffff;font-size:13px;font-weight:600;text-decoration:none;">View run &rarr;</a></p><p style="font-size:11px;line-height:1.7;word-break:break-all;color:#64748b;">Or open <a href="{safe_url}" style="color:#0369a1;">{safe_url}</a></p>'
    elif not is_test:
        action = '<p style="font-size:12px;line-height:1.7;color:#64748b;">Open this repository\'s CI page to view the run. Configure a public server URL in Email settings to include direct links.</p>'
    details = '<table role="presentation" width="100%" cellspacing="0" cellpadding="0">' + "".join(rows) + "</table>" if rows else '<p style="font-size:14px;line-height:1.8;color:#475569;">This is a test email from pygithost. No action is required.</p>'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{escape(title)}</title></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f1f5f9;"><tr><td align="center" style="padding:32px 16px;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:580px;"><tr><td style="padding:0 0 18px;font-size:12px;font-weight:700;letter-spacing:1px;color:#475569;">PYGITHOST <span style="font-weight:400;color:#94a3b8;">/ CONTINUOUS INTEGRATION</span></td></tr>
<tr><td style="background:#ffffff;border:1px solid #e2e8f0;border-top:4px solid {color};border-radius:12px;padding:28px;">
<span style="display:inline-block;background:{background};color:{color};padding:6px 10px;border-radius:6px;font-size:11px;font-weight:700;letter-spacing:.5px;">{escape("SMTP TEST" if is_test else run[4].replace("_", " ").upper())}</span>
<h1 style="margin:18px 0 8px;font-size:26px;letter-spacing:-.5px;line-height:1.3;color:#0f172a;">{escape(title)}</h1>
<p style="margin:0 0 24px;color:#64748b;font-size:14px;line-height:1.7;word-break:break-word;">{escape(subtitle)}</p>
{details}{action}</td></tr>
<tr><td style="padding:18px 4px;font-size:11px;line-height:1.8;color:#64748b;">Sent by pygithost CI. Notifications contain run metadata only, never commands, logs, or environment values.</td></tr></table>
</td></tr></table></body></html>'''


def send_notification(owner, repo, run, recipients, settings=None):
    """Send a bounded metadata-only message. No commands, environment, or logs."""
    settings = validate_settings(settings if settings is not None else environment_settings())
    host = settings["host"]
    sender = settings["sender"]
    if not host or not sender:
        raise ValueError("SMTP host and sender are not configured")
    if len(validate_recipients(sender)) != 1:
        raise ValueError("SMTP sender must be one address")
    mode = settings["tls"]
    if mode not in ("starttls", "ssl"):
        raise ValueError("SMTP TLS must be starttls or ssl")
    port = int(settings["port"])
    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    # Branch names and repository names are not trusted email header content.
    subject = f"[CI] {owner}/{repo} #{run[0]}: {run[4]}"
    if run[1] == "deployment":
        subject = f"[Deployment] {owner}/{repo} #{run[0]}: {run[4]}"
    message["Subject"] = subject.replace("\r", " ").replace("\n", " ")
    text = f"Repository: {owner}/{repo}\nRun: #{run[0]}\nStatus: {run[4]}\nEvent: {run[1]}\nBranch: {run[2]}\nCommit: {run[3]}\nExit code: {run[7]}\n"
    base = settings["public_url"].rstrip("/")
    url = ""
    if base and run[1] != "test":
        url = f"{base}/r/{quote(owner, safe='')}/{quote(repo, safe='')}/ci/runs/{run[0]}"
        text += f"\n{url}\n"
    if run[1] == "test":
        message.replace_header("Subject", "[CI] SMTP test email")
        text = "This is a test email from pygithost. SMTP settings are working.\n"
    message.set_content(text)
    message.add_alternative(_notification_html(owner, repo, run, url), subtype="html")
    message["Auto-Submitted"] = "auto-generated"
    context = tls_context(settings)
    client = smtplib.SMTP_SSL(host, port, timeout=15, context=context) if mode == "ssl" else smtplib.SMTP(host, port, timeout=15)
    with client:
        if mode == "starttls":
            client.ehlo()
            client.starttls(context=context)
            client.ehlo()
        username = settings["username"]
        if username:
            client.login(username, settings["password"])
        refused = client.send_message(message)
        if refused:
            raise smtplib.SMTPException("Some recipients were refused")
