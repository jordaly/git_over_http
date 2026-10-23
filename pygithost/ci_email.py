"""Server-owned SMTP settings; job environments never receive credentials."""

import os
import json
import re
import smtplib
import ssl
from email.message import EmailMessage
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
    message["Subject"] = subject.replace("\r", " ").replace("\n", " ")
    text = f"Repository: {owner}/{repo}\nRun: #{run[0]}\nStatus: {run[4]}\nEvent: {run[1]}\nBranch: {run[2]}\nCommit: {run[3]}\nExit code: {run[7]}\n"
    base = settings["public_url"].rstrip("/")
    if base and run[1] != "test":
        text += f"\n{base}/r/{quote(owner, safe='')}/{quote(repo, safe='')}/ci/runs/{run[0]}\n"
    if run[1] == "test":
        message.replace_header("Subject", "[CI] SMTP test email")
        text = "This is a test email from pygithost. SMTP settings are working.\n"
    message.set_content(text)
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
