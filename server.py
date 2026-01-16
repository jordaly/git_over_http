#!/usr/bin/env python3
import os
import sys
import threading
import subprocess
import ipaddress
import platform
import base64
import re
import html
import sqlite3
import secrets
import hashlib
import hmac
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs, unquote

# ============================================================
# CONFIG
# ============================================================
HOST = ""   # bind all interfaces
PORT = 8000

CURRENT_PLATFORM = platform.system()

if CURRENT_PLATFORM == "Windows":
    GIT_PROJECT_ROOT = r"C:\Servidor_Git"
    GIT_HTTP_BACKEND = r"C:\Program Files\Git\mingw64\libexec\git-core\git-http-backend.exe"
    TRACE_LOG = r"C:\temp\git-http-backend.log"
    DB_PATH = r"C:\temp\pygithost.db"

elif CURRENT_PLATFORM == "Linux":
    GIT_PROJECT_ROOT = "/home/jordaly/git_repos"
    GIT_HTTP_BACKEND = "/usr/lib/git-core/git-http-backend"
    TRACE_LOG = None
    DB_PATH = str(Path.home() / ".local/share/pygithost/pygithost.db")

elif CURRENT_PLATFORM == "Darwin":
    git_project_path = Path.home() / "git"
    git_project_path.mkdir(exist_ok=True)
    GIT_PROJECT_ROOT = str(git_project_path)
    GIT_HTTP_BACKEND = "/opt/homebrew/opt/git/libexec/git-core/git-http-backend"
    TRACE_LOG = "/tmp/git-http-backend.log"
    DB_PATH = str(Path.home() / ".local/share/pygithost/pygithost.db")

else:
    raise NotImplementedError()

URL_PREFIX = "/git"
ALLOWED_CLIENT_IPS = {"127.0.0.1"}  # add CIDRs if needed

REQUIRE_AUTH = True
REALM = "Git Repositories"

FLAT_OWNER_UI = "root"

# ============================================================
# HELPERS: validation / permissions
# ============================================================
SAFE_SEG = re.compile(r"^[A-Za-z0-9._-]+$")


def _safe_seg(s: str) -> bool:
    return bool(s) and SAFE_SEG.match(s) and ".." not in s and "/" not in s and "\\" not in s


def _safe_branch_name(name: str) -> bool:
    if not name:
        return False
    if name.startswith("/") or name.endswith("/"):
        return False
    if name.startswith("-"):
        return False
    if "\\" in name:
        return False
    if any(c in name for c in [" ", "\t", "\n", "\r"]):
        return False
    if ".." in name or "//" in name:
        return False
    if name.endswith(".lock"):
        return False
    for ch in name:
        ok = (
            ("a" <= ch <= "z")
            or ("A" <= ch <= "Z")
            or ("0" <= ch <= "9")
            or ch in "._-/"
        )
        if not ok:
            return False
    return True


def _has_write_scope(handler) -> bool:
    scopes = getattr(handler, "remote_scopes", set()) or set()
    if getattr(handler, "remote_is_admin", False):
        return True
    return "write" in {s.lower() for s in scopes}


def _require_admin(handler) -> bool:
    return bool(getattr(handler, "remote_is_admin", False))


# ============================================================
# HELPERS: DB (SQLite)
# ============================================================
def _ensure_dir(path: str):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def _db_connect() -> sqlite3.Connection:
    _ensure_dir(DB_PATH)
    conn = sqlite3.connect(DB_PATH, timeout=5, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def _db_init():
    conn = _db_connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                pass_salt BLOB NOT NULL,
                pass_hash BLOB NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                token_hash BLOB NOT NULL,
                scopes TEXT NOT NULL DEFAULT 'read,write',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash)")
    finally:
        conn.close()


def _pbkdf2_hash_password(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def _token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def db_create_user(username: str, password: str, is_admin: bool = False) -> None:
    if not _safe_seg(username):
        raise ValueError("Invalid username format.")
    salt = secrets.token_bytes(16)
    ph = _pbkdf2_hash_password(password, salt)
    conn = _db_connect()
    try:
        conn.execute(
            "INSERT INTO users(username, pass_salt, pass_hash, is_admin, is_active) VALUES(?,?,?,?,1)",
            (username, salt, ph, 1 if is_admin else 0),
        )
    finally:
        conn.close()


def db_get_user_by_username(username: str):
    conn = _db_connect()
    try:
        cur = conn.execute(
            "SELECT id, username, pass_salt, pass_hash, is_admin, is_active FROM users WHERE username=?",
            (username,),
        )
        return cur.fetchone()
    finally:
        conn.close()


def db_get_user_by_id(user_id: int):
    conn = _db_connect()
    try:
        cur = conn.execute(
            "SELECT id, username, is_admin, is_active, created_at FROM users WHERE id=?",
            (user_id,),
        )
        return cur.fetchone()
    finally:
        conn.close()


def db_list_users():
    conn = _db_connect()
    try:
        cur = conn.execute(
            "SELECT id, username, is_admin, is_active, created_at FROM users ORDER BY username COLLATE NOCASE"
        )
        return cur.fetchall()
    finally:
        conn.close()


def db_set_user_active(user_id: int, is_active: bool) -> None:
    conn = _db_connect()
    try:
        conn.execute("UPDATE users SET is_active=? WHERE id=?", (1 if is_active else 0, user_id))
    finally:
        conn.close()


def db_set_user_admin(user_id: int, is_admin: bool) -> None:
    conn = _db_connect()
    try:
        conn.execute("UPDATE users SET is_admin=? WHERE id=?", (1 if is_admin else 0, user_id))
    finally:
        conn.close()


def db_reset_password(user_id: int, new_password: str) -> None:
    salt = secrets.token_bytes(16)
    ph = _pbkdf2_hash_password(new_password, salt)
    conn = _db_connect()
    try:
        conn.execute("UPDATE users SET pass_salt=?, pass_hash=? WHERE id=?", (salt, ph, user_id))
    finally:
        conn.close()


def db_verify_password(username: str, password: str):
    row = db_get_user_by_username(username)
    if not row:
        return None
    uid, uname, salt, ph, is_admin, is_active = row
    if not is_active:
        return None
    computed = _pbkdf2_hash_password(password, salt)
    if hmac.compare_digest(computed, ph):
        return {
            "user_id": uid,
            "username": uname,
            "is_admin": bool(is_admin),
            "scopes": {"read", "write"},  # password login => full by default
        }
    return None


def db_create_token(user_id: int, name: str, scopes: str = "read,write") -> str:
    token = secrets.token_urlsafe(32)
    th = _token_hash(token)
    conn = _db_connect()
    try:
        conn.execute(
            "INSERT INTO tokens(user_id, name, token_hash, scopes, is_active) VALUES(?,?,?,?,1)",
            (user_id, name, th, scopes),
        )
    finally:
        conn.close()
    return token


def db_verify_token(username: str, token: str):
    user = db_get_user_by_username(username)
    if not user:
        return None
    uid, uname, _salt, _ph, is_admin, is_active = user
    if not is_active:
        return None

    th = _token_hash(token)
    conn = _db_connect()
    try:
        cur = conn.execute(
            "SELECT scopes, is_active FROM tokens WHERE user_id=? AND token_hash=? LIMIT 1",
            (uid, th),
        )
        row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        return None
    scopes, token_active = row
    if not token_active:
        return None

    scopes_set = {s.strip().lower() for s in (scopes or "").split(",") if s.strip()}
    return {"user_id": uid, "username": uname, "is_admin": bool(is_admin), "scopes": scopes_set}


def db_ensure_default_admin():
    conn = _db_connect()
    try:
        cur = conn.execute("SELECT COUNT(*) FROM users")
        count = int(cur.fetchone()[0])
    finally:
        conn.close()

    if count == 0:
        print("[DB] No users found. Creating default admin user: admin / admin")
        db_create_user("admin", "admin", is_admin=True)
        u = db_get_user_by_username("admin")
        if u:
            token = db_create_token(u[0], "default", scopes="read,write,admin")
            print(f"[DB] Default admin token (save it now): {token}")


# ============================================================
# HELPERS: repos + git + HTTP
# ============================================================
def _is_bare_repo_dir(p: Path) -> bool:
    return p.is_dir() and (p / "HEAD").is_file()


def _scan_repos(project_root: str) -> list[tuple[str, str, str]]:
    root = Path(project_root)
    results: list[tuple[str, str, str]] = []
    if not root.exists():
        return results

    for p in sorted(root.glob("*.git")):
        if _is_bare_repo_dir(p):
            repo = p.name[:-4]
            results.append((FLAT_OWNER_UI, repo, p.name))

    for owner_dir in sorted([x for x in root.iterdir() if x.is_dir()]):
        owner = owner_dir.name
        for p in sorted(owner_dir.glob("*.git")):
            if _is_bare_repo_dir(p):
                repo = p.name[:-4]
                rel = f"{owner}/{p.name}"
                results.append((owner, repo, rel))

    seen = set()
    uniq = []
    for o, r, rel in results:
        key = (o, r, rel)
        if key not in seen:
            seen.add(key)
            uniq.append((o, r, rel))
    return uniq


def _repo_bare_path(owner_ui: str, repo: str) -> str:
    if owner_ui == FLAT_OWNER_UI:
        return os.path.join(GIT_PROJECT_ROOT, repo + ".git")
    return os.path.join(GIT_PROJECT_ROOT, owner_ui, repo + ".git")


def _run_git(repo_git_dir: str, args: list[str]) -> tuple[int, bytes, bytes]:
    cmd = ["git", f"--git-dir={repo_git_dir}"] + args
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    return p.returncode, out, err


def _run_cmd(cmd: list[str], cwd: str | None = None) -> tuple[int, bytes, bytes]:
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    return p.returncode, out, err


def _git_default_branch(repo_git: str) -> str:
    code, out, _ = _run_git(repo_git, ["symbolic-ref", "HEAD"])
    if code == 0:
        head = out.decode("utf-8", "replace").strip()
        if head.startswith("refs/heads/"):
            return head[len("refs/heads/") :]
    return "main"


def _git_list_branches(repo_git: str) -> list[str]:
    code, out, _ = _run_git(repo_git, ["for-each-ref", "refs/heads", "--format=%(refname:short)"])
    if code != 0:
        return []
    branches = [ln.strip() for ln in out.decode("utf-8", "replace").splitlines() if ln.strip()]
    branches.sort(key=lambda s: s.lower())
    return branches


def _git_resolve_commit(repo_git: str, refish: str) -> str | None:
    code, out, _ = _run_git(repo_git, ["rev-parse", "--verify", refish + "^{commit}"])
    if code != 0:
        return None
    return out.decode("utf-8", "replace").strip()


def _git_create_branch(repo_git: str, new_branch: str, from_ref: str) -> tuple[bool, str]:
    commit = _git_resolve_commit(repo_git, from_ref)
    if not commit:
        return False, f"Could not resolve '{from_ref}' to a commit."
    existing = _git_resolve_commit(repo_git, f"refs/heads/{new_branch}")
    if existing:
        return False, "Branch already exists."
    code, _out, err = _run_git(repo_git, ["update-ref", f"refs/heads/{new_branch}", commit])
    if code != 0:
        return False, err.decode("utf-8", "replace").strip() or "git update-ref failed."
    return True, "Branch created."


def _git_delete_branch(repo_git: str, branch: str) -> tuple[bool, str]:
    code, _out, err = _run_git(repo_git, ["update-ref", "-d", f"refs/heads/{branch}"])
    if code != 0:
        return False, err.decode("utf-8", "replace").strip() or "git update-ref -d failed."
    return True, "Branch deleted."




# helper functions for seen commits content
def _git_commit_meta(repo_git: str, commit: str) -> dict[str, str] | None:
    # NUL-separated to safely capture multiline fields
    fmt = "%H%x00%P%x00%an%x00%ae%x00%ad%x00%s%x00%b"
    code, out, _ = _run_git(repo_git, ["show", "-s", "--date=iso", f"--format={fmt}", commit])
    if code != 0:
        return None
    parts = out.decode("utf-8", "replace").split("\x00")
    if len(parts) < 7:
        return None
    return {
        "hash": parts[0].strip(),
        "parents": parts[1].strip(),
        "author_name": parts[2].strip(),
        "author_email": parts[3].strip(),
        "date": parts[4].strip(),
        "subject": parts[5].strip(),
        "body": parts[6].rstrip(),
    }


def _git_commit_name_status(repo_git: str, commit: str) -> list[tuple[str, str]]:
    # returns [("M","path"), ("A","path"), ("D","path"), ("R100","old -> new"), ...]
    code, out, _ = _run_git(repo_git, ["show", "--name-status", "--format=", commit])
    if code != 0:
        return []
    rows = []
    for ln in out.decode("utf-8", "replace").splitlines():
        ln = ln.rstrip("\n")
        if not ln.strip():
            continue
        # name-status lines are tab separated
        parts = ln.split("\t")
        if len(parts) >= 2:
            status = parts[0].strip()
            path = parts[-1].strip()  # for renames, last is new path
            rows.append((status, path))
    return rows


def _git_commit_patch(repo_git: str, commit: str, max_bytes: int = 600_000) -> tuple[str, bool]:
    # Return patch text, and whether it was truncated
    code, out, _ = _run_git(repo_git, ["show", "--no-color", "--format=", commit])
    if code != 0:
        return "Could not render patch.", False
    if len(out) > max_bytes:
        return out[:max_bytes].decode("utf-8", "replace") + "\n\n[... truncated ...]\n", True
    return out.decode("utf-8", "replace"), False


def _ip_allowed(ip: str, allow: set[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not allow:
        return False
    for item in allow:
        try:
            if addr in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            try:
                if ipaddress.ip_address(item) == addr:
                    return True
            except ValueError:
                if item == ip:
                    return True
    return False


def _write_request_body_to_stdin(handler: BaseHTTPRequestHandler, proc: subprocess.Popen, content_len: int):
    remaining = content_len
    CHUNK = 65536
    try:
        while remaining > 0:
            to_read = CHUNK if remaining > CHUNK else remaining
            data = handler.rfile.read(to_read)
            if not data:
                break
            proc.stdin.write(data)
            remaining -= len(data)
        proc.stdin.flush()
    except Exception:
        pass
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass


def _read_form_urlencoded(handler: BaseHTTPRequestHandler) -> dict[str, str]:
    clen = int(handler.headers.get("Content-Length") or 0)
    if clen <= 0:
        return {}
    raw = handler.rfile.read(clen)
    text = raw.decode("utf-8", "replace")
    qs = parse_qs(text, keep_blank_values=True)
    return {k: (v[0] if v else "") for k, v in qs.items()}


def _html_page(title: str, body_html: str) -> bytes:
    return (
        f"<!doctype html><html><head><meta charset='utf-8'>"
        f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        f"<style>"
        f"body{{font-family:system-ui,Segoe UI,Arial;margin:24px;max-width:1200px}}"
        f"a{{text-decoration:none}} a:hover{{text-decoration:underline}}"
        f"code,pre{{font-family:ui-monospace,Consolas,monospace}}"
        f"pre{{padding:12px;border:1px solid #ddd;border-radius:10px;overflow:auto;background:#fafafa}}"
        f"table{{border-collapse:collapse;width:100%}}"
        f"td{{padding:8px 10px;border-bottom:1px solid #eee;vertical-align:top}}"
        f".muted{{color:#666}}"
        f".pill{{display:inline-block;padding:2px 10px;border:1px solid #ddd;border-radius:999px;"
        f"font-size:12px;color:#444;background:#fff}}"
        f".topbar{{display:flex;gap:12px;align-items:center;justify-content:space-between;margin-bottom:16px}}"
        f".box{{border:1px solid #eee;border-radius:14px;padding:14px;background:#fff}}"
        f".row{{display:flex;gap:10px;flex-wrap:wrap;align-items:end}}"
        f"label{{display:block;font-size:12px;color:#555;margin-bottom:4px}}"
        f"input,select{{padding:10px;border:1px solid #ddd;border-radius:10px;font-size:14px}}"
        f"button{{padding:10px 14px;border:1px solid #111;border-radius:10px;background:#111;color:#fff;cursor:pointer}}"
        f"button:hover{{opacity:.92}}"
        f".danger{{border-color:#7f1d1d;background:#7f1d1d}}"
        f".danger:hover{{opacity:.92}}"
        f".warn{{background:#fff7ed;border:1px solid #fed7aa;color:#9a3412;padding:10px;border-radius:12px}}"
        f".ok{{background:#ecfdf5;border:1px solid #a7f3d0;color:#065f46;padding:10px;border-radius:12px}}"
        f"</style></head><body>{body_html}</body></html>"
    ).encode("utf-8")


def _send_html(handler: BaseHTTPRequestHandler, status: int, body: bytes):
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.wfile.write(body)
    handler.wfile.flush()
    handler.close_connection = True


def _send_text(handler: BaseHTTPRequestHandler, status: int, text: str):
    body = text.encode("utf-8", "replace")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.wfile.write(body)
    handler.wfile.flush()
    handler.close_connection = True


# ============================================================
# SERVER
# ============================================================
class GitHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _client_ip(self) -> str:
        ip = self.client_address[0]
        if ip == "::1":
            return "127.0.0.1"
        return ip

    def _allowlist(self) -> set[str]:
        return getattr(self.server, "allowlist", ALLOWED_CLIENT_IPS)

    # -------- AUTH: accept token OR password --------
    def _require_auth(self) -> bool:
        if not REQUIRE_AUTH:
            return True

        auth_header = self.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Basic "):
            return self._request_auth()

        try:
            decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode("utf-8")
            username, secret = decoded.split(":", 1)
        except Exception:
            return self._request_auth()

        if not _safe_seg(username):
            return self._request_auth()

        info = db_verify_token(username, secret)
        if not info:
            info = db_verify_password(username, secret)

        if info:
            self.remote_user = info["username"]
            self.remote_user_id = info["user_id"]
            self.remote_is_admin = bool(info.get("is_admin"))
            self.remote_scopes = info.get("scopes", {"read"})
            return True

        return self._request_auth()

    def _request_auth(self) -> bool:
        body = b"Authentication required.\n"
        self.send_response(401, "Unauthorized")
        self.send_header("WWW-Authenticate", f'Basic realm="{REALM}"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except Exception:
            pass
        finally:
            self.close_connection = True
        return False

    def _forbidden(self, msg=b"403 Forbidden\n"):
        _send_text(self, 403, msg.decode("utf-8", "replace"))

    def _not_found(self):
        _send_text(self, 404, "404 Not Found\n")

    # ========================================================
    # UI: Home / Tokens / Create Repo
    # ========================================================
    def _ui_home(self, notice: str = "", notice_kind: str = "ok"):
        repos = _scan_repos(GIT_PROJECT_ROOT)

        rows = []
        for owner, repo, rel in repos:
            rows.append(
                f"<tr>"
                f"<td><a href='/r/{html.escape(owner)}/{html.escape(repo)}'>"
                f"{html.escape(owner)}/{html.escape(repo)}</a></td>"
                f"<td class='muted'><code>{html.escape(rel)}</code></td>"
                f"</tr>"
            )

        notice_html = ""
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = f"<div class='{cls}' style='margin-bottom:12px'>{html.escape(notice)}</div>"

        admin_link = ""
        if _require_admin(self):
            admin_link = "<a class='pill' href='/admin/users'>Admin: Users</a>"

        body = _html_page(
            "Repos",
            f"<div class='topbar'>"
            f"<h1 style='margin:0'>Repos</h1>"
            f"<div>"
            f"{admin_link} "
            f"<span class='pill'>User: <code>{html.escape(getattr(self, 'remote_user', '?'))}</code></span>"
            "<a class='pill' href='/logout'>Logout</a>"
            f"</div>"
            f"</div>"
            f"{notice_html}"
            f"<div class='box' style='margin-bottom:14px'>"
            f"<h2 style='margin:0 0 10px 0;font-size:16px'>Create repository</h2>"
            f"<form method='POST' action='/create-repo'>"
            f"<div class='row'>"
            f"<div><label>Owner (optional)</label>"
            f"<input name='owner' placeholder='{html.escape(FLAT_OWNER_UI)} for flat layout' /></div>"
            f"<div><label>Repo name</label>"
            f"<input name='repo' placeholder='my-repo' required /></div>"
            f"<div><button type='submit'>Create</button></div>"
            f"</div>"
            f"<p class='muted' style='margin:10px 0 0 0'>Create requires <code>write</code> scope.</p>"
            f"</form>"
            f"</div>"
            f"<div class='box' style='margin-bottom:14px'>"
            f"<h2 style='margin:0 0 10px 0;font-size:16px'>Tokens</h2>"
            f"<p class='muted'>Generate a new token for your user.</p>"
            f"<form method='POST' action='/admin/token'>"
            f"<div class='row'>"
            f"<div><label>Token name</label><input name='name' placeholder='laptop' required /></div>"
            f"<div><label>Scopes</label><input name='scopes' placeholder='read,write' value='read,write' /></div>"
            f"<div><button type='submit'>Generate</button></div>"
            f"</div>"
            f"</form>"
            f"</div>"
            f"<div class='box'>"
            f"<p class='muted'>GIT_PROJECT_ROOT: <code>{html.escape(GIT_PROJECT_ROOT)}</code></p>"
            f"<table>{''.join(rows) if rows else '<tr><td class=muted>No bare repos found.</td><td></td></tr>'}</table>"
            f"</div>"
        )
        _send_html(self, 200, body)

    def _ui_show_token(self, token: str):
        body = _html_page(
            "Token created",
            f"<div class='ok'>Token created. Copy it now (it won’t be shown again).</div>"
            f"<pre><code>{html.escape(token)}</code></pre>"
            f"<p><a class='pill' href='/'>Back</a></p>",
        )
        _send_html(self, 200, body)

    def _ui_create_token(self):
        form = _read_form_urlencoded(self)
        name = (form.get("name") or "").strip()
        scopes = (form.get("scopes") or "read,write").strip() or "read,write"
        if not name:
            return self._ui_home("Token name is required.", "warn")
        token = db_create_token(int(self.remote_user_id), name, scopes=scopes)
        return self._ui_show_token(token)

    def _ui_create_repo(self):
        if not _has_write_scope(self):
            return self._ui_home("You need write scope to create repos.", "warn")

        form = _read_form_urlencoded(self)
        owner = (form.get("owner") or "").strip()
        repo = (form.get("repo") or "").strip()

        owner_ui = FLAT_OWNER_UI if (not owner or owner == FLAT_OWNER_UI) else owner

        if owner_ui != FLAT_OWNER_UI and not _safe_seg(owner_ui):
            return self._ui_home("Invalid owner name.", "warn")
        if not _safe_seg(repo):
            return self._ui_home("Invalid repo name.", "warn")

        repo_git = _repo_bare_path(owner_ui, repo)

        try:
            if owner_ui == FLAT_OWNER_UI:
                os.makedirs(GIT_PROJECT_ROOT, exist_ok=True)
            else:
                os.makedirs(os.path.join(GIT_PROJECT_ROOT, owner_ui), exist_ok=True)
        except Exception as e:
            return self._ui_home(f"Failed to create owner folder: {e}", "warn")

        if os.path.exists(repo_git):
            return self._ui_home("Repo already exists.", "warn")

        code, out, err = _run_cmd(["git", "init", "--bare", repo_git])
        if code != 0:
            msg = err.decode("utf-8", "replace").strip() or out.decode("utf-8", "replace").strip()
            return self._ui_home(f"git init --bare failed: {msg}", "warn")

        return self._ui_home(f"Repo created: {owner_ui}/{repo}", "ok")

    # ========================================================
    # UI: Admin Users (create users + reset passwords)
    # ========================================================
    def _ui_admin_users(self, notice: str = "", notice_kind: str = "ok"):
        if not _require_admin(self):
            return self._forbidden(b"403 Forbidden: admin only.\n")

        notice_html = ""
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = f"<div class='{cls}' style='margin-bottom:12px'>{html.escape(notice)}</div>"

        users = db_list_users()
        rows = []

        for uid, uname, is_admin, is_active, created_at in users:
            pill_admin = "<span class='pill'>admin</span>" if is_admin else "<span class='pill muted'>user</span>"
            pill_active = "<span class='pill'>active</span>" if is_active else "<span class='pill muted'>disabled</span>"

            toggle_label = "Disable" if is_active else "Enable"
            toggle_btn_class = "danger" if is_active else ""

            # do not allow disabling yourself in UI? (optional)
            disable_self_guard = ""
            if int(uid) == int(getattr(self, "remote_user_id", -1)):
                disable_self_guard = "<span class='muted'> (you)</span>"

            rows.append(
                f"<tr>"
                f"<td><code>{html.escape(uname)}</code> {pill_admin} {pill_active}{disable_self_guard}</td>"
                f"<td class='muted'>{html.escape(str(created_at))}</td>"
                f"<td style='text-align:right'>"
                f"<form method='POST' action='/admin/users/toggle' style='display:inline'>"
                f"<input type='hidden' name='user_id' value='{uid}'/>"
                f"<input type='hidden' name='make_active' value='{0 if is_active else 1}'/>"
                f"<button type='submit' class='{toggle_btn_class}'>{toggle_label}</button>"
                f"</form>"
                f"</td>"
                f"</tr>"
            )

        # user dropdown for password reset
        options = []
        for uid, uname, _is_admin, _is_active, _created_at in users:
            options.append(f"<option value='{uid}'>{html.escape(uname)}</option>")

        body = _html_page(
            "Admin · Users",
            f"<div class='topbar'>"
            f"<h1 style='margin:0'>Admin · Users</h1>"
            f"<div><a class='pill' href='/'>Home</a></div>"
            f"</div>"
            f"{notice_html}"
            f"<div class='box' style='margin-bottom:14px'>"
            f"<h2 style='margin:0 0 10px 0;font-size:16px'>Create user</h2>"
            f"<form method='POST' action='/admin/users/create'>"
            f"<div class='row'>"
            f"<div><label>Username</label><input name='username' placeholder='john' required /></div>"
            f"<div><label>Password</label><input name='password' type='password' placeholder='••••••••' required /></div>"
            f"<div><label>Admin?</label>"
            f"<select name='is_admin'>"
            f"<option value='0' selected>No</option>"
            f"<option value='1'>Yes</option>"
            f"</select></div>"
            f"<div><button type='submit'>Create</button></div>"
            f"</div>"
            f"</form>"
            f"</div>"
            f"<div class='box' style='margin-bottom:14px'>"
            f"<h2 style='margin:0 0 10px 0;font-size:16px'>Reset password</h2>"
            f"<form method='POST' action='/admin/users/reset'>"
            f"<div class='row'>"
            f"<div><label>User</label><select name='user_id'>{''.join(options)}</select></div>"
            f"<div><label>New password</label><input name='new_password' type='password' required /></div>"
            f"<div><button type='submit'>Reset</button></div>"
            f"</div>"
            f"</form>"
            f"</div>"
            f"<div class='box'>"
            f"<h2 style='margin:0 0 10px 0;font-size:16px'>All users</h2>"
            f"<table>{''.join(rows) if rows else '<tr><td class=muted>No users.</td></tr>'}</table>"
            f"</div>",
        )
        _send_html(self, 200, body)

    def _ui_admin_users_create(self):
        if not _require_admin(self):
            return self._forbidden(b"403 Forbidden: admin only.\n")

        form = _read_form_urlencoded(self)
        username = (form.get("username") or "").strip()
        password = (form.get("password") or "").strip()
        is_admin = (form.get("is_admin") or "0").strip() == "1"

        if not _safe_seg(username):
            return self._ui_admin_users("Invalid username (use letters/numbers/._-).", "warn")
        if len(password) < 4:
            return self._ui_admin_users("Password too short (min 4).", "warn")

        try:
            db_create_user(username, password, is_admin=is_admin)
        except sqlite3.IntegrityError:
            return self._ui_admin_users("User already exists.", "warn")
        except Exception as e:
            return self._ui_admin_users(f"Failed to create user: {e}", "warn")

        return self._ui_admin_users(f"User created: {username}", "ok")

    def _ui_admin_users_reset(self):
        if not _require_admin(self):
            return self._forbidden(b"403 Forbidden: admin only.\n")

        form = _read_form_urlencoded(self)
        try:
            user_id = int((form.get("user_id") or "0").strip())
        except Exception:
            return self._ui_admin_users("Invalid user id.", "warn")

        new_password = (form.get("new_password") or "").strip()
        if len(new_password) < 4:
            return self._ui_admin_users("Password too short (min 4).", "warn")

        u = db_get_user_by_id(user_id)
        if not u:
            return self._ui_admin_users("User not found.", "warn")

        try:
            db_reset_password(user_id, new_password)
        except Exception as e:
            return self._ui_admin_users(f"Failed to reset password: {e}", "warn")

        return self._ui_admin_users(f"Password updated for: {u[1]}", "ok")

    def _ui_admin_users_toggle(self):
        if not _require_admin(self):
            return self._forbidden(b"403 Forbidden: admin only.\n")

        form = _read_form_urlencoded(self)
        try:
            user_id = int((form.get("user_id") or "0").strip())
        except Exception:
            return self._ui_admin_users("Invalid user id.", "warn")

        make_active = (form.get("make_active") or "0").strip() == "1"

        u = db_get_user_by_id(user_id)
        if not u:
            return self._ui_admin_users("User not found.", "warn")

        # prevent disabling yourself (safety)
        if int(user_id) == int(getattr(self, "remote_user_id", -1)) and not make_active:
            return self._ui_admin_users("You cannot disable your own account from the UI.", "warn")

        try:
            db_set_user_active(user_id, make_active)
        except Exception as e:
            return self._ui_admin_users(f"Failed to update user: {e}", "warn")

        return self._ui_admin_users(f"User '{u[1]}' is now {'active' if make_active else 'disabled'}.", "ok")

    # ========================================================
    # UI: Repo + Branches (same as before)
    # ========================================================
    def _ui_repo(self, owner: str, repo: str):
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return self._forbidden(b"403 Forbidden\n")

        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return self._not_found()

        default_branch = _git_default_branch(repo_git)
        branches = _git_list_branches(repo_git)

        if owner == FLAT_OWNER_UI:
            clone_url = f"http://USER:SECRET@HOST:{PORT}{URL_PREFIX}/{repo}.git"
        else:
            clone_url = f"http://USER:SECRET@HOST:{PORT}{URL_PREFIX}/{owner}/{repo}.git"

        options = []
        for b in branches:
            sel = " selected" if b == default_branch else ""
            options.append(f"<option value='{html.escape(b)}'{sel}>{html.escape(b)}</option>")

        base = f"/r/{owner}/{repo}"

        body = _html_page(
            f"{owner}/{repo}",
            f"<div class='topbar'>"
            f"<div>"
            f"<h1 style='margin:0'>{html.escape(owner)}/{html.escape(repo)}</h1>"
            f"<div class='muted'>Default branch: <code>{html.escape(default_branch)}</code></div>"
            f"</div>"
            f"<div>"
            f"<a class='pill' href='/'>All repos</a> "
            f"<a class='pill' href='{base}/branches'>Branches</a>"
            f"</div>"
            f"</div>"
            f"<div class='box' style='margin-bottom:14px'>"
            f"<div class='row'>"
            f"<div>"
            f"<label>Switch branch</label>"
            f"<select id='branchSel'>{''.join(options) if options else '<option>(none)</option>'}</select>"
            f"</div>"
            f"<div><button type='button' onclick=\"goBranch()\">Browse</button></div>"
            f"</div>"
            f"<script>"
            f"function goBranch(){{"
            f"var b=document.getElementById('branchSel').value;"
            f"if(!b) return;"
            f"window.location='{base}/tree/' + encodeURIComponent(b) + '/';"
            f"}}"
            f"</script>"
            f"</div>"
            f"<div class='box'>"
            f"<p>"
            f"<a href='{base}/commits?ref={html.escape(default_branch)}'>Commits</a> | "
            f"<a href='{base}/tree/{html.escape(default_branch)}/'>Browse default</a>"
            f"</p>"
            f"<p class='muted' style='margin-top:14px'>Clone:</p>"
            f"<pre><code>{html.escape(clone_url)}</code></pre>"
            f"</div>",
        )
        _send_html(self, 200, body)

    def _ui_branches(self, owner: str, repo: str, notice: str = "", notice_kind: str = "ok"):
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return self._forbidden(b"403 Forbidden\n")

        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return self._not_found()

        default_branch = _git_default_branch(repo_git)
        branches = _git_list_branches(repo_git)
        base = f"/r/{owner}/{repo}"

        notice_html = ""
        if notice:
            cls = "ok" if notice_kind == "ok" else "warn"
            notice_html = f"<div class='{cls}' style='margin-bottom:12px'>{html.escape(notice)}</div>"

        can_write = _has_write_scope(self)

        rows = []
        for b in branches:
            browse = f"{base}/tree/{html.escape(b)}/"
            if can_write and b != default_branch:
                del_html = (
                    f"<form method='POST' action='{base}/branches/delete' style='display:inline'>"
                    f"<input type='hidden' name='branch' value='{html.escape(b)}'/>"
                    f"<button class='danger' type='submit'>Delete</button>"
                    f"</form>"
                )
            elif b == default_branch:
                del_html = "<span class='muted'>protected</span>"
            else:
                del_html = "<span class='muted'>no write scope</span>"

            rows.append(
                f"<tr>"
                f"<td><code>{html.escape(b)}</code>{' <span class=pill>default</span>' if b == default_branch else ''}</td>"
                f"<td><a class='pill' href='{browse}'>Browse</a> "
                f"<a class='pill' href='{base}/commits?ref={html.escape(b)}'>Commits</a></td>"
                f"<td style='text-align:right'>{del_html}</td>"
                f"</tr>"
            )

        if can_write:
            create_box = (
                f"<div class='box' style='margin-bottom:14px'>"
                f"<h2 style='margin:0 0 10px 0;font-size:16px'>Create branch</h2>"
                f"<form method='POST' action='{base}/branches/create'>"
                f"<div class='row'>"
                f"<div><label>New branch name</label><input name='new_branch' placeholder='feature/x' required/></div>"
                f"<div><label>From (branch/tag/commit)</label><input name='from_ref' value='{html.escape(default_branch)}' required/></div>"
                f"<div><button type='submit'>Create</button></div>"
                f"</div>"
                f"</form>"
                f"</div>"
            )
        else:
            create_box = (
                f"<div class='box warn' style='margin-bottom:14px'>"
                f"You don’t have <code>write</code> scope, so branch create/delete is disabled."
                f"</div>"
            )

        body = _html_page(
            f"Branches · {owner}/{repo}",
            f"<div class='topbar'>"
            f"<h1 style='margin:0'>Branches</h1>"
            f"<div><a class='pill' href='{base}'>Repo</a> <a class='pill' href='/'>Home</a></div>"
            f"</div>"
            f"{notice_html}"
            f"{create_box}"
            f"<div class='box'>"
            f"<table>{''.join(rows) if rows else '<tr><td class=muted>No branches.</td><td></td><td></td></tr>'}</table>"
            f"</div>",
        )
        _send_html(self, 200, body)

    def _ui_branch_create(self, owner: str, repo: str):
        if not _has_write_scope(self):
            return self._ui_branches(owner, repo, "You need write scope to create branches.", "warn")

        form = _read_form_urlencoded(self)
        new_branch = (form.get("new_branch") or "").strip()
        from_ref = (form.get("from_ref") or "").strip()

        if not _safe_branch_name(new_branch):
            return self._ui_branches(owner, repo, "Invalid branch name.", "warn")
        if not from_ref:
            return self._ui_branches(owner, repo, "From ref is required.", "warn")

        repo_git = _repo_bare_path(owner, repo)
        ok, msg = _git_create_branch(repo_git, new_branch, from_ref)
        return self._ui_branches(owner, repo, msg, "ok" if ok else "warn")

    def _ui_branch_delete(self, owner: str, repo: str):
        if not _has_write_scope(self):
            return self._ui_branches(owner, repo, "You need write scope to delete branches.", "warn")

        form = _read_form_urlencoded(self)
        branch = (form.get("branch") or "").strip()
        if not _safe_branch_name(branch):
            return self._ui_branches(owner, repo, "Invalid branch name.", "warn")

        repo_git = _repo_bare_path(owner, repo)
        default_branch = _git_default_branch(repo_git)
        if branch == default_branch:
            return self._ui_branches(owner, repo, "Default branch is protected and cannot be deleted.", "warn")

        ok, msg = _git_delete_branch(repo_git, branch)
        return self._ui_branches(owner, repo, msg, "ok" if ok else "warn")

    def _ui_commits(self, owner: str, repo: str, ref: str):
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return self._not_found()

        fmt = "%H|%an|%ad|%s"
        code, out, err = _run_git(repo_git, ["log", "--date=iso", f"--format={fmt}", "-n", "50", ref])
        if code != 0:
            msg = html.escape(err.decode("utf-8", "replace"))
            body = _html_page("Commits", f"<h1>Commits</h1><pre>{msg}</pre><p><a class='pill' href='/'>Back</a></p>")
            return _send_html(self, 400, body)

        rows = []
        for ln in out.decode("utf-8", "replace").splitlines():
            parts = ln.split("|", 3)
            if len(parts) != 4:
                continue
            h, an, ad, subj = parts

            base = f"/r/{owner}/{repo}"
            commit_href = f"{base}/commit/{html.escape(h)}"

            rows.append(
                f"<tr><td><a href='{commit_href}'><code>{html.escape(h[:8])}</code></a></td>"
                f"<td>{html.escape(subj)}</td>"
                f"<td>{html.escape(an)}</td>"
                f"<td><small class='muted'>{html.escape(ad)}</small></td></tr>"
            )

            # rows.append(
            #     f"<tr><td><code>{html.escape(h[:8])}</code></td>"
            #     f"<td>{html.escape(subj)}</td>"
            #     f"<td>{html.escape(an)}</td>"
            #     f"<td><small class='muted'>{html.escape(ad)}</small></td></tr>"
            # )

        base = f"/r/{owner}/{repo}"
        body = _html_page(
            f"Commits · {owner}/{repo}",
            f"<div class='topbar'><h1 style='margin:0'>Commits</h1>"
            f"<div><a class='pill' href='{base}'>Repo</a> <a class='pill' href='{base}/branches'>Branches</a></div></div>"
            f"<div class='box'><p class='muted'>ref: <code>{html.escape(ref)}</code></p>"
            f"<table>{''.join(rows) or '<tr><td class=muted>No commits.</td></tr>'}</table></div>",
        )
        _send_html(self, 200, body)


    def _ui_commit(self, owner: str, repo: str, commitish: str):
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return self._forbidden(b"403 Forbidden\n")

        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return self._not_found()

        commit = _git_resolve_commit(repo_git, commitish)
        if not commit:
            return self._not_found()

        meta = _git_commit_meta(repo_git, commit)
        if not meta:
            return self._not_found()

        files = _git_commit_name_status(repo_git, commit)
        patch_text, truncated = _git_commit_patch(repo_git, commit)

        base = f"/r/{owner}/{repo}"
        parents = [p for p in (meta["parents"] or "").split() if p.strip()]
        parents_html = ""
        if parents:
            links = []
            for p in parents:
                links.append(f"<a class='pill' href='{base}/commit/{html.escape(p)}'><code>{html.escape(p[:8])}</code></a>")
            parents_html = f"<div class='muted' style='margin-top:6px'>Parents: {' '.join(links)}</div>"

        # Files list with links to blob at this commit
        file_rows = []
        for status, path in files:
            # For deleted files, blob will fail; still show the path without link
            safe_path = html.escape(path)
            if status.startswith("D"):
                file_rows.append(
                    f"<tr><td style='width:70px'><span class='pill'>{html.escape(status)}</span></td>"
                    f"<td><code>{safe_path}</code></td></tr>"
                )
            else:
                href = f"{base}/blob/{html.escape(commit)}/{path}"
                file_rows.append(
                    f"<tr><td style='width:70px'><span class='pill'>{html.escape(status)}</span></td>"
                    f"<td><a href='{href}'><code>{safe_path}</code></a></td></tr>"
                )

        message_html = html.escape(meta["subject"])
        if meta["body"].strip():
            message_html += "<br><br>" + "<pre style='margin:0'>" + html.escape(meta["body"]) + "</pre>"

        trunc_note = ""
        if truncated:
            trunc_note = "<div class='warn' style='margin-top:12px'>Patch truncated (too large).</div>"

        body = _html_page(
            f"Commit {meta['hash'][:8]} · {owner}/{repo}",
            f"<div class='topbar'>"
            f"<div>"
            f"<h1 style='margin:0'>Commit <code>{html.escape(meta['hash'][:8])}</code></h1>"
            f"<div class='muted'><code>{html.escape(meta['hash'])}</code></div>"
            f"{parents_html}"
            f"</div>"
            f"<div>"
            f"<a class='pill' href='{base}/commits?ref={html.escape(_git_default_branch(repo_git))}'>Commits</a> "
            f"<a class='pill' href='{base}/tree/{html.escape(meta['hash'])}/'>Browse</a>"
            f"</div>"
            f"</div>"
            f"<div class='box' style='margin-bottom:14px'>"
            f"<div><span class='muted'>Author:</span> {html.escape(meta['author_name'])} "
            f"&lt;{html.escape(meta['author_email'])}&gt;</div>"
            f"<div><span class='muted'>Date:</span> {html.escape(meta['date'])}</div>"
            f"<div style='margin-top:10px'>{message_html}</div>"
            f"</div>"
            f"<div class='box' style='margin-bottom:14px'>"
            f"<h2 style='margin:0 0 10px 0;font-size:16px'>Files changed</h2>"
            f"<table>{''.join(file_rows) if file_rows else '<tr><td class=muted>No files.</td></tr>'}</table>"
            f"</div>"
            f"<div class='box'>"
            f"<h2 style='margin:0 0 10px 0;font-size:16px'>Patch</h2>"
            f"{trunc_note}"
            f"<pre>{html.escape(patch_text)}</pre>"
            f"</div>"
        )
        _send_html(self, 200, body)


    def _ui_tree(self, owner: str, repo: str, ref: str, subpath: str):
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return self._not_found()

        subpath = subpath.strip("/")
        target = f"{ref}:{subpath}" if subpath else ref

        code, out, err = _run_git(repo_git, ["ls-tree", target])
        if code != 0:
            msg = html.escape(err.decode("utf-8", "replace"))
            body = _html_page("Tree", f"<h1>Tree</h1><pre>{msg}</pre><p><a class='pill' href='/'>Back</a></p>")
            return _send_html(self, 400, body)

        entries = []
        for ln in out.decode("utf-8", "replace").splitlines():
            if "\t" not in ln:
                continue
            meta, name = ln.split("\t", 1)
            parts = meta.split()
            if len(parts) < 2:
                continue
            typ = parts[1]
            entries.append((typ, name))

        base = f"/r/{owner}/{repo}"
        up = ""
        if subpath:
            parent = "/".join(subpath.split("/")[:-1])
            up = f"<p><a class='pill' href='{base}/tree/{html.escape(ref)}/{html.escape(parent)}/'>⬅ Up</a></p>"

        rows = []
        for typ, name in entries:
            if typ == "tree":
                newpath = f"{subpath}/{name}" if subpath else name
                href = f"{base}/tree/{ref}/{newpath}/"
                rows.append(f"<tr><td style='width:40px'>📁</td><td><a href='{href}'>{html.escape(name)}</a></td></tr>")
            else:
                newpath = f"{subpath}/{name}" if subpath else name
                href = f"{base}/blob/{ref}/{newpath}"
                rows.append(f"<tr><td style='width:40px'>📄</td><td><a href='{href}'>{html.escape(name)}</a></td></tr>")

        body = _html_page(
            f"Browse · {owner}/{repo}",
            f"<div class='topbar'>"
            f"<div><h1 style='margin:0'>{html.escape(owner)}/{html.escape(repo)}</h1>"
            f"<div class='muted'>ref: <code>{html.escape(ref)}</code></div></div>"
            f"<div><a class='pill' href='{base}'>Repo</a> <a class='pill' href='{base}/branches'>Branches</a></div>"
            f"</div>"
            f"{up}"
            f"<div class='box'><table>{''.join(rows) or '<tr><td class=muted>Empty.</td></tr>'}</table></div>",
        )
        _send_html(self, 200, body)

    def _ui_blob(self, owner: str, repo: str, ref: str, filepath: str):
        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return self._not_found()

        filepath = filepath.lstrip("/")
        spec = f"{ref}:{filepath}"
        code, out, err = _run_git(repo_git, ["show", spec])
        if code != 0:
            msg = html.escape(err.decode("utf-8", "replace"))
            body = _html_page("File", f"<h1>File</h1><pre>{msg}</pre><p><a class='pill' href='/'>Back</a></p>")
            return _send_html(self, 400, body)

        text = out.decode("utf-8", "replace")
        escaped = html.escape(text)

        base = f"/r/{owner}/{repo}"
        back = f"{base}/tree/{ref}/"
        if "/" in filepath:
            folder = "/".join(filepath.split("/")[:-1])
            back = f"{base}/tree/{ref}/{folder}/"

        body = _html_page(
            f"{filepath} · {owner}/{repo}",
            f"<p><a class='pill' href='{back}'>⬅ Back</a> <a class='pill' href='{base}/branches'>Branches</a></p>"
            f"<h1 style='margin-top:10px'><code>{html.escape(filepath)}</code></h1>"
            f"<div class='box'><pre>{escaped}</pre></div>",
        )
        _send_html(self, 200, body)

    # ========================================================
    # Git smart HTTP backend
    # ========================================================
    def _handle_git(self):
        if not self.path.startswith(URL_PREFIX + "/"):
            return self._not_found()

        parsed = urlparse(self.path)
        path_info = parsed.path[len(URL_PREFIX):]
        query = parsed.query or ""

        env = os.environ.copy()
        env["GIT_PROJECT_ROOT"] = GIT_PROJECT_ROOT
        env["GIT_HTTP_EXPORT_ALL"] = "1"

        env["REQUEST_METHOD"] = self.command
        env["PATH_INFO"] = path_info
        env["QUERY_STRING"] = query
        env["SCRIPT_NAME"] = URL_PREFIX
        env["REMOTE_ADDR"] = self._client_ip()
        env["SERVER_PROTOCOL"] = self.request_version
        env["SERVER_SOFTWARE"] = "PyGitHTTP/1.0"

        if hasattr(self, "remote_user"):
            env["REMOTE_USER"] = self.remote_user

        for k, v in self.headers.items():
            env["HTTP_" + k.upper().replace("-", "_")] = v

        ctype = self.headers.get("Content-Type")
        if ctype:
            env["CONTENT_TYPE"] = ctype
        clen = int(self.headers.get("Content-Length") or 0)
        if clen:
            env["CONTENT_LENGTH"] = str(clen)

        stderr_target = open(TRACE_LOG, "ab", buffering=0) if TRACE_LOG else subprocess.DEVNULL
        proc = subprocess.Popen(
            [GIT_HTTP_BACKEND],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr_target,
            env=env,
            bufsize=0,
        )

        if clen > 0:
            t = threading.Thread(
                target=_write_request_body_to_stdin,
                args=(self, proc, clen),
                daemon=True,
            )
            t.start()

        header_bytes = bytearray()
        while True:
            b = proc.stdout.read(1)
            if not b:
                break
            header_bytes.extend(b)
            if header_bytes.endswith(b"\r\n\r\n") or header_bytes.endswith(b"\n\n"):
                break

        header_text = header_bytes.decode("iso-8859-1", errors="replace")
        status_code = 200
        reason = "OK"
        extra_headers = []

        for line in header_text.splitlines():
            if not line.strip():
                continue
            if line.lower().startswith("status:"):
                try:
                    _, rest = line.split(":", 1)
                    rest = rest.strip()
                    code_str, _, reason_part = rest.partition(" ")
                    status_code = int(code_str)
                    if reason_part:
                        reason = reason_part.strip()
                except Exception:
                    pass
            else:
                if ":" in line:
                    k, v = line.split(":", 1)
                    extra_headers.append((k.strip(), v.strip()))

        self.send_response(status_code, reason)
        for k, v in extra_headers:
            if k.lower() in ("status", "content-length"):
                continue
            self.send_header(k, v)
        if not any(k.lower() == "connection" for k, _ in extra_headers):
            self.send_header("Connection", "close")
        self.end_headers()

        try:
            CHUNK = 65536
            while True:
                chunk = proc.stdout.read(CHUNK)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except Exception:
            pass
        finally:
            try:
                proc.stdout.close()
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            if TRACE_LOG and hasattr(stderr_target, "flush"):
                try:
                    stderr_target.flush()
                    stderr_target.close()
                except Exception:
                    pass

    # ========================================================
    # ROUTING
    # ========================================================
    def do_GET(self):
        ip = self._client_ip()
        if not _ip_allowed(ip, self._allowlist()):
            return self._forbidden(b"403 Forbidden: IP not allowed.\n")

        if not self._require_auth():
            return

        if self.path.startswith(URL_PREFIX + "/"):
            return self._handle_git()

        parsed = urlparse(self.path)
        p = parsed.path

        if p == "/":
            return self._ui_home()

        if p == "/logout":
            self.send_response(401, "Unauthorized")
            self.send_header("WWW-Authenticate", f'Basic realm="{REALM}"')
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", "10")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"Logged out")
            self.wfile.flush()
            self.close_connection = True
            return

        if p == "/admin/users":
            return self._ui_admin_users()

        m = re.match(r"^/r/([^/]+)/([^/]+)$", p)
        if m:
            return self._ui_repo(m.group(1), m.group(2))

        m = re.match(r"^/r/([^/]+)/([^/]+)/branches$", p)
        if m:
            return self._ui_branches(m.group(1), m.group(2))

        m = re.match(r"^/r/([^/]+)/([^/]+)/commits$", p)
        if m:
            qs = parse_qs(parsed.query or "")
            ref = (qs.get("ref") or ["main"])[0]
            return self._ui_commits(m.group(1), m.group(2), ref)


        m = re.match(r"^/r/([^/]+)/([^/]+)/commit/([^/]+)$", p)
        if m:
            return self._ui_commit(m.group(1), m.group(2), m.group(3))

        m = re.match(r"^/r/([^/]+)/([^/]+)/tree/([^/]+)(/.*)?$", p)
        if m:
            subpath = unquote(m.group(4) or "/")
            return self._ui_tree(m.group(1), m.group(2), m.group(3), subpath)

        m = re.match(r"^/r/([^/]+)/([^/]+)/blob/([^/]+)(/.*)$", p)
        if m:
            filepath = unquote(m.group(4) or "")
            return self._ui_blob(m.group(1), m.group(2), m.group(3), filepath)

        return self._not_found()

    def do_POST(self):
        ip = self._client_ip()
        if not _ip_allowed(ip, self._allowlist()):
            return self._forbidden(b"403 Forbidden: IP not allowed.\n")

        if not self._require_auth():
            return

        if self.path.startswith(URL_PREFIX + "/"):
            return self._handle_git()

        parsed = urlparse(self.path)
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "application/x-www-form-urlencoded" not in ctype:
            return _send_text(self, 415, "Unsupported Media Type\n")


        if parsed.path == "/create-repo":
            return self._ui_create_repo()

        if parsed.path == "/admin/token":
            return self._ui_create_token()

        if parsed.path == "/admin/users/create":
            return self._ui_admin_users_create()

        if parsed.path == "/admin/users/reset":
            return self._ui_admin_users_reset()

        if parsed.path == "/admin/users/toggle":
            return self._ui_admin_users_toggle()

        m = re.match(r"^/r/([^/]+)/([^/]+)/branches/create$", parsed.path)
        if m:
            return self._ui_branch_create(m.group(1), m.group(2))

        m = re.match(r"^/r/([^/]+)/([^/]+)/branches/delete$", parsed.path)
        if m:
            return self._ui_branch_delete(m.group(1), m.group(2))

        return self._not_found()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.allowlist = ALLOWED_CLIENT_IPS


def main():
    if TRACE_LOG:
        os.makedirs(os.path.dirname(TRACE_LOG), exist_ok=True)

    if not os.path.exists(GIT_HTTP_BACKEND):
        print(f"ERROR: backend not found: {GIT_HTTP_BACKEND}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(GIT_PROJECT_ROOT):
        print(f"ERROR: GIT_PROJECT_ROOT does not exist: {GIT_PROJECT_ROOT}", file=sys.stderr)
        sys.exit(1)

    _db_init()
    db_ensure_default_admin()

    os.environ["GIT_PROJECT_ROOT"] = GIT_PROJECT_ROOT
    os.environ["GIT_HTTP_EXPORT_ALL"] = "1"

    httpd = ThreadedHTTPServer((HOST, PORT), GitHTTPHandler)
    print("=" * 60)
    print(f"Git Smart HTTP + Web UI running on port {PORT}")
    print(f"Git URL prefix: {URL_PREFIX}")
    print(f"UI: http://localhost:{PORT}/")
    print(f"GIT_PROJECT_ROOT: {GIT_PROJECT_ROOT}")
    print(f"DB: {DB_PATH}")
    print("Auth: accepts either username:password OR username:token")
    print("Admin users page: /admin/users")
    print("=" * 60)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

