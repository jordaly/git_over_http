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
    # You can use either:
    #  - Flat layout: C:\Servidor_Git\repo.git
    #  - Owner layout: C:\Servidor_Git\owner\repo.git
    GIT_PROJECT_ROOT = r"C:\Servidor_Git"
    GIT_HTTP_BACKEND = r"C:\Program Files\Git\mingw64\libexec\git-core\git-http-backend.exe"
    TRACE_LOG = r"C:\temp\git-http-backend.log"

elif CURRENT_PLATFORM == "Linux":
    # Flat layout: /srv/git/repo.git
    # Owner layout: /srv/git/owner/repo.git
    GIT_PROJECT_ROOT = "/home/jordaly/git_repos"
    GIT_HTTP_BACKEND = "/usr/lib/git-core/git-http-backend"
    TRACE_LOG = None  # e.g. "/tmp/git-http-backend.log" to log backend stderr

elif CURRENT_PLATFORM == "Darwin":
    git_project_path = Path.home() / "git"
    git_project_path.mkdir(exist_ok=True)
    GIT_PROJECT_ROOT = str(git_project_path)
    GIT_HTTP_BACKEND = "/opt/homebrew/opt/git/libexec/git-core/git-http-backend"
    TRACE_LOG = "/tmp/git-http-backend.log"
else:
    raise NotImplementedError()

URL_PREFIX = "/git"  # URL prefix that maps to git-http-backend

ALLOWED_CLIENT_IPS = {
    "127.0.0.1",
    # Example: "192.168.16.0/24"
}

# ---- BASIC AUTH CONFIG ----
# MVP: user/pass (Git will prompt). Later you can switch to PAT tokens in sqlite.
REQUIRE_AUTH = True
REALM = "Git Repositories"
VALID_USERS = {
    "admin": "admin",
}

# UI owner name for flat repos (repos directly under GIT_PROJECT_ROOT)
FLAT_OWNER_UI = "root"

# ============================================================
# HELPERS
# ============================================================
SAFE_SEG = re.compile(r"^[A-Za-z0-9._-]+$")


def _safe_seg(s: str) -> bool:
    return bool(s) and SAFE_SEG.match(s) and ".." not in s and "/" not in s and "\\" not in s


def _is_bare_repo_dir(p: Path) -> bool:
    # Bare repo has a HEAD file; most have objects/ and refs/, but HEAD is the best quick indicator.
    return p.is_dir() and (p / "HEAD").is_file()


def _scan_repos(project_root: str) -> list[tuple[str, str, str]]:
    """
    Returns list of (owner_ui, repo_name, rel_git_path)
      - owner_ui is FLAT_OWNER_UI for flat repos
      - rel_git_path is relative path inside GIT_PROJECT_ROOT, like:
            "repo.git" or "owner/repo.git"
    """
    root = Path(project_root)
    results: list[tuple[str, str, str]] = []
    if not root.exists():
        return results

    # Case A: flat layout: <root>/*.git
    for p in sorted(root.glob("*.git")):
        if _is_bare_repo_dir(p):
            repo = p.name[:-4]
            results.append((FLAT_OWNER_UI, repo, p.name))

    # Case B: owner layout: <root>/<owner>/*.git
    for owner_dir in sorted([x for x in root.iterdir() if x.is_dir()]):
        owner = owner_dir.name
        for p in sorted(owner_dir.glob("*.git")):
            if _is_bare_repo_dir(p):
                repo = p.name[:-4]
                rel = f"{owner}/{p.name}"
                results.append((owner, repo, rel))

    # Deduplicate while preserving order
    seen = set()
    uniq = []
    for o, r, rel in results:
        key = (o, r, rel)
        if key not in seen:
            seen.add(key)
            uniq.append((o, r, rel))
    return uniq


def _repo_bare_path(owner_ui: str, repo: str) -> str:
    """
    Map UI owner/repo -> filesystem bare repo directory.
    - owner_ui == FLAT_OWNER_UI => <root>/<repo>.git
    - else => <root>/<owner>/<repo>.git
    """
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
        f"input{{padding:10px;border:1px solid #ddd;border-radius:10px;font-size:14px}}"
        f"button{{padding:10px 14px;border:1px solid #111;border-radius:10px;background:#111;color:#fff;cursor:pointer}}"
        f"button:hover{{opacity:.92}}"
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


def _ip_allowed(ip: str, allow: set[str]) -> bool:
    """Allow exact IPs or CIDRs; handles IPv4/IPv6. Empty allowlist denies all."""
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


def _write_request_body_to_stdin(
    handler: BaseHTTPRequestHandler, proc: subprocess.Popen, content_len: int
):
    """Stream request body into backend stdin without buffering the whole thing."""
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
    """
    Read application/x-www-form-urlencoded body into {key: value}.
    (No external deps)
    """
    clen = int(handler.headers.get("Content-Length") or 0)
    if clen <= 0:
        return {}
    raw = handler.rfile.read(clen)
    try:
        text = raw.decode("utf-8", "replace")
    except Exception:
        return {}
    # parse_qs returns lists
    qs = parse_qs(text, keep_blank_values=True)
    out: dict[str, str] = {}
    for k, v in qs.items():
        out[k] = v[0] if v else ""
    return out


# ============================================================
# SERVER
# ============================================================
class GitHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # -------- small helpers --------
    def _client_ip(self) -> str:
        ip = self.client_address[0]
        if ip == "::1":
            return "127.0.0.1"
        return ip

    def _allowlist(self) -> set[str]:
        return getattr(self.server, "allowlist", ALLOWED_CLIENT_IPS)

    # -------- AUTHENTICATION --------
    def _require_auth(self) -> bool:
        """Ask for username/password via HTTP Basic Auth (Git-native prompt)."""
        if not REQUIRE_AUTH:
            return True

        auth_header = self.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Basic "):
            return self._request_auth()

        try:
            decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:
            return self._request_auth()

        if VALID_USERS.get(username) == password:
            self.remote_user = username
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

    # -------- response helpers --------
    def _forbidden(self, msg=b"403 Forbidden\n"):
        _send_text(self, 403, msg.decode("utf-8", "replace"))

    def _not_found(self):
        _send_text(self, 404, "404 Not Found\n")

    # ========================================================
    # UI
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

        body = _html_page(
            "Repos",
            f"<div class='topbar'>"
            f"<h1 style='margin:0'>Repos</h1>"
            f"<span class='pill'>Smart HTTP: <code>{html.escape(URL_PREFIX)}/</code></span>"
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
            f"<p class='muted' style='margin:10px 0 0 0'>"
            f"• If owner is empty or '{html.escape(FLAT_OWNER_UI)}', repo is created as <code>{html.escape(GIT_PROJECT_ROOT)}/&lt;repo&gt;.git</code><br>"
            f"• Otherwise repo is created as <code>{html.escape(GIT_PROJECT_ROOT)}/&lt;owner&gt;/&lt;repo&gt;.git</code>"
            f"</p>"
            f"</form>"
            f"</div>"
            f"<div class='box'>"
            f"<p class='muted'>GIT_PROJECT_ROOT: <code>{html.escape(GIT_PROJECT_ROOT)}</code></p>"
            f"<table>"
            f"{''.join(rows) if rows else '<tr><td class=muted>No bare repos found (folders ending with .git containing HEAD).</td><td></td></tr>'}"
            f"</table>"
            f"</div>",
        )
        _send_html(self, 200, body)

    def _ui_repo(self, owner: str, repo: str):
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return self._forbidden(b"403 Forbidden\n")

        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return self._not_found()

        code, out, _ = _run_git(repo_git, ["symbolic-ref", "HEAD"])
        ref = "main"
        if code == 0:
            head = out.decode("utf-8", "replace").strip()
            if head.startswith("refs/heads/"):
                ref = head[len("refs/heads/") :]

        clone_url = f"http://USER:PASS@HOST:{PORT}{URL_PREFIX}/{owner}/{repo}.git"
        if owner == FLAT_OWNER_UI:
            # For flat repos, the git-http-backend path is /git/<repo>.git
            clone_url = f"http://USER:PASS@HOST:{PORT}{URL_PREFIX}/{repo}.git"

        body = _html_page(
            f"{owner}/{repo}",
            f"<div class='topbar'>"
            f"<div><h1 style='margin:0'>{html.escape(owner)}/{html.escape(repo)}</h1>"
            f"<div class='muted'>Default branch: <code>{html.escape(ref)}</code></div></div>"
            f"<div><a class='pill' href='/'>All repos</a></div>"
            f"</div>"
            f"<div class='box'>"
            f"<p><a href='/r/{html.escape(owner)}/{html.escape(repo)}/commits?ref={html.escape(ref)}'>Commits</a> | "
            f"<a href='/r/{html.escape(owner)}/{html.escape(repo)}/tree/{html.escape(ref)}/'>Browse</a></p>"
            f"<p class='muted' style='margin-top:14px'>Clone:</p>"
            f"<pre><code>{html.escape(clone_url)}</code></pre>"
            f"</div>",
        )
        _send_html(self, 200, body)

    def _ui_commits(self, owner: str, repo: str, ref: str):
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return self._forbidden(b"403 Forbidden\n")

        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return self._not_found()

        fmt = "%H|%an|%ad|%s"
        code, out, err = _run_git(
            repo_git, ["log", "--date=iso", f"--format={fmt}", "-n", "50", ref]
        )
        if code != 0:
            msg = html.escape(err.decode("utf-8", "replace"))
            body = _html_page("Commits", f"<h1>Commits</h1><pre>{msg}</pre>")
            return _send_html(self, 400, body)

        rows = []
        for ln in out.decode("utf-8", "replace").splitlines():
            parts = ln.split("|", 3)
            if len(parts) != 4:
                continue
            h, an, ad, subj = parts
            rows.append(
                f"<tr><td><code>{html.escape(h[:8])}</code></td>"
                f"<td>{html.escape(subj)}</td>"
                f"<td>{html.escape(an)}</td>"
                f"<td><small class='muted'>{html.escape(ad)}</small></td></tr>"
            )

        base = f"/r/{owner}/{repo}"
        body = _html_page(
            f"Commits · {owner}/{repo}",
            f"<div class='topbar'><h1 style='margin:0'>Commits</h1>"
            f"<div><a class='pill' href='{base}'>Repo</a> "
            f"<a class='pill' href='{base}/tree/{html.escape(ref)}/'>Browse</a></div></div>"
            f"<div class='box'><table>{''.join(rows) or '<tr><td class=muted>No commits.</td></tr>'}</table></div>",
        )
        _send_html(self, 200, body)

    def _ui_tree(self, owner: str, repo: str, ref: str, subpath: str):
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return self._forbidden(b"403 Forbidden\n")

        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return self._not_found()

        subpath = subpath.strip("/")
        target = f"{ref}:{subpath}" if subpath else ref

        code, out, err = _run_git(repo_git, ["ls-tree", target])
        if code != 0:
            msg = html.escape(err.decode("utf-8", "replace"))
            body = _html_page("Tree", f"<h1>Tree</h1><pre>{msg}</pre>")
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
                rows.append(
                    f"<tr><td style='width:40px'>📁</td><td><a href='{href}'>{html.escape(name)}</a></td></tr>"
                )
            else:
                newpath = f"{subpath}/{name}" if subpath else name
                href = f"{base}/blob/{ref}/{newpath}"
                rows.append(
                    f"<tr><td style='width:40px'>📄</td><td><a href='{href}'>{html.escape(name)}</a></td></tr>"
                )

        body = _html_page(
            f"Browse · {owner}/{repo}",
            f"<div class='topbar'>"
            f"<div><h1 style='margin:0'>{html.escape(owner)}/{html.escape(repo)}</h1>"
            f"<div class='muted'>ref: <code>{html.escape(ref)}</code></div></div>"
            f"<div><a class='pill' href='{base}'>Repo</a> "
            f"<a class='pill' href='{base}/commits?ref={html.escape(ref)}'>Commits</a></div>"
            f"</div>"
            f"{up}"
            f"<div class='box'><table>{''.join(rows) or '<tr><td class=muted>Empty.</td></tr>'}</table></div>",
        )
        _send_html(self, 200, body)

    def _ui_blob(self, owner: str, repo: str, ref: str, filepath: str):
        if not (_safe_seg(owner) and _safe_seg(repo)):
            return self._forbidden(b"403 Forbidden\n")

        repo_git = _repo_bare_path(owner, repo)
        if not os.path.isdir(repo_git):
            return self._not_found()

        filepath = filepath.lstrip("/")
        spec = f"{ref}:{filepath}"
        code, out, err = _run_git(repo_git, ["show", spec])
        if code != 0:
            msg = html.escape(err.decode("utf-8", "replace"))
            body = _html_page("File", f"<h1>File</h1><pre>{msg}</pre>")
            return _send_html(self, 400, body)

        text = out.decode("utf-8", "replace")
        escaped = html.escape(text)

        back = f"/r/{owner}/{repo}/tree/{ref}/"
        if "/" in filepath:
            folder = "/".join(filepath.split("/")[:-1])
            back = f"/r/{owner}/{repo}/tree/{ref}/{folder}/"

        body = _html_page(
            f"{filepath} · {owner}/{repo}",
            f"<p><a class='pill' href='{back}'>⬅ Back</a></p>"
            f"<h1 style='margin-top:10px'><code>{html.escape(filepath)}</code></h1>"
            f"<div class='box'><pre>{escaped}</pre></div>",
        )
        _send_html(self, 200, body)

    def _ui_create_repo(self):
        """
        POST /create-repo  (application/x-www-form-urlencoded)
          owner: optional (if empty or "root" => flat)
          repo: required
        """
        form = _read_form_urlencoded(self)
        owner = (form.get("owner") or "").strip()
        repo = (form.get("repo") or "").strip()

        # Normalize owner
        if not owner or owner == FLAT_OWNER_UI:
            owner_ui = FLAT_OWNER_UI
        else:
            owner_ui = owner

        # Validate
        if owner_ui != FLAT_OWNER_UI and not _safe_seg(owner_ui):
            return self._ui_home("Invalid owner name (allowed: A-Z a-z 0-9 . _ -).", "warn")
        if not _safe_seg(repo):
            return self._ui_home("Invalid repo name (allowed: A-Z a-z 0-9 . _ -).", "warn")

        repo_git = _repo_bare_path(owner_ui, repo)

        # Create path
        try:
            if owner_ui == FLAT_OWNER_UI:
                os.makedirs(GIT_PROJECT_ROOT, exist_ok=True)
            else:
                os.makedirs(os.path.join(GIT_PROJECT_ROOT, owner_ui), exist_ok=True)
        except Exception as e:
            return self._ui_home(f"Failed to create owner folder: {e}", "warn")

        # Already exists?
        if os.path.exists(repo_git):
            return self._ui_home("Repo already exists.", "warn")

        # Create bare repo
        # (We prefer: git init --bare <path>)
        code, out, err = _run_cmd(["git", "init", "--bare", repo_git])
        if code != 0:
            msg = err.decode("utf-8", "replace").strip() or out.decode("utf-8", "replace").strip()
            return self._ui_home(f"git init --bare failed: {msg}", "warn")

        # Success
        return self._ui_home(f"Repo created: {owner_ui}/{repo}", "ok")

    # ========================================================
    # Git Smart HTTP backend (unchanged, plus forwards HTTP_* headers)
    # ========================================================
    def _handle_git(self):
        if not self.path.startswith(URL_PREFIX + "/"):
            return self._not_found()

        parsed = urlparse(self.path)
        path_info = parsed.path[len(URL_PREFIX) :]
        query = parsed.query or ""

        env = os.environ.copy()
        env["GIT_PROJECT_ROOT"] = GIT_PROJECT_ROOT
        env["GIT_HTTP_EXPORT_ALL"] = "1"

        env["REQUEST_METHOD"] = self.command
        env["GIT_COMMITTER_NAME"] = env.get("GIT_COMMITTER_NAME", "git-http")
        env["GIT_COMMITTER_EMAIL"] = env.get("GIT_COMMITTER_EMAIL", "git-http@localhost")
        env["PATH_INFO"] = path_info
        env["QUERY_STRING"] = query
        env["SCRIPT_NAME"] = URL_PREFIX
        env["REMOTE_ADDR"] = self._client_ip()
        env["SERVER_PROTOCOL"] = self.request_version
        env["SERVER_SOFTWARE"] = "PyGitHTTP/1.0"

        if hasattr(self, "remote_user"):
            env["REMOTE_USER"] = self.remote_user

        # Forward HTTP headers (CGI format)
        for k, v in self.headers.items():
            hk = "HTTP_" + k.upper().replace("-", "_")
            env[hk] = v

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

        # Parse headers from git-http-backend
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
                if hasattr(proc.stdout, "close_reader"):
                    proc.stdout.close_reader()
                elif hasattr(proc.stdout, "close"):
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

        # /r/<owner>/<repo>
        m = re.match(r"^/r/([^/]+)/([^/]+)$", p)
        if m:
            return self._ui_repo(m.group(1), m.group(2))

        # /r/<owner>/<repo>/commits?ref=...
        m = re.match(r"^/r/([^/]+)/([^/]+)/commits$", p)
        if m:
            qs = parse_qs(parsed.query or "")
            ref = (qs.get("ref") or ["main"])[0]
            return self._ui_commits(m.group(1), m.group(2), ref)

        # /r/<owner>/<repo>/tree/<ref>/<path...>
        m = re.match(r"^/r/([^/]+)/([^/]+)/tree/([^/]+)(/.*)?$", p)
        if m:
            subpath = unquote(m.group(4) or "/")
            return self._ui_tree(m.group(1), m.group(2), m.group(3), subpath)

        # /r/<owner>/<repo>/blob/<ref>/<path...>
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

        # UI POST
        parsed = urlparse(self.path)
        if parsed.path == "/create-repo":
            # Only allow standard form posts
            ctype = (self.headers.get("Content-Type") or "").lower()
            if "application/x-www-form-urlencoded" not in ctype:
                return _send_text(self, 415, "Unsupported Media Type\n")
            return self._ui_create_repo()

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

    os.environ["GIT_PROJECT_ROOT"] = GIT_PROJECT_ROOT
    os.environ["GIT_HTTP_EXPORT_ALL"] = "1"

    httpd = ThreadedHTTPServer((HOST, PORT), GitHTTPHandler)
    print("=" * 60)
    print(f"Git Smart HTTP + Web UI running on port {PORT}")
    print(f"Git URL prefix: {URL_PREFIX}")
    print(f"UI: http://localhost:{PORT}/")
    print(f"GIT_PROJECT_ROOT: {GIT_PROJECT_ROOT}")
    print(f"Authentication: {'Enabled' if REQUIRE_AUTH else 'Disabled'}")
    print(f"Repo layouts supported:")
    print(f"  - Flat:  {GIT_PROJECT_ROOT}{os.sep}<repo>.git")
    print(f"  - Owner: {GIT_PROJECT_ROOT}{os.sep}<owner>{os.sep}<repo>.git")
    print("=" * 60)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

