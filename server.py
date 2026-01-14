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

# ---- CONFIG: adjust to your machine ----
HOST = ""  # bind all interfaces
PORT = 8000

CURRENT_PLATFORM = platform.system()

if CURRENT_PLATFORM == "Windows":
    GIT_PROJECT_ROOT = r"C:\Servidor_Git"  # recommended layout: C:\Servidor_Git\<owner>\<repo>.git
    GIT_HTTP_BACKEND = (
        r"C:\Program Files\Git\mingw64\libexec\git-core\git-http-backend.exe"
    )
    TRACE_LOG = r"C:\temp\git-http-backend.log"

elif CURRENT_PLATFORM == "Linux":
    GIT_PROJECT_ROOT = "/home/jordaly/git_repos"  # recommended layout: /srv/git/<owner>/<repo>.git
    GIT_HTTP_BACKEND = "/usr/lib/git-core/git-http-backend"
    TRACE_LOG = None  # e.g. "/tmp/git-http-backend.log" to log backend stderr

elif CURRENT_PLATFORM == "Darwin":
    git_project_path = Path.home() / "git"
    git_project_path.mkdir(exist_ok=True)
    GIT_PROJECT_ROOT = str(git_project_path)  # layout: ~/git/<owner>/<repo>.git
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
# For MVP: user/pass. Recommended next: username + PAT token (store in sqlite3).
REQUIRE_AUTH = True
REALM = "Git Repositories"
VALID_USERS = {
    "admin": "admin",
}

# ----------------------------------------

SAFE_SEG = re.compile(r"^[A-Za-z0-9._-]+$")


def _safe_seg(s: str) -> bool:
    return bool(s) and SAFE_SEG.match(s) and ".." not in s and "/" not in s and "\\" not in s


def _repo_bare_path(owner: str, repo: str) -> str:
    # UI route uses repo without .git, on disk it is <repo>.git
    return os.path.join(GIT_PROJECT_ROOT, owner, repo + ".git")


def _run_git(repo_git_dir: str, args: list[str]) -> tuple[int, bytes, bytes]:
    cmd = ["git", f"--git-dir={repo_git_dir}"] + args
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    return p.returncode, out, err


def _html_page(title: str, body_html: str) -> bytes:
    return (
        f"<!doctype html><html><head><meta charset='utf-8'>"
        f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        f"<style>"
        f"body{{font-family:system-ui,Segoe UI,Arial;margin:24px;max-width:1100px}}"
        f"a{{text-decoration:none}} a:hover{{text-decoration:underline}}"
        f"code,pre{{font-family:ui-monospace,Consolas,monospace}}"
        f"pre{{padding:12px;border:1px solid #ddd;border-radius:10px;overflow:auto;background:#fafafa}}"
        f"table{{border-collapse:collapse;width:100%}}"
        f"td{{padding:8px 10px;border-bottom:1px solid #eee;vertical-align:top}}"
        f".muted{{color:#666}} .pill{{display:inline-block;padding:2px 8px;border:1px solid #ddd;"
        f"border-radius:999px;font-size:12px;color:#444;background:#fff}}"
        f".topbar{{display:flex;gap:12px;align-items:center;justify-content:space-between;margin-bottom:16px}}"
        f".box{{border:1px solid #eee;border-radius:14px;padding:14px;background:#fff}}"
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
            # Save for downstream (git-http-backend can log/use it)
            self.remote_user = username  # set attribute on handler instance
            return True

        return self._request_auth()

    def _request_auth(self) -> bool:
        """Send 401 with proper headers and close connection cleanly."""
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
        self.send_response(403, "Forbidden")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(msg)
            self.wfile.flush()
        except Exception:
            pass
        self.close_connection = True

    def _not_found(self):
        self.send_response(404, "Not Found")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(b"404 Not Found\n")
            self.wfile.flush()
        except Exception:
            pass
        self.close_connection = True

    # -------- UI handlers --------
    def _ui_home(self):
        items = []
        root = Path(GIT_PROJECT_ROOT)
        if root.exists():
            # expected layout: <root>/<owner>/*.git
            for owner_dir in sorted([p for p in root.iterdir() if p.is_dir()]):
                owner = owner_dir.name
                for repo_git in sorted(owner_dir.glob("*.git")):
                    repo = repo_git.name[:-4]
                    items.append((owner, repo))

        rows = "".join(
            f"<tr><td><a href='/r/{html.escape(o)}/{html.escape(r)}'>{html.escape(o)}/{html.escape(r)}</a></td></tr>"
            for o, r in items
        )
        body = _html_page(
            "Repos",
            f"<div class='topbar'><h1 style='margin:0'>Repos</h1>"
            f"<span class='pill'>Smart HTTP at <code>{html.escape(URL_PREFIX)}/</code></span></div>"
            f"<div class='box'><table>{rows or '<tr><td class=muted>No repos found.</td></tr>'}</table></div>",
        )
        _send_html(self, 200, body)

    def _ui_repo(self, owner: str, repo: str):
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

        lines = out.decode("utf-8", "replace").splitlines()
        rows = []
        for ln in lines:
            parts = ln.split("|", 3)
            if len(parts) != 4:
                continue
            h, an, ad, subj = parts
            short = h[:8]
            rows.append(
                f"<tr><td><code>{html.escape(short)}</code></td>"
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
                    f"<tr><td style='width:40px'>📁</td>"
                    f"<td><a href='{href}'>{html.escape(name)}</a></td></tr>"
                )
            else:
                newpath = f"{subpath}/{name}" if subpath else name
                href = f"{base}/blob/{ref}/{newpath}"
                rows.append(
                    f"<tr><td style='width:40px'>📄</td>"
                    f"<td><a href='{href}'>{html.escape(name)}</a></td></tr>"
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

        # MVP: treat as text
        text = out.decode("utf-8", "replace")
        escaped = html.escape(text)

        back = f"/r/{owner}/{repo}/tree/{ref}/"
        # Back to folder if inside subdir
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

    # -------- main git backend handler --------
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

        # If we authenticated a user, pass it along
        if hasattr(self, "remote_user"):
            env["REMOTE_USER"] = self.remote_user

        # Forward some HTTP_* headers (helps git-http-backend in some setups)
        for k, v in self.headers.items():
            hk = "HTTP_" + k.upper().replace("-", "_")
            env[hk] = v

        ctype = self.headers.get("Content-Type")
        if ctype:
            env["CONTENT_TYPE"] = ctype
        clen = int(self.headers.get("Content-Length") or 0)
        if clen:
            env["CONTENT_LENGTH"] = str(clen)

        stderr_target = (
            open(TRACE_LOG, "ab", buffering=0) if TRACE_LOG else subprocess.DEVNULL
        )
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

    # -------- routing --------
    def do_GET(self):
        ip = self._client_ip()
        if not _ip_allowed(ip, self._allowlist()):
            self._forbidden(b"403 Forbidden: IP not allowed.\n")
            return

        # Require auth for both UI and git endpoints (GitHub-like). Change if you want public browsing.
        if not self._require_auth():
            return

        if self.path.startswith(URL_PREFIX + "/"):
            return self._handle_git()

        parsed = urlparse(self.path)
        p = parsed.path

        if p == "/":
            return self._ui_home()

        m = re.match(r"^/r/([^/]+)/([^/]+)$", p)
        if m:
            owner, repo = m.group(1), m.group(2)
            if not (_safe_seg(owner) and _safe_seg(repo)):
                return self._forbidden(b"403 Forbidden\n")
            return self._ui_repo(owner, repo)

        m = re.match(r"^/r/([^/]+)/([^/]+)/commits$", p)
        if m:
            owner, repo = m.group(1), m.group(2)
            qs = parse_qs(parsed.query or "")
            ref = (qs.get("ref") or ["main"])[0]
            return self._ui_commits(owner, repo, ref)

        m = re.match(r"^/r/([^/]+)/([^/]+)/tree/([^/]+)(/.*)?$", p)
        if m:
            owner, repo, ref = m.group(1), m.group(2), m.group(3)
            subpath = m.group(4) or "/"
            subpath = unquote(subpath)
            return self._ui_tree(owner, repo, ref, subpath)

        m = re.match(r"^/r/([^/]+)/([^/]+)/blob/([^/]+)(/.*)$", p)
        if m:
            owner, repo, ref = m.group(1), m.group(2), m.group(3)
            filepath = unquote(m.group(4) or "")
            return self._ui_blob(owner, repo, ref, filepath)

        return self._not_found()

    def do_POST(self):
        ip = self._client_ip()
        if not _ip_allowed(ip, self._allowlist()):
            self._forbidden(b"403 Forbidden: IP not allowed.\n")
            return
        if not self._require_auth():
            return
        if self.path.startswith(URL_PREFIX + "/"):
            return self._handle_git()
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
    print(f"Git Smart HTTP + UI server running on port {PORT}")
    print(f"Git URL prefix: {URL_PREFIX}")
    print(f"UI: http://localhost:{PORT}/ (repos)  |  /r/<owner>/<repo> (repo)")
    print(f"GIT_PROJECT_ROOT: {GIT_PROJECT_ROOT}")
    print(f"Authentication: {'Enabled' if REQUIRE_AUTH else 'Disabled'}")
    print("Repo layout expected: <root>/<owner>/<repo>.git (bare repos)")
    print("=" * 60)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

