"""Versioned API dispatch with bearer authentication and scoped mutations."""

import asyncio
import json
import hashlib
import logging
from pathlib import Path
import re
import secrets
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

from .. import database
from . import data, git
from .errors import APIError
from .policy import can_read_repository
from .responses import BinaryDownload


PREFIX = "/api/v1"
MAX_RESPONSE = 2 * 1024 * 1024
RESPONSE_TIMEOUT = 20
logger = logging.getLogger(__name__)


class API:
    def __init__(self, handler):
        # Import lazily: application owns HTTP transport, not the API contract.
        from .. import application
        self.app = application
        self.handler = handler
        self.request = handler.request
        self.request_id = secrets.token_hex(16)
        self.identity = None
        self.response_headers = []
        self.response_status = 200
        self.download_slot = False

    async def send(self, status, payload, headers=()):
        body = json.dumps(payload, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_RESPONSE:
            raise APIError(413, "response_too_large", "Response exceeds the API limit.")
        reasons = {201: "Created", 202: "Accepted", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
                   409: "Conflict", 415: "Unsupported Media Type", 422: "Unprocessable Content",
                   405: "Method Not Allowed", 413: "Content Too Large",
                   429: "Too Many Requests", 503: "Service Unavailable", 504: "Gateway Timeout"}
        await self.app._send_response(self.request, status, body, [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
            ("X-Request-ID", self.request_id), *headers,
         ], reason=reasons.get(status), include_body=self.request.method != "HEAD")

    async def send_download(self, download):
        try:
            await asyncio.wait_for(self.app._send_response(
                self.request, 200, download.content, [
                    ("Content-Type", "application/zip"), ("Content-Length", str(download.size)),
                    ("Content-Disposition", f'attachment; filename="{download.filename}"'),
                    ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                    ("X-Request-ID", self.request_id), ("Accept-Ranges", "none"),
                ], include_body=self.request.method != "HEAD"), RESPONSE_TIMEOUT)
        except (TimeoutError, asyncio.CancelledError) as exc:
            # Headers may already be sent; never append a second JSON response.
            # Abort drops buffered ZIP bytes even if the peer stopped reading.
            self.request.writer.transport.abort()
            self.request.writer.close()
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise self.app.ClientDisconnected() from None

    async def dispatch(self):
        try:
            if not self.app._ip_allowed(self.request.peer_ip, self.handler.server.allowlist):
                raise APIError(403, "forbidden", "Client IP is not allowed.")
            limiter = self.handler.server.api_limiter
            limiter.check(("ip", self.request.peer_ip))
            async with asyncio.timeout(RESPONSE_TIMEOUT):
                await self.authenticate()
                limiter.check(("user", self.identity["user_id"]))
                writing = self.request.method not in ("GET", "HEAD")
                if self.request.method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"):
                    raise APIError(405, "method_not_allowed", "Unsupported HTTP method.")
                if writing and "write" not in self.identity["scopes"]:
                    raise APIError(403, "insufficient_scope", "Token requires write scope.")
                if not writing and (self.request.headers.get("Transfer-Encoding")
                        or self.request.headers.get("Content-Length", "0") != "0"):
                    raise APIError(400, "unexpected_body", "Read requests must not contain a body.")
                parsed = urlsplit(self.request.target)
                if len(parsed.query) > 4096:
                    raise APIError(400, "invalid_query", "Query string is too long.")
                self.path = parsed.path
                try:
                    self.query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=20)
                except ValueError:
                    raise APIError(400, "invalid_query", "Too many query parameters.") from None
                self.page = self.integer("page", 1, 1, 10000)
                self.per_page = self.integer("per_page", 30, 1, 100)
                self.offset = (self.page - 1) * self.per_page
                if self.offset > 100000:
                    raise APIError(400, "invalid_pagination", "Pagination offset exceeds 100000.")
                if writing:
                    if self.query:
                        raise APIError(400, "invalid_query", "Mutation parameters belong in the JSON body.")
                    self.document = await self.read_json()
                    values = [v for k, v in self.request.headers.items() if k.lower() == "idempotency-key"]
                    if len(values) != 1 or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", values[0]):
                        raise APIError(422, "validation_error", "One Idempotency-Key header (1–128 safe ASCII characters) is required.")
                    self.idempotency_key = values[0]
                    # Do not cancel a mutation halfway through a Git/SQLite write
                    # when a response times out. Shutdown drains these tasks.
                    task = asyncio.create_task(self.perform_write())
                    self.handler.server.push_finalizers.add(task)
                    def finished(done):
                        self.handler.server.push_finalizers.discard(done)
                        if not done.cancelled():
                            done.exception()
                    task.add_done_callback(finished)
                    payload = await asyncio.shield(task)
                else:
                    async with self.handler.server.api_slots:
                        payload = await self.route()
            if isinstance(payload, BinaryDownload):
                await self.send_download(payload)
            else:
                await self.send(self.response_status, payload, self.response_headers)
        except APIError as exc:
            await self.send(exc.status, {"message": exc.message, "code": exc.code,
                                        "request_id": self.request_id}, exc.headers)
        except TimeoutError:
            await self.send(504, {"message": "API operation timed out.", "code": "timeout",
                                  "request_id": self.request_id})
        except self.app.ClientDisconnected:
            raise
        except Exception as exc:
            # Do not log request headers, tokens, URLs, or exception messages.
            self.log_failure(exc)
            await self.send(500, {"message": "Internal server error.", "code": "internal_error",
                                   "request_id": self.request_id})
        finally:
            if self.download_slot:
                self.handler.server.api_download_slots.release()
                self.download_slot = False

    def log_failure(self, exc):
        logger.error("API request failed request_id=%s type=%s", self.request_id, type(exc).__name__)

    async def read_json(self):
        if self.request.headers.get("Transfer-Encoding"):
            raise APIError(400, "invalid_body", "Chunked mutation bodies are not supported.")
        lengths = [v for k, v in self.request.headers.items() if k.lower() == "content-length"]
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,8}", lengths[0]):
            raise APIError(400, "invalid_body", "One valid Content-Length header is required.")
        size = int(lengths[0])
        if size > MAX_RESPONSE:
            raise APIError(413, "request_too_large", "JSON bodies are limited to 2 MiB.")
        if self.request.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            raise APIError(415, "unsupported_media_type", "Use Content-Type: application/json.")
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError("Duplicate key")
                result[key] = value
            return result
        def constant(_value):
            raise ValueError("Non-finite number")
        try:
            raw = await self.request.reader.readexactly(size)
            document = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
            json.dumps(document, ensure_ascii=False, allow_nan=False).encode("utf-8")  # Reject lone surrogates and overflowed numbers.
        except (ValueError, UnicodeError, RecursionError, asyncio.IncompleteReadError):
            raise APIError(400, "invalid_json", "Provide a valid UTF-8 JSON object without duplicate keys.") from None
        if not isinstance(document, dict):
            raise APIError(422, "validation_error", "Request body must be a JSON object.")
        return document

    async def perform_write(self):
        from . import mutations, writes
        async with self.handler.server.api_slots:
            target = await writes.authorize(self)
            fingerprint = hashlib.sha256(
                (self.request.method + "\n" + self.path + "\n" +
                 json.dumps(self.document, sort_keys=True, ensure_ascii=True)).encode()).hexdigest()
            key_hash, cached = await asyncio.to_thread(
                mutations.claim, self.identity["user_id"], self.idempotency_key, fingerprint,
                self.request_id, self.request.method, self.path)
            if cached:
                status, payload = cached
                self.response_headers.append(("X-Idempotent-Replay", "true"))
            else:
                try:
                    status, payload = await writes.route(self, target)
                except APIError as exc:
                    status, payload = exc.status, {"message": exc.message, "code": exc.code}
                # A crash between the write and completion leaves the claim pending,
                # never eligible for automatic re-execution.
                await asyncio.to_thread(mutations.complete, self.identity["user_id"], key_hash, status, payload)
            self.response_status = status
            if status >= 400:
                payload = {**payload, "request_id": self.request_id}
            return payload

    async def authenticate(self):
        values = [v for k, v in self.request.headers.items() if k.lower() == "authorization"]
        if len(values) != 1:
            raise self.unauthorized()
        parts = values[0].split()
        if len(parts) != 2 or parts[0].lower() != "bearer" or len(parts[1]) > 256:
            raise self.unauthorized()
        identity = await asyncio.to_thread(database.db_verify_token_any_user, parts[1])
        if not identity:
            raise self.unauthorized()
        if "read" not in identity["scopes"]:
            raise APIError(403, "insufficient_scope", "Token requires read scope.")
        self.identity = identity
        self.handler._apply_auth_info(identity)

    @staticmethod
    def unauthorized():
        return APIError(401, "unauthorized", "A valid bearer access token is required.",
                        headers=[("WWW-Authenticate", 'Bearer realm="api"')])

    def value(self, key, default=""):
        values = self.query.get(key, [default])
        if len(values) != 1 or len(values[0]) > 256:
            raise APIError(400, "invalid_query", f"Invalid {key} parameter.")
        return values[0]

    def integer(self, key, default, minimum, maximum):
        value = self.value(key, str(default))
        if not re.fullmatch(r"[0-9]{1,18}", value) or not minimum <= int(value) <= maximum:
            raise APIError(400, "invalid_query", f"{key} must be between {minimum} and {maximum}.")
        return int(value)

    def parameters(self, *allowed):
        if set(self.query) - {"page", "per_page", *allowed}:
            raise APIError(400, "invalid_query", "Unknown query parameter.")
        for key in self.query:
            self.value(key)

    def listing(self, rows):
        has_next = len(rows) > self.per_page
        links = []
        for relation, page in (("prev", self.page - 1), ("next", self.page + 1)):
            if (relation == "prev" and self.page > 1) or (relation == "next" and has_next):
                query = {k: v[0] for k, v in self.query.items()}
                query.update(page=str(page), per_page=str(self.per_page))
                links.append(f'<{self.path}?{urlencode(query)}>; rel="{relation}"')
        if links:
            self.response_headers.append(("Link", ", ".join(links)))
        self.response_headers.extend([("X-Page", str(self.page)), ("X-Per-Page", str(self.per_page))])
        return rows[:self.per_page]

    async def repository(self, owner, repo):
        if (any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", part)
                or part in (".", "..", ".git") for part in (owner, repo))
                or not self.app._safe_seg(owner) or not self.app._safe_seg(repo)
                or not can_read_repository(self.identity, owner, self.app.FLAT_OWNER_UI)):
            raise APIError(404, "not_found", "Repository not found.")
        def lookup():
            path = Path(self.app._repo_bare_path(owner, repo)).absolute()
            root = Path(self.handler.server.context.config.git_project_root).absolute()
            try:
                relative = path.relative_to(root)
            except ValueError:
                return None
            # Reject aliases even within the root: alice/link -> bob/repo must
            # never turn owner-namespace access into access to Bob's Git data.
            component = root
            for part in relative.parts:
                component /= part
                if component.is_symlink() or component.is_junction():
                    return None
            resolved = path.resolve()
            if not resolved.is_relative_to(root.resolve()) or not self.app._is_git_dir(resolved):
                return None
            return str(resolved)
        path = await asyncio.to_thread(lookup)
        if path is None:
            raise APIError(404, "not_found", "Repository not found.")
        return path

    @staticmethod
    def repo_object(owner, repo):
        encoded = quote(owner, safe="") + "/" + quote(repo, safe="")
        return {"name": repo, "full_name": owner + "/" + repo, "owner": {"login": owner},
                "url": PREFIX + "/repos/" + encoded, "html_url": "/r/" + encoded}

    async def route(self):
        if self.path == PREFIX + "/openapi.json":
            self.parameters()
            from .schema import specification
            return specification()
        if self.path in (PREFIX, PREFIX + "/"):
            self.parameters()
            return {"version": "v1", "read_only": False, "documentation_url": "/api/docs",
                    "openapi_url": PREFIX + "/openapi.json", "repositories_url": PREFIX + "/repos"}
        if self.path == PREFIX + "/user":
            self.parameters()
            return {"id": self.identity["user_id"], "login": self.identity["username"],
                    "is_admin": self.identity["is_admin"], "scopes": sorted(self.identity["scopes"])}
        if self.path == PREFIX + "/repos":
            self.parameters()
            scanned = await asyncio.to_thread(
                self.app._scan_repos, self.handler.server.context.config.git_project_root)
            visible = []
            for owner, repo, _relative in sorted(scanned, key=lambda row: (row[0], row[1])):
                if can_read_repository(self.identity, owner, self.app.FLAT_OWNER_UI):
                    try:
                        await self.repository(owner, repo)
                    except APIError as exc:
                        if exc.status == 404:
                            continue
                        raise
                    visible.append(self.repo_object(owner, repo))
                    if len(visible) > self.offset + self.per_page:
                        break
            return self.listing(visible[self.offset:self.offset + self.per_page + 1])
        match = re.fullmatch(r"/api/v1/repos/([^/]+)/([^/]+)(?:/(.*))?", self.path)
        if not match:
            raise APIError(404, "not_found", "API endpoint not found.")
        owner, repo = unquote(match[1]), unquote(match[2])
        tail = match[3] or ""
        path = await self.repository(owner, repo)
        if tail == "deployments/preflight":
            from . import preflight
            return await preflight.read(self, owner, repo, path)
        if tail == "deployments" or tail.startswith("deployments/"):
            from . import deployments
            return await deployments.read(self, owner, repo, tail)
        if tail == "ci/settings":
            from . import settings
            return await settings.read(self, owner, repo)
        if not tail:
            self.parameters()
            return {**self.repo_object(owner, repo), "default_branch": await git.default_branch(path)}
        if tail == "discussions" or tail.startswith("discussions/"):
            from . import discussions
            return await discussions.read(self, owner, repo, tail)
        if (tail in ("tree", "search", "archive", "compare/files", "compare/diff")
                or re.fullmatch(r"commits/[^/]+/(files|diff)", tail)
                or re.fullmatch(r"pulls/[0-9]{1,18}/(files|diff|commits)", tail)):
            from . import browsing
            return await browsing.read(self, owner, repo, path, tail)
        if tail == "branches":
            self.parameters()
            return self.listing(await git.branches(path, self.per_page + 1, self.offset))
        if tail.startswith("contents/"):
            self.parameters("branch")
            from .writes import file_content
            branch_name = self.value("branch") or await git.default_branch(path)
            return await file_content(path, unquote(tail[len("contents/"):]), branch_name)
        if tail.startswith("branches/"):
            self.parameters()
            name = unquote(tail[len("branches/"):])
            # Resolve only heads here: a tag with the same name is not a branch.
            if not name or name.startswith("-") or len(name) > 256:
                raise APIError(400, "invalid_ref", "Invalid branch name.")
            code, _out = await git.git(path, "check-ref-format", "refs/heads/" + name)
            if code:
                raise APIError(400, "invalid_ref", "Invalid branch name.")
            code, out = await git.git(path, "rev-parse", "--verify", "--end-of-options",
                                      "refs/heads/" + name + "^{commit}")
            if code:
                raise APIError(404, "not_found", "Branch not found.")
            sha = out.decode("ascii").strip()
            return {"name": name, "commit": {"sha": sha}}
        if tail == "commits":
            self.parameters("ref")
            ref = self.value("ref") or await git.default_branch(path)
            if ref is None:
                return self.listing([])
            try:
                sha = await git.resolve(path, ref)
            except APIError as exc:
                # Empty repositories have an unborn default branch.
                if exc.status == 404 and not self.value("ref") and not await git.branches(path, 1, 0):
                    return self.listing([])
                raise
            return self.listing(await git.commits(path, sha, self.per_page + 1, self.offset))
        if tail.startswith("commits/"):
            self.parameters()
            sha = await git.resolve(path, unquote(tail[len("commits/"):]))
            rows = await git.commits(path, sha, 1, 0)
            if not rows:
                raise APIError(404, "not_found", "Commit not found.")
            return rows[0]
        entity = re.fullmatch(r"(issues|pulls)(?:/([0-9]{1,18})(/comments(?:/([0-9]{1,18}))?)?)?", tail)
        if entity:
            kind, identity, comments, comment_id = entity.groups()
            self.parameters(*(["state"] if identity is None else []))
            state = self.value("state", "open") if identity is None else "all"
            if state not in ({"open", "closed", "all"} if kind == "issues" else {"open", "closed", "merged", "all"}):
                raise APIError(400, "invalid_query", "Invalid state filter.")
            read = data.issues if kind == "issues" else data.pulls
            if identity is None:
                return self.listing(await asyncio.to_thread(
                    read, owner, repo, state, self.per_page + 1, self.offset))
            rows = await asyncio.to_thread(read, owner, repo, "all", 1, 0, int(identity))
            if not rows:
                raise APIError(404, "not_found", "Resource not found.")
            if comments:
                rows = await asyncio.to_thread(
                    data.comments, kind, owner, repo, int(identity),
                    1 if comment_id else self.per_page + 1, 0 if comment_id else self.offset,
                    int(comment_id) if comment_id else None)
                if comment_id:
                    if not rows:
                        raise APIError(404, "not_found", "Comment not found.")
                    return rows[0]
                return self.listing(rows)
            return rows[0]
        if tail == "ci/pipelines":
            self.parameters()
            config = await self.handler.server.ci_manager.config(owner, repo)
            rows = [{"name": p["pipeline_id"], "runner": p["runner"],
                     "timeout_seconds": p["timeout_seconds"],
                     "repository_file": p["repository_file"] if p["repository_config"] else None}
                    for p in self.handler.server.ci_manager.pipelines(config)]
            return self.listing(rows[self.offset:self.offset + self.per_page + 1])
        if tail == "ci/artifacts" or re.fullmatch(
                r"ci/runs/[0-9]{1,18}/(logs|artifacts(?:/download)?)", tail):
            from . import ci_operations
            return await ci_operations.read(self, owner, repo, tail)
        run = re.fullmatch(r"ci/runs(?:/([0-9]{1,18}))?", tail)
        if run:
            identity = run[1]
            self.parameters(*(["status", "branch"] if identity is None else []))
            status, branch = self.value("status"), self.value("branch")
            if status and status not in {"queued", "running", "success", "failed", "cancelled", "timed_out", "interrupted"}:
                raise APIError(400, "invalid_query", "Invalid run status.")
            rows = await asyncio.to_thread(
                data.runs, owner, repo, 1 if identity else self.per_page + 1,
                0 if identity else self.offset, identity=int(identity) if identity else None,
                status=status, branch=branch)
            if identity:
                if not rows:
                    raise APIError(404, "not_found", "Run not found.")
                return rows[0]
            return self.listing(rows)
        raise APIError(404, "not_found", "API endpoint not found.")
