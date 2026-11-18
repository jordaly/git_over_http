"""Typed boundaries and serialized models for the JSON API.

The API deliberately exposes heterogeneous JSON.  ``DynamicJSONObject`` marks
mutable document trees whose individual fields are validated at runtime (request
bodies, CI configuration and the generated OpenAPI document).  Responses that
the API itself defines are described by the ``TypedDict`` models below.
"""

from __future__ import annotations

import asyncio
from collections.abc import Hashable, Mapping
from pathlib import Path
from typing import Any, Protocol, TypedDict, overload

from ..database_types import JSONObject

#: Mutable trees whose individual fields are validated at runtime.
type DynamicJSONObject = dict[str, Any]


class Identity(TypedDict):
    """Authenticated bearer-token identity returned by the database layer."""

    user_id: int
    username: str
    is_admin: bool
    scopes: set[str]


class Author(TypedDict):
    id: int
    login: str | None


class BranchReference(TypedDict):
    ref: str


class CommitAuthor(TypedDict):
    name: str
    email: str
    date: str


class CommitDetail(TypedDict):
    message: str
    author: CommitAuthor


class ShaReference(TypedDict):
    sha: str


class Branch(TypedDict):
    name: str
    commit: ShaReference


class Commit(TypedDict):
    sha: str
    parents: list[ShaReference]
    commit: CommitDetail


class Issue(TypedDict):
    id: int
    title: str
    body: str
    user: Author | None
    state: str
    created_at: str | None
    updated_at: str | None
    closed_at: str | None
    revision: str


class Pull(TypedDict):
    id: int
    title: str
    body: str
    user: Author | None
    state: str
    created_at: str | None
    closed_at: str | None
    merged_at: str | None
    head: BranchReference
    base: BranchReference
    merge_method: str | None
    merge_commit_sha: str | None
    revision: str


class Comment(TypedDict):
    id: int
    body: str
    user: Author | None
    created_at: str | None
    edited_at: str | None
    revision: str


class Run(TypedDict):
    id: int
    event: str
    branch: str
    head_sha: str
    status: str
    return_code: int | None
    created_at: str | None
    started_at: str | None
    finished_at: str | None
    pipeline: str


class Artifact(TypedDict):
    id: int
    run_id: int
    name: str
    size_in_bytes: int
    created_at: str | None
    expires_at: str | None


class DownloadableArtifact(Artifact):
    downloadable: bool
    download_url: str


class Discussion(TypedDict):
    id: int
    category: str
    title: str
    body: str
    user: Author | None
    locked: bool
    locked_by: int | None
    answered_comment_id: int | None
    created_at: str | None
    updated_at: str | None
    revision: str


class TreeEntry(TypedDict):
    path: str
    name: str
    mode: str
    type: str
    sha: str
    size: int | None


class SearchMatch(TypedDict):
    path: str
    line_number: int
    text: str
    commit_sha: str


class ChangedFile(TypedDict):
    path: str
    status: str
    additions: int | None
    deletions: int | None


class Diff(TypedDict):
    base_sha: str | None
    head_sha: str
    patch: str


class Deployment(TypedDict):
    id: int
    run_id: int
    commit_sha: str
    status: str
    started_at: str | None
    finished_at: str | None
    notification: str | None
    name: str
    pipeline: str
    branch: str | None
    run_retained: bool
    log_size_in_bytes: int


class SettingsSnapshot(TypedDict):
    configuration: JSONObject
    revision: str
    source_commit: str | None
    source_path: str
    status: str
    error: str | None


class DeploymentStep(TypedDict):
    index: int
    name: str
    status: str
    log_size_in_bytes: int


class HTTPTransport(Protocol):
    def abort(self) -> None: ...


class HTTPWriter(Protocol):
    @property
    def transport(self) -> HTTPTransport: ...

    def write(self, data: bytes) -> None: ...
    async def drain(self) -> None: ...
    def close(self) -> None: ...


class HTTPHeaders(Protocol):
    @overload
    def get(self, name: str) -> str | None: ...
    @overload
    def get(self, name: str, default: str) -> str: ...
    @overload
    def get(self, name: str, default: str | None) -> str | None: ...
    def items(self) -> list[tuple[str, str]]: ...


class HTTPBodyReader(Protocol):
    async def read(self, size: int = -1, /) -> bytes: ...
    async def readexactly(self, size: int, /) -> bytes: ...


class HTTPRequest(Protocol):
    @property
    def method(self) -> str: ...
    @property
    def target(self) -> str: ...
    @property
    def headers(self) -> HTTPHeaders: ...
    @property
    def reader(self) -> HTTPBodyReader: ...
    @property
    def writer(self) -> HTTPWriter: ...
    @property
    def peer_ip(self) -> str: ...
    @property
    def request_id(self) -> str | None: ...
    @request_id.setter
    def request_id(self, value: str | None) -> None: ...


class AppConfig(Protocol):
    @property
    def git_project_root(self) -> str: ...


class AppContext(Protocol):
    @property
    def config(self) -> AppConfig: ...


class CIManager(Protocol):
    async def config(
        self, owner: str, repo: str, revision: str = "HEAD", *, include_secrets: bool = True
    ) -> DynamicJSONObject: ...
    def pipelines(self, config: Mapping[str, Any]) -> list[DynamicJSONObject]: ...
    async def enqueue(
        self,
        owner: str,
        repo: str,
        event: str,
        branch: str = "",
        commit: str = "",
        payload: Mapping[str, Any] | None = None,
        *,
        pipeline: str | None = None,
    ) -> int | None: ...
    async def cancel(self, owner: str, repo: str, identity: int) -> bool: ...
    async def rerun(self, owner: str, repo: str, identity: int) -> int | None: ...
    async def merge_check(
        self,
        owner: str,
        repo: str,
        identity: int,
        base: str,
        head: str,
        branch: str,
    ) -> tuple[Any, ...] | None: ...
    async def save_document(
        self,
        owner: str,
        repo: str,
        document: DynamicJSONObject,
        *,
        preserve_page_settings: bool = False,
    ) -> DynamicJSONObject: ...


class RateLimitChecker(Protocol):
    def check(self, key: Hashable) -> None: ...


class Server(Protocol):
    @property
    def allowlist(self) -> set[str]: ...
    @property
    def api_limiter(self) -> RateLimitChecker: ...
    @property
    def api_slots(self) -> asyncio.Semaphore: ...
    @property
    def api_download_slots(self) -> asyncio.Semaphore: ...
    @property
    def push_finalizers(self) -> set[asyncio.Task[Any]]: ...
    @property
    def push_locks(self) -> dict[tuple[str, str], asyncio.Lock]: ...
    @property
    def settings_lock(self) -> asyncio.Lock: ...
    @property
    def ci_manager(self) -> CIManager: ...
    @property
    def context(self) -> AppContext: ...

    async def _branch_refs(self, owner: str, repo: str) -> dict[str, str] | None: ...
    async def _queue_push_changes(
        self, owner: str, repo: str, before_refs: dict[str, str] | None
    ) -> None: ...


class Application(Protocol):
    FLAT_OWNER_UI: str
    ClientDisconnected: type[BaseException]

    async def _send_response(
        self,
        request: HTTPRequest,
        status: int,
        body: bytes = b"",
        headers: list[tuple[str, str]] | None = None,
        reason: str | None = None,
        include_body: bool = True,
    ) -> None: ...
    def _ip_allowed(self, ip: str, allowlist: set[str]) -> bool: ...
    def _safe_seg(self, segment: str) -> bool: ...
    def _repo_bare_path(self, owner: str, repo: str) -> str: ...
    def _is_git_dir(self, path: Path) -> bool: ...
    def _is_worktree_repo_dir(self, path: Path) -> bool: ...
    def _scan_repos(self, project_root: str) -> list[tuple[str, str, str]]: ...
    async def _git_ff_merge(
        self,
        repo_git: str,
        target_branch: str,
        source_branch: str,
        *,
        expected: tuple[str | None, str | None] | None = None,
    ) -> tuple[bool, str, str | None]: ...


class HTTPHandler(Protocol):
    @property
    def request(self) -> HTTPRequest: ...
    @property
    def server(self) -> Server: ...

    def _apply_auth_info(self, info: Mapping[str, object]) -> None: ...


class APIContext(Protocol):
    """The part of :class:`pygithost.api.router.API` used by route modules."""

    @property
    def app(self) -> Application: ...
    @property
    def handler(self) -> HTTPHandler: ...
    @property
    def request(self) -> HTTPRequest: ...
    @property
    def request_id(self) -> str: ...
    @property
    def response_headers(self) -> list[tuple[str, str]]: ...
    @property
    def response_status(self) -> int: ...
    @response_status.setter
    def response_status(self, value: int) -> None: ...
    @property
    def download_slot(self) -> bool: ...
    @download_slot.setter
    def download_slot(self, value: bool) -> None: ...
    @property
    def path(self) -> str: ...
    @property
    def query(self) -> dict[str, list[str]]: ...
    @property
    def page(self) -> int: ...
    @property
    def per_page(self) -> int: ...
    @property
    def offset(self) -> int: ...
    @property
    def document(self) -> DynamicJSONObject: ...
    @property
    def idempotency_key(self) -> str: ...
    @property
    def identity(self) -> Identity: ...
    def value(self, key: str, default: str = "") -> str: ...
    def integer(self, key: str, default: int, minimum: int, maximum: int) -> int: ...
    def parameters(self, *allowed: str) -> None: ...
    def listing[T](self, rows: list[T]) -> list[T]: ...
    async def repository(self, owner: str, repo: str) -> str: ...
    def repo_object(self, owner: str, repo: str) -> DynamicJSONObject: ...
    def log_failure(self, exc: BaseException) -> None: ...
