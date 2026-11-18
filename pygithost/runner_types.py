"""Shared typing for CI coordinators, HTTP workers and image build preparation.

Configuration documents and database rows cross several modules.  These aliases
and protocols describe that data without importing any of the implementation
modules, so the worker protocol can stay independent of the local executor.
"""

from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, NotRequired, Protocol, TypeAlias, TypedDict

from .database_types import CIRunNotificationRow

#: Validated JSON-shaped configuration document. Values are re-validated at the
#: boundaries that consume them, so this alias only records the container shape;
#: :mod:`pygithost.database_types` keeps the stricter storage-only JSON union.
JsonObject: TypeAlias = dict[str, Any]

#: Fixed execution/queue row: run id, owner, repo, event, branch, commit hash and
#: payload JSON. The HTTP protocol serializes this row as a seven-element array.
RunRow: TypeAlias = CIRunNotificationRow

#: Notification stubs only need the run id, owner and repository.
RunIdentity: TypeAlias = tuple[int, str, str]


class RunnerJob(TypedDict):
    """Job document claimed by an HTTP worker from the server."""

    run_id: int
    attempt: str
    config: JsonObject
    row: RunRow


class StepState(TypedDict, total=False):
    """One execution or deployment step persisted for a CI run."""

    name: str
    status: str
    output: str
    started_at: str | None
    finished_at: str | None
    return_code: int | None
    duration: str
    run: str


class ProgressSnapshot(TypedDict):
    """Bounded progress payload uploaded by an HTTP worker."""

    output: str
    truncated: int
    phase: str
    steps: list[StepState]
    status: NotRequired[str]
    return_code: NotRequired[int | None]
    started_at: NotRequired[str]
    finished_at: NotRequired[str]
    reason: NotRequired[str]
    warnings: NotRequired[str]


class ProcessManager(Protocol):
    """The coordinator subset needed to run bounded subprocesses on a worker."""

    http_attempt: str
    docker_policy: JsonObject

    async def _capture_process(
        self,
        command: Sequence[str] | str,
        *,
        shell: bool,
        cwd: str | None,
        env: Mapping[str, str] | None,
        output: bytearray,
        truncated: list[bool],
        timeout: float,
        on_output: Callable[[], Awaitable[None]] | None = None,
        max_output: int = ...,
    ) -> int: ...


class SourceManager(Protocol):
    """Coordinator interface used while preparing a remote source bundle."""

    repo_path: Callable[[str, str], str]
