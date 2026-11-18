"""Shared value, row, and JSON types for the SQLite persistence helpers.

The synchronous database module deliberately keeps SQLite rows as positional
tuples.  These aliases document the column order of each query while keeping
the runtime API unchanged.
"""

import json
from typing import TypeAlias, TypedDict, cast

# Values SQLite can bind directly. sqlite3.Binary() is a memoryview.
SQLValue: TypeAlias = str | int | float | bytes | memoryview | None

# A row from a query with a dynamic projection (filters, optional columns).
SQLRow: TypeAlias = tuple[SQLValue, ...]

# Parsed JSON documents stored in TEXT columns.
JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
JSONObject: TypeAlias = dict[str, JSONValue]


def decode_json_object(raw: str) -> JSONObject:
    """Decode a persisted JSON document whose root must be an object.

    SQLite TEXT columns are untyped, so a syntactically valid JSON array or
    scalar is still an invalid application document.  Fail closed instead of
    treating it as a mapping.
    """
    decoded = json.loads(raw)
    if not isinstance(decoded, dict):
        raise ValueError("Expected a JSON object.")
    return cast(JSONObject, decoded)


# Authenticated identities returned by password/session/token verification.
AuthInfo: TypeAlias = dict[str, object]

# users: id, username, pass_salt, pass_hash, is_admin, is_active.
UserAuthRow: TypeAlias = tuple[int, str, bytes, bytes, int, int]
# users: id, username, is_admin, is_active, created_at.
UserRow: TypeAlias = tuple[int, str, int, int, str]

# tokens: id, name, scopes, is_active, created_at, expires_at, revoked_at, status.
TokenListRow: TypeAlias = tuple[int, str, str, int, str, str | None, str | None, str]
# tokens joined with users: u.id, u.username, u.is_admin, u.is_active,
# t.scopes, t.is_active, t.expires_at, t.revoked_at.
TokenAuthRow: TypeAlias = tuple[int, str, int, int, str, int, str | None, str | None]
# sessions joined with users: session id, user id, username, is_admin,
# is_active, expires_at, revoked_at.
SessionRow: TypeAlias = tuple[int, int, str, int, int, str, str | None]

# A comment joined with its author: id, author_user_id, username, body,
# created_at, edited_at.
CommentRow: TypeAlias = tuple[int, int | None, str | None, str, str, str | None]
# A comment identity check: id, parent_id, author_user_id, body.
CommentIdentityRow: TypeAlias = tuple[int, int, int | None, str]

# pull_requests: id, owner, repo, title, body, source_branch, target_branch,
# author_user_id, status, created_at, closed_at, merged_at, merge_method,
# merge_commit.
PullRequestRow: TypeAlias = tuple[
    int,
    str,
    str,
    str,
    str,
    str,
    str,
    int | None,
    str,
    str,
    str | None,
    str | None,
    str | None,
    str | None,
]
# pull_requests listing: id, title, source_branch, target_branch, status,
# created_at.
PullRequestListRow: TypeAlias = tuple[int, str, str, str, str, str]
# A pull request branch reference: id, branch.
PullRequestBranchRow: TypeAlias = tuple[int, str]

# issues: id, owner, repo, title, body, author_user_id, username, status,
# created_at, updated_at, closed_at.
IssueRow: TypeAlias = tuple[
    int,
    str,
    str,
    str,
    str,
    int | None,
    str | None,
    str,
    str,
    str | None,
    str | None,
]
# issues listing: id, title, status, created_at, author_user_id, username.
IssueListRow: TypeAlias = tuple[int, str, str, str, int | None, str | None]

# discussions: id, owner, repo, category, title, body, author_user_id,
# username, locked, locked_by, answered_comment_id, created_at, updated_at.
DiscussionRow: TypeAlias = tuple[
    int,
    str,
    str,
    str,
    str,
    str,
    int | None,
    str | None,
    int,
    int | None,
    int | None,
    str,
    str | None,
]
# discussions listing: id, title, category, created_at, author_user_id,
# username, answered_comment_id.
DiscussionListRow: TypeAlias = tuple[int, str, str, str, int | None, str | None, int | None]

# ci_deployments: status, output.
DeploymentRow: TypeAlias = tuple[str, str]
# ci_deployments email record: run_id, owner, repo, commit_hash, status,
# config_json, notification, started_at, finished_at.
DeploymentEmailRow: TypeAlias = tuple[int, str, str, str, str, str, str, str, str | None]
# ci_deployments history/detail: id, run_id, commit_hash, status, started_at,
# finished_at, notification, config_json, run_id, output, steps_json.
DeploymentListRow: TypeAlias = tuple[
    int,
    int,
    str,
    str,
    str,
    str | None,
    str,
    str,
    int | None,
    str,
    str,
]
# ci_deployments for a run: id, pipeline_id, status, output, notification,
# config_json.
DeploymentRunRow: TypeAlias = tuple[int, str, str, str, str, str]

# ci_runs detail: id, event, branch, commit_hash, status, output, truncated,
# return_code, created_at, started_at, finished_at.
CIRunRow: TypeAlias = tuple[
    int,
    str,
    str,
    str,
    str,
    str,
    int,
    int | None,
    str,
    str | None,
    str | None,
]
# A ci_runs listing without optional columns.
CIRunListRow: TypeAlias = CIRunRow
# A ci_runs listing with the trailing warnings column.
CIRunListWarningsRow: TypeAlias = tuple[
    int,
    str,
    str,
    str,
    str,
    str,
    int,
    int | None,
    str,
    str | None,
    str | None,
    str,
]
# A ci_runs listing with the trailing pipeline id column.
CIRunListPipelineRow: TypeAlias = tuple[
    int,
    str,
    str,
    str,
    str,
    str,
    int,
    int | None,
    str,
    str | None,
    str | None,
    str,
]
# A ci_runs listing with both trailing optional columns.
CIRunListWarningsPipelineRow: TypeAlias = tuple[
    int,
    str,
    str,
    str,
    str,
    str,
    int,
    int | None,
    str,
    str | None,
    str | None,
    str,
    str,
]
# ci_runs merge check: id, status.
CIRunStatusRow: TypeAlias = tuple[int, str]
# ci_runs latest run: id, status, event, branch, commit_hash, created_at.
CIRunLatestRow: TypeAlias = tuple[int, str, str, str, str, str]
# A queued/notifiable ci_runs row: id, owner, repo, event, branch,
# commit_hash, payload_json.
CIRunNotificationRow: TypeAlias = tuple[int, str, str, str, str, str, str]
# ci_artifacts list: run id, branch, commit_hash, status, event, created_at,
# archive size, expiration timestamp.
CIArtifactRow: TypeAlias = tuple[int, str, str, str, str, str, int, str | None]


class CIRunMetadata(TypedDict):
    """Non-scalar CI run fields used to rebuild pipeline state."""

    payload: str
    config: str
    phase: str
    reason: str
    notification: str
    warnings: str


class RetentionConfig(TypedDict):
    """Resolved artifact and run retention limits for one repository."""

    artifact_retention_days: int
    artifact_retention_count: int
    run_retention_count: int
