# REST API

The API provides authenticated reads and safe JSON mutations under
`/api/v1`. It is inspired by GitHub's conventions, **not GitHub API compatible**.
Existing Git HTTP and web routes are unchanged.

## Authentication and repository access

Create a personal access token on the **Tokens** page with at least `read` scope.
Every new token is bound to **one repository**, chosen when it is created (the
repository's **Settings** page links to the form with it preselected). The token
then works only for that repository, both here and for Git over HTTP: every other
repository answers `404`, and `GET /api/v1/repos` lists only the bound one.
`GET /api/v1/user` reports the binding as `"repository": "owner/repo"`. Tokens
created before repository binding existed report `null` and keep working for every
repository; revoke and recreate them to restrict them. Deleting a repository revokes
its tokens, so a new repository with the same name starts with none.
Send it in `Authorization: Bearer TOKEN`. A token with `write` scope also receives
`read`; `admin` alone does not imply `read`. Tokens are checked on every request:
revoked, expired tokens and tokens belonging to disabled users are rejected.

Every API endpoint, including discovery and OpenAPI, requires bearer authentication,
even if web authentication is disabled. Cookies, passwords, Basic authentication
and query-string tokens are not accepted. Anonymous API reads are not supported.
Use HTTPS when accessing the API outside trusted local development. The HTTP
server does not provide TLS; configure a reverse proxy.

Repository access is intentionally stricter than the web interface. The binding
narrows these rules and never widens them: a token bound to `bob/project` that
belongs to the non-admin `alice` still cannot read it through the API.

- Non-admin users can read only repositories whose owner namespace exactly matches
  their username.
- Administrators with a read-scoped token can read every repository.
- Flat-layout repositories use the server's flat owner name (normally `root`) and
  are accessible only to administrators through this API.
- Missing and inaccessible repositories both return `404`.
- Symlinked/junction owner directories and repositories are not exposed by the API,
  including aliases to another repository inside the project root.
- Repository collaborator ACLs are not implemented. A token's repository binding
  limits that token; it does not grant its owner membership of the repository.

The existing server IP allowlist applies. CORS access is not enabled.
Every mutation requires `write` scope as well as repository access. An administrator's
read-only token cannot write, even when web authentication is disabled.

When web authentication is disabled there is no signed-in user, so tokens made on
the **Tokens** page belong to the oldest active administrator account (normally the
bootstrap `admin`). Their repository binding is what limits them. Git over HTTP does
not check tokens at all in that mode (the IP allowlist is the boundary), so the
binding only restricts the API there.

## Quick start

In Bash, set your server address and token without putting credentials in URLs:

```sh
export PYGITHOST_URL="http://127.0.0.1:8000"
read -rsp "Access token: " PYGITHOST_TOKEN
export PYGITHOST_TOKEN
curl --fail-with-body -H "Authorization: Bearer $PYGITHOST_TOKEN" \
  "$PYGITHOST_URL/api/v1/user"
curl --fail-with-body -H "Authorization: Bearer $PYGITHOST_TOKEN" \
  "$PYGITHOST_URL/api/v1/repos?per_page=20"
```

Use Python's standard library:

```python
import json
import os
from urllib.request import Request, urlopen

base = os.environ["PYGITHOST_URL"].rstrip("/")
token = os.environ["PYGITHOST_TOKEN"]
request = Request(
    base + "/api/v1/repos",
    headers={"Authorization": "Bearer " + token},
)
with urlopen(request, timeout=30) as response:
    repositories = json.load(response)
for repository in repositories:
    print(repository["full_name"])
```

Do not log tokens, include them in source control, or publish your shell environment.

## Implemented endpoints

The following endpoints use `GET`. `HEAD` returns the same status and headers without
a body. Supported mutations are listed separately below.

| Path relative to `/api/v1` | Description |
| --- | --- |
| `/` | API discovery and documentation URLs |
| `/openapi.json` | OpenAPI 3.1 specification |
| `/user` | Token owner, administrator flag, granted scopes and bound `repository` (`owner/repo`, or `null` for a legacy token) |
| `/repos` | Accessible repositories, ordered by owner then name |
| `/repos/{owner}/{repo}` | Repository and default branch |
| `/repos/{owner}/{repo}/branches` | Branches, ordered by full ref name |
| `/repos/{owner}/{repo}/branches/{branch}` | One branch and commit SHA |
| `/repos/{owner}/{repo}/commits` | Commits from `ref`, defaulting to the default branch |
| `/repos/{owner}/{repo}/commits/{ref}` | Commit metadata, parents and message |
| `/repos/{owner}/{repo}/tree` | Paginated directory/tree metadata; `ref`, `path`, `recursive` |
| `/repos/{owner}/{repo}/search` | Literal text search; required `q`, optional `ref`, `path`, `ignore_case` |
| `/repos/{owner}/{repo}/compare/files` | Changed files between required `base` and `head` refs |
| `/repos/{owner}/{repo}/compare/diff` | Bounded patch between required `base` and `head` refs |
| `/repos/{owner}/{repo}/commits/{ref}/files` | Commit's changed files and line counts |
| `/repos/{owner}/{repo}/commits/{ref}/diff` | Commit's first-parent patch (root commits supported) |
| `/repos/{owner}/{repo}/archive` | Source ZIP for optional `ref` |
| `/repos/{owner}/{repo}/ci/settings` | Administrator-only read-only CI configuration with Git source commit/path, status, error and informational revision |
| `/repos/{owner}/{repo}/issues` | Issues; `state=open` (default), `closed`, or `all` |
| `/repos/{owner}/{repo}/issues/{id}` | One issue |
| `/repos/{owner}/{repo}/issues/{id}/comments` | Comments, ordered oldest first |
| `/repos/{owner}/{repo}/issues/{id}/comments/{comment_id}` | One issue comment and its revision |
| `/repos/{owner}/{repo}/pulls` | PRs; `state=open` (default), `closed`, `merged`, or `all` |
| `/repos/{owner}/{repo}/pulls/{id}` | One pull request |
| `/repos/{owner}/{repo}/pulls/{id}/comments` | PR comments, ordered oldest first |
| `/repos/{owner}/{repo}/pulls/{id}/comments/{comment_id}` | One PR comment and its revision |
| `/repos/{owner}/{repo}/pulls/{id}/files` | Files changed from the PR merge base to its head |
| `/repos/{owner}/{repo}/pulls/{id}/diff` | Bounded PR patch from the merge base |
| `/repos/{owner}/{repo}/pulls/{id}/commits` | Head commits not reachable from the current target |
| `/repos/{owner}/{repo}/discussions/categories` | Supported categories and accepted-answer capability |
| `/repos/{owner}/{repo}/discussions` | Discussion list; optional `category` and `locked` filters |
| `/repos/{owner}/{repo}/discussions/{id}` | One discussion, lock/answer state and revision |
| `/repos/{owner}/{repo}/discussions/{id}/comments` | Replies ordered oldest first |
| `/repos/{owner}/{repo}/discussions/{id}/comments/{comment_id}` | One reply and its revision |
| `/repos/{owner}/{repo}/contents/{path}` | Regular UTF-8 text file, base64-encoded; optional `branch` |
| `/repos/{owner}/{repo}/ci/pipelines` | Named pipeline summaries |
| `/repos/{owner}/{repo}/ci/runs` | CI run summaries; optional `status` and `branch` filters |
| `/repos/{owner}/{repo}/ci/runs/{id}` | One CI run summary |
| `/repos/{owner}/{repo}/ci/runs/{id}/logs` | Bounded log chunk; optional byte `offset` and `limit` |
| `/repos/{owner}/{repo}/ci/artifacts` | Paginated repository archive metadata |
| `/repos/{owner}/{repo}/ci/runs/{id}/artifacts` | Zero or one archive for the selected run |
| `/repos/{owner}/{repo}/ci/runs/{id}/artifacts/download` | Original ZIP archive (binary response) |

Use `id` values returned by the API. Issue and PR IDs currently come from separate
database-wide sequences, **not** GitHub-style per-repository issue numbers. Resources
are always looked up within their repository. PRs are not included in issue lists.
Closed PR filtering excludes merged PRs; use `state=merged` or `state=all`.

Commit `ref` accepts a branch name, tag name or full 40/64-character SHA; branch
names take priority over tags. Revision expressions, ranges, reflogs and abbreviated
SHAs are not supported. Percent-encode URL path segments and query values.
Slash-containing branch names can be passed as `feature%2Fapi` in branch paths;
use `?ref=feature%2Fapi` for commit lists. An empty repository returns empty branch
and default commit lists.

CI statuses are `queued`, `running`, `success`, `failed`, `timed_out`, `cancelled`,
and `interrupted`. Run/pipeline summaries do not expose environment variables,
configuration snapshots, scripts, payloads or log/archive contents. Separate log
and artifact endpoints provide authorized access to job outputs. Pipeline summaries
describe the current repository `ci/config.json` or the built-in missing-file
fallback, not saved database definitions.

## Safe write endpoints

All paths below are relative to `/api/v1`. Send `Content-Type: application/json`,
a JSON object, and one `Idempotency-Key` header. Mutation query parameters and
chunked bodies are not accepted. Unknown fields, forged authors, invalid types,
blank titles/comments and unsupported states are rejected rather than ignored.
Titles are limited to 256 characters, bodies to 65536, and commit messages to 4000.
The authenticated token owner is always recorded as the author.
Idempotency keys are scoped to the user, and additionally to the repository for
repository-bound tokens, so two bound tokens of one user never collide.

| Method | Path | Required JSON fields |
| --- | --- | --- |
| `POST` | `/user/repos` | `name`; optional `default_branch` (default `main`), `auto_init` (`true` adds a `README.md`), `gitignore_template` (`C`, `C#`, `C++`, `Go`, `Java`, `Node`, `Python`, `Rust`), `license_template` (`MIT`, `Apache-2.0`, `GPL-3.0`, `MPL-2.0`, `BSD-3-Clause`, `Unlicense`); any of these creates an initial commit |
| `POST` | `/repos/{owner}/{repo}/branches` | `name`, `sha` (full source commit SHA) |
| `DELETE` | `/repos/{owner}/{repo}/branches/{branch}` | `expected_head` (full current commit SHA) |
| `PUT` | `/repos/{owner}/{repo}/contents/{path}` | `branch`, `expected_head`, `message`, `content` (base64 UTF-8) |
| `DELETE` | `/repos/{owner}/{repo}/contents/{path}` | `branch`, `expected_head`, `message` |
| `POST` | `/repos/{owner}/{repo}/issues` | `title`; optional `body` |
| `PATCH` | `/repos/{owner}/{repo}/issues/{id}` | `expected_revision`; one or more of `title`, `body`, `state` |
| `POST` | `/repos/{owner}/{repo}/issues/{id}/comments` | `body` |
| `PATCH` | `/repos/{owner}/{repo}/issues/{id}/comments/{comment_id}` | `body`, `expected_revision` |
| `DELETE` | `/repos/{owner}/{repo}/issues/{id}/comments/{comment_id}` | `expected_revision` |
| `POST` | `/repos/{owner}/{repo}/pulls` | `title`, `head`, `base` (branch names); optional `body` |
| `PATCH` | `/repos/{owner}/{repo}/pulls/{id}` | `expected_revision`; one or more of `title`, `body`, `state` |
| `POST` | `/repos/{owner}/{repo}/pulls/{id}/comments` | `body` |
| `PATCH` | `/repos/{owner}/{repo}/pulls/{id}/comments/{comment_id}` | `body`, `expected_revision` |
| `DELETE` | `/repos/{owner}/{repo}/pulls/{id}/comments/{comment_id}` | `expected_revision` |
| `PUT` | `/repos/{owner}/{repo}/pulls/{id}/merge` | `sha` (source SHA), `expected_base_sha` (target SHA) |
| `POST` | `/repos/{owner}/{repo}/ci/runs` | `branch`, `pipeline`; optional `sha` to verify the branch tip |
| `POST` | `/repos/{owner}/{repo}/ci/runs/{id}/cancel` | Empty JSON object `{}` |
| `POST` | `/repos/{owner}/{repo}/ci/runs/{id}/rerun` | Empty JSON object `{}` |
| `POST` | `/repos/{owner}/{repo}/discussions` | `title`; optional `body`, `category` |
| `PATCH` | `/repos/{owner}/{repo}/discussions/{id}` | `expected_revision`; one or more discussion fields |
| `POST` | `/repos/{owner}/{repo}/discussions/{id}/comments` | `body` |
| `PATCH` | `/repos/{owner}/{repo}/discussions/{id}/comments/{comment_id}` | `body`, `expected_revision` |
| `DELETE` | `/repos/{owner}/{repo}/discussions/{id}/comments/{comment_id}` | `expected_revision` |

Creation returns `201`; updates, merges and deletions return `200` with a JSON
result. File PUT returns `201` for a new file and `200` for an update. CI triggers
and reruns return `202` with a run summary; cancellation returns `200`.
Repository creation is limited to the current user's namespace, including for
administrators, and is refused (`403`) for repository-bound tokens. Without
`auto_init` or a template a repository starts empty: push its first commit with Git.
Creating the first commit in an unborn branch through the contents API is not yet
supported. Repository deletion and repository settings updates are not implemented.

For issue/PR/comment edits, first GET the resource and pass its opaque `revision`
as `expected_revision`. A stale revision returns `409`, including after edits from
the web UI. State changes accept `open` or `closed`; merged PRs cannot be edited or
reopened. PR creation/reopening requires existing source and target branches.
Adding PR comments requires an open PR. Only the original comment author or an
administrator may edit/delete a comment, regardless of repository ownership.

Branch/file edits require full current SHAs and compare-and-swap updates. Protected
branches reject direct creation/deletion/file changes; the default branch cannot be
deleted. File changes are Git commits, not writes into a server checkout. They reuse
the browser editor's lease, receive hooks, executable modes and checked-out-branch
checks. Only regular UTF-8 text files up to 1 MiB are supported; binary files,
symlinks, submodules, `.git` paths and traversal are rejected. File GET defaults to
the default branch and returns `commit_sha` for use as `expected_head`.

Merges reuse the web UI's fast-forward-only merge operation. Both current source
and target SHAs must match, and required CI must pass for that exact pair. A Git
transaction verifies both refs during the update; non-fast-forward merges and
checked-out target branches are rejected. Branch operations and merges use Git ref
transactions, not receive-pack; file commits use receive-pack. There are no API
approval overrides, squash/rebase merges, or author impersonation fields.

Git-changing writes schedule the existing push/PR CI events. This preserves normal
CI/deployment behavior for qualifying branch updates; creating an issue/comment
does not run CI. If Git succeeds but subsequent CI scheduling fails, the successful
response includes `warnings`; inspect CI rather than blindly repeating the write.

### Write example and retry rules

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $PYGITHOST_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: create-issue-2026-001" \
  --data '{"title":"API-created issue","body":"Created by an integration"}' \
  "$PYGITHOST_URL/api/v1/repos/alice/project/issues"
```

Replace the owner/repository with one you may access. Use a write-scoped token.
Keep the same key for retries of the **same** operation; use a new key for a new
operation. Keys contain 1–128 ASCII letters, digits, dots, underscores, colons or
hyphens. They are scoped to the token owner's user ID, not to an individual token.

Completed requests replay their original status and resource response with
`X-Idempotent-Replay: true`. JSON object key order does not affect matching.
Reusing a key for different JSON, path or method returns `409 idempotency_conflict`.
Validation/state errors reached after a claim are also cached, so use a new key
after correcting the request. Authentication and current repository access are
checked again before replay.

A response timeout or disconnect does **not** cancel an accepted mutation.
Retry the identical request with the same key. If it is still running, or the
server crashed before recording its result, the API returns `409 operation_pending`
and does not run it again. Inspect the resource before taking recovery action.
Git and SQLite cannot be committed atomically; this is duplicate prevention, not
a guarantee of exactly-once distributed transactions.

The `api_mutations` SQLite table provides the mutation audit metadata (actor ID,
request ID, method, path, start/completion time and status) and durable response
cache. Keys and request fingerprints are hashed; tokens and raw request bodies are
not recorded. Cached resource responses can contain issue/comment text, so protect
the database and backups. Claims are not automatically expired; deleting one
removes its duplicate-prevention guarantee. There is no audit-management API yet.

## Repository browsing and comparisons

All of these endpoints require `read` scope and the same repository-access checks
as contents/commits. Refs accept branch names, tag names or full SHAs; ranges and
revision expressions are not accepted. Resolve once and pass a full SHA when you
need consistent pages while branches are changing.

### Trees and search

`GET .../tree?path=src&recursive=false` lists entries in a directory. Omit `path`
for the root; `recursive=true` includes descendant trees and files. Each entry has
`path`, `name`, `mode`, Git object `type`, `sha`, and `size` (null for trees/gitlinks).
Symlinks retain mode `120000` but are not followed; submodules retain mode `160000`
and type `commit` and are never fetched or recursively inspected.
Paths are checkout-relative, with no traversal or `.git` components. A missing
directory, a file used as a directory, or an unborn repository returns `404`.

`GET .../search?q=Needle&path=src&ignore_case=true` searches tracked text at the
selected commit, not the server working tree. `q` is a nonempty single-line literal
string up to 256 characters, not a regular expression. Binary files are skipped;
lines that are not valid UTF-8 are skipped. Results contain `path`, `line_number`,
`text`, and `commit_sha`. No textconv helpers or submodule fetches are executed.
`ignore_case` and `recursive` accept only `true` or `false`.

Both lists use normal pagination and return `X-Commit-SHA`. Tree/search Git output
is capped at 1 MiB before pagination, so an unusually large result can return `413`
even with a small page. Narrow the directory or search query. Query parameter values
are limited to 256 characters. JSON path metadata requires UTF-8 Git filenames;
unsupported encodings return `422`. UTF-8 spaces and Unicode names are preserved.

```sh
curl --fail-with-body -H "Authorization: Bearer $PYGITHOST_TOKEN" \
  "$PYGITHOST_URL/api/v1/repos/alice/project/tree?path=src&recursive=true"
curl --fail-with-body -G -H "Authorization: Bearer $PYGITHOST_TOKEN" \
  --data-urlencode "q=literal.*" --data-urlencode "path=src" \
  "$PYGITHOST_URL/api/v1/repos/alice/project/search"
```

### Changed files, patches and PR commits

`GET .../compare/files?base=main&head=feature` compares those two pinned trees
directly. Each changed file has `path`, Git `status`, `additions`, and `deletions`.
Binary changes have null line counts. Rename detection is disabled: moves appear
as a deletion and an addition. Files use standard pagination, `X-Base-SHA` and
`X-Commit-SHA` headers. `GET .../compare/diff` returns `base_sha`, `head_sha`, and
a bounded textual `patch` instead.

`GET .../commits/{ref}/files` and `/diff` compare a commit with its first parent.
Root commits are compared with an empty tree, with `base_sha: null`.

PR file/patch views compare the branches' **merge base** with the source head,
not the current target tree directly. This avoids including target-only changes.
`GET .../pulls/{id}/commits` lists head commits not reachable from the target,
newest first in Git log order. Unrelated histories return `409` for PR file/patch
views. These views resolve current branch tips; deleted branches return `404`.
They are not a stored immutable PR-diff history.

Diff/statistics output is bounded at 1 MiB per Git command and patches are not
silently truncated: excessive output returns `413`. Repository external-diff and
textconv programs are disabled. Binary patch content is not included. File diffs
and source text are untrusted data; do not execute content returned by the API.

### Source ZIP downloads

`GET .../archive?ref=main` generates a Git source ZIP with a
`{repo}-{commit-prefix}/` directory prefix. Standard Git `export-ignore` and
`export-subst` attributes apply. Untracked server files and Git's metadata directory
are not included; nothing is extracted on the server.

The ZIP is capped at 32 MiB and generation uses the bounded Git subprocess timeout.
It shares the two archive download permits with CI artifacts, including generation
and transfer. `HEAD` generates the same bounded ZIP to determine its length but
sends no body; unlike artifact HEAD, it cannot use a pre-stored archive size.
Responses use `application/zip`, an attachment filename and `Cache-Control: no-store`.
Treat archive entries as untrusted before extracting them on your system.

## Discussions

Discussion reads require `read` scope. Creates, edits, locking, accepted-answer
changes and reply deletion require `write`, repository access and an idempotency
key. Authors always come from the bearer token, never a request field.
Discussion IDs and comment IDs are database-wide within their own tables.

Create a topic with `POST .../discussions` and JSON such as:

```json
{"title":"How should we package the build?","category":"Q&A","body":"Please suggest an approach."}
```

Categories are `Announcements`, `Ideas`, `Q&A`, `Show and tell`, and `General`
(the default). Query `GET .../discussions/categories` rather than guessing category
values. Lists support `category` and `locked=true|false`; invalid filters return
`400`, not an unfiltered list. Discussion timestamps are UTC.

To edit, first GET the discussion and send `PATCH .../discussions/{id}` with its
`expected_revision` plus any of `title`, `body`, `category`, `locked`,
`answered_comment_id`. A stale revision returns `409`, including after web edits.
Unknown fields, invalid categories, non-boolean lock values and malformed revisions
return `422`. Titles/bodies have the same length limits as issues.

- Set `locked: true` to disable new replies, even for administrators. Set it to
  false to unlock and clear the recorded locker. Existing comment authors/admins
  may still edit or delete their replies while the discussion is locked.
- Set `answered_comment_id` to a reply from the **same Q&A discussion** to accept it.
  Set it to null to clear the answer. Another discussion's reply returns `404`;
  accepting an answer in a non-Q&A category returns `409`.
- Moving a topic out of Q&A clears its accepted answer. Deleting an accepted reply
  also clears the pointer in the same SQLite transaction.

Replies use `POST .../discussions/{id}/comments` with `body`. Reply PATCH/DELETE
requires the reply's `expected_revision`, not the parent's. Only the original reply
author or an administrator may edit/delete it; repository ownership alone is not
enough. Lock checks, revision checks and answer membership are transactional.
Replies are listed oldest first with standard pagination and include UTC edit times.
Deleting an entire discussion is not implemented (nor exposed by the current UI).

### Browsing and discussion tests

The new endpoint tests cover namespace isolation, literal search and Unicode paths,
root commits, binary statistics, merge-base PR comparisons, unrelated histories,
source ZIP limits, symlink/gitlink metadata, disabled external helpers, and
OpenAPI/in-page documentation. Discussion tests cover strict validation,
idempotency, stale web/API edits, lock behavior, reply ownership, accepted-answer
membership and transactional cleanup.

```sh
python -m unittest tests.test_api_browsing tests.test_api_discussions -v
```

## CI and deployment settings API

`GET /api/v1/repos/{owner}/{repo}/ci/settings` returns a read-only snapshot of the
repository's committed CI source. This endpoint is **administrator-only**, even for
repository owners. Bearer `read` scope is mandatory; administrator status does not
bypass scopes.

| Field | Meaning |
| --- | --- |
| `configuration` | Parsed committed document, or `{}` when the file is missing or unreadable. |
| `source_commit` | Full SHA inspected on the default branch, or `null` when the revision is unavailable. |
| `source_path` | Always `ci/config.json`. |
| `status` | `valid`, `missing`, `invalid`, `blocked` (administrator trust denied), or `unavailable` (revision cannot be resolved). |
| `error` | Fixed diagnostic for an invalid or blocked source, or `null`. It never includes file contents or environment values. |
| `revision` | Informational digest of the source commit/path. It changes when the committed configuration changes, not when page values change. |

Project CI and deployment definitions are owned by the repository, not by the
database or this API. Commit them to **`ci/config.json`**. This settings endpoint
shows the default branch configuration; CI runs use their recorded commit (the
target/base commit for pull-request checks). Validate before committing with
`python -m pygithost ci validate`; the web **CI → Run pipeline** page provides the same
read-only branch check with the exact configuration commit and status.

The entry file may use the simple pipeline form or a full grouped document with
named `pipelines` and `deployments`. Referenced pipeline files must be regular JSON
files strictly under `ci/`; the entry file cannot reference itself. Configuration
is limited to 256 KiB per regular blob, and invalid configuration fails closed when
the server reads it.

A malformed committed file fails closed for repository protection: merges require
CI and all direct branches are protected until an operator repairs the file through
Git or the server filesystem. A stale successful check cannot satisfy an invalid
base configuration. The API cannot repair it; there is no replacement operation or
saved-definition fallback. Validate configuration before committing.

`PUT /api/v1/repos/{owner}/{repo}/ci/settings` is **disabled**. A PUT returns
`410 Gone`; other unsupported methods return `405`. There is no API replacement
operation, no saved project definition and no writable revision to submit. Use the
normal Git workflow to commit configuration. The read response exposes only the
committed document; page-managed environment values are neither returned nor mixed
into `configuration`.

Repository environment variables and secrets stay on the project page, not in Git.
Configuration bodies, settings storage and logs are plaintext. Page values are
resolved when execution begins rather than copied into new stored run snapshots,
but they can appear in remote job assignments and logs. They are withheld from all
unmerged pull-request checks. The API does not expose or replace those values.
Never put credentials in `ci/config.json`; page-managed values override matching
committed `env` names. Repository rows may be scoped to ordinary non-PR CI,
administrator-authorized protected branches, or deployments only. Protected values
additionally require the exact `owner/repo:branch` in
`PYGITHOST_CI_PROTECTED_SECRET_BRANCHES`, matching default-branch protection rules,
and the current branch tip.

Host jobs and enabled deployments are trusted server-user code. Adding them to
`ci/config.json` does not authorize them: an administrator must add the exact
`owner/repo` under **Admin → Settings → Trusted CI repositories**. Wildcards, patterns and
malformed names are rejected. Ordinary Docker and remote-Docker pipelines continue
under the worker's own policy. A parseable document denied by this guard keeps its
declared branch policies but fails the queued run at configuration. The read
endpoint does not grant trust, execute a deployment or perform deployment preflight.

Tests: `python -m unittest tests.test_api_settings -v`.

## Deployment diagnostics and preflight

All deployment diagnostics require bearer `read` scope and repository access:

| GET endpoint (under `/api/v1/repos/{owner}/{repo}`) | Result |
| --- | --- |
| `/deployments` | Paginated history, newest first |
| `/deployments/{id}` | Status, tested SHA, pipeline/target, timestamps, notification state and retained-CI flag |
| `/deployments/{id}/steps` | Paginated step names, zero-based indexes, statuses and stored log sizes |
| `/deployments/{id}/logs` | Combined UTF-8 log chunk |
| `/deployments/{id}/steps/{step_index}/logs` | One step's UTF-8 log chunk |
| `/deployments/preflight` | Administrator-only advisory host prerequisite checks |

Deployment IDs are distinct from CI run IDs. History remains readable if the
associated CI run is no longer retained. Metadata does not expose configuration,
environment values or step commands. Logs are **not secret-redacted**.

Log query parameters are `offset` (UTF-8 byte offset, default 0) and `limit`
(4–65536 bytes, default 16384). Continue at `next_offset`; do not count JSON
characters. Invalid byte boundaries and offsets beyond stored output return `400`.
Responses contain `content`, `size_in_bytes`, `has_more`, `status` and `complete`.
`complete` means the attempt/step is terminal and the stored output is exhausted,
not that runner output was never capped. Deployment storage has no reliable
historical truncation flag; missing output cannot be recovered through this API.
Logs are sliced in SQLite, not loaded wholesale by the API.

```sh
curl --fail-with-body -H "Authorization: Bearer $PYGITHOST_TOKEN" \
  "$PYGITHOST_URL/api/v1/repos/alice/project/deployments"
curl --fail-with-body -H "Authorization: Bearer $PYGITHOST_TOKEN" \
  "$PYGITHOST_URL/api/v1/repos/alice/project/deployments/123/logs?limit=16384"
```

Preflight examines currently enabled targets from the repository's committed
configuration and returns the settings `revision`, per-target checks, overall `ok`
and `advisory: true`. It checks configured interpreters, external script
readability/executability, outside-repository placement, simple direct-script
shebang prerequisites and the named-step shell. It **does not execute** commands,
scripts or deployment code. No enabled targets yields `ok: false`. Advanced
`/usr/bin/env` shebang flags are conservatively reported as unsupported.

Preflight never opens a script path from an untrusted repository configuration
(`script_checked: false`), and never opens UNC or network paths such as
`\\host\share\deploy.ps1` (`script_local: false`), which on Windows would connect
to another machine with the server's credentials. Keep deployment scripts on a
local disk.

Preflight cannot validate arbitrary shell command dependencies, remote credentials,
network services, deployment destination permissions or future filesystem changes.
It does not authorize deployment, replace exact-commit CI/branch-tip checks, or
guarantee a later deployment will succeed. Configuration validation remains
read-only; call preflight explicitly after committing a change.

### Shared deployment helper with named steps

A project may combine `script_content` (or an external `script`) with named
deployment `steps` in `ci/config.json`. The shared helper is staged once and its
absolute path is available as `PYGITHOST_DEPLOY_SCRIPT`. Named commands invoke it
explicitly:

```json
{"name": "Release", "run": "sh \"$PYGITHOST_DEPLOY_SCRIPT\" release"}
```

With named steps the helper is **not run implicitly**. Each command chooses its
interpreter/arguments; `run_with` still controls script-only execution. Steps run
in order with the existing shared timeout and stop-on-failure behavior. They use
separate processes, so shell variables do not carry over. This does not trust
repository-managed scripts or grant ordinary users host execution privileges.

### Deployment checkout

Every deployment starts a detached clone of the tested commit, removes its
`origin` remote, and uses it as the working directory for scripts and steps. The
path is `PYGITHOST_WORKTREE`. Deployment code can therefore read committed files
at exactly that SHA but cannot fetch a later tip. The checkout omits submodule
contents, starts without CI artifacts, and is deleted afterwards, including
uncommitted changes. A checkout that exceeds the deployment timeout or cannot be
created fails with `Deployment did not start` and does **not** consume the
one-attempt-per-commit record.

Tests: `python -m unittest tests.test_api_deployments tests.test_deployments -v`.

## HTTP Docker runners

CI can execute on a separate Linux worker through outbound HTTP polling.
Select `execution.runner: "remote-docker"` for that pipeline. See
[HTTP Docker runner](http-runner.md) for provisioning, tokens, protocol and limits.

POST `/api/runner/v1/claim`, `/source`, `/heartbeat` and `/complete` use dedicated
repository-restricted runner tokens, not personal API tokens or SSH. Attempt
identity provides retry safety rather than the user API's `Idempotency-Key`.
Deployment configuration is not sent to workers; host deployment gates remain.
Plain HTTP requires `--allow-http` and exposes credentials and data in transit.

Tests: `python -m unittest tests.test_remote_ci -q`.

Pipeline configuration accepts `execution.docker` resource/capability requests.
Worker-owned ceilings and secret/network permissions are configured separately,
not through the repository configuration. A rejected request fails with phase
`runner policy`. See [Docker profiles](docker-profiles.md) and the
[new-server installation requirements](remote-runner-setup.md).

## CI automation

CI mutations use the same bearer authentication, `write` scope, repository-access
checks, JSON validation and durable idempotency keys as other mutations.
Logs and artifacts require `read` scope and access to the repository.
No webhook endpoints, subscriptions or delivery infrastructure are implemented.
See [CI API safety and test coverage](#ci-api-safety-and-test-coverage) for the
regression coverage and commands to run it locally.

### Trigger, cancel and rerun

Trigger exactly one named pipeline on the current tip of a branch:

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $PYGITHOST_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: checks-main-2026-001" \
  --data '{"branch":"main","pipeline":"checks"}' \
  "$PYGITHOST_URL/api/v1/repos/alice/project/ci/runs"
```

Use the names returned by `GET .../ci/pipelines`. The simple form of
`ci/config.json` creates the pipeline name `ci`; a full grouped document uses its
named pipelines. An explicit pipeline is required; API triggering does not fan out
to every pipeline.
Optionally include a full commit `sha` to reject a moved branch with `409`.
The web **CI → Run pipeline** page applies the same guard by binding **Queue run** to the
SHA from its read-only **Check configuration** result. The server resolves and
records the actual branch commit; arbitrary events, commits from another branch,
environment overrides, commands, runner settings and deployment flags are not
accepted. Manual runs remain available even if a legacy manual trigger was disabled.
A missing `ci/config.json` returns `409` without creating a run.

`202` means a run record was created, not that execution succeeded. A configuration
error or full CI queue may create an immediately failed run. Poll the returned ID
with `GET .../ci/runs/{id}` and read its logs when appropriate.
A malformed repository pipeline, including attempts to override its runner, creates
a configuration-failed run without executing the supplied commands. A malformed
committed file additionally fails closed for merge and direct-branch protection
until it is repaired. Such a run may have no usable snapshot; fix the file and
trigger a new run rather than rerunning it.

Cancel with `POST .../ci/runs/{id}/cancel` and JSON `{}`. Queued jobs are removed
from the scheduler; running jobs use the CI manager's existing process/container
cleanup. Already-cancelled runs return their summary. Other terminal states return
`409`; a completion racing a cancellation can return the finished state instead.
A job not owned by the local scheduler cannot be cancelled by this API.

Rerun a terminal job with `POST .../ci/runs/{id}/rerun` and JSON `{}`. It creates
a new run ID using the old commit, stored Git configuration, limits, pipeline,
payload and event—not today's committed configuration. Page-managed values are
resolved again at execution and remain withheld from unmerged pull-request reruns;
a protected value also requires the original commit to still be the branch tip.
Pending/running jobs or runs without a usable snapshot return `409`. To test new
committed configuration, trigger a new manual run instead. Do not send snapshot or
environment fields in the request.

**Manual runs never deploy.** Reruns preserve the original event: a manual rerun
never deploys, while a push/PR-merged rerun retains the existing deployment gates
and per-commit attempt deduplication, just as in the web UI. This API does not add
manual deployment, deployment retries or approval bypasses.

Trigger/cancel/rerun retries must reuse the same idempotency key and body. Replays
return the original response snapshot, which may still say `queued` even after the
job finishes; GET the run ID for current state. Use a new key for a genuinely new run.
A completed idempotency record also survives CI history retention: replaying it does
not queue a replacement if the original run was pruned. Its run ID can therefore
return `404`. Choose a new key only when you intentionally want a new execution.

### Read bounded logs

`GET .../ci/runs/{id}/logs?offset=0&limit=16384` returns JSON:

```json
{
  "run_id": 42,
  "encoding": "utf-8",
  "content": "Tests passed\n",
  "offset": 0,
  "next_offset": 13,
  "size_in_bytes": 13,
  "has_more": false,
  "truncated": false,
  "status": "success",
  "complete": true,
  "phase": "step 1: Tests",
  "reason": ""
}
```

`offset` and `next_offset` count **UTF-8 bytes**, not JSON or Python characters.
Always use the returned `next_offset`. `limit` defaults to 16384 bytes and must be
4–65536; the server can return fewer bytes to avoid splitting a UTF-8 character.
Invalid character-boundary offsets and offsets beyond stored output return `400`.
Log slicing happens in SQLite, so Python does not load a whole oversized legacy log.

Follow `has_more` to read existing chunks. If it is false but `complete` is false,
poll the same next offset later: a queued/running job may append more output.
`complete` means the job is terminal and this chunk reached the end of stored output.
`truncated` indicates output discarded by CI's capture limit, not just a partial API
chunk. Logs are point-in-time snapshots, not an SSE/WebSocket stream. If output was
rewritten and a previous cursor becomes invalid, restart from offset zero.
Poll no faster than every two seconds and observe `Retry-After` on `429`.
`phase` and `reason` provide operational diagnostics, including queue failures that
have no captured output. Diagnostic reasons are limited to 4096 characters.

### List and download artifacts

`GET .../ci/artifacts` lists repository archives newest first with standard
pagination. `GET .../ci/runs/{id}/artifacts` returns zero or one archive, since the
current CI system stores one ZIP per run. The archive `id` equals its `run_id`.
Metadata includes the name, byte size, UTC creation/expiry timestamps,
`downloadable`, and a relative `download_url`.

Download the URL with the same bearer header; there are no redirects or signed
public URLs:

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $PYGITHOST_TOKEN" \
  --output ci-artifacts.zip \
  "$PYGITHOST_URL/api/v1/repos/alice/project/ci/runs/42/artifacts/download"
```

Successful downloads use `application/zip`, `Content-Disposition: attachment`,
`Content-Length`, `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
`HEAD` reports archive size without loading or sending its body.
Full downloads honor the run's `execution.limits.artifact_mb` snapshot (default
16 MiB for new runs). Legacy runs without that snapshot retain the **32 MiB**
API ceiling, separately from the JSON response limit. See [CI limits](ci-limits.md).
At most two archive bodies are read/transferred concurrently per server process;
the permit remains held until the transfer finishes or the connection closes.
Oversized metadata has `downloadable=false`; GET/HEAD download requests return
`413`. The SQL size check and archive fetch read the same row version, and an
oversized BLOB is not loaded into Python. Range downloads are not implemented.

Existing retention rules apply to API lists/downloads, including cleanup of expired
archives. The active limits follow the default branch's configuration and
administrator limits. A run with no retained archive has an empty list;
downloading a missing or expired archive returns `404`. Unknown/inaccessible runs
also return `404`. Disabling artifact age retention gives `expires_at: null`; count
limits still apply. The active policy follows the default branch configuration and
administrator caps; feature branches and reruns cannot change it. A lower default
branch limit can remove previously retained archives at the next cleanup. Count/age
cleanup stays scoped to the selected repository and does not remove another
repository's archives. See [Retention](ci-retention.md) for refresh and cleanup
timing.
The server returns the original ZIP without extracting or scanning it.

**Treat logs and archives as sensitive, untrusted job output.** Job commands can
print credentials or save secret-bearing files. These endpoints do not guarantee
secret masking; only repository-authorized callers may consume them. Inspect ZIP
entries before extracting them on your own system.

## CI API safety and test coverage

The regression suite exercises HTTP endpoints against temporary repositories and a
temporary database. Scheduler state is controlled for race-sensitive assertions;
a separate real POSIX host-runner test generates a report, reads its logs and ZIP,
and verifies that neither the manual run nor its rerun deploys.

| Area | What the tests verify |
| --- | --- |
| Authentication | Missing/invalid/revoked bearer tokens cannot read logs or ZIPs; read-only tokens cannot trigger, cancel or rerun jobs. |
| Repository isolation | Run IDs cannot be used to read or mutate another repository's jobs or archives. |
| Concurrent retries | Two simultaneous requests with the same idempotency key queue at most one job; an unfinished claim returns `operation_pending`. |
| Recovery | Scheduler errors do not expose exception text or cause automatic re-execution; cached results remain authoritative after run retention. |
| Trigger validation | Explicit pipeline selection avoids fanout; slash-containing branches work; runner/env/event/payload overrides are rejected. |
| Configuration failures | Invalid or malformed repository `ci/config.json` fails without executing its commands; a malformed committed document fails closed with CI required and direct branches protected; saved database commands never act as a fallback. |
| Repository source | Simple steps and full named documents read from exact commits; PR checks use the trusted base; referenced files stay under `ci/`. |
| Trust boundary | Host jobs and deployments fail unless the exact repository is authorized; wildcards/malformed names are rejected and historical snapshots are rechecked. |
| Rerun snapshots | Old event, commit and steps are retained. Page-managed values are resolved again when executing and are withheld from unmerged PRs. |
| Cancellation races | Pending/running jobs use scheduler cleanup; a job that finishes successfully during cancellation is not rewritten as cancelled. |
| Log cursors | Mixed Unicode, NUL, quotes and control characters round-trip across byte-limited chunks; changed output and invalid offsets fail clearly. |
| Log limits | Large logs are sliced in SQLite; diagnostic reasons are bounded; HEAD sends no output. |
| Archive limits | An archive exactly at the size limit is accepted; an oversized BLOB is not loaded into Python. |
| Archive concurrency | A third transfer waits without loading another archive while both download permits are held. |
| Retention and timestamps | Expiry, disabled age limits, repository-scoped count limits, UTC metadata and full-size pagination work correctly. |
| Transfer cleanup | Timeout/cancellation aborts buffered output and closes the connection without appending a second HTTP response. |
| Documentation | OpenAPI describes CI mutations, log chunks and binary downloads; this page renders the safety guidance and navigation links. |

Run the CI API tests with Python 3.14+, Git and `git-http-backend` installed:

```sh
python -m unittest tests.test_api_ci -v
```

Run all API tests, or the complete repository suite:

```sh
python -m unittest tests.test_api tests.test_api_writes tests.test_api_ci tests.test_api_browsing tests.test_api_discussions -v
python -m unittest discover -v
```

The CI API tests do not require Docker, external services or webhooks. The real
host-runner test is POSIX-only; other platform/feature requirements are reported
as test skips. These tests validate the documented safeguards, not exactly-once
execution across arbitrary server crashes or automatic secret masking in job output.

## Responses, pagination and errors

Objects use `snake_case`; timestamps are UTC RFC 3339 strings. Legacy local
issue/PR/comment timestamps use the server's local timezone before conversion.
CI run, artifact and discussion SQLite timestamps are already UTC.
Repository URLs are relative to this server. Repository lists contain summary
objects; repository detail also includes `default_branch`.

Lists return JSON arrays with `page` (default `1`) and `per_page` (default `30`,
maximum `100`). Follow the relative `Link` header's `rel="next"` URL until it is
absent. `X-Page` and `X-Per-Page` report the selected page. Offset cannot exceed
100000 and page cannot exceed 10000. Issues, PRs and CI runs are ordered by
descending ID; comments use ascending ID. Git commit lists use Git log order.
Pagination is not snapshot-isolated: concurrent updates can shift page boundaries.

Unknown, repeated, out-of-range query parameters and invalid filters return `400`.
All responses use `Cache-Control: no-store` and include `X-Request-ID`.
API errors contain `message`, `code`, and the same `request_id`:

```json
{
  "message": "A valid bearer access token is required.",
  "code": "unauthorized",
  "request_id": "server-generated-request-id"
}
```

| Status | Meaning |
| --- | --- |
| `400` | Invalid query, malformed JSON, framing or unexpected read body |
| `401` | Missing or invalid bearer token |
| `403` | Missing scope, protected branch, comment ownership or IP blocked |
| `404` | Unknown endpoint, missing or inaccessible resource |
| `405` | Method not implemented at the selected endpoint |
| `409` | Revision, branch, merge, state or idempotency conflict |
| `413` | Request, response, Git output or archive exceeds the safety limit |
| `415` | Mutation must use `application/json` |
| `422` | Invalid fields, missing idempotency key or unsupported file type |
| `429` | Rate limit reached; wait for `Retry-After` seconds |
| `500` | Internal error; retain the request ID when reporting |
| `503` | Git repository cannot be read |
| `504` | Operation timed out |

Rate limits are currently 120 requests per minute per client IP **and** per
authenticated user, in memory per server process. Token rotation does not reset a
user's bucket. The bounded limiter is a basic safeguard, not a distributed abuse
defense; enforce additional limits at your reverse proxy. The peer socket IP is
used, not untrusted forwarded headers. Behind a proxy, the IP bucket is shared.

Responses have a 20-second operation timeout. ZIP transfer waits are also bounded
to 20 seconds; a timeout after headers closes the connection rather than appending
a JSON error to a partially sent archive. API Git reads have a 10-second timeout
and 1 MiB output limit; JSON requests/responses are capped at 2 MiB. Shared editor
operations have a 30-second timeout per Git subprocess. Accepted mutations may
continue after the response timeout to finish safely and record their result.
At most eight API resource operations run concurrently per server process; waiting
for a slot counts toward the response timeout.
Use smaller pages if output exceeds the limit. Read requests must not have bodies.
HTTP framing errors rejected before API dispatch retain the server's ordinary
HTTP error format, rather than the API error envelope.

## Delivery roadmap

1. **Implemented:** read-only foundation, bearer authentication, fail-closed
   repository access, pagination, public serializers, rate/output/time limits,
   OpenAPI, in-page documentation and tests.
2. **Implemented:** safe repository creation, branch/file changes, issue/comment
   and PR mutations, ff-only merges, scope/protection enforcement, revision/SHA
   checks, durable idempotency/audit records and regression tests.
3. **Implemented:** CI triggering/cancellation/reruns, bounded UTF-8 log reads,
   paginated artifact metadata and size-limited authenticated ZIP downloads.
   Webhooks are explicitly deferred and are not part of this implementation.
4. **Implemented in this batch:** directory/recursive trees, literal search,
   direct/commit/PR diffs and changed-file statistics, PR commit lists, bounded
   source ZIPs, discussions/replies, locking and accepted-answer management.
5. **Still pending:** the items in the coverage gaps below. This is not complete
   feature parity with every repository action.

## Remaining API coverage gaps

| Area | Still unavailable through the API |
| --- | --- |
| File mutations | Multi-file commits, rename/move operations, binary writes and creating an initial commit in an empty repository |
| Pull requests | Conflict inspection/resolution and frozen historical PR diff snapshots |
| CI settings | Read-only configuration inspection; replacement is disabled. Separate environment/retention editing and server defaults are not exposed through the API |
| CI details | Individual step results and email-delivery retry |
| Deployments | Controlled retries; history, step results and bounded logs are now available |
| Repository administration | Settings updates and deletion |
| Access administration | Granular/repository-restricted tokens, collaborator ACLs, service accounts and audit/token-management endpoints |
| Webhooks | Intentionally deferred; no subscription or delivery infrastructure |

Existing web/Git workflows remain available for supported features without API
parity. Some future items need new underlying functionality, not just routing.

These future operations are not available through the API yet. GitHub SDKs and
GitHub Actions integrations are not drop-in compatible. Existing endpoint contracts
should remain stable within v1; incompatible changes require a new API version.
