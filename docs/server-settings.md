# Server and repository settings

[CI reference](ci-options.md) · [Retention](ci-retention.md) · [Server setup](getting-started.md)

## Where settings live

| Page | Controls | When changes apply |
| --- | --- | --- |
| **Admin → Settings → Appearance** | Display name and browser favicon | Immediately. |
| **Admin → Settings → Basic server configuration** | Bind address/port, Git URLs/backend, repository/database/static paths, authentication, allowed IPs, cookies and request limits | Saved to the startup file; restart required. |
| **Admin → Settings → Basic server configuration → Logging** | Log level/format, rotating file, retention bounds, access log and audit trail | Saved to the startup file; restart required. See [Logging and audit trail](logging.md). |
| **Admin → Settings → Environment variables** | Server-wide CI variables | Resolved when jobs execute; repository values can override names, and unmerged PR checks receive none. |
| **Admin → Settings → Runs and artifacts** | Default artifact age/count and completed-run count | Applies to repositories using defaults or omitting project values; a nonzero administrator limit caps explicit project limits. |
| **Repository → CI → Settings** | Repository environment variables and secrets, optionally scoped to a pipeline and to ordinary, protected-branch, or deployment-only use | Resolved when jobs execute; page values override matching Git `env` and are not copied into new run snapshots. |
| **Repository → `ci/config.json`** | Pipeline, trigger, deployment, policy and optional project retention definitions | Read from the recorded commit; retention follows the default branch; validate before committing and queue a new run to exercise changes. |
| **Admin → Email** | SMTP delivery | Future notifications; credentials are separate from CI variables. |

These pages require an administrator when authentication is enabled. With
authentication disabled, access is governed by the IP allowlist. CI actions still
require write access when authentication is enabled; manual runs never deploy.

The favicon is served publicly at `/favicon.ico`, defaults to the bundled
`favicon.ico` next to the `static/` directory, and can be replaced from
**Appearance** with an ICO, PNG, GIF, JPEG, WebP or SVG file up to 512 KiB.
**Use default** removes the uploaded image.

There is no project JSON editor. Pipeline and deployment definitions must be
committed to `ci/config.json`; the repository settings page intentionally contains
only environment variables/secrets. `PUT /ci/settings` is disabled, and project
retention has no separate page form. Validate before committing with
`python -m pygithost ci validate` (add `--rev HEAD` for committed files), or select
a branch under **CI → Runs** and choose **Check configuration** to read its exact
configuration commit and status without queueing a job.

## Worked inheritance example

1. In `ci/config.json`, configure execution inside each pipeline, for example
   `"execution":{"runner":"docker","image":"python:3.14-slim","timeout_seconds":600}`
   and optionally `"cancellation":{"superseded":true}`. Omitted options use
   built-in defaults; there is no execution-defaults settings form.
2. Add server variables `PYTHONUNBUFFERED=1` and `BUILD_MODE=development` under
   **Admin → Settings → Environment variables**; save variables.
3. Set administrator artifact retention to `30` days, maximum bundles to `50`, and
   maximum completed runs to `100` under **Admin → Settings → Runs and artifacts**.
4. In the repository's **CI → Settings**, add a repository variable
   `BUILD_MODE=production` for **All pipelines** and scope it to **Non-PR CI runs**.
   Its CI inherits `PYTHONUNBUFFERED=1`, but uses `BUILD_MODE=production`; unmerged
   PR checks receive neither page value.
5. Add a pipeline-scoped row if one pipeline needs a different value. Pipeline rows
   override repository-wide rows, which override server values. Use **Deployments
   only** for a host deployment credential, or **Authorized protected branch** only
   with the server-side protected allowlist described below.
6. To change a pipeline's timeout, set `execution.timeout_seconds` to `900` in that
   pipeline's entry in `ci/config.json`, commit it, and queue a new run.
7. Omit that key to use the built-in timeout. Removing the repository `BUILD_MODE`
   row similarly restores the server variable value.

Execution and cancellation belong to the committed pipeline configuration, with
built-in defaults for omitted options. Environment rows stay on the project page.
Values are resolved when a job executes, not copied into new stored run snapshots.
Project retention, when used, belongs in the full grouped document on the default
branch; administrator limits may cap it.

Values are stored in plaintext; logs, remote job assignments and committed
configuration are not redacted. **Show values** changes visual masking only. Do not
treat these controls as an encrypted secrets manager. Saving the repository variable
table replaces its legacy JSON variables, including when all rows are removed. See
[Secrets, retention and administrator defaults](ci-options.md#secrets-retention-and-administrator-defaults).

Never put secrets in `ci/config.json`. Git history, live page values, remote
assignments and job logs are not a secret store. Page values override matching
committed `env` names.

## Repository configuration lives in Git

For a single Docker pipeline with the built-in triggers, commit a minimal
`ci/config.json`:

```json
{
  "version": 1,
  "steps": [
    {"name": "Python version", "run": "python --version"},
    {"name": "Tests", "run": "python -m unittest discover -v"}
  ]
}
```

Use the [expanded example](examples/ci/all-options.json) when you need multiple named
pipelines, deployment targets, protection policies or project retention. Commit the
document as `ci/config.json`; referenced pipeline files must also be under `ci/`.
Do not commit secrets or trusted host deployment scripts inside the repository.

A malformed committed file fails closed: merges require CI and all direct branches
are protected until an administrator repairs `ci/config.json` through Git or the
server filesystem. Validate before committing; there is no page editor or saved
configuration fallback.

Project retention, if configured, is part of the full document:

```json
{
  "version": 1,
  "pipelines": [],
  "deployments": [],
  "retention": {"artifacts": {"days": 30, "max_count": 50}, "runs": {"max_count": 100}}
}
```

The default branch's configuration determines project retention. An explicit
nonzero administrator setting caps the corresponding project limit. Feature
branches and reruns cannot change the active policy.

## Host and deployment authorization

Host jobs and enabled deployments are trusted server-user code. They are rejected
unless the exact `owner/repo` is listed in the server environment variable
`PYGITHOST_CI_TRUSTED_REPOSITORIES` (comma- or newline-separated, default empty).
Use exact names only; wildcards, patterns and malformed entries are rejected. This
is administrator authorization outside Git; adding a deployment or setting
`runner: "host"` in the repository cannot grant it. The check is repeated for
reruns and historical snapshots. A parseable document denied by the guard keeps its
declared branch policies but fails the queued run during configuration.

Ordinary Docker and remote-Docker jobs continue without this allowlist, subject to
the worker's own policy. See [Host and deployment trust boundary](pipelines.md#host-and-deployment-trust-boundary).

Protected page values use a separate server process allowlist. The exact
`owner/repo:branch` must appear in `PYGITHOST_CI_PROTECTED_SECRET_BRANCHES`
(comma- or newline-separated, default empty); the current default branch's committed
`block_direct_pushes`/`protected_branches` rules must also match, and the execution
commit must equal the current branch tip. A repository writer cannot grant this by
editing `ci/config.json`.

## Basic server configuration and restart

The page edits the same startup file passed to `server.py run --config ...`.
It preserves unrelated keys and writes atomically. If the file changed since the
page was loaded, reload before saving to avoid overwriting another edit.
Programmatic instances without a startup file show basic controls read-only.

No listener, authentication, database or storage change is applied mid-request.
Restart your existing service using its normal startup command after reviewing the
saved values. Start with valid admin credentials before enabling authentication;
HTTPS-only cookies require HTTPS. Keep an allowed client IP to avoid lockout.
Changing a path does not move repositories or migrate the database. Back up/move
data deliberately before using new paths; a new database will not contain the old
accounts, CI environment values or history.

The startup JSON does not contain the database-backed environment and default
settings tables. Back up the startup file, database and repository Git data when
moving a server. Project pipeline definitions travel with the repositories.
