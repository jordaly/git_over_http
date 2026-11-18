# Repository CI configuration

[Every option](ci-options.md) · [Recipes](pipeline-examples.md) · [Migration](ci-migration.md)

AI assistants: see [Guidance for AI agents](ci-options.md#guidance-for-ai-agents)
before editing configuration or triggering runs.

Project CI is defined by **`ci/config.json` in the repository**, not by a page
editor or the database. Commit the file and push it; the server reads the recorded
commit. **CI → Settings** manages repository environment variables and secrets
only. There is no project JSON editor, no saved project definition, and no API
replacement endpoint.

For a missing file, CI stays idle and creates no run. A malformed file produces a
configuration failure without executing commands. Push/manual runs read the
recorded commit; pull-request checks read the recorded target/base commit, not the
unreviewed source branch.

A malformed committed configuration **fails closed**: until an operator repairs
`ci/config.json` in Git or directly on the server filesystem, merges require CI for
the affected exact base/head and all direct branches are protected. A stale
successful check cannot satisfy an invalid base configuration. There is no web
configuration editor, API replacement or saved-definition fallback for repair.
Validate the JSON before committing; a broken file on the default branch may need
administrator Git/filesystem intervention.

## Repository CI directory

Keep repository-owned pipeline JSON and helper scripts together under `ci/`:

```text
ci/
  config.json       # required entry point
  tests.json        # optional pipeline referenced by config.json
  test.sh           # optional helper script
```

Create the directory with `mkdir -p ci`, add `ci/config.json`, and commit it. Only
`ci/config.json` is the entry point. A full document may reference other pipeline
files, but every referenced path must be a regular JSON file strictly inside
`ci/`, for example `ci/tests.json` or `ci/pipelines/checks.json`. Root-level files,
traversal, absolute paths, backslashes and symlinks are rejected. A pipeline cannot
reference `ci/config.json` recursively.

File references are relative to the **repository root**, and steps start at the
checkout root. Invoke a helper as `sh ci/test.sh`, not `sh test.sh`. Putting JSON
under `ci/` does not change the command's working directory. See
[multiple Git-managed pipelines](pipeline-examples.md#multiple-git-managed-pipelines).

Never commit credentials, tokens or private keys under `ci/` or anywhere else in
Git. Repository environment values are entered in **CI → Settings** and stored
separately from Git.

## Minimal pipeline

A simple single-pipeline document is valid at `ci/config.json`:

```json
{
  "version": 1,
  "timeout_seconds": 600,
  "steps": [
    {"name": "Python version", "run": "python --version"},
    {"name": "Tests", "run": "python -m unittest discover -v"}
  ]
}
```

This creates one pipeline named `ci`. It uses built-in Docker execution with image
`python:3.14-slim`, enables pushes and pull-request opened/updated/reopened events
on all branches, and always permits manual runs for write-authorized users. No
deployment, protection policy or project retention is enabled automatically.
`command` is a legacy alternative to `steps`; use one or the other.

The simple form accepts only `version`, `command`, `steps`, `env`, `artifacts` and
`timeout_seconds`. Use the full grouped document when you need named pipelines,
deployments, policies or retention. `env` is optional and is not secret storage;
page-managed values override it.

Prepare the image on the server (`docker pull python:3.14-slim`). Tools and
dependencies are not installed automatically, and Docker jobs have no network by
default.

To verify the setup, commit and push `ci/config.json`, then open **CI → Runs**.
A push may already have queued `ci`; to test on demand, choose the branch, select
**Check configuration**, then queue pipeline `ci` from the validated commit. If a
step needs a credential, add it under **CI → Settings** with the appropriate scope.
Page values are resolved when execution begins and are not stored in new run
snapshots; unmerged PR checks never receive them.

## Full document: named pipelines and deployments

Use one grouped document at `ci/config.json` when the project needs multiple
pipelines, deployment targets, protections or retention:

```json
{
  "version": 1,
  "pipelines": [
    {
      "name": "checks",
      "execution": {"runner": "docker", "image": "python:3.14-slim", "timeout_seconds": 600},
      "triggers": {"push": {"enabled": true, "branches": ["main"]}},
      "steps": [
        {"name": "Python version", "run": "python --version"},
        {"name": "Tests", "run": "python -m unittest discover -v"}
      ]
    },
    {
      "name": "compile",
      "execution": {"runner": "docker", "image": "python:3.14-slim", "timeout_seconds": 120},
      "steps": [{"name": "Compile", "run": "python -m compileall -q ."}]
    }
  ],
  "deployments": [
    {"name": "production", "pipeline": "checks", "enabled": false, "branch": "main", "script": "/opt/deploy/production.sh"}
  ],
  "policies": {"require_ci": false, "block_direct_pushes": false, "protected_branches": ["main"]}
}
```

Each pipeline independently defines execution, triggers, cancellation, artifacts
and notifications. The `compile` pipeline has no automatic trigger, but both
pipelines can be queued manually with write access. Each deployment references a
pipeline and has its own branch, script and notification settings. Multiple
targets may reference the same pipeline.

The example deployment is disabled. Host jobs and **any enabled deployment**
require administrator authorization outside Git; see the trust boundary below.
Install trusted deployment scripts outside repositories and review the
[deployment walkthrough](automatic-deployment.md) before enabling one.

## Names and execution

Every pipeline and deployment object requires a unique `name` within its own list.
Names use 1–64 ASCII letters, digits, underscores or hyphens, beginning
alphanumeric. Keep them stable: names identify runs, target references and
deployment attempts. Up to 16 pipelines and 32 deployments are supported. Empty
lists are valid and stop new automatic runs without deleting history.

Steps contain exactly `name` and `run`. Steps run in order; failure skips later
steps. Each starts a fresh shell in the checkout root. Files persist, not `cd`,
exported variables or shell state. Checkout, PR preparation and all steps share
that pipeline's timeout. Jobs and deployments remain sequential per repository;
independent configurations do not imply parallel execution or cross-pipeline
dependencies.

## Environment secrets and retention

Enter repository secrets and other environment values in **CI → Settings**.
Server-wide defaults are managed under **Admin → Settings → Environment
variables**. A repository value overrides a server value with the same name, and a
pipeline-scoped row overrides the repository-wide row. Page-managed values also
override matching `env` entries in `ci/config.json`.

Use page values for secrets. Git history is shared, copied and not redacted.
Page-managed values are read when the job runs, not copied into new CI snapshots.
They remain plaintext in settings storage. Active remote assignments carry the
job environment; GitHost removes it from the assignment record on completion,
closure, or recovery. This does not erase earlier database backups or redact logs.
**Show values** only changes visual masking. Logs are not secret-redacted, so
keep steps from printing secrets. Unmerged PR checks never receive page-managed
values, including server-wide values.

Repository values can be scoped to non-PR CI runs, authorized protected
branches, or deployments only. Protected branch values require a matching
`owner/repo:branch` entry in the administrator's
`PYGITHOST_CI_PROTECTED_SECRET_BRANCHES`, a matching protection rule in the current
default branch's committed configuration, and a run at the current branch tip.
The allowlist is comma- or newline-separated and is empty by default.
Deployment-only values are not sent to CI test jobs.

Server-wide retention defaults are under **Admin → Settings → Runs and artifacts**.
A full grouped document may set project `retention` on the default branch, within
nonzero administrator caps. Feature branches and reruns cannot change the active
policy.
The project settings page has no retention form. See
[Retention](ci-retention.md) for defaults, refresh and deletion warnings.

## Host and deployment trust boundary

Repository writers cannot grant themselves execution as the server user by
editing code. Host jobs and enabled deployments are rejected unless the exact
`owner/repo` name appears in the server environment variable
**`PYGITHOST_CI_TRUSTED_REPOSITORIES`** (comma- or newline-separated, default
empty). Use exact names only: wildcards, patterns, malformed entries and `..` are
rejected, and a bad allowlist value is a configuration error rather than a broad
match. Administrator authorization is separate from `ci/config.json`; it is not
another pipeline setting.

- Ordinary `docker` and `remote-docker` pipelines continue without this
  allowlist. Remote workers still enforce their own administrator-owned Docker
  policy.
- `runner: "host"` and every enabled deployment require the allowlist because they
  run directly as the server user outside the job container.
- Missing authorization is a configuration error for the queued run: commands do
  not execute. The committed document is still parseable, so its declared branch
  policies remain in effect. This is different from a malformed file, which fails
  closed with CI required and all direct branches protected.
- A deployment object is enabled by default unless it sets `"enabled": false`.
  Enabling it does not grant authorization or deploy immediately: a qualifying
  successful push or merged-PR run is still required.
- The check is repeated whenever a run or deployment executes, including reruns and
  historical snapshots. Removing authorization stops those jobs; it does not
  rewrite history.

## Commit, test and migrate

Before pushing, run `python -m pygithost ci validate` in the checkout. Use
`--rev HEAD` to check the committed version rather than working files.
In **CI → Runs**, select a branch and click **Check configuration** to validate
the committed files and list that branch's pipelines without running them.

After committing a configuration change, queue a **new** manual run or push a new
commit to exercise it. Rerun uses the original stored snapshot and does not adopt
the new `ci/config.json`. Manual runs never deploy. Only a qualifying successful
push or merged-PR run can deploy.

Existing definitions saved only in the database are not read after this model is
installed. Copy them into a full grouped document, commit it as `ci/config.json`,
and configure any needed trust allowlist explicitly before upgrading. There is no
automatic import, no implicit deployment and no replay of historical definitions.
See [Move root files into ci](ci-migration.md#move-root-files-into-ci) and the full
[Migration](ci-migration.md) guide.
