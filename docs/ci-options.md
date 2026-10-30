# CI JSON: every option

[Quick start](pipelines.md) · [Recipes](pipeline-examples.md) · [Deployment](automatic-deployment.md) · [Retention](ci-retention.md)

This manual is rendered directly in **CI → Documentation**. Edit the repository
document under **CI → Settings → Configuration JSON**; it is separate from the
server's `pygithost.config.json` (network, authentication and storage).

## Contents

- [Complete examples](#complete-examples)
- [Document structure](#document-structure)
- [Independent configuration](#independent-configuration)
- [Every execution option](#every-execution-option)
- [Triggers and cancellation](#triggers-and-cancellation)
- [Steps](#steps)
- [Artifacts and notifications](#artifacts-and-notifications)
- [Every deployment option](#every-deployment-option)
- [Every repository setting](#every-repository-setting)
- [Compatibility](#compatibility)
- [Variables, limits and troubleshooting](#variables-limits-and-troubleshooting)

## Complete examples

| Example | Purpose |
| --- | --- |
| [All options](examples/ci/all-options.json) | Independent checks/release pipelines and separately named deployments, cancellation, artifacts, notifications, policies and retention. |
| [Inline deployment](examples/ci/inline-deployment.json) | Python script content rather than a host script path. |
| [Git-managed configuration](examples/ci/git-managed.json) | Administrator document for an existing Git-backed setup. |
| [Repository pipeline](examples/ci/repository-pipeline.json) | **Not** an administrator document: commit this as `.pygithost-ci.json` for the previous example. |

Example links display complete JSON in the application. Deployments in these files
are disabled until you review and enable them. Replace example recipients and script
paths. Prepare Docker images/dependencies before running; validation does not install
tools or execute the examples. A generic Python image may not include your build tools.

> Saving replaces the entire document, not a patch. Preserve your existing pipeline
> entries and policies when adapting examples. Retention changes can delete existing
> data immediately.

## Document structure

| Option | Default / type | Example and meaning |
| --- | --- | --- |
| `version` | Integer `1` | `"version": 1`; the only supported version. |
| `pipelines` | Required array | `"pipelines": [{"name":"checks","steps":[{"name":"Tests","run":"python -m unittest discover -v"}]}]`. Every object requires its own name and independent configuration. |
| `deployments` | Array, default `[]` | `"deployments":[{"name":"production","pipeline":"checks","enabled":false,"script":"/opt/deploy/app.sh"}]`; separately named targets linked to a pipeline. |
| `policies` | Protection off | `"policies":{"require_ci":true}`; administrator-controlled, repository-wide. |
| `retention` | Artifact age 7 days, unlimited artifact count, normally 100 completed runs | `"retention":{"artifacts":{"days":30,"max_count":50},"runs":{"max_count":100}}`; repository-wide. |

Up to 16 pipelines and 32 deployments. Each object requires `name`, using 1–64 ASCII
letters, digits, underscores or hyphens, beginning alphanumeric. Names are unique
within each list; pipeline and deployment names may match. Keep them stable.
`"pipelines": [], "deployments": []` stops new runs without deleting history or
cancelling queued commands. Referenced pipelines must exist; remove/repoint their
deployments when deleting a pipeline.

Pipeline-local groups: `execution`, `triggers`, `cancellation`, `artifacts`,
`notifications`, `steps`, or compatibility `file` instead of steps. Deployment
configuration belongs only in the separate deployments list. Policies/retention
remain repository-wide. There is no defaults object or root notifications object.

## Independent configuration

No pipeline or deployment inherits configuration from another object. An omitted
field uses only its built-in default. Set execution, triggers, cancellation, artifacts
and notifications explicitly on every pipeline that needs them. Enabling email on
one pipeline does not enable another pipeline's or a deployment's email.

Empty branch arrays match **all** branches; disable a trigger with `enabled: false`
to stop it. Empty recipients are invalid with enabled email. Empty artifact paths
disable collection. Empty protected patterns are invalid with direct-push blocking.

## Every execution option

These fields belong in each pipeline object's `execution` group.
Table examples are **field fragments**; use the complete examples for surrounding JSON.

| Option | Type / built-in default | Example | Behavior |
| --- | --- | --- | --- |
| `runner` | String `"host"` | `"runner":"docker"` | `host` runs as the server OS user, without a sandbox. `docker` uses local Linux containers. |
| `image` | String `"python:3.14-slim"` | `"image":"registry.example.com/team/ci:2026-10"` | Docker image must already exist locally. Include tools/dependencies and preferably pin a digest. |
| `timeout_seconds` | Positive integer `1800` | `"timeout_seconds":600` | One budget for checkout, PR merge preparation and all steps. Deployment has a separate timeout. |
| `env` | String-valued object `{}` | `"env":{"PYTHONUNBUFFERED":"1","BUILD_MODE":"development"}` | Up to 64 effective entries; valid identifier keys, string values up to 8192 characters, no NUL. Built-in names are reserved. |

**Host** commands use `/bin/sh` on POSIX and `cmd.exe` on Windows. A restricted
environment prevents accidental credential inheritance but does not restrict
filesystem/process access. Host CI is trusted-code-only.

**Docker** uses `/bin/sh`, overrides the image entrypoint, and mounts only the
independent checkout—not the production repository or Docker socket. No network,
read-only root filesystem, no capabilities or privilege escalation; limits are
1 GiB memory, one CPU, 128 PIDs and a 256 MiB writable `/tmp`. Checkout storage has
no disk quota. Linux uses the server user's UID/GID. This is defense in depth, not
a complete hostile-code boundary; use a dedicated runner host for hostile code.

Jobs cannot pull missing images or install dependencies from the network. Even
`pip install -e .` may need network for build dependencies; build the tools into
your CI image. Docker environment values cannot contain CR/LF.

Each run has an independent clone, without an origin remote or shared object files.
Jobs/deployments are sequential per repository. Pipeline order is not a dependency
graph; a deployment does not automatically wait for another pipeline's success.

## Triggers and cancellation

Triggers belong in each pipeline object's `triggers` group.

| Option | Type / built-in default | Example | Meaning |
| --- | --- | --- | --- |
| `push.enabled` | Boolean `false` | `"push":{"enabled":true}` | Actual pushed branch updates. Qualifying successful updates may deploy. |
| `push.branches` | String array `[]` | `"push":{"branches":["main","develop","release/*"]}` | Case-sensitive globs; empty/omitted means all branches. |
| `pull_request.enabled` | Boolean `false` | `"pull_request":{"enabled":true}` | Enables the PR-related events selected below. |
| `pull_request.branches` | String array `[]` | `"pull_request":{"branches":["main","develop"]}` | Filters PR **target**, including merged events. |
| `pull_request.events` | String array `["opened","updated","reopened"]` when omitted | `"pull_request":{"events":["opened","updated","reopened","merged"]}` | An empty selection queues no PR events, even if enabled. |
| `manual.enabled` | Boolean `false` | `"manual":{"enabled":true}` | Allows a write-authorized user to select a branch under Runs. Push/PR filters do not restrict manual runs. Manual runs **never deploy**. |
| `cancellation.superseded` | Boolean `false` | `"cancellation":{"superseded":true}` | Pipeline-local, not inside triggers. Cancels older matching event/branch/PR runs of the **same** pipeline. Manual runs are not superseded. |

Every PR event string is supported explicitly:

| Event | Trigger | Can deploy? |
| --- | --- | --- |
| `"opened"` | New PR | No. |
| `"updated"` | Either PR source or target changes | No. |
| `"reopened"` | Closed PR reopened | No. |
| `"merged"` | PR merged through this server | Yes, for a qualifying target update. Not included by default. |

PR checks merge the recorded head into the recorded base before steps run; conflicts
fail preparation. Enable opened/updated/reopened when requiring CI. Patterns are
case-sensitive globs (`release/*`, `feature/?`), not regular expressions; do not
assume `!pattern` exclusion syntax or another CI product's glob semantics.

## Steps

| Option | Requirement | Example |
| --- | --- | --- |
| `steps` | Pipeline-local array, 1–64 objects | `"steps":[{"name":"Tests","run":"python -m unittest discover -v"}]` |
| `name` | String, 1–120 trimmed characters | `"name":"Unit tests"` |
| `run` | Nonempty string, at most 8192 characters, no NUL | `"run":"python -m compileall -q ."` |

Only `name` and `run` are accepted. Steps run in order with separate statuses,
exit codes and logs. Failure skips later steps. There is no per-step timeout,
retry, condition, env override or continue-on-error option.

Each step starts a fresh shell in the checkout root. Files persist; `cd`, `export`
and shell variables do not. Combine dependent operations in one step, for example
`cd src && python -m unittest discover -v` on POSIX. Docker starts a separate
container per step; only checkout files persist, not container `/tmp`.

`run` supports single-pass `{{ env.NAME }}` substitution, for example
`"run":"python tools/build.py --mode \"{{ env.BUILD_MODE }}\""`. Missing variables
fail the step. Filters, expressions, loops/calls and recursive expansion are not
supported. Values are **not shell-escaped**; quote for the runner shell and avoid
interpolating untrusted executable syntax. Prefer tools reading values directly
from their environment. JSON strings escape newlines as `\n` and quotes as `\"`.
Environment/snapshots are plaintext and logs are not secret-redacted.

## Artifacts and notifications

Artifacts belong to the pipeline producing them. Notifications belong inside the
pipeline or deployment that should send them; there is no shared notification policy.

| Option | Default | Example / behavior |
| --- | --- | --- |
| `artifacts.paths` | `[]` | `"paths":["dist/*","reports/**/*.xml"]`; relative **file** globs, not directory-only archives. |
| `artifacts.when` | `"always"` | `"when":"always"` collects after success/failure/timeout where a checkout exists; cancelled runs never collect. |
| `artifacts.when` | — | `"when":"success"` only collects successful execution; `"when":"failure"` collects failed/timed-out execution. |
| `notifications.email.mode` | `"off"` | `"email":{"mode":"failures"}`; allowed modes below. |
| `notifications.email.recipients` | `[]` | `"email":{"recipients":["ci@example.com","ops@example.com"]}`; at most 20 plain addresses, one per string. |

Missing artifact matches produce no download, not an error. Collection errors or
limit violations fail a run. ZIPs appear on run details and Artifacts, are stored
in SQLite, and obey repository access controls. JUnit/report contents are not parsed.
No symlinks, junctions, hardlinks, `.git` contents, traversal or absolute paths.

| Email mode | CI notification behavior |
| --- | --- |
| `"off"` | Disabled. |
| `"failures"` | Failed and timed-out results. |
| `"all"` | Successful, failed and timed-out completions; cancelled/interrupted CI does not send. |
| `"recovery"` | Failures plus the first success after failure/timeout in the same pipeline/event/branch, or same PR across PR-check events. |

Every enabled email mode needs recipients on that same pipeline/deployment object.
No mode or recipients are inherited from other objects.
SMTP is configured under **Admin: Email**, not in JSON. Deployment sends separate
messages with the same policy, including interrupted deployment failures and
deployment-specific recovery. Messages contain metadata, not commands/logs/env.
Recipients may learn private repository metadata without a login. Delivery failure
does not change results; see [email operations](../README.md#email-notifications).

## Every deployment option

Each object in top-level `deployments` describes a separately named target. Multiple
targets can reference the same pipeline. They execute sequentially after that pipeline
passes, with separate logs, results, attempt identity and notifications. Deployments
still execute trusted host scripts, even when CI execution uses Docker.

| Option | Type / default | Example | Behavior |
| --- | --- | --- | --- |
| `name` | Required unique string | `"name":"production"` | Stable target name; one attempt per repository/deployment/commit. |
| `pipeline` | Required existing pipeline name | `"pipeline":"checks"` | The pipeline whose successful branch update gates this deployment. No execution/email settings are inherited from it. |
| `enabled` | Boolean `true` when block exists | `"enabled":false` | Keeps configuration while disabling deployment. No block means no deployment. |
| `branch` | One valid branch name, `"main"` | `"branch":"develop"` | Exact branch, not a glob/array; add another deployment object for another target. |
| `script` | Absolute host path, none | `"script":"/opt/deploy/staging.sh"` | Must exist outside repositories; server user needs access. |
| `script_content` | UTF-8 text, none | `"script_content":"import sys\nprint(sys.argv[1])\n"` | Alternative to script; use this example with `run_with: "python"`. Written privately during execution, then removed. |
| `run_with` | String `"direct"` | `"run_with":"python"` | Uses the server's interpreter and virtual environment, not the CI image. |
| `run_with` | — | `"run_with":"bash -e"` | Other installed interpreters include `node` or `pwsh -NoProfile -File`; no shell expansion/pipes/chaining. |
| `run_with` | — | `"run_with":"direct"` | Blank/direct executes the script itself; POSIX needs an executable script with a shebang. |
| `timeout_seconds` | Integer 1–86400, `600` | `"timeout_seconds":900` | Separate deployment budget, not the CI timeout. |

Supply script or script_content, not both. An enabled block requires one; a
disabled draft may omit it. Windows path example: `C:/deploy/release.py` with
`run_with: "python"`. Dependencies belong on the host. Quote interpreter paths
containing spaces. The exact invocation is interpreter arguments + script path +
tested SHA; there is no configurable script args array.

Deployment follows only its **own** successful push/merged run, while the tested
commit is still the branch tip. It does not wait for another pipeline. Manual and
PR-check runs never deploy. Scripts receive the SHA as argument 1 and
`PYGITHOST_COMMIT`, plus owner/repo/branch/pipeline variables. They run in a separate
temporary directory, with network, without CI checkout or automatic artifact handoff.
Retrieve/deploy that exact SHA, not a later fetched branch tip.

Removing/changing/disabling deployment prevents old snapshots from deploying.
Each repository/deployment/commit gets **one attempt**, including failures: no automatic
retry or rollback. Restarts mark unfinished attempts interrupted rather than replaying
them. Verify the real target after interruption. Protect scripts/credentials from
CI job writes; same-user processes are not isolated by owner-only permissions.
Read the [deployment walkthrough](automatic-deployment.md) before enabling it.

## Every repository setting

Policies and retention are repository-wide; never repeat them inside pipelines.

| Option | Type / default | Example | Behavior |
| --- | --- | --- | --- |
| `policies.require_ci` | Boolean `false` | `"policies":{"require_ci":true}` | Each applicable PR-check pipeline needs a newest successful check for exact current base/head. Missing/stale/pending/unsuccessful checks block merging; push/manual jobs do not qualify. No qualifying checks means blocked. |
| `policies.block_direct_pushes` | Boolean `false` | `"policies":{"block_direct_pushes":true}` | Blocks matching direct HTTP branch creations, force pushes and deletions; approved PR merges remain allowed. |
| `policies.protected_branches` | String array `["main"]` | `"protected_branches":["main","release/*"]` | Case-sensitive globs; nonempty when blocking is enabled. Also prevents matching branch UI creation/deletion. |
| `retention.artifacts.days` | Integer 0–36500, `7` | `"artifacts":{"days":30}` | Artifact age expiration; 0 disables it. |
| `retention.artifacts.max_count` | Integer 0–1000000, `0` | `"artifacts":{"max_count":50}` | Repository-wide bundle count; oldest run IDs removed first. 0 disables it. |
| `retention.runs.max_count` | Integer 0–1000000, server default normally `100` | `"runs":{"max_count":200}` | Repository-wide completed-run limit; 0 disables pruning. `PYGITHOST_CI_RETENTION` sets the omitted default. |

Both protection switches are independent; enable both to require PRs and passing
CI. Initialize branches first. Existing pre-receive hooks are preserved; chaining
requires Git 2.36+. Enforcement covers this HTTP server, not SSH/local filesystem
changes. Host CI with server-user access cannot enforce a boundary against malicious
jobs manipulating refs directly.

Retention is current storage policy, not a run snapshot. Both artifact age/count
apply; set both to zero for indefinite artifact storage. Retained artifacts protect
parent runs, as do active runs and pending notifications, so the run count may be
exceeded. Deployment history is independent and is not pruned by these settings.
Saving applies immediately and can permanently delete existing data. Expiration is
checked at startup/storage operations, not by an exact-time timer. SQLite may reuse
freed pages without shrinking its OS file. See [Retention](ci-retention.md).

## Compatibility

Existing keyed/shared-default documents remain readable. Opening the editor converts
them to named arrays, resolves inherited values into each pipeline, and moves inline
deployments to the separate list. Old pipeline IDs become names; old target names
match those IDs to retain deduplication. Policies/scripts/disabled states survive.
See the [migration guide](ci-migration.md) for every old-to-new field mapping and
a comparison with the proposed configuration design.

Pipeline-local `file` retains an existing Git-managed source instead of steps:
`"file":".pygithost-ci.json"`. Use a regular root-level `.json` filename, not a
path/symlink. Do not commit the administrator document: repository code must not
control trusted host deployment or policies.

The separate Git file accepts version 1, named `steps`, optional `env`, `artifacts`
and `timeout_seconds`; legacy `command` remains readable, mutually exclusive with
steps. Its env replaces rather than merges the effective server env. Its timeout
cannot exceed the pipeline's configured limit. A regular blob is limited to 64 KiB.
Missing/invalid files fail closed. Push/manual runs read the recorded commit; PR
checks read the **recorded target/base commit's file**, not unreviewed PR-head changes.
Snapshots retain effective settings and SHAs for reruns.

Unsupported features are rejected, not ignored: execution working_directory,
per-step timeout/retry/conditions/continue_on_error, arbitrary script args,
cross-pipeline requires, manual deployment, approvals or
approver groups, per-pipeline artifact age, and deployment-history retention.
Use pipeline execution timeout, ordered steps, named host deployments and
repository-wide retention for the behavior currently available.

## Variables, limits and troubleshooting

| Built-in variable | Meaning |
| --- | --- |
| `CI` | `true`. |
| `PYGITHOST_PIPELINE` | Stable pipeline ID; also available to deployment. |
| `PYGITHOST_DEPLOYMENT` | Deployment-only target name, e.g. production; not a CI job variable. |
| `PYGITHOST_OWNER`, `PYGITHOST_REPO` | Repository owner/name; also available to deployment. |
| `PYGITHOST_REPOSITORY` | Owner/name pair. |
| `PYGITHOST_EVENT` | Internal label such as push, manual, pull_request_updated. |
| `PYGITHOST_REF`, `PYGITHOST_BRANCH` | Branch ref and recorded branch (PR target for checks); branch also available to deployment. |
| `PYGITHOST_COMMIT` | Recorded commit/base for PR preparation; also deployment argument 1. |
| `PYGITHOST_OLD_COMMIT` | Previous push commit or empty. |
| `PYGITHOST_PR_NUMBER` | PR number string or empty. |
| `PYGITHOST_BASE_BRANCH`, `PYGITHOST_HEAD_BRANCH` | PR target/source; head branch falls back to recorded branch for non-PR runs. |
| `PYGITHOST_BASE_COMMIT` | Recorded PR base or empty. |
| `PYGITHOST_WORKTREE` | Independent checkout path, `/workspace` inside Docker. |

Only the documented subset reaches deployment; do not assume every CI variable
exists there. No documented `PYGITHOST_HEAD_COMMIT` is provided.

| Limit | Value |
| --- | --- |
| Administrator JSON | 256 KiB UTF-8; no comments, duplicate keys, unknown fields or trailing commas. |
| Pipelines/deployments/steps | 16 pipelines, 32 deployments; 1–64 steps per pipeline, step names 1–120 trimmed characters, run strings up to 8192 characters. |
| Environment | 64 effective entries, identifier names, string values up to 8192 characters, no NUL; Docker forbids CR/LF. |
| Branch arrays | Nonempty string entries without CR/LF/NUL; each complete filter field at most 2048 joined characters. |
| Email | 20 plain addresses, at most 2048 joined characters. |
| Docker image | At most 256 valid image-name characters. |
| Artifact patterns | 32 patterns of 256 characters; relative forward-slash paths, no `.git`, traversal, absolute paths, colon, backslash or NUL. |
| Artifact archive | 20 MiB uncompressed / 1000 files; at most 10,000 matched entries. |
| Deployment script content | 64 KiB UTF-8, no NUL. |
| Deployment path/interpreter | At most 4096 characters; path absolute and outside repo; interpreter one line with no CR/LF/NUL. |
| Deployment branch/timeout | One valid branch of up to 255 characters; timeout 1–86400 seconds. |
| Stored combined logs | 1 MiB cap while output continues to drain. |

### Troubleshooting

| Symptom | Check |
| --- | --- |
| No runs appear | Enable the effective trigger and inspect case-sensitive branch arrays. Manual also needs an existing branch/write access. |
| A branch array fails | Use `["main"]`, not a scalar/newline-separated string. `[]` matches all; disable trigger to stop it. |
| Another object's setting has no effect | Expected: configurations are independent. Put values explicitly on the affected pipeline/deployment. |
| Step loses cd/export | Fresh shell per step; combine dependent operations. |
| Docker cannot install/build | Prebuild dependencies/tools in the image; no job network or automatic image pull. |
| Another pipeline passed but merge is blocked | Each applicable pipeline needs its own exact-commit PR check, not a push/manual run. |
| Deployment did not run | Check push/merged event, enabled block, exact branch tip, changed settings and prior attempt. |
| Rerun uses old settings | Expected: original snapshot and SHAs. Queue a new run for new settings. |
| Artifacts disappeared | Current retention applies immediately; raising limits does not restore deleted data. |
| JSON rejected | Correct the displayed error in the same editor. Unsupported proposed features are not silently accepted; saved data stays unchanged. |

See [Runs, queues and recovery](../README.md#runs-queues-and-recovery) for scheduler
limits, shutdown, process-tree/container cleanup and the single-server boundary.
