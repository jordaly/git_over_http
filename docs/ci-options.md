# CI JSON: every option

[Quick start](pipelines.md) · [Recipes](pipeline-examples.md) · [Deployment](automatic-deployment.md) · [Retention](ci-retention.md) · [HTTP runner](http-runner.md)

This manual is rendered directly in **CI → Documentation** from the checked-in
documentation. Project CI configuration is read from **`ci/config.json`** in the
repository, separate from the server's `pygithost.config.json` (network,
authentication and storage). Commit configuration changes to Git; there is no page
JSON editor and no API replacement endpoint.

## Contents

- [Complete examples](#complete-examples)
- [Repository configuration](#repository-configuration)
- [Secrets, retention and administrator defaults](#secrets-retention-and-administrator-defaults)
- [Document structure](#document-structure)
- [Independent configuration](#independent-configuration)
- [Every execution option](#every-execution-option)
- [Triggers and cancellation](#triggers-and-cancellation)
- [Steps](#steps)
- [Artifacts and notifications](#artifacts-and-notifications)
- [Every deployment option](#every-deployment-option)
- [Guidance for AI agents](#guidance-for-ai-agents)
- [Every repository setting](#every-repository-setting)
- [Compatibility and file rules](#compatibility-and-file-rules)
- [Variables, limits and troubleshooting](#variables-limits-and-troubleshooting)

## Complete examples

| Example | Purpose |
| --- | --- |
| [All options](examples/ci/all-options.json) | Full document with checks/release pipelines, separately named deployments, cancellation, artifacts, notifications, policies and retention. Commit as `ci/config.json`. |
| [Inline deployment](examples/ci/inline-deployment.json) | Full document using Python script content rather than a host script path. Commit as `ci/config.json`. |
| [Git-managed configuration](examples/ci/git-managed.json) | Full document with named pipelines that reference `ci/tests.json` and `ci/build.json`. Commit the document as `ci/config.json` and the referenced files under `ci/`. |
| [Repository pipeline](examples/ci/repository-pipeline.json) | Simple single-pipeline document. Commit as `ci/config.json`. |

Example links display complete JSON in the application. Deployments in these files
are disabled until reviewed and enabled. Replace example recipients and script
paths. Prepare Docker images/dependencies before running; validation does not
install tools or execute the examples. A generic Python image may not include your
build tools.

> Commit the file; do not paste it into a page. There is no project configuration
> editor or replacement API. Every enabled deployment still needs administrator
> trust authorization.

## Repository configuration

Project CI has two supported forms at **`ci/config.json`**:

1. A **simple pipeline** with `version` and `steps` (or the legacy `command`).
2. A **full grouped document** with named `pipelines` and `deployments` arrays,
   plus optional root `policies` and `retention`.

A missing `ci/config.json` means no automatic run. An invalid or malformed file
produces a configuration failure without executing commands. A malformed committed
file also fails closed for repository protection: merges require CI and all direct
branches are treated as protected until an operator repairs the file through Git or
the server filesystem. No stale successful check can satisfy an invalid base
configuration. There is no web editor, API replacement or saved-definition fallback
for repair, so validate JSON before committing. Committed configuration is read
from the recorded commit, never from an uncommitted working tree or a saved
database definition. Push/manual runs use the run's commit; pull-request checks use
the recorded target/base commit so unreviewed PR code cannot replace its own
pipeline.

Validate a checkout or repository without executing or queuing anything:

```sh
python -m pygithost ci validate                 # working tree, including uncommitted changes
python -m pygithost ci validate --rev HEAD      # committed HEAD instead
python -m pygithost ci validate /path/to/repo   # another checkout or bare repository
```

The optional path may also be supplied as `--repository`, `--repo` or `--path`.
With `--rev`/`--revision`, use `HEAD`, a branch reference such as
`refs/heads/main`, or a full commit SHA. Outside a working tree, the command
inspects committed `HEAD`. It validates every referenced pipeline file with the
same parser used by the server and exits nonzero for a missing, invalid or
unresolvable configuration. Working-tree validation is a pre-commit check; runtime
CI still reads the recorded commit.

**CI → Run pipeline** validates branch-first. Choose a branch and select **Check
configuration** to read its committed `ci/config.json` and referenced files without
queuing a job. The page shows the exact configuration commit SHA and status:
`valid`, `missing`, `invalid`, `blocked` (administrator authorization denied), or
`unavailable` (revision cannot be resolved). The manual run form is enabled only for
a runnable pipeline in a `valid` or parseable `blocked` configuration. It carries
the validated commit SHA, so a manual run is rejected with a prompt to recheck if
the branch tip moved.

The simple form is one pipeline named `ci`:

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

It accepts only `version`, `command`, `steps`, `env`, `artifacts` and
`timeout_seconds`. Built-in execution is Docker with image `python:3.14-slim`.
Pushes and pull-request opened/updated/reopened events are enabled on all branches;
manual runs are always available to write-authorized users. The simple form cannot
define deployments, protection policies or retention.

The full grouped form is described below. Up to 16 pipelines and 32 deployments
are supported. Empty `pipelines` and `deployments` arrays stop new automatic runs
without deleting history. A pipeline may use inline `steps` or a `file` reference
to another pipeline file, but not both. Every referenced file must be a regular
JSON file under `ci/`; `ci/config.json` itself cannot be referenced recursively.

`ci/config.json` cannot be a `{"version":1,"file":"ci/config.json"}` reference to
itself. That obsolete Settings-only shorthand is not a valid configuration root.

## Secrets, retention and administrator defaults

**CI → Settings** is the repository environment-variable and secret page. It does
not edit pipeline JSON or project retention. **Admin → Settings** retains
server-wide environment defaults and storage retention defaults.

- Server variables are inherited by name. Repository rows override matching names;
  pipeline-scoped rows override repository-wide rows.
- Page-managed values also override matching `env` entries committed in
  `ci/config.json`. Values are resolved when a job executes, not copied into new
  stored run snapshots. They can still appear in remote job assignments and logs.
- All page values, including server-wide values, are withheld from unmerged
  pull-request checks. Those checks receive only committed `env` and built-in
  variables.
- Repository rows can be scoped to **Non-PR CI runs** (ordinary), **Authorized
  protected branch**, or **Deployments only**. Deployment-only values are not sent
  to CI test jobs. An ordinary value is not sent to a deployment. A restricted
  repository override also does not fall back to a broader or server-wide value
  when its scope is not allowed.
- A protected value additionally requires the server process environment variable
  `PYGITHOST_CI_PROTECTED_SECRET_BRANCHES` to contain the exact
  `owner/repo:branch`, the current default branch's committed
  `block_direct_pushes` and `protected_branches` policy to match the branch, and
  the execution commit to equal the current branch tip. Entries are comma- or
  newline-separated; the default is empty. This server-side authorization prevents
  a repository writer from self-granting protected values by editing Git.
- Never commit secrets to Git. Settings storage, committed configuration and logs
  are plaintext, and logs are not secret-redacted. **Show values** changes masking
  only.
- A blank repository value is a real empty string. Removing an override restores
  the server value.
- The default branch's full grouped document controls cleanup, within nonzero
  administrator caps. Feature branches and reruns cannot change it. The project
  page has no retention form.

See [Retention](ci-retention.md) for limits, administrator caps, refresh and
deletion timing.

## Document structure

The full grouped form uses named arrays:

| Option | Default / type | Example and meaning |
| --- | --- | --- |
| `version` | Integer `1` | `"version": 1`; the only supported version. |
| `pipelines` | Required array | `"pipelines": [{"name":"checks","steps":[{"name":"Tests","run":"python -m unittest discover -v"}]}]`. Every object requires its own name. |
| `deployments` | Array, default `[]` | `"deployments":[{"name":"production","pipeline":"checks","enabled":false,"script":"/opt/deploy/app.sh"}]`; separately named host targets linked to a pipeline. |
| `policies` | Protection off | `"policies":{"require_ci":true}`; repository-wide merge/direct-push protection. |
| `retention` | Administrator defaults | `"retention":{"artifacts":{"days":30,"max_count":50},"runs":{"max_count":100}}`; set it on the default branch. |

Up to 16 pipelines and 32 deployments. Each object requires `name`, using 1–64 ASCII
letters, digits, underscores or hyphens, beginning alphanumeric. Names are unique
within each list; pipeline and deployment names may match. Keep them stable.
Referenced pipelines must exist; remove or repoint their deployments when deleting
a pipeline.

Pipeline-local groups: `execution`, `triggers`, `cancellation`, `artifacts`,
`notifications`, `steps`, or `file` instead of steps. Deployment configuration
belongs only in the separate deployments list. Policies and retention remain at
the document root. There is no top-level notification policy.

## Independent configuration

No pipeline or deployment inherits configuration from another pipeline/deployment.
Omitted execution and cancellation fields use built-in defaults. Other fields use
their documented built-ins. Enabling email on one pipeline does not enable another
pipeline's or a deployment's email.

Empty branch arrays match **all** branches; disable a trigger with `enabled: false`
to stop it. Empty recipients are invalid with enabled email. Empty artifact paths
disable collection. Empty protected patterns are invalid with direct-push blocking.

## Every execution option

These fields belong in each pipeline object's `execution` group. Table examples are
**field fragments**; use the complete examples for surrounding JSON.

| Option | Type / built-in default | Example | Behavior |
| --- | --- | --- | --- |
| `runner` | `"docker"` | `"runner":"remote-docker"` | `host` runs as the server OS user, without a sandbox, and requires administrator trust authorization. `docker` uses local Linux containers; `remote-docker` uses an outbound HTTP worker. |
| `docker` | Hardened profile | `"docker":{"memory_mb":2048}` | Declarative resources, network, paths, tmpfs and named mounts. Remote requests must fit an administrator-owned worker policy; see [Docker profiles](docker-profiles.md). |
| `source_limit_mb` | `100` | `"source_limit_mb":500` | Positive integer MiB for the remote source bundle; no hard-coded upper configured size ceiling. |
| `limits` | Bounded defaults | `"limits":{"log_mb":8,"artifact_mb":128}` | Log/artifact sizes/counts and source/transfer timeouts; see [CI limits](ci-limits.md). |
| `image` | String `"python:3.14-slim"` | `"image":"registry.example.com/team/ci:2026-10"` | Docker image must already exist locally. Include tools/dependencies and preferably pin a digest. |
| `timeout_seconds` | Built-in `1800` | `"timeout_seconds":600` | One budget for checkout, PR merge preparation and all steps. Deployment has a separate timeout. |
| `env` | Public defaults only | `"env":{"BUILD_MODE":"release"}` | Up to 64 effective entries; valid identifier keys, string values up to 8192 characters, no NUL. Never put secrets in Git. Page-managed values override matching names at execution and are withheld from unmerged PR checks. |

**Host** commands use `/bin/sh` on POSIX and `cmd.exe` on Windows. A restricted
environment prevents accidental credential inheritance but does not restrict
filesystem/process access. Host CI is trusted-code-only and additionally requires
the exact repository name under **Admin → Settings → Trusted CI repositories**; wildcard or
malformed allowlist entries are rejected.

**Docker** uses `/bin/sh` and overrides the image entrypoint. By default it mounts
the independent checkout—not the production repository or Docker socket. Defaults:
no network, read-only root filesystem, no capabilities or privilege escalation;
1 GiB memory, one CPU, 128 PIDs and a 256 MiB writable `/tmp`. Checkout storage has
no disk quota. Linux uses the server user's UID/GID. This is defense in depth, not
a complete hostile-code boundary; use a dedicated runner host for hostile code.
Resource/path requests and worker-approved named mounts are described in
[Docker profiles](docker-profiles.md).

Remote workers can download missing images on the host by default, controlled by
worker policy `image_pull`. Local Docker jobs still require prepared local images.
Job containers cannot install dependencies from the network under the default
network isolation. Even `pip install -e .` may need network for build dependencies;
build the tools into your CI image. Docker environment values cannot contain CR/LF.

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
| `manual.enabled` | Always enabled | Optional legacy Boolean | Accepted for compatibility, but `false` does not disable manual runs. Write access, a runnable pipeline and an existing branch are required. Push/PR filters do not restrict manual runs. Manual runs **never deploy**. |
| `cancellation.superseded` | Built-in `false` | `"cancellation":{"superseded":true}` | Pipeline-local, not inside triggers. Cancels older matching event/branch/PR runs of the **same** pipeline. Manual runs are not superseded. |

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

The simple pipeline publishes push and PR opened/updated/reopened events by default
with no branch filters.

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
from their environment. Branch placeholders (`PYGITHOST_REF`, `PYGITHOST_BRANCH`,
`PYGITHOST_BASE_BRANCH`, `PYGITHOST_HEAD_BRANCH`) are chosen by whoever pushes or
opens the pull request, so the step fails instead of inserting a value containing
anything other than letters, digits and `. _ / @ + , = -`; use the quoted
environment variable (`"$PYGITHOST_BRANCH"`, `%PYGITHOST_BRANCH%`) when you need
arbitrary branch names. JSON strings escape newlines as `\n` and quotes as `\"`.
Committed configuration and stored snapshots are plaintext; page-managed values are
resolved live and are not stored in new snapshots. Neither logs nor remote job
assignments are secret-redacted.

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

Each object in top-level `deployments` describes a separately named host target.
Multiple targets can reference the same pipeline. They execute sequentially after
that pipeline passes, with separate logs, results, attempt identity and
notifications.

Deployments execute trusted host scripts or host steps, even when CI execution uses
Docker. **Every enabled deployment requires an administrator grant under
Trusted CI repositories.** Repository writers cannot grant themselves
server-user execution by adding a deployment. The allowlist accepts exact
`owner/repo` entries only; wildcards, patterns, malformed names and `..` are
rejected rather than matched. A parseable configuration denied by this guard keeps
its declared branch policies but fails the queued run during configuration, before
commands execute.

| Option | Type / default | Example | Behavior |
| --- | --- | --- | --- |
| `name` | Required unique string | `"name":"production"` | Stable target name; one attempt per repository/deployment/commit. |
| `pipeline` | Required existing pipeline name | `"pipeline":"checks"` | The pipeline whose successful branch update gates this deployment. No execution/email settings are inherited from it. |
| `enabled` | Boolean `true` when block exists | `"enabled":false` | Keeps configuration while disabling deployment. No block means no deployment. |
| `branch` | One valid branch name, `"main"` | `"branch":"develop"` | Exact branch, not a glob/array; add another deployment object for another target. |
| `script` | Absolute host path, none | `"script":"/opt/deploy/staging.sh"` | Must exist outside repositories; server user needs access. |
| `script_content` | UTF-8 text, none | `"script_content":"import sys\nprint(sys.argv[1])\n"` | Alternative to script; use this example with `run_with: "python"`. Written privately during execution, then removed. |
| `steps` | Array, default `[]`, at most 64 | `"steps":[{"name":"Release","run":"/opt/deploy/release.sh"}]` | Named host-shell commands with individual status/output. Each requires nonempty `name` and `run`; no other step fields are supported. Alternative to either script option. |
| `run_with` | String `"direct"` | `"run_with":"python"` | Uses the server's interpreter and virtual environment, not the CI image. |
| `run_with` | — | `"run_with":"bash -e"` | Other installed interpreters include `node` or `pwsh -NoProfile -File`; no shell expansion/pipes/chaining. |
| `run_with` | — | `"run_with":"direct"` | Blank/direct executes the script itself; POSIX needs an executable script with a shebang. |
| `timeout_seconds` | Integer 1–86400, `600` | `"timeout_seconds":900` | Separate deployment budget, not the CI timeout. |

Supply nonempty steps, script or script_content, without combining execution forms.
An enabled block requires one; a disabled draft may omit it. Windows path example:
`C:/deploy/release.py` with `run_with: "python"`. Dependencies belong on the host.
Quote interpreter paths containing spaces. The exact invocation is interpreter
arguments + script path + tested SHA; there is no configurable script args array.

Deployment steps use fresh host shells in a checkout of the tested commit, not the
CI job's checkout. Files persist between steps; shell state does not. `run_with`
does not select their shell. All steps share `timeout_seconds`; failure skips later
steps. Read the tested SHA from `PYGITHOST_COMMIT` in step commands and resolve
repository files against the checkout at `PYGITHOST_WORKTREE`, which is also the
working directory. The Deployments list and detail pages refresh live logs and
statuses every two seconds, with per-step and combined output. Existing script
targets are displayed as a single Deploy step.

Deployment follows only its **own** successful push/merged run, while the tested
commit is still the branch tip. It does not wait for another pipeline. Manual and
PR-check runs never deploy. Scripts receive the SHA as argument 1 and
`PYGITHOST_COMMIT`, plus owner/repo/branch/pipeline variables. They run in a detached
checkout of that commit with its `origin` removed, with network, without the CI job's
working tree or automatic artifact handoff. Submodules are not initialized.
Retrieve/deploy that exact SHA, not a later fetched branch tip.

Removing/changing/disabling deployment prevents old snapshots from deploying.
Each repository/deployment/commit gets **one attempt**, including failures: no
automatic retry or rollback. Restarts mark unfinished attempts interrupted rather
than replaying them. Verify the real target after interruption. Protect
scripts/credentials from CI job writes; same-user processes are not isolated by
owner-only permissions. Read the [deployment walkthrough](automatic-deployment.md)
before enabling it.

## Guidance for AI agents

When generating or modifying CI/deployment configuration:

1. **Edit the repository file.** Project configuration is `ci/config.json` in Git.
   Use the simple form or one full grouped document with named `pipelines` and
   `deployments` arrays. Referenced files must also be under `ci/`. Do not invent a
   page editor, a saved database document or a replacement API. Do not confuse the
   project file with `pygithost.config.json`.
2. **Never commit secrets.** Put credentials in **CI → Settings** environment
   rows and choose the least permissive scope that works: ordinary for non-PR CI,
   protected only for an administrator-authorized protected branch at its current
   tip, or deployment-only for host deployments. Committed `env` is public
   configuration only. Page values override matching Git values and are resolved
   at execution; unmerged PR checks receive none. Logs, remote assignments and
   committed configuration are not redacted.
3. **Preserve unrelated configuration.** Read the current file before proposing a
   replacement. Keep existing names, pipeline references, notifications, policies
   and retention. Commit the whole resulting document; there is no JSON patch.
4. **Use only supported fields.** Deployment steps contain `name` and `run`, not
   CI-provider-specific `uses`, `needs`, retries, approvals or per-step timeouts.
   Use one execution form per target and one target-wide timeout. Run
   `python -m pygithost ci validate` before committing; a generic JSON syntax check
   alone does not validate pipeline fields or referenced files.
5. **Respect the trust boundary.** Host jobs and enabled deployments require an
   administrator to add the exact `owner/repo` to
   **Admin → Settings → Trusted CI repositories**. Wildcards and malformed entries are
   rejected; repository code cannot self-authorize. Propose new targets with
   `enabled:false` until reviewed. Do not expand trust, change branch protections
   or alter credentials without explicit authorization.
6. **Deploy the tested SHA.** Use the script's first argument or
   `PYGITHOST_COMMIT` in step commands. Do not deploy the latest branch tip instead.
   Do not assume CI checkout, artifacts or CI environment values exist on the
   deployment host.
7. **Verify without triggering a release.** A manual run checks CI and never
   deploys. Deployment requires a qualifying successful push or merged-PR run.
   Inspect CI results separately from deployment results and live step output.
8. **Handle uncertainty safely.** Each repository/target/commit gets one attempt.
   After timeout or interruption, inspect the real target before proposing recovery.
   Do not rename targets to evade duplicate protection or assume automatic rollback.

For code changes to this feature, update the option reference, deployment guide and
applicable JSON examples together. Test validation, failure/skipped steps, live
output persistence, HTML escaping and independent target results. Report which
checks actually ran.

## Every repository setting

Policies and retention are repository-wide root fields in the full grouped document;
never repeat them inside pipelines. A simple pipeline cannot set them.

| Option | Type / default | Example | Behavior |
| --- | --- | --- | --- |
| `policies.require_ci` | Boolean `false` | `"policies":{"require_ci":true}` | Each applicable PR-check pipeline needs a newest successful check for exact current base/head. Missing/stale/pending/unsuccessful checks block merging; push/manual jobs do not qualify. No qualifying checks means blocked. |
| `policies.block_direct_pushes` | Boolean `false` | `"policies":{"block_direct_pushes":true}` | Blocks matching direct HTTP branch updates, including web conflict resolutions that would write to a protected PR source branch. Approved PR merges remain allowed. |
| `policies.protected_branches` | String array `["main"]` | `"policies":{"protected_branches":["main","release/*"]}` | Case-sensitive globs; nonempty when blocking is enabled. Also prevents matching branch UI creation/deletion. |
| `policies.merge_methods` | String array `["merge","squash","rebase","ff"]` | `"policies":{"merge_methods":["squash"]}` | Merge methods the pull request merge button and API accept, for every target branch: merge commit, squash and merge, rebase and merge, fast-forward. The first listed is the default choice. |
| `policies.required_approvals` | Integer 0–10, `0` | `"policies":{"required_approvals":1}` | Pull requests into a branch matching `protected_branches` need this many approving reviews (latest review per reviewer, authors cannot approve their own PR) before merging. |
| `policies.dismiss_stale_approvals` | Boolean `false` | `"policies":{"dismiss_stale_approvals":true}` | New commits on the head branch dismiss earlier approvals of PRs into protected branches. |
| `policies.block_on_changes_requested` | Boolean `false` | `"policies":{"block_on_changes_requested":true}` | A reviewer's outstanding "Request changes" blocks merging into protected branches until they approve or the review is dismissed. |
| `policies.require_conversation_resolution` | Boolean `false` | `"policies":{"require_conversation_resolution":true}` | Every review conversation must be resolved before merging into protected branches. |
| `retention.artifacts.days` | Integer 0–36500 | `"retention":{"artifacts":{"days":30}}` | Artifact age expiration; 0 disables it. Omitted uses administrator defaults. |
| `retention.artifacts.max_count` | Integer 0–1000000 | `"retention":{"artifacts":{"max_count":50}}` | Repository-wide bundle count; oldest run IDs removed first. 0 disables it. |
| `retention.runs.max_count` | Integer 0–1000000 | `"retention":{"runs":{"max_count":100}}` | Repository-wide completed-run limit; 0 disables pruning. Omitted uses administrator defaults. |

Both protection switches are read from the default branch. Enable both to
require PRs and passing CI. The exact PR target commit still defines which checks
must pass. GitHost rejects protected mutations when it cannot verify the
repository policy; a verified empty repository has no policy yet.
Existing pre-receive hooks are preserved; chaining
requires Git 2.36+. Enforcement covers this HTTP server, not SSH/local filesystem
changes. Host CI with server-user access cannot enforce a boundary against malicious
jobs manipulating refs directly.

Policy changes are configuration changes: commit them and review them with the same
care as executable code. A malformed committed document fails closed with CI
required and every direct branch protected; a parseable host/deployment denial keeps
these declared policies but fails the queued run at configuration. Retention is
the default branch's storage policy, subject to administrator limits, not a
per-run setting. Both artifact age/count apply;
set both to zero to keep artifacts indefinitely. Retained artifacts protect parent
runs, as do active runs and pending notifications, so the run count may be exceeded.
Deployment history is independent and is not pruned by these settings. Lower
limits can permanently delete existing data during the next cleanup. See
[Retention](ci-retention.md).

## Compatibility and file rules

Project definitions previously stored only in the database are no longer an
alternative configuration source. Copy any needed old document into
`ci/config.json` before upgrading; there is no automatic import, no read-through
fallback and no replay of old saved commands. Existing page environment values
remain until the variables form is saved. Historical snapshots that mixed page
credentials into Git variables are not replayed, and new stored run snapshots
exclude page credentials. See the [migration guide](ci-migration.md).

The obsolete Settings-only `{"version":1,"file":"ci/config.json"}` reference is not
valid as the root of `ci/config.json`. That historical example remains only to
explain migration.

Pipeline-local `file` selects a separate Git-managed pipeline source instead of
steps:

```json
{"name":"tests","file":"ci/tests.json","triggers":{"push":{"enabled":true}}}
```

Use a regular `.json` file under `ci/`, for example `ci/tests.json`. Paths are
checkout-relative; outside-`ci`, absolute, traversal, `.git`, backslash and symlink
files are rejected. A referenced pipeline file uses the simple pipeline fields
(`version`, `steps` or `command`, `env`, `artifacts`, `timeout_seconds`) and cannot
itself contain deployments or policies. It is read from the same trusted commit as
the entry document. Push/manual runs read the recorded commit; PR checks read the
**recorded target/base commit's file**, not unreviewed PR-head changes.

A regular configuration blob is limited to 256 KiB; duplicate keys, comments and
non-object roots are rejected. Snapshots retain committed settings, limits and SHAs
for reruns; page-managed values are resolved live instead of being stored. A rerun
does not adopt a newer commit's configuration and does not retry deployments.

Unsupported features are rejected, not ignored: execution working_directory,
per-step timeout/retry/conditions/continue_on_error, arbitrary script args,
cross-pipeline requires, manual deployment, approvals or approver groups,
per-pipeline artifact age, and deployment-history retention. Use pipeline execution
timeout, ordered steps, named host deployments and repository-wide retention for
the behavior currently available.

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
| `PYGITHOST_WORKTREE` | Checkout path; `/workspace` inside Docker. Also set for deployment, where it is the working directory. |

Only the documented subset reaches deployment; do not assume every CI variable
exists there. No documented `PYGITHOST_HEAD_COMMIT` is provided.

| Limit | Value |
| --- | --- |
| Configuration files | 256 KiB UTF-8 per regular blob; no comments, duplicate keys, unknown fields or trailing commas. |
| Pipelines/deployments/steps | 16 pipelines, 32 deployments; 1–64 steps per pipeline, step names 1–120 trimmed characters, run strings up to 8192 characters. |
| Environment | 64 effective entries, identifier names, string values up to 8192 characters, no NUL; Docker forbids CR/LF. |
| Branch arrays | Nonempty string entries without CR/LF/NUL; each complete filter field at most 2048 joined characters. |
| Email | 20 plain addresses, at most 2048 joined characters. |
| Docker image | At most 256 valid image-name characters. |
| Artifact patterns | 32 patterns of 256 characters; relative forward-slash paths, no `.git`, traversal, absolute paths, colon, backslash or NUL. |
| Artifact archive | Defaults: 16 MiB compressed / 20 MiB uncompressed / 1000 files. Configurable through `execution.limits`; glob budget scales with file count. |
| Deployment script content | 64 KiB UTF-8, no NUL. |
| Deployment path/interpreter | At most 4096 characters; path absolute and outside repo; interpreter one line with no CR/LF/NUL. |
| Deployment branch/timeout | One valid branch of up to 255 characters; timeout 1–86400 seconds. |
| Stored combined logs | Default 1 MiB; configurable `execution.limits.log_mb`. Output continues to drain after truncation. |

### Troubleshooting

| Symptom | Check |
| --- | --- |
| No runs appear | Commit `ci/config.json`; enable the effective trigger and inspect case-sensitive branch arrays. In **CI → Run pipeline**, choose the branch and select **Check configuration** for its exact commit/status, or run `python -m pygithost ci validate --rev HEAD`. Manual also needs an existing branch/write access. A missing file creates no run; an invalid file fails configuration. |
| Manual run says the branch changed | The validated configuration SHA no longer matches the branch tip. Select **Check configuration** again, review the new commit, then queue from that result. |
| A branch array fails | Use `["main"]`, not a scalar/newline-separated string. `[]` matches all; disable trigger to stop it. |
| Another object's setting has no effect | Expected: configurations are independent. Put values explicitly on the affected pipeline/deployment. |
| Step loses cd/export | Fresh shell per step; combine dependent operations. |
| Docker cannot install/build | Prebuild dependencies/tools in the image; containers have no network by default. Remote image downloads use the worker host and its `image_pull` policy. |
| Another pipeline passed but merge is blocked | Each applicable pipeline needs its own exact-commit PR check, not a push/manual run. |
| Deployment did not run | Check administrator trust authorization, push/merged event, enabled block, exact branch tip, changed settings and prior attempt. |
| Host configuration fails closed | An administrator can add the exact `owner/repo` under **Trusted CI repositories**. Wildcards and malformed names are rejected. The parseable document keeps its declared policies but the queued run fails at configuration. |
| Malformed `ci/config.json` | Merges require CI and all direct branches are protected until the file is repaired through Git or the server filesystem. Fix and validate the JSON, then commit it; there is no saved-definition fallback. |
| Rerun uses old settings | Expected: original Git configuration and SHAs. Page-managed values are resolved again at execution and are withheld from unmerged PR reruns. Queue a new run for new committed configuration. |
| Artifacts disappeared | Check the default branch's retention and administrator limits. Raising limits does not restore deleted data. |
| JSON rejected | Correct the committed `ci/config.json`; validation happens when the server reads that commit. Unsupported proposed features are not silently accepted. |

See [Runs, queues and recovery](../README.md#runs-queues-and-recovery) for scheduler
limits, shutdown, process-tree/container cleanup and the single-server boundary.
