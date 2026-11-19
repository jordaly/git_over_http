# Migrating repository CI to `ci/config.json`

[Quick start](pipelines.md) · [Every option](ci-options.md) · [Complete example](examples/ci/all-options.json)

Project CI definitions are now repository-owned. The server reads
**`ci/config.json`** from the recorded commit and does not read saved database
definitions. Migration is therefore required for projects that configured CI only
through the old settings editor or stored files at the repository root. There is no
automatic import, no fallback to saved commands, no automatic deployment expansion
and no replay of historical definitions.

## Before upgrading

1. **Back up the database and server configuration.** CI history and environment
   values live in SQLite; project pipeline definitions do not move automatically.
2. **Capture the old configuration JSON.** While the old **CI → Settings** page is
   still available, copy the complete displayed JSON. After upgrading, the page has
   no JSON editor and the API has no replacement operation, so a database-only
   document is not recoverable through the application.
3. **Keep secrets on the project page.** Confirm the required values are present
   in **CI → Settings**. Do not copy them into the migration JSON or Git.
4. **Note project retention values.** The old page retention form is removed. Move
   desired project limits into the full grouped document, or deliberately use the
   administrator defaults under **Admin → Settings → Runs and artifacts**.
5. **Review host and deployment use.** Host jobs and enabled deployments require an
   explicit server trust entry. Add the exact `owner/repo` before expecting either
   to run.

## Build the committed document

Create `ci/config.json` with either a simple single pipeline or a full grouped
document. A full grouped document is required to keep multiple pipelines,
deployments, policies or project retention:

```json
{
  "version": 1,
  "pipelines": [
    {
      "name": "checks",
      "execution": {"runner": "docker", "image": "python:3.14-slim", "timeout_seconds": 600},
      "triggers": {"push": {"enabled": true, "branches": ["main"]}},
      "steps": [{"name": "Tests", "run": "python -m unittest discover -v"}]
    }
  ],
  "deployments": [
    {"name": "production", "pipeline": "checks", "enabled": false, "branch": "main", "script": "/opt/deploy/production.sh"}
  ],
  "policies": {"require_ci": false, "block_direct_pushes": false, "protected_branches": ["main"]}
}
```

Every named pipeline and deployment must retain a stable name. Names identify run
history and deployment attempts. If the old document used a single pipeline or
inline deployment, turn it into these two arrays rather than keeping page-only
references. Keep deployments disabled until scripts, trust authorization and the
real target have been reviewed.

A project with no deployments, policies or retention may use the simpler form:

```json
{
  "version": 1,
  "steps": [{"name": "Tests", "run": "python -m unittest discover -v"}]
}
```

The simple form creates a pipeline named `ci` with built-in Docker execution,
push/PR events and manual runs. It cannot contain deployments, protections or
project retention.

## Move root files into ci

Only `ci/config.json` is the entry point. A full document may reference additional
pipeline files, but every reference must be strictly inside `ci/`:

```sh
mkdir -p ci
git mv .ci-config.json ci/config.json   # or: git mv .pygithost-ci.json ci/config.json
git mv checks.json ci/checks.json       # update the pipeline's file to ci/checks.json
git add ci
git commit -m "Move project CI configuration into ci"
```

If the old file was a full document, keep it as `ci/config.json`. If it was only a
steps file, it can remain a simple document or become one pipeline inside a full
document. References to old root filenames such as `.ci-config.json`,
`.pygithost-ci.json` or `checks.json` are no longer accepted. Root-level paths,
traversal, absolute paths, backslashes and symlinks are rejected. A pipeline cannot
reference `ci/config.json` recursively.

The historical `examples/ci/repository-reference.json` example was a Settings-only
`{"version":1,"file":"ci/config.json"}` reference. It is **not** valid as the root of
`ci/config.json`; commit a real pipeline or full document instead.

Validate the JSON **before** committing (for example with a JSON parser and the
documented field shapes). Server-side validation happens only when the file is
read. If a malformed file reaches the default branch, repository CI fails closed:
merges require CI and every direct branch is protected until an operator repairs
`ci/config.json` through Git or the server filesystem. There is no page editor, API
replacement or saved-definition fallback to repair it.

## Put secrets only on the project page

Enter repository environment variables in **CI → Settings**. Server defaults remain
under **Admin → Settings → Environment variables**. Repository values override
server values by name; pipeline-scoped rows override repository-wide rows. Page
values also override matching `env` entries in Git and are resolved when a job
executes, not copied into new stored run snapshots.

Choose a scope for each repository row: **Non-PR CI runs**, **Authorized protected
branch**, or **Deployments only**. Unmerged pull-request checks receive no
page-managed values, including server-wide values. Deployment-only values are not
sent to CI test jobs. Protected values require the exact `owner/repo:branch` in the
server process environment variable `PYGITHOST_CI_PROTECTED_SECRET_BRANCHES`, a
matching protection rule in the current default branch configuration, and an
execution commit equal to the current branch tip.

Never commit a token, password, private key or other secret. Git history is copied,
shared and not redacted. Settings storage, remote job assignments and logs are
plaintext, and logs are not redacted. Existing saved environment values may remain
available until you save the repository variables form, but old saved commands,
triggers, execution settings and deployments never become an alternative
configuration source. Re-enter and verify secrets deliberately instead of relying
on inherited database values. Historical snapshots that mixed page credentials into
Git variables are not replayed as page values.

## Configure trust before host jobs or deployments

Ordinary `docker` and `remote-docker` pipelines need no new trust entry and keep
their existing worker-policy boundaries. A repository that requests
`runner: "host"`, or that enables any deployment, cannot run that job unless its
exact `owner/repo` is granted under **Admin → Settings → Trusted CI repositories**:

```text
alice/project,ops/tools
```

Comma-separated or newline-separated values are accepted; the default is empty.
Existing process-environment grants remain active.
Use exact `owner/repo` names only. Wildcards, patterns, malformed entries and `..`
are rejected, and an invalid allowlist value is a configuration error rather than a
broad match. Match the namespace used in repository URLs. This is administrator
authorization, not an alternative pipeline setting, and repository writers cannot
add themselves.

Adding a deployment object or changing `runner` in Git does **not** expand trust.
The server checks authorization again at execution time, including reruns and
historical snapshots. If authorization is removed, host jobs and deployments stop
running; queued old definitions are not retried or migrated. A parseable document
denied by this guard keeps its declared branch policies, but its queued run fails
during configuration before commands execute.

## Retention and policies

Project retention belongs in the full grouped document:

```json
{
  "retention": {
    "artifacts": {"days": 30, "max_count": 50},
    "runs": {"max_count": 100}
  }
}
```

Retention follows **the default branch**, not a run snapshot. Feature branches and
reruns cannot change it, and a nonzero administrator limit caps the project value.
The next retention cleanup can permanently delete artifacts or runs under lower
limits. Omitted fields use administrator defaults. See [Retention](ci-retention.md)
for refresh and cleanup timing.

Policies (`require_ci`, `block_direct_pushes`, `protected_branches`) also move to
the full document root. Review policy changes as security-sensitive code. The
simple form cannot set them.

## Validate without replaying history

1. Validate the checkout **before** committing with
   `python -m pygithost ci validate`. It checks `ci/config.json`, every referenced
   pipeline file and the supported field shapes without executing or queueing
   anything. Use `--rev HEAD` to validate the committed version instead of
   uncommitted working-tree changes. A malformed default-branch file fails closed
   and may require administrator Git/filesystem repair.
2. Commit the migrated files and push.
3. In **CI → Run pipeline**, select the branch and **Check configuration**. Confirm the
   exact configuration commit SHA and a `valid` status, then queue a **new** manual
   run from that result. Manual runs never deploy, and a request is rejected if the
   branch moved after the check.
4. Exercise deployment only with a harmless reviewed script and a real qualifying
   branch update after trust is configured.
5. Inspect CI and deployment results separately.

Reruns use the original stored Git configuration snapshot—not the current
`ci/config.json`. Current administrator authorization and page-managed values still apply, and
unmerged pull-request reruns still receive no page values. A protected value is
released only if the original commit is still the branch tip. Reruns do not change
the repository's retention policy. Old deployment attempts are not
retried automatically. A server restart marks unfinished work interrupted rather
than replaying it. Verify the real target after any interruption.

## Behavior changes at a glance

| Previous behavior | Current behavior |
| --- | --- |
| JSON edited and saved on **CI → Settings** | Commit `ci/config.json`; the page has no JSON editor. |
| Saved database definitions were an alternative source | Database definitions are ignored for execution; migration is required. |
| `PUT /ci/settings` replaced configuration | Replacement is disabled; `GET` is read-only. |
| Project retention form applied immediately | Project retention comes from the full document on the default branch, within administrator limits. |
| Repository environment and retention shared the CI settings page | Environment values remain on the project page, scoped to ordinary non-PR CI, authorized protected branches, or deployments only; retention is server defaults plus optional default-branch project JSON. |
| Page variables were copied into every run snapshot | New snapshots exclude page credentials. Values are resolved live at execution, withheld from all unmerged PR checks, and may appear in remote assignments/logs. |
| Configuration was validated only when a run was queued | Run `python -m pygithost ci validate` or use **CI → Run pipeline → Check configuration** to read the exact commit and status without queueing. |
| Root file references were supported | Entry point is `ci/config.json`; referenced pipeline files must be under `ci/`. |
| Repository JSON could not grant host execution | Host jobs and enabled deployments require an administrator grant under **Trusted CI repositories**. |
| Historical definitions might load implicitly | No automatic migration, no implicit deployment and no historical retry. |
| Malformed configuration was only a failed run | It now fails closed: merges require CI and all direct branches are protected until an administrator repairs the file. |
