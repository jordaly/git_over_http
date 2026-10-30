# Automatic deployment

[JSON reference](ci-options.md#every-deployment-option) · [Multiple-target example](pipeline-examples.md#one-pipeline-separate-named-targets)

Each target is a named object in top-level `deployments` in **CI → Settings →
Configuration JSON**. `pipeline` references an independently configured pipeline.
There are no shared defaults or inherited deployment notification settings.

## Safe first run

Create a trusted script outside repositories, for example `/opt/deploy/check.sh`:

```sh
#!/bin/sh
set -eu
printf 'Would deploy commit %s from pipeline %s\n' "$1" "$PYGITHOST_PIPELINE"
```

Make it executable and readable by the server's unprivileged OS account. Then save
this complete example, adapting the test command for your project:

```json
{
  "version": 1,
  "pipelines": [
    {
      "name": "release",
      "triggers": {"push": {"enabled": true, "branches": ["main"]}, "manual": {"enabled": true}},
      "steps": [
        {"name": "Tests", "run": "python -m unittest discover -v"}
      ]
    }
  ],
  "deployments": [{"name": "test-target", "pipeline": "release", "branch": "main", "script": "/opt/deploy/check.sh"}]
}
```

Queue `release` manually to verify tests first. **Manual runs never deploy.** Push
an actual update to `main` after saving to exercise deployment; inspect the run's
deployment section and **CI → Deployments**. Only replace the harmless script with
a real deployment tool after verifying the tested commit and target.

## Conditions and execution

- Only successful **push** and **PR merged** runs deploy. PR checks, manual runs,
  failed tests and unmatched branches do not. Enable the corresponding events.
- The tested commit must still be the selected branch tip immediately before
  deployment. Scripts must deploy that exact SHA, not fetch and deploy a later tip.
- Each deployment follows its own pipeline, not an aggregate of all pipelines.
  Put all required checks in that pipeline's steps if they must pass first.
- Scripts receive the tested SHA as argument 1 and `PYGITHOST_COMMIT`, plus
  `PYGITHOST_OWNER`, `PYGITHOST_REPO`, `PYGITHOST_BRANCH`, `PYGITHOST_PIPELINE`
  and the target's `PYGITHOST_DEPLOYMENT` name.
- They run in a fresh temporary directory on the Git server, **outside Docker**,
  as the server user, with network access. They must fetch/retrieve the desired
  build themselves; the CI checkout and artifacts are not automatically passed.
- One repository runner slot covers CI and deployment. Runs and deployments in
  that repository cannot overlap. Different repositories can proceed concurrently.
- A deployment object enables its target by default. Set `enabled` to false or remove
  the target to stop future deployments, including pending snapshots. Changing deployment
  settings also prevents old queued configurations from deploying.
- Only one attempt per repository/deployment/commit is recorded, even if it fails.
  There is no automatic retry or rollback. Existing history remains under its
  original identity. Multiple targets linked to one run retain separate results and logs.

## Scripts and interpreters

Use `script` for an absolute host path. Alternatively, put UTF-8 text in
`script_content` and use `run_with`, for example:

```json
{
  "name": "production",
  "pipeline": "release",
  "branch": "main",
  "run_with": "python",
  "script_content": "import sys\nprint('Would deploy', sys.argv[1])\n",
  "timeout_seconds": 600
}
```

This is a **deployment object** to insert into the top-level deployments array, not a
complete configuration. Do not supply both `script` and `script_content`.
`python` uses the server's interpreter and virtual environment; dependencies must
be installed there, not only in the CI image. Other interpreters such as `node`,
`bash -e` or `pwsh -NoProfile -File` must exist on the host. No shell expansion,
pipes or command chaining is performed for `run_with`. Quote paths containing
spaces; use forward slashes for Windows executable paths.

Direct execution on POSIX requires a shebang. Inline content is limited to 64 KiB,
stored in SQLite, written to a private temporary file only during deployment, and
removed afterward. Timeout defaults to 600 seconds, maximum 86400.

## SSH to Ubuntu

Provision a dedicated restricted deployment identity and pin the target's host
key in a protected known-hosts file. A trusted host script can invoke your remote
release tool with the tested hexadecimal SHA:

```sh
#!/bin/sh
set -eu
commit="$1"
case "$commit" in ''|*[!0-9a-fA-F]*) exit 1 ;; esac
exec ssh -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/etc/pygithost/deploy_known_hosts \
  -i /etc/pygithost/deploy_key deploy@app.example.com \
  /opt/my-app/release "$commit"
```

The target-side `/opt/my-app/release` is your own deployment tool; provision and
authorize it separately. Do not disable host-key checking or put private keys in
JSON. The script must explicitly reference credential files because deployment
does not inherit arbitrary server environment variables.

## Security, results and recovery

Host scripts are trusted code with the server user's filesystem/network access.
Protect scripts and credentials from CI job writes. Owner-only permissions do not
isolate processes running as that same user. JSON, script snapshots and logs are
not secret-redacted. Use a dedicated unprivileged account and restrict backups.

Deployment status and bounded logs are separate from test results; a deployment
failure does not turn successful tests into failing tests. History survives CI
run pruning. Configure `notifications.email.mode` and `notifications.email.recipients`
on each target for deployment notifications; pipeline email settings are not inherited.
SMTP lives under **Admin: Email**.

After timeout, cancellation, crash or restart, inspect the real target state before
taking further action: subprocess termination cannot undo a partial deployment.
Unfinished attempts become interrupted rather than replayed. Use a supervisor
that terminates the service's complete process tree/cgroup; Docker containers
can need separate crash cleanup. There are no environment approvals, secret
manager, remote runner protocol or built-in rollback.
