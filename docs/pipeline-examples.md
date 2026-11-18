# Configuration recipes

[Every option](ci-options.md) · [Quick start](pipelines.md) · [Migration](ci-migration.md)

Every example is a repository file. Commit it as **`ci/config.json`** (or as a
referenced file under `ci/`) and push the commit; do not paste it into a page. The
project settings page manages environment variables and secrets only. All examples
are displayed directly inside **CI → Documentation**.

Retain unrelated pipelines, deployment targets, policies and retention when
combining examples. Validate before committing with
`python -m pygithost ci validate` (or `--rev HEAD` for the committed version); it
checks referenced files without executing them. Environment values belong on the
project page, not in Git. Enabled deployments additionally require
administrator authorization in `PYGITHOST_CI_TRUSTED_REPOSITORIES` using exact
`owner/repo` names; wildcards and malformed entries are rejected.

A malformed committed file fails closed: merges require CI and all direct branches
are protected until an operator repairs `ci/config.json` through Git or the server
filesystem. There is no saved-definition fallback.

## Minimal pipeline

Commit the [repository pipeline example](examples/ci/repository-pipeline.json) as
`ci/config.json`:

```json
{
  "version": 1,
  "steps": [
    {"name": "Python version", "run": "python --version"},
    {"name": "Tests", "run": "python -m unittest discover -v"}
  ],
  "artifacts": {"paths": ["reports/**/*.xml"], "when": "failure"},
  "timeout_seconds": 300
}
```

The simple form creates one pipeline named `ci`, uses Docker
`python:3.14-slim`, enables push and PR opened/updated/reopened events on all
branches, and always allows manual runs. Prepare the image first. Set environment
values in **CI → Settings**; administrator retention defaults are under
**Admin → Settings → Runs and artifacts**. Manual runs never deploy.

The obsolete Settings-only reference `{"version":1,"file":"ci/config.json"}` is not
valid as the root of `ci/config.json`.

## Full document

For custom execution, named pipelines, deployments, protections or project
retention, commit a grouped document. The [all-options example](examples/ci/all-options.json)
combines checks and release pipelines, disabled staging/production deployments,
cancellation, artifacts, notifications, policies and retention. Review and adapt it
before enabling anything.

The [inline deployment example](examples/ci/inline-deployment.json) uses
`script_content` with `run_with` instead of an external host script. It still runs
on the host, not in the CI container, and still requires administrator trust.

## Multiple Git-managed pipelines

Only `ci/config.json` is the entry point. For separate pipeline files, commit
`ci/tests.json` and `ci/build.json`, each using the simple pipeline shape, and
commit a full document like the
[Git-managed example](examples/ci/git-managed.json) as `ci/config.json`:

```json
{
  "version": 1,
  "pipelines": [
    {
      "name": "tests",
      "file": "ci/tests.json",
      "execution": {"runner": "docker", "image": "python:3.14-slim", "timeout_seconds": 600},
      "triggers": {"push": {"enabled": true, "branches": ["main"]}}
    },
    {
      "name": "build",
      "file": "ci/build.json",
      "execution": {"runner": "docker", "image": "python:3.14-slim", "timeout_seconds": 600},
      "triggers": {"push": {"enabled": true, "branches": ["main"]}}
    }
  ],
  "deployments": []
}
```

Replace each referenced file's steps with the appropriate tests or build commands
and prepare the Docker image first. References must be regular JSON files strictly
inside `ci/`; root filenames, traversal, absolute paths and symlinks are rejected.
A referenced file cannot itself contain deployments, policies or retention. File
references and step commands are checkout-root-relative, even when the JSON lives
in a nested directory. Do not reference `ci/config.json` recursively.

The entry document is the only project configuration source. It runs these two
named pipelines; there is no additional implicit `ci/config.json` job or saved
database definition.

## Two independent PR checks

```json
{
  "version": 1,
  "pipelines": [
    {
      "name": "tests",
      "execution": {"runner": "docker", "image": "python:3.14-slim", "timeout_seconds": 600},
      "cancellation": {"superseded": true},
      "triggers": {"pull_request": {"enabled": true, "branches": ["main"]}},
      "steps": [{"name": "Tests", "run": "python -m unittest discover -v"}]
    },
    {
      "name": "compile",
      "execution": {"runner": "docker", "image": "python:3.14-slim", "timeout_seconds": 120},
      "cancellation": {"superseded": false},
      "triggers": {"pull_request": {"enabled": true, "branches": ["main"]}},
      "steps": [{"name": "Compile", "run": "python -m compileall -q ."}]
    }
  ],
  "deployments": [],
  "policies": {"require_ci": true}
}
```

Set non-secret `PYTHONUNBUFFERED=1` in each pipeline's committed `env` rather than
on the project variables page if these checks must receive it: unmerged PR checks
never receive page-managed values, including server-wide values. These commands
need the prepared Python Docker image. Each pipeline specifies its own
configuration. Both PR checks must pass for the exact current PR base/head;
manual/push success is not a substitute. Omitted PR events default to opened,
updated and reopened. PR checks read the target/base commit's `ci/config.json`.

## One pipeline, separate named targets

```json
{
  "version": 1,
  "pipelines": [
    {
      "name": "checks",
      "execution": {"runner": "docker", "image": "python:3.14-slim", "timeout_seconds": 600},
      "triggers": {"push": {"enabled": true, "branches": ["main", "develop"]}},
      "steps": [
        {"name": "Tests", "run": "python -m unittest discover -v"},
        {"name": "Compile", "run": "python -m compileall -q ."}
      ],
      "artifacts": {"paths": ["reports/**/*.xml"], "when": "always"},
      "notifications": {"email": {"mode": "off", "recipients": []}}
    }
  ],
  "deployments": [
    {"name": "staging", "pipeline": "checks", "enabled": false, "branch": "develop", "script": "/opt/deploy/staging.sh", "timeout_seconds": 600},
    {"name": "production", "pipeline": "checks", "enabled": false, "branch": "main", "script": "/opt/deploy/production.sh", "timeout_seconds": 900, "notifications": {"email": {"mode": "off", "recipients": ["ops@example.com"]}}}
  ],
  "retention": {"artifacts": {"days": 30, "max_count": 50}, "runs": {"max_count": 100}}
}
```

Both targets are disabled in the example. Install trusted executable deployment
scripts outside repositories, add the exact `owner/repo` to
`PYGITHOST_CI_TRUSTED_REPOSITORIES`, and only then enable a reviewed target.
Deployments run on the host, not in the CI container. Each target matches its own
exact branch and has independent logs/result/email state. Several targets may use
the same branch if the same tested update must deploy to several hosts. They
execute sequentially; one target failure does not change passing tests or overwrite
another target's result.

Deployment email is configured on the deployment, not inherited from CI. SMTP must
be configured under **Admin: Email**. Repository page variables scoped to
**Deployments only** are resolved for deployment execution; ordinary and protected
CI values are not sent to deployments. Manual runs never deploy; push a real branch
update to exercise deployment. No approvals, manual deployment, automatic retry or
rollback exist.

Retention here comes from the default branch's configuration, not a queued run
snapshot. Feature branches and reruns cannot change it, and a nonzero administrator
limit caps the project value. Lower limits can delete existing artifacts or runs at
the next cleanup. See [Retention](ci-retention.md) for refresh and cleanup timing.

Build/publish the image with dependencies included: Docker jobs have no network
by default. Remote workers download missing registry images according to worker
policy; local Docker jobs need the image preinstalled.

## Complete option examples

- [All options](examples/ci/all-options.json): independent checks/release pipelines,
  separate staging/production targets, artifacts, policies and retention.
- [Inline Python deployment](examples/ci/inline-deployment.json): script_content with
  run_with rather than an external host path.
- [Git-backed pipeline](examples/ci/git-managed.json) and its separate
  [repository file](examples/ci/repository-pipeline.json).

Artifact example: put `"artifacts":{"paths":["dist/*","reports/**/*.xml"],"when":"success"}`
inside the pipeline that produces those files. Notifications example: put
`"notifications":{"email":{"mode":"failures","recipients":["ci@example.com"]}}`
inside the pipeline or deployment that should send them. Email policies are not
inherited; omitted execution options use built-in defaults.
