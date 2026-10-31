# Configuration recipes

[Every option](ci-options.md) · [Quick start](pipelines.md)

Copy a Settings example into **CI → Settings → Configuration JSON**. Saving replaces
the pipeline/deployment document; retain existing policies when combining examples.
Variables and retention are separate page controls and are not reset by JSON saves.
All examples are displayed directly inside **CI → Documentation**.

## Default repository file

Unconfigured repositories discover `.ci-config.json` automatically. If you want to
save an explicit reference in Settings, use:

```json
{
  "version": 1,
  "file": ".ci-config.json"
}
```

Commit the separate [repository pipeline example](examples/ci/repository-pipeline.json)
as `.ci-config.json`; do not commit the reference above as the pipeline file.
Prepare the Docker image before running. Set variables under **Environment variables**
and storage limits under **Runs and artifacts**. See
[Server and repository settings](server-settings.md) for a worked inheritance example.
Manual runs are always available for runnable pipelines with write access.

The compact reference uses built-in execution settings. For custom execution,
copy the [expanded Git-managed example](examples/ci/git-managed.json): configure
`execution.runner`, `execution.image`, `execution.timeout_seconds` and
`cancellation.superseded` inside its named pipeline. Keep `file` alongside those
objects. There is no execution-defaults form in Admin or repository settings.
Omitting an option uses its built-in default; it does not inherit a saved page
override or another pipeline's value. The inline deployment example intentionally
omits execution and cancellation to demonstrate this behavior.

## Two independent checks

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

Set `PYTHONUNBUFFERED=1` in the page's variables table if wanted. These commands need
the prepared Python Docker image. Each pipeline specifies its own configuration. Both PR
checks must pass for the exact current PR base/head; manual/push success is not a
substitute. Omitted PR events default to opened, updated and reopened.

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
      "notifications": {"email": {"mode": "off", "recipients": []}}
    }
  ],
  "deployments": [
    {"name": "staging", "pipeline": "checks", "enabled": false, "branch": "develop", "script": "/opt/deploy/staging.sh", "timeout_seconds": 600},
    {"name": "production", "pipeline": "checks", "enabled": false, "branch": "main", "script": "/opt/deploy/production.sh", "timeout_seconds": 900, "notifications": {"email": {"mode": "off", "recipients": ["ops@example.com"]}}}
  ]
}
```

Pre-pull/build the image and include dependencies: Docker jobs have no network.
For 30-day artifacts, at most 50 bundles and 100 completed runs, enter those values
in **CI → Settings → Runs and artifacts**, acknowledge cleanup and save.
Install trusted executable deployment scripts outside repositories before enabling
targets. Deployments still run on the host, not in the CI container. Each target
matches its own exact branch and has independent logs/result/email state. Several
targets may use the same branch if the same tested update must deploy to several
hosts. They execute sequentially; one target failure does not change passing tests
or overwrite another target's result.

Deployment emails are configured on the deployment, not inherited from CI. SMTP
must be configured under **Admin: Email**. Manual runs never deploy; push a real
branch update to exercise deployment. No approvals, manual deployment or rollback exist.

## Complete option examples

- [All options](examples/ci/all-options.json): independent checks/release pipelines,
  separate staging/production targets, artifacts and policies.
- [Inline Python deployment](examples/ci/inline-deployment.json): script_content with
  run_with rather than an external host path.
- [Git-backed pipeline](examples/ci/git-managed.json) and its separate
  [repository file](examples/ci/repository-pipeline.json).

Artifact example: put `"artifacts":{"paths":["dist/*","reports/**/*.xml"],"when":"success"}`
inside the pipeline that produces those files. Notifications example: put
`"notifications":{"email":{"mode":"failures","recipients":["ci@example.com"]}}`
inside the pipeline or deployment that should send them. Email policies are not
inherited; omitted execution options use built-in defaults.
