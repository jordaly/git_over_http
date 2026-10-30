# Configuration recipes

[Every option](ci-options.md) · [Quick start](pipelines.md)

Copy a complete example into **CI → Settings → Configuration JSON**. Saving replaces
the document; retain existing policies and retention limits when combining examples.
All examples are displayed directly inside **CI → Documentation**.

## Two independent checks

```json
{
  "version": 1,
  "pipelines": [
    {
      "name": "tests",
      "execution": {"runner": "host", "timeout_seconds": 600, "env": {"PYTHONUNBUFFERED": "1"}},
      "cancellation": {"superseded": true},
      "triggers": {"pull_request": {"enabled": true, "branches": ["main"]}, "manual": {"enabled": true}},
      "steps": [{"name": "Tests", "run": "python -m unittest discover -v"}]
    },
    {
      "name": "compile",
      "execution": {"runner": "host", "timeout_seconds": 120},
      "cancellation": {"superseded": false},
      "triggers": {"pull_request": {"enabled": true, "branches": ["main"]}, "manual": {"enabled": true}},
      "steps": [{"name": "Compile", "run": "python -m compileall -q ."}]
    }
  ],
  "deployments": [],
  "policies": {"require_ci": true}
}
```

Host code must be trusted. Each pipeline specifies its own configuration. Both PR
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
      "triggers": {"push": {"enabled": true, "branches": ["main", "develop"]}, "manual": {"enabled": true}},
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
  ],
  "retention": {"artifacts": {"days": 30, "max_count": 50}, "runs": {"max_count": 100}}
}
```

Pre-pull/build the image and include dependencies: Docker jobs have no network.
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
  separate staging/production targets, artifacts, policies and retention.
- [Inline Python deployment](examples/ci/inline-deployment.json): script_content with
  run_with rather than an external host path.
- [Git-backed pipeline](examples/ci/git-managed.json) and its separate
  [repository file](examples/ci/repository-pipeline.json).

Artifact example: put `"artifacts":{"paths":["dist/*","reports/**/*.xml"],"when":"success"}`
inside the pipeline that produces those files. Notifications example: put
`"notifications":{"email":{"mode":"failures","recipients":["ci@example.com"]}}`
inside the pipeline or deployment that should send them. No configuration is inherited.
