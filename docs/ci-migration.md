# Migrating to independent named lists

[Quick start](pipelines.md) · [Every option](ci-options.md) · [Complete example](examples/ci/all-options.json)

Open **CI → Settings** to see existing configuration converted for editing. The
expanded format has two arrays: `pipelines` and `deployments`. Every object explicitly
defines its `name`. Pipelines do not inherit from one another; omitted execution
settings use built-in defaults. The compact default reference is
`{"version":1,"file":".ci-config.json"}`. Existing saved configurations take priority
over automatic discovery and are not silently replaced by that reference.

## Current shape

Execution and cancellation are configured inside each pipeline. The removed
**CI execution defaults** settings form has no replacement outside the pipeline
JSON. Previously saved page execution overrides are ignored; copy any values you
still need into each applicable pipeline. Omit options to use built-in defaults,
not `null` or a shared execution-defaults object. Variables and retention remain
separate page controls with server/repository inheritance.

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
  "policies": {"require_ci": false}
}
```

The example keeps deployment disabled. Prepare the Docker image and install trusted
deployment scripts before enabling it. Inspect retention in the page controls;
applying lower limits can permanently delete data. Manual CI is always available
for runnable pipelines with write access; a legacy manual flag set to false no
longer disables it.

## Old field → new location

| Previous structure | Current structure |
| --- | --- |
| `pipelines: {"checks": {...}}` | `pipelines: [{"name":"checks", ...}]`. |
| `defaults.execution`, `defaults.triggers`, `defaults.cancellation`, `defaults.artifacts` | Values are copied explicitly into each pipeline using them. The defaults object is removed. |
| Root `notifications` | Copied explicitly into each pipeline/legacy deployment that used it, then removed from the root. |
| Pipeline-local `deployment` | Separate object in `deployments`, with its own name and `pipeline` reference. Legacy migration uses the pipeline's old ID as the target name to preserve deduplication. |
| Flat runner/image/timeout | Same pipeline's `execution` group; omitted fields use built-in defaults. |
| JSON `env` / `execution.env` | **Environment variables** page table, optionally scoped to a pipeline. Existing values are preserved; the editor hides them. |
| Flat event flags and branch arrays | Same pipeline's `triggers.push` and `triggers.pull_request` groups. PR flags become an explicit event array; manual runs are always available. |
| Flat cancel_superseded | Same pipeline's `cancellation.superseded`. |
| Flat email mode/recipients | Same object's `notifications.email.mode` and `recipients`. |
| Old settings protection fields | Root `policies`. |
| Old settings artifact/run retention / JSON `retention` | **Runs and artifacts** page controls. Existing values remain repository overrides until you choose **Use server default**. |
| Single command | A step named `Run`; no new single-command editor. |
| Git-backed source | Same pipeline's `file`, mutually exclusive with inline steps. |

Values previously inherited are resolved before migration, including partial PR-event
overrides and environment variables. The resulting objects are independent: changing
one never changes another. Existing IDs, scripts and disabled deployment states are
preserved; historical run snapshots are not rewritten.

## What remains repository-wide

`policies` in JSON controls repository merge/direct-push protection. Page-managed
retention controls repository storage across pipeline histories, with optional
server-default inheritance. Saving pipeline JSON preserves existing variables and
retention values; saving the variables form makes its rows authoritative. There is no per-pipeline
artifact-age setting or deployment-history pruning option.

## Deployment semantics

A deployment references one pipeline by name. Multiple deployments can reference
the same pipeline; each has its own branch, script, timeout, notifications, logs and
result. They run sequentially after a qualifying successful update. Deployment code
still runs on the host even if the pipeline tests use Docker. Manual CI never deploys.

This structure does not add approvals, manual deployment, retries, per-step conditions
or timeouts, working directories, custom script args, or cross-pipeline dependencies.
Unsupported fields fail validation rather than being silently ignored.

## Safe checklist

1. Back up configuration and the database. The displayed JSON no longer includes
   page-managed environment variables and retention, so copying it alone is not a full backup.
2. Check explicit names, expanded values, deployment pipeline references and disabled states.
3. Preserve policies when changing the JSON document. Review variables and retention
   in their separate forms; selecting **Use server default** changes inheritance,
   whereas a retention value of `0` explicitly disables that limit.
4. Save and queue a **new** manual run to test changed CI configuration. Rerun uses
   the old snapshot. Manual runs cannot deploy.
5. Test deployment separately with a harmless trusted script and a real branch update.
6. Inspect each named deployment's result. An old attempt is not retried by rerunning
   CI; there is no automatic rollback. See [Deployment](automatic-deployment.md).
