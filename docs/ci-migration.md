# Migrating to independent named lists

[Quick start](pipelines.md) · [Every option](ci-options.md) · [Complete example](examples/ci/all-options.json)

Open **CI → Settings** to see existing configuration converted for editing. The
current format has two arrays: `pipelines` and `deployments`. Every object explicitly
defines its `name`. There is no shared-default or inherited pipeline configuration.

## Current shape

```json
{
  "version": 1,
  "pipelines": [
    {
      "name": "checks",
      "execution": {"runner": "host", "timeout_seconds": 600},
      "triggers": {"push": {"enabled": true, "branches": ["main"]}, "manual": {"enabled": true}},
      "steps": [{"name": "Tests", "run": "python -m unittest discover -v"}]
    }
  ],
  "deployments": [
    {"name": "production", "pipeline": "checks", "enabled": false, "branch": "main", "script": "/opt/deploy/production.sh"}
  ],
  "policies": {"require_ci": false},
  "retention": {"artifacts": {"days": 7}, "runs": {"max_count": 100}}
}
```

The example keeps deployment disabled. Install trusted scripts and inspect existing
retention before enabling/saving; applying lower limits can permanently delete data.

## Old field → new location

| Previous structure | Current structure |
| --- | --- |
| `pipelines: {"checks": {...}}` | `pipelines: [{"name":"checks", ...}]`. |
| `defaults.execution`, `defaults.triggers`, `defaults.cancellation`, `defaults.artifacts` | Values are copied explicitly into each pipeline using them. The defaults object is removed. |
| Root `notifications` | Copied explicitly into each pipeline/legacy deployment that used it, then removed from the root. |
| Pipeline-local `deployment` | Separate object in `deployments`, with its own name and `pipeline` reference. Legacy migration uses the pipeline's old ID as the target name to preserve deduplication. |
| Flat runner/image/timeout/env | Same pipeline's `execution` group. |
| Flat event flags and branch arrays | Same pipeline's `triggers.push`, `triggers.pull_request`, `triggers.manual` groups. PR flags become an explicit event array. |
| Flat cancel_superseded | Same pipeline's `cancellation.superseded`. |
| Flat email mode/recipients | Same object's `notifications.email.mode` and `recipients`. |
| Old settings protection fields | Root `policies`. |
| Old settings artifact/run retention | Root `retention.artifacts` and `retention.runs`. |
| Single command | A step named `Run`; no new single-command editor. |
| Git-backed source | Same pipeline's `file`, mutually exclusive with inline steps. |

Values previously inherited are resolved before migration, including partial PR-event
overrides and environment variables. The resulting objects are independent: changing
one never changes another. Existing IDs, scripts and disabled deployment states are
preserved; historical run snapshots are not rewritten.

## What remains repository-wide

`policies` controls repository merge/direct-push protection. `retention` controls
repository storage. These are not shared execution defaults. They remain root-level
administrator controls and apply across pipeline histories. There is no per-pipeline
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

1. Save a copy of the currently displayed JSON.
2. Check explicit names, expanded values, deployment pipeline references and disabled states.
3. Preserve policies and retention limits when changing the document. Saving replaces
   everything; omission restores built-in defaults rather than retaining old values.
4. Save and queue a **new** manual run to test changed CI configuration. Rerun uses
   the old snapshot. Manual runs cannot deploy.
5. Test deployment separately with a harmless trusted script and a real branch update.
6. Inspect each named deployment's result. An old attempt is not retried by rerunning
   CI; there is no automatic rollback. See [Deployment](automatic-deployment.md).
