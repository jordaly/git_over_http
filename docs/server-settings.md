# Server and repository settings

[CI reference](ci-options.md) · [Retention](ci-retention.md) · [Server setup](getting-started.md)

## Where settings live

| Page | Controls | When changes apply |
| --- | --- | --- |
| **Admin → Settings → Appearance** | Display name | Immediately. |
| **Admin → Settings → Basic server configuration** | Bind address/port, Git URLs/backend, repository/database/static paths, authentication, allowed IPs, cookies and request limits | Saved to the startup file; restart required. |
| **Admin → Settings → Environment variables** | Server-wide CI variables | Future runs; repository values can override names. |
| **Admin → Settings → Runs and artifacts** | Default artifact age/count and completed-run count | Existing stored data, immediately after acknowledgement. |
| **Repository → CI → Settings** | Monaco pipeline JSON plus separate variable and retention controls | Future CI snapshots, except retention which applies immediately. |
| **Admin → Email** | SMTP delivery | Future notifications; credentials are separate from CI variables. |

These pages require an administrator when authentication is enabled. With
authentication disabled, access is governed by the IP allowlist. CI actions still
require write access when authentication is enabled; manual runs never deploy.

## Worked inheritance example

1. Configure execution in each pipeline's JSON: `"execution":{"runner":"docker","image":"python:3.14-slim","timeout_seconds":600}` and optionally `"cancellation":{"superseded":true}`. Omitted options use built-in defaults; there is no execution-defaults settings form.
2. Add server variables `PYTHONUNBUFFERED=1` and `BUILD_MODE=development`; save variables.
3. Set artifact retention to `30` days, maximum bundles to `50`, and maximum completed
   runs to `100`. Acknowledge possible deletion, then save retention.
4. In a repository's **CI → Settings**, leave retention at **Use server default**.
5. Add a repository variable `BUILD_MODE=production` for **All pipelines**. Its CI
   inherits `PYTHONUNBUFFERED=1`, but uses `BUILD_MODE=production`.
6. To change a pipeline's timeout, set `execution.timeout_seconds` to `900` in that pipeline's JSON.
7. Omit that key to use the built-in timeout. Removing the repository
   `BUILD_MODE` row similarly restores the server variable value.

Execution and cancellation belong to each pipeline's JSON, with built-in defaults for omitted options. Previously saved settings-page execution overrides are no longer applied.
Variables can also be scoped to one named pipeline in the repository table. A blank
variable value is an actual empty string. Retention `0` means unlimited, not inherit.

Values are stored in plaintext and logs are not redacted. **Show values** changes
visual masking only. Do not treat these controls as an encrypted secrets manager.
Saving the repository variable table replaces its legacy JSON variables, including
when all rows are removed. See [Compatibility](ci-options.md#page-settings-and-inheritance).

## Pipeline JSON stays small

For omitted execution options, the built-ins are Docker, image `python:3.14-slim`,
a 1800-second timeout and superseded-run cancellation off. To customize a file-backed
pipeline, use the [expanded Git-managed example](examples/ci/git-managed.json):
its `execution` and `cancellation` objects belong inside the named pipeline,
alongside `file`. The committed `.ci-config.json` remains the separate steps file.

For the default file-backed pipeline, the Settings editor only needs:

```json
{
  "version": 1,
  "file": ".ci-config.json"
}
```

Commit the separate [pipeline file](examples/ci/repository-pipeline.json) as
`.ci-config.json`. Use the [expanded example](examples/ci/all-options.json) if you
need multiple named pipelines, deployment targets or protection policies.
Do not put environment variables or retention into new pipeline JSON examples.
Pipeline saves do not reset page-managed values or rewrite historical run snapshots.

## Basic server configuration and restart

The page edits the same startup file passed to `server.py run --config ...`.
It preserves unrelated keys and writes atomically. If the file changed since the
page was loaded, reload before saving to avoid overwriting another edit.
Programmatic instances without a startup file show basic controls read-only.

No listener, authentication, database or storage change is applied mid-request.
Restart your existing service using its normal startup command after reviewing the
saved values. Start with valid admin credentials before enabling authentication;
HTTPS-only cookies require HTTPS. Keep an allowed client IP to avoid lockout.
Changing a path does not move repositories or migrate the database. Back up/move
data deliberately before using new paths; a new database will not contain the old
accounts, CI preferences or history.

The startup JSON does not contain the database-backed CI preference tables. Back up
both the startup file and database when moving a server.
