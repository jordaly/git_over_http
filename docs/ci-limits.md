# CI source, logs, artifacts and transfer limits

Each run has explicit positive limits. Omission uses the defaults below; `0`,
negative values, booleans, strings and fractions are rejected. There is **no
hard-coded upper size ceiling** on configured values. Limits are recorded in the
queued configuration snapshot, so changing settings does not change an existing
run.

MB-suffixed settings use **MiB** (`1024 × 1024` bytes).

## Configuration

Fields belong inside a pipeline's `execution`, alongside `runner`, `image` and
`docker`:

```json
{
  "version": 1,
  "pipelines": [
    {
      "name": "large-tests",
      "execution": {
        "runner": "remote-docker",
        "image": "my-project-ci:1",
        "timeout_seconds": 1800,
        "source_limit_mb": 500,
        "limits": {
          "log_mb": 8,
          "artifact_mb": 128,
          "artifact_uncompressed_mb": 512,
          "artifact_files": 5000,
          "source_timeout_seconds": 300,
          "transfer_timeout_seconds": 180
        }
      },
      "triggers": {"manual": {"enabled": true}},
      "steps": [{"name": "Tests", "run": "python -m unittest discover -v"}],
      "artifacts": {"paths": ["reports/**/*"], "when": "always"}
    }
  ]
}
```

Prepare the image first; adapt the command and generate the report files.
Keep existing unrelated pipeline/deployment settings rather than blindly replacing
the whole document. Container resource/security permissions are separate:
see [Docker profiles](docker-profiles.md).

## Defaults and enforcement

| Setting | Default | Enforcement |
|---|---|---|
| `source_limit_mb` | **100 MiB** | Compressed Git bundle, including required histories; checked by GitHost before reading/enqueueing, at source delivery, and by the worker after decoding. No old 32 MiB ceiling. |
| `limits.log_mb` | **1 MiB** | Combined CI output collection cap. Output continues to drain after truncation; raising it also raises permitted progress uploads. |
| `limits.artifact_mb` | **16 MiB** | Maximum compressed ZIP collected, uploaded, stored from the worker and downloaded through the CI artifact API for new runs. |
| `limits.artifact_uncompressed_mb` | **20 MiB** | Total collected file bytes and declared uncompressed archive budget. |
| `limits.artifact_files` | **1000** | Artifact file count; glob traversal budget scales to at least ten times this count, with a 10,000-entry minimum. |
| `limits.source_timeout_seconds` | **60 s** | Total GitHost source-bundle preparation budget and the worker's bundle-clone timeout. |
| `limits.transfer_timeout_seconds` | **60 s** | Worker source/log/completion HTTP operations, server upload processing and CI artifact download transfer timeout. Socket timeouts are not guaranteed total wall-clock deadlines. |
| `timeout_seconds` | **1800 s** | Existing execution budget for checkout, merge and steps. The worker's administrator-owned timeout ceiling still applies. |

`source_limit_mb` and source preparation are remote-runner features. Log and
artifact collection settings also apply to local CI execution. Deployment log
limits remain separate and are not changed by these CI fields.

The worker sends heartbeats while downloading/preparing source and uploading
results, so a busy transfer does not by itself expire the lease. Server
cancellation and connection-loss handling still apply. Cancellation stops awaiting
a transfer; an underlying blocking socket/Git operation may take until its timeout
to return.

## No hidden fixed transfer ceiling

Source HTTP response bounds include base64 expansion and the JSON envelope,
derived from the requested source limit. The old worker response cap does not
prevent downloading a larger authorized bundle.

Runner progress/completion body budgets scale with the stored log/artifact
limits, including worst-case JSON escaping and base64 overhead. The client supplies
`X-Runner-Run-ID` so GitHost can resolve those budgets from a token-owned assignment
**before reading the body**. Limits are never taken from arbitrary request JSON.
Attempt validation, repository restrictions and duplicate-completion protection
remain required.

The CI artifact API honors the run's stored compressed-artifact limit. Legacy runs
without a `limits` snapshot retain the historical 32 MiB API download ceiling.
Unrelated repository source ZIP, browsing, editing and diff API limits are not
changed by a CI pipeline setting.

## Capacity warning

These are **limits, not preallocated capacity**. Raising them does not add RAM,
disk, bandwidth or CPU. Git bundles, base64 JSON, uploaded artifacts and logs are
still buffered/stored in memory and SQLite; peak memory can be several times the
payload size. Use conservative measured values on both GitHost and the worker.
Very large jobs may require a future streamed/object-storage transport rather
than simply increasing the values. OS/filesystem, database and proxy limits still
apply even though the configuration schema has no fixed upper size ceiling.

Shared infrastructure/security rules remain administrator-controlled: one job per
worker token, scheduler concurrency, API rate/download permits, step-count and
configuration-document bounds, heartbeat/lease rules, image provisioning and
Docker policy permissions. A pipeline cannot request arbitrary host paths,
privileged containers, Docker socket access or automatic replay of uncertain work.

## Verification

Run:

```bash
python -m unittest tests.test_ci_limits tests.test_remote_ci tests.test_api_ci -q
```

Coverage includes defaults, invalid values, large configured values, named-pipeline
snapshot round trips, exact/over-limit bundles, receiving source beyond the old
32/46 MiB caps, source delivery rechecks, log truncation, artifact count and size
boundaries, token-owned upload bounds, artifact API limits and cancellation during
transfer. Changing a limit is not proof the real application passes: run a smoke
pipeline and inspect its logs/artifact downloads on the target worker.
