# Remote CI runners: proposed design

**Status: proposal, not implemented.** The current CI scheduler and its host and
Docker executors run on the Git server. This document describes how execution
could move to a separate Ubuntu machine while keeping configuration, job history,
logs, artifacts, and access controls on the Git server.

## Architecture

```text
Git server                         Ubuntu worker
----------                         -------------
Repositories                       Worker agent (systemd service)
CI configuration                   Git and Docker Engine
Queue and scheduler  <--- HTTPS --- Job checkouts and containers
Run history                        Temporary logs and artifacts
Logs and artifacts
```

The worker initiates all connections. It polls the server for jobs, downloads
source, executes jobs locally, and uploads results. The worker does not need an
inbound listening port, SSH access to the server, a shared filesystem, or direct
database access.

The server remains the authority for job configuration, authorization, scheduling,
cancellation, and final results. Workers execute only the assignments they receive.
Existing local execution remains available.

## Ubuntu worker requirements

Use a dedicated Ubuntu server or VM with:

- A supported Python version compatible with the eventual worker package. The
  minimum version must be established and tested during implementation.
- Git, Docker Engine, and trusted CA certificates.
- A dedicated unprivileged service account and persistent worker data directory.
- Enough CPU, RAM, and disk for the configured number of simultaneous jobs.
- Outbound HTTPS access to the Git server through a LAN, VPN, or public endpoint.
- Access to an image registry when an administrator installs or updates images.
- A server URL and a revocable worker-specific authentication token.

No application database or web server is required on the worker. Build tools and
dependencies should normally be installed in the job image, not on Ubuntu itself.

Docker daemon access is effectively root-level access on a typical installation.
The service account is therefore not a strong isolation boundary against a
compromised worker agent. Prefer a dedicated machine with no unrelated workloads
or production credentials.

### Images and container isolation

Initially, preserve the existing Docker executor policy:

- Images must already exist on the worker; jobs do not automatically pull them.
- Images must contain `/bin/sh` and all required tools and dependencies.
- Prefer immutable image digests for reproducibility.
- Containers have no network, a read-only root filesystem, dropped capabilities,
  no privilege escalation, and bounded CPU, memory, process count, and `/tmp`.
- Only the job checkout is mounted writable. Do not mount the Docker socket,
  worker configuration, server repositories, or authentication tokens.

The worker agent needs network access even though job containers do not. Git
checkout and PR merge preparation happen outside the job container. Container
restrictions reduce risk but do not make hostile code safe on a shared host.
Writable checkouts also need disk usage controls or monitoring.

## Communication and job lifecycle

All worker API requests use HTTPS with certificate verification and a worker
token. Internal certificate authorities are supported by installing their CA on
Ubuntu; disabling TLS verification is not an acceptable deployment shortcut.

1. **Connect:** the worker authenticates and reports its identity, supported
   protocol version, capabilities, and available capacity.
2. **Request work:** the worker polls or long-polls for an assignment. The server
   checks repository permissions, runner eligibility, and concurrency limits.
3. **Claim:** the server atomically leases a queued run to the worker and returns
   an assignment ID, lease identity, immutable job configuration, source details,
   timeout, and upload limits.
4. **Prepare:** the worker downloads job-scoped source and creates an independent
   checkout at the recorded commit. PR jobs merge the recorded head commit into
   the recorded base commit, preserving current CI semantics.
5. **Execute:** the worker runs sequential pipeline steps in Docker using the
   configuration snapshot and explicit job environment.
6. **Report:** the worker sends ordered log chunks, step updates, and regular
   heartbeats. Heartbeat responses can instruct it to cancel.
7. **Finish:** the worker uploads allowed artifacts and submits a final result.
   The server validates the assignment before accepting it, then updates history,
   merge checks, and notifications using the existing server-side rules.
8. **Clean up:** the worker removes containers and temporary job data, with a
   bounded cleanup timeout. Cleanup warnings do not replace the job result.

Use retry backoff and jitter when the server is unavailable. Repeated requests
must not accidentally create duplicate assignments or duplicate output.

### Proposed API responsibilities

Exact endpoint names and payloads are implementation details. The protocol needs
operations for:

| Operation | Purpose |
| --- | --- |
| Request assignment | Atomically claim an eligible queued job |
| Heartbeat | Renew a lease and receive cancellation instructions |
| Download source | Fetch only the assigned job's source |
| Append logs | Submit bounded, ordered output chunks |
| Update steps | Report execution progress |
| Upload artifacts | Store bounded, validated job outputs |
| Complete assignment | Submit an idempotent final result |

Every operation must verify worker identity and assignment ownership. Request
sizes, upload sizes, and request rates must be bounded. Protocol versioning allows
the server to reject incompatible workers with a useful diagnostic.

## Source access

Prefer a server-generated Git bundle containing the commits required by the job.
The worker receives short-lived, assignment-scoped access to that bundle rather
than a reusable repository credential. Bundles preserve the Git data needed for
checkout and PR merges without sharing the server's filesystem.

The server must verify requested commit identities and construct the source from
the recorded run, not from branch names that may have moved. Bundle access must
expire and must not expose unrelated repositories. Workers necessarily receive
the assigned source and any history included in the bundle, so register only
trusted machines and keep bundles limited to the required history.

Submodules and Git LFS require an explicit policy; do not silently give jobs
general credentials or enable network access to support them.

## Scheduling and runner pools

A pool is a named group of eligible workers. For example, `ubuntu` could contain
two general-purpose machines, while `gpu` contains one specialized machine. A
pool can contain just one worker.

Repository settings choose local execution or a remote pool. The server assigns
work to a connected eligible worker with free capacity. Labels may later narrow
selection by operating system, architecture, or specialized hardware. Pool and
label membership must be administrator-controlled, not trusted solely because a
worker claims a label.

Preserve existing global queue limits and the one-running-job-per-repository
rule. Define the global concurrency limit to cover local and remote assignments,
and also enforce each worker's own concurrency limit. Jobs without an eligible
worker remain visibly queued with a clear reason; they must not silently fall
back to execution on the Git server.

For the first version, one remote pool and one Ubuntu worker are enough.

## Leases, disconnects, and cancellation

A job assignment needs an expiring lease and a unique attempt identity. For
example, heartbeats might occur every 10 seconds with a 60-second lease; these
are illustrative values, not existing settings.

- A lost worker cannot leave a run permanently marked as running. On expiry,
  record an interrupted attempt with a worker-disconnected reason.
- Reject output and completion from expired or superseded attempts.
- A worker that cannot renew its lease stops execution before its last confirmed
  lease expires. Network loss must not allow indefinite offline execution.
- Make retry policy explicit. Initially, require a manual rerun rather than
  automatically repeating commands that may have external side effects.
- Cancellation is persisted on the server and delivered through heartbeats. The
  worker terminates its container and subprocesses, then acknowledges it.
- On startup, the worker reconciles its recorded assignments and removes stale
  containers and temporary data belonging to that worker only.

Leases cannot guarantee exactly-once external side effects. A disconnected job
may have performed an action before its interruption was recorded.

The current server interrupts running jobs during restart. Remote assignments
need separate recovery logic: persist leases and attempt identities, then allow
valid workers to reconnect within their lease window. Keep the current
single-server scheduler/database lock model; remote workers do not imply support
for multiple web servers sharing the SQLite database.

## Authentication and data security

- Administrators create, restrict, rotate, and revoke worker tokens.
- Store token hashes on the server and the worker's token in a protected file.
- Bind tokens to a worker and approved repositories or pools. They must not grant
  general user, repository administration, or unrelated CI access.
- Never pass worker tokens into job environments, source URLs visible to jobs,
  containers, artifacts, or logs.
- Revocation prevents new claims and further authorized API access. It cannot
  erase source already downloaded or guarantee a hostile worker stops running.
- Worker configuration and repository pipeline configuration remain separate.
  Repository code must not control Docker mounts, privileged mode, or the worker
  service configuration.

Current CI environment settings are plaintext configuration, not a secret store,
and output is not redacted. Remote execution does not change that. A future
secrets feature needs its own design and trust model.

Workers are trusted executors: a compromised worker can read assigned source and
forge execution results. Repository eligibility is therefore a security boundary,
not just a scheduling preference.

## Logs and artifacts

Keep the existing web UI and access controls on the server. Browsers do not
connect directly to workers.

- Sequence log chunks and acknowledge offsets so retries do not duplicate output.
- Apply server-side log limits while continuing to drain process output locally.
- Bound local buffering during outages; do not allow logs to fill the worker disk.
- Reuse artifact pattern semantics, but validate uploaded names, paths, counts,
  and total bytes on the server. Never trust worker-supplied filesystem paths.
- Reject path traversal, symlink escapes, and uploads for another assignment.
- Make artifact uploads retry-safe and define when a run is complete relative to
  its uploads. Incomplete uploads must not appear as valid downloadable files.

## Example Ubuntu deployment

The eventual installation procedure would be:

1. Install the supported Python runtime, Git, Docker Engine, and CA certificates.
2. Create a dedicated worker service account and data directory.
3. Install the worker package in a dedicated virtual environment.
4. Register the worker on the server and securely provision its token.
5. Pre-pull the approved Docker images on the worker.
6. Install and enable a systemd service.
7. Select the remote pool in repository CI settings and run a test pipeline.

Illustrative configuration—not an implemented file format:

```ini
server_url=https://git.example.com
runner_name=ubuntu-worker-1
token_file=/etc/pygithost-worker/token
concurrency=2
work_directory=/var/lib/pygithost-worker
```

The service should start after boot, restart on failure, and run as the worker
account. Use `KillMode=control-group` to stop agent subprocesses, but also explicitly
stop job containers: Docker daemon-managed containers are not automatically
terminated by stopping the service's process group.

Monitor available disk, Docker image storage, worker heartbeats, stuck cleanup,
and job failure rates. Provide administrator controls to disable new assignments
and drain a worker before maintenance. During shutdown, stop taking jobs and
either finish active assignments or explicitly interrupt them.

## Implementation scope

The main refactor is to separate execution from `CIManager` in
`pygithost/ci.py`. Reuse its pipeline, checkout, container, timeout, log, and
artifact behavior behind an executor interface rather than creating a second
implementation with different semantics.

Additional work includes worker and assignment database records, authenticated
HTTP endpoints, source bundle generation, a worker CLI/service, remote settings,
worker status UI, and lease-aware restart recovery. Keep final run updates,
notifications, and merge protection decisions on the server.

### First release

- One supported Ubuntu worker platform and Docker-only remote execution.
- One remote pool with repository-scoped worker authorization.
- Atomic claims, heartbeats, lease expiry, and cancellation.
- Exact-commit source transfer, pipeline steps, live logs, and artifacts.
- Manual retry after worker loss; no automatic retry of interrupted jobs.
- Existing local runners remain compatible.
- Documented installation, token rotation, cleanup, and upgrade procedures.

### Required validation

Test simultaneous claims, global and repository concurrency, token isolation,
revocation, source authorization, PR merges, timeouts, cancellation, duplicate log
chunks, malicious artifact paths, oversized uploads, worker crashes, server
restarts, lease expiry, stale completion, disk exhaustion, and failed cleanup.
Include an end-to-end test with a real Docker-enabled Ubuntu worker.

Named specialized pools, remote host-mode execution, automatic image pulls,
autoscaling, and multiple scheduler servers are outside the initial scope.
