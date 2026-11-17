# HTTP Docker runner

GitHost enables SQLite WAL during database initialization, not on every connection.
Runner schema creation and upgrades also run only at initialization. Runtime
connections retain `synchronous=NORMAL` and foreign-key enforcement. If SQLite
reports `SQLITE_BUSY` during connection setup, GitHost closes that connection and
retries setup at most twice (each connection has a five-second busy timeout,
with 50/100 ms backoff). No application statement or job command is replayed.
Other SQLite errors and sustained contention still fail explicitly.

Progress and artifact validation happen before acquiring the runner's write
transaction; assignment ownership and state are checked again under that lock.
SQLite warnings identify local connection/operation/thread IDs, active explicit
transactions and their ages, plus statements/transactions taking at least one
second. They do not include SQL text, parameters or credentials. This identifies
possible in-process blockers, not locks held by uninstrumented external processes.

If a database error escapes CI coordination, an active run is marked `interrupted`
with an explicitly uncertain outcome; retained logs, step evidence and phase are
preserved. Coordinator errors cannot overwrite a terminal result. These errors do
not prove that application tests failed, and uncertain executions are not replayed
automatically. Inspect server logs before authorizing another run.

[Fresh Ubuntu server walkthrough](remote-runner-setup.md) ·
[Configurable Docker limits and worker policy](docker-profiles.md)

Keep GitHost on Windows and run CI on a dedicated Linux Docker worker. The worker
makes outbound HTTP requests only: no SSH and no inbound worker ports.

This initial version supports one job at a time per token. Use a separate token
and private work directory for each worker. Matching uses explicit repository
restrictions, not labels. Local `host` and `docker` runners remain available.

Container restrictions below describe the **defaults**. Pipelines may request a
validated `execution.docker` profile; the worker must separately authorize higher
ceilings or expanded capabilities. See [Docker profiles](docker-profiles.md).
An existing worker without `--policy-file` retains the restrictive built-in policy.

## Already-installed test server

The Ubuntu runner is installed, enabled at boot, and has passed real Docker tests.
You do **not** need to reinstall it to enable another repository.

| Component | Current value |
|---|---|
| GitHost checkout (Windows) | `C:\git_over_http` |
| GitHost database | `C:\temp\pygithost.db` |
| GitHost process management | Windows scheduled task `git_over_http` |
| Worker checkout (Ubuntu) | `/opt/pygithost` |
| Worker account | `githost-runner` (unprivileged, with Docker access) |
| Worker service | `pygithost-runner.service` |
| Worker → GitHost URL | `http://192.168.250.1:8000` |
| Worker IP allowed by GitHost | `192.168.250.2` |
| Token file | `/var/lib/githost-runner/config/token` |
| Private work directory | `/var/lib/githost-runner/work` |
| Pre-pulled image | `python:3.14-slim` |
| Currently authorized repository | `root/http-runner-smoke` **only** |

Real runs #121–124 verified success, nonzero exit, timeout and cancellation.
Run #121 also verified the exact commit, Linux, a non-root container user and
artifact transfer back to Windows. Existing application pipelines were not changed.

### Enable an application repository

1. **Check Linux compatibility.** Commands run in `/bin/sh`, not PowerShell or
   `cmd.exe`. Use `/workspace` or relative paths, not `C:\...`. Windows-only
   packaging, service management and deployments must stay on a Windows runner/host.
2. **Prepare an image** containing the tools and dependencies needed by that
   pipeline; see [Docker images and dependencies](#docker-images-and-dependencies).
3. **Authorize the repository** with a replacement token containing the complete
   desired repository list; see [Change authorized repositories](#change-authorized-repositories).
4. Open the repository's **CI → Settings → Configuration JSON**. In the chosen
   pipeline's `execution`, set `runner` to `remote-docker` and `image` to the
   prepared local or registry image name. Preserve its other triggers, steps and policies;
   do not replace a working configuration with the minimal example below.
5. Save, then use the repository's **CI** manual-run action if enabled, or push a
   real update if its push trigger is enabled.
6. Open the run and check its steps, logs and artifacts. Ubuntu service logs alone
   do not establish that a job succeeded.

GitHost must stay running on Windows. Switching CI to Ubuntu does not migrate the
web server, repositories, database or deployments. A manual CI run never triggers
automatic deployment; successful eligible push/merged runs keep existing gates.

## GitHost setup

Install the updated code on Windows first. In the server's Python environment,
create a token using its **actual existing database**:

```powershell
python -m pygithost.runner create-token --db C:\path\to\githost.db --name ubuntu-ci --repository alice/project
```

Repeat `--repository owner/name` to authorize more repositories. Use the namespace
from the actual repository URL (including flat-repository namespaces). The token
is displayed once for secure transfer; only its SHA-256 digest is stored.
Do not put the token in Git, job scripts or CI variables. Provisioning requires
local administrative access to the database, not a personal API token.

Select `remote-docker` explicitly in the repository CI configuration:

```json
{
  "version": 1,
  "pipelines": [
    {
      "name": "checks",
      "execution": {
        "runner": "remote-docker",
        "image": "python:3.14-slim",
        "timeout_seconds": 600
      },
      "triggers": {"push": {"enabled": true}, "manual": {"enabled": true}},
      "steps": [{"name": "Tests", "run": "python -m unittest discover -q"}]
    }
  ]
}
```

Existing enqueue/trust checks, per-repository scheduling and concurrency limits
apply before assignment. Waiting jobs occupy scheduler slots; cancel them if no
matching worker is available. They do not silently fall back to local execution.

### Change authorized repositories

The current token is intentionally restricted to the smoke repository. Selecting
`remote-docker` on another repository without authorizing it will leave its job
waiting for a matching worker.

There is no CLI command to edit an existing token's restrictions. Provision a
replacement with the **complete** repository list. On Windows, from
`C:\git_over_http`, using the GitHost Python environment:

```powershell
python -m pygithost.runner create-token --db C:\temp\pygithost.db --name ubuntu-ci-v2 --repository root/http-runner-smoke --repository root/YOUR_REPOSITORY
```

Replace `root/YOUR_REPOSITORY` with the exact namespace/name from the repository's
URL. This example creates a new credential; it does not update `ubuntu-ci`.
Choose a fresh name for later rotations. Never post the printed token in a
ticket, chat, log or repository.

When no job is active, stop the Ubuntu worker and replace its token securely.
The following commands are for an administrator's interactive Bash terminal;
the secret is entered without terminal echo and is not placed in shell history:

```bash
sudo systemctl stop pygithost-runner
sudo -v
read -rsp 'New runner token: ' RUNNER_TOKEN
echo
printf '%s' "$RUNNER_TOKEN" | sudo tee /var/lib/githost-runner/config/token >/dev/null
unset RUNNER_TOKEN
sudo chown githost-runner:githost-runner /var/lib/githost-runner/config/token
sudo chmod 600 /var/lib/githost-runner/config/token
sudo systemctl start pygithost-runner
sudo systemctl is-active pygithost-runner
```

For a new worker without a service unit yet, perform only the token-entry and
file-permission commands; defer service start/stop until the unit is installed.

Verify an authorized CI job succeeds, then revoke the old credential on Windows:

```powershell
python -m pygithost.runner revoke-token --db C:\temp\pygithost.db --name ubuntu-ci
```

Keep the old credential until verification succeeds, or restore it securely if
rollback is needed. Revoking by name revokes all tokens with that name. Do not
share one token between multiple worker machines/processes.

## Docker images and dependencies

The supplied `python:3.14-slim` image is sufficient for standard-library Python
tests, **not** projects requiring extra packages, compilers, Git inside the
container, or system libraries. Git on Ubuntu is used for checkout; it does not
automatically become available inside the image.

Job containers have no network. A CI step such as `pip install -r requirements.txt`
cannot download packages. Build a trusted image ahead of time on Ubuntu:

```dockerfile
FROM python:3.14-slim
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
```

From an administrator-prepared build directory containing that Dockerfile and the
reviewed requirements file:

```bash
sudo docker build -t githost/my-project-ci:1 .
sudo -u githost-runner docker image inspect githost/my-project-ci:1 >/dev/null
```

Then use `"image": "githost/my-project-ci:1"` in the pipeline's `execution`.
Do not switch the source checkout to a later branch tip during testing: the runner
already supplies the exact recorded commit. Review Dockerfiles before building;
image builds execute code with Docker privileges and may access the network.

Steps run as the unprivileged worker UID. Install dependencies in the image during
the build, not into root-owned image directories during CI. Write test reports and
artifacts inside the checkout. Each step starts a fresh container, so keep needed
generated files in the shared checkout.

To retain a generated file, add this field alongside the pipeline's `steps`:

```json
{
  "artifacts": {
    "paths": ["test-results.json"],
    "when": "always"
  }
}
```

The command must actually create that file. View/download collected artifacts from
the run in GitHost. Secrets should be configured through existing trusted CI
variables, never baked into an image or put in artifact files.

## Ubuntu setup

This section is for a **new worker**, not the already-installed test VM above.

Use an **unprivileged dedicated account** with Git, Python 3.14 and Docker CLI
available. Install the same GitHost source version on the worker. The worker uses
Python's standard library and does not start a GitHost web server.

On Ubuntu 26.04, the version used on the test VM:

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv docker.io docker-compose-v2
sudo systemctl enable --now docker
python3 --version
git --version

id githost-runner >/dev/null 2>&1 || sudo useradd --system --create-home --home-dir /var/lib/githost-runner --shell /usr/sbin/nologin githost-runner
sudo usermod -aG docker githost-runner
sudo git clone https://github.com/jordaly/git_over_http.git /opt/pygithost
sudo python3 -m venv /opt/pygithost/.venv
sudo install -d -m 700 -o githost-runner -g githost-runner /var/lib/githost-runner/config /var/lib/githost-runner/work
```

Confirm Python is 3.14-compatible before continuing. Older Ubuntu releases may
need a separately installed compatible interpreter. If `/opt/pygithost` already
exists, inspect it rather than cloning over it or discarding changes.

The account needs Docker daemon access. The `docker` group effectively grants root
access: use a dedicated VM, not a shared host for hostile code.

The remote worker defaults to **pull if missing**: it checks the local cache and
downloads a missing image on the Ubuntu host before executing the job. Existing
images are reused. Administrators can set worker-policy `image_pull` to `never`
(offline/cache-only) or `always` (refresh before each job). Pre-pulling remains
optional: `sudo docker pull python:3.14-slim`.

Containers themselves still use `--pull=never` and the existing hardened executor:
no network by default, read-only root, writable checkout/tmp,
dropped capabilities, no Docker socket, CPU/memory/process limits. Each step uses
a fresh container; files persist in the shared checkout, not installed packages
or shell state. Dependencies must already be in the image.

Keep the token outside repositories, in a mode-600 file owned by the runner:

```bash
# Securely install the issued token using the interactive procedure above.
cd /opt/pygithost
sudo -u githost-runner /opt/pygithost/.venv/bin/python -m pygithost.runner run \
  --server http://192.168.250.1:8000 \
  --token-file /var/lib/githost-runner/config/token \
  --work-dir /var/lib/githost-runner/work \
  --allow-http
```

For a different network, replace the server URL with the GitHost address reachable
from that worker. This foreground command runs until interrupted. Stop it before
starting the systemd service; do not run two workers against the same token/state.

Plain HTTP exposes credentials, source, logs and secrets in transit. `--allow-http`
explicitly accepts this risk on the trusted test network. For HTTPS, change the URL
and omit that flag. TLS verification remains enabled. Redirects and environment
proxies are not used. GitHost's client IP allowlist must permit the worker.

For the private Ubuntu VM on the test Windows host, use
`http://192.168.250.1:8000` and allow the VM's `192.168.250.2` address. Connecting
through the host's LAN address can traverse WinNAT and appear to GitHost as the
Windows host itself; the private interface avoids needing that broader allowlist.

Example systemd service; adapt the account and absolute paths:

```ini
[Unit]
Description=PyGitHost HTTP CI runner
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=githost-runner
Group=githost-runner
SupplementaryGroups=docker
WorkingDirectory=/opt/pygithost
ExecStart=/opt/pygithost/.venv/bin/python -m pygithost.runner run --server http://192.168.250.1:8000 --token-file /var/lib/githost-runner/config/token --work-dir /var/lib/githost-runner/work --allow-http
Restart=on-failure
RestartSec=10
TimeoutStopSec=150
UMask=0077

[Install]
WantedBy=multi-user.target
```

Test credentials, permissions, image and server configuration before enabling it.
Save the unit as `/etc/systemd/system/pygithost-runner.service`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pygithost-runner
sudo systemctl status pygithost-runner --no-pager
```

## Operate the installed Ubuntu service

Run these on Ubuntu with administrative access:

```bash
sudo systemctl status pygithost-runner --no-pager
sudo journalctl -u pygithost-runner --no-pager -n 50
sudo systemctl is-enabled pygithost-runner
sudo -u githost-runner docker info --format '{{.ServerVersion}}'
sudo docker ps -a --filter label=pygithost.http-attempt
```

The worker polls quietly when idle; no new journal lines is normal. Read detailed
job output in the GitHost CI run, not just the service journal.

After reviewing queued/running jobs, stop/start/restart only the runner:

```bash
sudo systemctl stop pygithost-runner
sudo systemctl start pygithost-runner
sudo systemctl restart pygithost-runner
```

Stopping it during a job interrupts that attempt; it is not a pause/resume action.
Do not restart Windows or stop application services such as
`FuenteInteligenteAPI` to manage CI.

### Update the worker

Use the same tested code revision on GitHost and its worker. Arrange updates while
CI is idle; do not reset or discard modifications in either checkout.

```bash
sudo systemctl stop pygithost-runner
sudo git -C /opt/pygithost status --short
sudo git -C /opt/pygithost pull --ff-only origin main
sudo systemctl start pygithost-runner
sudo systemctl is-active pygithost-runner
```

Review local changes before pulling. Update Windows GitHost separately and restart
its scheduled task only if the server code/configuration requires it and no CI or
deployment is active. The worker does not require a GitHost restart just to change
its token or preinstall an image.

## Troubleshooting

| Symptom | Check/action |
|---|---|
| Job waits for an HTTP runner | Service active; repository authorized with exact namespace; pipeline uses `remote-docker`; server has a free scheduler slot. |
| HTTP 403 | GitHost client IP allowlist. On this VM use `192.168.250.1:8000`, not the Windows LAN address. |
| HTTP 401 | Wrong/revoked token; personal API tokens are not runner tokens. Check file ownership and permissions without printing it. |
| Docker permission denied | `githost-runner` needs Docker access; restart the worker after group-membership changes. |
| Image unavailable / phase `image` fails | With `image_pull=missing` (default), the worker host downloads it. Check host internet/DNS, registry permissions, image name and pull timeout. With `never`, pre-pull/build it or change the worker policy. |
| Package downloads fail | Expected: containers have no network. Install dependencies in the image beforehand. |
| PowerShell/Windows command not found | Convert only Linux-compatible checks to `/bin/sh`; keep Windows-specific jobs local. |
| Job interrupted after disconnect | Inspect real container/target state. Fix connectivity, then manually rerun with a new run ID; do not delete the attempt receipt. |
| Service active but job failed | Inspect GitHost run logs/step exit codes; an active service does not mean tests passed. |

Do not expose the Docker daemon on port 2375 or open inbound worker ports as a
connectivity workaround. Worker HTTP traffic is initiated from Ubuntu.

## Protocol

All calls use JSON `POST /api/runner/v1/{operation}` and
`Authorization: Bearer TOKEN`. User API tokens cannot call these endpoints, and
runner tokens cannot call the user API. Authentication is mandatory even when web
authentication is disabled.

The dedicated protocol OpenAPI document is available at
`GET /api/runner/v1/openapi.json` using a runner token.

| Operation | Request fields | Response |
|---|---|---|
| `claim` | none (`{}`) | `job: null`, or job with `run_id`, `attempt`, row and execution configuration |
| `source` | `run_id`, `attempt` | Base64 `bundle`, or `cancel: true` |
| `heartbeat` | `run_id`, `attempt`, `progress` | acknowledgement or `cancel: true` |
| `complete` | `run_id`, `attempt`, terminal `progress`, optional base64 artifact ZIP | acknowledgement or `cancel: true` |

Progress contains `output`, integer `truncated`, `phase`, and `steps`. Completion
adds `status` (`success`, `failed`, `timed_out`, `interrupted`), integer `return_code`,
timestamps, `reason`, and `warnings`. Success requires return code zero.
Only the assigned token/attempt can download source or report results.
Deployment commands/configuration never leave GitHost.

Transactional claims are durable. Repeated claims return the same active attempt;
duplicate completion is not applied twice. Assignment identity replaces the user
API's `Idempotency-Key` for these worker operations.

The worker polls every five seconds. Heartbeats renew a 90-second lease; expiration
interrupts the run without assigning it again. After 45 seconds of failed heartbeat
contact the worker stops execution. An on-disk receipt prevents replay after worker
restart. Cancellation is delivered through heartbeat responses; server restart
recovery interrupts jobs rather than replaying them.

Normal cancellation/timeouts clean containers. A detached watchdog removes
attempt-labelled containers after the job deadline or worker-process death.
Worker startup also cleans containers from its previous attempt. A whole-VM,
Docker-daemon or watchdog failure still requires inspection before a manual rerun.
Stopping a job cannot undo external side effects. Do not delete the receipt to
force uncertain jobs to rerun. Inspect leftover `job-*` directories before removal.

Default limits: 100 MiB source bundle (including required histories), 16 MiB
artifact ZIP compressed, 20 MiB uncompressed, 1000 artifact files and 1 MiB logs.
Configure `execution.source_limit_mb` and `execution.limits` to change them;
there is no hard-coded upper configured size ceiling. Protocol body limits scale
with the stored run limits. Transfers remain buffered, not chunked.
See [CI limits](ci-limits.md) for timeouts, defaults and capacity warnings.

Results appear in the normal CI UI/API, including logs, steps and artifacts.
Deployment stays on Windows with the existing exact-commit, branch-tip and trust
checks. Nothing in this setup deploys host code to Ubuntu.

Revoke a token locally on the GitHost host:

```powershell
python -m pygithost.runner revoke-token --db C:\path\to\githost.db --name ubuntu-ci
```

Revocation rejects subsequent requests. The worker fails closed and the server
expires its lease. Stop the worker too when decommissioning it.
## Server-side source storage

New remote CI jobs keep their Git bundle in a private temporary file; SQLite
stores its path, not the bundle contents. The file is removed when the job
closes, is cancelled, or is interrupted by coordinator startup recovery.
Cleanup paths are recorded durably before assignment references are cleared.
If Windows readers/scanners temporarily block deletion, startup and job results
are not failed: the path remains in `ci_remote_source_cleanup` and is retried
on later runner claims or coordinator recovery, including after a restart.
Cancellation during source preparation also waits for preparation to finish
and removes the unqueued file.

The runner HTTP protocol is unchanged: `source` still returns a base64 bundle.
Existing queued jobs with SQLite bundles remain readable during migration.
Deploy the server update normally; workers do not require a simultaneous update.
Reading and encoding a file-backed bundle happens after releasing SQLite's
write transaction. This change does not shrink existing database files or move
artifact storage out of SQLite; it does not run `VACUUM`.

Source reads use bounded chunks rather than allocating the configured size
ceiling. A small bundle therefore does not reserve that whole budget; the byte
limit is still enforced if the file grows while being read. The complete bundle
and base64 response remain buffered in memory, so large actual payloads still
require adequate RAM.
