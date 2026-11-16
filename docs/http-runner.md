# HTTP Docker runner

Keep GitHost on Windows and run CI on a dedicated Linux Docker worker. The worker
makes outbound HTTP requests only: no SSH and no inbound worker ports.

This initial version supports one job at a time per token. Use a separate token
and private work directory for each worker. Matching uses explicit repository
restrictions, not labels. Local `host` and `docker` runners remain available.

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
      "events": {"push": true, "manual": true},
      "steps": [{"name": "Tests", "run": "python -m unittest discover -q"}]
    }
  ]
}
```

Existing enqueue/trust checks, per-repository scheduling and concurrency limits
apply before assignment. Waiting jobs occupy scheduler slots; cancel them if no
matching worker is available. They do not silently fall back to local execution.

## Ubuntu setup

Use an **unprivileged dedicated account** with Git, Python 3.14 and Docker CLI
available. Install the same GitHost source version on the worker. The worker uses
Python's standard library and does not start a GitHost web server.

The account needs Docker daemon access. The `docker` group effectively grants root
access: use a dedicated VM, not a shared host for hostile code.

Pre-pull images (`docker pull python:3.14-slim`). Jobs use `--pull=never` and the
existing hardened executor: no network, read-only root, writable checkout/tmp,
dropped capabilities, no Docker socket, CPU/memory/process limits. Each step uses
a fresh container; files persist in the shared checkout, not installed packages
or shell state. Dependencies must already be in the image.

Keep the token outside repositories, in a mode-600 file owned by the runner:

```bash
mkdir -m 700 -p ~/.config/pygithost-runner ~/.local/state/pygithost-runner
# Securely write the issued token to ~/.config/pygithost-runner/token.
chmod 600 ~/.config/pygithost-runner/token
python -m pygithost.runner run \
  --server http://192.168.16.16:8000 \
  --token-file ~/.config/pygithost-runner/token \
  --work-dir ~/.local/state/pygithost-runner \
  --allow-http
```

Plain HTTP exposes credentials, source, logs and secrets in transit. `--allow-http`
explicitly accepts this risk on the trusted test network. For HTTPS, change the URL
and omit that flag. TLS verification remains enabled. Redirects and environment
proxies are not used. GitHost's client IP allowlist must permit the worker.

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
ExecStart=/opt/pygithost/.venv/bin/python -m pygithost.runner run --server http://192.168.16.16:8000 --token-file /home/githost-runner/.config/pygithost-runner/token --work-dir /home/githost-runner/.local/state/pygithost-runner --allow-http
Restart=on-failure
RestartSec=10
TimeoutStopSec=150
UMask=0077

[Install]
WantedBy=multi-user.target
```

Test credentials, permissions, image and server configuration before enabling it.

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

Limits: 32 MiB source bundle (including required commit histories), 16 MiB artifact
ZIP compressed, 20 MiB declared uncompressed, 1000 artifact files, 26 MiB request
JSON. Existing bounded log collection applies. Transfers are buffered, not chunked.

Results appear in the normal CI UI/API, including logs, steps and artifacts.
Deployment stays on Windows with the existing exact-commit, branch-tip and trust
checks. Nothing in this setup deploys host code to Ubuntu.

Revoke a token locally on the GitHost host:

```powershell
python -m pygithost.runner revoke-token --db C:\path\to\githost.db --name ubuntu-ci
```

Revocation rejects subsequent requests. The worker fails closed and the server
expires its lease. Stop the worker too when decommissioning it.
