# git_over_http

A dependency-free asynchronous Git Smart HTTP server with a web interface,
authentication, repository browsing, branches, tokens, users, and pull requests.

## Requirements

- Python 3.14 or newer (the UI renderer uses Python t-strings)
- Git and `git-http-backend`

## Configuration and startup

Generate a platform-specific configuration file:

```sh
python server.py generate-config --platform Linux
```

Review `pygithost.config.json`, particularly `git_project_root`,
`git_http_backend`, `db_path`, and the allowed client IPs, then run:

```sh
python server.py run --config pygithost.config.json
```

The package entry point is equivalent:

```sh
python -m pygithost run --config pygithost.config.json
```

## Project structure

- `server.py` is the backward-compatible executable and import facade.
- `pygithost/config.py` owns immutable configuration loading and validation.
- `pygithost/context.py` defines the dependencies passed into a server instance.
- `pygithost/rendering.py` owns safe HTML and t-string rendering.
- `pygithost/database.py` owns users, sessions, tokens, and pull requests.
- `pygithost/cli.py` owns command parsing and startup commands.
- `pygithost/application.py` contains the HTTP protocol, Git backend, and current
  feature handlers. New infrastructure modules should be kept free of
  request-handler state and added to `AppContext` when they need dependencies.

Programmatic startup uses explicit configuration instead of patching globals:

```python
from pygithost import AppConfig, AppContext, AsyncGitServer

config = AppConfig.from_file("pygithost.config.json")
app = AsyncGitServer(AppContext(config))
```

## Tests

Run the suite with the project virtual environment:

```sh
.venv/bin/python -m unittest discover -v
```

The integration tests use the real `git-http-backend` and bind a loopback port.

## Continuous integration

Open a repository's **CI → CI settings** page as an administrator. Set a command
(for example `python -m unittest discover -v`), select triggers, and save. Enable
the **manual** trigger to queue a branch from the CI page. Write access is required
to queue, cancel, or rerun jobs; configuration and email retries require admin
access when authentication is enabled. With authentication disabled, the IP
allowlist is the security boundary, including for CI administration.

### Execution and security

- **Host** is the backward-compatible default and is **trusted-code-only**. Jobs
  run as the server's OS user, not in a sandbox. A restricted environment prevents
  accidental credential inheritance, but does not prevent filesystem access or
  access to other processes. Use a dedicated unprivileged server account. Do not
  run untrusted PR code on the host runner.
- **Docker** uses a local Linux Docker daemon and `/bin/sh` (including on a
  Windows host with Linux containers). On Linux, run the server as a non-root
  user with Docker access. Only the independent checkout is bind-mounted; the
  production repository and Docker socket are not mounted. Containers use the
  host user's UID/GID on Linux, no network, a read-only root filesystem, no Linux
  capabilities, no privilege escalation, 1 GiB memory, one CPU, 128 PIDs, and a
  256 MiB writable `/tmp`. The checkout itself is writable and has no disk quota.
  Docker is defense in depth, not a substitute for a dedicated runner host when
  executing hostile code.
- Pre-pull/build the image on the server (`docker pull python:3.14-slim`); CI does
  not pull missing images. Include your tools/dependencies in the image because
  jobs have no network. The image must contain `/bin/sh`; its configured
  entrypoint is overridden. Pin an image digest for reproducibility.
- Each run gets a separate clone without shared object files or an origin remote.
  PR checks merge the recorded head SHA into the recorded base SHA before running
  the command. Changes to either branch trigger a fresh check when PR updates are
  enabled. Merge conflicts are reported separately from command failures.
- Host commands use `/bin/sh` on POSIX or `cmd.exe` on Windows. Jobs inherit only
  basic executable-search/platform/locale variables; `HOME` and temporary paths
  point to the job's temporary directory. Add other necessary variables explicitly
  in settings. Values in settings are **not secrets**: they are stored in plaintext
  configuration snapshots, and job output is not redacted. Do not put credentials
  there or print them in logs.

Jobs expose `CI=true` and `PYGITHOST_OWNER`, `PYGITHOST_REPO`,
`PYGITHOST_REPOSITORY`, `PYGITHOST_EVENT`, `PYGITHOST_REF`, `PYGITHOST_BRANCH`,
`PYGITHOST_COMMIT`, `PYGITHOST_OLD_COMMIT`, `PYGITHOST_PR_NUMBER`,
`PYGITHOST_BASE_BRANCH`, `PYGITHOST_HEAD_BRANCH`, `PYGITHOST_BASE_COMMIT`, and
`PYGITHOST_WORKTREE`. Built-in variable names cannot be overridden.

Branch filters use one case-sensitive glob per line (`main`, `release/*`); blank
means all branches. PR filters match the **target** branch.

### Runs, queues, and recovery

Commands and settings are snapshotted when queued. **Rerun** uses the same
configuration, event, payload, and SHAs—not today's branch tip or settings. It
still depends on the selected image/toolchain and on Git retaining the commit
objects. Older runs without snapshots can be viewed but cannot be rerun exactly.

Output is saved approximately every half-second, shown by polling, and capped at
1 MiB while the process output continues to be drained. The detail page provides
follow/copy/download controls, queue wait, duration, phase, failure reason, and
email status. Commands plus checkout/merge have a shared 30-minute timeout.
Cleanup has a separate bounded timeout; cleanup warnings do not overwrite a
successful command result.

Only one job per repository runs at once. Server environment settings:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PYGITHOST_CI_CONCURRENCY` | `2` | Global simultaneous jobs |
| `PYGITHOST_CI_QUEUE_LIMIT` | `100` | Global waiting jobs, excluding running jobs |
| `PYGITHOST_CI_RETENTION` | `100` | Completed runs retained per repository (1–10000) |

A full queue produces a failed run with a queue-specific reason instead of
silently dropping the event. Optionally cancel superseded runs for the same
event/branch/PR. Cancelled and interrupted runs do not send email. Filters and
cursor pagination let you browse retained history; the repository badge shows
the default branch and marks results stale when its commit changes.

The scheduler takes an OS lock beside the SQLite database; do not run multiple
servers against the same database. Waiting jobs survive shutdown, running jobs
are interrupted, and the queue is periodically reconciled with the database.
After a hard process/host crash, the database is recovered, but OS processes,
Docker containers (`pygithost-ci-<pid>-<run>`), and temporary checkouts may require
operator cleanup. Use a service supervisor that terminates the entire service
process tree/cgroup (for example systemd's `KillMode=control-group`), not just the
server's process group: CI subprocesses use separate sessions. Docker containers
need separate cleanup after a crash. This is not a distributed worker system.

### Email notifications

Open **Admin: Email** from the repository list (or `/admin/email`) to configure the
SMTP hostname, port, TLS mode, sender, username, password, and optional public
server URL. Save, then use **Send test email** to verify delivery. Changes take
effect immediately. CI settings also link to this page.
The port is fully editable (1–65535), including custom ports such as 2525;
choose the TLS mode your mail server uses on that port.

This page is administrator-only when authentication is enabled, uses protected
POST forms, and never displays the password. Leave the password blank to retain
it, or select **Clear existing password**. Use HTTPS: web-configured credentials
are stored **unencrypted in the server SQLite database**, so restrict database
and backup access. Saving email settings sets the database and existing SQLite
sidecars to owner-only permissions on POSIX; on Windows, configure appropriate
file ACLs. Host-runner code has the server user's filesystem access and
must remain trusted. With authentication disabled, the IP allowlist protects
email administration as well as the rest of the application.

For a self-signed SMTP server or internal certificate authority, paste its
**public PEM certificate** in **Trusted SMTP certificate / CA certificates** on
the Email settings page. Obtain it from your mail administrator and verify its
fingerprint through a trusted channel; do not blindly trust a certificate fetched
from an unverified connection. Never paste a private key. Multiple PEM certificates
are supported. These are added to system trust for SMTP only; hostname and expiry
verification remain enabled for both STARTTLS and implicit TLS. The SMTP hostname
must match the certificate's Subject Alternative Name. Clear the field to return
to system trust only, save, and use **Send test email** to check the result.

Environment-based setup is still supported when no web settings have been saved;
saved web settings override the entire SMTP environment configuration. Example
POSIX shell configuration:

```sh
export PYGITHOST_SMTP_HOST=smtp.example.com
export PYGITHOST_SMTP_PORT=587
export PYGITHOST_SMTP_TLS=starttls
export PYGITHOST_SMTP_FROM=ci@example.com
export PYGITHOST_SMTP_USERNAME=ci@example.com
export PYGITHOST_SMTP_PASSWORD='your-smtp-password'
export PYGITHOST_PUBLIC_URL=https://git.example.com
```

`PYGITHOST_SMTP_TLS` accepts `starttls` (default, port 587) or `ssl` (default port
465); TLS certificate verification is always enabled. Authentication is optional
when the username is omitted. `PYGITHOST_PUBLIC_URL` is optional and may include
a deployment path prefix; it supplies the run link in messages.

In each repository's CI settings, enter up to 20 plain recipient addresses and
choose **Off**, **Failures only**, **All completions**, or **Failures and recovery**.
Recovery means the first success after a failed/timed-out result for the same
event/branch, or the same PR across opened/updated/reopened events. Messages contain
run metadata and a link, never commands, logs, or environment values. Recipients
can receive repository/branch/commit information even if they cannot log in, so
choose them accordingly.

Email delivery runs separately from jobs, with two simultaneous deliveries and
15-second SMTP operation timeouts. Delivery failures are visible on the run page
and never change the CI result. Queued notifications survive restart. Deliveries
already in progress during a crash are marked uncertain and are not automatically
resent, to avoid duplicates; failed deliveries are also not automatically retried.
After fixing SMTP settings, an administrator can use **Retry email** on the run
page without rerunning the build. SMTP acceptance does not guarantee inbox delivery.

### Additional CI tests

The regular suite includes host-runner regression tests and mocked TLS/SMTP
delivery tests; it does not send real email. To also exercise Docker execution
and timeout cleanup using an existing local Linux image:

```sh
PYGITHOST_TEST_DOCKER_IMAGE=python:3.14-slim .venv/bin/python -m unittest discover -v
```
