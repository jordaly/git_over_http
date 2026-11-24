# Getting started

[Back to README](../README.md)

This guide starts a local instance before exposing it to other machines. PyGitHost
uses Python's standard library; Git must be installed separately. Local Docker CI
requires a local Linux Docker daemon and prepared image. Remote Docker CI uses a
separate Linux worker, which can download missing registry images on its host
according to administrator policy. See [Remote runner setup](remote-runner-setup.md).

## 1. Check prerequisites

Run these commands from the project directory:

```sh
python --version
git --version
git --exec-path
```

Python must be **3.14 or newer**, because the HTML renderer uses t-strings. On
systems where `python` points to an older interpreter, use `python3.14` in the
commands below. The directory printed by `git --exec-path` should contain
`git-http-backend` (`git-http-backend.exe` on Windows).

An optional virtual environment keeps the interpreter selection explicit:

```sh
python -m venv .venv
```

Use `.venv/bin/python` on Linux/macOS or `.venv\Scripts\python.exe` on Windows
instead of `python` for subsequent commands. No pip installation is required to
run the server from this checkout.

## 2. Generate and review configuration

```sh
python server.py generate-config --config local.config.json
```

The platform defaults to the current OS. To inspect defaults for another platform
without creating a file:

```sh
python server.py generate-config --platform Windows --print
```

Edit `local.config.json` before starting. For a first local run, set:

```json
{
  "host": "127.0.0.1",
  "port": 8000,
  "allowed_client_ips": ["127.0.0.1"],
  "filter_ips": true,
  "require_auth": true,
  "session_cookie_secure": false
}
```

This is a set of fields to change in the generated file, not a replacement for
its platform-specific paths. In particular, verify `git_http_backend` against
your Git installation. Keep HTTP and insecure cookies confined to loopback;
use HTTPS and secure cookies for remote access.

### Built-in Git HTTP backend

When `git_http_backend` points to a missing file, the server prints
`WARNING: GIT_HTTP_BACKEND not found ...; using the built-in Python Git HTTP backend`
and keeps running. Set `"git_http_backend": "builtin"` to choose it explicitly.

The built-in backend is a pure-Python implementation of the same CGI program
(`pygithost/git_http_fallback.py`). It drives `git upload-pack` and
`git receive-pack`, exactly like `git-http-backend`, so the `git` executable must
still be on `PATH`. It supports protocol v0, v1 and v2, gzip request bodies, the
read-only dumb HTTP protocol, and the per-repository `http.uploadpack`,
`http.receivepack` and `http.getanyfile` settings. Authentication, write scopes,
branch protection and CI triggers behave identically with either backend. Each
request starts a short-lived Python process, which adds a few tens of milliseconds
compared with the native executable.

### Essential configuration fields

| Field | Purpose / guidance |
| --- | --- |
| `host`, `port` | Bind address and port. An empty host listens on all interfaces; use `127.0.0.1` for local access only. |
| `git_project_root` | Repository storage directory. The server account needs access to repositories and write permission for mutations. |
| `deleted_repos_root` | Optional. Where **Settings → Danger zone → Delete** moves repositories; defaults to a sibling of `git_project_root` named `<root>-deleted` (for example `C:\Servidor_Git-deleted`). Must be outside `git_project_root` so the Git service cannot reach it. See [Restoring a deleted repository](#restoring-a-deleted-repository). |
| `git_http_backend` | Path to the Git Smart HTTP backend executable, not the main `git` executable. If the file does not exist, or the value is `builtin`, the server uses its built-in pure-Python backend (see below). |
| `db_path` | SQLite database for users, sessions, settings, CI history, and artifacts. Keep it outside publicly served directories. |
| `url_prefix` | Git HTTP endpoint prefix; defaults to `/git`. This is not a prefix for all web-interface routes. |
| `filter_ips` | Enables client IP filtering; defaults to `true`. |
| `allowed_client_ips` | Explicit client IP addresses. Replace the generated example addresses with your own; do not assume CIDR support. |
| `require_auth` | Enables authentication; defaults to `false`. Without it, the IP allowlist is also the administration security boundary. |
| `session_cookie_secure` | Set to `true` when serving the browser interface through HTTPS. Secure cookies are not suitable for ordinary local HTTP. |
| `static_root` | Directory containing this checkout's `static/` assets. Review it if moving the checkout or configuration. |
| `trace_log` | Optional Git backend trace destination; restrict access to diagnostic logs. |
| `log_level`, `log_format`, `log_file` | Application/access logging: level, `json` or `text`, and rotating file. Empty `log_file` logs to stderr only. See [Logging](logging.md). |
| `log_max_bytes`, `log_backup_count` | Rotation threshold and number of retained files. |
| `access_log`, `audit_log` | Enable per-request access records and SQLite security events. |

Use JSON booleans (`true` / `false`), not quoted strings. Prefer absolute paths
for storage and executables so service startup does not depend on its working
directory. Restart the server after editing the configuration file.

## 3. Start and sign in

```sh
python server.py run --config local.config.json
```

Open <http://127.0.0.1:8000/>. On an empty user database, startup creates an
`admin` account and prints its generated password in the server output. Save it
securely and sign in at `/login`. Treat startup logs as sensitive. The environment
variable `PYGITHOST_DEFAULT_ADMIN_PASSWORD` can supply the initial password, but
does not reset an account in an existing database.

The equivalent package command is:

```sh
python -m pygithost run --config local.config.json
```

Do not run multiple server instances against the same database. Stop a foreground
instance with Ctrl+C. For persistent deployments, use a service supervisor and
review the [CI recovery notes](../README.md#runs-queues-and-recovery).

## 4. Use Git over HTTP

Open a repository in the browser and copy the URL from its **Code** dropdown.
Using that URL avoids guessing the owner/path layout:

```sh
git clone http://127.0.0.1:8000/git/OWNER/REPOSITORY.git
```

Replace the example URL with the copied one. When authentication is enabled,
enter your username and password or access token when Git prompts. Tokens can be
managed on the **Tokens** page; use an appropriate scope for read or write access.
Never embed credentials in a clone URL or commit them in scripts.

## Before allowing remote access

- Enable authentication and replace the generated IP allowlist.
- Use HTTPS; Basic authentication over plain HTTP does not protect credentials.
- Run as a dedicated, unprivileged OS user and restrict database, backup, and log access.
- If using a reverse proxy, verify the effective client IP filtering behavior;
  do not assume forwarded headers make the allowlist protect individual clients.
- Back up both the repositories and SQLite data using a consistent backup method;
  repository copies alone do not preserve users, settings, PRs, or CI artifacts.
- Host CI and deployment scripts execute as the server user. Read
  [Execution and security](../README.md#execution-and-security) before enabling jobs.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Syntax error while importing the application | Confirm the interpreter is Python 3.14+, including the interpreter used by your service or virtual environment. |
| Configuration file already exists | Edit that file or choose another `--config` path. `--overwrite` replaces it intentionally. |
| Configuration file not found | Pass the same `--config` path to both generation and startup. |
| Browser cannot connect | Check startup errors, bind address, port, firewall, and whether another process occupies the port. |
| Request denied by IP filtering | Check `allowed_client_ips` against the actual connecting address. For this guide, use `127.0.0.1`, not an IPv6 localhost address. |
| Git clone/push fails | Confirm `git_http_backend` exists (or that the built-in backend is in use, as reported at startup), copy the repository's clone URL, and check credentials, token scope, filesystem permissions, and branch protection. |
| Login does not persist | Check whether `session_cookie_secure` is enabled while accessing the site over plain HTTP. |
| Styles or scripts are missing | Check that `static_root` points to this checkout's `static/` directory. |
| PR creation fails with an author foreign-key or NOT NULL constraint | Back up the database and restart the updated server. Startup migrates legacy NOT NULL authors to nullable authors while preserving PR history. Do not create user ID 0 or disable foreign keys. |
| CI command cannot find a tool | Host jobs have a restricted environment; Docker jobs require tools in the prepared image and have no network. |

## Manage settings in the browser

Open **Admin → Settings** to edit the display name and browser favicon, basic server configuration,
and server-wide CI variables and retention. Unlike appearance and CI environment/default changes, basic server
configuration is saved to the startup file for the **next restart**. Review allowed
IPs, credentials, cookie security and storage paths before restarting; saving paths
does not migrate data. Instances started programmatically without a config file
show the basic fields read-only.

Repository **CI → Settings** manages only environment variables and secrets.
Pipeline, trigger, deployment, policy and optional retention definitions are read
from the committed **`ci/config.json`**. There is no project JSON editor and no
retention form on that page; administrator retention defaults remain under
**Admin → Settings → Runs and artifacts**. Page values are resolved when a job
executes, are not stored in new run snapshots, and are withheld from unmerged PR
checks; repository rows may be scoped to ordinary non-PR CI, an authorized protected
branch, or deployments only. Execution and cancellation are per-pipeline JSON;
omitted options use built-in defaults. See
[Server and repository settings](server-settings.md) for a worked example and
[Browser editing and pull requests](repository-workflow.md) for editing/committing
from the web UI.

Commit the [repository pipeline example](examples/ci/repository-pipeline.json) as
`ci/config.json`, prepare the Python Docker image, and adapt its steps to your
project. Validate before committing with `python -m pygithost ci validate`
(add `--rev HEAD` for the committed version), or choose a branch in **CI → Run pipeline**
and select **Check configuration** to see its exact configuration commit and status
without queueing. A missing file creates no run; an invalid file fails
configuration, and a malformed committed file fails closed with CI required and all
direct branches protected until repaired through Git or the server filesystem.
Manual runs always require write access and a runnable pipeline; they never deploy,
and a manual request is rejected if the branch moved after the configuration check.
Host jobs and enabled deployments additionally require administrator authorization
under **Admin → Settings → Trusted CI repositories** using exact `owner/repo` names; wildcards and
malformed entries are rejected.

## Development checks

From the project root, using Python 3.14+:

```sh
python -m unittest discover -v
```

Integration tests execute the real Git HTTP backend and bind a loopback port.
Docker tests are opt-in; see [Additional CI tests](../README.md#additional-ci-tests).

## Restoring a deleted repository

Deleting a repository from the web interface does not erase anything. Each
deletion creates `<deleted_repos_root>/<owner>/<repo>-<timestamp>-<id>/` with:

- the Git directory exactly as it was (for example `project.git/`);
- `data.sqlite`, holding the repository's issues, pull requests, discussions,
  comments, CI runs, steps, artifacts, deployments and settings rows;
- `manifest.json`, recording who deleted it, when, and the original path.

To restore, stop the server, back up the database, and move the Git directory
back to `original_path` from the manifest (no repository with that name may
exist). Then copy the rows back with the `sqlite3` shell, children last:

```sql
ATTACH 'C:/Servidor_Git-deleted/root/project-20261124-130000-ab12cd/data.sqlite' AS a;
BEGIN;
INSERT INTO pull_requests SELECT * FROM a.pull_requests;  -- repeat for each table in a
INSERT INTO pr_comments SELECT * FROM a.pr_comments;
COMMIT;
```

Insert parent tables (`pull_requests`, `issues`, `discussions`, `ci_runs`)
before their child tables (`pr_comments`, `issue_comments`,
`discussion_comments`, `ci_steps`, `ci_artifacts`). To free disk space instead,
delete the archived folder once it is no longer needed.
