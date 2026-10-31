# Getting started

[Back to README](../README.md)

This guide starts a local instance before exposing it to other machines. PyGitHost
uses Python's standard library; Git must be installed separately. CI Docker runners
also require a local Linux Docker daemon and a prepared image.

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

### Essential configuration fields

| Field | Purpose / guidance |
| --- | --- |
| `host`, `port` | Bind address and port. An empty host listens on all interfaces; use `127.0.0.1` for local access only. |
| `git_project_root` | Repository storage directory. The server account needs access to repositories and write permission for mutations. |
| `git_http_backend` | Path to the Git Smart HTTP backend executable, not the main `git` executable. |
| `db_path` | SQLite database for users, sessions, settings, CI history, and artifacts. Keep it outside publicly served directories. |
| `url_prefix` | Git HTTP endpoint prefix; defaults to `/git`. This is not a prefix for all web-interface routes. |
| `filter_ips` | Enables client IP filtering; defaults to `true`. |
| `allowed_client_ips` | Explicit client IP addresses. Replace the generated example addresses with your own; do not assume CIDR support. |
| `require_auth` | Enables authentication; defaults to `false`. Without it, the IP allowlist is also the administration security boundary. |
| `session_cookie_secure` | Set to `true` when serving the browser interface through HTTPS. Secure cookies are not suitable for ordinary local HTTP. |
| `static_root` | Directory containing this checkout's `static/` assets. Review it if moving the checkout or configuration. |
| `trace_log` | Optional Git backend trace destination; restrict access to diagnostic logs. |

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
| Git clone/push fails | Confirm `git_http_backend` exists, copy the repository's clone URL, and check credentials, token scope, filesystem permissions, and branch protection. |
| Login does not persist | Check whether `session_cookie_secure` is enabled while accessing the site over plain HTTP. |
| Styles or scripts are missing | Check that `static_root` points to this checkout's `static/` directory. |
| PR creation fails with an author foreign-key or NOT NULL constraint | Back up the database and restart the updated server. Startup migrates legacy NOT NULL authors to nullable authors while preserving PR history. Do not create user ID 0 or disable foreign keys. |
| CI command cannot find a tool | Host jobs have a restricted environment; Docker jobs require tools in the prepared image and have no network. |

## Manage settings in the browser

Open **Admin → Settings** to edit the display name, basic server configuration,
and server-wide CI variables and retention. Unlike appearance/CI preference changes, basic server
configuration is saved to the startup file for the **next restart**. Review allowed
IPs, credentials, cookie security and storage paths before restarting; saving paths
does not migrate data. Instances started programmatically without a config file
show the basic fields read-only.

Repository **CI → Settings** supplies per-pipeline execution JSON, environment variable
rows and retention controls. Leave **Use server default** selected to inherit an
individual retention limit. Execution and cancellation are per-pipeline JSON;
omitted options use built-in defaults. See [Server and repository settings](server-settings.md)
for a worked example and [Browser editing and pull requests](repository-workflow.md)
for editing/committing from the web UI.

An unconfigured repository automatically looks for `.ci-config.json`. Commit the
[repository pipeline example](examples/ci/repository-pipeline.json) under that name,
prepare the Python Docker image, and adapt its steps to your project. Manual runs
always require write access and a runnable pipeline; they never deploy.

## Development checks

From the project root, using Python 3.14+:

```sh
python -m unittest discover -v
```

Integration tests execute the real Git HTTP backend and bind a loopback port.
Docker tests are opt-in; see [Additional CI tests](../README.md#additional-ci-tests).
