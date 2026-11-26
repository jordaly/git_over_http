# Logging and audit trail

PyGitHost writes three kinds of records:

1. **Application log** — lifecycle, CI/deployment warnings and unhandled request
   failures. One JSON object per line by default.
2. **Access log** — one record per HTTP request with method, path, status,
   duration, peer address and authenticated user.
3. **Audit trail** — security-relevant events stored in SQLite (login attempts,
   token changes, user administration, settings changes, runner-token issuance).

The access/audit hooks intentionally omit request bodies, `Authorization` and
`Cookie` headers, query strings, passwords and generated token values. Audit
metadata does include selected values such as usernames, token names and scopes.
Query strings are stripped because they can contain search terms or reset links.
Normal request-failure records use the exception type rather than its message.

This is **not an automatic secret-redaction system**. Application messages,
client-supplied path/metadata and DEBUG tracebacks can contain sensitive text.
Callers must not pass secrets to logging/audit helpers; keep logs private and do
not enable DEBUG in production without reviewing the disclosure risk.

This guide is also rendered under **CI → Documentation → Logging and audit trail**.

## Configuration

These keys live in the startup JSON file and can be edited from
**Admin → Settings → Basic server configuration → Logging**. Changes require a
server restart because the handlers are installed at startup.

| Key | Default | Meaning |
| --- | --- | --- |
| `log_level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`. |
| `log_format` | `json` | `json` for collectors, `text` for terminals. |
| `log_file` | `~/.local/share/pygithost/pygithost.log` (`C:\temp\pygithost.log` on Windows) | Rotating file. Empty or `null` logs to stderr only. |
| `log_max_bytes` | `10485760` | Rotation threshold (minimum 1024), not a strict per-record/file size cap. |
| `log_backup_count` | `5` | Number of rotated files to keep (0–100). **0 disables rotation**, allowing the active file to grow. |
| `access_log` | `true` | Emit one access record per request. |
| `audit_log` | `true` | Write web security events to SQLite. CLI runner-token issuance is audited independently of this flag. |

Example:

```json
{
  "log_level": "INFO",
  "log_format": "json",
  "log_file": "/var/log/pygithost/server.log",
  "log_max_bytes": 10485760,
  "log_backup_count": 5,
  "access_log": true,
  "audit_log": true
}
```

A missing key uses its default, so existing configuration files keep working.
The log directory is created automatically. An unwritable path aborts startup
with a clear error instead of silently dropping logs.

## Application and access records

```json
{"ts":"2026-11-17T10:15:02.431Z","level":"INFO","logger":"pygithost.access",
 "message":"request","event":"http_request","method":"GET","path":"/r/alice/project",
 "status":200,"duration_ms":12.731,"ip":"192.168.16.75","user":"alice",
 "size":18422,"protocol":"HTTP/1.1","request_id":"4f2c..."}
```

- `path` is the URL path only; the query string is never written.
- `user` is present when the request authenticated.
- `request_id` matches the `X-Request-ID` header returned by the REST API.
- Disconnects that never produced a response are logged at `DEBUG` with status
  `499`, so browser preconnects do not flood the file.
- Responses `>= 500` are logged at `WARNING`; the access record is still emitted.
- Git smart-HTTP responses also record the backend's HTTP status and body-byte
  count. Successful clone/fetch/push traffic is visible at `INFO`, not mistaken
  for a disconnected request with no response.

Records remain subject to `log_level`: for example, `ERROR` suppresses INFO access
records. The Git body-byte count excludes HTTP headers; it is not a network-wire
byte total or proof that the client consumed the complete response.

Startup and shutdown emit `event: "server_start"` / `"server_stop"`. Unhandled
request failures emit `event: "request_failure"` with `error_type`.

Useful commands:

```bash
tail -f ~/.local/share/pygithost/pygithost.log
jq 'select(.status >= 500)' ~/.local/share/pygithost/pygithost.log
jq 'select(.logger == "pygithost.access" and .user == "alice")' \
  ~/.local/share/pygithost/pygithost.log
```

Rotated files append `.1`, `.2`, … to the configured filename (for example,
`pygithost.log.1`). The server has no log-download endpoint and does not attach
application logs to CI artifacts automatically. Keep `log_file` outside repository
and static-file directories, with access restricted to administrators.

## Audit trail

Events are stored in the `audit_events` table of the SQLite database:

| Column | Meaning |
| --- | --- |
| `created_at` | UTC timestamp with milliseconds. |
| `actor` / `actor_user_id` | Authenticated user, or `cli`/`system` for non-web actions. |
| `action` | `login`, `logout`, `token_create`, `token_revoke`, `user_create`, `user_password_reset`, `user_status`, `settings_save`, `runner_token_create`. |
| `outcome` | `success` or `failure`. |
| `target` | Username, token name/id, settings action or repository list. |
| `detail` | Short metadata such as `invalid_credentials`, `scopes=read` or `disabled`. |
| `ip` / `user_agent` | Request origin when available. |

Web audit writes are awaited before the response but never break the request:
a failed insert is logged as `event: "audit_failure"` and the operation continues.
CLI runner-token issuance similarly remains successful if auditing fails and
emits a warning. The newly issued token is still returned to the administrator;
the warning never includes its value. Runner-token issuance is attempted even
when the HTTP server's `audit_log` flag is disabled.
The table is append-only from the application; there is no automatic pruning, so
plan retention according to your compliance requirements.

```bash
sqlite3 ~/.local/share/pygithost/pygithost.db \
  "SELECT created_at,actor,action,outcome,target,ip FROM audit_events
   ORDER BY id DESC LIMIT 20;"

sqlite3 ~/.local/share/pygithost/pygithost.db \
  "SELECT created_at,actor,ip FROM audit_events
   WHERE action='login' AND outcome='failure' ORDER BY id DESC LIMIT 20;"
```

Failed logins record the attempted username. The hooks do not record passwords
or generated token values. Web token creation records its *name* and scopes;
runner-token issuance records its name and repository restrictions.

## Operational notes

- `pygithost.database` warns on SQLite busy errors, connection-setup retries,
  statements taking at least one second, and long explicit transactions.
  Diagnostics include connection IDs, operation names, thread/process IDs and
  active local transaction ages—not SQL text or bound values. A listed transaction
  is a possible blocker, not proof that it owns the conflicting lock. External
  processes and uninstrumented connections are not enumerated.
  See [HTTP runner database coordination](http-runner.md).

- Logging is process-wide and thread-safe; a single server process writes the
  file. Do not point two server processes at the same rotating file.
- `DEBUG` enables exception tracebacks on request failures. Those tracebacks can
  include exception text, so keep `DEBUG` out of production unless diagnosing an
  incident.
- Text formatting can produce multiline tracebacks; use JSON for one-record-per-line
  collection. A `log_backup_count` of zero disables file rotation rather than
  providing a bounded active file with no backups.
- The existing `trace_log` setting is separate: it captures `git-http-backend`
  stderr, not PyGitHost logs.
- `source_cleanup_deferred` warns that a remote source file could not yet be
  deleted. Its path remains tracked for retry; the event records only the error
  type, not exception text or bundle contents.
- `settings_pages` writes unknown/new keys back to the startup file when an
  administrator saves the basic form, so the logging block appears there after
  the first save.

## Exporting to Fuente Sentinel

PyGitHost can send operational events to Fuente Sentinel's Release 0.2
ingestion API. Register an application in Sentinel (named **PyGitHost** unless
`PYGITHOST_SENTINEL_APPLICATION` says otherwise) and create an API key with the
`ingest` scope restricted to that application.
Set the following variables in the Git server's service environment and restart
PyGitHost.

| Variable | Value |
| --- | --- |
| `PYGITHOST_SENTINEL_URL` | Sentinel base URL, for example `https://192.168.16.16:8002`. Leave unset to disable export. |
| `PYGITHOST_SENTINEL_KEY` | The application's ingestion key. Store it in a restricted service environment or secret store. |
| `PYGITHOST_SENTINEL_APPLICATION` | Sentinel application name the key is authorized for, defaulting to `PyGitHost`. |
| `PYGITHOST_SENTINEL_ENVIRONMENT` | Deployment name used in Sentinel, defaulting to `production`. |
| `SSL_CERT_FILE` | Optional PEM trust bundle for a private or self-signed Sentinel certificate. System trust is used by default. |

HTTPS validates the server certificate and hostname. Plain HTTP is available
for local testing on loopback.

Check **Clients** for the PyGitHost heartbeat and **Logs** for `server_start`
and `http_request` after making a Git, REST API, or web request. Requests
include a route group, status, and duration in milliseconds. REST API events
carry the response's `X-Request-ID` as their correlation ID. Server failures
can include the exception type. The exporter uses fixed messages and omits
raw URLs, query strings, request bodies, usernames, IP addresses, and
tracebacks. Request durations are log attributes.

The background worker stores batches in a separate
`*.sentinel-*.sqlite3` file beside the PyGitHost database. Each destination
and deployment environment has its own spool and installation ID. The
worker retries transient failures using the same event IDs, honors
`Retry-After`, and waits longer on authentication or application errors.
Permanently rejected events are stored in the spool's `dead_letters` table.

The spool holds up to 20,000 unsent events and 500 recent dead letters.
Spool overflow evicts the oldest informational events first. A full in-memory
queue drops incoming events and reports a count to the local log. Events
already committed to the spool survive a restart. Events still in memory can
be lost if the process is killed or exits while the worker is blocked on an
HTTP request. Shutdown waits up to two seconds for the exporter to persist
queued events for the next run.

### Events and metrics sent to Sentinel

All attributes are low-cardinality scalars. Repository names are `owner/repo`;
usernames, email addresses, IP addresses, raw URLs, file paths, commit messages,
tokens and exception messages are never sent.

| Event | Level | Attributes |
| --- | --- | --- |
| `ci_run_queued` | Information | `repo`, `branch`, `trigger`, `run_number` |
| `ci_run_started` | Information | `repo`, `branch`, `trigger`, `run_number`, `runner` |
| `ci_run_finished` | Information / Warning (`cancelled`) / Error (`failed`, `error`) | `repo`, `status`, `run_number`, `duration_ms`, `runner` |
| `deployment_started` | Information | `repo`, `environment` |
| `deployment_finished` | Information / Warning (`interrupted`) / Error (`failed`, `timed_out`) | `repo`, `environment`, `status`, `duration_ms` |
| `git_push` | Information | `repo`, `refs_updated`, `branch` (single branch only), `outcome` |
| `pull_request_opened` | Information | `repo`, `pr_number` |
| `pull_request_merged` | Information | `repo`, `pr_number` |
| `pull_request_closed` | Information | `repo`, `pr_number` |
| `pull_request_reopened` | Information | `repo`, `pr_number` |
| `pull_request_review` | Information | `repo`, `pr_number`, `state` |
| `audit_<action>` | Information, Warning for failed `login`/`csrf` | `action`, `outcome`, `reason` (only fixed code-like details) |
| `auth_failure` | Warning | `surface`, `method`, `reason` |
| `audit_failure` | Warning | `action`, `error_type` |
| `ci_retention_startup_failure`, `ci_retention_retry_failure`, `ci_retention_refresh_failure` | Warning | `repo`, `error_type` |
| `ci_email_failure`, `deployment_email_failure` | Warning | `repo`, `run_number`, `error_type` |
| `pr_push_record_failure` | Warning | `repo`, `error_type` |
| `source_cleanup_deferred` | Warning | `error_type` |
| `ci_ip_trust_all_enabled` | Warning | none |
| `ci_coordinator_failure` | Error | `repo`, `run_number`, `error_type` |

| Metric | Type | Attributes |
| --- | --- | --- |
| `ci.run.count` | counter | `repo`, `status` |
| `ci.run.duration` | histogram (ms) | `repo`, `status` |
| `ci.run.queue_wait` | histogram (ms) | `repo` |
| `ci.deployment.count` | counter | `repo`, `status` |
| `git.push.count` | counter | `repo`, `outcome` |
| `git.fetch.count` | counter | `repo` |
| `pull_request.event.count` | counter | `repo`, `action` |
| `auth.login.count` | counter | `outcome`, `method` |
| `auth.failure.count` | counter | `surface`, `method` |
| `auth.success.count` | counter | `surface`, `method` |

Each CI execution also emits a `ci run` root span with child spans for
`checkout`, `merge`, `image build`, every configured step, and (for remote
runners) the remote execution and any step timing reported at completion.
Span names longer than 128 characters are truncated.
