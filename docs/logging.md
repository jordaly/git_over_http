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
| `PYGITHOST_SENTINEL_REQUEST_LOGS` | Per-request log volume: `errors` (default) logs only 5xx and unhandled failures, `all` logs every request, `off` logs none. Invalid values fall back to `errors`. |
| `PYGITHOST_SENTINEL_TRACE_SAMPLE_RATE` | Fraction of successful requests sent as traces, from `0` to `1`, default `0.01`. Errors, slow requests, and requests with an incoming sampled `traceparent` are always traced. |
| `PYGITHOST_SENTINEL_SLOW_REQUEST_MS` | Request duration that always produces a `slow_request` Warning and a trace, default `2000`. **`0` disables slow-request detection**; there is no way to mark every request slow. |
| `PYGITHOST_SENTINEL_METRICS` | `on` (default) or `off` for aggregated metrics and gauges. |
| `SSL_CERT_FILE` | Optional PEM trust bundle for a private or self-signed Sentinel certificate. System trust is used by default. |

HTTPS validates the server certificate and hostname. Plain HTTP is available
for local testing on loopback.

Check **Clients** for the PyGitHost registration/heartbeat and **Logs** for
`server_start` after making a Git, REST API, or web request. The exporter sends
a batch `resource` once per connection (`service.name`, `service.version`,
`deployment.environment.name`, `client.id`, `host.name`, `os.type`,
`process.pid`, `session.id`); events, metrics, and spans inherit it. Heartbeats
include the application version, machine, operating system, process ID, and
attributes for memory usage, spool backlog, and dropped events.

### Startup registration

When the worker starts it sends `POST /api/v1/clients/register` once with the
same identity fields as a heartbeat plus a flat `metadata` object:
`platform`, `port`, `url_prefix`, `ci_trust_all` (bool),
`remote_runner_enabled` (bool; the HTTP runner API is always mounted, so this
is `true`), `request_logs`, and `trace_sample_rate`.
Registration is not buffered and a failure is ignored, exactly like a
heartbeat; the next heartbeat still proves the installation is online.

### Events

All attributes are low-cardinality scalars. Repository names are `owner/repo`;
usernames, email addresses, IP addresses, raw URLs, file paths, commit messages,
tokens, exception messages, and tracebacks are never sent.

| Event | Level | Attributes |
| --- | --- | --- |
| `server_start` / `server_stop` | Information | none |
| `server_error` | Error | `error_type` |
| `http_request` | Information | `route_group`, `status`, `duration_ms` (only in `all` mode) |
| `request_failure` | Error | `route_group`, `status`, `duration_ms`, `error_type` |
| `slow_request` | Warning | `route_group`, `status`, `duration_ms` |
| `ci_run_queued` | Information | `repo`, `branch`, `trigger`, `run_number` |
| `ci_run_started` | Information | `repo`, `branch`, `trigger`, `run_number`, `runner` |
| `ci_run_finished` | Information (`success`) / Warning (`cancelled`, `interrupted`) / Error (`failed`, `error`) | `repo`, `status`, `run_number`, `duration_ms`, `runner` |
| `deployment_started` | Information | `repo`, `environment` |
| `deployment_finished` | Information / Warning (`interrupted`) / Error (`failed`, `timed_out`) | `repo`, `environment`, `status`, `duration_ms` |
| `git_push` | Information | `repo`, `refs_updated`, `branch` (single branch only), `outcome`, `source` (`push` or `pull_request_merge`) |
| `pull_request_opened` | Information | `repo`, `pr_number` |
| `pull_request_merged` | Information | `repo`, `pr_number` |
| `pull_request_closed` | Information | `repo`, `pr_number` |
| `pull_request_reopened` | Information | `repo`, `pr_number` |
| `pull_request_review` | Information | `repo`, `pr_number`, `state` |
| `audit_<action>` | Information, Warning for failed `login`/`csrf` | `action`, `outcome`, `reason` (only fixed code-like details) |
| `auth_failure` | Warning | `surface`, `method`, `reason` (malformed/invalid credentials only; see below) |
| `audit_failure` | Warning | `action`, `error_type` |
| `slow_db_operation` | Warning | `operation` (code-level name), `duration_ms` |
| `ci_retention_startup_failure`, `ci_retention_retry_failure`, `ci_retention_refresh_failure` | Warning | `repo`, `error_type` |
| `ci_email_failure`, `deployment_email_failure` | Warning | `repo`, `run_number`, `error_type` |
| `pr_push_record_failure` | Warning | `repo`, `error_type` |
| `source_cleanup_deferred` | Warning | `error_type` |
| `ci_ip_trust_all_enabled` | Warning | none |
| `ci_coordinator_failure` | Error | `repo`, `run_number`, `error_type` |
| `log_warning` / `log_error` | Warning / Error | `logger`, `event` (fixed name from the record's `event` extra), `error_type`, `template` (see logging bridge) |

An unauthenticated Git or API probe is not an auth failure: clients send one
request without credentials, receive the 401 challenge, and retry. Those
requests only count `auth.challenge.count` (attribute `surface`). Events and
`auth.failure.count` are reserved for malformed or invalid credentials.

### Metrics

Counters use unit `{event}` and histograms use unit `ms` unless noted. All are
delta measurements aggregated in-process and flushed every 60 seconds.

| Metric | Type | Attributes |
| --- | --- | --- |
| `http.server.request.count` | counter | `route_group`, `status_class` (`1xx`…`5xx`) |
| `http.server.request.duration` | histogram (ms) | `route_group`, `status_class` |
| `ci.run.count` | counter | `repo`, `status` |
| `ci.run.duration` | histogram (ms) | `repo`, `status` |
| `ci.run.queue_wait` | histogram (ms) | `repo` |
| `ci.deployment.count` | counter | `repo`, `status` |
| `git.push.count` | counter | `repo`, `outcome`, `source` (`push` or `pull_request_merge`) |
| `git.fetch.count` | counter | `repo` |
| `git.backend.duration` | histogram (ms) | `service` (`upload-pack`, `receive-pack`, `info-refs`, `other`), `outcome` (`success`, `client_error`, `server_error`, `error`) |
| `db.operation.duration` | histogram (ms) | `operation` (code-level name, never SQL) |
| `db.lock_wait.duration` | histogram (ms) | `operation` (time a statement blocked before SQLite reported BUSY) |
| `pull_request.mergeability.duration` | histogram (ms) | `outcome` (`clean`, `conflict`, `up_to_date`, `closed`, `merged`, `unknown`, `error`) |
| `pull_request.event.count` | counter | `repo`, `action` |
| `auth.challenge.count` | counter | `surface` (`git`, `api`) |
| `auth.login.count` | counter | `outcome`, `method` |
| `auth.failure.count` | counter | `surface`, `method` |
| `auth.success.count` | counter | `surface`, `method` |
| `log.records.count` | counter | `level` (`warning`, `error`), `logger` |
| `log.suppressed.count` | counter | `logger` (records hidden by the 60 s rate limit) |

`git.fetch.count` is incremented exactly once per fetch or clone: on the
`GET .../info/refs?service=git-upload-pack` advertisement. That request starts
every smart-HTTP fetch, and the later `POST .../git-upload-pack` requests belong
to the same operation. The counter is recorded only after authentication,
repository-bound-token checks, and resolution of an existing repository, and it
uses the repository's canonical `owner/repo` rather than the request path.

`git_push` includes merges performed through the pull-request UI/API; use the
`source` attribute to separate them from real Git pushes.

Metric names are validated and each interval is capped at 500 distinct series to
bound cardinality. Metric attribute values never come from unauthenticated or
unvalidated input.

### Spans and traces

Every request contributes the HTTP metrics above. Sampled requests produce a
`server` span named `<METHOD> <route_group>`; the method is normalized to
`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, or `OTHER`, so a
client cannot choose an unbounded span name. Errors and slow requests are always
traced.

An incoming W3C `traceparent` header (`00-<32 hex>-<16 hex>-<2 hex>`) is
validated strictly. When valid, the server span joins the caller's trace: the
request's trace ID is reused and the incoming span becomes its parent. A sampled
flag of `01` forces tracing even when `PYGITHOST_SENTINEL_TRACE_SAMPLE_RATE` is
`0`. Invalid, all-zero, or unsupported-version values are ignored. PyGitHost does
**not** echo the server `traceparent` back: responses are streamed before
request-end telemetry runs, so a response header would require buffering every
response.

Each CI execution also emits a `ci run` root span with child spans for
`checkout`, `merge`, `image build`, every configured step, and (for remote
runners) the remote execution and any step timing reported at completion.
Span names longer than 128 characters are truncated. Git backend, database, and
mergeability timings are metrics only because no request or CI trace span is
available at those points.

### Gauges

Sampled at each metric flush by the exporter thread; callbacks are cheap,
never raise, and costly queries are cached for five minutes.

| Gauge | Unit | Meaning |
| --- | --- | --- |
| `process.memory.usage` | By | Resident memory of the server process. |
| `sentinel.spool.pending` | `{event}` | Unsent items in the local spool. |
| `ci.runs.queued` | `{run}` | Queued CI runs (`CIManager.pending`). |
| `ci.runs.active` | `{run}` | Running CI runs (`CIManager.active`). |
| `http.server.active_requests` | `{request}` | Requests currently being handled. |
| `db.size` | By | Main SQLite file plus its `-wal` file. |
| `disk.repositories.free` | By | Free bytes on the repositories filesystem. |
| `disk.database.free` | By | Free bytes on the database directory filesystem. |
| `repositories.count` | `{repository}` | Existing repositories (cached). |
| `sessions.active` | `{session}` | Non-expired, non-revoked web sessions (cached). |
| `ci.remote_runner.last_seen_age` | s | Seconds since the last remote-runner claim or heartbeat; absent before any runner activity. |

### Logging bridge

While the exporter runs it installs a `logging.Handler` on the `pygithost`
logger and removes it on shutdown. Records at `WARNING` and above become
`log_warning` / `log_error` events with these attributes:

- `logger`: the record's logger name (`pygithost.ci`, …).
- `event`: the record's `event` extra when it matches `^[a-z_]{1,64}$` and is
  not already sent explicitly by a call site (for example `server_start`,
  `request_failure`, `ci_email_failure`, `audit_failure`); explicit events are
  skipped so one condition is not reported twice.
- `error_type`: the `error_type` extra, or the `exc_info` exception class name.
- `template`: the raw `record.msg` **only** when the call passed `%`-style
  arguments (fixed text, truncated to 256 characters). The formatted message is
  never sent, so values interpolated into it stay local.

Repeat records with the same `(logger, template or event)` are limited to one
event per 60 seconds; the rest increment `log.suppressed.count`. Every eligible
record increments `log.records.count`. Records from `pygithost.sentinel` are
ignored to prevent recursion.

### Spool and delivery

The background worker stores batches in a separate
`*.sentinel-*.sqlite3` file beside the PyGitHost database. Each destination
and deployment environment has its own spool and installation ID. The
worker retries transient failures using the same event IDs, honors
`Retry-After`, and waits longer on authentication or application errors.
Permanently rejected events are stored in the spool's `dead_letters` table.

The spool holds up to 20,000 unsent items and 500 recent dead letters. Logs,
aggregated metrics, and spans share the spool but are always sent in
single-kind batches to `/api/v1/logs/batch`, `/api/v1/metrics/batch`, and
`/api/v1/traces/batch`. Spool overflow evicts the oldest informational items
first. A full in-memory queue drops incoming items and reports a count to the
local log. Items already committed to the spool survive a restart. Items still in memory can
be lost if the process is killed or exits while the worker is blocked on an
HTTP request. Shutdown waits up to two seconds for the exporter to persist
queued events for the next run.

### Privacy guarantees

The exporter sends only fixed event names, fixed reason codes, exception class
names, `owner/repo`, branch names, run numbers, CI step/deployment names,
durations, counts, booleans, and low-cardinality metric attributes. It never
sends usernames, email addresses, IP addresses, user agents, raw request URLs or
paths, query strings, request or response bodies, credentials/tokens, commit
messages, file paths, exception messages, or tracebacks. The one path-like value
is the fixed, administrator-configured `url_prefix` in startup registration
metadata. Server-side Sentinel redaction is a safety net, not a guarantee.

### What to watch in Sentinel

- `ci.run.count` split by `status` — failures/timeouts, and `interrupted` after a
  restart or shutdown.
- `auth.failure.count` by `surface` — malformed or invalid credentials. A rise
  without a matching rise in `auth.success.count` suggests credential stuffing
  or a broken client; `auth.challenge.count` is normal client probing.
- `http.server.request.count` with `status_class=5xx` — server error rate;
  correlate with `request_failure`, `server_error`, and `log_error`.
- p95 of `http.server.request.duration` by `route_group` — slow web/API/git
  responses; `slow_request` events name the affected route group.
- `sentinel.spool.pending` and `log.suppressed.count` — the exporter is behind or
  the rate limiter is hiding repeated noise.
- `disk.repositories.free` / `disk.database.free` and `db.size` — disk pressure;
  `slow_db_operation` and `db.lock_wait.duration` show database contention.
- `ci.runs.queued` / `ci.runs.active` and `ci.remote_runner.last_seen_age` — CI
  backlog and remote-runner health.
