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

## Repository interface

- The home page searches repository names, owners, and paths with the search box.
  Search is case-insensitive and works without JavaScript; its URL can be bookmarked.
- Repository tabs keep **Code**, **Branches**, **Pull requests**, **CI**, and
  **Artifacts** accessible while browsing files, commits, and pull requests.
- The Code overview shows the latest commit's author, message, short SHA, and
  relative date. File/folder rows include their last commit message and date;
  folder dates reflect changes to their contents. History metadata is cached by
  commit (10 recent snapshots per repository). Cold lookups use at most four Git
  processes at once and cover the first 200 root entries; unavailable metadata is
  shown as a dash rather than a fabricated date.
- The sidebar includes a README-derived About summary, commit/branch/tag counts,
  recent tags with source ZIP links, Git contributors, and Languages. README and
  license navigation leads to a safe README preview and the license text. The
  built-in Markdown preview supports common headings, lists, code fences, inline
  code, bold text, and HTTP(S) links; raw HTML is escaped. It is intentionally not
  a complete GitHub Markdown implementation. Public/private labels, releases,
  stars and forks are not invented when the server does not track those features.
- The Code page's **Languages** sidebar estimates the default branch's language
  percentages by tracked source-file bytes, with a colored distribution bar.
  Detection uses Git tree metadata only—no checkout, compilation, or file-content
  parsing. Common dependency/build folders, generated/minified files, symlinks,
  submodules, binaries with unknown extensions, and documentation/data formats
  are excluded. This is a conservative extension-based estimate, not Linguist.
  SQLite caches results by repository and exact commit (10 recent commits per
  repository), so unchanged commits are not rescanned. Metadata scans are bounded
  to 15 seconds / 32 MiB; unavailable results do not prevent repository browsing.
- File views include folder breadcrumbs, clickable line numbers (`#L42`), Raw,
  Download, Copy contents, commit-pinned Permalink, and file-specific History.
  Raw/download responses preserve original bytes and cannot execute HTML content.
  Text files are displayed in full, with no 5000-line or 1 MiB preview cutoff.
  Syntax highlighting is skipped automatically above 100 KiB or 2000 lines;
  use **Highlight syntax** to opt in directly.
  Highlighting can be disabled again without reloading the file. Line numbers,
  copy, scrolling and downloads remain available without highlighting.
  Binary files show a download prompt instead of an unreadable text preview.
- The **Code** dropdown offers a copyable HTTP(S) clone URL and **Download ZIP**
  for the branch or commit currently being viewed. ZIPs contain tracked source
  files, not Git history or CI artifacts; Git archive attributes such as
  `export-ignore` apply. Branches are resolved to an immutable commit before
  archiving. Downloads use normal repository access controls, are streamed from
  temporary storage, and have a 256 MiB compressed-size / 60-second generation
  limit. Credentials are never embedded in the displayed clone URL.
- **Branches** separates the default branch from other branches, displays latest
  commit details, and supports name search, recently-updated/name sorting, and a
  protected-branch filter. Protection labels reflect the server's configured policy.
- **New pull request** on a branch prefills the source and default target branch.
  New branches can start from a branch, tag, or commit, with suggestions for existing
  branch names.
- Branch deletion requires write access, excludes default/protected branches,
  asks for browser confirmation, and rejects stale revisions rather than deleting
  work pushed since the page was loaded.

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

### Versioned JSON pipelines and named steps

Existing single-command CI settings continue to work. To use named sequential
steps, choose **Named steps** under **What should run?** and enter a JSON array of
`name`/`run` objects. Only the selected command mode is saved. Settings are grouped
into pipeline, triggers, runner, protection, and collapsible optional sections.
**Single command**, **Named steps**, and **JSON in page** are three equal choices
under **What should run?**, sharing one **Save CI settings** button. Turn off
Git-based configuration to edit the server pipeline. JSON in page saves without
creating a repository file or commit. Triggers, runner/image, email and protection
policies use the same form. Command/steps are replaced; supplied JSON environment,
artifact and timeout fields override their form fields; omitted fields use the
form values. The selected editor is remembered after saving. As an
administrator setting, an inline timeout can raise the server limit. Invalid JSON
is redisplayed for correction without changing saved settings.

Alternatively, enable **Load .pygithost-ci.json from Git** in
the repository's server-side CI settings and commit a file such as:

```json
{
  "version": 1,
  "steps": [
    {
      "name": "Test",
      "run": "python -m unittest discover -v"
    },
    {
      "name": "Compile",
      "run": "python -m compileall -q pygithost"
    }
  ],
  "artifacts": {
    "paths": ["pygithost/__pycache__/*.pyc"],
    "when": "always"
  }
}
```

- Each step starts a **separate shell** in the checkout root, with the configured
  environment. Files persist, but `cd`, `export`, and shell variables do not carry
  over. Docker steps also start separate containers; only the checkout persists,
  not container `/tmp` or other container state.
- Each step has its own status, exit code, duration, and logs. A nonzero exit code
  stops execution and skips remaining steps. The timeout is a total budget for
  checkout, PR merge preparation, and all steps—not a new budget per step.
- `command` and `steps` are mutually exclusive. A file may also contain `env`,
  `artifacts`, and `timeout_seconds`; version defaults to `1`. Unknown fields are
  rejected. There are at most 64 steps, with commands up to 8192 characters.
- Server settings still select **triggers, branch filters, runner/image, email,
  and protection policies**. A repository timeout cannot exceed the server's
  configured timeout. Repository `env`, when supplied, replaces the server's
  ordinary job environment mapping; it cannot override built-in variables.
- The file is read from the exact recorded commit and snapshotted when queued.
  **PR checks use the recorded target/base commit's file**, not the PR head's
  potentially unreviewed pipeline. Pipeline changes in a PR take effect after
  merging; push/manual runs use the selected commit's file.
- Opting in requires a regular `.pygithost-ci.json` file, limited to 64 KiB.
  Missing, malformed, or disallowed configuration creates a failed configuration
  run; it never silently falls back to the server command. Successful enqueueing
  snapshots the effective configuration, so reruns use that same configuration.

### Optional merge and branch protections

Both settings live in the repository's **CI settings**, are administrator-only
when authentication is enabled, and default to **off**:

- **Require successful CI before merging**: the newest qualifying PR check for
  this PR's exact current source **and** target commit must be successful.
  Missing, stale, pending, failed, cancelled, interrupted, or timed-out checks
  block merging. Manual/push runs and checks from another PR do not qualify.
  Enable PR opened, updated, and reopened triggers so checks are produced.
  The merge endpoint enforces this independently of the UI; the Git ref update
  atomically verifies source and target SHAs to reject concurrent branch changes.
- **Block direct pushes**: rejects HTTP pushes to configured branch patterns,
  including creations, force-pushes, and deletions. Other branches remain writable;
  approved PR merges through the server remain allowed. Protected branches cannot
  be created/deleted through the branch UI either. Patterns are case-sensitive,
  one per line (for example `main` and `release/*`). Initialize the branch before
  enabling protection.

These controls are independent: enable both to require a PR and passing CI.
Repository JSON cannot disable either setting. Push protection adds a temporary
pre-receive hook without replacing repository hooks on disk; existing hooks still
run for allowed pushes. Chaining an existing pre-receive hook requires Git 2.36+
(`git hook run`). Local filesystem access, SSH pushes, and other Git servers are
outside this HTTP server's enforcement boundary. Host CI is trusted-code-only
and can access the server filesystem, so it is not a security boundary against
malicious jobs modifying refs directly.

### Downloadable artifacts

Configure relative file globs in **Artifacts** or the JSON file's `artifacts.paths`.
`artifacts.when` accepts `always` (default), `success`, or `failure`. Artifacts are
collected after execution and before checkout cleanup, including after failures
or timeouts as selected; cancelled runs do not collect artifacts. The run page
offers one ZIP download. No test output, JUnit XML, or artifact content is parsed.
The repository's **Artifacts** tab lists available archives across runs, with
source branches, commit IDs, sizes, expiration times, and direct downloads.
Downloads also remain available on each CI run page.

- Use file patterns such as `dist/*` or `reports/**/*.xml`; matched directories
  are not implicitly archived. Missing matches simply produce no download.
- Regular private files only: symlinks, junctions, hardlinks, `.git` contents,
  absolute paths, and parent traversal are excluded/rejected.
- Limits: **20 MiB uncompressed / 1000 files per run**, 32 patterns, and 10,000
  matched entries. Collection errors/limit violations fail the run explicitly.
- Archives are stored in SQLite, not publicly served from the static directory.
  Downloads use the same access controls as CI logs, and are attachments only.
- Artifacts expire after **7 days**, or earlier when their run is pruned. Expired
  records are removed at startup and artifact access/collection. SQLite may retain
  freed database pages for reuse; these are logical retention limits, not an OS
  filesystem quota.

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
verification remain enabled by default for both STARTTLS and implicit TLS. The SMTP hostname
must match the certificate's Subject Alternative Name. Clear the field to return
to system trust only, save, and use **Send test email** to check the result.

Alternatively, check **Trust server certificate without verification (insecure)**
and save to connect without pasting a certificate. This is disabled by default
and applies only to SMTP, including test messages. TLS encryption remains required,
but certificate-chain, expiry, and hostname verification are disabled; an attacker
could impersonate the mail server and steal SMTP credentials. The checkbox takes
precedence over pasted certificates. Uncheck it and save to restore verification.

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
465); TLS certificate verification is enabled unless explicitly disabled using the
web checkbox described above. Authentication is optional
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
