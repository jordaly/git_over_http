# git_over_http

A dependency-free asynchronous Git Smart HTTP server with a web interface,
authentication, repository browsing, branches, tokens, users, and pull requests.

## Documentation

- [REST API](docs/api.md): authenticated `/api/v1` reads and safe writes, permissions,
  repository browsing/search/diffs, discussions, read-only CI settings, CI
  automation/logs/artifacts, deployment diagnostics and advisory preflight,
  pagination, idempotency and OpenAPI.
  Also available at **`/api/docs`**. Webhooks are deferred.
  See [CI API safety and tests](docs/api.md#ci-api-safety-and-test-coverage)
  for regression coverage and local test commands.

- [Getting started](docs/getting-started.md): local setup, configuration, first
  login, Git access, and troubleshooting.
- [Repository interface](#repository-interface): browsing files and managing branches.
- [Server and repository settings](docs/server-settings.md): administrator defaults,
  repository environment variables, retention and restart-required configuration.
- [Logging and audit trail](docs/logging.md): JSON application/access records,
  rotating files, SQLite security events and configuration keys.
- [Browser editing and pull requests](docs/repository-workflow.md): single-file editing,
  Web IDE, search, commit/discard, PR creation and permalinks.
- [Continuous integration](#continuous-integration): runners, pipelines, protections,
  artifacts, and notifications.
- [Pipeline guide](docs/pipelines.md): repository `ci/config.json` setup, JSON
  examples, local validation, variables, artifacts, trust and troubleshooting.
- [Repository CI directory](docs/pipelines.md#repository-ci-directory): `ci/config.json`,
  helper scripts, referenced files and migration from root-level files.
- [Every CI option](docs/ci-options.md): types, built-in defaults, examples, independence,
  limits, and complete JSON configurations.
- [Repository CI migration](docs/ci-migration.md): moving database-only definitions
  into `ci/config.json`, field changes, trust and a safe migration checklist.
- [Multiple-pipeline examples](docs/pipeline-examples.md): independent checks,
  Git-managed pipelines, and staging/production deployments.
- [Automatic deployment walkthrough](docs/automatic-deployment.md).
- [Retention and pagination](docs/ci-retention.md).
- [HTTP Docker runner](docs/http-runner.md): Ubuntu Docker setup, installed test-server
  paths, authorizing repositories, dependency images, service management and troubleshooting
  while GitHost/deployments stay on Windows.
- [Install a remote runner](docs/remote-runner-setup.md): server requirements and
  step-by-step provisioning, policy, credentials, service and smoke validation.
- [Docker profiles](docs/docker-profiles.md): pipeline resource requests, safe
  defaults, administrator ceilings, networking, writable directories and named secrets.
- [CI transfer limits](docs/ci-limits.md): configurable source (100 MiB default),
  logs, artifacts, file counts and preparation/transfer timeouts.
- [Remote runner design](docs/remote-ci-runners.md): original proposal and future extensions.

The full reference, recipes, deployment/retention guides and complete JSON examples
are also rendered directly in each repository's **CI → Documentation** page.

> **Security:** generated configuration listens on all interfaces and disables
> authentication by default. IP filtering is enabled, but its generated allowlist
> contains example private-network addresses. Review these settings before starting
> the server. Use the loopback-only setup below for a first run.

## Requirements

- Python 3.14 or newer (the UI renderer uses Python t-strings)
- Git. `git-http-backend` is used when present; otherwise a built-in pure-Python
  replacement serves Git Smart HTTP (see [Getting started](docs/getting-started.md)).

## Configuration and startup

Generate a platform-specific configuration file:

```sh
python server.py generate-config --platform Linux
```

If the file already exists, generation refuses to overwrite it. Edit the existing
file or use `--config` to choose another destination; use `--overwrite` only when
you intentionally want to replace it. Use `--print` to inspect generated defaults
without writing a file. Supported platforms are `Linux`, `Darwin`, and `Windows`.

Review `pygithost.config.json`, particularly `git_project_root`,
`git_http_backend`, `db_path`, and the allowed client IPs, then run:

```sh
python server.py run --config pygithost.config.json
```

The package entry point is equivalent:

```sh
python -m pygithost run --config pygithost.config.json
```

For a safe local setup and a configuration reference, follow
[Getting started](docs/getting-started.md). Configuration changes require a server
restart; settings saved through the web interface take effect as documented below.

## Development checks

Using Python 3.14 or newer, install the development tools and enable the local
Git commit hook (once per clone):

```sh
python -m pip install -r requirements-dev.txt
python -m pre_commit install
python -m pre_commit run --all-files
```

Activate your virtual environment first, if using one. The first run downloads
the pinned hooks and creates isolated environments. Hooks include:

- **Ruff:** Python linting, import sorting, and formatting (Python 3.14, 100 columns).
  Safe lint fixes and formatting run automatically; review and re-stage changes.
- **mypy:** strict whole-application type checking, with no baseline filtering.
  All diagnostics, including existing typing debt, block commits.
- Python syntax (including t-strings), JSON/YAML/TOML validity, merge conflicts,
  private keys, whitespace, final newlines, LF line endings, case conflicts,
  broken symlinks, and newly added files larger than 1,000 KiB.

Vendored assets are excluded from whitespace rewriting. Ruff has narrowly scoped
exceptions for the legacy application's dynamic configuration globals and
compatibility imports.

Run individual tools directly:

```sh
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m unittest discover -q
```

Strict mode requires function annotations, checks untyped function bodies, and
rejects untyped calls, implicit generic arguments, and `Any` returns, among other
checks. The hook checks all of `pygithost`, `server.py`, and `hl_mappings.py` on
every commit, including configuration-only commits. Tests are linted/formatted
but are not in the mypy scope. Type errors must be fixed before the strict hook
will pass; there is no grandfathering or baseline-update command. Shared SQL row
types, JSON storage values, and runner interfaces are documented in
`pygithost/database_types.py` and `pygithost/runner_types.py`. JSON and foreign
function boundaries still require runtime validation; annotations do not replace
the existing permission, schema, or resource-limit checks.

The full test suite is deliberately not run on every commit. None of these tools
adds runtime dependencies to the server.

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

The integration tests use the real `git-http-backend` when it is installed and bind a
loopback port. `tests/test_git_http_fallback.py` runs real clones and pushes through
the built-in Python backend.
`tests/test_git_http_conformance.py` runs the same wire-level request matrix and git
client workflows against every Git HTTP backend and compares each one with
`git-http-backend` byte for byte. To compare backend performance:

```sh
.venv/bin/python scripts/bench_git_http.py          # add --quick for a short run
```

Per-option CI validation and configuration-mapping tests run with the regular suite.
To also check documentation and CI example highlighting in a real Chromium
browser, opt in with an installed executable:

```sh
PYGITHOST_TEST_BROWSER=chromium .venv/bin/python -m unittest tests.test_ci_docs.DocumentationBrowserTests -v
```

This starts a disposable local test server and checks the browser-generated Prism
tokens, not just HTML attributes. The browser harness disables Chromium's sandbox
only for the disposable local test; it is not a production browser configuration.
Docker integration is separately opt-in (see below), Windows process tests require
Windows, and SMTP/TLS delivery tests use mocks rather than sending real mail.

## Repository interface

**Admin → Settings** now exposes basic network/security/storage configuration as
well as appearance, server-wide CI variables and retention. Basic configuration saves target
the startup JSON file and require a restart; they do not rebind the running server
or switch its database. **CI → Settings** manages repository environment variables
and secrets only, optionally scoped to a pipeline and to ordinary, protected-branch,
or deployment-only use. Values are resolved when a job executes, not copied into new
stored run snapshots, and are withheld from all unmerged pull-request checks.
Pipeline, trigger, deployment, policy and optional retention definitions are read
from committed **`ci/config.json`**; there is no project JSON editor or project
retention form. See
[Secrets, retention and administrator defaults](docs/ci-options.md#secrets-retention-and-administrator-defaults).

Every repository reads **`ci/config.json`** from the recorded commit. A missing file
means no automatic run; an invalid file produces a configuration failure. The simple
form creates a built-in Docker pipeline named `ci` with push, pull-request and
manual triggers. Use the full grouped document for named pipelines, deployments,
policies or project retention. Referenced pipeline files must also be under `ci/`.
Saved database definitions are not read; migrate them before upgrading. Existing
database-backed page values remain available until the variables form is saved.
Historical snapshots that embedded page credentials are not replayed as page
values, and new stored run snapshots exclude them. Validate before committing with
`python -m pygithost ci validate`; add `--rev HEAD` to check the committed files
instead of working-tree changes. See
[Repository configuration](docs/ci-options.md#repository-configuration) and
[Migration](docs/ci-migration.md).

Host jobs and every enabled deployment additionally require administrator
authorization in **Admin → Settings → Trusted CI repositories** (exact
`owner/repo`, comma- or newline-separated). Wildcards, patterns and malformed
names are rejected. This trust check is separate from repository configuration and
is repeated for reruns and historical snapshots. Missing authorization fails the
queued run at configuration while preserving a parseable document's declared branch
policies. Ordinary Docker and remote-Docker pipelines do not require it.

### Browser editing: single file or Web IDE

The repository UI offers two GitLab-style entry points, both powered by locally
bundled Monaco (no CDN):

- From a file, choose **Edit → Edit single file** for a focused editor inside the
  repository page. Use **Write** and **Preview changes**, then enter a message and
  **Commit changes**, or **Cancel** to return to the file.
- From a file, choose **Edit → Open in Web IDE**. From a repository, directory,
  or pull request, choose **Code → Open in Web IDE**. The current branch and
  file/folder are preserved; pull requests open their source branch. Pressing
  **.** on those browsing pages also opens the IDE (except while typing).
- In the single-file editor, **Open in Web IDE** expands the existing editor
  without reloading: pending edits, the model and undo history are retained.

The full-window workspace provides an **Explorer**, collapsible folders, filename
filter, open-file tabs, a **Source Control** panel with change counts and per-file
diff/discard actions, and a branch/cursor status bar. The branch name in the
status bar opens a searchable branch picker, like the language selector; switching
discards pending changes after a confirmation. Closing a tab does **not**
discard its changes: reopen it from Explorer or Source Control. Open tabs stay
open after committing. The Explorer header offers **New file** and **New folder**;
new folders include an empty `.gitkeep` file because Git does not track empty
directories. Both remain pending until committed and can be discarded. The
Explorer shows folders before files at every level, with folder, code-file and
text-file icons. Folders fetch their contents only when opened, and wide folders
add entries in chunks as you scroll, keeping large repositories responsive. The
Explorer is built from the branch snapshot without waiting for the editor engine,
so the file list appears while Monaco is still starting. Drag the splitter
between the panel and editor to resize it (arrow keys work too; double-click
resets), and the width is remembered. **Collapse all folders** closes the entire
tree (and clears the filename filter). Add files with the toolbar, select a file
and use **Delete file** (also available in single-file mode), or hover a folder
and use its trash action to mark every file under it for deletion. Deleting is
pending until committed.

The activity bar's **Search** tool (**Ctrl/⌘+Shift+F**) searches file contents in
the branch snapshot, overlaid with pending edits/new files and excluding pending
deletions. Matching results open their file at the matching line. Search is
literal and case-insensitive, with a 200-line result limit, 256 KiB Git-output
limit and 10-second timeout; narrow the query when results are limited. It does
not execute external text converters. The Explorer's filename filter and
**Go to file** remain available separately.

Use **Ctrl/⌘+P** (or **Go to file**) to find files, **Ctrl/⌘+Shift+E** for Explorer,
and **Ctrl/⌘+Shift+G** for Source Control. **Ctrl/⌘+S** keeps your current panel,
file and focus; it does not create a commit. Use Source Control when you are
ready to commit. **Preview changes**
compares a file against its base; **Write** returns to editing. Word wrap is
enabled by default; toggle it with **Alt+Z** or the status-bar button.

- **Commit changes** saves all pending changes in one commit on the selected
  branch. Enter a commit message first. Commits use the signed-in username and
  a generated `@users.pygithost.local` address, not a verified personal email.
- **Discard file changes** restores one file. **Discard all** restores
  the browser workspace without changing Git history or server-side files.
- Edits live in browser memory, not on the server or in persistent browser
  storage. Leaving/reloading the page warns about pending changes. Do not close
  the tab before committing or copying work you want to keep.
- Write scope, CSRF checks, direct-push branch protections and repository receive
  hooks apply to commits. Successful commits use the same push/PR CI scheduling
  as HTTP pushes. Create a feature branch under **Branches** when direct commits
  to your target are blocked, then open a pull request.
- If another push changes the branch, committing is rejected and your browser
  edits remain available. Copy your edits before reloading; there is no automatic
  merge/rebase. A failed CI scheduling attempt is reported separately from a
  successful Git commit.

The first version supports existing, nonempty branches and UTF-8 text files up
to 1 MiB each, at most 100 changed files and 5 MiB of content per commit (the HTTP
form also has a 10 MiB encoded limit). The Explorer loads directories on demand,
so repository size is not limited by the file listing; **Go to file**, the
filename filter and new-path validation use an optional flat index capped at
200,000 files. Symlinks/submodules cannot be edited; binary files cannot be
opened. Branches checked out in a server-side working tree cannot be committed
through the IDE, avoiding a desynchronized checkout. Tags/historical commits
are read-only; editing never silently switches them to the default branch. This
is a Monaco-based workbench, not the full VS Code runtime: no extension
marketplace, terminal, persistent drafts, staging, or automatic merge/rebase.
Create/manage branches and pull requests through the linked repository pages.

Backend regression tests run with the normal suite. To exercise actual Monaco
editing, diff review, discard, single-to-multi-file expansion, tabs, quick file
search, branch context and commits through Chromium:

```sh
PYGITHOST_TEST_BROWSER=chromium .venv/bin/python -m unittest tests.test_webide -v
```

Administrators can customize the browser favicon and the name in the top-left
header under **Home → Admin: Settings → Appearance**. Both are stored in the
database, apply to all pages immediately, and survive restart. The favicon
defaults to the bundled `favicon.ico` (looked up next to the `static/` directory)
and can be replaced with an ICO, PNG, GIF, JPEG, WebP or SVG file up to 512 KiB;
**Use default** restores the bundled icon. Leave the display name blank to restore
`pygithost`. The limit is 80 characters; repository URLs and email sender settings
are unchanged. With authentication disabled, the IP allowlist protects access to
these settings, as with other administration pages.

- The home page searches repository names, owners, and paths with the search box.
  Search is case-insensitive and works without JavaScript; its URL can be bookmarked.
  Filesystem discovery runs off the request loop so a slow disk scan does not
  block other requests. Repository overviews load independent Git metadata,
  README, language estimates, and CI status concurrently; commit-keyed metadata
  caches remain in use, while branch/tag and CI status reads stay live.
  Database startup automatically adds indexes for CI branch/status/event and
  warning filters, deployment/PR history, pending notifications, open-PR branch
  lookups, and user-name ordering. Existing primary-key indexes already cover
  settings and artifact/run lookups; no manual index setup is needed. The first
  startup after upgrading a large database can take longer while indexes build.
- Repository tabs keep **Code**, **Branches**, **Pull requests**, **CI**, and
  **Artifacts** accessible while browsing files, commits, and pull requests.
- The Code overview shows the latest commit's author, message, short SHA, and
  relative date. File/folder rows include their last commit message and date;
  folder dates reflect changes to their contents. History metadata is cached by
  commit (10 recent snapshots per repository). Cold lookups use at most four Git
  processes at once and cover only the entries on the current page; unavailable
  metadata is shown as a dash rather than a fabricated date.
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
  commit details, and supports name search, recently-updated/name sorting, and
  protected/merged filters. Protection labels reflect the server's configured policy.
  Branches whose commits are all in the default branch carry a purple **Merged**
  label, so leftover pull-request branches are easy to clean up.
- **New pull request** on a branch prefills the source and default target branch.
  New branches can start from a branch, tag, or commit, with suggestions for existing
  branch names.
- PR creation requires write access and two different existing branches. Signed-in
  requests retain their author; with authentication disabled, author is empty rather
  than a dummy user. See [Browser editing and pull requests](docs/repository-workflow.md)
  for the complete workflow and permalink behavior.
- Branch deletion requires write access, excludes default/protected branches,
  asks for browser confirmation, and rejects stale revisions rather than deleting
  work pushed since the page was loaded.

## Continuous integration

Repositories define CI in committed **`ci/config.json`**. Commit the
[pipeline file](docs/examples/ci/repository-pipeline.json) directly as
`ci/config.json`; the obsolete Settings reference
`{"version":1,"file":"ci/config.json"}` is not a valid configuration root. A missing
file means no automatic run; a malformed file produces a configuration failure.
A malformed file also **fails closed** for repository protection: merges require CI
and all direct branches remain protected until an operator repairs the committed
file through Git or the server filesystem. Validate before committing with
`python -m pygithost ci validate` (or `--rev HEAD` for the committed version);
there is no web editor, API replacement or saved-definition fallback for repair.

**CI → Settings** manages repository environment variables and secrets only. There
is no page JSON editor, no saved project definition and no project retention form.
Administrator defaults remain under **Admin → Settings**. For multiple named
pipelines, commit the full grouped document with optional repository-wide
`policies` and `retention`. For example:

```json
{
  "version": 1,
  "pipelines": [
    {
      "name": "tests",
      "triggers": {"push": {"enabled": true}},
      "steps": [
        {"name": "Check Python", "run": "python --version"},
        {"name": "Tests", "run": "python -m unittest discover -v"}
      ]
    }
  ],
  "deployments": []
}
```

Each pipeline has its own ordered steps, with individual statuses and logs.
A failed step skips later steps. Files persist between steps, but shell state
does not. Add other independently configured objects to `pipelines`; every object
has its own `name`. There is no shared defaults object; see the
[complete examples](docs/pipeline-examples.md).

Manual runs are always available for runnable pipelines; no trigger flag is needed.
Write access is required
to queue, cancel, or rerun jobs; email retry requires admin access when
authentication is enabled. With authentication disabled, the IP
allowlist is the security boundary, including for CI administration.

**CI → Run pipeline** validates configuration branch-first. Choose a branch and select
**Check configuration** to read its committed `ci/config.json` and referenced files
without queueing a job. The page shows the exact configuration commit SHA and a
status: `valid`, `missing`, `invalid`, `blocked` (administrator trust denied), or
`unavailable`. A manual run is enabled only for a valid or blocked-but-parseable
configuration with a runnable pipeline. Its request carries the validated SHA and
is rejected if the branch moved, so recheck the configuration before queueing
again.

### Execution and security

- Configure execution in each pipeline's committed JSON; omitted options use
  built-in defaults, initially **Docker**.
- **Host** is **trusted-code-only** and is disabled for a repository unless an
  administrator lists its exact `owner/repo` under **Trusted CI repositories**.
  Jobs run as the server's OS user, not in a
  sandbox. A restricted environment prevents accidental credential inheritance,
  but does not prevent filesystem access or access to other processes. Use a
  dedicated unprivileged server account. Do not run untrusted PR code on the host
  runner.
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
  point to the job's temporary directory. Add other necessary variables on the
  project environment page. Committed CI configuration and stored run snapshots
  are plaintext, and job output is not redacted. Page-managed values are resolved
  live at execution rather than stored in new run snapshots, but they can still
  appear in remote job assignments and logs. Do not commit credentials or print
  them in logs.

Jobs expose `CI=true` and `PYGITHOST_OWNER`, `PYGITHOST_REPO`,
`PYGITHOST_REPOSITORY`, `PYGITHOST_EVENT`, `PYGITHOST_REF`, `PYGITHOST_BRANCH`,
`PYGITHOST_COMMIT`, `PYGITHOST_OLD_COMMIT`, `PYGITHOST_PR_NUMBER`,
`PYGITHOST_BASE_BRANCH`, `PYGITHOST_HEAD_BRANCH`, `PYGITHOST_BASE_COMMIT`, and
`PYGITHOST_WORKTREE`, and `PYGITHOST_PIPELINE`. Built-in variable names cannot be overridden.

Step `run` strings support dependency-free placeholders: `{{ env.NAME }}`.
Set variables in the **Environment variables** page table: server defaults, repository
overrides, or rows scoped to one named pipeline. Page values override matching `env`
entries committed in `ci/config.json`; use the page for secrets. Do not commit new
variables or credentials in Git. Configured and built-in CI variables are available.
Substitution occurs once immediately before command execution; missing variables
fail the command's run/step. No Jinja filters, loops, function calls, or expression
evaluation are supported. Inserted values are not recursively expanded or
automatically shell-escaped: quote appropriately for the runner shell.

Repository rows can be limited to **Non-PR CI runs**, **Authorized protected
branch**, or **Deployments only**. Unmerged pull-request checks receive no
page-managed values, including server-wide values. Deployment-only rows are not
sent to CI test jobs. A protected-branch row is released only when the server
process allows the exact `owner/repo:branch` in
`PYGITHOST_CI_PROTECTED_SECRET_BRANCHES`, the default branch's committed
protection policy still matches that branch, and the execution commit is the
current branch tip. This is administrator authorization outside Git, so a
repository writer cannot self-grant protected values by editing `ci/config.json`.
Page values are plaintext in settings storage, logs are not secret-redacted, and
page values are not stored in new run snapshots. They can appear in remote job
assignments and logs. Prefer tools reading sensitive values directly from their
environment.

`triggers.push.branches` and `triggers.pull_request.branches` use arrays of case-sensitive globs
(`["main", "release/*"]`); omitted filters or `[]` match all branches. PR filters
match the **target** branch.

### JSON configuration

The [pipeline guide](docs/pipelines.md) is the configuration reference; the
[examples](docs/pipeline-examples.md) cover multiple checks and staging/production.
Project configuration is committed as `ci/config.json` and read from the recorded
commit. Each pipeline independently defines execution, triggers, cancellation,
artifacts and notifications. Each object in `deployments` has its own name, script
and pipeline reference. Multiple targets can reference one pipeline without sharing
results, logs or email state. Protection and optional retention stay repository-wide
at the document root. Omitted execution/cancellation options use built-in defaults,
not another pipeline's configuration. Email policies are not inherited.

The project page has no JSON editor. Environment variables and secrets remain on
**CI → Settings**; administrator retention defaults remain under **Admin → Settings**.
Project retention, when needed, belongs in the default branch's full grouped
document. Feature-branch commits and reruns do not change cleanup limits, and a
nonzero administrator limit caps the project value. Jobs remain sequential per
repository. See [Retention](docs/ci-retention.md) for defaults and cleanup timing,
the guide for limits, and [migration](docs/ci-migration.md).

### Optional merge and branch protections

Both settings live under `policies` in the full committed `ci/config.json`, default
to **off**, and change only when their commit is read:

- **`require_ci`**: the newest qualifying PR check for each applicable pipeline for
  this PR's exact current source **and** target commit must be successful.
  Missing, stale, pending, failed, cancelled, interrupted, or timed-out checks
  block merging. Manual/push runs and checks from another PR do not qualify.
  Enable PR opened, updated, and reopened triggers so checks are produced.
  The merge endpoint enforces this independently of the UI; the Git ref update
  atomically verifies source and target SHAs to reject concurrent branch changes.
- **`block_direct_pushes`**: rejects HTTP pushes to configured branch patterns,
  including creations, force-pushes, and deletions. Other branches remain writable;
  approved PR merges through the server remain allowed. Protected branches cannot
  be created/deleted through the branch UI either. Patterns are case-sensitive,
  supplied as `policies.protected_branches` (for example `["main", "release/*"]`). Initialize the branch before
  enabling protection.

These controls are independent: enable both to require a PR and passing CI.
Treat policy edits as security-sensitive code. Push protection adds a temporary
pre-receive hook without replacing repository hooks on disk; existing hooks still
run for allowed pushes. Chaining an existing pre-receive hook requires Git 2.36+
(`git hook run`). Local filesystem access, SSH pushes, and other Git servers are
outside this HTTP server's enforcement boundary. Host CI is trusted-code-only
and can access the server filesystem, so it is not a security boundary against
malicious jobs modifying refs directly.

### Downloadable artifacts

Configure relative file globs in each producing pipeline's `artifacts.paths`.
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
- Administrator retention defaults are under **Admin → Settings → Runs and
  artifacts**: artifact expiration defaults to **7 days**, maximum bundles defaults
  to **0 (unlimited)**, and completed-run retention defaults to **100** (or the
  server environment fallback). There is no project retention form.
- Set project `retention` in the default branch's full grouped `ci/config.json`.
  Omitted fields use administrator defaults, and a nonzero administrator limit caps
  the project value. Feature branches and reruns do not change repository cleanup
  limits. See [Retention and pagination](docs/ci-retention.md) for refresh and
  cleanup timing.
- Both artifact limits apply; the oldest bundles by run ID are removed when the
  count limit is exceeded. Retained artifacts protect their parent run from
  pruning, so retained run counts can exceed the configured run limit. Active runs
  and runs with pending CI notifications are also protected.
- Lower limits can permanently delete existing data during the next cleanup.
  **0** explicitly disables that limit; it does not mean inherit. Expiration is
  checked at startup, artifact operations, and
  run/configuration pruning—not by an exact-time deletion timer. SQLite may retain
  freed database pages for reuse; these are logical retention limits, not an OS
  filesystem quota.

### Runs, queues, and recovery

Committed commands, Git-defined settings, limits, and SHAs are snapshotted when a
run is queued; page-managed environment values are not. **Rerun** uses the same
configuration, event, payload, and SHAs—not today's branch tip or committed
settings—but resolves page values again at execution. Unmerged pull-request runs
still receive no page values, and a protected value is not released unless the
original commit is still the branch tip. Rerun depends on the selected
image/toolchain and on Git retaining the commit objects. Older runs without
snapshots can be viewed but cannot be rerun exactly.

Output is saved approximately every half-second, shown by polling, and capped at
1 MiB while the process output continues to be drained. The detail page provides
follow/copy/download controls, queue wait, duration, phase, failure reason, and
email status. Commands plus checkout/merge have a shared 30-minute timeout.
Cleanup has a separate bounded timeout; cleanup warnings do not overwrite a
successful command result.

Runs with recorded cleanup or metadata-save warnings show a **Warning** badge in
the CI Runs table. Click it to view the warning on the run detail page. Under
**Find runs**, choose **With warnings** or **Without warnings**; this combines with
status, event, branch, and search filters and is preserved during pagination and
live refresh. Warnings are separate from success/failure and deployment skip
reasons. Arbitrary warning text printed by your commands is not automatically
classified. Existing cleanup warnings in stored run reasons are migrated.

Only one job per repository runs at once. Server environment settings:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PYGITHOST_CI_CONCURRENCY` | `2` | Global simultaneous jobs |
| `PYGITHOST_CI_QUEUE_LIMIT` | `100` | Global waiting jobs, excluding running jobs |
| `PYGITHOST_CI_RETENTION` | `100` | Default completed-run limit when project configuration omits it (0–10000; 0 = unlimited) |
| `PYGITHOST_CI_TRUSTED_REPOSITORIES` | empty | Additional grants inherited by GitHost. Exact `owner/repo` entries, comma- or newline-separated; these are additive to **Admin → Settings → Trusted CI repositories** |
| `PYGITHOST_CI_TRUST_ADMIN_IPS` | empty | Exact client IPs allowed to manage trusted CI repositories in IP-only mode. Requires IP filtering and an IP allowed by the normal client allowlist |
| `PYGITHOST_CI_PROTECTED_SECRET_BRANCHES` | empty | Exact `owner/repo:branch` entries, comma- or newline-separated, allowed to receive protected page-managed values; a matching default-branch protection rule and current branch tip are also required |

A full queue produces a failed run with a queue-specific reason instead of
silently dropping the event. Optionally cancel superseded runs for the same
event/branch/PR. Cancelled and interrupted runs do not send email. Filters and
Previous/Next pagination lets you browse retained history; the repository badge shows
the default branch and marks results stale when its commit changes.

Growing lists default to **25 items per page** with consistent First/Previous/Next/Last
controls, numbered pages, and result totals: repositories, CI runs, deployments,
artifacts, tokens, users, branches,
pull requests and their commits, and commit changed-file lists.
Repository Code pages and folder explorers show folders before files. Directories
wider than 100 entries are paged 100 at a time (`per_page` accepts 10/25/50/100),
and last-commit metadata is resolved only for the visible page.
Full commit history retains 50-commit chunks and Load more, with page links too.
Searches, filters, sorting, selected revisions, and paths are preserved across pages.
New searches start on page 1. Pagination is a live view:
new entries or retention cleanup can shift entries between pages on refresh.
See [Retention and pagination](docs/ci-retention.md) for examples and limits.

The scheduler takes an OS lock beside the SQLite database; do not run multiple
servers against the same database. Waiting jobs survive shutdown, running jobs
are interrupted, and the queue is periodically reconciled with the database.
After a hard process/host crash, the database is recovered, but OS processes,
Docker containers (`pygithost-ci-<pid>-<run>-<step>`), and temporary checkouts may require
operator cleanup. Use a service supervisor that terminates the entire service
process tree/cgroup (for example systemd's `KillMode=control-group`), not just the
server's process group: CI subprocesses use separate sessions. Docker containers
need separate cleanup after a crash. This is not a distributed worker system.

For a proposed distributed execution model, see
[Remote CI runners](docs/remote-ci-runners.md). This is a design document, not an
available feature.

### Automatic deployment

See the [automatic deployment walkthrough](docs/automatic-deployment.md) for a
safe first run, trigger reference, Ubuntu SSH example, and recovery checklist.
The website also includes help under **CI → Docs → Deployment**.

Add an object to `deployments` in the full grouped `ci/config.json` with `name`,
`pipeline`, `branch`, `script` (absolute host path), and optional `timeout_seconds`.
Alternatively use `script_content` and `run_with` for inline scripts. A deployment
block enables it unless `enabled` is false. Every enabled deployment requires the
exact `owner/repo` in **Trusted CI repositories**; adding the object in Git
cannot authorize itself. `run_with: "python"` selects the Git server's interpreter
and virtual environment; install dependencies there, not just in the CI image.
Direct POSIX execution requires a shebang. Script content is UTF-8, at most 64 KiB,
committed in the project configuration and captured in the run snapshot, then
written to a temporary file only during execution. There is no separate
upload form. Deployment-only page variables are available to deployment scripts
and steps, resolved live at execution; ordinary and protected page variables are
not sent to deployments. See the guide for the complete JSON example and migration
details.

Enable the **Push** and/or **PR merged** CI triggers. After a successful run for
an actual update to the selected branch, the server checks that its tip still
matches the tested commit and runs the script. PR checks and manually queued
runs never deploy. The repository's runner slot remains occupied until deployment
finishes, so deployments cannot overlap within a repository. Disabling deployment
or changing its settings prevents older queued configurations from deploying.

The exact tested commit is passed as the first argument and `PYGITHOST_COMMIT`;
`PYGITHOST_OWNER`, `PYGITHOST_REPO`, and `PYGITHOST_BRANCH` are also available.
The script must deploy that commit, not fetch and deploy the latest branch tip.
It runs in a temporary directory, not the CI checkout, and must fetch source or
retrieve the desired build itself. It does not automatically receive CI artifacts.

```sh
#!/bin/sh
set -eu
commit="$1"
# Invoke your trusted deployment tool with this exact commit.
/opt/my-app/release "$commit"
```

**Deployment scripts are trusted host code**, even when CI uses Docker. They run
as the Git server's OS user with network access. Repository writers cannot grant
themselves that execution by editing `ci/config.json`; administrator trust
authorization must already include the exact `owner/repo`, and the check is
repeated for reruns and historical snapshots. Protect scripts from modification
by repository jobs. Store SSH keys and other credentials in protected server
files, not CI environment settings or script contents. The execution environment
does not inherit arbitrary server variables; scripts should use explicit
credential paths. Logs are not secret-redacted.

Deployment status and bounded logs appear separately on the CI run page after
execution finishes. **CI → Deployments**, next to Runs, lists deployment history;
open an entry for its output, including after the originating CI run is pruned.
Refresh to update active attempts. Deployment failure does not turn passing tests
into failing tests. Separate **[Deployment]** emails use the existing repository email recipients
and notification mode (off, failures, all completions, or failures and recovery).
Failures include timed-out and interrupted deployments; recovery compares previous
deployment results, not test results. Messages contain metadata only, not logs or
scripts. Delivery status appears on the run page, and SMTP failures never change
deployment results. Each repository/deployment/commit gets at most one deployment attempt, including
failed attempts. Attempt records survive CI history pruning. There is no automatic
retry or rollback. Server restarts mark unfinished deployments interrupted rather
than replaying them; operators must verify the target's actual state. As with CI,
use a service supervisor to terminate subprocesses after shutdown or crashes.

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

On each pipeline or deployment, set `notifications.email.recipients` to an array of up
to 20 addresses and `notifications.email.mode` to `off`, `failures`, `all`, or `recovery`.
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
# PR and commit review pages

Pull-request and commit lists/details use a GitLab-inspired review layout with
compact list rows, status badges, section navigation, metadata sidebars and framed
diffs. On narrow screens the sidebar moves below the content. Section navigation
uses ordinary links and works without JavaScript; existing merge permissions,
comment actions and commit pagination are unchanged.
