# Automatic deployment

Automatically run a trusted deployment script after CI passes for updates to one
branch. Configure everything under **CI → Settings → Automatic deployment**.
The website also provides this feature's reference under **CI → Docs → Deployment**.

```text
Push or merge into main
        ↓
Run CI for that exact commit
        ↓ tests pass
Check that main still points to that commit
        ↓
Run deployment script on the Git server
        ↓
Record deployment success or failure separately from CI
```

This is a script runner, not a complete release manager. Your script decides how
to transfer or retrieve the application, restart it, and check its health.
Remote CI workers are not required.

## 1. Try it without changing an application

Start with a harmless script so you can verify the trigger and script arguments
before giving deployment access to a production server.

1. Configure your repository's normal test pipeline.
2. Enable **Push**, **PR merged**, or both. Ensure their branch filters allow
   `main`. A successful PR check before merging is not a deployment trigger.
3. Under **Automatic deployment**, enable **Deploy after successful branch CI**.
4. Set **Deployment branch** to `main` and leave the timeout at `600` seconds.
5. Paste this into **New script contents**, or save it as `deploy.sh` and select
   it with the file picker:

   ```sh
   #!/bin/sh
   set -eu
   printf 'Repository: %s/%s\n' "$PYGITHOST_OWNER" "$PYGITHOST_REPO"
   printf 'Branch: %s\n' "$PYGITHOST_BRANCH"
   printf 'Would deploy commit: %s\n' "$1"
   ```

6. Click **Save CI settings**. Selecting a file alone does not save or execute it.
7. Push a **new commit** to `main`, or merge a PR into it through the website.
8. Open the resulting CI run. After CI succeeds, the **Deployment** section
   should show `success` and the commit printed by the script.

This script deploys nothing. Replace it with your real deployment procedure only
after checking the output. Saving deployment settings does not retrospectively
deploy already completed runs; manually queueing a run does not trigger deployment.

## 2. Understand the conditions

| Event or condition | Deployment behavior |
| --- | --- |
| Push to the configured branch; CI passes | Eligible |
| PR merged into the configured branch; its post-merge CI passes | Eligible |
| PR opened, updated, or reopened | No deployment |
| Manually queued CI run | No deployment |
| CI fails, times out, or is cancelled | No deployment |
| Another branch | No deployment |
| Branch has advanced past the tested commit | Skipped |
| Deployment was disabled when the run was queued | No deployment |
| Deployment is disabled before execution | No deployment |
| Deployment branch, script path, Run with, or timeout changed since queueing | No deployment |
| This repository/commit already has a deployment attempt | No second attempt |

The corresponding CI event trigger must be enabled, and its branch filters must
match. The deployment branch is one exact name, **not a glob pattern**.

Only one run/deployment per repository executes at a time. Different repositories
may deploy concurrently: if they share a deployment target, coordinate access in
your deployment tooling. The tip check happens immediately before deployment;
it does not freeze the branch while the script runs.

## 3. Script inputs and execution environment

### Python scripts on Ubuntu and Windows

Set **Run with** to `python`. Uploading a `.py` file fills this in if the field is
blank; when pasting contents or entering a server path, set it yourself.
No shebang or executable bit is required when an interpreter runs the file.

### Other languages and runner options

Any installed interpreter or runner can be used. The server executes an argument
list consisting of **Run with + script path + commit SHA**, without a shell.

| Language | Run with |
| --- | --- |
| Python (server's interpreter) | `python` |
| Python with explicit executable/options | `python3 -u` |
| JavaScript | `node` |
| Bash | `bash -e` |
| PowerShell | `pwsh -NoProfile -File` |
| Ruby | `ruby` |
| PHP | `php` |

Leave blank to execute the script directly. The legacy value `direct` also means
direct execution. Runner names are resolved using the server's executable search
path; absolute paths are more predictable. Quote paths containing spaces. Parsing
uses shell-style quoting on both platforms; use forward slashes in Windows paths,
for example `"C:/Program Files/Python/python.exe" -u`.

Pipes, redirects, variable expansion, and command chaining are not evaluated in
this field. Put multi-command logic in the uploaded script instead. Runners must
accept the stored script path followed by its arguments. Stored upload filenames
are content hashes without extensions: extension-dependent tools need a wrapper
that handles their required filename. Compiled languages need a build/run wrapper.
Install runtimes and dependencies on the Git server, not only in the CI image.

```python
import os
import sys

commit = sys.argv[1]
print(f"Would deploy {os.environ['PYGITHOST_REPO']} at {commit}", flush=True)
# Add your deployment logic here. Raise an exception or exit nonzero on failure.
```

The server invokes its own interpreter as `python <stored-script> <commit>` using
an argument list, so paths containing spaces are supported. It uses the same
Python installation/virtual environment as the server. Install deployment
dependencies there. Python code and any external commands it calls must themselves
be compatible with the target server OS; choosing Python does not make shell
commands portable. Existing configurations without a runner retain direct execution.

| Input | Meaning |
| --- | --- |
| First argument (`$1` in a shell script) | Exact tested commit SHA |
| `PYGITHOST_COMMIT` | The same commit SHA |
| `PYGITHOST_OWNER` | Repository owner |
| `PYGITHOST_REPO` | Repository name |
| `PYGITHOST_BRANCH` | Deployment branch |
| `CI` | `true` |

- The script executes **on the Git server**, as the server's OS user, even when
  tests run in Docker. Network access is available subject to server/firewall rules.
- The exact runner value `python` invokes the server interpreter; a blank runner runs the
  file itself. Neither uses the CI command shell or template engine. For direct
  scripts on Ubuntu, include an installed interpreter in a shebang, such as `#!/bin/sh`.
- Its working directory and `HOME` are temporary. Do not assume your normal
  `.ssh` files, Git configuration, or current directory are available.
- CI environment settings and arbitrary server environment variables are not
  automatically passed through. Use explicit configuration and credential paths.
- The original CI checkout and artifacts are **not automatically supplied**.
  The script must retrieve the exact source or an immutable build itself.
- Exit `0` for success; any other exit code means failure. Use `set -eu` for
  shell scripts so failed commands do not accidentally produce success.
- Timeout defaults to 600 seconds; accepted values are 1–86400 seconds.

**Never deploy a moving branch name instead of the supplied SHA.** Otherwise a
new, untested commit could be released between testing and deployment. Rebuilding
the same source also does not guarantee the same binary: for reproducible releases,
have your tooling retrieve an immutable, previously tested build.

## 4. Example: invoke a release tool on another Ubuntu server

This example delegates application-specific work to a trusted tool on the target.
It is not a complete application installer.

### Prerequisites

On the **Git server**:

- Install the OpenSSH client.
- Provision a dedicated deployment key readable by the Git server service user.
  Keep it outside repositories and uploaded scripts.
- Create a protected known-hosts file using a host key fingerprint verified through
  a trusted channel. Do not blindly trust a key collected over the network.
- Allow outbound SSH access to the deployment target.

On the **target Ubuntu server**:

- Create a restricted deployment account, such as `deploy`.
- Authorize only the deployment key and restrict it to the needed operations.
- Install an executable `/opt/my-app/release` tool that accepts one commit SHA,
  retrieves the exact version, installs it, restarts the appropriate service,
  and returns nonzero if a health check fails.
- Give that tool only the privileges it needs. Avoid unrestricted passwordless
  `sudo`, shared administrator keys, or broad shell access where possible.

### Script to upload

Replace the host, user, and file paths for your installation:

```sh
#!/bin/sh
set -eu
commit="$1"
# Validate before placing the SHA into an SSH remote command.
case "$commit" in
  ''|*[!0-9a-fA-F]*) echo 'Invalid commit SHA' >&2; exit 1 ;;
esac
case "${#commit}" in
  40|64) ;;
  *) echo 'Invalid commit SHA length' >&2; exit 1 ;;
esac

/usr/bin/ssh -F /dev/null \
  -i /etc/pygithost-deploy/my-app-key \
  -o IdentitiesOnly=yes \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/etc/pygithost-deploy/known_hosts \
  -o ConnectTimeout=15 \
  deploy@app.example.com "/opt/my-app/release '$commit'"
```

Test connectivity and the release tool as the **Git server's service user**, not
just from your administrator login. Explicit identity and known-hosts paths matter
because deployment uses a temporary `HOME`.

SSH disconnection or killing the local SSH process does not guarantee that work
on the target stops. The target tool must handle interruption and partial releases
safely. Prefer versioned release directories, an atomic activation step, a health
check, and retention of the previous release for manual recovery.

## 5. Uploading, replacing, and backing up scripts

You can upload a file, paste text, or provide an absolute path to an externally
managed script. For an external script, ensure it exists outside the repository
and is executable by the server user.

- Uploads accept UTF-8 text, no NUL bytes, up to 64 KiB. CRLF becomes LF.
  An explicit runner does not require a shebang; direct scripts on Ubuntu do.
- The file picker loads an editable preview. **Save CI settings** stores it.
- Nonempty **New script contents** replaces the path field when saved.
- To use an external path instead, clear the new contents field before saving.
- Uploading a changed script creates a different content-addressed path. Runs
  queued with the previous script path will not deploy under the changed settings.
- Uploaded versions reside in `deployment-scripts` beside the database, with
  owner-only file permissions. Back up that directory together with the database.
  Unused script versions are not automatically removed.

## 6. Results, failures, and recovery

Deployment status and logs appear separately on the originating CI run page.
Open **CI → Deployments**, immediately next to **Runs**, for paginated deployment
history. Each entry shows status, branch, commit, timestamps, duration, and email
delivery state. Open an entry to read its output. Deployment details remain
available even after the originating CI run is pruned; retained runs have a link
back to their CI page. Refresh the page to update active attempts. Skipped
deployments are not recorded in history.
Logs become available when the attempt finishes, rather than streaming live, and
are bounded to 1 MiB. A passing CI result stays passing even if deployment fails;
CI completion email is not a deployment-success notification. Separate messages
with a **[Deployment]** subject report deployment results using the repository's
email recipients and mode. Configure server SMTP under **Admin → Email**, then
recipients and mode in **CI settings → Email notifications**:

- **Off:** no deployment email.
- **Failures:** failed, timed-out, or interrupted deployments.
- **All completions:** every completed deployment attempt.
- **Failures and recovery:** failures plus success following an unsuccessful deployment.

Skipped deployments do not send email. Messages include repository, branch, commit,
status, and a run link when a public URL is configured; never scripts, credentials,
or output. Deployment email delivery state appears on the run page. SMTP failures
do not change deployment results. Queued messages survive restart; delivery that
was in progress at a crash is marked uncertain rather than resent automatically.
Failed or uncertain deployment messages currently have no manual retry button.

Each repository/commit gets **at most one attempt**, including failed or interrupted
attempts. Attempt records survive CI history pruning. Rerunning CI cannot retry
an already attempted deployment. A skipped run without an attempt does not consume
that commit's attempt.

There is no deployment retry button or automatic rollback. If deployment fails:

1. Read the deployment output and inspect the target's actual state.
2. Recover or roll back using your trusted deployment tool.
3. Correct the problem and deploy manually, or push a new commit that passes CI
   to trigger a new attempt. Do not delete database records to force a retry.

Restart recovery marks unfinished deployments `interrupted`; it does not replay
them. A timeout or cancellation cannot undo an already completed remote action.
Use a service supervisor to clean up server subprocesses after shutdown/crashes.

### Troubleshooting checklist

| Symptom | Check |
| --- | --- |
| No CI run | Pipeline configured, event enabled, branch filter matches |
| CI passed, no Deployment section | Actual event, exact branch, queue-time settings, current tip, previous attempt |
| Script cannot start | Absolute path, executable bit, shebang, interpreter installed on Git server |
| Command missing | Tool installed on Git server, not only in the CI Docker image |
| SSH fails | Service-user permissions, explicit key path, verified known-hosts entry, target account, firewall |
| No output during execution | Deployment output appears after completion |
| Tests pass but application is unchanged | Separate deployment result, correct target, exact SHA, release tool health checks |
| Rerun does not deploy | Manual runs are excluded; already-attempted commits cannot deploy again |

## Security boundary and current limits

Only trusted administrators should configure deployments. If authentication is
disabled, the IP allowlist is the administration boundary. Uploading a deployment
script authorizes execution with the server user's filesystem and network access.

Keep keys and tokens in protected server files, not script contents or CI settings.
Logs are not secret-redacted and are visible to users who can read the CI run.
Untrusted host CI jobs share the server user's access; they are not safely isolated
from scripts or deployment credentials. Owner-only file permissions do not isolate
processes running as that same user.

The current feature has one branch/target script per repository, no environment
approvals, no secrets manager, no automatic artifact handoff, no remote worker
protocol, and no built-in rollback. The script can invoke external deployment
tools, but those tools and their access policies must be provisioned separately.
