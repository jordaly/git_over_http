"""Inline, dependency-free documentation for the CI configuration page."""

import json

from .ci import BUILTINS
from .rendering import html_t, join_html, safe_html


EXAMPLE_PIPELINE = {
    "version": 1,
    "steps": [
        {"name": "Test", "run": "python -m unittest discover -v"},
        {"name": "Compile", "run": "python -m compileall -q pygithost"},
    ],
    "env": {"PYTHONUNBUFFERED": "1"},
    "timeout_seconds": 600,
    "artifacts": {"paths": ["pygithost/__pycache__/*.pyc"], "when": "always"},
}


def ci_configuration_guide():
    pipeline_json = json.dumps(EXAMPLE_PIPELINE, indent=2)
    steps_json = json.dumps(EXAMPLE_PIPELINE["steps"], indent=2)
    command_json = json.dumps({"version": 1, "command": "python -m unittest discover -v"}, indent=2)
    variables = join_html([html_t(t"<li><code>{name}</code></li>") for name in sorted(BUILTINS)])
    return safe_html(html_t(t'''<section id="ci-configuration-guide" class="box ci-guide" aria-labelledby="ci-guide-heading">
<h2 id="ci-guide-heading">CI configuration guide</h2>
<p>On the <b>Settings</b> tab, choose <b>Single command</b>, <b>Named steps</b>, or <b>JSON in page</b> and use the same <b>Save CI settings</b> button. You can also enable a versioned <code>.pygithost-ci.json</code> file. Everything uses standard JSON: double-quoted strings, no comments, and no trailing commas.</p>
<nav class="row" aria-label="CI guide sections"><a href="#ci-guide-start">Quick start</a><a href="#ci-guide-json">JSON reference</a><a href="#ci-guide-settings">Server settings</a><a href="#ci-guide-retention">Retention</a><a href="#ci-guide-deployment">Deployment</a><a href="#ci-guide-variables">Variables</a></nav>

<details id="ci-guide-start" open><summary>Quick start: configure a pipeline</summary>
<ol><li>Choose a runner and ensure the required tools are installed. Host runs use the server machine; Docker runs use an image already available locally.</li>
<li>For a single command, choose <b>Single command</b> and enter <code>python -m unittest discover -v</code> in <b>Command</b>.</li>
<li>Alternatively, choose <b>Named steps</b> and paste this array into its editor. Only the selected command mode is saved. These example commands target this Python project; change them for your repository.</li></ol>
<pre tabindex="0" aria-label="Named steps JSON example">{steps_json}</pre>
<p>Select at least one event trigger, save settings, then queue a branch from <b>CI runs</b> if the manual trigger is enabled. Queueing requires write access and an existing branch.</p>
</details>

<details id="ci-guide-json" open><summary>Repository file: .pygithost-ci.json</summary>
<p>Place the file in the repository root, commit it, and enable <b>Load .pygithost-ci.json from Git</b> on the Settings tab. The file does not enable CI triggers by itself.</p>
<pre tabindex="0" aria-label="Complete repository pipeline JSON example">{pipeline_json}</pre>
<p>For a single-command file, use this instead:</p><pre tabindex="0" aria-label="Single-command repository pipeline example">{command_json}</pre>
<div class="ci-table-scroll"><table><thead><tr><th>JSON field</th><th>Type and behavior</th></tr></thead><tbody>
<tr><td><code>version</code></td><td>Optional integer; defaults to <code>1</code>. Only version 1 is supported.</td></tr>
<tr><td><code>command</code></td><td>One shell command, up to 8192 characters. Use this or nonempty <code>steps</code>, not both.</td></tr>
<tr><td><code>steps</code></td><td>Array of up to 64 objects, each containing only <code>name</code> and <code>run</code>. Names contain 1–120 characters; commands contain 1–8192 characters.</td></tr>
<tr><td><code>env</code></td><td>Optional object of string values, up to 64 entries. When supplied, replaces the server's ordinary job environment mapping. Names must be valid environment variable identifiers and cannot override built-in variables.</td></tr>
<tr><td><code>timeout_seconds</code></td><td>Optional positive whole number. Defaults to the server setting and cannot exceed it. Covers checkout, PR merge preparation, and all steps together.</td></tr>
<tr><td><code>artifacts</code></td><td>Optional object with <code>paths</code> (array of relative file patterns) and <code>when</code> (<code>always</code>, <code>success</code>, or <code>failure</code>).</td></tr>
</tbody></table></div>
<p>Only these fields are accepted. The file must be a regular file no larger than 64 KiB. Missing, malformed, or disallowed configuration fails the run rather than falling back to the server command.</p>
<p class="warn"><b>Which commit supplies the file?</b> Push and manual runs use the selected commit. PR checks use the recorded target/base commit's file, not the unreviewed PR head's file. Pipeline changes in a PR take effect after merging.</p>
<p>The effective configuration is saved when the run is queued. Reruns use that saved snapshot, not the latest file or current command settings.</p>
<p><b>Prefer to paste JSON?</b> Turn off loading from Git and choose <b>JSON in page</b> on the Settings tab, using the same fields and examples. Save CI settings saves the pipeline and other form settings together; it does not create a commit. Command/steps are replaced; supplied environment, artifact and timeout fields override the corresponding form fields. Omitted optional fields use the form values. Since this is an administrator action, the inline timeout may also raise the server's limit. Triggers, runner/image, email, and protections are controlled by the form, not pipeline JSON.</p>
</details>

<details><summary>Step execution and logs</summary>
<ul><li>Steps run sequentially, each in a <b>separate shell</b>, starting in the checkout root. Files persist, but <code>cd</code>, <code>export</code>, and shell variables do not carry over.</li>
<li>Host shells use <code>/bin/sh</code> on POSIX or <code>cmd.exe</code> on Windows. Docker uses <code>/bin/sh</code>. Write commands appropriate for the runner's shell.</li>
<li>Docker steps start separate containers. Only files in the checkout persist between containers; container <code>/tmp</code> and other container state do not.</li>
<li>A nonzero exit code fails the step and skips later steps. Test output and JUnit reports are not parsed.</li>
<li>Each step has its own status, exit code, duration, and output. Combined run output is limited to 1 MiB; the run page provides a raw-log download.</li></ul>
<p><b>Run warnings:</b> cleanup and step-metadata-save issues show a separate Warning badge in the Runs table, even when tests pass. Click the badge for details. In Find runs, select With warnings or Without warnings; the selection combines with other filters and survives pagination/live refresh. Warnings remain visible independently of deployment skip reasons. The server does not classify arbitrary command output as warnings.</p>
</details>

<details><summary>Jinja-style environment placeholders</summary>
<p>Use <code>{{{{ env.NAME }}}}</code> in a command or step's <code>run</code> string to insert a configured environment value. The same syntax works on Windows, Linux, and Docker, without installing Jinja.</p>
<pre>{{
  "command": "my-tool --password \\"{{{{ env.DB_PASSWORD }}}}\\""
}}</pre>
<p>Set <code>DB_PASSWORD</code> in the CI settings environment field. Omit JSON <code>env</code> to inherit that mapping; supplying JSON <code>env</code> replaces it. Built-in variables such as <code>{{{{ env.PYGITHOST_BRANCH }}}}</code> are also available.</p>
<p>Substitution happens once, just before each command executes. Undefined variables fail the run/step without executing that command. Loops, filters, function calls, and other Jinja expressions are not supported. References inside inserted values are not expanded recursively.</p>
<p class="warn">Values are inserted as literal command text, not automatically shell-escaped. Quote them for the selected shell; special characters may change how a command executes. Environment values remain plaintext in configuration snapshots and output is not redacted. Avoid printing credentials. Prefer tools that read sensitive values directly from the environment where possible.</p>
</details>

<details><summary>Artifacts: downloadable files</summary>
<p>In the form, enter one file pattern per line. In JSON, use <code>"artifacts": {{"paths": ["dist/*", "reports/**/*.xml"], "when": "always"}}</code>.</p>
<ul><li>Paths are relative to the checkout. Use forward slashes. Matched directories are not implicitly archived; choose file patterns. No matches means no download.</li>
<li><code>always</code> is the default; <code>success</code> collects only after success; <code>failure</code> collects after failure or timeout. Cancelled runs do not collect artifacts.</li>
<li>Files are collected before checkout cleanup and offered as one ZIP on the run page. Content is not interpreted, including test reports.</li>
<li>Limits: 32 patterns, 256 characters per pattern, 1000 files, 10,000 matched entries, and 20 MiB total uncompressed content per run. Collection errors or limit violations fail the run.</li>
<li>Absolute paths, parent traversal, and <code>.git</code> paths are rejected/excluded. Symlinks, junctions, and hardlinks are not collected.</li>
<li>Downloads use the same access controls as CI logs. Retention defaults to 7 days and can be changed in <b>Additional settings → Artifact and run retention</b>. Retained archives protect their run records from pruning.</li></ul>
</details>

<details id="ci-guide-retention" open><summary>Artifact expiration, storage limits, and pagination</summary>
<p>Administrators configure these repository-level policies under <b>Settings → Additional settings → Artifact and run retention</b>. They cannot be set in repository pipeline JSON. These are current storage policies, not frozen per-run settings.</p>
<div class="ci-table-scroll"><table><thead><tr><th>Setting</th><th>Default</th><th>Meaning</th></tr></thead><tbody>
<tr><td>Artifact expiration (days)</td><td>7</td><td>Whole days from archive creation; 0 means never expire by age. Maximum 36500.</td></tr>
<tr><td>Maximum artifact bundles</td><td>0</td><td>One bundle is one run's ZIP, not one file. Keep the newest N runs' bundles; 0 means unlimited. Maximum 1000000.</td></tr>
<tr><td>Completed CI runs to retain</td><td>100, or server default</td><td>Keep the newest N completed runs; 0 means unlimited. Maximum 1000000. Runs with retained artifacts, active runs, and pending notifications are protected.</td></tr>
</tbody></table></div>
<p><b>Examples:</b> 30 days and 50 bundles keeps at most the newest 50 bundles, none older than 30 days. To retain artifacts forever, set <b>both</b> artifact values to 0. To retain run history forever too, set completed-run retention to 0. Protected artifact-bearing runs can make the run total exceed its limit.</p>
<p class="warn">Saving applies to existing archives and completed runs immediately. Reducing limits can permanently delete data; increasing them cannot restore it. Unlimited retention can fill the server disk. SQLite may reuse freed pages without shrinking the database file.</p>
<p>Expiration cleanup runs at startup, artifact access/collection, and run/configuration pruning; it is not an exact-time background timer. Expiration dates on the Artifacts page reflect the current age policy, while count limits may remove a bundle earlier. With age expiration disabled, the page shows <b>Never expires</b>; a nonzero count limit can still remove it.</p>
<p>Growing lists use the same controls: <b>First</b> and <b>Last</b> jump to the beginning/end; <b>Previous</b> and <b>Next</b> move one page; numbered links select nearby pages. The summary shows the visible range and total matches. Boundary controls are disabled. Lists default to 25 entries, while full commit history defaults to 50 and also supports Load more. Search, filters, sorting, revision, and path are preserved; submitting a new search starts at page 1. This applies to repositories, runs, deployments, artifacts, tokens, users, branches, pull requests, PR commits, and commit changed-file lists. Repository Code pages and folder explorers show full file listings without pagination. Running jobs and new entries may shift pages on refresh. Skipped deployments do not create history entries. Deployment history is not deleted by CI run retention. Fixed reference tables are not paginated.</p>
</details>

<details id="ci-guide-settings"><summary>Server-controlled settings and triggers</summary>
<p>These settings are configured only through the Settings tab, not repository JSON. Configuration requires administrator access when authentication is enabled.</p>
<div class="ci-table-scroll"><table><thead><tr><th>Setting</th><th>Behavior</th></tr></thead><tbody>
<tr><td>Runner and Docker image</td><td><b>Host</b> runs trusted code as the server's OS user. <b>Docker</b> requires a local daemon and a pre-pulled image with dependencies installed. Containers have no network, a read-only root filesystem, 1 GiB memory, one CPU, and a 128-process limit. Pin an image digest for reproducibility.</td></tr>
<tr><td>Timeout</td><td>Default: 1800 seconds (30 minutes) for setup and all execution. A repository file may lower this budget, not raise it.</td></tr>
<tr><td>Event triggers</td><td>Push, PR opened, PR updated, PR reopened, PR merged, and manual runs are independently enabled. All are off by default. PR updated includes changes to either the source or target branch.</td></tr>
<tr><td>Branch filters</td><td>One case-sensitive glob per line, such as <code>main</code> or <code>release/*</code>. Blank means all branches. Push filters match the pushed branch; PR filters match the target branch.</td></tr>
<tr><td>Cancel superseded runs</td><td>When enabled, newer non-manual runs cancel older queued/running runs for the same repository, event, branch, and PR identity. Manual runs are not superseded.</td></tr>
<tr><td>Email notifications</td><td>Requires server SMTP configuration and recipients, one address per line. Modes: off, failures only, all completions, or failures and recovery. Messages contain metadata, not logs or environment values.</td></tr>
</tbody></table></div>
<p class="warn">Host execution is trusted-code-only, not a sandbox. Environment values are stored in plaintext snapshots and are not redacted from logs. Do not use them as a secret store. Docker isolation is not a substitute for a dedicated runner when executing hostile code.</p>
</details>

<details><summary>Optional merge checks and protected branches</summary>
<p>Both switches default to off and are independent. Repository JSON cannot change either policy.</p>
<ul><li><b>Require successful CI:</b> the newest qualifying PR run for this PR's exact current source and target commits must pass. Missing, outdated, pending, failed, cancelled, interrupted, or timed-out checks block merging. Push/manual runs and another PR's checks do not qualify. Enable PR opened, updated, and reopened triggers.</li>
<li><b>Block direct pushes:</b> HTTP pushes cannot create, change, force-push, or delete branches matching protected patterns. The branch UI also blocks protected branch creation/deletion. Approved PR merges through the server remain allowed.</li>
<li>Initialize a protected branch before enabling push protection. Patterns are case-sensitive, one per line. With protection enabled, at least one pattern is required.</li>
<li>Enable both switches to require PRs and passing CI. Local filesystem access, SSH, and other Git servers are outside this HTTP server's enforcement boundary. Host jobs can access server files and are not isolated from Git refs.</li>
<li>Existing repository hooks are preserved. Chaining an existing pre-receive hook requires Git 2.36 or newer.</li></ul>
</details>

<details id="ci-guide-variables"><summary>Built-in environment variables</summary>
<p>These variables are supplied by CI and cannot be overridden in <code>env</code>. PR-only values may be empty for other events. <code>CI</code> is <code>true</code>; <code>PYGITHOST_COMMIT</code> is the recorded checkout commit (the base commit for PR checks), and <code>PYGITHOST_WORKTREE</code> is the checkout directory.</p>
<ul class="ci-variable-list">{variables}</ul>
</details>

<details id="ci-guide-deployment" open><summary>Automatic deployment and script upload</summary>
<p>Deployment runs a trusted script on the Git server after successful CI for an update to one configured branch. It is optional and disabled by default. Configure it in <b>Settings → Automatic deployment</b>, not in repository pipeline JSON.</p>
<h3>Set up automatic deployment</h3>
<ol><li>Configure a working CI pipeline, then enable <b>Push</b> and/or <b>PR merged</b> triggers. Ensure the branch filters include your deployment branch.</li>
<li>Enable <b>Deploy after successful branch CI</b> and enter one exact branch name, for example <code>main</code>. This field does not accept glob patterns.</li>
<li>Enter an absolute script path already on the server, or select a file under <b>Or upload a deployment script</b>. The upload populates the editable <b>Deployment script contents</b> field; review it before saving. You may also paste script contents directly. Saved uploaded contents are shown again when you reopen settings, ready for review and editing. External server-path files are not loaded; clear the contents field before switching to an external path.</li>
<li>Set <b>Run with</b> to the installed runner, for example <code>python</code>, <code>node</code>, <code>bash -e</code>, or <code>pwsh -NoProfile -File</code>. No shebang is needed with an explicit interpreter. A <code>.py</code> upload fills in <code>python</code> when the field is blank; this shortcut uses the server's Python interpreter and virtual environment. Leave blank for direct execution, which requires a shebang for Ubuntu scripts. Uploads must be UTF-8 without NUL bytes, at most 64 KiB; CRLF is normalized.</li>
<li>Set the deployment timeout (default 600 seconds; allowed range 1–86400 seconds), then click <b>Save CI settings</b>. Nonempty new script contents take precedence over the path field. Uploading or saving does not execute the script.</li>
<li>Push a new commit or merge a PR into the configured branch. Open its CI run page to inspect the separate deployment status and output.</li></ol>
<h3>When does it deploy?</h3>
<div class="ci-table-scroll"><table><thead><tr><th>Situation</th><th>Deploys?</th></tr></thead><tbody>
<tr><td>Push or post-merge CI succeeds on the configured branch</td><td>Yes, if the tested commit is still the branch tip and has no prior attempt.</td></tr>
<tr><td>PR check before merging, manually queued run, or another branch</td><td>No.</td></tr>
<tr><td>Failed, cancelled, or timed-out CI</td><td>No.</td></tr>
<tr><td>Deployment disabled or deployment settings changed since queueing</td><td>No.</td></tr>
<tr><td>Same commit already attempted, including a failed deployment</td><td>No second attempt.</td></tr>
</tbody></table></div>
<ul><li>The run must be a successful <b>Push</b> or <b>PR merged</b> run for the exact deployment branch. PR checks and manually queued runs do not deploy.</li>
<li>Immediately before deployment, the server verifies that the branch tip still equals the tested commit. Outdated commits are skipped.</li>
<li>Deployment must have been enabled when the run was queued and must still be enabled. Changing the deployment branch, script path or contents, Run with, or timeout prevents older configurations from deploying.</li>
<li>The repository's runner slot stays occupied during deployment. Runs and deployments in that repository cannot overlap; different repositories may deploy concurrently.</li>
<li>There is at most one deployment attempt per repository/commit, even if that attempt fails or is interrupted. Rerunning CI does not retry an already attempted deployment.</li></ul>
<h3>Script contract: Ubuntu example</h3>
<p><b>Cross-platform Python:</b> set <b>Run with</b> to <code>python</code> and upload or paste this script. No shebang is needed on Ubuntu or Windows. This smoke test prints the commit without deploying anything.</p>
<pre tabindex="0" aria-label="Cross-platform Python deployment example">import sys

commit = sys.argv[1]
print("Would deploy", commit, flush=True)
</pre>
<p><b>Start safely:</b> first upload the harmless script below, save settings, then push a new commit to the deployment branch. Confirm its output in the run's Deployment section before configuring production access. Saving settings alone does not deploy an existing completed run.</p>
<pre tabindex="0" aria-label="Safe deployment smoke test">#!/bin/sh
set -eu
printf 'Would deploy %s/%s at %s\\n' "$PYGITHOST_OWNER" "$PYGITHOST_REPO" "$1"
</pre>
<p>Once the smoke test works, invoke your own release tool. The following path is a placeholder: you must install and configure the tool yourself.</p>
<pre tabindex="0" aria-label="Ubuntu deployment script example">#!/bin/sh
set -eu
commit="$1"
# Replace this command with your own trusted deployment tool.
/opt/my-app/release "$commit"
</pre>
<p>The server executes <b>Run with + script path + commit SHA</b> as an argument list, without a command shell. Leave Run with blank to execute the file itself. The script receives the exact tested commit as its first argument, plus <code>CI=true</code>, <code>PYGITHOST_COMMIT</code>, <code>PYGITHOST_OWNER</code>, <code>PYGITHOST_REPO</code>, and <code>PYGITHOST_BRANCH</code>. Deploy that commit, not the latest branch tip, which may change while deployment is running. Exit zero for success and nonzero for failure.</p>
<div class="ci-table-scroll"><table><thead><tr><th>Runtime</th><th>Run with example</th></tr></thead><tbody>
<tr><td>Python, server interpreter</td><td><code>python</code></td></tr>
<tr><td>Python, explicit interpreter and arguments</td><td><code>python3 -u</code></td></tr>
<tr><td>JavaScript</td><td><code>node</code></td></tr>
<tr><td>Bash</td><td><code>bash -e</code></td></tr>
<tr><td>PowerShell</td><td><code>pwsh -NoProfile -File</code></td></tr>
<tr><td>Ruby / PHP</td><td><code>ruby</code> / <code>php</code></td></tr>
</tbody></table></div>
<p>Install the runner and dependencies on the Git server. Quote executable paths with spaces; parsing uses shell-style quoting on both platforms. For Windows paths, use forward slashes, for example <code>"C:/Program Files/Python/python.exe" -u</code>. Pipes, redirection, command chaining, and environment expansion are not supported in Run with; put that logic in the script. Temporary scripts use .py for Python, .ps1 for PowerShell, .js for Node, and .sh otherwise; other extension-dependent runners need a wrapper. Compiled languages need a build/run wrapper too. No runner makes OS-specific script commands portable automatically.</p>
<p>The working directory and <code>HOME</code> are temporary directories, not the CI checkout or the server user's normal home. The script does not inherit arbitrary server environment variables or the CI settings environment mapping. Source checkouts and CI artifacts are not automatically passed to it: your deployment tool must retrieve the required source or build itself. Use explicit paths for tools, SSH keys, and SSH known-hosts files. Provision these securely before enabling deployment.</p>
<p><b>Deploying to another Ubuntu machine?</b> Install an SSH client on the Git server, provision a dedicated restricted key and a verified known-hosts file, and use explicit paths for both. Install a release tool on the target that accepts the exact commit, activates that release, and checks application health. Test as the Git server service user. Never disable SSH host verification. Stopping a local SSH process does not guarantee the remote release stops.</p>
<h3>Security and storage</h3>
<p class="warn"><b>This is host execution, even if CI uses Docker.</b> Deployment scripts run as the Git server's OS user with network and filesystem access. Only trusted administrators should configure them. When authentication is disabled, the IP allowlist is the administration security boundary. Never let untrusted jobs modify scripts, deployment tools, or credentials. Output is not secret-redacted, and anyone with access to the CI run can read deployment output.</p>
<p>Keep credentials in protected server files, not uploaded script contents, repository files, or CI environment settings. Uploaded/pasted scripts are stored in SQLite and snapshotted with new runs. Only at deployment execution are the contents written to an owner-only temporary file, removed afterward. Back up the database. Legacy uploads in <code>deployment-scripts</code> remain readable; reopen settings and save their contents to migrate them. Old files are not deleted automatically.</p>
<h3>Failures, recovery, and troubleshooting</h3>
<p>If deployment did not run, open the successful CI run and read its <b>Deployment skipped</b> reason. A manually queued run does not deploy; save settings, enable Push/PR merged, and push a new commit to the configured branch.</p>
<p><b>Where to view deployments:</b> open <b>CI → Deployments</b>, immediately next to Runs. The paginated history shows status, branch, commit, start/finish times, duration, and email state. Select a deployment to view its output; details remain available after its CI run is pruned. Refresh for updated status. Skipped deployments are not recorded.</p>
<ul><li><b>CI passed but nothing deployed:</b> check the event, exact branch, branch filters, deployment settings at queue time, current branch tip, and whether this commit already has an attempt. An automatically skipped deployment does not create a deployment record.</li>
<li><b>Script cannot start:</b> check its path, shebang/interpreter, executable permissions for externally installed scripts, and availability of required tools on the server. Installing tools only in the Docker CI image is not sufficient.</li>
<li><b>SSH authentication or host verification fails:</b> the temporary HOME does not contain your normal SSH configuration. Configure explicit identity and trusted known-hosts paths; do not disable host verification.</li>
<li><b>No live deployment output:</b> deployment logs appear when the attempt finishes, not as a live stream. Output is bounded to 1 MiB. Deployment failure or timeout does not change the successful CI test result; check the separate deployment status.</li>
<li><b>Server restart or cancellation:</b> unfinished deployments are marked interrupted rather than replayed. Use a service supervisor to terminate subprocesses. Cancellation and timeout do not undo changes already made on the target.</li>
<li><b>Retry or rollback:</b> there is no built-in deployment retry or automatic rollback. Inspect the target and recover with your deployment tool. A new branch commit that passes CI can trigger a new attempt; rerunning the same already-attempted commit cannot.</li></ul>
<p>Deployment attempt records survive CI history pruning. Separate <b>[Deployment]</b> emails use the repository's existing email recipients and mode: off disables them, failures includes failed/timed-out/interrupted attempts, all completions includes successes, and failures and recovery adds success after a failed deployment. Configure server SMTP under Admin → Email first. Skipped deployments do not send messages. Emails contain metadata and an optional run link, never scripts or output. Delivery status appears in the Deployment section; email failure does not change the deployment result. Queued messages survive restart; uncertain sends are not automatically retried, and deployment email has no retry button yet. CI completion emails still describe tests, not deployment success. This feature does not provide remote runner pools, environment approvals, or a secrets manager.</p>
</details>

<details><summary>Troubleshooting</summary>
<ul><li><b>No runs appear:</b> enable a matching trigger, check branch filters, and configure a command, steps, or repository file. Save settings before queueing.</li>
<li><b>Configuration failure:</b> check JSON syntax, accepted fields, file size, and the commit supplying the pipeline. Do not put runner, image, events, or protection settings in the repository file.</li>
<li><b>Missing tools or dependencies:</b> install them on the host or bake them into the Docker image. Docker jobs cannot download dependencies because networking is disabled.</li>
<li><b>Merge blocked after a new push:</b> the old success does not apply to changed source or target commits. Wait for a fresh qualifying PR check. Rerunning an outdated run still checks its old commits.</li>
<li><b>No artifacts:</b> check that patterns match files, collection mode matches the result, and the run was not cancelled. Expired/pruned artifacts are no longer downloadable.</li></ul>
</details>
</section>'''))
