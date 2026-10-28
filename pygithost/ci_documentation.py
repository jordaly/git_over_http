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
<nav class="row" aria-label="CI guide sections"><a href="#ci-guide-start">Quick start</a><a href="#ci-guide-json">JSON reference</a><a href="#ci-guide-settings">Server settings</a><a href="#ci-guide-variables">Variables</a></nav>

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
</details>

<details><summary>Artifacts: downloadable files</summary>
<p>In the form, enter one file pattern per line. In JSON, use <code>"artifacts": {{"paths": ["dist/*", "reports/**/*.xml"], "when": "always"}}</code>.</p>
<ul><li>Paths are relative to the checkout. Use forward slashes. Matched directories are not implicitly archived; choose file patterns. No matches means no download.</li>
<li><code>always</code> is the default; <code>success</code> collects only after success; <code>failure</code> collects after failure or timeout. Cancelled runs do not collect artifacts.</li>
<li>Files are collected before checkout cleanup and offered as one ZIP on the run page. Content is not interpreted, including test reports.</li>
<li>Limits: 32 patterns, 256 characters per pattern, 1000 files, 10,000 matched entries, and 20 MiB total uncompressed content per run. Collection errors or limit violations fail the run.</li>
<li>Absolute paths, parent traversal, and <code>.git</code> paths are rejected/excluded. Symlinks, junctions, and hardlinks are not collected.</li>
<li>Downloads use the same access controls as CI logs. Archives expire after 7 days, or earlier when the run is pruned.</li></ul>
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

<details><summary>Troubleshooting</summary>
<ul><li><b>No runs appear:</b> enable a matching trigger, check branch filters, and configure a command, steps, or repository file. Save settings before queueing.</li>
<li><b>Configuration failure:</b> check JSON syntax, accepted fields, file size, and the commit supplying the pipeline. Do not put runner, image, events, or protection settings in the repository file.</li>
<li><b>Missing tools or dependencies:</b> install them on the host or bake them into the Docker image. Docker jobs cannot download dependencies because networking is disabled.</li>
<li><b>Merge blocked after a new push:</b> the old success does not apply to changed source or target commits. Wait for a fresh qualifying PR check. Rerunning an outdated run still checks its old commits.</li>
<li><b>No artifacts:</b> check that patterns match files, collection mode matches the result, and the run was not cancelled. Expired/pruned artifacts are no longer downloadable.</li></ul>
</details>
</section>'''))
