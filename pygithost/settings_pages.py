"""Form rendering/validation for page-managed server and repository settings."""

import hashlib
import json
import os
from pathlib import Path
import tempfile

from .ci import default_config
from .ci_preferences import RETENTION, validate
from .config import AppConfig
from .rendering import html_t, join_html, safe_html

RETENTION_FIELDS = (("artifact_retention_days", "Artifact retention (days; 0 = unlimited)", 7),
                    ("artifact_retention_count", "Maximum artifact bundles (0 = unlimited)", 0),
                    ("run_retention_count", "Maximum completed runs (0 = unlimited)", None))


def preferences_forms(action, token, global_values, local_values=None, *, legacy=None, pipelines=(), submitted=None):
    repository = local_values is not None
    local = dict(local_values or {}) if repository else dict(global_values)
    legacy = legacy or {}
    for key in RETENTION:
        if key not in local and key in legacy:
            local[key] = legacy[key]
    forms = []
    for kind, title, fields in (("retention", "Runs and artifacts", RETENTION_FIELDS),):
        controls = []
        for key, label, builtin in fields:
            builtin = default_config()[key] if builtin is None else builtin
            inherited = global_values.get(key)
            inherited = builtin if inherited is None else inherited
            value = local.get(key)
            inherit = repository and value is None
            if submitted and submitted.get("action") == "ci_" + kind:
                inherit = repository and bool(submitted.get("inherit_" + key))
                value = None if inherit else submitted.get(key, "")
                if key == "cancel_superseded" and value is not None:
                    value = value == "true"
            if value is None:
                value = inherited if repository else builtin
            inheritance = safe_html(html_t(t'<label class="settings-inherit"><input type="checkbox" name="inherit_{key}" data-inherits="{key}"{safe_html(" checked" if inherit else "")}> Use server default ({str(inherited)})</label>')) if repository else safe_html("")
            if key == "runner":
                control = html_t(t'<select id="pref-{key}" name="{key}"><option value="docker"{safe_html(" selected" if value == "docker" else "")}>Docker</option><option value="host"{safe_html(" selected" if value == "host" else "")}>Host (trusted code only)</option></select>')
            elif key == "cancel_superseded":
                control = html_t(t'<select id="pref-{key}" name="{key}"><option value="false"{safe_html(" selected" if not value else "")}>No</option><option value="true"{safe_html(" selected" if value else "")}>Yes</option></select>')
            else:
                kind_type = "text" if key == "image" else "number"
                control = html_t(t'<input id="pref-{key}" name="{key}" type="{kind_type}" value="{value}">')
            controls.append(html_t(t'<div class="settings-field" data-setting="{key}"><label for="pref-{key}">{label}</label>{safe_html(control)}{inheritance}</div>'))
        confirmation = safe_html('<label><input type="checkbox" name="confirm_retention" value="yes" required> Apply retention limits; this may permanently delete existing data immediately (completed runs and artifacts).</label>') if kind == "retention" else safe_html("")
        forms.append(html_t(t'<section class="box"><h2>{title}</h2><form method="POST" action="{action}" class="settings-page-form"><input type="hidden" name="action" value="ci_{kind}"><input type="hidden" name="csrf" value="{token}"><div class="settings-grid">{join_html(controls)}</div>{confirmation}<button type="submit">Save {title.lower()}</button></form></section>'))
    values = local.get("env", legacy.get("env", {})) or {}
    pipeline_values = local.get("pipeline_env", legacy.get("pipeline_env", {})) or {}
    names = sorted(set(pipelines) | set(pipeline_values))

    def row(index, name="", value="", pipeline=""):
        options = join_html([html_t(t'<option value="{item}"{safe_html(" selected" if item == pipeline else "")}>{item}</option>') for item in names])
        scope = safe_html(html_t(t'<label>Pipeline<select name="env_pipeline_{index}"><option value="">All pipelines</option>{options}</select></label>')) if repository else safe_html("")
        return html_t(t'<div class="settings-env-row"><label>Name<input name="env_name_{index}" value="{name}" autocomplete="off" spellcheck="false"></label><label>Value<input class="settings-env-value" type="password" name="env_value_{index}" value="{value}" autocomplete="off" spellcheck="false"></label>{scope}<label class="settings-remove"><input type="checkbox" name="env_remove_{index}"> Remove</label></div>')

    if submitted and submitted.get("action") == "ci_environment":
        try:
            count = min(256, max(0, int(submitted.get("env_count", "0"))))
        except ValueError:
            count = 0
        rows = [row(index, submitted.get(f"env_name_{index}", ""), submitted.get(f"env_value_{index}", ""), submitted.get(f"env_pipeline_{index}", "")) for index in range(count)]
    else:
        rows = [row(index, name, value) for index, (name, value) in enumerate(sorted(values.items()))]
        for pipeline, env in sorted(pipeline_values.items()):
            for name, value in sorted(env.items()):
                rows.append(row(len(rows), name, value, pipeline))
    if len(rows) < 256:
        rows.append(row(len(rows)))
    inherited_names = ", ".join(sorted(global_values.get("env") or {})) or "None"
    inherited_note = safe_html(html_t(t'<p class="muted">Inherited server variables: {inherited_names}. Repository values override matching names; removing an override restores inheritance.</p>')) if repository else safe_html("")
    forms.append(html_t(t'<section class="box"><h2>Environment variables</h2>{inherited_note}<form method="POST" action="{action}" class="settings-page-form settings-env-form"><input type="hidden" name="action" value="ci_environment"><input type="hidden" name="csrf" value="{token}"><input type="hidden" name="env_count" value="{len(rows)}"><div class="settings-env-rows">{join_html(rows)}</div><template>{safe_html(row("__index__"))}</template><div class="row"><button type="button" class="settings-add-env">Add variable</button><button type="button" class="settings-show-env">Show values</button><button type="submit">Save variables</button></div><p class="muted">Stored in plaintext. CI logs are not secret-redacted. Reserved runner variables are rejected.</p></form></section>'))
    return safe_html(join_html(forms))


def parse_preferences(form, previous, *, repository=False):
    values = dict(previous)
    action = form.get("action")
    if action == "ci_retention":
        if action == "ci_retention" and form.get("confirm_retention") != "yes":
            raise ValueError("Confirm applying retention limits before saving.")
        fields = RETENTION_FIELDS
        for key, _label, _builtin in fields:
            if repository and form.get("inherit_" + key):
                values[key] = None
            elif key in ("runner", "image"):
                values[key] = form.get(key, "").strip()
            elif key == "cancel_superseded":
                if form.get(key) not in ("true", "false"):
                    raise ValueError("Select Yes or No for cancellation.")
                values[key] = form[key] == "true"
            else:
                text = form.get(key, "")
                if not text.isascii() or not text.isdecimal():
                    raise ValueError(f"Enter a nonnegative whole number for {_label}.")
                values[key] = int(text)
    elif action == "ci_environment":
        count = int(form.get("env_count", "0"))
        if not 0 <= count <= 256:
            raise ValueError("At most 256 variable rows are supported.")
        env, pipeline_env, seen = {}, {}, set()
        for index in range(count):
            if form.get(f"env_remove_{index}"):
                continue
            name, value = form.get(f"env_name_{index}", "").strip(), form.get(f"env_value_{index}", "")
            pipeline = form.get(f"env_pipeline_{index}", "") if repository else ""
            if not name and not value:
                continue
            if (pipeline, name) in seen:
                raise ValueError(f"Duplicate variable: {name}.")
            seen.add((pipeline, name))
            (pipeline_env.setdefault(pipeline, {}) if pipeline else env)[name] = value
        values["env"] = env
        if repository:
            values["pipeline_env"] = pipeline_env
    else:
        raise ValueError("Unknown settings action.")
    return validate(values)


BASIC_GROUPS = {
    "Network": ("host", "port", "url_prefix", "realm"),
    "Storage and Git": ("git_project_root", "git_http_backend", "db_path", "trace_log", "flat_owner_ui"),
    "Security": ("require_auth", "filter_ips", "allowed_client_ips", "session_cookie_secure", "session_ttl_seconds", "static_requires_auth"),
    "Advanced": ("session_cookie_name", "login_path", "static_url_prefix", "static_root", "static_cache_seconds", "pr_patch_max_bytes", "prism_diff_highlight_max_bytes", "max_header_bytes", "read_chunk"),
}
LABELS = {"host": "Bind address", "port": "HTTP port", "url_prefix": "Git URL prefix", "realm": "Authentication realm",
          "git_project_root": "Repository storage directory", "git_http_backend": "Git HTTP backend executable",
          "db_path": "Database path", "trace_log": "Git trace log (optional)", "require_auth": "Require authentication",
          "filter_ips": "Restrict client IPs", "allowed_client_ips": "Allowed IP addresses (one per line)",
          "session_cookie_secure": "HTTPS-only session cookies", "static_requires_auth": "Require authentication for static files"}


def basic_form(action, token, running, config_path):
    values = AppConfig.from_file(config_path).to_dict() if config_path else running
    revision = hashlib.sha256(Path(config_path).read_bytes()).hexdigest() if config_path else ""
    groups = []
    for title, fields in BASIC_GROUPS.items():
        controls = []
        for key in fields:
            value = values[key]
            if isinstance(value, bool):
                control = html_t(t'<input type="checkbox" name="basic_{key}" value="yes"{safe_html(" checked" if value else "")}>')
            elif key == "allowed_client_ips":
                control = html_t(t'<textarea name="basic_{key}" rows="4">{"\n".join(value)}</textarea>')
            else:
                control = html_t(t'<input name="basic_{key}" type="{"number" if isinstance(value, int) else "text"}" value="{value if value is not None else ""}">')
            controls.append(html_t(t'<label>{LABELS.get(key, key.replace("_", " ").capitalize())}{safe_html(control)}</label>'))
        groups.append(html_t(t'<fieldset><legend>{title}</legend><div class="settings-grid">{join_html(controls)}</div></fieldset>'))
    disabled = safe_html("" if config_path else " disabled")
    location = str(config_path) if config_path else "No startup configuration file was supplied (read-only)."
    return safe_html(html_t(t'<section class="box"><h2>Basic server configuration</h2><p class="muted">{location}</p><p>Changes are written to the startup configuration file and require a server restart. They do not change the running listener, security settings, database or storage paths immediately.</p><form method="POST" action="{action}"><input type="hidden" name="action" value="basic"><input type="hidden" name="csrf" value="{token}"><input type="hidden" name="basic_revision" value="{revision}"><fieldset{disabled}>{join_html(groups)}<label><input type="checkbox" name="confirm_restart" value="yes" required> I will restart the server and have reviewed authentication, allowed IPs, paths and cookie settings.</label><button type="submit">Save configuration for next restart</button></fieldset></form></section>'))


def save_basic(config_path, form):
    if not config_path:
        raise ValueError("This server was not started with a configuration file.")
    if form.get("confirm_restart") != "yes":
        raise ValueError("Confirm that these changes require a restart.")
    path = Path(config_path)
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != form.get("basic_revision"):
        raise ValueError("The configuration file changed. Reload settings before saving.")
    raw = json.loads(data)
    current = AppConfig.from_mapping(raw).to_dict()
    for key in (key for keys in BASIC_GROUPS.values() for key in keys):
        old = current[key]
        text = form.get("basic_" + key, "")
        if isinstance(old, bool):
            current[key] = text == "yes"
        elif isinstance(old, int):
            if not text.isascii() or not text.isdecimal():
                raise ValueError(f"{key} must be a nonnegative integer.")
            current[key] = int(text)
        elif key == "allowed_client_ips":
            import ipaddress
            current[key] = [str(ipaddress.ip_address(value.strip())) for value in text.splitlines() if value.strip()]
        else:
            if len(text) > 4096 or any(ord(char) < 32 for char in text):
                raise ValueError(f"Invalid {key}.")
            current[key] = None if key == "trace_log" and not text else text
    for key in ("git_project_root", "git_http_backend", "db_path", "static_root", "session_cookie_name", "flat_owner_ui"):
        if not current[key]:
            raise ValueError(f"{key} cannot be empty.")
    for key in ("session_ttl_seconds", "max_header_bytes", "read_chunk"):
        if not 1 <= current[key] <= 100000000:
            raise ValueError(f"{key} must be between 1 and 100000000.")
    if current["filter_ips"] and not current["allowed_client_ips"]:
        raise ValueError("Add an allowed IP before enabling IP restrictions.")
    AppConfig.from_mapping(current)
    raw.update(current)
    fd, temporary = tempfile.mkstemp(prefix=".server-settings-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.chmod(temporary, path.stat().st_mode & 0o777)
            json.dump(raw, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
