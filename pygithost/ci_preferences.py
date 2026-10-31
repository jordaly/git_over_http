"""Page-managed CI defaults, repository overrides and legacy compatibility."""

import copy
import json
import re

RETENTION = {"artifact_retention_days": 36500, "artifact_retention_count": 1000000,
             "run_retention_count": 1000000}
EXECUTION = {"runner", "image", "timeout_seconds", "cancel_superseded"}


def validate(values):
    from .ci import validate_config
    if not isinstance(values, dict) or set(values) - (set(RETENTION) | EXECUTION | {"env", "pipeline_env"}):
        raise ValueError("Invalid CI preferences.")
    result = copy.deepcopy(values)
    for key, value in result.items():
        if value is None:
            continue
        if key == "pipeline_env":
            if not isinstance(value, dict) or len(value) > 16:
                raise ValueError("Invalid pipeline environment variables.")
            for name, env in value.items():
                if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
                    raise ValueError("Invalid pipeline name in variables.")
                validate_config({"env": env})
        else:
            validate_config({key: value})
    return result


def read(conn, owner=None, repo=None):
    global_row = conn.execute("SELECT value FROM server_settings WHERE key='ci_defaults'").fetchone()
    global_values = json.loads(global_row[0]) if global_row else {}
    row = conn.execute("SELECT settings_json FROM repository_ci_settings WHERE owner=? AND repo=?", (owner, repo)).fetchone() if owner is not None else None
    return global_values, json.loads(row[0]) if row else {}


def legacy_retention(config):
    document = config.get("document")
    if document is None:
        return {key: config[key] for key in RETENTION if key in config}
    settings = document.get("settings", {})
    result = {key: settings[key] for key in RETENTION if key in settings}
    retention = document.get("retention", {})
    for key, section, name in (("artifact_retention_days", "artifacts", "days"),
                               ("artifact_retention_count", "artifacts", "max_count"),
                               ("run_retention_count", "runs", "max_count")):
        if name in retention.get(section, {}):
            result[key] = retention[section][name]
    return result


def retention(global_values, repository_values, legacy):
    from .ci import default_config
    defaults = default_config()
    result = {}
    for key in RETENTION:
        inherited = global_values.get(key)
        if inherited is None:
            inherited = defaults[key]
        result[key] = legacy.get(key, inherited)
        if key in repository_values:
            result[key] = inherited if repository_values[key] is None else repository_values[key]
    return result


def environment(global_values, repository_values, legacy, pipeline):
    # A saved variables form owns the repository's variables, including an empty
    # form used to remove old JSON values. Otherwise retain legacy definitions.
    result = dict(global_values.get("env") or {})
    if "env" not in repository_values and "pipeline_env" not in repository_values:
        result.update(legacy)
    result.update(repository_values.get("env") or {})
    result.update((repository_values.get("pipeline_env") or {}).get(pipeline, {}))
    return result


def explicit_execution(document, identity, key):
    public_key = "superseded" if key == "cancel_superseded" else key
    section = "cancellation" if key == "cancel_superseded" else "execution"
    if "file" in document:
        return False
    pipelines = document.get("pipelines", [])
    if isinstance(pipelines, list):
        item = next((item for item in pipelines if item.get("name") == identity), {})
        return public_key in item.get(section, {})
    item = pipelines.get(identity, {})
    defaults = document.get("defaults", {})
    return key in item or key in defaults or public_key in item.get(section, {}) or public_key in defaults.get(section, {})


def apply(config, global_values, repository_values):
    from .ci import default_config
    builtins = {**default_config(), "runner": "docker"}
    document = config.get("document")
    for item in [config, *config.get("pipelines", [])]:
        identity = item.get("pipeline_id", "default")
        for key in EXECUTION:
            value = builtins[key]
            if document is not None and not explicit_execution(document, identity, key):
                item[key] = value
        item["env"] = environment(global_values, repository_values, item.get("env", {}), identity)
    config.update(retention(global_values, repository_values, legacy_retention(config)))
    return config


def editor_document(document):
    """Hide page-managed settings without mutating the persisted source."""
    document = copy.deepcopy(document)
    document.pop("retention", None)
    for key in RETENTION:
        document.get("settings", {}).pop(key, None)
    if not document.get("settings"):
        document.pop("settings", None)
    pipelines = document.get("pipelines", [])
    for item in pipelines if isinstance(pipelines, list) else pipelines.values():
        item.pop("env", None)
        item.get("execution", {}).pop("env", None)
    document.get("defaults", {}).pop("env", None)
    document.get("defaults", {}).get("execution", {}).pop("env", None)
    return document
