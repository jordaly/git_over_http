"""The single administrator-facing JSON format for repository CI settings."""

import json

from .ci import default_config, validate_config
from .ci_email import validate_recipients


SETTINGS = {"require_ci", "block_direct_pushes", "protected_branches",
            "artifact_retention_days", "artifact_retention_count", "run_retention_count"}
COMMON = {"runner", "image", "env", "events", "push_branches", "pr_branches",
          "timeout_seconds", "cancel_superseded", "email_mode", "email_recipients",
          "artifacts"}
DEPLOYMENT = {"enabled": "deploy_enabled", "branch": "deploy_branch",
              "script": "deploy_script", "script_content": "deploy_script_content",
              "run_with": "deploy_interpreter", "timeout_seconds": "deploy_timeout"}
BRANCH_FILTERS = ("push_branches", "pr_branches")
STRING_LISTS = (*BRANCH_FILTERS, "protected_branches", "email_recipients")


def _execution_fields(raw, label):
    """Translate public string arrays to the legacy runner's line-based values."""
    result = dict(raw)
    for key in STRING_LISTS:
        if key not in result:
            continue
        patterns = result[key]
        if not isinstance(patterns, list) or any(
            not isinstance(pattern, str) or not pattern.strip()
            or any(char in pattern for char in ("\n", "\r", "\0"))
            for pattern in patterns
        ):
            raise ValueError(f"{label}.{key} must be an array of nonempty strings.")
        if key == "email_recipients":
            for address in patterns:
                if len(validate_recipients(address)) != 1:
                    raise ValueError(f"{label}.email_recipients: use one email address per array entry.")
        result[key] = "\n".join(patterns)
    return result


def _export_filters(raw):
    result = dict(raw)
    for key in STRING_LISTS:
        if isinstance(result.get(key), str):
            value = result[key].replace(",", "\n") if key == "email_recipients" else result[key]
            result[key] = [line.strip() for line in value.splitlines() if line.strip()]
    return result

EXAMPLE = {
    "version": 1,
    "defaults": {"events": {"push": True, "manual": True}, "timeout_seconds": 600},
    "pipelines": {
        "tests": {"steps": [{"name": "Unit tests", "run": "python -m unittest discover -v"}]},
        "compile": {"steps": [{"name": "Compile sources", "run": "python -m compileall -q ."}]},
    },
}


def _object(value, allowed, label):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object.")
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"{label}: unknown fields: {', '.join(sorted(unknown))}.")
    return value


def compile_document(document):
    from .ci_schema import flatten_document, is_grouped, split_named_document, _email
    if isinstance(document, dict) and isinstance(document.get("pipelines"), list):
        grouped, deployments = split_named_document(document)
        flat = flatten_document(grouped)
        for name, target in deployments.items():
            pipeline = flat["pipelines"][target["pipeline"]]
            fields = {DEPLOYMENT[key]: value for key, value in target.items() if key in DEPLOYMENT}
            if target.get("script") and target.get("script_content"):
                raise ValueError(f"deployments.{name}: use script or script_content, not both.")
            fields.update(deployment_name=name, deploy_enabled=target.get("enabled", True))
            email = _email(target.get("notifications", {}), f"deployments.{name}.notifications")
            fields.update(email_mode=email.get("email_mode", "off"),
                          email_recipients=_execution_fields(email, f"deployments.{name}").get("email_recipients", ""))
            pipeline.setdefault("deployment_targets", []).append(fields)
        result = _compile_flat_document(flat)
        result["document"] = json.loads(json.dumps(document))
        return result
    if is_grouped(document):
        result = _compile_flat_document(flatten_document(document))
        result["document"] = json.loads(json.dumps(document))
        return result
    return _compile_flat_document(document)


def editor_document(config):
    from .ci_schema import group_document
    return group_document(export_document(config))


def _compile_flat_document(document):
    """Validate and expand shared defaults into execution snapshots."""
    _object(document, {"version", "defaults", "pipelines", "settings"}, "Configuration")
    if type(document.get("version", 1)) is not int or document.get("version", 1) != 1:
        raise ValueError("Configuration version must be 1.")
    defaults = _object(document.get("defaults", {}), COMMON, "defaults")
    settings = _object(document.get("settings", {}), SETTINGS, "settings")
    settings = _execution_fields(settings, "settings")
    if "events" in defaults:
        _object(defaults["events"], set(default_config()["events"]), "defaults.events")
    validate_config(_execution_fields(defaults, "defaults"))
    pipelines = document.get("pipelines")
    if not isinstance(pipelines, dict) or len(pipelines) > 16:
        raise ValueError("pipelines must be an object with at most 16 named pipelines.")
    compiled = []
    for identity, raw in pipelines.items():
        _object(raw, COMMON | {"steps", "deployment", "file", "deployment_targets"}, f"pipelines.{identity}")
        effective = {**defaults, **raw, "pipeline_id": identity}
        # Merge mappings so a pipeline can override one variable or event without
        # restating shared values. Other fields replace their shared value.
        for key in ("env", "events"):
            if key in defaults and key in raw:
                if not isinstance(defaults[key], dict) or not isinstance(raw[key], dict):
                    raise ValueError(f"{identity}.{key} must be an object.")
                effective[key] = {**defaults[key], **raw[key]}
        if "events" in effective:
            _object(effective["events"], set(default_config()["events"]), f"{identity}.events")
        deployment = _object(raw.get("deployment", {}), set(DEPLOYMENT), f"{identity}.deployment")
        if deployment.get("script") and deployment.get("script_content"):
            raise ValueError(f"{identity}.deployment: use script or script_content, not both.")
        effective.update({DEPLOYMENT[key]: value for key, value in deployment.items()})
        if "deployment" in raw:
            effective["deploy_enabled"] = deployment.get("enabled", True)
        if "file" in raw:
            if "steps" in raw:
                raise ValueError(f"{identity}: use steps or file, not both.")
            effective.update(repository_config=True, repository_file=raw["file"])
        elif not isinstance(raw.get("steps"), list) or not raw["steps"]:
            raise ValueError(f"{identity}: provide a nonempty steps array.")
        try:
            compiled.append(validate_config(_execution_fields(effective, f"pipelines.{identity}")))
        except ValueError as exc:
            raise ValueError(f"pipelines.{identity}: {exc}") from exc
    # Reuse the existing persistence layout without requiring a special default
    # pipeline in the administrator document.
    root = next((item for item in compiled if item["pipeline_id"] == "default"), compiled[0] if compiled else default_config())
    root = {**root, **settings, "pipelines": [item for item in compiled if item["pipeline_id"] != root["pipeline_id"]]}
    result = validate_config(root)
    result["document"] = json.loads(json.dumps(document))
    return result


def export_document(config):
    """Expose existing settings without dropping legacy commands or Git sources."""
    if "document" in config:
        document = json.loads(json.dumps(config["document"]))
        if isinstance(document.get("pipelines"), list):
            return document
        if "defaults" in document:
            document["defaults"] = _export_filters(document["defaults"])
        if "settings" in document:
            document["settings"] = _export_filters(document["settings"])
        document["pipelines"] = {name: _export_filters(item) for name, item in document["pipelines"].items()}
        return document
    baseline = default_config()
    pipelines = {}
    for item in [{**config, "pipelines": []}, *config.get("pipelines", [])]:
        if not (item.get("steps") or item.get("command") or item.get("repository_config") or item.get("deploy_enabled")):
            continue
        pipeline = {key: item[key] for key in sorted(COMMON) if key in item and item[key] != baseline.get(key)}
        if item.get("repository_config"):
            pipeline["file"] = item.get("repository_file", ".pygithost-ci.json")
        else:
            pipeline["steps"] = item.get("steps") or [{"name": "Run", "run": item.get("command", "")}]
        deployment = {key: item[field] for key, field in DEPLOYMENT.items()
                      if field in item and item[field] != baseline.get(field)}
        if deployment:
            deployment["enabled"] = item.get("deploy_enabled", False)
            pipeline["deployment"] = deployment
        pipelines[item.get("pipeline_id", "default")] = _export_filters(pipeline)
    shared = {}
    if len(pipelines) > 1:
        entries = list(pipelines.values())
        for key in sorted(COMMON):
            if key in entries[0] and all(item.get(key) == entries[0][key] for item in entries):
                shared[key] = entries[0][key]
        for item in entries:
            for key in shared:
                item.pop(key)
    settings = {key: config[key] for key in sorted(SETTINGS) if key in config and config[key] != baseline.get(key)}
    settings = _export_filters(settings)
    return {"version": 1, **({"defaults": shared} if shared else {}),
            "pipelines": pipelines, **({"settings": settings} if settings else {})}
