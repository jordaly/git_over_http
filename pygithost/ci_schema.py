"""Grouped JSON presentation, translated to the existing execution contract."""

import copy
import re


EXECUTION = {"runner", "image", "timeout_seconds", "env"}
PR_EVENTS = {"opened": "pr_opened", "updated": "pr_updated", "reopened": "pr_reopened", "merged": "pr_merged"}
POLICIES = {"require_ci", "block_direct_pushes", "protected_branches"}
GROUPS = {"execution", "triggers", "cancellation", "artifacts"}
DEPLOYMENT_FIELDS = {"enabled", "branch", "script", "script_content", "run_with", "timeout_seconds"}


def _named(items, path):
    if not isinstance(items, list):
        raise ValueError(f"{path} must be an array of objects with name fields.")
    result = {}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"{path}[{index}] must be an object.")
        name = item.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
            raise ValueError(f"{path}[{index}].name must contain 1–64 letters, digits, underscores or hyphens, starting alphanumeric.")
        if name in result:
            raise ValueError(f"Duplicate {path} name: {name}")
        result[name] = {key: value for key, value in item.items() if key != "name"}
    return result


def split_named_document(document):
    """Lower the two named lists for execution while keeping targets separate."""
    _object(document, {"version", "pipelines", "deployments", "policies", "retention"}, "Configuration")
    pipelines = _named(document.get("pipelines"), "pipelines")
    deployments = _named(document.get("deployments", []), "deployments")
    if len(deployments) > 32:
        raise ValueError("Use at most 32 deployments.")
    for name, pipeline in pipelines.items():
        if "deployment" in pipeline:
            raise ValueError(f"pipelines.{name}: put deployment in the top-level deployments array.")
    for name, deployment in deployments.items():
        _object(deployment, DEPLOYMENT_FIELDS | {"pipeline", "notifications"}, f"deployments.{name}")
        if not isinstance(deployment.get("pipeline"), str) or deployment["pipeline"] not in pipelines:
            raise ValueError(f"deployments.{name}.pipeline must reference an existing pipeline name.")
    grouped = {key: copy.deepcopy(value) for key, value in document.items() if key != "deployments"}
    grouped["pipelines"] = pipelines
    return grouped, deployments


def _object(value, keys, path):
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object.")
    unknown = set(value) - keys
    if unknown:
        raise ValueError(f"{path}: unsupported fields: {', '.join(sorted(unknown))}.")
    return value


def _boolean(value, path):
    if type(value) is not bool:
        raise ValueError(f"{path} must be true or false.")
    return value


def is_grouped(document):
    if not isinstance(document, dict):
        return False
    if isinstance(document.get("pipelines"), list) or set(document) & {"notifications", "policies", "retention"}:
        return True
    if isinstance(document.get("defaults"), dict) and set(document["defaults"]) & {"execution", "triggers", "cancellation"}:
        return True
    return isinstance(document.get("pipelines"), dict) and any(
        isinstance(item, dict) and set(item) & {"execution", "triggers", "cancellation", "notifications"}
        for item in document["pipelines"].values())


def _merge(base, override):
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key != "artifacts" and isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _email(raw, path):
    _object(raw, {"email"}, path)
    email = _object(raw.get("email", {}), {"mode", "recipients"}, path + ".email")
    return {target: email[key] for key, target in (("mode", "email_mode"), ("recipients", "email_recipients")) if key in email}


def _execution(raw, path):
    _object(raw, GROUPS | {"steps", "deployment", "file", "notifications"}, path)
    result = dict(_object(raw.get("execution", {}), EXECUTION, path + ".execution"))
    cancellation = _object(raw.get("cancellation", {}), {"superseded"}, path + ".cancellation")
    if "superseded" in cancellation:
        result["cancel_superseded"] = _boolean(cancellation["superseded"], path + ".cancellation.superseded")
    triggers = _object(raw.get("triggers", {}), {"push", "pull_request", "manual"}, path + ".triggers")
    events = {}
    for key in ("push", "pull_request", "manual"):
        if key not in triggers:
            continue
        allowed = {"enabled"} | ({"branches"} if key != "manual" else set()) | ({"events"} if key == "pull_request" else set())
        trigger = _object(triggers[key], allowed, path + ".triggers." + key)
        enabled = _boolean(trigger.get("enabled", False), path + ".triggers." + key + ".enabled")
        if key == "pull_request":
            selected = trigger.get("events", ["opened", "updated", "reopened"])
            if not isinstance(selected, list) or any(not isinstance(event, str) or event not in PR_EVENTS for event in selected):
                raise ValueError(f"{path}.triggers.pull_request.events must be an array of opened, updated, reopened or merged.")
            events.update({target: enabled and source in selected for source, target in PR_EVENTS.items()})
        else:
            events[key] = enabled
        if key != "manual" and "branches" in trigger:
            result["push_branches" if key == "push" else "pr_branches"] = trigger["branches"]
    if events:
        result["events"] = events
    if "notifications" in raw:
        result.update(_email(raw["notifications"], path + ".notifications"))
    for key in ("steps", "deployment", "file", "artifacts"):
        if key in raw:
            result[key] = raw[key]
    return result


def flatten_document(document):
    """Validate grouped fields and lower them without inventing new runner features."""
    _object(document, {"version", "defaults", "pipelines", "notifications", "policies", "retention"}, "Configuration")
    defaults = _object(document.get("defaults", {}), GROUPS, "defaults")
    shared = copy.deepcopy(defaults)
    if "notifications" in document:
        shared["notifications"] = document["notifications"]
    flat_defaults = _execution(shared, "defaults")
    pipelines = document.get("pipelines")
    if not isinstance(pipelines, dict):
        raise ValueError("pipelines must be an object of named pipelines.")
    flat_pipelines = {}
    for name, pipeline in pipelines.items():
        _object(pipeline, GROUPS | {"steps", "deployment", "file", "notifications"}, f"pipelines.{name}")
        # Validate both the override and the resolved configuration: typos in
        # disabled triggers or malformed groups must never disappear in merging.
        _execution(pipeline, f"pipelines.{name}")
        flat_pipelines[name] = _execution(_merge(shared, pipeline), f"pipelines.{name}")
    policies = _object(document.get("policies", {}), POLICIES, "policies")
    settings = dict(policies)
    retention = _object(document.get("retention", {}), {"artifacts", "runs"}, "retention")
    for kind, fields in (("artifacts", {"days": "artifact_retention_days", "max_count": "artifact_retention_count"}),
                         ("runs", {"max_count": "run_retention_count"})):
        values = _object(retention.get(kind, {}), set(fields), "retention." + kind)
        settings.update({fields[key]: value for key, value in values.items()})
    return {"version": document.get("version", 1), "defaults": flat_defaults,
            "pipelines": flat_pipelines, "settings": settings}


def group_document(document):
    """Present both old formats as two named arrays without changing identities."""
    if isinstance(document.get("pipelines"), list):
        return copy.deepcopy(document)
    grouped = _group_legacy_document(document)
    deployments = []
    pipelines = []
    for name, pipeline in grouped["pipelines"].items():
        baseline = copy.deepcopy(grouped.get("defaults", {}))
        if "notifications" in grouped:
            baseline["notifications"] = grouped["notifications"]
        item = _merge(baseline, pipeline)
        deployment = item.pop("deployment", None)
        if deployment is not None:
            notifications = {"notifications": copy.deepcopy(item["notifications"])} if "notifications" in item else {}
            deployments.append({"name": name, "pipeline": name, **deployment, **notifications})
        pipelines.append({"name": name, **item})
    grouped["pipelines"] = pipelines
    grouped["deployments"] = deployments
    grouped.pop("defaults", None)
    grouped.pop("notifications", None)
    return grouped


def _group_legacy_document(document):
    """Convert previously saved flat documents to one canonical editor format."""
    if is_grouped(document):
        return copy.deepcopy(document)

    def pipeline(raw):
        result = {key: copy.deepcopy(raw[key]) for key in ("steps", "deployment", "file", "artifacts") if key in raw}
        execution = {key: raw[key] for key in sorted(EXECUTION) if key in raw}
        if execution:
            result["execution"] = execution
        if "cancel_superseded" in raw:
            result["cancellation"] = {"superseded": raw["cancel_superseded"]}
        events = raw.get("events", {})
        triggers = {}
        for key in ("push", "manual"):
            if key in events or (key == "push" and "push_branches" in raw):
                triggers[key] = {"enabled": events.get(key, False)}
                if key == "push" and "push_branches" in raw:
                    triggers[key]["branches"] = raw["push_branches"]
        if set(events) & set(PR_EVENTS.values()) or "pr_branches" in raw:
            selected = [key for key, event in PR_EVENTS.items() if events.get(event)]
            triggers["pull_request"] = {"enabled": bool(selected), "events": selected}
            if "pr_branches" in raw:
                triggers["pull_request"]["branches"] = raw["pr_branches"]
        if triggers:
            result["triggers"] = triggers
        email = {key: raw[field] for key, field in (("mode", "email_mode"), ("recipients", "email_recipients")) if field in raw}
        if email:
            result["notifications"] = {"email": email}
        return result

    # Resolve old mapping inheritance before changing its PR flags to one enabled
    # flag plus an events array. This preserves partial legacy PR overrides.
    defaults = document.get("defaults", {})
    grouped_defaults = pipeline(defaults)
    notifications = grouped_defaults.pop("notifications", None)
    pipelines = {}
    for name, raw in document["pipelines"].items():
        merged = {**defaults, **raw}
        for key in ("env", "events"):
            if key in defaults and key in raw:
                merged[key] = {**defaults[key], **raw[key]}
        grouped = pipeline(merged)
        for key in list(grouped):
            if grouped.get(key) == grouped_defaults.get(key):
                grouped.pop(key)
        if notifications and grouped.get("notifications") == notifications:
            grouped.pop("notifications")
        pipelines[name] = grouped
    result = {"version": document.get("version", 1), "pipelines": pipelines}
    if grouped_defaults:
        result["defaults"] = grouped_defaults
    if notifications:
        result["notifications"] = notifications
    settings = document.get("settings", {})
    policies = {key: settings[key] for key in sorted(POLICIES) if key in settings}
    if policies:
        result["policies"] = policies
    retention = {}
    artifacts = {key: settings[field] for key, field in (("days", "artifact_retention_days"), ("max_count", "artifact_retention_count")) if field in settings}
    if artifacts:
        retention["artifacts"] = artifacts
    if "run_retention_count" in settings:
        retention["runs"] = {"max_count": settings["run_retention_count"]}
    if retention:
        result["retention"] = retention
    return result
