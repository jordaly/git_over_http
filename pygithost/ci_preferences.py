"""Page-managed CI defaults, repository overrides and legacy compatibility."""

import copy
import re
import sqlite3
from collections.abc import Mapping
from typing import Any

from .database_types import JSONObject, RetentionConfig, decode_json_object
from .runner_types import JsonObject

RETENTION = {
    "artifact_retention_days": 36500,
    "artifact_retention_count": 1000000,
    "run_retention_count": 1000000,
}
EXECUTION = {"runner", "image", "timeout_seconds", "cancel_superseded"}
# ``env_scopes`` is metadata for repository values.  The empty identity is the
# repository-wide environment; other identities are pipeline names.
ENV_SCOPES = {"ordinary", "protected", "deployment"}
DEFAULT_ENV_SCOPE = "ordinary"


def validate(values: object) -> JsonObject:
    from .ci import validate_config

    if not isinstance(values, dict) or set(values) - (
        set(RETENTION) | EXECUTION | {"env", "pipeline_env", "env_scopes"}
    ):
        raise ValueError("Invalid CI preferences.")
    result: JsonObject = copy.deepcopy(values)
    for key, value in result.items():
        if value is None:
            continue
        if key == "env_scopes":
            if not isinstance(value, dict) or len(value) > 17:
                raise ValueError("Invalid environment scopes.")
            for identity, entries in value.items():
                if not isinstance(identity, str) or (
                    identity and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", identity)
                ):
                    raise ValueError("Invalid pipeline name in environment scopes.")
                if (
                    not isinstance(entries, dict)
                    or len(entries) > 64
                    or any(
                        not isinstance(name, str)
                        or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
                        or not isinstance(scope, str)
                        or scope not in ENV_SCOPES
                        for name, scope in entries.items()
                    )
                ):
                    raise ValueError("Invalid environment scope.")
        elif key == "pipeline_env":
            if not isinstance(value, dict) or len(value) > 16:
                raise ValueError("Invalid pipeline environment variables.")
            for name, env in value.items():
                if not isinstance(name, str) or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name
                ):
                    raise ValueError("Invalid pipeline name in variables.")
                validate_config({"env": env})
        else:
            validate_config({key: value})
    return result


def read(
    conn: sqlite3.Connection, owner: str | None = None, repo: str | None = None
) -> tuple[JSONObject, JSONObject]:
    global_row = conn.execute(
        "SELECT value FROM server_settings WHERE key='ci_defaults'"
    ).fetchone()
    global_values: JSONObject = decode_json_object(global_row[0]) if global_row else {}
    row = (
        conn.execute(
            "SELECT settings_json FROM repository_ci_settings WHERE owner=? AND repo=?",
            (owner, repo),
        ).fetchone()
        if owner is not None
        else None
    )
    repository_values: JSONObject = decode_json_object(row[0]) if row else {}
    return global_values, repository_values


def legacy_retention(config: Mapping[str, Any]) -> JsonObject:
    document = config.get("document")
    if document is None:
        return {key: config[key] for key in RETENTION if key in config}
    settings = document.get("settings", {})
    result = {key: settings[key] for key in RETENTION if key in settings}
    retention_document = document.get("retention", {})
    for key, section, name in (
        ("artifact_retention_days", "artifacts", "days"),
        ("artifact_retention_count", "artifacts", "max_count"),
        ("run_retention_count", "runs", "max_count"),
    ):
        if name in retention_document.get(section, {}):
            result[key] = retention_document[section][name]
    return result


def retention(
    global_values: Mapping[str, Any],
    repository_values: Mapping[str, Any],
    legacy: Mapping[str, Any],
) -> RetentionConfig:
    from .ci import default_config

    defaults = default_config()
    result: dict[str, Any] = {}
    for key in RETENTION:
        inherited = global_values.get(key)
        if inherited is None:
            inherited = defaults[key]
        result[key] = legacy.get(key, inherited)
        if key in repository_values:
            result[key] = inherited if repository_values[key] is None else repository_values[key]
    return RetentionConfig(
        artifact_retention_days=result["artifact_retention_days"],
        artifact_retention_count=result["artifact_retention_count"],
        run_retention_count=result["run_retention_count"],
    )


def environment(
    global_values: Mapping[str, Any],
    repository_values: Mapping[str, Any],
    legacy: Mapping[str, Any],
    pipeline: str,
    *,
    repository_owned: bool = False,
) -> dict[str, str]:
    # A saved variables form owns the repository's variables, including an empty
    # form used to remove old JSON values. Otherwise retain legacy definitions.
    result: dict[str, str] = dict(global_values.get("env") or {})
    if repository_owned or (
        "env" not in repository_values and "pipeline_env" not in repository_values
    ):
        result.update(legacy)
    result.update(repository_values.get("env") or {})
    result.update((repository_values.get("pipeline_env") or {}).get(pipeline, {}))
    return result


def page_environment(
    global_values: Mapping[str, Any],
    repository_values: Mapping[str, Any],
    pipeline: str,
    *,
    event: str,
    protected: bool = False,
    deployment: bool = False,
) -> dict[str, str]:
    """Resolve page-managed values that are safe for one execution phase.

    Unmerged pull-request events never receive page-managed values, including
    server-wide defaults.  Scopes are independent: an ordinary value is not
    reused during deployment, a protected-branch value never authorizes a
    deployment, and a deployment value is not available to ordinary runs.
    """
    from .ci import UNMERGED_PR_EVENTS

    if event in UNMERGED_PR_EVENTS:
        return {}
    result: dict[str, str] = {}
    scopes = repository_values.get("env_scopes") or {}
    for values, restrictions in (
        (global_values.get("env") or {}, {}),
        (repository_values.get("env") or {}, scopes.get("") or {}),
        (
            (repository_values.get("pipeline_env") or {}).get(pipeline, {}),
            scopes.get(pipeline) or {},
        ),
    ):
        for name, value in values.items():
            # A restricted override must not silently fall back to a value
            # supplied by a broader scope.
            result.pop(name, None)
            scope = restrictions.get(name, DEFAULT_ENV_SCOPE)
            allowed = (
                (scope == "ordinary" and not deployment)
                or (scope == "protected" and protected and not deployment)
                or (scope == "deployment" and deployment)
            )
            if allowed:
                result[name] = value
    return result


def explicit_execution(document: Mapping[str, Any], identity: str, key: str) -> bool:
    public_key = "superseded" if key == "cancel_superseded" else key
    section = "cancellation" if key == "cancel_superseded" else "execution"
    if "file" in document:
        return False
    pipelines = document.get("pipelines", [])
    if isinstance(pipelines, list):
        item: JsonObject = next((item for item in pipelines if item.get("name") == identity), {})
        return public_key in item.get(section, {})
    item = pipelines.get(identity, {})
    defaults = document.get("defaults", {})
    return (
        key in item
        or key in defaults
        or public_key in item.get(section, {})
        or public_key in defaults.get(section, {})
    )


def apply(
    config: JsonObject,
    global_values: Mapping[str, Any],
    repository_values: Mapping[str, Any],
    *,
    repository_owned: bool = False,
) -> JsonObject:
    from .ci import default_config

    builtins: JsonObject = {**default_config(), "runner": "docker"}
    document = config.get("document")
    for item in [config, *config.get("pipelines", [])]:
        identity = item.get("pipeline_id", "default")
        for key in EXECUTION:
            value = builtins[key]
            if document is not None and not explicit_execution(document, identity, key):
                item[key] = value
        item["env"] = environment(
            global_values,
            repository_values,
            item.get("env", {}),
            identity,
            repository_owned=repository_owned,
        )
    config.update(retention(global_values, repository_values, legacy_retention(config)))
    return config


def editor_document(document: JsonObject) -> JsonObject:
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
