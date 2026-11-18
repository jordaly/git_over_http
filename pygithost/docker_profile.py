"""Declarative container requests and worker-owned security ceilings.

Never accept arbitrary Docker arguments or repository-provided host paths.
"""

import copy
import math
import re
from pathlib import Path
from typing import Any

DEFAULTS: dict[str, Any] = {
    "cpus": 1,
    "memory_mb": 1024,
    "pids_limit": 128,
    "tmpfs_mb": 256,
    "read_only": True,
    "network": "none",
    "user": "runner",
    "checkout_path": "/workspace",
    "checkout_read_only": False,
    "workdir": "/workspace",
    "mounts": [],
    "tmpfs": [],
}
POLICY_DEFAULTS: dict[str, Any] = {
    "max_cpus": 1,
    "max_memory_mb": 1024,
    "max_pids_limit": 128,
    "max_tmpfs_mb": 256,
    "max_timeout_seconds": 1800,
    "networks": ["none"],
    "allow_writable_root": False,
    "allow_root": False,
    "secrets": {},
    "image_pull": "missing",
    "max_image_pull_timeout_seconds": 600,
    "builds": {
        "repositories": [],
        "events": [],
        "networks": ["none"],
        "max_timeout_seconds": 1800,
        "max_memory_mb": 1024,
        "max_cpus": 1,
    },
}


def container_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 256
        or not re.fullmatch(r"/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", value)
        or any(part in (".", "..") for part in value.split("/"))
        or value.split("/")[1] in ("proc", "sys", "dev", "etc", "run")
        or value == "/var/run"
        or value.startswith("/var/run/")
    ):
        raise ValueError("Docker paths must be safe absolute container paths, not system mounts.")
    return value


def number(value: object, low: float, high: float, label: str, integer: bool = True) -> int | float:
    if (
        not isinstance(value, int | float)
        or type(value) not in ((int,) if integer else (int, float))
        or not low <= value <= high
        or not math.isfinite(value)
    ):
        raise ValueError(
            f"{label} must be {'an integer' if integer else 'a number'} between {low} and {high}."
        )
    return value


def profile(raw: object = None) -> dict[str, Any]:
    raw = {} if raw is None else raw
    if not isinstance(raw, dict) or set(raw) - set(DEFAULTS):
        raise ValueError("Unknown Docker profile fields.")
    result: dict[str, Any] = {**copy.deepcopy(DEFAULTS), **copy.deepcopy(raw)}
    result["cpus"] = number(result["cpus"], 0.1, 64, "docker.cpus", False)
    for key, high in (("memory_mb", 131072), ("pids_limit", 32768), ("tmpfs_mb", 131072)):
        number(result[key], 1, high, "docker." + key)
    for key in ("read_only", "checkout_read_only"):
        if type(result[key]) is not bool:
            raise ValueError("docker.read_only must be boolean.")
    if result["user"] not in ("runner", "root"):
        raise ValueError("docker.user must be runner or root.")
    if (
        not isinstance(result["network"], str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", result["network"])
        or result["network"] in ("host", "container")
    ):
        raise ValueError(
            "Docker network must be none, bridge or an administrator-approved named network; host is forbidden."
        )
    result["checkout_path"] = container_path(result["checkout_path"])
    if result["checkout_path"] == "/tmp" or result["checkout_path"].startswith("/tmp/"):
        raise ValueError("Checkout cannot overlap the /tmp tmpfs.")
    result["workdir"] = container_path(raw.get("workdir", result["checkout_path"]))
    targets = [result["checkout_path"], "/tmp"]
    for key in ("mounts", "tmpfs"):
        entries = result[key]
        if not isinstance(entries, list) or len(entries) > 16:
            raise ValueError(f"docker.{key} must contain at most 16 entries.")
        for item in entries:
            allowed = {"target", "size_mb"} if key == "tmpfs" else {"source", "target", "read_only"}
            if not isinstance(item, dict) or set(item) - allowed or "target" not in item:
                raise ValueError(f"Invalid docker.{key} entry.")
            target = container_path(item["target"])
            if any(
                target == path or target.startswith(path + "/") or path.startswith(target + "/")
                for path in targets
            ):
                raise ValueError("Docker mounts/tmpfs cannot overlap or shadow another mount.")
            targets.append(target)
            if key == "tmpfs":
                number(item.get("size_mb"), 1, 131072, "tmpfs.size_mb")
            else:
                source = item.get("source")
                if not isinstance(source, str) or (
                    source not in ("checkout", "results")
                    and not re.fullmatch(r"secret:[A-Za-z0-9][A-Za-z0-9_-]{0,63}", source)
                ):
                    raise ValueError(
                        "Mount source must be checkout, results or secret:NAME, never a host path."
                    )
                item.setdefault("read_only", source != "results")
                if (
                    type(item["read_only"]) is not bool
                    or source.startswith("secret:")
                    and not item["read_only"]
                ):
                    raise ValueError(
                        "Secrets must be mounted read-only; read_only must be boolean."
                    )
    return result


def policy(raw: object = None) -> dict[str, Any]:
    raw = {} if raw is None else raw
    if not isinstance(raw, dict) or set(raw) - set(POLICY_DEFAULTS):
        raise ValueError("Unknown worker Docker policy fields.")
    result: dict[str, Any] = {**copy.deepcopy(POLICY_DEFAULTS), **copy.deepcopy(raw)}
    for key, high in (
        ("max_memory_mb", 131072),
        ("max_pids_limit", 32768),
        ("max_tmpfs_mb", 131072),
        ("max_timeout_seconds", 86400),
        ("max_image_pull_timeout_seconds", 86400),
    ):
        number(result[key], 1, high, key)
    number(result["max_cpus"], 0.1, 64, "max_cpus", False)
    for key in ("allow_root", "allow_writable_root"):
        if type(result[key]) is not bool:
            raise ValueError("Worker permissions must be boolean.")
    networks = result["networks"]
    if result["image_pull"] not in ("never", "missing", "always"):
        raise ValueError("Worker image_pull must be never, missing or always.")
    if (
        not isinstance(networks, list)
        or not networks
        or len(networks) > 32
        or any(
            not isinstance(n, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", n)
            or n in ("host", "container")
            for n in networks
        )
    ):
        raise ValueError("Invalid worker network allowlist.")
    if not isinstance(result["secrets"], dict) or len(result["secrets"]) > 32:
        raise ValueError("Invalid worker secrets.")
    builds = result["builds"]
    if not isinstance(builds, dict) or set(builds) - set(POLICY_DEFAULTS["builds"]):
        raise ValueError("Invalid worker image build policy.")
    builds = result["builds"] = {**copy.deepcopy(POLICY_DEFAULTS["builds"]), **builds}
    for key in ("repositories", "events", "networks"):
        if not isinstance(builds[key], list) or len(builds[key]) > 128:
            raise ValueError("Invalid build policy allowlist.")
    if (
        any(
            not isinstance(repo, str) or not re.fullmatch(r"[^/\s]+/[^/\s]+", repo)
            for repo in builds["repositories"]
        )
        or any(event not in ("manual", "push", "pull_request_merged") for event in builds["events"])
        or not builds["networks"]
        or any(net not in ("none", "bridge") for net in builds["networks"])
    ):
        raise ValueError("Builds require explicit repository/trusted-event/network allowlists.")
    number(builds["max_timeout_seconds"], 1, 86400, "build max timeout")
    number(builds["max_memory_mb"], 1, 131072, "build max memory")
    number(builds["max_cpus"], 0.1, 64, "build max CPUs", False)
    for name, secret in result["secrets"].items():
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name)
            or not isinstance(secret, dict)
            or set(secret) != {"path", "repositories", "events"}
            or not isinstance(secret["path"], str)
            or not Path(secret["path"]).is_absolute()
            or not isinstance(secret["repositories"], list)
            or not secret["repositories"]
            or any(
                not isinstance(repo, str) or not re.fullmatch(r"[^/\s]+/[^/\s]+", repo)
                for repo in secret["repositories"]
            )
            or not isinstance(secret["events"], list)
            or not secret["events"]
            or any(
                event not in ("manual", "push", "pull_request_merged") for event in secret["events"]
            )
        ):
            raise ValueError(
                "Secrets require an absolute worker path and explicit repository/trusted-event restrictions."
            )
    return result


def authorize(
    request: object,
    worker_policy: object = None,
    *,
    timeout: float = 1800,
    repository: str = "",
    event: str = "",
    image_pull_timeout: float = 600,
) -> tuple[dict[str, Any], dict[str, str]]:
    request, limits = profile(request), policy(worker_policy)
    for key in ("cpus", "memory_mb", "pids_limit"):
        if request[key] > limits["max_" + key]:
            raise ValueError(f"Docker request exceeds worker policy: {key}.")
    if (
        request["tmpfs_mb"] + sum(item["size_mb"] for item in request["tmpfs"])
        > limits["max_tmpfs_mb"]
    ):
        raise ValueError("Docker tmpfs request exceeds worker policy.")
    if timeout > limits["max_timeout_seconds"]:
        raise ValueError("CI timeout exceeds worker policy.")
    if image_pull_timeout > limits["max_image_pull_timeout_seconds"]:
        raise ValueError("Image pull timeout exceeds worker policy.")
    if request["network"] not in limits["networks"]:
        raise ValueError("Docker network is not permitted by worker policy.")
    if not request["read_only"] and not limits["allow_writable_root"]:
        raise ValueError("Writable container root is not permitted by worker policy.")
    if request["user"] == "root" and not limits["allow_root"]:
        raise ValueError("Root container user is not permitted by worker policy.")
    resolved = {}
    for mount in request["mounts"]:
        if mount["source"].startswith("secret:"):
            name = mount["source"].split(":", 1)[1]
            secret = limits["secrets"].get(name)
            if (
                not secret
                or repository not in secret["repositories"]
                or event not in secret["events"]
            ):
                raise ValueError("Secret mount is not authorized for this repository/event.")
            path = Path(secret["path"])
            if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
                raise ValueError("Worker secret must be a regular non-symlink file.")
            if path.name in ("docker.sock", "token", "runner.lock", "attempt.json"):
                raise ValueError("Worker control files cannot be mounted as job secrets.")
            resolved[name] = str(path)
    return request, resolved
