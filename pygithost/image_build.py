"""Opt-in, trusted-repository Docker image builds on HTTP workers."""

import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .docker_profile import number


def relative_path(value):
    if (not isinstance(value, str) or not value or len(value) > 512
            or not re.fullmatch(r"[A-Za-z0-9_. /-]+", value)
            or value.startswith(("/", "-")) or "\\" in value
            or any(part == ".." for part in value.split("/"))):
        raise ValueError("Build paths must be relative checkout paths without traversal.")
    return value


def recipe(raw):
    if not isinstance(raw, dict) or set(raw) - {"dockerfile", "context", "target", "args"}:
        raise ValueError("Unknown image build recipe fields.")
    result = {
        "dockerfile": relative_path(raw.get("dockerfile", "Dockerfile")),
        "context": relative_path(raw.get("context", ".")),
        "target": raw.get("target", ""), "args": raw.get("args", {}),
    }
    if (not isinstance(result["target"], str)
            or result["target"] and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", result["target"])):
        raise ValueError("Invalid Docker build target.")
    args = result["args"]
    if (not isinstance(args, dict) or len(args) > 32
            or any(not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key)
                   or not isinstance(value, str) or len(value) > 4096
                   or any(c in value for c in "\r\n\0") for key, value in args.items())):
        raise ValueError("Build args must be a mapping of safe names to single-line strings.")
    return result


def configuration(raw):
    if raw is None:
        return None
    if (not isinstance(raw, dict)
            or set(raw) - {"policy", "pull", "dockerfile", "context", "target", "args",
                           "prerequisites", "timeout_seconds", "memory_mb", "cpus", "network"}):
        raise ValueError("Unknown image_build fields.")
    if raw.get("policy", "if-missing") != "if-missing":
        raise ValueError("image_build.policy must be if-missing.")
    if type(raw.get("pull", True)) is not bool:
        raise ValueError("image_build.pull must be boolean.")
    result = recipe({key: raw[key] for key in ("dockerfile", "context", "target", "args") if key in raw})
    result.update(policy="if-missing", pull=raw.get("pull", True),
                  timeout_seconds=number(raw.get("timeout_seconds", 1800), 1, 86400, "build timeout"),
                  memory_mb=number(raw.get("memory_mb", 1024), 1, 131072, "build memory"),
                  cpus=number(raw.get("cpus", 1), .1, 64, "build CPUs", False),
                  network=raw.get("network", "none"), prerequisites=[])
    if result["network"] not in ("none", "bridge"):
        raise ValueError("Build network must be none or bridge; host networking is forbidden.")
    prerequisites = raw.get("prerequisites", [])
    if not isinstance(prerequisites, list) or len(prerequisites) > 4:
        raise ValueError("Build prerequisites must be an array of at most four images.")
    names = set()
    for item in prerequisites:
        if not isinstance(item, dict):
            raise ValueError("Invalid build prerequisite.")
        name, image = item.get("name"), item.get("image")
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", name)
                or name == "final" or name in names or not isinstance(image, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:-]{0,255}", image)):
            raise ValueError("Prerequisites require unique names and valid image references.")
        entry = recipe({key: value for key, value in item.items() if key not in ("name", "image")})
        _references(entry, names)
        names.add(name)
        result["prerequisites"].append(dict(entry, name=name, image=image))
    _references(result, names)
    return result


def _references(item, names):
    for value in item["args"].values():
        if value.startswith("${image:"):
            if not value.endswith("}") or value[8:-1] not in names:
                raise ValueError("Build image references must name an earlier prerequisite.")


def authorize(build, worker_policy, repository, event):
    if not build:
        return
    allowed = worker_policy["builds"]
    if repository not in allowed["repositories"] or event not in allowed["events"]:
        raise ValueError("Image builds are not authorized for this repository/event.")
    for key in ("timeout_seconds", "memory_mb", "cpus"):
        if build[key] > allowed["max_" + key]:
            raise ValueError("Image build exceeds worker policy: " + key)
    if build["network"] not in allowed["networks"]:
        raise ValueError("Image build network is not authorized.")
    if not build["pull"] and worker_policy["image_pull"] == "always":
        raise ValueError("Local-only builds conflict with image_pull=always.")


def checked_path(checkout, value, *, directory=False):
    root = Path(checkout).resolve()
    path = root / relative_path(value)
    # Do not follow even in-checkout symlinks as Dockerfiles or context roots.
    current = root
    for part in Path(value).parts:
        current /= part
        if current.is_symlink():
            raise ValueError("Build Dockerfile/context cannot contain symlink components.")
    if not path.resolve().is_relative_to(root):
        raise ValueError("Build path escapes the checkout.")
    if directory and not path.is_dir() or not directory and not path.is_file():
        raise ValueError("Build Dockerfile/context is missing from the exact-commit checkout.")
    return str(path)


def cache_directory(path=None):
    root = Path(path) if path else Path.home() / ".cache" / "pygithost-images"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or root.stat().st_uid != os.getuid() or stat.S_IMODE(root.stat().st_mode) & 0o077:
        raise ValueError("Image cache directory must be private and owned by the worker.")
    return root


async def lock_file(path, *, exclusive=True):
    """Cancellation-aware host-wide cache coordination (same worker account)."""
    import fcntl
    handle = path.open("a")
    try:
        while True:
            try:
                fcntl.flock(handle, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
                return handle
            except BlockingIOError:
                await asyncio.sleep(.1)
    except BaseException:
        handle.close()
        raise


def unavailable(output):
    """Fail closed: access denied, DNS, TLS and timeouts are NOT missing images."""
    text = output.decode("utf-8", "replace").lower()
    if any(word in text for word in ("unauthorized", "authentication", "denied", "timeout",
                                     "timed out", "connection", "certificate", "no such host")):
        return False
    return "manifest unknown" in text or "manifest_unknown" in text


async def prepare(manager, row, config, checkout, output, truncated, publish):
    """Hold the prune guard until the caller finishes using the prepared image."""
    root = cache_directory(getattr(manager, "image_cache_dir", None))
    deadline = asyncio.get_running_loop().time() + config["image_build"]["timeout_seconds"]
    guard = await asyncio.wait_for(lock_file(root / "prune.lock", exclusive=False),
                                   timeout=config["image_build"]["timeout_seconds"])
    try:
        await _prepare(manager, row, config, checkout, output, truncated, publish, deadline)
        return guard
    except BaseException:
        guard.close()
        raise


async def _prepare(manager, row, config, checkout, output, truncated, publish, deadline):
    """Resolve prerequisites and final image under a bounded preparation budget."""
    build = config["image_build"]
    repository = f"{row[1]}/{row[2]}"
    authorize(build, manager.docker_policy, repository, row[3])
    maximum = config["limits"]["log_mb"] * 1024 * 1024
    root = cache_directory(getattr(manager, "image_cache_dir", None))
    references = {}

    async def capture(command, *, buffer=None, build_command=False, pull=False):
        remaining = deadline - asyncio.get_running_loop().time()
        return await manager._capture_process(
            command, shell=False, cwd=checkout if build_command else None,
            env={**os.environ, **({"DOCKER_BUILDKIT": "0"} if build_command else {})},
            output=output if buffer is None else buffer,
            truncated=truncated if buffer is None else [False],
            on_output=publish if buffer is None else None,
            timeout=min(remaining, config["limits"]["image_pull_timeout_seconds"]) if pull else remaining,
            max_output=maximum)

    async def message(text):
        data = (text + "\n").encode()
        room = max(0, maximum - len(output))
        output.extend(data[:room])
        truncated[0] |= len(data) > room
        await publish()

    def identity(item):
        key = hashlib.sha256(json.dumps(
            [repository, row[5], json.loads(row[6] or "{}").get("head_commit", ""), item],
            sort_keys=True).encode()).hexdigest()
        tag = "pygithost-build/" + hashlib.sha256(repository.encode()).hexdigest()[:16] + ":" + key
        return key, tag

    async def cached(item, tag):
        if manager.docker_policy["image_pull"] == "always":
            return None
        for candidate in (item["image"], tag):
            inspected = bytearray()
            if await capture(["docker", "image", "inspect", "--format={{.Id}}", candidate],
                             buffer=inspected) == 0:
                return candidate
            if b"No such image" not in inspected and b"not found" not in inspected.lower():
                raise ValueError("Docker image inspection failed; refusing an unverified build fallback.")
        return None

    final = dict(build, image=config["image"], name="final")
    selected = await cached(final, identity(final)[1])
    if selected:
        config["image"] = selected
        await message("Using cached final image.")
        return
    async def pull_image(image):
        pulled = bytearray()
        rc = await capture(["docker", "pull", "--quiet", image], buffer=pulled, pull=True)
        room = max(0, maximum - len(output))
        output.extend(pulled[:room])
        truncated[0] |= len(pulled) > room
        await publish()
        if rc and not unavailable(pulled):
            raise ValueError("Image pull failed (not a confirmed missing manifest); build fallback refused.")
        return rc == 0

    pull_enabled = build["pull"] and manager.docker_policy["image_pull"] != "never"
    if pull_enabled and await pull_image(final["image"]):
        await message("Using downloaded final image.")
        return
    for item in [*build["prerequisites"], final]:
        key, tag = identity(item)
        handle = await asyncio.wait_for(lock_file(root / (key + ".lock")),
                                        timeout=max(.001, deadline - asyncio.get_running_loop().time()))
        try:
            # Builds never overwrite the requested tag or another repository's images.
            selected = await cached(item, tag)
            if selected:
                await message("Using cached image: " + item["name"])
            else:
                pull = pull_enabled and item["name"] != "final"
                if pull:
                    if await pull_image(item["image"]):
                        selected = item["image"]
                if not selected:
                    dockerfile = checked_path(checkout, item["dockerfile"])
                    context = checked_path(checkout, item["context"], directory=True)
                    command = [
                        "docker", "build", "--force-rm", "--rm", "--pull=false",
                        "--memory", str(build["memory_mb"]) + "m",
                        "--memory-swap", str(build["memory_mb"]) + "m",
                        "--cpu-period", "100000", "--cpu-quota", str(int(build["cpus"] * 100000)),
                        "--network", build["network"],
                        "--label", "pygithost.build-cache=1",
                        "--label", "pygithost.http-attempt=" + manager.http_attempt,
                        "--tag", tag, "--file", dockerfile,
                    ]
                    if item["target"]:
                        command += ["--target", item["target"]]
                    for name, value in item["args"].items():
                        if value.startswith("${image:"):
                            value = references[value[8:-1]]
                        command += ["--build-arg", name + "=" + value]
                    command.append(context)
                    await message("Building image: " + item["name"])
                    if await capture(command, build_command=True):
                        raise ValueError("Docker image build failed: " + item["name"])
                    selected = tag
            references[item["name"]] = selected
        finally:
            handle.close()
    config["image"] = references["final"]
