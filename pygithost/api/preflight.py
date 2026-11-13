"""Read-only prerequisite checks; never execute deployment commands."""

import asyncio
import os
from pathlib import Path
import shlex
import shutil

from ..ci import deployment_prefix
from . import settings


def inspect(config, repository):
    checks = []

    def check(name, ok):
        checks.append({"name": name, "ok": bool(ok)})

    prefix = deployment_prefix(config.get("deploy_interpreter", "direct"))
    if prefix:
        check("interpreter_available", shutil.which(prefix[0]) is not None)
    if config.get("deploy_steps"):
        check("command_shell_available", shutil.which(os.environ.get("COMSPEC", "cmd.exe")) is not None if os.name == "nt"
              else os.path.isfile("/bin/sh") and os.access("/bin/sh", os.X_OK))
    content = config.get("deploy_script_content", "")
    path = config.get("deploy_script")
    if path and not content:
        try:
            script = Path(path).resolve()
            check("script_outside_repository", not script.is_relative_to(Path(repository).resolve()))
            check("script_readable", script.is_file() and os.access(script, os.R_OK))
            if not prefix:
                check("script_executable", script.is_file() and os.access(script, os.X_OK))
            if script.is_file() and not prefix and os.name != "nt":
                with script.open("rb") as stream:
                    content = stream.read(4096).decode("utf-8", "replace")
        except (OSError, ValueError):
            check("script_accessible", False)
    if content and not prefix and os.name != "nt":
        first = content.split("\n", 1)[0]
        try:
            command = shlex.split(first[2:]) if first.startswith("#!") else []
            check("shebang_interpreter_available", bool(command) and shutil.which(command[0]) is not None)
            if command and Path(command[0]).name == "env":
                # Only plain '#!/usr/bin/env executable' is unambiguous here.
                check("shebang_program_available", len(command) == 2 and
                      not command[1].startswith("-") and shutil.which(command[1]) is not None)
        except ValueError:
            check("shebang_interpreter_available", False)
    check("execution_defined", bool(path or content or config.get("deploy_steps")))
    return {"ok": all(item["ok"] for item in checks), "checks": checks}


async def read(api, owner, repo, path):
    settings.authorize(api)
    api.parameters()
    async with api.handler.server.settings_lock:
        state = await settings.snapshot(api, owner, repo)
        config = await api.handler.server.ci_manager.config(owner, repo)
        targets = []
        for pipeline in api.handler.server.ci_manager.pipelines(config):
            entries = pipeline.get("deployment_targets") or [pipeline]
            for entry in entries:
                target = {**pipeline, **entry}
                if not target.get("deploy_enabled"):
                    continue
                result = await asyncio.to_thread(inspect, target, path)
                targets.append({"name": target.get("deployment_name") or pipeline["pipeline_id"],
                                "pipeline": pipeline["pipeline_id"], **result})
        return {"revision": state["revision"], "ok": bool(targets) and all(t["ok"] for t in targets),
                "targets": targets, "advisory": True}
