"""Temporary receive hooks for server-controlled branch protection.

Existing repository hooks are preserved, never overwritten on disk.
"""

import fnmatch
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile


def prepare_hooks(original, patterns):
    directory = tempfile.TemporaryDirectory(prefix="pygithost-protection-")
    try:
        root = Path(directory.name)
        hooks = root / "hooks"
        if Path(original).is_dir():
            shutil.copytree(original, hooks, symlinks=False)
        else:
            hooks.mkdir()
        policy = root / "policy.json"
        policy.write_text(json.dumps({"original": str(original), "patterns": patterns}), encoding="utf-8")
        hook = hooks / "pre-receive"
        # The Git-for-Windows hook launcher also understands this shell shim.
        arguments = [sys.executable, str(Path(__file__).resolve()), str(policy)]
        hook.write_text("#!/bin/sh\nexec " + " ".join(shlex.quote(arg.replace("\\", "/")) for arg in arguments) + "\n", encoding="utf-8")
        hook.chmod(0o700)
        return directory, str(hooks)
    except BaseException:
        directory.cleanup()
        raise


def check_updates(data, patterns):
    for line in data.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) != 3:
            raise ValueError("Malformed receive command.")
        ref = parts[2]
        if ref.startswith("refs/heads/") and any(fnmatch.fnmatchcase(ref[11:], pattern) for pattern in patterns):
            raise ValueError(f"Direct updates to protected branch {ref[11:]} are blocked; use a pull request.")


def main():
    policy = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    data = sys.stdin.buffer.read()
    try:
        check_updates(data, policy["patterns"])
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    original = Path(policy["original"]) / "pre-receive"
    if original.is_file() and os.access(original, os.X_OK):
        # Let Git execute the existing hook with its original interpreter.
        with tempfile.NamedTemporaryFile(delete=False) as stream:
            stream.write(data)
            input_path = stream.name
        try:
            return subprocess.call(["git", "-c", "core.hooksPath=" + policy["original"],
                                    "hook", "run", "--to-stdin=" + input_path, "pre-receive"])
        finally:
            os.unlink(input_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
