"""Shared fixtures for Git Smart HTTP backend conformance tests and benchmarks.

``BACKENDS`` lists every Git HTTP backend implementation the server can use.
Each value is the ``git_http_backend`` configuration that selects it, or None
when it is unavailable on this machine. A new implementation (for example an
in-process backend) is covered by adding one entry here: the conformance suite
and benchmark pick it up automatically.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from tests.test_server import _which_git_backend

MISSING_BACKEND = "/nonexistent/git-http-backend"

BACKENDS: dict[str, str | None] = {
    # Reference implementation: git's own CGI program.
    "native": _which_git_backend(),
    # Pure-Python CGI program, selected when the executable is missing.
    "python-cgi": MISSING_BACKEND,
}
REFERENCE_BACKEND = "native"

FIXED_DATE = "2026-01-02T03:04:05+00:00"

# Machine-wide git settings (Git for Windows sets http.receivepack=true in its
# system gitconfig, for example) must not leak into backend behaviour under test.
_ISOLATION = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
_saved_environment: dict[str, str | None] = {}


def isolate_git_config() -> None:
    """Make the server, backends and git clients ignore system/global git config."""
    for key, value in _ISOLATION.items():
        _saved_environment[key] = os.environ.get(key)
        os.environ[key] = value


def restore_git_config() -> None:
    for key, value in _saved_environment.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    _saved_environment.clear()


def git_env(**extra: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        GIT_TERMINAL_PROMPT="0",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_AUTHOR_NAME="Fixture",
        GIT_AUTHOR_EMAIL="fixture@example.com",
        GIT_COMMITTER_NAME="Fixture",
        GIT_COMMITTER_EMAIL="fixture@example.com",
        GIT_AUTHOR_DATE=FIXED_DATE,
        GIT_COMMITTER_DATE=FIXED_DATE,
    )
    env.update(extra)
    return env


def git(
    *args: str | os.PathLike[str],
    cwd: str | os.PathLike[str] | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 120,
) -> str:
    return subprocess.run(
        ["git", *map(str, args)],
        cwd=cwd,
        env=env or git_env(),
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    ).stdout


def make_source(path: Path, commits: int = 3, blob_bytes: int = 0) -> Path:
    """A non-bare repository with history, a branch and both kinds of tags."""
    git("init", "-b", "main", path)
    for index in range(commits):
        (path / f"file{index}.txt").write_text(f"content {index}\n" * (index + 1))
        git("-C", path, "add", ".")
        git("-C", path, "commit", "-m", f"Commit {index}")
    if blob_bytes:
        (path / "large.bin").write_bytes(os.urandom(blob_bytes))
        git("-C", path, "add", ".")
        git("-C", path, "commit", "-m", "Add large blob")
    git("-C", path, "branch", "feature", "HEAD~1" if commits > 1 else "HEAD")
    git("-C", path, "tag", "-a", "v1.0", "-m", "Release 1.0")
    git("-C", path, "tag", "light", "HEAD")
    return path


def bare_clone(source: Path, target: Path, **config: str) -> Path:
    git("clone", "--bare", "--quiet", source, target)
    # Single-threaded pack-objects keeps pack bytes deterministic for wire comparisons.
    git("--git-dir", target, "config", "pack.threads", "1")
    for key, value in config.items():
        git("--git-dir", target, "config", key.replace("_", "."), value)
    return target


def build_project_root(root: Path) -> dict[str, str]:
    """Create every repository layout the conformance matrix needs.

    Returns facts about the fixture (object ids and file names) for scenarios.
    """
    source = make_source(root.parent / f"{root.name}-source")
    repo = bare_clone(source, root / "repo.git", http_receivepack="true")
    git("--git-dir", repo, "config", "uploadpack.allowFilter", "true")
    git("--git-dir", repo, "repack", "-a", "-d", "-q")
    loose = (
        subprocess.run(
            ["git", "--git-dir", str(repo), "hash-object", "-w", "--stdin"],
            input=b"loose object for dumb http\n",
            capture_output=True,
            check=True,
            env=git_env(),
        )
        .stdout.decode()
        .strip()
    )
    pack = next((repo / "objects" / "pack").glob("pack-*.pack")).name
    git("init", "--bare", "-q", "-b", "main", root / "empty.git")
    (root / "team").mkdir()
    bare_clone(source, root / "team" / "proj.git")
    git("clone", "-q", source, root / "plain")
    bare_clone(source, root / "noany.git", http_getanyfile="false")
    bare_clone(source, root / "noupload.git", http_uploadpack="false")
    bare_clone(source, root / "norecv.git")
    shutil.rmtree(source)
    return {
        "main": git("--git-dir", repo, "rev-parse", "main").strip(),
        "feature": git("--git-dir", repo, "rev-parse", "feature").strip(),
        "loose": loose,
        "pack": pack,
    }
