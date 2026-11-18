"""Command-line interface for PyGitHost."""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import subprocess
import sys
from pathlib import Path

from .application import main_async
from .config import DEFAULT_CONFIG_FILENAME, AppConfig


def default_config_path() -> Path:
    return Path(__file__).resolve().parent.parent / DEFAULT_CONFIG_FILENAME


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pygithost",
        description="Async Git Smart HTTP + Web UI server.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Run the server using a JSON config file.")
    run.add_argument("--config", default=str(default_config_path()))

    generate = commands.add_parser(
        "generate-config", help="Generate a platform-dependent JSON config file."
    )
    generate.add_argument("--config", default=str(default_config_path()))
    generate.add_argument(
        "--platform",
        choices=["Windows", "Linux", "Darwin"],
        default=platform.system(),
    )
    generate.add_argument("--overwrite", action="store_true")
    generate.add_argument("--print", dest="print_only", action="store_true")

    ci = commands.add_parser("ci", help="Inspect repository-owned CI configuration.")
    ci_commands = ci.add_subparsers(dest="ci_command", required=True)
    validate = ci_commands.add_parser(
        "validate",
        help="Validate ci/config.json and every pipeline file it references without running it.",
    )
    validate.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Repository or checkout to inspect; defaults to the current directory.",
    )
    validate.add_argument(
        "--repository",
        "--repo",
        "--path",
        dest="repository",
        default=None,
        help="Repository or checkout to inspect; defaults to the current directory.",
    )
    validate.add_argument(
        "--rev",
        "--revision",
        dest="revision",
        default=None,
        help="Validate a committed revision (for example HEAD or refs/heads/main) "
        "instead of the working tree.",
    )
    return parser


def _git(root: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except OSError, subprocess.SubprocessError:
        return None
    if result.returncode:
        return None
    return result.stdout.decode("utf-8", "replace").strip()


def _git_directory(root: Path) -> str | None:
    directory = _git(root, "rev-parse", "--absolute-git-dir")
    return directory or None


def _is_working_tree(root: Path) -> bool:
    return _git(root, "rev-parse", "--is-inside-work-tree") == "true"


def _validate_ci(path: str | None, repository: str | None, revision: str | None) -> int:
    from .repository_ci import (
        CONFIG_FILE,
        inspect_configuration,
        inspect_working_configuration,
    )

    root = Path(repository or path or ".").expanduser()
    if not root.exists():
        print(f"ERROR: Repository path not found: {root}", file=sys.stderr)
        return 1

    label: str
    if revision is not None:
        git_directory = _git_directory(root)
        if git_directory is None:
            print(f"ERROR: Not a Git repository: {root}", file=sys.stderr)
            return 1
        inspection = inspect_configuration(git_directory, revision)
        label = f"at {revision}"
    elif _is_working_tree(root):
        top_level = _git(root, "rev-parse", "--show-toplevel")
        worktree = Path(top_level) if top_level else root
        inspection = inspect_working_configuration(worktree)
        label = "in the working tree"
    else:
        git_directory = _git_directory(root)
        if git_directory is None:
            print(f"ERROR: Not a Git repository: {root}", file=sys.stderr)
            return 1
        inspection = inspect_configuration(git_directory, "HEAD")
        revision = "HEAD"
        label = "at HEAD"

    if inspection.error:
        print(f"ERROR: {inspection.error}", file=sys.stderr)
        return 1
    if inspection.config is None:
        if revision is not None and inspection.commit is None:
            print(f"ERROR: Cannot resolve revision {revision!r}.", file=sys.stderr)
        else:
            print(f"ERROR: No {CONFIG_FILE} found {label}.", file=sys.stderr)
        return 1
    print(f"Repository CI configuration is valid {label}.")
    return 0


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if args.command == "ci":
        raise SystemExit(_validate_ci(args.path, args.repository, args.revision))
    if args.command == "generate-config":
        try:
            config = AppConfig.default_for_platform(args.platform)
            if args.print_only:
                print(json.dumps(config.to_dict(), indent=4))
            else:
                print(
                    f"Config file generated: {config.write(args.config, overwrite=args.overwrite)}"
                )
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        return

    config_path = Path(args.config).expanduser()
    if not config_path.is_file():
        print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
        print(
            f"Create one first with: {Path(sys.argv[0]).name} generate-config --config {config_path}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        asyncio.run(main_async(config_path))
    except KeyboardInterrupt:
        pass
