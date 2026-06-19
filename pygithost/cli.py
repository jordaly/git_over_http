"""Command-line interface for PyGitHost."""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import sys
from pathlib import Path

from .application import main_async
from .config import AppConfig, DEFAULT_CONFIG_FILENAME


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
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if args.command == "generate-config":
        try:
            config = AppConfig.default_for_platform(args.platform)
            if args.print_only:
                print(json.dumps(config.to_dict(), indent=4))
            else:
                print(f"Config file generated: {config.write(args.config, overwrite=args.overwrite)}")
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
