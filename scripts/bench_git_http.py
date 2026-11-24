"""Benchmark the Git Smart HTTP backends served by pygithost.

Runs the same workload against every backend in ``tests.git_http_backends.BACKENDS``
(native git-http-backend, the Python CGI fallback, and any future implementation)
and prints a comparison table. Each backend gets a fresh copy of the fixtures.

Usage (from the project root):

    .venv/bin/python scripts/bench_git_http.py [--quick] [--json results.json]
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.git_http_backends import (  # noqa: E402
    BACKENDS,
    REFERENCE_BACKEND,
    bare_clone,
    git,
    git_env,
    make_source,
)
from tests.test_server import ServerRunner  # noqa: E402

PROJECT = Path(__file__).resolve().parent.parent
ENV = git_env()


def timed(action: Callable[[], object], runs: int) -> list[float]:
    samples = []
    for _ in range(runs):
        start = time.perf_counter()
        action()
        samples.append((time.perf_counter() - start) * 1000)
    return samples


def summary(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    return {
        "runs": len(samples),
        "mean_ms": statistics.fmean(samples),
        "p50_ms": statistics.median(samples),
        "p95_ms": ordered[min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))],
        "min_ms": ordered[0],
    }


def build_templates(base: Path, quick: bool) -> Path:
    """Repositories shared (by copy) between backends."""
    root = base / "template"
    root.mkdir()
    small = make_source(base / "small-src", commits=20)
    bare_clone(small, root / "small.git", http_receivepack="true")
    # Medium: this project's own history, a realistic code repository.
    git("clone", "--bare", "--quiet", "--no-local", PROJECT, root / "medium.git")
    git("--git-dir", root / "medium.git", "config", "http.receivepack", "true")
    large = make_source(base / "large-src", commits=2, blob_bytes=(16 if quick else 64) << 20)
    bare_clone(large, root / "large.git", http_receivepack="true")
    for repo in root.glob("*.git"):
        git("--git-dir", repo, "repack", "-a", "-d", "-q")
    return root


def advertise(port: int, repo: str) -> None:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    try:
        conn.request("GET", f"/git/{repo}/info/refs?service=git-upload-pack")
        response = conn.getresponse()
        response.read()
        assert response.status == 200, response.status
    finally:
        conn.close()


def run_backend(
    name: str, backend: str, template: Path, work: Path, quick: bool
) -> dict[str, dict[str, float]]:
    root = work / f"root-{name}"
    shutil.copytree(template, root)
    clients = work / f"clients-{name}"
    clients.mkdir()
    counter = iter(range(10**9))
    results: dict[str, dict[str, float]] = {}
    scale = 1 if quick else 2

    with ServerRunner(
        project_root=str(root), backend_path=backend, access_log=False, log_level="WARNING"
    ) as srv:
        url = f"http://127.0.0.1:{srv.port}/git"
        advertise(srv.port, "small.git")  # warm-up

        def clone(repo: str, *args: str) -> Path:
            target = clients / f"c{next(counter)}"
            git("clone", "-q", *args, f"{url}/{repo}", target, env=ENV)
            return target

        results["info/refs (1 request)"] = summary(
            timed(lambda: advertise(srv.port, "small.git"), 100 * scale)
        )
        results["ls-remote (medium)"] = summary(
            timed(lambda: git("ls-remote", f"{url}/medium.git", env=ENV), 10 * scale)
        )
        results["clone small (20 commits)"] = summary(timed(lambda: clone("small.git"), 5 * scale))
        results["clone medium (this repo)"] = summary(timed(lambda: clone("medium.git"), 3 * scale))
        results[f"clone large ({16 if quick else 64} MB blob)"] = summary(
            timed(lambda: clone("large.git"), 2 if quick else 3)
        )
        fetcher = clone("medium.git")
        results["fetch, up to date (medium)"] = summary(
            timed(lambda: git("-C", fetcher, "fetch", "-q", env=ENV), 10 * scale)
        )

        pusher = clone("small.git")

        def push_small() -> None:
            index = next(counter)
            (pusher / f"p{index}.txt").write_text(f"{index}\n")
            git("-C", pusher, "add", ".", env=ENV)
            git("-C", pusher, "commit", "-q", "-m", f"bench {index}", env=ENV)
            git("-C", pusher, "push", "-q", "origin", "HEAD:main", env=ENV)

        results["push small commit"] = summary(timed(push_small, 5 * scale))

        big_mb = 8 if quick else 32

        def push_big() -> None:
            index = next(counter)
            (pusher / f"big{index}.bin").write_bytes(os.urandom(big_mb << 20))
            git("-C", pusher, "add", ".", env=ENV)
            git("-C", pusher, "commit", "-q", "-m", f"big {index}", env=ENV)
            git("-C", pusher, "push", "-q", "origin", "HEAD:main", env=ENV)

        results[f"push {big_mb} MB blob"] = summary(timed(push_big, 2 if quick else 3))

        def parallel_clones() -> None:
            errors: list[BaseException] = []

            def worker() -> None:
                try:
                    clone("medium.git")
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

            threads = [threading.Thread(target=worker) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            if errors:
                raise errors[0]

        results["8 parallel clones (medium), wall"] = summary(
            timed(parallel_clones, 2 if quick else 3)
        )
    shutil.rmtree(clients, ignore_errors=True)
    shutil.rmtree(root, ignore_errors=True)
    return results


def print_table(all_results: dict[str, dict[str, dict[str, float]]]) -> None:
    names = list(all_results)
    reference = REFERENCE_BACKEND if REFERENCE_BACKEND in all_results else names[0]
    header = "| Operation | " + " | ".join(f"{n} p50 (mean) ms" for n in names)
    header += "".join(f" | {n} vs {reference}" for n in names if n != reference) + " |"
    print(header)
    print("|" + "---|" * (1 + len(names) + len(names) - 1))
    for op in all_results[reference]:
        cells = [
            f"{all_results[n][op]['p50_ms']:.1f} ({all_results[n][op]['mean_ms']:.1f})"
            for n in names
        ]
        ratios = []
        for n in names:
            if n == reference:
                continue
            base = all_results[reference][op]["p50_ms"]
            delta = all_results[n][op]["p50_ms"] - base
            ratios.append(f"{delta:+.1f} ms ({delta / base * 100:+.0f}%)")
        print(f"| {op} | " + " | ".join(cells + ratios) + " |")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--quick", action="store_true", help="smaller data and fewer runs")
    parser.add_argument("--json", type=Path, help="write raw results to this file")
    args = parser.parse_args()

    backends = {name: path for name, path in BACKENDS.items() if path}
    with tempfile.TemporaryDirectory(prefix="git-http-bench-") as tmp:
        work = Path(tmp)
        print("Preparing fixtures...", file=sys.stderr)
        template = build_templates(work, args.quick)
        all_results = {}
        for name, backend in backends.items():
            print(f"Benchmarking {name} ({backend})...", file=sys.stderr)
            all_results[name] = run_backend(name, backend, template, work, args.quick)
    git_version = subprocess.run(
        ["git", "--version"], capture_output=True, text=True
    ).stdout.strip()
    print(
        f"\n{platform.platform()} · Python {platform.python_version()} · {git_version} · "
        f"{os.cpu_count()} CPUs\n"
    )
    print_table(all_results)
    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "platform": platform.platform(),
                    "python": platform.python_version(),
                    "git": git_version,
                    "results": all_results,
                },
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
