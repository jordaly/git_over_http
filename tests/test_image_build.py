import asyncio
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pygithost import database, image_build
from pygithost.ci import CIManager, validate_config
from pygithost.docker_profile import policy
from pygithost.runner import execute_with_image


class BuildConfigurationTests(unittest.TestCase):
    def test_grouped_configuration_round_trip_and_snapshot(self):
        from pygithost.ci_config import compile_document, editor_document

        document = {
            "version": 1,
            "pipelines": [
                {
                    "name": "tests",
                    "execution": {
                        "runner": "remote-docker",
                        "image": "local/test:v1",
                        "image_build": {
                            "pull": False,
                            "dockerfile": "ci/Dockerfile",
                            "context": ".",
                        },
                    },
                    "steps": [{"name": "test", "run": "true"}],
                }
            ],
        }
        compiled = compile_document(document)
        self.assertFalse(compiled["image_build"]["pull"])
        self.assertEqual(editor_document(compiled), document)
        self.assertEqual(validate_config(compiled)["image_build"], compiled["image_build"])

    def test_invalid_configuration(self):
        for raw in (
            False,
            [],
            {"policy": "always"},
            {"context": "/etc"},
            {"context": "../outside"},
            {"dockerfile": "-f"},
            {"context": "http://host/context"},
            {"privileged": True},
            {"network": "host"},
            {"cpus": True},
            {"timeout_seconds": 0},
            {"pull": "false"},
            {"args": {1: "x"}},
            {"args": {"SECRET": "a\nb"}},
            {"prerequisites": [{"name": "final", "image": "test"}]},
            {"args": {"BASE_IMAGE": "${image:unknown}"}},
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                image_build.configuration(raw)
        with self.assertRaises(ValueError):
            validate_config({"image_build": {}})

    def test_builds_denied_by_default_and_only_trusted_events_allowed(self):
        build = image_build.configuration({})
        with self.assertRaises(ValueError):
            image_build.authorize(build, policy(), "alice/project", "manual")
        granted = policy({"builds": {"repositories": ["alice/project"], "events": ["manual"]}})
        image_build.authorize(build, granted, "alice/project", "manual")
        for repo, event in (
            ("bob/project", "manual"),
            ("alice/project", "pull_request"),
            ("alice/project", "push"),
        ):
            with self.subTest(repo=repo, event=event), self.assertRaises(ValueError):
                image_build.authorize(build, granted, repo, event)
        for raw in (
            {"events": ["pull_request_opened"]},
            {"networks": ["host"]},
            {"max_memory_mb": True},
            {"allow_privileged": True},
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                policy({"builds": raw})
        for raw in (
            {"cpus": 2},
            {"memory_mb": 2048},
            {"timeout_seconds": 1801},
            {"network": "bridge"},
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                image_build.authorize(
                    image_build.configuration(raw), granted, "alice/project", "manual"
                )

    def test_pull_classification_does_not_hide_authentication_or_network_errors(self):
        self.assertTrue(image_build.unavailable(b"manifest unknown"))
        self.assertTrue(
            image_build.unavailable(
                b'Error response from daemon: failed to resolve reference "docker.io/library/python:missing": docker.io/library/python:missing: not found'
            )
        )
        for text in (
            b"pull access denied, repository does not exist",
            b"unauthorized",
            b"TLS certificate error",
            b"connection refused",
            b"no such host",
            b"manifest unknown: authentication required",
            b'failed to resolve reference "registry/private:tag": registry/private:tag: 403 Forbidden',
            b'failed to resolve reference "registry/private:tag": another/image:tag: not found',
            b"repository not found",
            b"manifest unknown: toomanyrequests",
        ):
            self.assertFalse(image_build.unavailable(text), text)

    def test_documentation_example_and_in_page_guide(self):
        from pygithost.ci_config import compile_document
        from pygithost.ci_docs import manual_content

        text = (Path(__file__).resolve().parents[1] / "docs/image-builds.md").read_text()
        document = json.loads(text.split("```json\n", 1)[1].split("```", 1)[0])
        self.assertIsNotNone(compile_document(document)["image_build"])
        rendered = str(manual_content("image-builds", None, "/r/root/project/ci/docs"))
        for marker in ("if-missing", "sqlpackage", "DOCKER_BUILDKIT=0", "prune-images"):
            self.assertIn(marker, rendered)


@unittest.skipUnless(os.name == "posix", "Linux worker build orchestration")
class BuildPreparationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "Dockerfile").write_text("FROM scratch\n")
        self.manager = mock.Mock()
        self.manager.http_attempt = "a" * 64
        self.manager.image_cache_dir = self.root / "cache"
        self.manager.docker_policy = policy(
            {"builds": {"repositories": ["alice/project"], "events": ["manual"]}}
        )
        self.config = validate_config(
            {"runner": "docker", "image": "local/test:v1", "image_build": {"pull": False}}
        )
        self.row = (1, "alice", "project", "manual", "main", "b" * 40, "{}")
        self.output, self.truncated = bytearray(), [False]
        self.publish = mock.AsyncMock()
        self.images = set()
        self.commands = []

        async def capture(command, **kwargs):
            self.commands.append(command)
            if command[1:3] == ["image", "inspect"]:
                if command[-1] in self.images:
                    kwargs["output"].extend(b"sha256:123\n")
                    return 0
                kwargs["output"].extend(b"Error response from daemon: No such image\n")
                return 1
            if command[1] == "build":
                self.images.add(command[command.index("--tag") + 1])
                kwargs["output"].extend(b"BUILD_LOG\n")
                await kwargs["on_output"]()
                self.assertEqual(kwargs["env"]["DOCKER_BUILDKIT"], "0")
                self.assertIn("--memory-swap", command)
                self.assertIn("--cpu-quota", command)
                self.assertEqual(command[command.index("--network") + 1], "none")
                self.assertGreater(kwargs["timeout"], 0)
                return 0
            if command[1] == "pull":
                kwargs["output"].extend(b"manifest unknown\n")
                return 1
            raise AssertionError(command)

        self.capture = capture
        self.manager._capture_process = mock.AsyncMock(side_effect=capture)

    async def asyncTearDown(self):
        self.temp.cleanup()

    async def prepare(self, config=None):
        config = config or self.config
        guard = await image_build.prepare(
            self.manager, self.row, config, self.root, self.output, self.truncated, self.publish
        )
        guard.close()
        return config

    async def test_missing_local_image_builds_namespaced_cache_and_reuses_it(self):
        config = await self.prepare()
        self.assertTrue(config["image"].startswith("pygithost-build/"))
        self.assertNotIn("local/test:v1", self.images)
        self.assertIn(b"BUILD_LOG", self.output)
        self.publish.assert_awaited()
        second = validate_config(
            {"runner": "docker", "image": "local/test:v1", "image_build": {"pull": False}}
        )
        await self.prepare(second)
        self.assertEqual(second["image"], config["image"])
        self.assertEqual(sum(cmd[1] == "build" for cmd in self.commands), 1)
        self.assertFalse(any(cmd[1] == "pull" for cmd in self.commands))

    async def test_cached_final_skips_prerequisites(self):
        self.images.add("local/test:v1")
        self.config["image_build"]["prerequisites"] = [
            {
                "name": "base",
                "image": "missing/base:v1",
                "dockerfile": "Missing",
                "context": ".",
                "args": {},
                "target": "",
            }
        ]
        await self.prepare()
        self.assertEqual(len(self.commands), 1)

    async def test_pull_before_build_only_for_confirmed_missing_manifest(self):
        self.config["image_build"]["pull"] = True
        await self.prepare()
        actions = [cmd[1] for cmd in self.commands]
        self.assertLess(actions.index("pull"), actions.index("build"))
        self.assertEqual(actions.count("pull"), 1)

    async def test_denied_pull_never_builds(self):
        self.config["image_build"]["pull"] = True

        async def denied(command, **kwargs):
            if command[1] == "pull":
                kwargs["output"].extend(b"pull access denied, repository does not exist")
                return 1
            return await self.capture(command, **kwargs)

        self.manager._capture_process.side_effect = denied
        with self.assertRaisesRegex(ValueError, "fallback refused"):
            await self.prepare()
        self.assertFalse(any(cmd[1] == "build" for cmd in self.commands))
        self.assertIn(b"access denied", self.output)

    async def test_docker29_exact_missing_reference_allows_build_fallback(self):
        self.config["image_build"]["pull"] = True

        async def modern(command, **kwargs):
            if command[1] == "pull":
                self.commands.append(command)
                kwargs["output"].extend(
                    b'Error response from daemon: failed to resolve reference "docker.io/local/test:v1": docker.io/local/test:v1: not found\n'
                )
                return 1
            return await self.capture(command, **kwargs)

        self.manager._capture_process.side_effect = modern
        await self.prepare()
        self.assertEqual(sum(cmd[1] == "build" for cmd in self.commands), 1)
        self.assertIn(b"not found", self.output)

    async def test_prerequisite_resolves_to_private_base_image_arg(self):
        self.config["image_build"] = image_build.configuration(
            {
                "pull": False,
                "args": {"BASE_IMAGE": "${image:wine}"},
                "prerequisites": [
                    {"name": "wine", "image": "wine/base:v1", "dockerfile": "Dockerfile"}
                ],
            }
        )
        await self.prepare()
        builds = [cmd for cmd in self.commands if cmd[1] == "build"]
        self.assertEqual(len(builds), 2)
        base_tag = builds[0][builds[0].index("--tag") + 1]
        self.assertIn("BASE_IMAGE=" + base_tag, builds[1])

    async def test_duplicate_builds_are_serialized(self):
        other = validate_config(
            {"runner": "docker", "image": "local/test:v1", "image_build": {"pull": False}}
        )

        async def slow(command, **kwargs):
            if command[1] == "build":
                await asyncio.sleep(0.05)
            return await self.capture(command, **kwargs)

        self.manager._capture_process.side_effect = slow
        await asyncio.gather(self.prepare(), self.prepare(other))
        self.assertEqual(sum(cmd[1] == "build" for cmd in self.commands), 1)

    async def test_symlink_and_missing_context_fail_without_building(self):
        (self.root / "link").symlink_to("/etc")
        self.config["image_build"]["context"] = "link"
        with self.assertRaisesRegex(ValueError, "symlink"):
            await self.prepare()
        self.config["image_build"]["context"] = "absent"
        with self.assertRaisesRegex(ValueError, "missing"):
            await self.prepare()
        self.assertFalse(any(cmd[1] == "build" for cmd in self.commands))

    async def test_build_failure_timeout_and_cancel_are_not_retried(self):
        for failure in (1, asyncio.TimeoutError(), asyncio.CancelledError()):
            self.commands.clear()

            async def fail(command, **kwargs):
                if command[1] == "build":
                    self.commands.append(command)
                    if isinstance(failure, BaseException):
                        raise failure
                    return failure
                return await self.capture(command, **kwargs)

            self.manager._capture_process.side_effect = fail
            with self.subTest(failure=type(failure).__name__):
                expected = type(failure) if isinstance(failure, BaseException) else ValueError
                with self.assertRaises(expected):
                    await self.prepare()
                self.assertEqual(sum(cmd[1] == "build" for cmd in self.commands), 1)

    async def test_prune_refuses_active_jobs_and_scopes_deletion(self):
        from pygithost.runner import main

        root = image_build.cache_directory(self.manager.image_cache_dir)
        guard = await image_build.lock_file(root / "prune.lock", exclusive=False)
        argv = ["runner", "prune-images", "--cache-dir", str(root), "--older-than-hours", "24"]
        try:
            with mock.patch("sys.argv", argv), mock.patch("subprocess.run") as prune:
                with self.assertRaises(SystemExit):
                    main()
                prune.assert_not_called()
        finally:
            guard.close()
        with mock.patch("sys.argv", argv), mock.patch("subprocess.run") as prune:
            main()
            command = prune.call_args.args[0]
            self.assertEqual(command[:3], ["docker", "image", "prune"])
            self.assertIn("label=pygithost.build-cache=1", command)
            self.assertIn("until=24h", command)

    async def test_waiting_for_cache_lock_is_cancellable(self):
        root = image_build.cache_directory(self.manager.image_cache_dir)
        path = root / "held.lock"
        first = await image_build.lock_file(path)
        second = asyncio.create_task(image_build.lock_file(path))
        try:
            await asyncio.sleep(0.02)
            self.assertFalse(second.done())
            second.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await second
        finally:
            first.close()
        third = await asyncio.wait_for(image_build.lock_file(path), timeout=1)
        third.close()

    async def test_checkout_exists_before_build_and_build_precedes_test_container(self):
        old_db = database.DB_PATH
        database.DB_PATH = str(self.root / "worker.db")
        try:
            database._db_init()
            source = self.root / "source"
            source.mkdir()
            (source / "Dockerfile").write_text("FROM scratch\n")

            def git(*args):
                return (
                    subprocess.check_output(["git", *map(str, args)], stderr=subprocess.DEVNULL)
                    .decode()
                    .strip()
                )

            git("init", "-b", "main", source)
            git("-C", source, "add", ".")
            git(
                "-C",
                source,
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-m",
                "source",
            )
            commit = git("-C", source, "rev-parse", "HEAD")
            self.config["steps"] = [{"name": "test", "run": "true"}]
            run = database.db_ci_run_create(
                "alice", "project", "manual", "main", commit, "{}", json.dumps(self.config)
            )
            manager = CIManager(lambda *_: str(source))
            manager.docker_policy = self.manager.docker_policy
            manager.http_attempt = "a" * 64
            manager.image_cache_dir = self.root / "cache"
            original = manager._capture_process

            async def capture(command, **kwargs):
                if command[0] != "docker":
                    return await original(command, **kwargs)
                if command[1] == "build":
                    dockerfile = Path(command[command.index("--file") + 1])
                    self.assertEqual(dockerfile.read_text(), "FROM scratch\n")
                if command[1] in ("run", "rm"):
                    self.commands.append(command)
                    return 0
                return await self.capture(command, **kwargs)

            manager._capture_process = mock.AsyncMock(side_effect=capture)
            await execute_with_image(
                manager, (run, "alice", "project", "manual", "main", commit, "{}"), self.config
            )
            self.assertEqual(database.db_ci_run_get("alice", "project", run)[4], "success")
            actions = [cmd[1] for cmd in self.commands]
            self.assertLess(actions.index("build"), actions.index("run"))
            self.assertTrue(
                any(
                    "pygithost-build/" in arg
                    for cmd in self.commands
                    if cmd[1] == "run"
                    for arg in cmd
                )
            )
        finally:
            database.DB_PATH = old_db
