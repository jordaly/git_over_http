import asyncio
import http.client
import io
import json
import os
import shlex
import subprocess
import tempfile
import unittest
import zipfile
from contextlib import closing
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

from pygithost import database
from pygithost.application import FLAT_OWNER_UI, _git_ff_merge
from pygithost.ci import (
    CIManager,
    collect_artifacts,
    default_config,
    protected_branch,
    render_command,
    validate_config,
)
from pygithost.ci_documentation import EXAMPLE_PIPELINE, ci_configuration_guide
from pygithost.ci_protection import check_updates, prepare_hooks
from tests.ci_fixtures import (
    commit_ci_config,
    commit_file,
    commit_legacy_config,
    trusted_ci_repositories,
    verified_retention,
)
from tests.test_server import ServerRunner, _which_git_backend, with_csrf


class PipelineTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pipeline-")
        self.root = Path(self.temp.name)
        self.old_db = database.DB_PATH
        database.DB_PATH = str(self.root / "ci.db")
        database._db_init()
        self.managers = []
        trust = trusted_ci_repositories("owner/repo", "root/repo")
        trust.__enter__()
        self.addCleanup(trust.__exit__, None, None, None)

    async def asyncTearDown(self):
        for manager in self.managers:
            await manager.stop()
            # Tests that mock start() still schedule configuration-failure mail
            # bookkeeping. Drain it before deleting its temporary database.
            if manager.notification_tasks:
                await asyncio.gather(*tuple(manager.notification_tasks), return_exceptions=True)
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(
            ["git", *map(str, args)], stderr=subprocess.PIPE, text=True
        ).strip()

    def repository(self, pipeline=None, filename="ci/config.json"):
        source, bare = self.root / "source", self.root / "repo.git"
        self.git("init", "-b", "main", source)
        self.git("-C", source, "config", "user.name", "CI")
        self.git("-C", source, "config", "user.email", "ci@test")
        (source / "file.txt").write_text("fixture")
        if pipeline is not None:
            (source / filename).parent.mkdir(parents=True, exist_ok=True)
            (source / filename).write_text(json.dumps(pipeline))
        self.git("-C", source, "add", ".")
        self.git("-C", source, "commit", "-m", "initial")
        self.git("clone", "--bare", source, bare)
        return source, bare, self.git("-C", source, "rev-parse", "HEAD")

    def commit_config(
        self, document, *, branch="main", filename="ci/config.json", raw=None, message="CI fixture"
    ):
        return commit_ci_config(
            self.root / "repo.git",
            document,
            filename=filename,
            branch=branch,
            raw=raw,
            message=message,
        )

    def commit_legacy(self, config, *, branch="main"):
        return commit_legacy_config(self.root / "repo.git", config, branch=branch)

    def manager(self, bare):
        manager = CIManager(lambda *_: str(bare))
        self.managers.append(manager)
        return manager

    async def execute(self, manager, commit, config):
        config = validate_config(config)
        config["_page_environment_live"] = True
        run_id = database.db_ci_run_create(
            "owner", "repo", "manual", "main", commit, "{}", json.dumps(config)
        )
        await manager._execute((run_id, "owner", "repo", "manual", "main", commit, "{}"))
        return database.db_ci_run_get("owner", "repo", run_id)

    def test_defaults_and_validation(self):
        config = default_config()
        self.assertFalse(config["require_ci"])
        self.assertFalse(config["block_direct_pushes"])
        self.assertFalse(config["repository_config"])
        for value in (
            {"steps": [{}]},
            {"steps": [{"name": "test", "run": ""}]},
            {"command": "true", "steps": [{"name": "test", "run": "true"}]},
            {"artifacts": {"paths": ["../secret"]}},
            {"artifacts": {"paths": [".git/config"]}},
            {"artifacts": {"paths": ["C:/secret"]}},
            {"require_ci": "true"},
            {"block_direct_pushes": True, "protected_branches": ""},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_config(value)

    async def test_unconfigured_repository_has_generic_docker_file_preset(self):
        _source, bare, commit = self.repository()
        manager = self.manager(bare)
        config = await manager.config("owner", "repo")
        self.assertEqual(config["pipeline_id"], "ci")
        self.assertEqual(config["repository_file"], "ci/config.json")
        self.assertEqual(config["runner"], "docker")
        self.assertTrue(config["repository_config"])
        for key in ("push", "pr_opened", "pr_updated", "pr_reopened", "manual"):
            self.assertTrue(config["events"][key], key)
        self.assertFalse(config["deploy_enabled"])
        self.assertEqual(config["deployment_targets"], [])
        for event in ("push", "manual", "pull_request"):
            self.assertIsNone(await manager.enqueue("owner", "repo", event, "main", commit))
        self.assertEqual(database.db_ci_runs_list("owner", "repo"), [])
        self.assertIsNone(database.db_ci_config_get("owner", "repo"))

    def test_repository_paths_are_relative_and_safe(self):
        for filename in (
            "ci/config.json",
            "ci/pipelines/tests.json",
            ".ci-config.json",
            ".pygithost-ci.json",
        ):
            with self.subTest(filename=filename):
                self.assertEqual(
                    validate_config({"repository_file": filename})["repository_file"], filename
                )
        for filename in (
            "/ci/config.json",
            "../config.json",
            "ci/../config.json",
            "ci/./config.json",
            "ci/.git/config.json",
            "ci//config.json",
            "ci\\config.json",
            "ci/config.json\0",
            "ci/*.json",
            "ci/config.txt",
        ):
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                validate_config({"repository_file": filename})

    async def test_nested_pipeline_is_read_at_exact_commit(self):
        pipeline = {"version": 1, "steps": [{"name": "Checks", "run": "echo committed"}]}
        source, bare, commit = self.repository(pipeline, "ci/pipelines/tests.json")
        (source / "ci/pipelines/tests.json").write_text("not json")
        config = validate_config(
            {"repository_config": True, "repository_file": "ci/pipelines/tests.json"}
        )
        result = await self.manager(bare).repository_pipeline("owner", "repo", commit, config)
        self.assertEqual(result["steps"], pipeline["steps"])

    async def test_nested_pipeline_symlink_is_rejected(self):
        source, bare, _commit = self.repository()
        (source / "ci").mkdir()
        (source / "ci/config.json").symlink_to("../file.txt")
        self.git("-C", source, "add", ".")
        self.git("-C", source, "commit", "-m", "symlink")
        commit = self.git("-C", source, "rev-parse", "HEAD")
        self.git("-C", source, "push", bare, "main")
        config = validate_config({"repository_config": True, "repository_file": "ci/config.json"})
        with self.assertRaisesRegex(ValueError, "Missing regular"):
            await self.manager(bare).repository_pipeline("owner", "repo", commit, config)

    async def test_generic_file_is_snapshotted_without_saving_settings(self):
        pipeline = {
            "version": 1,
            "steps": [{"name": "Test", "run": "echo auto-ci"}],
            "env": {"MODE": "test"},
            "timeout_seconds": 30,
            "artifacts": {"paths": ["results/*.log"], "when": "always"},
        }
        _source, bare, commit = self.repository(pipeline, "ci/config.json")
        manager = self.manager(bare)
        with mock.patch.object(manager, "start", new_callable=mock.AsyncMock):
            run_id = await manager.enqueue("owner", "repo", "push", "main", commit)
        self.assertIsNotNone(run_id)
        metadata = database.db_ci_run_metadata("owner", "repo", run_id)
        config = json.loads(metadata["config"])
        self.assertEqual(config["steps"], pipeline["steps"])
        self.assertEqual(config["env"], pipeline["env"])
        self.assertEqual(config["timeout_seconds"], 30)
        self.assertEqual(config["runner"], "docker")
        self.assertEqual(config["pipeline_id"], "ci")
        self.assertFalse(config["deploy_enabled"])
        self.assertEqual(config["artifacts"], pipeline["artifacts"])
        self.assertIsNone(database.db_ci_config_get("owner", "repo"))

    async def test_saved_legacy_configuration_does_not_hide_repository_config(self):
        _source, bare, commit = self.repository(
            {"steps": [{"name": "Test", "run": "echo auto"}]}, "ci/config.json"
        )
        manager = self.manager(bare)
        await manager.save_document(
            "owner", "repo", {"version": 1, "pipelines": [], "deployments": []}
        )
        config = await manager.config("owner", "repo", commit)
        self.assertNotIn("_autodetect_repository_config", config)
        self.assertEqual(config["steps"], [{"name": "Test", "run": "echo auto"}])

    async def test_manual_runs_ignore_disabled_legacy_manual_trigger(self):
        _source, bare, _commit = self.repository()
        manager = self.manager(bare)
        raw = default_config()
        raw.update(command="echo manual-only")
        raw["events"] = {key: False for key in raw["events"]}
        commit = self.commit_legacy(raw)
        with mock.patch.object(manager, "start", new_callable=mock.AsyncMock):
            self.assertIsNone(await manager.enqueue("owner", "repo", "push", "main", commit))
            run_id = await manager.enqueue("owner", "repo", "manual", "main", commit)
        self.assertIsNotNone(run_id)
        config = json.loads(database.db_ci_run_metadata("owner", "repo", run_id)["config"])
        self.assertTrue(config["events"]["manual"])

    async def test_invalid_auto_file_fails_and_cannot_enable_deployment_or_host(self):
        source, bare, commit = self.repository(
            {"steps": [{"name": "Test", "run": "echo auto"}], "runner": "host"}, "ci/config.json"
        )
        manager = self.manager(bare)
        with mock.patch.object(manager, "start", new_callable=mock.AsyncMock):
            run_id = await manager.enqueue("owner", "repo", "push", "main", commit)
        run = database.db_ci_run_get("owner", "repo", run_id)
        self.assertEqual(run[4], "failed")
        self.assertIn("does not match the supported pipeline schema", run[5])
        self.assertEqual(manager.pending, {})

    async def test_saving_legacy_preset_does_not_activate_missing_file(self):
        _source, bare, commit = self.repository()
        manager = self.manager(bare)
        from pygithost.ci_config import editor_document

        await manager.save_document(
            "owner", "repo", editor_document(await manager.config("owner", "repo"))
        )
        config = await manager.config("owner", "repo", commit)
        self.assertTrue(config["_autodetect_repository_config"])
        with mock.patch.object(manager, "start", new_callable=mock.AsyncMock):
            self.assertIsNone(await manager.enqueue("owner", "repo", "manual", "main", commit))
        self.assertIsNotNone(database.db_ci_config_get("owner", "repo"))

    @unittest.skipUnless(
        os.name == "posix" and os.environ.get("PYGITHOST_TEST_DOCKER_IMAGE") == "python:3.14-slim",
        "requires the default python:3.14-slim Docker test image",
    )
    async def test_automatic_repository_pipeline_executes_in_real_docker(self):
        _source, bare, commit = self.repository(
            {
                "version": 1,
                "timeout_seconds": 30,
                "steps": [
                    {"name": "Auto-discovered test", "run": "python -c \"print('auto-ci-ok')\""}
                ],
            },
            "ci/config.json",
        )
        manager = self.manager(bare)
        run_id = await manager.enqueue("owner", "repo", "push", "main", commit)
        await manager.wait_idle()
        run = database.db_ci_run_get("owner", "repo", run_id)
        self.assertEqual(run[4], "success", run[5])
        self.assertIn("auto-ci-ok", run[5])
        self.assertIsNone(database.db_ci_config_get("owner", "repo"))

    def test_multiple_pipeline_validation(self):
        config = validate_config(
            {
                "pipelines": [
                    {"pipeline_id": "lint", "command": "echo lint", "events": {"push": True}}
                ]
            }
        )
        self.assertEqual(config["pipelines"][0]["pipeline_id"], "lint")
        self.assertTrue(config["pipelines"][0]["events"]["manual"])
        self.assertEqual(validate_config(config), config)
        for children in (
            [{"pipeline_id": "default"}],
            [{"pipeline_id": "same"}, {"pipeline_id": "same"}],
            [{"pipeline_id": "../bad"}],
            [{}],
            [{"pipeline_id": "lint", "require_ci": True}],
            [{"pipeline_id": "lint", "repository_file": "../ci.json"}],
            [{"pipeline_id": "lint", "pipelines": [{"pipeline_id": "nested"}]}],
        ):
            with self.subTest(children=children), self.assertRaises(ValueError):
                validate_config({"pipelines": children})

    async def test_multiple_pipelines_fan_out_and_manual_selection(self):
        _source, bare, _commit = self.repository()
        manager = self.manager(bare)
        commit = self.commit_legacy(
            {
                "command": "echo default",
                "events": {"push": True, "manual": True},
                "cancel_superseded": True,
                "pipelines": [
                    {
                        "pipeline_id": "lint",
                        "command": "echo {{ env.PYGITHOST_PIPELINE }}",
                        "cancel_superseded": True,
                        "events": {"push": True, "manual": True},
                    }
                ],
            }
        )
        await manager.enqueue("owner", "repo", "push", "main", commit)
        await manager.wait_idle()
        runs = database.db_ci_runs_list("owner", "repo")
        self.assertEqual(len(runs), 2)
        self.assertTrue(all(row[4] == "success" for row in runs))
        self.assertIn("lint", runs[0][5])
        identities = {
            json.loads(database.db_ci_run_metadata("owner", "repo", row[0])["config"])[
                "pipeline_id"
            ]
            for row in runs
        }
        self.assertEqual(identities, {"default", "lint"})
        selected = await manager.enqueue("owner", "repo", "manual", "main", commit, pipeline="lint")
        await manager.wait_idle()
        self.assertEqual(len(database.db_ci_runs_list("owner", "repo")), 3)
        rerun = await manager.rerun("owner", "repo", selected)
        await manager.wait_idle()
        self.assertEqual(
            json.loads(database.db_ci_run_metadata("owner", "repo", rerun)["config"])[
                "pipeline_id"
            ],
            "lint",
        )
        with self.assertRaises(ValueError):
            await manager.enqueue("owner", "repo", "manual", "main", commit, pipeline="missing")

    async def test_json_document_executes_shared_defaults_and_keeps_rerun_snapshot(self):
        _source, bare, _commit = self.repository()
        manager = self.manager(bare)
        document = {
            "defaults": {
                "triggers": {"manual": {"enabled": True}},
                "execution": {"env": {"VALUE": "original"}},
            },
            "pipelines": {"tests": {"steps": [{"name": "Test", "run": "echo {{ env.VALUE }}"}]}},
        }
        commit = self.commit_config(document)
        self.assertEqual((await manager.config("owner", "repo", commit))["document"], document)
        first = await manager.enqueue("owner", "repo", "manual", "main", commit, pipeline="tests")
        await manager.wait_idle()
        self.assertIn("original", database.db_ci_run_get("owner", "repo", first)[5])
        document["defaults"]["execution"]["env"]["VALUE"] = "changed"
        self.commit_config(document)
        rerun = await manager.rerun("owner", "repo", first)
        await manager.wait_idle()
        self.assertIn("original", database.db_ci_run_get("owner", "repo", rerun)[5])
        self.assertNotIn(
            "document", json.loads(database.db_ci_run_metadata("owner", "repo", rerun)["config"])
        )

    async def test_json_document_merge_check_does_not_require_phantom_default(self):
        self.repository()
        manager = self.manager(self.root / "repo.git")
        base = self.commit_config(
            {
                "policies": {"require_ci": True},
                "defaults": {"triggers": {"pull_request": {"enabled": True}}},
                "pipelines": {"tests": {"steps": [{"name": "Test", "run": "echo test"}]}},
            }
        )
        payload = {
            "pr_number": 1,
            "base_commit": base,
            "head_commit": "head",
            "pipeline_id": "tests",
        }
        run = database.db_ci_run_create(
            "owner", "repo", "pull_request", "main", base, json.dumps(payload)
        )
        self.assertNotEqual(
            (await manager.merge_check("owner", "repo", 1, base, "head", "main"))[1], "success"
        )
        database.db_ci_run_update(run, status="success")
        self.assertEqual(
            (await manager.merge_check("owner", "repo", 1, base, "head", "main"))[1], "success"
        )

    async def test_merge_requires_each_applicable_pipeline(self):
        self.repository()
        manager = self.manager(self.root / "repo.git")
        base = self.commit_legacy(
            {
                "command": "echo test",
                "require_ci": True,
                "events": {"pr_opened": True},
                "pipelines": [
                    {"pipeline_id": "lint", "command": "echo lint", "events": {"pr_opened": True}}
                ],
            }
        )
        payload = {"pr_number": 1, "base_commit": base, "head_commit": "head"}
        first = database.db_ci_run_create(
            "owner", "repo", "pull_request", "main", base, json.dumps(payload)
        )
        database.db_ci_run_update(first, status="success")
        self.assertIsNone(await manager.merge_check("owner", "repo", 1, base, "head", "main"))
        second = database.db_ci_run_create(
            "owner",
            "repo",
            "pull_request",
            "main",
            base,
            json.dumps({**payload, "pipeline_id": "lint"}),
        )
        database.db_ci_run_update(second, status="success")
        self.assertEqual(
            (await manager.merge_check("owner", "repo", 1, base, "head", "main"))[1], "success"
        )
        database.db_ci_run_update(second, status="failed")
        self.assertEqual(
            (await manager.merge_check("owner", "repo", 1, base, "head", "main"))[1], "failed"
        )

    def test_deployment_claim_is_per_pipeline_and_commit(self):
        self.assertTrue(database.db_deployment_claim(1, "owner", "repo", "sha"))
        lint = json.dumps({"pipeline_id": "lint"})
        self.assertTrue(database.db_deployment_claim(2, "owner", "repo", "sha", lint))
        self.assertFalse(database.db_deployment_claim(3, "owner", "repo", "sha", lint))
        database._db_init()
        self.assertFalse(database.db_deployment_claim(4, "owner", "repo", "sha"))

    def test_configuration_guide_examples_and_reference(self):
        example = {key: value for key, value in EXAMPLE_PIPELINE.items() if key != "version"}
        self.assertEqual(validate_config(example)["steps"], EXAMPLE_PIPELINE["steps"])
        guide = str(ci_configuration_guide())
        for text in (
            "ci/config.json",
            "fresh shell",
            "target/base commit",
            "256 KiB",
            "20 MiB",
            "settings",
            "No runs appear",
            "PYGITHOST_WORKTREE",
            "trailing commas",
            "Trusted CI repositories",
        ):
            self.assertIn(text, guide)
        self.assertIn('id="ci-configuration-guide"', guide)

    def test_jinja_style_environment_references_are_literal_single_pass(self):
        env = {"NAME": "value with spaces", "OTHER": "{{ env.NAME }}", "EMPTY": ""}
        self.assertEqual(
            render_command('echo "{{ env.NAME }}" {{env.EMPTY}}', env), 'echo "value with spaces" '
        )
        self.assertEqual(render_command("{{ env.OTHER }}", env), "{{ env.NAME }}")
        self.assertEqual(render_command("echo unchanged", env), "echo unchanged")
        self.assertEqual(render_command("{{ not_a_ci_template }}", env), "{{ not_a_ci_template }}")
        for template in (
            "{{ env.MISSING }}",
            "{{ env.NAME | upper }}",
            "{{ env['NAME'] }}",
            "{{ env.NAME",
        ):
            with self.subTest(template=template), self.assertRaises(ValueError):
                render_command(template, env)

    async def test_environment_templates_execute_without_expanding_saved_snapshot(self):
        _source, bare, commit = self.repository()
        manager = self.manager(bare)
        config = {
            "env": {"GREETING": "template-value"},
            "steps": [
                {"name": "Template", "run": "echo {{ env.GREETING }} {{ env.PYGITHOST_BRANCH }}"}
            ],
        }
        run = await self.execute(manager, commit, config)
        self.assertEqual(run[4], "success")
        self.assertIn("template-value main", run[5])
        snapshot = database.db_ci_run_metadata("owner", "repo", run[0])["config"]
        self.assertIn("{{ env.GREETING }}", snapshot)
        config = {
            "steps": [
                {"name": "Missing", "run": "echo {{ env.NOT_CONFIGURED }}"},
                {"name": "Skipped", "run": "echo should-not-execute"},
            ]
        }
        run = await self.execute(manager, commit, config)
        self.assertEqual(run[4], "failed")
        self.assertIn("Undefined CI environment variable: NOT_CONFIGURED", run[5])
        self.assertEqual(
            [step["status"] for step in json.loads(database.db_ci_steps_get(run[0]))],
            ["failed", "skipped"],
        )

    @unittest.skipUnless(os.name == "posix", "POSIX shell syntax")
    async def test_steps_use_fresh_shells_share_files_and_stop_on_failure(self):
        _source, bare, commit = self.repository()
        manager = self.manager(bare)
        run = await self.execute(
            manager,
            commit,
            {
                "env": {"EXPECTED": "configured"},
                "steps": [
                    {
                        "name": "Prepare",
                        "run": "mkdir sub; echo persisted > result.txt; export TRANSIENT=yes; cd sub",
                    },
                    {
                        "name": "Check",
                        "run": 'test -z "$TRANSIENT" && test "$EXPECTED" = configured && test -f result.txt && echo isolated',
                    },
                    {"name": "Fail", "run": "exit 7"},
                    {"name": "Skipped", "run": "echo should-not-run"},
                ],
            },
        )
        self.assertEqual(run[4], "failed")
        self.assertEqual(run[7], 7)
        steps = json.loads(database.db_ci_steps_get(run[0]))
        self.assertEqual(
            [step["status"] for step in steps], ["success", "success", "failed", "skipped"]
        )
        self.assertIn("isolated", steps[1]["output"])
        self.assertNotIn("Cloning", steps[0]["output"])
        self.assertTrue(steps[1]["finished_at"])
        self.assertNotIn("should-not-run", run[5])

    async def test_repository_config_is_snapshotted_and_server_policy_cannot_be_overridden(self):
        _source, bare, _commit = self.repository()
        manager = self.manager(bare)
        self.commit_config(
            {"version": 1, "steps": [{"name": "Test", "run": "echo versioned"}]},
            filename="ci/pipeline.json",
        )
        commit = self.commit_config(
            {
                "version": 1,
                "settings": {"require_ci": True},
                "pipelines": {
                    "tests": {
                        "file": "ci/pipeline.json",
                        "events": {"manual": True},
                        "runner": "host",
                    }
                },
            }
        )
        server = manager.pipelines(await manager.config("owner", "repo", commit))[0]
        self.assertTrue(server["require_ci"])
        self.assertEqual(server["pipeline_id"], "tests")
        run_id = await manager.enqueue("owner", "repo", "manual", "main", commit)
        await manager.wait_idle()
        run = database.db_ci_run_get("owner", "repo", run_id)
        self.assertEqual(run[4], "success", run[5])
        self.assertIn("versioned", run[5])
        config = json.loads(database.db_ci_run_metadata("owner", "repo", run_id)["config"])
        self.assertTrue(config["require_ci"])
        for raw in (
            {"require_ci": False},
            {"runner": "host"},
            {"image": "evil"},
            {"command": "true", "timeout_seconds": 9999},
            {"version": 2},
        ):
            with self.subTest(raw=raw):
                sha = self.commit_config(raw, filename="ci/pipeline.json", message="invalid")
                with self.assertRaises(ValueError):
                    await manager.repository_pipeline("owner", "repo", sha, server)

    async def test_missing_repository_config_fails_closed(self):
        _source, bare, _commit = self.repository()
        manager = self.manager(bare)
        commit = self.commit_config(
            {
                "version": 1,
                "pipelines": {
                    "tests": {
                        "file": "ci/pipeline.json",
                        "events": {"manual": True},
                        "runner": "host",
                    }
                },
            }
        )
        run_id = await manager.enqueue("owner", "repo", "manual", "main", commit)
        run = database.db_ci_run_get("owner", "repo", run_id)
        self.assertEqual(run[4], "failed")
        self.assertEqual(
            database.db_ci_run_metadata("owner", "repo", run_id)["phase"], "configuration"
        )
        with self.assertRaises(ValueError):
            await manager.rerun("owner", "repo", run_id)

    async def test_pr_uses_base_pipeline_and_rerun_keeps_snapshot(self):
        _source, bare, _commit = self.repository()
        base = self.commit_config(
            {
                "version": 1,
                "pipelines": {
                    "default": {
                        "runner": "host",
                        "steps": [{"name": "Reviewed", "run": "echo reviewed-pipeline"}],
                        "events": {"pr_opened": True},
                    }
                },
            }
        )
        head = self.commit_config(
            {
                "version": 1,
                "pipelines": {
                    "default": {
                        "runner": "host",
                        "steps": [
                            {"name": "Unreviewed", "run": "echo unreviewed-pipeline; exit 9"}
                        ],
                        "events": {"pr_opened": True},
                    }
                },
            }
        )
        manager = self.manager(bare)
        run_id = await manager.enqueue(
            "owner",
            "repo",
            "pull_request",
            "main",
            head,
            {"pr_number": 1, "base_commit": base, "head_commit": head},
        )
        await manager.wait_idle()
        run = database.db_ci_run_get("owner", "repo", run_id)
        self.assertEqual(run[4], "success", run[5])
        self.assertIn("reviewed-pipeline", run[5])
        self.assertNotIn("unreviewed-pipeline", run[5])
        self.commit_config(
            {
                "version": 1,
                "runner": "host",
                "steps": [{"name": "Changed", "run": "exit 10"}],
            }
        )
        rerun_id = await manager.rerun("owner", "repo", run_id)
        await manager.wait_idle()
        self.assertEqual(database.db_ci_run_get("owner", "repo", rerun_id)[4], "success")

    def test_artifact_and_step_metadata_cascade_and_crash_recovery(self):
        run_id = database.db_ci_run_create("owner", "repo", "manual", "main", "a" * 40, "{}")
        database.db_ci_artifact_set(run_id, b"archive")
        database.db_ci_steps_set(run_id, json.dumps([{"status": "running"}, {"status": "pending"}]))
        database.db_ci_run_update(run_id, status="running")
        database.db_ci_recover_runs()
        steps = json.loads(database.db_ci_steps_get(run_id))
        self.assertEqual([step["status"] for step in steps], ["interrupted", "skipped"])
        with closing(database._db_connect()) as connection:
            connection.execute("DELETE FROM ci_runs WHERE id=?", (run_id,))
            self.assertEqual(connection.execute("SELECT count(*) FROM ci_steps").fetchone()[0], 0)
            self.assertEqual(
                connection.execute("SELECT count(*) FROM ci_artifacts").fetchone()[0], 0
            )

    @unittest.skipUnless(os.name == "posix", "POSIX shell syntax")
    async def test_artifacts_collected_on_failure_and_download_ownership(self):
        _source, bare, commit = self.repository()
        run = await self.execute(
            self.manager(bare),
            commit,
            {
                "command": "mkdir reports; echo raw > reports/test.xml; exit 1",
                "artifacts": {"paths": ["reports/*.xml"], "when": "failure"},
            },
        )
        archive = database.db_ci_artifact_get("owner", "repo", run[0], content=True)
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            self.assertEqual(zipped.read("reports/test.xml"), b"raw\n")
        self.assertIsNone(database.db_ci_artifact_get("other", "repo", run[0], content=True))
        self.assertEqual(run[4], "failed")
        with verified_retention(commit, ("owner", "repo")):
            with closing(database._db_connect()) as connection:
                connection.execute("UPDATE ci_artifacts SET created_at=datetime('now','-8 days')")
            self.assertIsNone(database.db_ci_artifact_get("owner", "repo", run[0]))

    def test_artifacts_skip_symlinks_hardlinks_git_and_enforce_size(self):
        work = self.root / "checkout"
        work.mkdir()
        (work / ".git").mkdir()
        (work / ".git" / "config").write_text("private")
        (work / "safe.txt").write_text("safe")
        outside = self.root / "outside"
        outside.write_text("private")
        if os.name == "posix":
            (work / "link.txt").symlink_to(outside)
            (work / "linked-dir").symlink_to(self.root, target_is_directory=True)
            os.link(outside, work / "hard.txt")
        archive = collect_artifacts(work, ["**/*"])
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            self.assertEqual(zipped.namelist(), ["safe.txt"])
        with (work / "huge").open("wb") as stream:
            stream.truncate(20 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(ValueError, "20 MiB"):
            collect_artifacts(work, ["huge"])

    def test_artifact_list_is_scoped_paginated_and_excludes_expired_archives(self):
        ids = []
        for owner in ("owner", "owner", "other"):
            run_id = database.db_ci_run_create(owner, "repo", "manual", "main", "a" * 40, "{}")
            database.db_ci_artifact_set(run_id, b"archive")
            ids.append(run_id)
        rows = database.db_ci_artifacts_list("owner", "repo", limit=1)
        self.assertEqual([row[0] for row in rows], [ids[1]])
        rows = database.db_ci_artifacts_list("owner", "repo", before=ids[1])
        self.assertEqual([row[0] for row in rows], [ids[0]])
        with verified_retention("a" * 40, ("owner", "repo")):
            with closing(database._db_connect()) as connection:
                connection.execute(
                    "UPDATE ci_artifacts SET created_at=datetime('now','-8 days') WHERE run_id=?",
                    (ids[1],),
                )
            self.assertEqual(
                [row[0] for row in database.db_ci_artifacts_list("owner", "repo")], [ids[0]]
            )
        self.assertEqual(database.db_ci_artifacts_list("owner", "different"), [])

    def test_merge_check_requires_exact_pr_base_and_head_and_newest_result(self):
        payload = {"pr_number": 1, "base_commit": "base", "head_commit": "head"}
        first = database.db_ci_run_create(
            "owner", "repo", "pull_request", "main", "base", json.dumps(payload)
        )
        database.db_ci_run_update(first, status="success")
        self.assertEqual(
            database.db_ci_merge_check("owner", "repo", 1, "base", "head"), (first, "success")
        )
        for args in ((2, "base", "head"), (1, "new", "head"), (1, "base", "new")):
            self.assertIsNone(database.db_ci_merge_check("owner", "repo", *args))
        newer = database.db_ci_run_create(
            "owner", "repo", "pull_request_updated", "main", "base", json.dumps(payload)
        )
        self.assertEqual(
            database.db_ci_merge_check("owner", "repo", 1, "base", "head"), (newer, "queued")
        )

    async def test_ff_merge_rejects_stale_sha_and_merges_atomically(self):
        source, bare, base = self.repository()
        (source / "next").write_text("next")
        self.git("-C", source, "add", ".")
        self.git("-C", source, "commit", "-m", "next")
        head = self.git("-C", source, "rev-parse", "HEAD")
        self.git("--git-dir", bare, "fetch", source, "main:refs/heads/feature")
        ok, _message, _commit = await _git_ff_merge(
            str(bare), "main", "feature", expected=(base, base)
        )
        self.assertFalse(ok)
        self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), base)
        ok, _message, merged = await _git_ff_merge(
            str(bare), "main", "feature", expected=(base, head)
        )
        self.assertTrue(ok)
        self.assertEqual(merged, head)

    def test_push_patterns_reject_all_updates_including_deletion(self):
        policy = {"block_direct_pushes": True, "protected_branches": "main\nrelease/*"}
        self.assertTrue(protected_branch(policy, "release/1"))
        self.assertFalse(protected_branch(policy, "feature"))
        for branch in ("main", "release/1"):
            for old, new in (("a" * 40, "b" * 40), ("a" * 40, "0" * 40), ("0" * 40, "a" * 40)):
                with self.assertRaises(ValueError):
                    check_updates(
                        f"{old} {new} refs/heads/{branch}\n".encode(), ["main", "release/*"]
                    )
        check_updates(b"a b refs/heads/feature\n", ["main"])

    @unittest.skipUnless(os.name == "posix", "POSIX hooks")
    async def test_real_receive_hook_chains_existing_hooks_and_does_not_overwrite(self):
        source, bare, base = self.repository()
        existing = bare / "hooks" / "pre-receive"
        existing.write_text("#!/bin/sh\ncat > received-refs\nexit 0\n")
        existing.chmod(0o755)
        directory, hooks = prepare_hooks(bare / "hooks", ["main"])
        try:
            receive = "--receive-pack=git -c core.hooksPath=" + shlex.quote(hooks) + " receive-pack"
            self.git("-C", source, "commit", "--allow-empty", "-m", "next")
            rejected = subprocess.run(
                ["git", "-C", str(source), "push", receive, str(bare), "HEAD:main"],
                capture_output=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(b"protected branch main", rejected.stderr)
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), base)
            allowed = subprocess.run(
                ["git", "-C", str(source), "push", receive, str(bare), "HEAD:feature"],
                capture_output=True,
            )
            self.assertEqual(allowed.returncode, 0, allowed.stderr.decode())
            self.assertIn("refs/heads/feature", (bare / "received-refs").read_text())
            self.assertIn("cat > received-refs", existing.read_text())
        finally:
            directory.cleanup()

    @unittest.skipUnless(_which_git_backend() and os.name == "posix", "real HTTP Git backend")
    async def test_http_push_protection_toggle_and_artifact_route(self):
        source, bare, _base = self.repository()
        self.git("--git-dir", bare, "config", "http.receivepack", "true")
        protected = commit_legacy_config(
            bare,
            validate_config({"block_direct_pushes": True, "protected_branches": "main\nrelease/*"}),
        )
        self.git("-C", source, "fetch", bare, "main")
        self.git("-C", source, "reset", "--hard", "FETCH_HEAD")
        self.git("-C", source, "commit", "--allow-empty", "-m", "next")
        with ServerRunner(project_root=str(self.root)) as server:
            remote = f"http://127.0.0.1:{server.port}/git/repo.git"

            async def push(ref):
                return await asyncio.to_thread(
                    subprocess.run,
                    ["git", "-C", str(source), "push", remote, ref],
                    capture_output=True,
                )

            rejected = await push("HEAD:main")
            self.assertNotEqual(rejected.returncode, 0, rejected.stderr.decode())
            self.assertIn(b"protected branch main", rejected.stderr)
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), protected)
            allowed = await push("HEAD:feature")
            self.assertEqual(allowed.returncode, 0, allowed.stderr.decode())
            # Turning the independent toggle off restores direct pushing.
            unprotected = commit_legacy_config(bare, default_config())
            self.git("-C", source, "fetch", bare, "main")
            self.git("-C", source, "reset", "--hard", "FETCH_HEAD")
            allowed = await push("HEAD:main")
            self.assertEqual(allowed.returncode, 0, allowed.stderr.decode())
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), unprotected)
            run_id = database.db_ci_run_create(
                FLAT_OWNER_UI, "repo", "manual", "main", unprotected, "{}"
            )
            database.db_ci_artifact_set(run_id, b"zip-fixture")

            def fetch(path):
                connection = http.client.HTTPConnection("127.0.0.1", server.port)
                try:
                    connection.request("GET", path)
                    response = connection.getresponse()
                    return (
                        response.status,
                        response.read(),
                        response.getheader("Content-Disposition"),
                    )
                finally:
                    connection.close()

            status, body, disposition = await asyncio.to_thread(
                fetch, f"/r/{FLAT_OWNER_UI}/repo/ci/runs/{run_id}/artifacts"
            )
            self.assertEqual(status, 200)
            self.assertEqual(body, b"zip-fixture")
            self.assertIn("attachment", disposition)
            status, body, _ = await asyncio.to_thread(fetch, f"/r/{FLAT_OWNER_UI}/repo/ci/config")
            self.assertEqual(status, 200)
            self.assertIn(b"Project pipelines", body)
            self.assertIn(b"ci/config.json", body)
            self.assertIn(b">Deployments</a>", body)
            self.assertIn(b"Environment variables", body)
            status, deployment_body, _ = await asyncio.to_thread(
                fetch, f"/r/{FLAT_OWNER_UI}/repo/ci/deployments"
            )
            self.assertEqual(status, 200)
            self.assertIn(b"No deployments yet", deployment_body)
            self.assertIn(b'<nav class="ci-tabs"', deployment_body)
            database.db_deployment_claim(run_id, FLAT_OWNER_UI, "repo", unprotected)
            database.db_deployment_finish(run_id, "failed", "<script>private output</script>")
            deployment_id = database.db_deployments_list(FLAT_OWNER_UI, "repo")[0][0]
            status, deployment_body, _ = await asyncio.to_thread(
                fetch, f"/r/{FLAT_OWNER_UI}/repo/ci/deployments/{deployment_id}"
            )
            self.assertEqual(status, 200)
            self.assertIn(b"&lt;script&gt;private output&lt;/script&gt;", deployment_body)
            self.assertNotIn(b"<script>private output</script>", deployment_body)
            self.assertIn(f'href="/r/{FLAT_OWNER_UI}/repo/ci/docs"'.encode(), body)
            self.assertNotIn(b'id="ci-configuration-guide"', body)
            self.assertNotIn(b'name="configuration_json"', body)
            self.assertNotIn(b"Apply pipeline JSON", body)
            self.assertIn(b'action="/r/root/repo/ci/preferences"', body)
            for old in (
                b'name="pipeline_mode"',
                b'for="ci-command"',
                b'name="pipelines"',
                b'name="event_push"',
            ):
                self.assertNotIn(old, body)
            status, body, _ = await asyncio.to_thread(fetch, f"/r/{FLAT_OWNER_UI}/repo/ci/docs")
            self.assertEqual(status, 200)
            self.assertIn(b'id="ci-configuration-guide"', body)
            self.assertIn(b'aria-current="page">Documentation', body)
            self.assertIn(b"Every execution option", body)
            self.assertIn(b"PYGITHOST_PIPELINE", body)
            status, body, _ = await asyncio.to_thread(fetch, f"/r/{FLAT_OWNER_UI}/repo/artifacts")
            self.assertEqual(status, 200)
            self.assertRegex(
                body, rb'aria-current="page"><svg[^>]*>.*?</svg><span>Artifacts</span>'
            )
            self.assertIn(f"ci-{run_id}-artifacts.zip".encode(), body)
            self.assertIn(f"/ci/runs/{run_id}/artifacts".encode(), body)
            status, body, _ = await asyncio.to_thread(fetch, f"/r/{FLAT_OWNER_UI}/repo")
            self.assertEqual(status, 200)
            self.assertIn(f'href="/r/{FLAT_OWNER_UI}/repo/artifacts"'.encode(), body)

    @unittest.skipUnless(_which_git_backend(), "real HTTP backend")
    async def test_json_editor_posts_are_rejected_in_favor_of_repository_file(self):
        self.repository()
        with ServerRunner(project_root=str(self.root)) as server:

            def post(fields):
                connection = http.client.HTTPConnection("127.0.0.1", server.port)
                try:
                    connection.request(
                        "POST",
                        f"/r/{FLAT_OWNER_UI}/repo/ci/config",
                        body=urlencode(with_csrf(server, fields)),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            for fields in (
                {"configuration_json": '{"command": "echo must-not-save"}'},
                {"pipeline_mode": "command", "command": "echo stale-command"},
            ):
                with self.subTest(fields=fields):
                    status, body = await asyncio.to_thread(post, fields)
                    self.assertEqual(status, 410, body)
                    self.assertIn(b"ci/config.json", body)
                    self.assertNotIn(b"Configuration saved", body)
            self.assertIsNone(database.db_ci_config_get(FLAT_OWNER_UI, "repo"))

    @unittest.skipUnless(_which_git_backend(), "real HTTP backend")
    async def test_http_merge_enforcement_is_optional_and_checks_current_commits(self):
        source, bare, base = self.repository()
        self.git("-C", source, "commit", "--allow-empty", "-m", "feature")
        head = self.git("-C", source, "rev-parse", "HEAD")
        self.git("--git-dir", bare, "fetch", source, "main:refs/heads/feature")
        with ServerRunner(project_root=str(self.root)) as server:
            with closing(database._db_connect()) as connection:
                connection.execute(
                    "INSERT INTO users(username,pass_salt,pass_hash) VALUES('author',X'00',X'00')"
                )
            author = database.db_get_user_by_username("author")[0]

            async def merge(pr_id):
                def request():
                    connection = http.client.HTTPConnection("127.0.0.1", server.port)
                    try:
                        connection.request(
                            "POST",
                            f"/r/{FLAT_OWNER_UI}/repo/pulls/{pr_id}/merge",
                            body=urlencode(with_csrf(server, {"merge_method": "ff"})),
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                        )
                        response = connection.getresponse()
                        return response.status, response.read()
                    finally:
                        connection.close()

                return await asyncio.to_thread(request)

            pr_id = database.db_pr_create(
                FLAT_OWNER_UI, "repo", "Optional", "", "feature", "main", author
            )
            status, _ = await merge(pr_id)
            self.assertEqual(status, 303)
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), head)
            self.git("--git-dir", bare, "update-ref", "refs/heads/main", base)
            required = commit_legacy_config(
                bare,
                validate_config(
                    {
                        "command": "true",
                        "require_ci": True,
                        "block_direct_pushes": True,
                        "events": {"pr_opened": True},
                    }
                ),
            )
            self.git("--git-dir", bare, "update-ref", "refs/heads/feature", required)
            changed = commit_file(bare, "feature.txt", "changed\n", branch="feature")
            pr_id = database.db_pr_create(
                FLAT_OWNER_UI, "repo", "Required", "", "feature", "main", author
            )
            status, body = await merge(pr_id)
            self.assertEqual(status, 409)
            self.assertIn(b"Merge blocked", body)
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), required)
            payload = {"pr_number": pr_id, "base_commit": required, "head_commit": changed}
            run_id = database.db_ci_run_create(
                FLAT_OWNER_UI, "repo", "pull_request", "main", required, json.dumps(payload)
            )
            for result in ("queued", "running", "failed", "cancelled", "timed_out"):
                database.db_ci_run_update(run_id, status=result)
                status, body = await merge(pr_id)
                self.assertIn(b"Merge blocked", body)
                self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), required)
            database.db_ci_run_update(run_id, status="success")
            newer = commit_file(bare, "feature.txt", "newer\n", branch="feature")
            status, body = await merge(pr_id)
            self.assertIn(b"Merge blocked", body)
            payload["head_commit"] = newer
            run_id = database.db_ci_run_create(
                FLAT_OWNER_UI,
                "repo",
                "pull_request_updated",
                "main",
                required,
                json.dumps(payload),
            )
            database.db_ci_run_update(run_id, status="success")
            status, body = await merge(pr_id)
            self.assertEqual(status, 303, body)
            self.assertNotIn(b"Merge blocked", body)
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), newer, body)

    @unittest.skipUnless(_which_git_backend(), "real HTTP backend")
    async def test_http_merge_reads_ci_requirement_from_default_branch(self):
        source, bare, _base = self.repository()
        required = self.commit_legacy(
            {"command": "true", "require_ci": True, "events": {"pr_opened": True}}
        )
        self.git("--git-dir", bare, "branch", "release", required)
        release = self.commit_legacy(
            {"command": "true", "events": {"pr_opened": True}}, branch="release"
        )
        self.git("-C", source, "fetch", bare, "release")
        self.git("-C", source, "reset", "--hard", "FETCH_HEAD")
        self.git("-C", source, "commit", "--allow-empty", "-m", "release feature")
        head = self.git("-C", source, "rev-parse", "HEAD")
        self.git("-C", source, "push", bare, "HEAD:refs/heads/feature")
        with ServerRunner(project_root=str(self.root)) as server:
            with closing(database._db_connect()) as connection:
                connection.execute(
                    "INSERT INTO users(username,pass_salt,pass_hash) VALUES('author',X'00',X'00')"
                )
            author = database.db_get_user_by_username("author")[0]
            pr_id = database.db_pr_create(
                FLAT_OWNER_UI, "repo", "Release policy", "", "feature", "release", author
            )

            async def merge():
                def request():
                    connection = http.client.HTTPConnection("127.0.0.1", server.port)
                    try:
                        connection.request(
                            "POST",
                            f"/r/{FLAT_OWNER_UI}/repo/pulls/{pr_id}/merge",
                            body=urlencode(with_csrf(server, {"merge_method": "ff"})),
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                        )
                        response = connection.getresponse()
                        return response.status, response.read()
                    finally:
                        connection.close()

                return await asyncio.to_thread(request)

            status, body = await merge()
            self.assertIn(b"Merge blocked", body)
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "release"), release)

            # A success recorded for the default branch is not a check for the
            # release target commit and must not unlock this merge.
            main_run = database.db_ci_run_create(
                FLAT_OWNER_UI,
                "repo",
                "pull_request",
                "main",
                required,
                json.dumps({"pr_number": pr_id, "base_commit": required, "head_commit": head}),
            )
            database.db_ci_run_update(main_run, status="success")
            status, body = await merge()
            self.assertIn(b"Merge blocked", body)
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "release"), release)

            release_run = database.db_ci_run_create(
                FLAT_OWNER_UI,
                "repo",
                "pull_request",
                "release",
                release,
                json.dumps({"pr_number": pr_id, "base_commit": release, "head_commit": head}),
            )
            database.db_ci_run_update(release_run, status="success")
            status, body = await merge()
            self.assertEqual(status, 303, body)
            self.assertNotIn(b"Merge blocked", body)
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "release"), head)

    @unittest.skipUnless(_which_git_backend() and os.name == "posix", "real HTTP Git backend")
    async def test_http_push_rejects_unverifiable_ci_policy(self):
        source, bare, base = self.repository()
        self.git("--git-dir", bare, "config", "http.receivepack", "true")
        self.git("-C", source, "commit", "--allow-empty", "-m", "next")
        with ServerRunner(project_root=str(self.root)) as server:
            remote = f"http://127.0.0.1:{server.port}/git/repo.git"
            with mock.patch.object(
                CIManager,
                "config",
                new=mock.AsyncMock(
                    return_value={
                        "_configuration_git_error": True,
                        "require_ci": False,
                        "block_direct_pushes": False,
                    }
                ),
            ):
                rejected = await asyncio.to_thread(
                    subprocess.run,
                    ["git", "-C", str(source), "push", remote, "HEAD:main"],
                    capture_output=True,
                )
            self.assertNotEqual(rejected.returncode, 0, rejected.stderr.decode())
            self.assertIn(b"503", rejected.stderr)
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), base)
