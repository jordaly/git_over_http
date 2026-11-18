import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pygithost import database
from pygithost.api.preflight import inspect as inspect_deployment
from pygithost.ci import (
    CIManager,
    authorize_repository_execution,
    protected_branch,
    validate_config,
)
from pygithost.repository_ci import (
    compile_repository_document,
    configuration_path,
    read_document,
)


class RepositoryCISourceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="repository-ci-source-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repository"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "ci@example.invalid")
        self.git("config", "user.name", "CI tests")
        self.old_db = database.DB_PATH
        database.DB_PATH = str(self.root / "test.db")
        self.addCleanup(setattr, database, "DB_PATH", self.old_db)
        old_resolver = database._retention_head_resolver
        database.configure_retention_head_resolver(
            lambda _owner, _repo: self.git("rev-parse", "HEAD")
        )
        self.addCleanup(database.configure_retention_head_resolver, old_resolver)
        database._db_init()
        self.manager = CIManager(lambda _owner, _repo: str(self.repo / ".git"))

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args]).decode().strip()

    def commit(self, document=None, raw=None):
        path = self.repo / "ci" / "config.json"
        path.parent.mkdir(exist_ok=True)
        if document is not None or raw is not None:
            path.write_text(raw if raw is not None else json.dumps(document), encoding="utf-8")
        else:
            (self.repo / "README").write_text("No CI configured.", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-q", "--allow-empty", "-m", "CI fixture")
        return self.git("rev-parse", "HEAD")

    def document(self, name="tests"):
        return {
            "version": 1,
            "pipelines": [
                {
                    "name": name,
                    "execution": {"runner": "docker"},
                    "triggers": {"push": {"enabled": True}},
                    "steps": [{"name": "Tests", "run": "echo repository"}],
                }
            ],
            "deployments": [],
        }

    async def test_saved_database_commands_are_not_a_configuration_source(self):
        self.commit()
        await self.manager.save_config(
            "owner", "repo", {"command": "echo must-not-run", "events": {"push": True}}
        )
        config = await self.manager.config("owner", "repo")
        self.assertEqual(config["command"], "")
        self.assertEqual(config["steps"], [])
        self.assertEqual(config["repository_file"], "ci/config.json")
        self.assertTrue(config["_autodetect_repository_config"])

    async def test_full_document_and_deployments_are_read_from_git(self):
        document = self.document()
        document["deployments"] = [
            {
                "name": "release",
                "pipeline": "tests",
                "branch": "main",
                "script_content": "echo deploy",
                "run_with": "sh",
            }
        ]
        commit = self.commit(document)
        with mock.patch.dict("os.environ", {"PYGITHOST_CI_TRUSTED_REPOSITORIES": "owner/repo"}):
            config = await self.manager.config("owner", "repo", commit)
        self.assertEqual(config["steps"][0]["run"], "echo repository")
        self.assertEqual(config["deployment_targets"][0]["deployment_name"], "release")
        self.assertFalse(config["repository_config"])

    async def test_repository_cannot_self_authorize_host_execution(self):
        document = self.document()
        document["pipelines"][0]["execution"]["runner"] = "host"
        commit = self.commit(document)
        self.manager.started = True
        with (
            mock.patch.dict("os.environ", {"PYGITHOST_CI_TRUSTED_REPOSITORIES": ""}),
            mock.patch.object(self.manager, "_schedule_notification"),
            mock.patch.object(self.manager, "_capture_process") as process,
        ):
            run_id = await self.manager.enqueue("owner", "repo", "push", "main", commit)
        self.assertEqual(database.db_ci_run_get("owner", "repo", run_id)[4], "failed")
        self.assertIn(
            "administrator authorization",
            database.db_ci_run_metadata("owner", "repo", run_id)["reason"],
        )
        process.assert_not_called()
        self.assertEqual(self.manager.pending, {})

    async def test_host_denial_preserves_declared_branch_policy(self):
        document = self.document()
        document["pipelines"][0]["execution"]["runner"] = "host"
        document["policies"] = {
            "require_ci": True,
            "block_direct_pushes": True,
            "protected_branches": ["release/*"],
        }
        commit = self.commit(document)
        with mock.patch.dict("os.environ", {"PYGITHOST_CI_TRUSTED_REPOSITORIES": ""}):
            config = await self.manager.config("owner", "repo", commit)
        self.assertTrue(config["require_ci"])
        self.assertTrue(protected_branch(config, "release/v1"))
        self.assertFalse(protected_branch(config, "feature"))
        self.assertIn("_repository_config_error", self.manager.pipelines(config)[0])

    async def test_revoked_host_authorization_blocks_snapshot_rerun(self):
        config = validate_config({"runner": "host", "command": "echo must-not-run"})
        old = database.db_ci_run_create(
            "owner", "repo", "manual", "main", "a" * 40, "{}", json.dumps(config)
        )
        self.manager.started = True
        with (
            mock.patch.dict("os.environ", {"PYGITHOST_CI_TRUSTED_REPOSITORIES": ""}),
            mock.patch.object(self.manager, "_schedule_notification"),
        ):
            run_id = await self.manager.rerun("owner", "repo", old)
        self.assertEqual(database.db_ci_run_get("owner", "repo", run_id)[4], "failed")
        self.assertEqual(self.manager.pending, {})

    async def test_execution_rechecks_authorization_after_queueing(self):
        config = validate_config({"runner": "host", "command": "echo must-not-run"})
        run_id = database.db_ci_run_create(
            "owner", "repo", "manual", "main", "a" * 40, "{}", json.dumps(config)
        )
        row = (run_id, "owner", "repo", "manual", "main", "a" * 40, "{}")
        with (
            mock.patch.dict("os.environ", {"PYGITHOST_CI_TRUSTED_REPOSITORIES": ""}),
            mock.patch.object(self.manager, "_capture_process") as process,
        ):
            with self.assertRaisesRegex(ValueError, "administrator authorization"):
                await self.manager._execute(row)
        process.assert_not_called()

    async def test_deployment_rechecks_authorization_before_claim_or_checkout(self):
        config = validate_config(
            {
                "runner": "docker",
                "command": "echo test",
                "deploy_enabled": True,
                "deploy_branch": "main",
                "deploy_script_content": "echo must-not-run",
                "deploy_interpreter": "sh",
            }
        )
        run_id = database.db_ci_run_create(
            "owner", "repo", "push", "main", "a" * 40, "{}", json.dumps(config)
        )
        database.db_ci_run_update(run_id, status="success", return_code=0)
        row = (run_id, "owner", "repo", "push", "main", "a" * 40, "{}")
        with (
            mock.patch.dict("os.environ", {"PYGITHOST_CI_TRUSTED_REPOSITORIES": ""}),
            mock.patch.object(self.manager, "_capture_process") as process,
            mock.patch.object(database, "db_deployment_claim") as claim,
        ):
            await self.manager._deploy_target(row, config, config)
        process.assert_not_called()
        claim.assert_not_called()
        self.assertIn(
            "administrator authorization",
            database.db_ci_run_metadata("owner", "repo", run_id)["reason"],
        )

    def test_host_authorization_is_exact_and_separate_from_docker_policy(self):
        host = {"runner": "host"}
        deployment = {"runner": "docker", "deployment_targets": [{"deploy_enabled": True}]}
        with mock.patch.dict("os.environ", {"PYGITHOST_CI_TRUSTED_REPOSITORIES": "owner/repo"}):
            authorize_repository_execution("owner", "repo", host)
            authorize_repository_execution("owner", "repo", deployment)
            with self.assertRaises(ValueError):
                authorize_repository_execution("owner", "repo-other", host)
        with mock.patch.dict("os.environ", {"PYGITHOST_CI_TRUSTED_REPOSITORIES": ""}):
            authorize_repository_execution("owner", "repo", {"runner": "remote-docker"})
            with self.assertRaises(ValueError):
                authorize_repository_execution("owner", "repo", deployment)
        with mock.patch.dict("os.environ", {"PYGITHOST_CI_TRUSTED_REPOSITORIES": "owner/*"}):
            with self.assertRaises(ValueError):
                authorize_repository_execution("owner", "repo", host)

    def test_preflight_cannot_report_denied_deployment_as_ready(self):
        result = inspect_deployment(
            {
                "deploy_steps": [{"name": "Deploy", "run": "echo deploy"}],
                "_repository_config_error": "Host execution is not authorized.",
            },
            str(self.repo),
        )
        self.assertFalse(result["ok"])
        self.assertIn({"name": "execution_authorized", "ok": False}, result["checks"])

    async def test_simple_pipeline_remains_supported(self):
        commit = self.commit({"version": 1, "steps": [{"name": "Tests", "run": "echo simple"}]})
        config = await self.manager.config("owner", "repo", commit)
        self.assertEqual(config["steps"][0]["run"], "echo simple")
        self.assertFalse(config["repository_config"])

    async def test_page_secrets_override_repository_values_without_erasing_other_variables(self):
        document = self.document()
        document["pipelines"][0]["execution"]["env"] = {
            "TOKEN": "repository-placeholder",
            "PUBLIC_VALUE": "yes",
        }
        commit = self.commit(document)
        database.db_ci_preferences_set(
            {"env": {"TOKEN": "page-secret"}, "pipeline_env": {"tests": {"SCOPED": "secret"}}},
            "owner",
            "repo",
        )
        config = await self.manager.config("owner", "repo", commit)
        self.assertEqual(
            config["env"],
            {"TOKEN": "page-secret", "PUBLIC_VALUE": "yes", "SCOPED": "secret"},
        )

    async def test_legacy_secrets_are_preserved_but_not_legacy_execution(self):
        commit = self.commit(self.document())
        await self.manager.save_config(
            "owner", "repo", {"command": "echo retired", "env": {"TOKEN": "existing-secret"}}
        )
        config = await self.manager.config("owner", "repo", commit)
        self.assertEqual(config["env"]["TOKEN"], "existing-secret")
        self.assertEqual(config["command"], "")
        self.assertEqual(config["steps"][0]["run"], "echo repository")

    async def test_empty_page_secrets_remove_legacy_values_but_keep_git_variables(self):
        document = self.document()
        document["pipelines"][0]["execution"]["env"] = {"PUBLIC_VALUE": "yes"}
        commit = self.commit(document)
        await self.manager.save_config("owner", "repo", {"env": {"TOKEN": "retired-secret"}})
        database.db_ci_preferences_set({"env": {}, "pipeline_env": {}}, "owner", "repo")
        config = await self.manager.config("owner", "repo", commit)
        self.assertEqual(config["env"], {"PUBLIC_VALUE": "yes"})

    async def test_retention_uses_default_branch_and_ignores_run_snapshots(self):
        database.db_ci_preferences_set({"artifact_retention_days": 4})
        database.db_ci_preferences_set({"artifact_retention_days": 36500}, "owner", "repo")
        document = self.document()
        document["retention"] = {"artifacts": {"days": 2}}
        self.commit(document)
        await self.manager.refresh_retention("owner", "repo")
        database.db_ci_run_create(
            "owner",
            "repo",
            "manual",
            "main",
            "a" * 40,
            "{}",
            json.dumps({"artifact_retention_days": 7, "_repository_retention": {}}),
        )
        connection = database._db_connect()
        try:
            self.assertEqual(
                database._db_ci_retention(connection, "owner", "repo")["artifact_retention_days"], 2
            )
        finally:
            connection.close()
        database.db_ci_run_create(
            "owner",
            "repo",
            "manual",
            "main",
            "b" * 40,
            "{}",
            json.dumps({"_repository_retention": {"artifact_retention_days": 1}}),
        )
        connection = database._db_connect()
        try:
            self.assertEqual(
                database._db_ci_retention(connection, "owner", "repo")["artifact_retention_days"], 2
            )
        finally:
            connection.close()

    async def test_invalid_default_configuration_caches_commit_but_pauses_cleanup(self):
        database.db_ci_preferences_set({"artifact_retention_days": 1})
        commit = self.commit(raw='{"pipelines": [')
        run_id = database.db_ci_run_create("owner", "repo", "manual", "main", commit, "{}")
        database.db_ci_artifact_set(run_id, b"archive")
        connection = database._db_connect()
        try:
            connection.execute(
                "UPDATE ci_artifacts SET created_at=datetime('now','-30 days') WHERE run_id=?",
                (run_id,),
            )
        finally:
            connection.close()
        await self.manager.refresh_retention("owner", "repo")
        connection = database._db_connect()
        try:
            row = connection.execute(
                "SELECT commit_hash FROM ci_retention_policy WHERE owner=? AND repo=?",
                ("owner", "repo"),
            ).fetchone()
            self.assertEqual(row, (commit,))
            self.assertEqual(
                database._db_ci_retention(connection, "owner", "repo")["artifact_retention_days"],
                0,
            )
        finally:
            connection.close()
        # An invalid configuration is never allowed to fall back to old limits.
        self.assertEqual(database.db_ci_artifact_get("owner", "repo", run_id), 7)

    async def test_out_of_band_head_change_pauses_cleanup_until_refresh(self):
        document = self.document()
        document["retention"] = {"artifacts": {"days": 1}}
        self.commit(document)
        await self.manager.refresh_retention("owner", "repo")
        run_id = database.db_ci_run_create("owner", "repo", "manual", "main", "a" * 40, "{}")
        database.db_ci_artifact_set(run_id, b"archive")
        connection = database._db_connect()
        try:
            connection.execute(
                "UPDATE ci_artifacts SET created_at=datetime('now','-30 days') WHERE run_id=?",
                (run_id,),
            )
        finally:
            connection.close()
        # A direct Git update raises the limit without a push finalizer.
        document["retention"] = {"artifacts": {"days": 0}}
        self.commit(document)
        self.assertEqual(database.db_ci_artifact_get("owner", "repo", run_id), 7)
        await self.manager.refresh_retention("owner", "repo")
        self.assertEqual(database.db_ci_artifact_get("owner", "repo", run_id), 7)

    async def test_default_branch_switch_pauses_cleanup_until_refresh(self):
        document = self.document()
        document["retention"] = {"artifacts": {"days": 1}}
        self.commit(document)
        await self.manager.refresh_retention("owner", "repo")
        run_id = database.db_ci_run_create("owner", "repo", "manual", "main", "a" * 40, "{}")
        database.db_ci_artifact_set(run_id, b"archive")
        connection = database._db_connect()
        try:
            connection.execute(
                "UPDATE ci_artifacts SET created_at=datetime('now','-30 days') WHERE run_id=?",
                (run_id,),
            )
        finally:
            connection.close()
        # HEAD now points at another branch whose verified limits are unknown.
        self.git("checkout", "-q", "-b", "release")
        document["retention"] = {"artifacts": {"days": 0}}
        self.commit(document)
        self.assertEqual(database.db_ci_artifact_get("owner", "repo", run_id), 7)
        await self.manager.refresh_retention("owner", "repo")
        self.assertEqual(database.db_ci_artifact_get("owner", "repo", run_id), 7)

    async def test_enqueue_refreshes_missing_retention_then_reuses_the_cache(self):
        commit = self.commit(self.document())
        self.manager.started = True
        with mock.patch.object(self.manager, "_enqueue", new_callable=mock.AsyncMock) as enqueue:
            enqueue.return_value = None
            await self.manager.enqueue("owner", "repo", "manual", "main", commit)
        connection = database._db_connect()
        try:
            row = connection.execute(
                "SELECT commit_hash FROM ci_retention_policy WHERE owner=? AND repo=?",
                ("owner", "repo"),
            ).fetchone()
            self.assertEqual(row, (commit,))
        finally:
            connection.close()
        # A later run with a verified cache row does not read Git again.
        with (
            mock.patch.object(
                self.manager, "refresh_retention", new_callable=mock.AsyncMock
            ) as refresh,
            mock.patch.object(self.manager, "_enqueue", new_callable=mock.AsyncMock) as enqueue,
        ):
            enqueue.return_value = None
            await self.manager.enqueue("owner", "repo", "manual", "main", commit)
        refresh.assert_not_awaited()

    async def test_failed_retention_refresh_retries_are_bounded(self):
        self.manager.started = True
        self.manager.retention_failed.add(("owner", "repo"))
        with mock.patch.object(
            self.manager, "refresh_retention", new_callable=mock.AsyncMock
        ) as refresh:
            await self.manager.ensure_retention("owner", "repo")
            await self.manager.ensure_retention("owner", "repo")
        self.assertEqual(refresh.await_count, 1)

    async def test_enqueue_uses_exact_commit_not_current_head(self):
        original = self.commit(self.document("original"))
        self.commit(self.document("changed"))
        with mock.patch.object(self.manager, "_enqueue", new_callable=mock.AsyncMock) as enqueue:
            await self.manager.enqueue("owner", "repo", "push", "main", original)
        self.assertEqual(enqueue.call_args.kwargs["selected"]["pipeline_id"], "original")

    async def test_pull_request_configuration_comes_from_base_not_head(self):
        base = self.commit(self.document("reviewed"))
        head = self.commit(self.document("unreviewed"))
        with mock.patch.object(self.manager, "_enqueue", new_callable=mock.AsyncMock) as enqueue:
            await self.manager.enqueue(
                "owner",
                "repo",
                "pull_request",
                "main",
                head,
                {"base_commit": base, "head_commit": head},
            )
        self.assertEqual(enqueue.call_args.kwargs["selected"]["pipeline_id"], "reviewed")

    async def test_malformed_config_never_falls_back_to_saved_commands(self):
        commit = self.commit(raw='{"pipelines": [')
        await self.manager.save_config("owner", "repo", {"command": "echo retired"})
        config = await self.manager.config("owner", "repo", commit)
        self.assertEqual(config["command"], "")
        self.assertTrue(config["_repository_config_invalid"])
        self.assertTrue(config["require_ci"])
        self.assertTrue(protected_branch(config, "main"))
        self.assertTrue(protected_branch(config, "feature"))
        self.assertIsNone(
            await self.manager.merge_check("owner", "repo", 1, commit, "b" * 40, "main")
        )
        with self.assertRaises(ValueError):
            await self.manager.repository_pipeline("owner", "repo", commit, config)

    async def test_invalid_configuration_records_failure_without_executing(self):
        commit = self.commit(raw='{"pipelines": [')
        self.manager.started = True
        with mock.patch.object(self.manager, "_schedule_notification"):
            run_id = await self.manager.enqueue("owner", "repo", "push", "main", commit)
        run = database.db_ci_run_get("owner", "repo", run_id)
        self.assertEqual(run[4], "failed")
        self.assertEqual(self.manager.pending, {})
        self.assertEqual(
            database.db_ci_run_metadata("owner", "repo", run_id)["phase"], "configuration"
        )

    async def test_missing_configuration_does_not_queue_database_commands(self):
        commit = self.commit()
        await self.manager.save_config(
            "owner", "repo", {"command": "echo retired", "events": {"push": True}}
        )
        with mock.patch.object(self.manager, "start") as start:
            self.assertIsNone(await self.manager.enqueue("owner", "repo", "push", "main", commit))
        start.assert_not_called()
        self.assertEqual(database.db_ci_runs_list("owner", "repo"), [])

    async def test_referenced_pipeline_uses_trusted_pr_base(self):
        document = self.document()
        document["pipelines"][0]["triggers"]["pull_request"] = {"enabled": True}
        document["pipelines"][0].pop("steps")
        document["pipelines"][0]["file"] = "ci/tests.json"
        child = self.repo / "ci" / "tests.json"
        child.parent.mkdir(exist_ok=True)
        child.write_text(json.dumps({"steps": [{"name": "Tests", "run": "echo reviewed"}]}))
        base = self.commit(document)
        child.write_text(json.dumps({"steps": [{"name": "Tests", "run": "echo unreviewed"}]}))
        head = self.commit(document)
        self.manager.started = True
        run_id = await self.manager.enqueue(
            "owner",
            "repo",
            "pull_request",
            "main",
            head,
            {"base_commit": base, "head_commit": head},
        )
        config = json.loads(database.db_ci_run_metadata("owner", "repo", run_id)["config"])
        self.assertEqual(config["steps"][0]["run"], "echo reviewed")
        self.assertNotEqual(base, head)

    async def test_unverified_git_reads_fail_closed_but_verified_unborn_is_allowed(self):
        self.commit(self.document())
        broken = CIManager(lambda _owner, _repo: str(self.root / "missing.git"))
        config = await broken.config("owner", "repo")
        self.assertTrue(config["_configuration_git_error"])
        self.assertEqual(config["_configuration_status"], "unavailable")
        self.assertTrue(config["require_ci"])
        self.assertTrue(config["block_direct_pushes"])
        self.assertTrue(protected_branch(config, "main"))
        self.assertIsNone(await broken.merge_check("owner", "repo", 1, "a" * 40, "b" * 40, "main"))

        empty = self.root / "empty.git"
        subprocess.check_call(["git", "init", "-q", "--bare", str(empty)])
        unborn = CIManager(lambda _owner, _repo: str(empty))
        config = await unborn.config("owner", "repo")
        self.assertFalse(config["_configuration_git_error"])
        self.assertFalse(config["require_ci"])
        self.assertFalse(config["block_direct_pushes"])

    def test_configuration_references_must_stay_inside_ci(self):
        for filename in (
            "pipeline.json",
            "../ci/x.json",
            "ci/../x.json",
            "ci//x.json",
            "/ci/x",
            "ci\\x",
        ):
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                configuration_path(filename)
        self.assertEqual(configuration_path("ci/pipelines/tests.json"), "ci/pipelines/tests.json")
        document = self.document()
        document["pipelines"][0].pop("steps")
        document["pipelines"][0]["file"] = "outside.json"
        with self.assertRaises(ValueError):
            compile_repository_document(document)

    def test_duplicate_keys_and_nonobject_roots_are_rejected(self):
        for raw in ('{"steps":[],"steps":[]}', "null", "[]"):
            with self.subTest(raw=raw):
                commit = self.commit(raw=raw)
                with self.assertRaises(ValueError):
                    read_document(str(self.repo / ".git"), commit)

    def test_symlink_and_oversized_config_are_rejected(self):
        commit = self.commit(raw=" " * 262145)
        with self.assertRaisesRegex(ValueError, "256 KiB"):
            read_document(str(self.repo / ".git"), commit)
        path = self.repo / "ci" / "config.json"
        path.unlink()
        try:
            path.symlink_to("../README")
        except OSError:
            self.skipTest("Symlinks are unavailable.")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "Symlink fixture")
        with self.assertRaisesRegex(ValueError, "regular"):
            read_document(str(self.repo / ".git"), self.git("rev-parse", "HEAD"))
