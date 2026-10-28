import asyncio
import io
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import shlex
from contextlib import closing
import unittest
from unittest import mock
import zipfile
from urllib.parse import urlencode

from pygithost import database
from pygithost.application import _git_ff_merge
from pygithost.ci import CIManager, collect_artifacts, default_config, protected_branch, validate_config
from pygithost.ci_protection import check_updates, prepare_hooks
from pygithost.ci_documentation import EXAMPLE_PIPELINE, ci_configuration_guide
from tests.test_server import ServerRunner, _which_git_backend
from pygithost.application import FLAT_OWNER_UI


class PipelineTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pipeline-")
        self.root = Path(self.temp.name)
        self.old_db = database.DB_PATH
        database.DB_PATH = str(self.root / "ci.db")
        database._db_init()
        self.managers = []

    async def asyncTearDown(self):
        for manager in self.managers:
            await manager.stop()
        database.DB_PATH = self.old_db
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *map(str, args)], stderr=subprocess.PIPE, text=True).strip()

    def repository(self, pipeline=None):
        source, bare = self.root / "source", self.root / "repo.git"
        self.git("init", "-b", "main", source)
        self.git("-C", source, "config", "user.name", "CI")
        self.git("-C", source, "config", "user.email", "ci@test")
        (source / "file.txt").write_text("fixture")
        if pipeline is not None:
            (source / ".pygithost-ci.json").write_text(json.dumps(pipeline))
        self.git("-C", source, "add", ".")
        self.git("-C", source, "commit", "-m", "initial")
        self.git("clone", "--bare", source, bare)
        return source, bare, self.git("-C", source, "rev-parse", "HEAD")

    def manager(self, bare):
        manager = CIManager(lambda *_: str(bare))
        self.managers.append(manager)
        return manager

    async def execute(self, manager, commit, config):
        config = validate_config(config)
        run_id = database.db_ci_run_create("owner", "repo", "manual", "main", commit, "{}", json.dumps(config))
        await manager._execute((run_id, "owner", "repo", "manual", "main", commit, "{}"))
        return database.db_ci_run_get("owner", "repo", run_id)

    def test_defaults_and_validation(self):
        config = default_config()
        self.assertFalse(config["require_ci"])
        self.assertFalse(config["block_direct_pushes"])
        self.assertFalse(config["repository_config"])
        for value in ({"steps": [{}]}, {"steps": [{"name": "test", "run": ""}]},
                      {"command": "true", "steps": [{"name": "test", "run": "true"}]},
                      {"artifacts": {"paths": ["../secret"]}},
                      {"artifacts": {"paths": [".git/config"]}},
                      {"artifacts": {"paths": ["C:/secret"]}},
                      {"require_ci": "true"}, {"block_direct_pushes": True, "protected_branches": ""}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_config(value)

    def test_configuration_guide_examples_and_reference(self):
        example = {key: value for key, value in EXAMPLE_PIPELINE.items() if key != "version"}
        self.assertEqual(validate_config(example)["steps"], EXAMPLE_PIPELINE["steps"])
        guide = str(ci_configuration_guide())
        for text in (".pygithost-ci.json", "separate shell", "target/base commit",
                     "64 KiB", "20 MiB", "Server-controlled", "No runs appear",
                     "PYGITHOST_WORKTREE", "no trailing commas"):
            self.assertIn(text, guide)
        self.assertIn('id="ci-configuration-guide"', guide)

    @unittest.skipUnless(os.name == "posix", "POSIX shell syntax")
    async def test_steps_use_fresh_shells_share_files_and_stop_on_failure(self):
        _source, bare, commit = self.repository()
        manager = self.manager(bare)
        run = await self.execute(manager, commit, {"env": {"EXPECTED": "configured"}, "steps": [
            {"name": "Prepare", "run": "mkdir sub; echo persisted > result.txt; export TRANSIENT=yes; cd sub"},
            {"name": "Check", "run": 'test -z "$TRANSIENT" && test "$EXPECTED" = configured && test -f result.txt && echo isolated'},
            {"name": "Fail", "run": "exit 7"},
            {"name": "Skipped", "run": "echo should-not-run"}]})
        self.assertEqual(run[4], "failed")
        self.assertEqual(run[7], 7)
        steps = json.loads(database.db_ci_steps_get(run[0]))
        self.assertEqual([step["status"] for step in steps], ["success", "success", "failed", "skipped"])
        self.assertIn("isolated", steps[1]["output"])
        self.assertNotIn("Cloning", steps[0]["output"])
        self.assertTrue(steps[1]["finished_at"])
        self.assertNotIn("should-not-run", run[5])

    async def test_repository_config_is_snapshotted_and_server_policy_cannot_be_overridden(self):
        _source, bare, commit = self.repository({"version": 1, "steps": [{"name": "Test", "run": "echo versioned"}]})
        manager = self.manager(bare)
        server = validate_config({"repository_config": True, "events": {"manual": True}, "require_ci": True})
        await manager.save_config("owner", "repo", server)
        run_id = await manager.enqueue("owner", "repo", "manual", "main", commit)
        await manager.wait_idle()
        run = database.db_ci_run_get("owner", "repo", run_id)
        self.assertEqual(run[4], "success")
        self.assertIn("versioned", run[5])
        config = json.loads(database.db_ci_run_metadata("owner", "repo", run_id)["config"])
        self.assertTrue(config["require_ci"])
        for raw in ({"require_ci": False}, {"runner": "host"}, {"image": "evil"},
                    {"command": "true", "timeout_seconds": 9999}, {"version": 2}):
            with mock.patch.object(manager, "repository_pipeline", wraps=manager.repository_pipeline):
                # Commit each invalid file so validation exercises real Git reads.
                source = self.root / "source"
                (source / ".pygithost-ci.json").write_text(json.dumps(raw))
                self.git("-C", source, "add", ".")
                self.git("-C", source, "commit", "-m", "invalid")
                self.git("--git-dir", bare, "fetch", source, "main")
                sha = self.git("-C", source, "rev-parse", "HEAD")
                with self.assertRaises(ValueError):
                    await manager.repository_pipeline("owner", "repo", sha, server)

    async def test_missing_repository_config_fails_closed(self):
        _source, bare, commit = self.repository()
        manager = self.manager(bare)
        await manager.save_config("owner", "repo", {"repository_config": True, "events": {"manual": True}})
        run_id = await manager.enqueue("owner", "repo", "manual", "main", commit)
        run = database.db_ci_run_get("owner", "repo", run_id)
        self.assertEqual(run[4], "failed")
        self.assertEqual(database.db_ci_run_metadata("owner", "repo", run_id)["phase"], "configuration")
        with self.assertRaises(ValueError):
            await manager.rerun("owner", "repo", run_id)

    async def test_pr_uses_base_pipeline_and_rerun_keeps_snapshot(self):
        source, bare, base = self.repository({"command": "echo reviewed-pipeline"})
        (source / ".pygithost-ci.json").write_text(json.dumps({"command": "echo unreviewed-pipeline; exit 9"}))
        self.git("-C", source, "add", ".")
        self.git("-C", source, "commit", "-m", "unreviewed pipeline")
        head = self.git("-C", source, "rev-parse", "HEAD")
        self.git("--git-dir", bare, "fetch", source, "main:refs/heads/feature")
        manager = self.manager(bare)
        await manager.save_config("owner", "repo", {"repository_config": True, "events": {"pr_opened": True}})
        run_id = await manager.enqueue("owner", "repo", "pull_request", "main", base,
            {"pr_number": 1, "base_commit": base, "head_commit": head})
        await manager.wait_idle()
        run = database.db_ci_run_get("owner", "repo", run_id)
        self.assertEqual(run[4], "success")
        self.assertIn("reviewed-pipeline", run[5])
        self.assertNotIn("unreviewed-pipeline", run[5])
        await manager.save_config("owner", "repo", {"command": "exit 10"})
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
            self.assertEqual(connection.execute("SELECT count(*) FROM ci_artifacts").fetchone()[0], 0)

    @unittest.skipUnless(os.name == "posix", "POSIX shell syntax")
    async def test_artifacts_collected_on_failure_and_download_ownership(self):
        _source, bare, commit = self.repository()
        run = await self.execute(self.manager(bare), commit, {"command": "mkdir reports; echo raw > reports/test.xml; exit 1",
            "artifacts": {"paths": ["reports/*.xml"], "when": "failure"}})
        archive = database.db_ci_artifact_get("owner", "repo", run[0], content=True)
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            self.assertEqual(zipped.read("reports/test.xml"), b"raw\n")
        self.assertIsNone(database.db_ci_artifact_get("other", "repo", run[0], content=True))
        self.assertEqual(run[4], "failed")
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
        with closing(database._db_connect()) as connection:
            connection.execute("UPDATE ci_artifacts SET created_at=datetime('now','-8 days') WHERE run_id=?", (ids[1],))
        self.assertEqual([row[0] for row in database.db_ci_artifacts_list("owner", "repo")], [ids[0]])
        self.assertEqual(database.db_ci_artifacts_list("owner", "different"), [])

    def test_merge_check_requires_exact_pr_base_and_head_and_newest_result(self):
        payload = {"pr_number": 1, "base_commit": "base", "head_commit": "head"}
        first = database.db_ci_run_create("owner", "repo", "pull_request", "main", "base", json.dumps(payload))
        database.db_ci_run_update(first, status="success")
        self.assertEqual(database.db_ci_merge_check("owner", "repo", 1, "base", "head"), (first, "success"))
        for args in ((2, "base", "head"), (1, "new", "head"), (1, "base", "new")):
            self.assertIsNone(database.db_ci_merge_check("owner", "repo", *args))
        newer = database.db_ci_run_create("owner", "repo", "pull_request_updated", "main", "base", json.dumps(payload))
        self.assertEqual(database.db_ci_merge_check("owner", "repo", 1, "base", "head"), (newer, "queued"))

    async def test_ff_merge_rejects_stale_sha_and_merges_atomically(self):
        source, bare, base = self.repository()
        (source / "next").write_text("next")
        self.git("-C", source, "add", ".")
        self.git("-C", source, "commit", "-m", "next")
        head = self.git("-C", source, "rev-parse", "HEAD")
        self.git("--git-dir", bare, "fetch", source, "main:refs/heads/feature")
        ok, _message, _commit = await _git_ff_merge(str(bare), "main", "feature", expected=(base, base))
        self.assertFalse(ok)
        self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), base)
        ok, _message, merged = await _git_ff_merge(str(bare), "main", "feature", expected=(base, head))
        self.assertTrue(ok)
        self.assertEqual(merged, head)

    def test_push_patterns_reject_all_updates_including_deletion(self):
        policy = {"block_direct_pushes": True, "protected_branches": "main\nrelease/*"}
        self.assertTrue(protected_branch(policy, "release/1"))
        self.assertFalse(protected_branch(policy, "feature"))
        for branch in ("main", "release/1"):
            for old, new in (("a" * 40, "b" * 40), ("a" * 40, "0" * 40), ("0" * 40, "a" * 40)):
                with self.assertRaises(ValueError):
                    check_updates(f"{old} {new} refs/heads/{branch}\n".encode(), ["main", "release/*"])
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
            rejected = subprocess.run(["git", "-C", str(source), "push", receive, str(bare), "HEAD:main"], capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(b"protected branch main", rejected.stderr)
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), base)
            allowed = subprocess.run(["git", "-C", str(source), "push", receive, str(bare), "HEAD:feature"], capture_output=True)
            self.assertEqual(allowed.returncode, 0, allowed.stderr.decode())
            self.assertIn("refs/heads/feature", (bare / "received-refs").read_text())
            self.assertIn("cat > received-refs", existing.read_text())
        finally:
            directory.cleanup()

    @unittest.skipUnless(_which_git_backend() and os.name == "posix", "real HTTP Git backend")
    async def test_http_push_protection_toggle_and_artifact_route(self):
        source, bare, base = self.repository()
        self.git("--git-dir", bare, "config", "http.receivepack", "true")
        self.git("-C", source, "commit", "--allow-empty", "-m", "next")
        head = self.git("-C", source, "rev-parse", "HEAD")
        with ServerRunner(project_root=str(self.root)) as server:
            database.db_ci_config_set(FLAT_OWNER_UI, "repo", json.dumps(validate_config({
                "block_direct_pushes": True, "protected_branches": "main\nrelease/*"})))
            remote = f"http://127.0.0.1:{server.port}/git/repo.git"
            async def push(ref):
                return await asyncio.to_thread(subprocess.run,
                    ["git", "-C", str(source), "push", remote, ref], capture_output=True)
            rejected = await push("HEAD:main")
            self.assertNotEqual(rejected.returncode, 0, rejected.stderr.decode())
            self.assertIn(b"protected branch main", rejected.stderr)
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), base)
            allowed = await push("HEAD:feature")
            self.assertEqual(allowed.returncode, 0, allowed.stderr.decode())
            # Turning the independent toggle off restores direct pushing.
            database.db_ci_config_set(FLAT_OWNER_UI, "repo", json.dumps(default_config()))
            allowed = await push("HEAD:main")
            self.assertEqual(allowed.returncode, 0, allowed.stderr.decode())
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), head)
            run_id = database.db_ci_run_create(FLAT_OWNER_UI, "repo", "manual", "main", head, "{}")
            database.db_ci_artifact_set(run_id, b"zip-fixture")
            def fetch(path):
                connection = http.client.HTTPConnection("127.0.0.1", server.port)
                try:
                    connection.request("GET", path)
                    response = connection.getresponse()
                    return response.status, response.read(), response.getheader("Content-Disposition")
                finally:
                    connection.close()
            status, body, disposition = await asyncio.to_thread(fetch, f"/r/{FLAT_OWNER_UI}/repo/ci/runs/{run_id}/artifacts")
            self.assertEqual(status, 200)
            self.assertEqual(body, b"zip-fixture")
            self.assertIn("attachment", disposition)
            status, body, _ = await asyncio.to_thread(fetch, f"/r/{FLAT_OWNER_UI}/repo/ci/config")
            self.assertEqual(status, 200)
            self.assertIn(b"Require successful CI", body)
            self.assertIn(f'href="/r/{FLAT_OWNER_UI}/repo/ci/docs"'.encode(), body)
            self.assertNotIn(b'id="ci-configuration-guide"', body)
            self.assertIn(b'JSON in page', body)
            self.assertNotIn(b'Apply pipeline JSON', body)
            for heading in (b"What should run?", b"When should it run?", b"Where should it run?", b"Additional settings"):
                self.assertIn(heading, body)
            self.assertIn(b'name="pipeline_mode" value="command" checked', body)
            self.assertIn(b'for="ci-command"', body)
            status, body, _ = await asyncio.to_thread(fetch, f"/r/{FLAT_OWNER_UI}/repo/ci/docs")
            self.assertEqual(status, 200)
            self.assertIn(b'id="ci-configuration-guide"', body)
            self.assertIn(b'aria-current="page">Documentation', body)
            self.assertIn(b'Complete repository pipeline JSON example', body)
            self.assertIn(b'Built-in environment variables', body)
            status, body, _ = await asyncio.to_thread(fetch, f"/r/{FLAT_OWNER_UI}/repo/artifacts")
            self.assertEqual(status, 200)
            self.assertIn(b'aria-current="page">Artifacts', body)
            self.assertIn(f"ci-{run_id}-artifacts.zip".encode(), body)
            self.assertIn(f'/ci/runs/{run_id}/artifacts'.encode(), body)
            status, body, _ = await asyncio.to_thread(fetch, f"/r/{FLAT_OWNER_UI}/repo")
            self.assertEqual(status, 200)
            self.assertIn(f'href="/r/{FLAT_OWNER_UI}/repo/artifacts"'.encode(), body)

    @unittest.skipUnless(_which_git_backend(), "real HTTP backend")
    async def test_inline_json_editor_preserves_policy_and_rejects_invalid_input(self):
        self.repository()
        with ServerRunner(project_root=str(self.root)) as server:
            original = validate_config({"command": "echo old", "repository_config": True,
                "require_ci": True, "block_direct_pushes": True,
                "runner": "docker", "image": "python:3.14-slim",
                "events": {"manual": True}, "env": {"KEEP": "yes"}})
            database.db_ci_config_set(FLAT_OWNER_UI, "repo", json.dumps(original))
            async def apply(text):
                def request():
                    connection = http.client.HTTPConnection("127.0.0.1", server.port)
                    try:
                        connection.request("POST", f"/r/{FLAT_OWNER_UI}/repo/ci/config",
                            body=urlencode({"config_mode": "json", "pipeline_json": text}),
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
                        response = connection.getresponse()
                        return response.status, response.read()
                    finally:
                        connection.close()
                return await asyncio.to_thread(request)
            text = json.dumps({"version": 1, "steps": [{"name": "Test", "run": "echo new"}], "timeout_seconds": 3600})
            status, body = await apply(text)
            self.assertEqual(status, 200)
            self.assertIn(b"Pipeline JSON saved", body)
            saved = json.loads(database.db_ci_config_get(FLAT_OWNER_UI, "repo"))
            self.assertEqual(saved["steps"], [{"name": "Test", "run": "echo new"}])
            self.assertEqual(saved["command"], "")
            self.assertEqual(saved["timeout_seconds"], 3600)
            self.assertFalse(saved["repository_config"])
            for key in ("require_ci", "block_direct_pushes", "runner", "image", "events", "env"):
                self.assertEqual(saved[key], original[key])
            for invalid in ('{"command": "</textarea><script>bad</script>"',
                            '{"command":"echo new", "require_ci":false}',
                            '{"steps":[]}', '[1,2]', '{"command":"' + "a" * 65536 + '"}'):
                status, body = await apply(invalid)
                self.assertEqual(status, 200)
                self.assertIn(b"Pipeline JSON:", body)
                self.assertNotIn(b"<script>bad</script>", body)
                self.assertEqual(json.loads(database.db_ci_config_get(FLAT_OWNER_UI, "repo")), saved)
            status, _ = await apply('{"command":"echo simple", "env":{}}')
            self.assertEqual(status, 200)
            saved = json.loads(database.db_ci_config_get(FLAT_OWNER_UI, "repo"))
            self.assertEqual(saved["steps"], [])
            self.assertEqual(saved["command"], "echo simple")
            self.assertEqual(saved["env"], {})

    @unittest.skipUnless(_which_git_backend(), "real HTTP backend")
    async def test_settings_pipeline_mode_ignores_inactive_editor(self):
        self.repository()
        with ServerRunner(project_root=str(self.root)) as server:
            async def save(mode, steps, pipeline_json=""):
                def request():
                    connection = http.client.HTTPConnection("127.0.0.1", server.port)
                    try:
                        fields = {"pipeline_mode": mode, "command": "echo stale-command",
                            "steps": steps, "pipeline_json": pipeline_json,
                            "timeout_seconds": "1800", "event_manual": "on"}
                        connection.request("POST", f"/r/{FLAT_OWNER_UI}/repo/ci/config",
                            body=urlencode(fields), headers={"Content-Type": "application/x-www-form-urlencoded"})
                        response = connection.getresponse()
                        return response.status, response.read()
                    finally:
                        connection.close()
                return await asyncio.to_thread(request)
            status, body = await save("steps", '[{"name":"Test","run":"echo steps"}]')
            self.assertEqual(status, 200)
            self.assertIn(b"CI settings saved", body)
            config = json.loads(database.db_ci_config_get(FLAT_OWNER_UI, "repo"))
            self.assertEqual(config["command"], "")
            self.assertEqual(config["steps"][0]["run"], "echo steps")
            self.assertIn(b'name="pipeline_mode" value="steps" checked', body)
            status, body = await save("command", "invalid JSON in unused editor")
            self.assertEqual(status, 200)
            self.assertIn(b"CI settings saved", body)
            config = json.loads(database.db_ci_config_get(FLAT_OWNER_UI, "repo"))
            self.assertEqual(config["command"], "echo stale-command")
            self.assertEqual(config["steps"], [])
            status, body = await save("steps", "invalid JSON")
            self.assertEqual(status, 200)
            self.assertNotIn(b"CI settings saved", body)
            self.assertIn(b"invalid JSON</textarea>", body)
            self.assertIn(b'name="pipeline_mode" value="steps" checked', body)
            self.assertEqual(json.loads(database.db_ci_config_get(FLAT_OWNER_UI, "repo")), config)
            status, body = await save("json", "invalid inactive steps", '{"command":"echo json", "env":{"FROM_JSON":"yes"}}')
            self.assertEqual(status, 200)
            self.assertIn(b"CI settings saved", body)
            self.assertIn(b'name="pipeline_mode" value="json" checked', body)
            config = json.loads(database.db_ci_config_get(FLAT_OWNER_UI, "repo"))
            self.assertEqual(config["pipeline_mode"], "json")
            self.assertEqual(config["command"], "echo json")
            self.assertEqual(config["env"], {"FROM_JSON": "yes"})
            self.assertTrue(config["events"]["manual"])
            status, body = await save("json", "[]", "invalid JSON")
            self.assertNotIn(b"CI settings saved", body)
            self.assertIn(b'name="pipeline_mode" value="json" checked', body)
            self.assertIn(b"invalid JSON</textarea>", body)
            self.assertEqual(json.loads(database.db_ci_config_get(FLAT_OWNER_UI, "repo")), config)

    @unittest.skipUnless(_which_git_backend(), "real HTTP backend")
    async def test_http_merge_enforcement_is_optional_and_checks_current_commits(self):
        source, bare, base = self.repository()
        self.git("-C", source, "commit", "--allow-empty", "-m", "feature")
        head = self.git("-C", source, "rev-parse", "HEAD")
        self.git("--git-dir", bare, "fetch", source, "main:refs/heads/feature")
        with ServerRunner(project_root=str(self.root)) as server:
            with closing(database._db_connect()) as connection:
                connection.execute("INSERT INTO users(username,pass_salt,pass_hash) VALUES('author',X'00',X'00')")
            author = database.db_get_user_by_username("author")[0]
            async def merge(pr_id):
                def request():
                    connection = http.client.HTTPConnection("127.0.0.1", server.port)
                    try:
                        connection.request("POST", f"/r/{FLAT_OWNER_UI}/repo/pulls/{pr_id}/merge", body=b"", headers={"Content-Type": "application/x-www-form-urlencoded"})
                        response = connection.getresponse()
                        return response.status, response.read()
                    finally:
                        connection.close()
                return await asyncio.to_thread(request)
            pr_id = database.db_pr_create(FLAT_OWNER_UI, "repo", "Optional", "", "feature", "main", author)
            status, _ = await merge(pr_id)
            self.assertEqual(status, 200)
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), head)
            self.git("--git-dir", bare, "update-ref", "refs/heads/main", base)
            pr_id = database.db_pr_create(FLAT_OWNER_UI, "repo", "Required", "", "feature", "main", author)
            database.db_ci_config_set(FLAT_OWNER_UI, "repo", json.dumps(validate_config({
                "require_ci": True, "block_direct_pushes": True})))
            status, body = await merge(pr_id)
            self.assertEqual(status, 200)
            self.assertIn(b"Merge blocked", body)
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), base)
            payload = {"pr_number": pr_id, "base_commit": base, "head_commit": head}
            run_id = database.db_ci_run_create(FLAT_OWNER_UI, "repo", "pull_request", "main", base, json.dumps(payload))
            for result in ("queued", "running", "failed", "cancelled", "timed_out"):
                database.db_ci_run_update(run_id, status=result)
                status, body = await merge(pr_id)
                self.assertIn(b"Merge blocked", body)
                self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), base)
            database.db_ci_run_update(run_id, status="success")
            self.git("-C", source, "commit", "--allow-empty", "-m", "changed")
            changed = self.git("-C", source, "rev-parse", "HEAD")
            self.git("--git-dir", bare, "fetch", source, "main:refs/heads/feature")
            status, body = await merge(pr_id)
            self.assertIn(b"Merge blocked", body)
            payload["head_commit"] = changed
            run_id = database.db_ci_run_create(FLAT_OWNER_UI, "repo", "pull_request_updated", "main", base, json.dumps(payload))
            database.db_ci_run_update(run_id, status="success")
            status, body = await merge(pr_id)
            self.assertEqual(status, 200)
            self.assertEqual(self.git("--git-dir", bare, "rev-parse", "main"), changed)
