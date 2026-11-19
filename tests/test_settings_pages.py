import asyncio
import json
import os
import re
import subprocess
import tempfile
import unittest
from dataclasses import replace
from unittest import mock

from pygithost import application, database
from pygithost.ci import CIManager, authorize_repository_execution, default_config
from pygithost.settings_pages import BASIC_GROUPS
from tests import test_repository_ui as ui
from tests.ci_fixtures import commit_ci_config, seed_verified_retention


class SettingsPagesTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ui.RepositoryUITests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        conn = database._db_connect()
        try:
            conn.execute("DELETE FROM ci_configs")
        finally:
            conn.close()
        self.owner = application.FLAT_OWNER_UI
        self.base = self.fixture.base
        self.manager = CIManager(lambda *_: str(self.fixture.bare))
        seed_verified_retention(self.fixture.sha, (self.owner, "project"))

    def config(self):
        return asyncio.run(self.manager.config(self.owner, "project"))

    def token(self, path="/admin/settings"):
        status, page = self.fixture.request(path)
        self.assertEqual(status, 200)
        return re.search(r'name="csrf" value="([^"]+)"', page)[1]

    def save(self, action, *, repository=False, **fields):
        path = self.base + "/ci/preferences" if repository else "/admin/settings"
        return self.fixture.request(
            path,
            {
                "action": action,
                "csrf": self.token(self.base + "/ci/config" if repository else path),
                **fields,
            },
        )

    def variables(self, values, *, repository=False):
        fields = {"env_count": str(len(values))}
        for index, (name, value, pipeline) in enumerate(values):
            fields.update(
                {
                    f"env_name_{index}": name,
                    f"env_value_{index}": value,
                    f"env_pipeline_{index}": pipeline,
                }
            )
        return self.save("ci_environment", repository=repository, **fields)

    def test_admin_page_has_real_controls_and_repository_inheritance(self):
        status, page = self.fixture.request("/admin/settings")
        self.assertEqual(status, 200)
        for heading in (
            "Appearance",
            "Basic server configuration",
            "Network",
            "Security",
            "Storage and Git",
            "Runs and artifacts",
            "Environment variables",
        ):
            self.assertIn(heading, page)
        self.assertIn('<input name="basic_host"', page)
        self.assertNotIn("CI execution defaults", page)
        self.assertNotIn("&lt;select id=&quot;pref-runner", page)
        _, page = self.fixture.request(self.base + "/ci/config")
        self.assertNotIn('name="inherit_timeout_seconds"', page)
        self.assertNotIn('name="configuration_json"', page)
        self.assertNotIn('id="ci-config-json"', page)
        self.assertNotIn('name="run_retention_count"', page)
        self.assertIn("ci/config.json", page)
        self.assertIn('name="env_name_0"', page)
        self.assertIn('<template><div class="settings-env-row">', page)

    def test_trusted_ci_repositories_require_authenticated_admin_and_csrf(self):
        fields = {
            "trusted_repositories": f"{self.owner}/project",
            "confirm_execution_trust": "yes",
        }
        _, page = self.fixture.request("/admin/settings")
        self.assertNotIn('name="trusted_repositories"', page)
        self.assertEqual(self.save("ci_execution_trust", **fields)[0], 403)
        with (
            mock.patch.object(application, "REQUIRE_AUTH", True),
            mock.patch.object(application, "_require_admin", return_value=True) as admin,
            mock.patch.object(
                application.GitHTTPHandler,
                "_require_session_auth",
                new_callable=mock.AsyncMock,
                return_value=True,
            ),
            mock.patch.dict(os.environ, {"PYGITHOST_CI_TRUSTED_REPOSITORIES": "ops/legacy"}),
        ):
            _, page = self.fixture.request("/admin/settings")
            self.assertIn('name="trusted_repositories"', page)
            self.assertIn("ops/legacy", page)
            revision = re.search(r'name="trust_revision" value="([^"]+)"', page)[1]
            fields["trust_revision"] = revision
            self.assertEqual(
                self.fixture.request("/admin/settings", {"action": "ci_execution_trust", **fields})[
                    0
                ],
                403,
            )
            _, page = self.save("ci_execution_trust", **{**fields, "trusted_repositories": "ops/*"})
            self.assertIn("exact owner/repo", page)
            self.assertEqual(database.db_ci_execution_trust_get(), ("", revision))
            _, page = self.save("ci_execution_trust", **fields)
            self.assertIn("No restart is required", page)
            current, new_revision = database.db_ci_execution_trust_get()
            self.assertEqual(current, fields["trusted_repositories"])
            self.assertNotEqual(new_revision, revision)
            self.assertEqual(
                self.save("ci_execution_trust", **{**fields, "trusted_repositories": ""})[0], 409
            )
            self.assertEqual(database.db_ci_execution_trust_get(), (current, new_revision))
            admin.return_value = False
            self.assertEqual(self.fixture.request("/admin/settings")[0], 403)

    def test_saved_trust_is_additive_exact_and_revocable(self):
        host = {"runner": "host"}
        with mock.patch.dict(os.environ, {"PYGITHOST_CI_TRUSTED_REPOSITORIES": "ops/legacy"}):
            with self.assertRaisesRegex(ValueError, "administrator authorization"):
                authorize_repository_execution(self.owner, "project", host)
            identity = f"{self.owner}/project"
            actor = {"actor": "admin", "actor_user_id": None, "ip": "127.0.0.1"}
            self.assertTrue(database.db_ci_execution_trust_set(identity, "0", **actor))
            authorize_repository_execution(self.owner, "project", host, allow_page_trust=True)
            with self.assertRaisesRegex(ValueError, "administrator authorization"):
                authorize_repository_execution(self.owner, "project", host, allow_page_trust=False)
            authorize_repository_execution("ops", "legacy", host)
            with self.assertRaisesRegex(ValueError, "administrator authorization"):
                authorize_repository_execution(
                    self.owner, "project-other", host, allow_page_trust=True
                )
            revision = database.db_ci_execution_trust_get()[1]
            self.assertTrue(database.db_ci_execution_trust_set("", revision, **actor))
            self.assertFalse(database.db_ci_execution_trust_set(identity, revision, **actor))
            with self.assertRaisesRegex(ValueError, "administrator authorization"):
                authorize_repository_execution(self.owner, "project", host, allow_page_trust=True)
            authorize_repository_execution("ops", "legacy", host)
            for action in ("ci_execution_trust_grant", "ci_execution_trust_revoke"):
                events = database.db_audit_list(action=action)
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["target"], identity)
                self.assertEqual(events[0]["actor"], "admin")

    def test_ip_only_trust_requires_configured_peer_and_keeps_csrf(self):
        app = self.fixture.server.app
        identity = f"{self.owner}/project"
        fields = {
            "trusted_repositories": identity,
            "confirm_execution_trust": "yes",
            "trust_revision": "0",
        }
        with mock.patch.object(app, "ci_trust_admin_ips", frozenset({"192.0.2.9"})):
            self.assertEqual(self.save("ci_execution_trust", **fields)[0], 403)
        with mock.patch.object(app, "ci_trust_admin_ips", frozenset({"127.0.0.1"})):
            _, page = self.fixture.request("/admin/settings")
            self.assertIn('name="trusted_repositories"', page)
            self.assertIn("IP-only mode", page)
            self.assertEqual(
                self.fixture.request("/admin/settings", {"action": "ci_execution_trust", **fields})[
                    0
                ],
                403,
            )
            self.assertEqual(self.save("ci_execution_trust", **fields)[0], 200)
        self.assertEqual(database.db_ci_execution_trust_get()[0], identity)
        event = database.db_audit_list(action="ci_execution_trust_grant")[0]
        self.assertEqual(event["actor"], "ip:127.0.0.1")

    def test_ip_only_trust_startup_requires_ip_filter_and_eligible_peer(self):
        app = self.fixture.server.app
        for value in ("*", "192.0.2.0/24", "127.0.0.1/32"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "exact IP"):
                application._ci_trust_admin_ips(value)
        config = app.context.config
        with mock.patch.dict(os.environ, {"PYGITHOST_CI_TRUST_ADMIN_IPS": "127.0.0.1,192.0.2.9"}):
            other = application.AsyncGitServer(app.context, allowlist={"192.0.2.10"})
            self.assertEqual(other.ci_trust_admin_ips, frozenset())
            self.assertFalse(other.ci_manager.allow_page_trust)
            eligible = application.AsyncGitServer(app.context, allowlist={"127.0.0.1"})
            self.assertEqual(eligible.ci_trust_admin_ips, frozenset({"127.0.0.1"}))
            self.assertTrue(eligible.ci_manager.allow_page_trust)
            try:
                unfiltered = application.AsyncGitServer(
                    application.AppContext(replace(config, filter_ips=False)),
                    allowlist={"127.0.0.1"},
                )
                self.assertEqual(unfiltered.ci_trust_admin_ips, frozenset())
                self.assertFalse(unfiltered.ci_manager.allow_page_trust)
            finally:
                application.apply_config(config)

    def test_trust_all_is_opt_in_and_never_applies_with_sign_in(self):
        config = self.fixture.server.app.context.config
        opt_in = replace(config, ip_trust_all_ci_repositories=True)
        checker = application._ip_filter_trusts_ci_repositories
        allowed = {"192.0.2.9"}
        self.assertFalse(checker(config, allowed))
        self.assertTrue(checker(opt_in, allowed))
        self.assertFalse(checker(replace(opt_in, require_auth=True), allowed))
        self.assertFalse(checker(replace(opt_in, filter_ips=False), allowed))
        for unsafe in (set(), {"0.0.0.0/0"}, {"192.0.2.0/24"}, {"*"}):
            with self.subTest(unsafe=unsafe):
                self.assertFalse(checker(opt_in, unsafe))
        with self.assertRaisesRegex(ValueError, "JSON boolean"):
            application.AppConfig.from_mapping({"ip_trust_all_ci_repositories": "false"})

        with mock.patch.dict(os.environ, {"PYGITHOST_CI_TRUSTED_REPOSITORIES": ""}):
            unsigned = CIManager(
                self.manager.repo_path, trust_all_repositories=checker(opt_in, allowed)
            )
            signed = CIManager(
                self.manager.repo_path,
                allow_page_trust=True,
                trust_all_repositories=checker(replace(opt_in, require_auth=True), allowed),
            )
            for requested in ({"runner": "host"}, {"deploy_enabled": True}):
                asyncio.run(unsigned._authorize_execution(self.owner, "any-project", requested))
                with self.assertRaisesRegex(ValueError, "administrator authorization"):
                    asyncio.run(signed._authorize_execution(self.owner, "any-project", requested))

    def test_execution_uses_pipeline_json_or_builtins_not_preferences(self):
        database.db_ci_preferences_set({"timeout_seconds": 60, "cancel_superseded": True})
        self.assertEqual(self.config()["timeout_seconds"], default_config()["timeout_seconds"])
        self.assertFalse(self.config()["cancel_superseded"])
        _, page = self.fixture.request(self.base + "/ci/config")
        self.assertNotIn('name="execution_json"', page)
        from pygithost.settings_pages import parse_preferences

        with self.assertRaises(ValueError):
            parse_preferences({"action": "ci_execution", "execution_json": "{}"}, {})
        # Pipeline-specific choices remain explicit, rather than shared defaults.
        document = {
            "version": 1,
            "pipelines": [
                {
                    "name": "checks",
                    "execution": {"runner": "docker", "timeout_seconds": 123},
                    "steps": [{"name": "Check", "run": "echo test"}],
                }
            ],
            "deployments": [],
        }
        commit_ci_config(self.fixture.bare, document)
        self.assertEqual(self.config()["timeout_seconds"], 123)

    def test_environment_inheritance_pipeline_scope_and_removing_override(self):
        commit_ci_config(
            self.fixture.bare,
            {
                "version": 1,
                "pipelines": [
                    {"name": name, "steps": [{"name": "Check", "run": "echo test"}]}
                    for name in ("ci", "lint")
                ],
            },
        )
        self.variables([("MODE", "global", ""), ("GLOBAL_ONLY", "inherited", "")])
        self.assertEqual(self.config()["env"], {"MODE": "global", "GLOBAL_ONLY": "inherited"})
        self.variables(
            [("MODE", "repository", ""), ("SCOPED", "one-pipeline", "ci")], repository=True
        )
        environments = {
            pipeline["pipeline_id"]: pipeline["env"]
            for pipeline in CIManager.pipelines(self.config())
        }
        self.assertEqual(
            environments["ci"],
            {"MODE": "repository", "GLOBAL_ONLY": "inherited", "SCOPED": "one-pipeline"},
        )
        self.assertEqual(environments["lint"], {"MODE": "repository", "GLOBAL_ONLY": "inherited"})
        self.variables([], repository=True)
        self.assertEqual(self.config()["env"], {"MODE": "global", "GLOBAL_ONLY": "inherited"})
        # Saving secrets doesn't create a database-backed pipeline definition.
        self.assertIsNone(database.db_ci_config_get(self.owner, "project"))

    def test_legacy_environment_is_preserved_without_restoring_retention_or_editor(self):
        document = {
            "version": 1,
            "pipelines": [
                {
                    "name": "ci",
                    "file": "ci/pipeline.json",
                    "execution": {"env": {"KEEP_ME": "legacy"}},
                }
            ],
            "deployments": [],
            "retention": {"runs": {"max_count": 33}, "artifacts": {"days": 8}},
        }
        asyncio.run(self.manager.save_document(self.owner, "project", document))
        _, page = self.fixture.request(self.base + "/ci/config")
        self.assertNotIn('id="ci-config-json"', page)
        self.assertNotIn('name="configuration_json"', page)
        self.assertNotIn('name="run_retention_count"', page)
        self.assertIn('value="KEEP_ME"', page)
        config = self.config()
        self.assertEqual(config["env"]["KEEP_ME"], "legacy")
        # Legacy page retention is not an execution setting any more.
        self.assertEqual(config["run_retention_count"], default_config()["run_retention_count"])
        self.assertEqual(
            config["artifact_retention_days"], default_config()["artifact_retention_days"]
        )
        stored = database.db_ci_config_get(self.owner, "project")
        status, _ = self.fixture.request(
            self.base + "/ci/config", {"configuration_json": json.dumps(document)}
        )
        self.assertEqual(status, 410)
        self.assertEqual(database.db_ci_config_get(self.owner, "project"), stored)
        self.variables([], repository=True)
        self.assertEqual(self.config()["env"], {})

    def test_global_retention_applies_to_cleanup_and_project_page_cannot_override(self):
        fields = {
            "artifact_retention_days": "0",
            "artifact_retention_count": "1",
            "run_retention_count": "2",
            "confirm_retention": "yes",
        }
        self.save("ci_retention", **fields)
        queued = database.db_ci_run_create(self.owner, "project", "manual", "main", "a" * 40, "{}")
        for index in range(4):
            run = database.db_ci_run_create(self.owner, "project", "manual", "main", "b" * 40, "{}")
            database.db_ci_run_update(run, status="success")
            database.db_ci_artifact_set(run, b"fixture")
        rows = database.db_ci_runs_list(self.owner, "project")
        self.assertEqual(len(rows), 3)  # Two completed plus the queued job.
        self.assertIsNotNone(database.db_ci_run_get(self.owner, "project", queued))
        self.assertEqual(database.db_ci_artifacts_count(self.owner, "project"), 1)
        status, body = self.save(
            "ci_retention",
            repository=True,
            artifact_retention_days="0",
            artifact_retention_count="0",
            run_retention_count="0",
            confirm_retention="yes",
        )
        self.assertEqual(status, 400)
        self.assertIn("environment variables", body)
        self.assertEqual(database.db_ci_preferences_get(self.owner, "project")[1], {})
        self.assertEqual(self.config()["run_retention_count"], 2)
        self.assertEqual(self.config()["artifact_retention_count"], 1)

    def test_invalid_forms_csrf_and_admin_permissions_do_not_save(self):
        status, _ = self.fixture.request(
            "/admin/settings", {"action": "ci_environment", "env_count": "0", "csrf": "wrong"}
        )
        self.assertEqual(status, 403)
        _, page = self.variables([("CI", "forbidden", "")])
        self.assertIn("Invalid or reserved environment variable", page)
        self.assertEqual(database.db_ci_preferences_get()[0], {})
        self.assertIn('name="env_name_0" value="CI"', page)
        _, page = self.save(
            "ci_retention",
            artifact_retention_days="1",
            artifact_retention_count="1",
            run_retention_count="1",
        )
        self.assertIn("Confirm applying retention", page)
        self.assertEqual(database.db_ci_preferences_get()[0], {})
        with (
            mock.patch.object(application, "REQUIRE_AUTH", True),
            mock.patch.object(application, "_require_admin", return_value=False),
            mock.patch.object(
                application.GitHTTPHandler,
                "_require_session_auth",
                new_callable=mock.AsyncMock,
                return_value=True,
            ),
        ):
            for path in ("/admin/settings", self.base + "/ci/config"):
                self.assertEqual(self.fixture.request(path)[0], 403)
            self.assertEqual(
                self.fixture.request(self.base + "/ci/preferences", {"action": "ci_environment"})[
                    0
                ],
                403,
            )

    def basic_fields(self, values):
        fields = {"action": "basic", "confirm_restart": "yes"}
        for keys in BASIC_GROUPS.values():
            for key in keys:
                value = values[key]
                if isinstance(value, bool):
                    if value:
                        fields["basic_" + key] = "yes"
                else:
                    fields["basic_" + key] = (
                        "\n".join(value)
                        if isinstance(value, list)
                        else ""
                        if value is None
                        else str(value)
                    )
        return fields

    @unittest.skipUnless(
        os.environ.get("PYGITHOST_TEST_BROWSER"), "set PYGITHOST_TEST_BROWSER to Chromium"
    )
    def test_browser_variable_rows_inheritance_and_retention_forms(self):
        database.db_ci_preferences_set(
            {"env": {"MODE": "server"}, "timeout_seconds": 60, "run_retention_count": 10}
        )
        script = r"""<script>
(async function() {
 const sleep = () => new Promise(resolve => setTimeout(resolve,50));
 const form = action => { const input = document.querySelector('input[name="action"][value="'+action+'"]'); return input ? input.form : null; };
 async function wait(test) { for(let i=0;i<180;i++){if(test())return;await sleep();} throw Error("Settings controls did not initialize"); }
 async function submit(node, message) {
  let posted;
  node.addEventListener("submit", event => { event.preventDefault(); posted=fetch(node.getAttribute("action"),{method:"POST",body:new URLSearchParams(new FormData(node))}).then(response=>response.text()); }, {once:true});
  node.requestSubmit();
  if(!posted) throw Error("Page form validation blocked " + node.elements.action.value);
  const html=await posted;
  if(!html.includes(message)) throw Error("Page form did not save " + node.elements.action.value + ": " + (new DOMParser().parseFromString(html,"text/html").querySelector(".warn")?.textContent || "No response message"));
 }
 try {
  const env=form("ci_environment");
   await wait(()=>env.querySelector(".settings-add-env").onclick);
  if(!env.querySelector("template").content.querySelector("input")) throw Error("Variable template is escaped");
  env.elements.env_name_0.value="MODE"; env.elements.env_value_0.value="repository";
  env.querySelector(".settings-show-env").click(); env.querySelector(".settings-add-env").click();
  if(env.elements.env_count.value!=="2" || env.elements.env_value_1.type!=="text") throw Error("Add variable/show values failed");
  env.elements.env_name_1.value="PIPE_ONLY"; env.elements.env_value_1.value="scoped"; env.elements.env_pipeline_1.value="ci";
  await submit(env, "Repository settings saved");
  if(form("ci_retention")) throw Error("Repository retention form still exists");
  if(document.querySelector('[name="execution_json"]') || document.getElementById("ci-config-json")) throw Error("Removed JSON editor still exists");
  const admin=new DOMParser().parseFromString(await (await fetch("/admin/settings")).text(),"text/html");
  if(!admin.querySelector('[name="basic_port"]') || !admin.querySelector('[name="basic_require_auth"]')) throw Error("Basic server settings are not real form fields");
  const retention=admin.querySelector('input[name="action"][value="ci_retention"]').form;
  const params=new URLSearchParams(new FormData(retention));
  params.set("run_retention_count","3"); params.set("confirm_retention","yes");
  const saved=await (await fetch("/admin/settings",{method:"POST",body:params})).text();
  if(!saved.includes("Server retention defaults saved")) throw Error("Server retention form did not save");
  document.documentElement.dataset.settingsPagesTest="passed";
 }catch(error){document.documentElement.dataset.settingsPagesTest="failed";document.documentElement.dataset.settingsPagesError=error.message;}
})();</script>"""
        original = application._html_page

        def page(title, body):
            result = original(title, body)
            return (
                result.replace(b"</body>", script.encode() + b"</body>")
                if title.startswith("CI settings")
                else result
            )

        with tempfile.TemporaryDirectory(
            prefix="settings-pages-browser-", dir="/tmp/opencode"
        ) as profile:
            with mock.patch.object(application, "_html_page", side_effect=page):
                result = subprocess.run(
                    [
                        os.environ["PYGITHOST_TEST_BROWSER"],
                        "--headless",
                        "--no-sandbox",
                        "--disable-gpu",
                        "--no-first-run",
                        "--disable-dev-shm-usage",
                        "--user-data-dir=" + profile,
                        "--dump-dom",
                        "--virtual-time-budget=15000",
                        f"http://127.0.0.1:{self.fixture.server.port}{self.base}/ci/config",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        error = re.search(r'data-settings-pages-error="([^"]*)"', result.stdout)
        self.assertTrue(
            'data-settings-pages-test="passed"' in result.stdout,
            error[1] if error else result.stderr[-2000:],
        )
        config = self.config()
        self.assertEqual(config["env"], {"MODE": "repository", "PIPE_ONLY": "scoped"})
        self.assertEqual(config["timeout_seconds"], default_config()["timeout_seconds"])
        self.assertEqual(config["run_retention_count"], 3)

    def test_basic_server_settings_are_atomic_restart_only_and_detect_conflicts(self):
        path = self.fixture.root / "startup.json"
        values = self.fixture.server.app.context.config.to_dict()
        path.write_text(json.dumps({**values, "preserve_unknown": "yes"}))
        self.fixture.server.app.config_path = path
        _, page = self.fixture.request("/admin/settings")
        revision = re.search(r'name="basic_revision" value="([^"]+)"', page)[1]
        fields = self.basic_fields(values)
        fields.update(
            csrf=self.token(), basic_revision=revision, basic_port="8123", basic_host="127.0.0.1"
        )
        original_port = application.PORT
        status, page = self.fixture.request("/admin/settings", fields)
        self.assertEqual(status, 200)
        self.assertIn("Restart the server", page)
        saved = json.loads(path.read_text())
        self.assertEqual(saved["port"], 8123)
        self.assertEqual(saved["preserve_unknown"], "yes")
        self.assertEqual(application.PORT, original_port)
        _, page = self.fixture.request("/admin/settings", fields)
        self.assertIn("configuration file changed", page)
        self.assertEqual(json.loads(path.read_text()), saved)
        fields["basic_revision"] = re.search(r'name="basic_revision" value="([^"]+)"', page)[1]
        fields["basic_port"] = "999999"
        _, page = self.fixture.request("/admin/settings", fields)
        self.assertIn("port must be between", page)
        self.assertEqual(json.loads(path.read_text()), saved)

    @unittest.skipUnless(
        os.name == "posix" and os.environ.get("PYGITHOST_TEST_DOCKER_IMAGE") == "python:3.14-slim",
        "requires Docker test image",
    )
    def test_page_environment_reaches_real_docker_but_is_not_in_run_snapshot(self):
        self.variables([("PAGE_VALUE", "global", "")])
        self.variables([("PAGE_VALUE", "repository", "")], repository=True)
        source = self.fixture.source
        (source / "ci").mkdir(exist_ok=True)
        (source / "ci/config.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "steps": [
                        {
                            "name": "Environment",
                            "run": "python -c \"import os; print('page-env=' + os.environ['PAGE_VALUE'])\"",
                        }
                    ],
                }
            )
        )
        self.fixture.git("-C", source, "add", ".")
        self.fixture.git("-C", source, "commit", "-m", "Page environment integration")
        self.fixture.git("-C", source, "push", str(self.fixture.bare), "main")
        commit = self.fixture.git("--git-dir", self.fixture.bare, "rev-parse", "main")

        async def execute():
            try:
                run_id = await self.manager.enqueue(self.owner, "project", "manual", "main", commit)
                await self.manager.wait_idle()
                return run_id
            finally:
                await self.manager.stop()

        run_id = asyncio.run(execute())
        run = database.db_ci_run_get(self.owner, "project", run_id)
        self.assertEqual(run[4], "success", run[5])
        self.assertIn("page-env=repository", run[5])
        self.variables([("PAGE_VALUE", "changed-after-run", "")], repository=True)
        snapshot = json.loads(database.db_ci_run_metadata(self.owner, "project", run_id)["config"])
        self.assertNotIn("PAGE_VALUE", snapshot["env"])
