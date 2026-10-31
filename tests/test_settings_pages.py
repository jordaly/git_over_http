import asyncio
import json
import os
import re
import subprocess
import tempfile
import unittest
from unittest import mock

from pygithost import application, database
from pygithost.ci import CIManager
from pygithost.settings_pages import BASIC_GROUPS
from tests import test_repository_ui as ui


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

    def config(self):
        return asyncio.run(self.manager.config(self.owner, "project"))

    def token(self, path="/admin/settings"):
        status, page = self.fixture.request(path)
        self.assertEqual(status, 200)
        return re.search(r'name="csrf" value="([^"]+)"', page)[1]

    def save(self, action, *, repository=False, **fields):
        path = self.base + "/ci/preferences" if repository else "/admin/settings"
        return self.fixture.request(path, {"action": action, "csrf": self.token(self.base + "/ci/config" if repository else path), **fields})

    def variables(self, values, *, repository=False):
        fields = {"env_count": str(len(values))}
        for index, (name, value, pipeline) in enumerate(values):
            fields.update({f"env_name_{index}": name, f"env_value_{index}": value, f"env_pipeline_{index}": pipeline})
        return self.save("ci_environment", repository=repository, **fields)

    def test_admin_page_has_real_controls_and_repository_inheritance(self):
        status, page = self.fixture.request("/admin/settings")
        self.assertEqual(status, 200)
        for heading in ("Appearance", "Basic server configuration", "Network", "Security", "Storage and Git", "Runs and artifacts", "Environment variables"):
            self.assertIn(heading, page)
        self.assertIn('<input name="basic_host"', page)
        self.assertNotIn('CI execution defaults', page)
        self.assertNotIn('&lt;select id=&quot;pref-runner', page)
        _, page = self.fixture.request(self.base + "/ci/config")
        self.assertNotIn('name="inherit_timeout_seconds"', page)
        self.assertIn('name="env_name_0"', page)
        self.assertIn('<template><div class="settings-env-row">', page)

    def test_execution_uses_pipeline_json_or_builtins_not_preferences(self):
        from pygithost.ci import default_config
        database.db_ci_preferences_set({"timeout_seconds": 60, "cancel_superseded": True})
        self.assertEqual(self.config()["timeout_seconds"], default_config()["timeout_seconds"])
        self.assertFalse(self.config()["cancel_superseded"])
        _, page = self.fixture.request(self.base + "/ci/config")
        self.assertNotIn('name="execution_json"', page)
        from pygithost.settings_pages import parse_preferences
        with self.assertRaises(ValueError):
            parse_preferences({"action": "ci_execution", "execution_json": "{}"}, {})
        # Pipeline-specific choices remain explicit, rather than shared defaults.
        document = {"version": 1, "pipelines": [{"name": "checks", "execution": {"timeout_seconds": 123}, "steps": [{"name": "Check", "run": "echo test"}]}], "deployments": []}
        self.fixture.request(self.base + "/ci/config", {"configuration_json": json.dumps(document)})
        self.assertEqual(self.config()["timeout_seconds"], 123)

    def test_environment_inheritance_pipeline_scope_and_removing_override(self):
        self.variables([("MODE", "global", ""), ("GLOBAL_ONLY", "inherited", "")])
        self.assertEqual(self.config()["env"], {"MODE": "global", "GLOBAL_ONLY": "inherited"})
        self.variables([("MODE", "repository", ""), ("SCOPED", "one-pipeline", "ci")], repository=True)
        self.assertEqual(self.config()["env"], {"MODE": "repository", "GLOBAL_ONLY": "inherited", "SCOPED": "one-pipeline"})
        self.variables([], repository=True)
        self.assertEqual(self.config()["env"], {"MODE": "global", "GLOBAL_ONLY": "inherited"})
        # Preferences alone do not disable file discovery or create CI settings.
        self.assertIsNone(database.db_ci_config_get(self.owner, "project"))

    def test_editor_hides_legacy_environment_retention_without_losing_values(self):
        document = {"version": 1, "pipelines": [{"name": "ci", "file": ".ci-config.json", "execution": {"env": {"KEEP_ME": "legacy"}}}],
                    "deployments": [], "retention": {"runs": {"max_count": 33}, "artifacts": {"days": 8}}}
        asyncio.run(self.manager.save_document(self.owner, "project", document))
        _, page = self.fixture.request(self.base + "/ci/config")
        from html import unescape
        editor = json.loads(unescape(re.search(r'<textarea id="ci-config-json"[^>]*>(.*?)</textarea>', page, re.S)[1]))
        self.assertNotIn("retention", editor)
        self.assertNotIn("env", editor["pipelines"][0].get("execution", {}))
        self.assertIn('value="KEEP_ME"', page)
        self.assertIn('name="run_retention_count" type="number" value="33"', page)
        self.fixture.request(self.base + "/ci/config", {"configuration_json": json.dumps(editor)})
        config = self.config()
        self.assertEqual(config["env"]["KEEP_ME"], "legacy")
        self.assertEqual(config["run_retention_count"], 33)
        self.variables([], repository=True)
        self.assertEqual(self.config()["env"], {})

    def test_global_retention_applies_to_cleanup_and_repository_can_override(self):
        fields = {"artifact_retention_days": "0", "artifact_retention_count": "1", "run_retention_count": "2", "confirm_retention": "yes"}
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
        self.save("ci_retention", repository=True, artifact_retention_days="0", artifact_retention_count="0", run_retention_count="0", confirm_retention="yes")
        self.assertEqual(self.config()["run_retention_count"], 0)
        self.assertEqual(self.config()["artifact_retention_count"], 0)
        self.save("ci_retention", repository=True, inherit_artifact_retention_days="on", inherit_artifact_retention_count="on", inherit_run_retention_count="on", confirm_retention="yes")
        self.assertEqual(self.config()["run_retention_count"], 2)
        self.assertEqual(self.config()["artifact_retention_count"], 1)

    def test_invalid_forms_csrf_and_admin_permissions_do_not_save(self):
        status, _ = self.fixture.request("/admin/settings", {"action": "ci_environment", "env_count": "0", "csrf": "wrong"})
        self.assertEqual(status, 403)
        _, page = self.variables([("CI", "forbidden", "")])
        self.assertIn("Invalid or reserved environment variable", page)
        self.assertEqual(database.db_ci_preferences_get()[0], {})
        self.assertIn('name="env_name_0" value="CI"', page)
        _, page = self.save("ci_retention", artifact_retention_days="1", artifact_retention_count="1", run_retention_count="1")
        self.assertIn("Confirm applying retention", page)
        self.assertEqual(database.db_ci_preferences_get()[0], {})
        with mock.patch.object(application, "REQUIRE_AUTH", True), mock.patch.object(application, "_require_admin", return_value=False), mock.patch.object(application.GitHTTPHandler, "_require_session_auth", new_callable=mock.AsyncMock, return_value=True):
            for path in ("/admin/settings", self.base + "/ci/config"):
                self.assertEqual(self.fixture.request(path)[0], 403)
            self.assertEqual(self.fixture.request(self.base + "/ci/preferences", {"action": "ci_environment"})[0], 403)

    def basic_fields(self, values):
        fields = {"action": "basic", "confirm_restart": "yes"}
        for keys in BASIC_GROUPS.values():
            for key in keys:
                value = values[key]
                if isinstance(value, bool):
                    if value:
                        fields["basic_" + key] = "yes"
                else:
                    fields["basic_" + key] = "\n".join(value) if isinstance(value, list) else "" if value is None else str(value)
        return fields

    @unittest.skipUnless(os.environ.get("PYGITHOST_TEST_BROWSER"), "set PYGITHOST_TEST_BROWSER to Chromium")
    def test_browser_variable_rows_inheritance_and_retention_forms(self):
        database.db_ci_preferences_set({"env": {"MODE": "server"}, "timeout_seconds": 60, "run_retention_count": 10})
        script = r'''<script>
(async function() {
 const sleep = () => new Promise(resolve => setTimeout(resolve,50));
 const form = action => document.querySelector('input[name="action"][value="'+action+'"]').form;
 async function wait(test) { for(let i=0;i<180;i++){if(test())return;await sleep();} throw Error("Settings controls did not initialize"); }
 async function submit(node) {
  let posted;
  node.addEventListener("submit", event => { event.preventDefault(); posted=fetch(node.getAttribute("action"),{method:"POST",body:new URLSearchParams(new FormData(node))}).then(response=>response.text()); }, {once:true});
  node.requestSubmit();
  if(!posted) throw Error("Page form validation blocked " + node.elements.action.value);
  const html=await posted;
  if(!html.includes("Repository settings saved")) throw Error("Page form did not save " + node.elements.action.value + ": " + (new DOMParser().parseFromString(html,"text/html").querySelector(".warn")?.textContent || "No response message"));
 }
 try {
  const env=form("ci_environment");
   await wait(()=>env.querySelector(".settings-add-env").onclick);
  if(!env.querySelector("template").content.querySelector("input")) throw Error("Variable template is escaped");
  env.elements.env_name_0.value="MODE"; env.elements.env_value_0.value="repository";
  env.querySelector(".settings-show-env").click(); env.querySelector(".settings-add-env").click();
  if(env.elements.env_count.value!=="2" || env.elements.env_value_1.type!=="text") throw Error("Add variable/show values failed");
  env.elements.env_name_1.value="PIPE_ONLY"; env.elements.env_value_1.value="scoped"; env.elements.env_pipeline_1.value="ci";
  await submit(env);
   if(document.querySelector('[name="execution_json"]')) throw Error("Execution defaults form still exists");
  const retention=form("ci_retention");
  if(!retention.elements.run_retention_count.disabled || retention.elements.run_retention_count.value!=="10") throw Error("Global retention not inherited");
  retention.elements.inherit_run_retention_count.click(); retention.elements.run_retention_count.value="3";
  retention.elements.confirm_retention.checked=true; await submit(retention);
  const json=JSON.parse(document.getElementById("ci-config-json").value);
  if("env" in json || "retention" in json) throw Error("Page settings leaked into editor JSON");
  const admin=new DOMParser().parseFromString(await (await fetch("/admin/settings")).text(),"text/html");
  if(!admin.querySelector('[name="basic_port"]') || !admin.querySelector('[name="basic_require_auth"]')) throw Error("Basic server settings are not real form fields");
  document.documentElement.dataset.settingsPagesTest="passed";
 }catch(error){document.documentElement.dataset.settingsPagesTest="failed";document.documentElement.dataset.settingsPagesError=error.message;}
})();</script>'''
        original = application._html_page

        def page(title, body):
            result = original(title, body)
            return result.replace(b"</body>", script.encode() + b"</body>") if title.startswith("CI settings") else result

        with tempfile.TemporaryDirectory(prefix="settings-pages-browser-", dir="/tmp/opencode") as profile:
            with mock.patch.object(application, "_html_page", side_effect=page):
                result = subprocess.run([os.environ["PYGITHOST_TEST_BROWSER"], "--headless", "--no-sandbox", "--disable-gpu",
                    "--no-first-run", "--disable-dev-shm-usage", "--user-data-dir="+profile,
                    "--dump-dom", "--virtual-time-budget=15000",
                    f"http://127.0.0.1:{self.fixture.server.port}{self.base}/ci/config"], capture_output=True,text=True,timeout=60)
        self.assertEqual(result.returncode,0,result.stderr[-2000:])
        error=re.search(r'data-settings-pages-error="([^"]*)"',result.stdout)
        self.assertTrue('data-settings-pages-test="passed"' in result.stdout, error[1] if error else result.stderr[-2000:])
        config=self.config()
        self.assertEqual(config["env"],{"MODE":"repository","PIPE_ONLY":"scoped"})
        from pygithost.ci import default_config
        self.assertEqual(config["timeout_seconds"], default_config()["timeout_seconds"])
        self.assertEqual(config["run_retention_count"],3)

    def test_basic_server_settings_are_atomic_restart_only_and_detect_conflicts(self):
        path = self.fixture.root / "startup.json"
        values = self.fixture.server.app.context.config.to_dict()
        path.write_text(json.dumps({**values, "preserve_unknown": "yes"}))
        self.fixture.server.app.config_path = path
        _, page = self.fixture.request("/admin/settings")
        revision = re.search(r'name="basic_revision" value="([^"]+)"', page)[1]
        fields = self.basic_fields(values)
        fields.update(csrf=self.token(), basic_revision=revision, basic_port="8123", basic_host="127.0.0.1")
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

    @unittest.skipUnless(os.name == "posix" and os.environ.get("PYGITHOST_TEST_DOCKER_IMAGE") == "python:3.14-slim", "requires Docker test image")
    def test_page_environment_reaches_real_docker_and_run_keeps_snapshot(self):
        self.variables([("PAGE_VALUE", "global", "")])
        self.variables([("PAGE_VALUE", "repository", "")], repository=True)
        source = self.fixture.source
        (source / ".ci-config.json").write_text(json.dumps({"version": 1, "steps": [{"name": "Environment", "run": "python -c \"import os; print('page-env=' + os.environ['PAGE_VALUE'])\""}]}))
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
        self.assertEqual(snapshot["env"]["PAGE_VALUE"], "repository")
