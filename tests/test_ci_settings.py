import json
import os
import re
import subprocess
import tempfile
import unittest
from html import unescape
from unittest import mock

from pygithost import application, database
from tests import test_repository_ui as ui


class AutomaticCISettingsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ui.RepositoryUITests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        conn = database._db_connect()
        try:
            conn.execute("DELETE FROM ci_configs")
            conn.commit()
        finally:
            conn.close()

    def test_default_settings_and_manual_missing_file_notice(self):
        status, page = self.fixture.request(self.fixture.base + "/ci/config")
        self.assertEqual(status, 200)
        self.assertNotIn("Automatic repository CI", page)
        self.assertNotIn("Use two arrays", page)
        self.assertIn(".ci-config.json", page)
        self.assertIn('id="ci-config-editor"', page)
        self.assertIn('src="/static/ci-settings.js"', page)
        self.assertIn('name="configuration_json"', page)  # No-JS form still works.
        text = unescape(re.search(r'<textarea id="ci-config-json"[^>]*>(.*?)</textarea>', page, re.S)[1])
        doc = json.loads(text)
        self.assertEqual(doc, {"version": 1, "file": ".ci-config.json"})
        status, page = self.fixture.request(self.fixture.base + "/ci")
        self.assertEqual(status, 200)
        self.assertIn('<option value="ci">ci</option>', page)
        status, page = self.fixture.request(self.fixture.base + "/ci/run", {"pipeline": "ci", "branch": "main"})
        self.assertEqual(status, 200)
        self.assertIn("Add .ci-config.json", page)
        self.assertEqual(database.db_ci_runs_list(application.FLAT_OWNER_UI, "project"), [])
        self.assertIsNone(database.db_ci_config_get(application.FLAT_OWNER_UI, "project"))

    @unittest.skipUnless(os.environ.get("PYGITHOST_TEST_BROWSER"), "set PYGITHOST_TEST_BROWSER to Chromium")
    def test_monaco_settings_edit_format_validation_and_save(self):
        script = r'''<script>
(async function () {
 const el = id => document.getElementById(id);
 const sleep = () => new Promise(resolve => setTimeout(resolve, 50));
 async function wait(test, stage) { for (let i=0;i<180;i++) { if(test()) return; await sleep(); } throw Error("Settings editor timed out (" + stage + "): " + el("ci-editor-status").textContent); }
 try {
  await wait(() => window.monaco && el("ci-config-json").hidden, "loading");
  const model = monaco.editor.getModels().find(m => m.uri.authority === "ci-settings");
  if (!model || model.getLanguageId() !== "json" || !document.querySelector("#ci-config-editor .monaco-editor")) throw Error("JSON Monaco did not mount");
  const reference = JSON.parse(model.getValue());
  const doc = {version:1, pipelines:[{name:"browser-settings", file:reference.file,
    execution:{runner:"docker",timeout_seconds:123}}], deployments:[]};
  model.setValue("{");
  await wait(() => monaco.editor.getModelMarkers({resource:model.uri}).some(marker => marker.severity === monaco.MarkerSeverity.Error), "syntax diagnostics");
  el("ci-settings-form").requestSubmit();
  if (!el("ci-json-status").textContent.includes("Invalid JSON") || model.getValue() !== "{") throw Error("Invalid JSON was not preserved/rejected");
  model.setValue('{"file":".ci-config.json","duplicate":1,"duplicate":2,"large":9007199254740993,"nested":{"empty":[],"text":"a, b: [value]"}}');
  el("ci-format-json").click();
  if ((model.getValue().match(/"duplicate"/g) || []).length !== 2 || !model.getValue().includes("9007199254740993")) throw Error("Formatting changed duplicate keys or numeric literals");
  if (JSON.parse(model.getValue()).nested.text !== "a, b: [value]") throw Error("Formatting damaged a string");
  model.setValue(JSON.stringify(doc));
  el("ci-format-json").click();
  await wait(() => model.getValue().includes("\n"), "formatting");
  if (el("ci-config-json").value !== model.getValue()) throw Error("Submitted textarea did not sync");
  let posted;
  el("ci-settings-form").addEventListener("submit", event => {
   event.preventDefault();
   posted = fetch(event.target.action, {method:"POST", body:new URLSearchParams(new FormData(event.target))}).then(response => response.text());
  });
  el("ci-settings-form").requestSubmit();
  if (!posted || !(await posted).includes("Configuration saved")) throw Error("Settings save failed");
  document.documentElement.dataset.ciSettingsTest = "passed";
 } catch(error) { document.documentElement.dataset.ciSettingsTest = "failed"; document.documentElement.dataset.ciSettingsError = error.message; }
})();</script>'''
        original = application._html_page

        def page(title, body):
            result = original(title, body)
            return result.replace(b"</body>", script.encode() + b"</body>") if title.startswith("CI settings") else result

        with tempfile.TemporaryDirectory(prefix="ci-settings-browser-", dir="/tmp/opencode") as profile:
            with mock.patch.object(application, "_html_page", side_effect=page):
                result = subprocess.run([os.environ["PYGITHOST_TEST_BROWSER"], "--headless", "--no-sandbox", "--disable-gpu",
                    "--no-first-run", "--disable-dev-shm-usage", "--user-data-dir=" + profile,
                    "--dump-dom", "--virtual-time-budget=15000",
                    f"http://127.0.0.1:{self.fixture.server.port}{self.fixture.base}/ci/config"],
                    capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        error = re.search(r'data-ci-settings-error="([^"]*)"', result.stdout)
        self.assertTrue('data-ci-settings-test="passed"' in result.stdout,
                        unescape(error[1]) if error else result.stderr[-2000:])
        saved = json.loads(database.db_ci_config_get(application.FLAT_OWNER_UI, "project"))
        self.assertEqual(saved["pipeline_id"], "browser-settings")
        self.assertEqual(saved["timeout_seconds"], 123)
        self.assertEqual(saved["repository_file"], ".ci-config.json")
