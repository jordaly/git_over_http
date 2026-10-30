import copy
import json
import unittest

from pygithost.ci import CIManager, validate_config
from pygithost.ci_config import EXAMPLE, compile_document, export_document


class JSONConfigurationTests(unittest.TestCase):
    def test_shared_defaults_and_mapping_overrides(self):
        document = copy.deepcopy(EXAMPLE)
        document["defaults"]["env"] = {"SHARED": "yes", "VALUE": "base"}
        document["pipelines"]["tests"].update(env={"VALUE": "override"}, events={"push": False})
        config = compile_document(document)
        pipelines = {item["pipeline_id"]: item for item in CIManager.pipelines(config)}
        self.assertEqual(set(pipelines), {"tests", "compile"})
        self.assertEqual(pipelines["tests"]["env"], {"SHARED": "yes", "VALUE": "override"})
        self.assertFalse(pipelines["tests"]["events"]["push"])
        self.assertTrue(pipelines["tests"]["events"]["manual"])
        self.assertTrue(pipelines["compile"]["events"]["push"])
        self.assertEqual(export_document(config), document)
        self.assertNotIn("document", pipelines["tests"])

    def test_validation_rejects_old_modes_and_unknown_fields(self):
        for document in (
            [], {"pipelines": [{}]}, {"pipelines": {"bad/name": {"steps": [{"name": "x", "run": "echo x"}]}}},
            {"pipelines": {"tests": {"command": "echo old"}}},
            {"pipelines": {"tests": {"steps": []}}},
            {"defaults": {"steps": []}, "pipelines": {}},
            {"defaults": {"events": {"typo": True}}, "pipelines": {}},
            {"settings": {"runner": "docker"}, "pipelines": {}},
            {"pipelines": {"tests": {"steps": [{"name": "x", "run": "echo x"}], "require_ci": True}}},
            {"version": True, "pipelines": {}},
        ):
            with self.subTest(document=document), self.assertRaises(ValueError):
                compile_document(document)

    def test_deployment_and_repository_policy(self):
        config = compile_document({"settings": {"require_ci": True, "run_retention_count": 0},
            "pipelines": {"release": {"steps": [{"name": "Tests", "run": "echo test"}],
                "deployment": {"branch": "main", "script_content": "print('deploy')", "run_with": "python"}}}})
        self.assertTrue(config["require_ci"])
        self.assertEqual(config["run_retention_count"], 0)
        child = CIManager.pipelines(config)[0]
        self.assertTrue(child["deploy_enabled"])
        self.assertEqual(child["deploy_interpreter"], "python")
        self.assertEqual(CIManager.pipelines(compile_document({"pipelines": {}})), [])

    def test_legacy_configuration_converts_without_changing_execution(self):
        legacy = validate_config({"command": "echo legacy", "events": {"push": True},
            "require_ci": True, "deploy_enabled": True, "deploy_script": "/opt/deploy/app.sh",
            "pipelines": [{"pipeline_id": "lint", "repository_config": True, "repository_file": "lint.json"}]})
        document = export_document(legacy)
        converted = compile_document(document)
        self.assertEqual(converted["steps"], [{"name": "Run", "run": "echo legacy"}])
        self.assertTrue(converted["require_ci"])
        self.assertEqual(converted["deploy_script"], legacy["deploy_script"])
        self.assertTrue(converted["pipelines"][0]["repository_config"])
        self.assertEqual(export_document(converted), document)

    def test_migration_never_enables_disabled_deployment(self):
        config = validate_config({"command": "echo test", "events": {"push": True},
            "deploy_script": "/opt/deploy/app.sh", "deploy_enabled": False})
        document = export_document(config)
        self.assertFalse(document["pipelines"]["default"]["deployment"]["enabled"])
        self.assertFalse(compile_document(document)["deploy_enabled"])

    def test_sixteen_pipelines_need_no_special_default(self):
        config = compile_document({"pipelines": {
            f"job-{index}": {"steps": [{"name": "Test", "run": "echo test"}]}
            for index in range(16)}})
        self.assertEqual(len(CIManager.pipelines(config)), 16)

    def test_branch_filters_are_string_arrays(self):
        document = copy.deepcopy(EXAMPLE)
        document["defaults"]["push_branches"] = ["main", "release/*"]
        document["pipelines"]["tests"]["pr_branches"] = ["main"]
        document["pipelines"]["compile"]["push_branches"] = []
        config = compile_document(document)
        items = {item["pipeline_id"]: item for item in CIManager.pipelines(config)}
        self.assertEqual(items["tests"]["push_branches"], "main\nrelease/*")
        self.assertEqual(items["tests"]["pr_branches"], "main")
        self.assertEqual(items["compile"]["push_branches"], "")
        self.assertTrue(CIManager._matches(items["tests"]["push_branches"], "release/1"))
        self.assertFalse(CIManager._matches(items["tests"]["push_branches"], "feature"))
        self.assertEqual(export_document(config), document)
        for value in ("main", None, [1], [""], ["main\nother"], ["main\rother"]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                compile_document({"defaults": {"push_branches": value}, "pipelines": {}})
        with self.assertRaises(ValueError):
            compile_document({"pipelines": {"test": {"steps": [{"name": "x", "run": "echo x"}], "pr_branches": "main"}}})

    def test_existing_branch_strings_are_exported_as_arrays(self):
        legacy = validate_config({"command": "echo test", "push_branches": "main\nrelease/*"})
        document = export_document(legacy)
        self.assertEqual(document["pipelines"]["default"]["push_branches"], ["main", "release/*"])
        self.assertEqual(compile_document(document)["push_branches"], "main\nrelease/*")
        saved = {"document": {"defaults": {"push_branches": "main"}, "pipelines": {
            "test": {"steps": [{"name": "x", "run": "echo x"}], "pr_branches": "main"}}}}
        converted = export_document(saved)
        self.assertEqual(converted["defaults"]["push_branches"], ["main"])
        self.assertEqual(converted["pipelines"]["test"]["pr_branches"], ["main"])
        compile_document(converted)

    def test_other_multivalue_fields_use_string_arrays(self):
        document = copy.deepcopy(EXAMPLE)
        document["defaults"].update(email_mode="failures", email_recipients=["ci@example.com", "ops@example.com"])
        document["settings"] = {"block_direct_pushes": True, "protected_branches": ["main", "release/*"]}
        config = compile_document(document)
        self.assertEqual(config["protected_branches"], "main\nrelease/*")
        self.assertEqual(config["email_recipients"], "ci@example.com\nops@example.com")
        self.assertEqual(export_document(config), document)
        for key in ("protected_branches", "email_recipients"):
            for value in ("main", [1], [""], ["main\nrelease/*"]):
                invalid = copy.deepcopy(document)
                invalid["settings" if key == "protected_branches" else "defaults"][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    compile_document(invalid)
        document["defaults"]["email_recipients"] = ["ci@example.com,ops@example.com"]
        with self.assertRaises(ValueError):
            compile_document(document)

    def test_legacy_multivalue_strings_migrate_to_arrays(self):
        legacy = validate_config({"command": "echo test", "protected_branches": "main\nrelease/*",
            "email_recipients": "ci@example.com,ops@example.com", "email_mode": "all"})
        document = export_document(legacy)
        self.assertEqual(document["settings"]["protected_branches"], ["main", "release/*"])
        self.assertEqual(document["pipelines"]["default"]["email_recipients"], ["ci@example.com", "ops@example.com"])
        compile_document(document)

    def test_examples_in_docs_validate(self):
        import re
        from pathlib import Path
        for path in ("docs/pipeline-examples.md", "docs/pipelines.md", "docs/ci-migration.md"):
            for block in re.findall(r"```json\n(.*?)\n```", Path(path).read_text(), re.S):
                with self.subTest(path=path):
                    compile_document(json.loads(block))

    def test_downloadable_examples_validate_and_cover_every_option(self):
        from pathlib import Path
        from pygithost.ci import default_config, pipeline_config
        from pygithost.ci_config import COMMON, DEPLOYMENT, SETTINGS
        from pygithost.ci_schema import flatten_document, is_grouped, split_named_document

        seen_common, seen_settings, seen_deployment, seen_pipeline = set(), set(), set(), set()
        for path in sorted(Path("docs/examples/ci").glob("*.json")):
            raw = json.loads(path.read_text())
            with self.subTest(path=path):
                if path.name == "repository-pipeline.json":
                    pipeline_config(raw, default_config())
                    continue
                compile_document(raw)
                if isinstance(raw.get("pipelines"), list):
                    raw, targets = split_named_document(raw)
                    for target in targets.values():
                        seen_deployment.update(set(target) & set(DEPLOYMENT))
                    if targets:
                        seen_pipeline.add("deployment")
                if is_grouped(raw):
                    raw = flatten_document(raw)
                seen_common.update(set(raw.get("defaults", {})) & COMMON)
                seen_settings.update(raw.get("settings", {}))
                for pipeline in raw["pipelines"].values():
                    seen_common.update(set(pipeline) & COMMON)
                    seen_pipeline.update(pipeline)
                    seen_deployment.update(pipeline.get("deployment", {}))
        self.assertEqual(seen_common, COMMON)
        self.assertEqual(seen_settings, SETTINGS)
        self.assertEqual(seen_deployment, set(DEPLOYMENT))
        self.assertTrue({"steps", "deployment", "file"} <= seen_pipeline)

        # The page renders this same reference, so coverage checks both surfaces.
        reference = Path("docs/ci-options.md").read_text()
        fields = {"runner", "image", "timeout_seconds", "env", "steps", "name", "run", "file"} | set(DEPLOYMENT)
        fields |= {"push.enabled", "push.branches", "pull_request.enabled", "pull_request.branches", "pull_request.events", "manual.enabled", "cancellation.superseded"}
        fields |= {"artifacts.paths", "artifacts.when", "notifications.email.mode", "notifications.email.recipients"}
        fields |= {"policies.require_ci", "policies.block_direct_pushes", "policies.protected_branches", "retention.artifacts.days", "retention.artifacts.max_count", "retention.runs.max_count"}
        for field in fields:
            self.assertIn(f"`{field}`", reference)
