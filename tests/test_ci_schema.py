import unittest

from pygithost.ci import CIManager
from pygithost.ci_config import compile_document, editor_document
from pygithost.ci_schema import group_document


class GroupedConfigurationTests(unittest.TestCase):
    def example(self):
        return {"version": 1,
            "defaults": {
                "execution": {"runner": "docker", "image": "python:3.14-slim", "timeout_seconds": 600,
                              "env": {"COMMON": "yes", "MODE": "development"}},
                "triggers": {"push": {"enabled": True, "branches": ["main", "develop"]},
                             "pull_request": {"enabled": True, "branches": ["main"]},
                             "manual": {"enabled": True}},
                "cancellation": {"superseded": True}},
            "pipelines": {
                "checks": {"steps": [{"name": "Tests", "run": "echo tests"}]},
                "release": {"execution": {"env": {"MODE": "production"}},
                            "triggers": {"push": {"branches": ["main"]}, "pull_request": {"enabled": False}},
                            "steps": [{"name": "Build", "run": "echo build"}]}},
            "notifications": {"email": {"mode": "off", "recipients": ["ci@example.com"]}},
            "policies": {"require_ci": True, "protected_branches": ["main"]},
            "retention": {"artifacts": {"days": 30, "max_count": 50}, "runs": {"max_count": 100}}}

    def test_grouped_fields_and_inheritance(self):
        raw = self.example()
        config = compile_document(raw)
        items = {item["pipeline_id"]: item for item in CIManager.pipelines(config)}
        self.assertTrue(config["require_ci"])
        self.assertEqual(config["artifact_retention_days"], 30)
        self.assertEqual(items["release"]["env"], {"COMMON": "yes", "MODE": "production"})
        self.assertEqual(items["release"]["push_branches"], "main")
        self.assertTrue(items["release"]["events"]["push"])
        self.assertFalse(items["release"]["events"]["pr_opened"])
        self.assertTrue(items["checks"]["events"]["pr_updated"])
        self.assertFalse(items["checks"]["events"]["pr_merged"])
        migrated = editor_document(config)
        self.assertIsInstance(migrated["pipelines"], list)
        self.assertNotIn("defaults", migrated)
        after = compile_document(migrated)
        self.assertEqual(CIManager.pipelines(after), CIManager.pipelines(config))

    def test_named_lists_are_independent_and_have_explicit_names(self):
        document = {"pipelines": [
            {"name": "first", "execution": {"runner": "docker", "env": {"ONLY_FIRST": "yes"}},
             "triggers": {"manual": {"enabled": True}}, "steps": [{"name": "First", "run": "echo first"}],
             "notifications": {"email": {"mode": "all", "recipients": ["first@example.com"]}}},
            {"name": "second", "steps": [{"name": "Second", "run": "echo second"}]}
        ], "deployments": [
            {"name": "staging", "pipeline": "first", "enabled": False, "script": "/opt/staging.sh"},
            {"name": "production", "pipeline": "first", "enabled": False, "script": "/opt/production.sh"}]}
        config = compile_document(document)
        first, second = CIManager.pipelines(config)
        self.assertEqual(first["runner"], "docker")
        self.assertEqual(second["runner"], "host")
        self.assertEqual(second["env"], {})
        self.assertFalse(second["events"]["manual"])
        self.assertEqual(second["email_mode"], "off")
        self.assertEqual(len(first["deployment_targets"]), 2)
        self.assertTrue(all(target["email_mode"] == "off" for target in first["deployment_targets"]))
        self.assertEqual(editor_document(config), document)
        for invalid in (
            {"defaults": {}, **document}, {"notifications": {}, **document},
            {"pipelines": [{"steps": [{"name": "x", "run": "echo x"}]}]},
            {"pipelines": [document["pipelines"][0], document["pipelines"][0]]},
            {"pipelines": document["pipelines"], "deployments": [{"name": "x", "pipeline": "missing"}]},
            {"pipelines": document["pipelines"], "deployments": [{"pipeline": "first"}]},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                compile_document(invalid)

    def test_merged_event_is_explicit_and_notifications_can_override(self):
        raw = self.example()
        raw["pipelines"]["release"]["triggers"]["pull_request"] = {"enabled": True, "events": ["merged"]}
        raw["pipelines"]["release"]["notifications"] = {"email": {"mode": "all"}}
        config = compile_document(raw)
        release = CIManager.pipelines(config)[1]
        self.assertTrue(release["events"]["pr_merged"])
        self.assertFalse(release["events"]["pr_opened"])
        self.assertEqual(release["email_mode"], "all")
        self.assertEqual(release["email_recipients"], "ci@example.com")

    def test_unimplemented_features_and_malformed_values_fail_explicitly(self):
        for group, value in (
            ("execution", {"working_directory": "."}),
            ("cancellation", {"superseded": "yes"}),
            ("triggers", {"manual": {"enabled": "yes"}}),
            ("triggers", {"pull_request": {"enabled": True, "events": ["typo"]}}),
            ("execution", {"retry": {"attempts": 2}}),
            ("artifacts", {"paths": [], "retention_days": 7}),
            ("steps", [{"name": "Tests", "run": "echo x", "continue_on_error": True}]),
            ("deployment", {"approval": {"required": True}}),
        ):
            raw = self.example()
            raw["pipelines"]["checks"][group] = value
            with self.subTest(group=group, value=value), self.assertRaises(ValueError):
                compile_document(raw)
        raw = self.example()
        raw["retention"]["deployments"] = {"max_count": 100}
        with self.assertRaises(ValueError):
            compile_document(raw)

    def test_old_partial_pr_overrides_migrate_without_changing_behavior(self):
        raw = {"defaults": {"events": {"pr_opened": True, "pr_updated": True, "manual": True}},
               "pipelines": {"checks": {"events": {"pr_updated": False},
                            "steps": [{"name": "Tests", "run": "echo x"}]}}}
        before = compile_document(raw)
        grouped = group_document(raw)
        after = compile_document(grouped)
        for key in ("events", "steps", "runner", "env"):
            self.assertEqual(before[key], after[key])
        self.assertEqual(group_document(grouped), grouped)
