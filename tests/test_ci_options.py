"""Per-option tests for the public independent-pipeline JSON schema."""

import copy
import unittest

from pygithost.ci import CIManager
from pygithost.ci_config import compile_document


class ConfigurationOptionTests(unittest.TestCase):
    def document(self):
        return {"version": 1, "pipelines": [{"name": "checks", "steps": [{"name": "Test", "run": "echo test"}]}], "deployments": []}

    def set_value(self, document, path, value):
        target = document
        for key in path[:-1]:
            if isinstance(key, int):
                target = target[key]
            else:
                target = target.setdefault(key, {})
        target[path[-1]] = value

    def test_each_pipeline_option_reaches_the_execution_configuration(self):
        cases = [
            (("execution", "runner"), "docker", "runner", "docker"),
            (("execution", "image"), "python:3.14-slim", "image", "python:3.14-slim"),
            (("execution", "timeout_seconds"), 37, "timeout_seconds", 37),
            (("execution", "env"), {"MODE": "test"}, "env", {"MODE": "test"}),
            (("cancellation", "superseded"), True, "cancel_superseded", True),
            (("triggers", "push", "branches"), ["main", "release/*"], "push_branches", "main\nrelease/*"),
            (("triggers", "pull_request", "branches"), ["develop"], "pr_branches", "develop"),
            (("artifacts", "paths"), ["dist/*"], "artifacts", {"paths": ["dist/*"], "when": "always"}),
            (("notifications", "email", "recipients"), ["ci@example.com"], "email_recipients", "ci@example.com"),
        ]
        for path, value, internal, expected in cases:
            with self.subTest(path=path):
                document = self.document()
                self.set_value(document, ("pipelines", 0, *path), value)
                self.assertEqual(compile_document(document)[internal], expected)
        for trigger in ("push", "manual"):
            for enabled in (True, False):
                document = self.document()
                self.set_value(document, ("pipelines", 0, "triggers", trigger, "enabled"), enabled)
                self.assertEqual(compile_document(document)["events"][trigger], True if trigger == "manual" else enabled)

    def test_each_pr_event_is_selected_individually(self):
        mapping = {"opened": "pr_opened", "updated": "pr_updated", "reopened": "pr_reopened", "merged": "pr_merged"}
        for event, internal in mapping.items():
            for enabled in (True, False):
                with self.subTest(event=event, enabled=enabled):
                    document = self.document()
                    document["pipelines"][0]["triggers"] = {"pull_request": {"enabled": enabled, "events": [event]}}
                    flags = compile_document(document)["events"]
                    self.assertEqual({key for key in mapping.values() if flags[key]}, {internal} if enabled else set())

    def test_each_email_and_artifact_mode(self):
        for mode in ("off", "failures", "all", "recovery"):
            for when in ("always", "success", "failure"):
                with self.subTest(mode=mode, when=when):
                    document = self.document()
                    document["pipelines"][0].update(notifications={"email": {"mode": mode, "recipients": ["ci@example.com"]}},
                                                   artifacts={"paths": [], "when": when})
                    config = compile_document(document)
                    self.assertEqual(config["email_mode"], mode)
                    self.assertEqual(config["artifacts"]["when"], when)

    def test_each_policy_and_retention_option(self):
        cases = [
            (("policies", "require_ci"), True, "require_ci"),
            (("policies", "block_direct_pushes"), True, "block_direct_pushes"),
            (("policies", "protected_branches"), ["main", "release/*"], "protected_branches"),
            (("retention", "artifacts", "days"), 30, "artifact_retention_days"),
            (("retention", "artifacts", "max_count"), 50, "artifact_retention_count"),
            (("retention", "runs", "max_count"), 200, "run_retention_count"),
        ]
        for path, value, internal in cases:
            with self.subTest(path=path):
                document = self.document()
                self.set_value(document, path, value)
                expected = "\n".join(value) if isinstance(value, list) else value
                self.assertEqual(compile_document(document)[internal], expected)

    def test_each_deployment_option_and_independent_email(self):
        document = self.document()
        document["pipelines"][0]["notifications"] = {"email": {"mode": "all", "recipients": ["pipeline@example.com"]}}
        document["deployments"] = [{"name": "production", "pipeline": "checks", "enabled": False,
            "branch": "develop", "script_content": "print('deploy')\n", "run_with": "python", "timeout_seconds": 73,
            "notifications": {"email": {"mode": "failures", "recipients": ["target@example.com"]}}}]
        target = compile_document(document)["deployment_targets"][0]
        expected = {"deployment_name": "production", "deploy_enabled": False, "deploy_branch": "develop",
                    "deploy_script_content": "print('deploy')\n", "deploy_interpreter": "python", "deploy_timeout": 73,
                    "email_mode": "failures", "email_recipients": "target@example.com"}
        for key, value in expected.items():
            self.assertEqual(target[key], value, key)
        document["deployments"][0].pop("script_content")
        document["deployments"][0]["script"] = "/opt/deploy/app.sh"
        document["deployments"][0]["enabled"] = True
        target = compile_document(document)["deployment_targets"][0]
        self.assertEqual(target["deploy_script"], "/opt/deploy/app.sh")
        self.assertTrue(target["deploy_enabled"])

    def test_invalid_pipeline_options_are_rejected(self):
        cases = [
            (("execution", "runner"), "unknown"), (("execution", "image"), "bad image"),
            (("execution", "timeout_seconds"), 0), (("execution", "env"), {"X": 1}),
            (("execution", "env"), {"CI": "override"}), (("cancellation", "superseded"), "true"),
            (("triggers", "push", "enabled"), 1), (("triggers", "manual", "enabled"), "yes"),
            (("triggers", "push", "branches"), "main"), (("triggers", "pull_request", "branches"), [1]),
            (("triggers", "pull_request", "events"), ["invalid"]),
            (("artifacts", "paths"), ["../private"]), (("artifacts", "when"), "invalid"),
            (("notifications", "email", "mode"), "invalid"), (("notifications", "email", "recipients"), "ci@example.com"),
        ]
        for path, value in cases:
            document = self.document()
            self.set_value(document, ("pipelines", 0, *path), value)
            with self.subTest(path=path, value=value), self.assertRaises(ValueError):
                compile_document(document)

    def test_step_and_git_file_options(self):
        document = self.document()
        document["pipelines"][0]["steps"] = [{"name": "Compile", "run": "python -m compileall -q ."}]
        self.assertEqual(compile_document(document)["steps"], document["pipelines"][0]["steps"])
        document["pipelines"][0].pop("steps")
        document["pipelines"][0]["file"] = ".pygithost-ci.json"
        config = compile_document(document)
        self.assertTrue(config["repository_config"])
        self.assertEqual(config["repository_file"], ".pygithost-ci.json")

    def test_changing_one_pipeline_does_not_change_another(self):
        document = self.document()
        other = copy.deepcopy(document["pipelines"][0])
        other["name"] = "other"
        document["pipelines"].append(other)
        before = CIManager.pipelines(compile_document(document))[1]
        document["pipelines"][0].update(execution={"runner": "docker", "env": {"ONLY_FIRST": "1"}},
                                        triggers={"manual": {"enabled": True}})
        self.assertEqual(CIManager.pipelines(compile_document(document))[1], before)
