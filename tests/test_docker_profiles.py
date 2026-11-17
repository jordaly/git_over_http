import json
from pathlib import Path
import tempfile
import unittest

from pygithost.ci import docker_command
from pygithost.ci_config import compile_document
from pygithost.docker_profile import authorize, policy, profile
from pygithost.runner import run_job


class DockerProfileTests(unittest.TestCase):
    def test_defaults_preserve_existing_isolation(self):
        config = profile()
        self.assertEqual(config["network"], "none")
        self.assertTrue(config["read_only"])
        self.assertEqual(config["memory_mb"], 1024)
        command = docker_command("test", "/safe/checkout", "/safe/env", {"image": "python:3.14-slim", "command": "true"})
        for option in ("--memory=1g", "--cpus=1", "--pids-limit=128", "--read-only",
                       "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges"):
            self.assertIn(option, command)
        self.assertNotIn("--privileged", command)

    def test_configuration_roundtrips_through_public_schema(self):
        result = compile_document({"version": 1, "pipelines": [{
            "name": "wine", "execution": {"runner": "remote-docker", "docker": {
                "memory_mb": 2048, "checkout_path": "/source", "read_only": False,
                "mounts": [{"source": "results", "target": "/results"}]}},
            "steps": [{"name": "Test", "run": "true"}]}]})
        self.assertEqual(result["docker"]["memory_mb"], 2048)
        self.assertEqual(result["docker"]["workdir"], "/source")
        self.assertEqual(result["docker"]["mounts"][0]["source"], "results")

    def test_multiple_normalized_pipeline_snapshots_can_be_reloaded(self):
        from pygithost.ci import validate_config
        document = {"version": 1, "pipelines": [
            {"name": name, "execution": {"runner": "remote-docker", "docker": {"memory_mb": memory}},
             "steps": [{"name": "Test", "run": "true"}]}
            for name, memory in (("small", 512), ("large", 2048))]}
        compiled = compile_document(document)
        reloaded = validate_config(json.loads(json.dumps(compiled)))
        self.assertEqual(reloaded["docker"]["memory_mb"], 512)
        self.assertEqual(reloaded["pipelines"][0]["docker"]["memory_mb"], 2048)

    def test_worker_ceiling_cannot_be_raised_by_repository(self):
        for request in ({"cpus": 2}, {"memory_mb": 2048}, {"pids_limit": 129},
                        {"tmpfs_mb": 257}, {"network": "bridge"}, {"user": "root"},
                        {"read_only": False}):
            with self.subTest(request=request), self.assertRaises(ValueError):
                authorize(request)
        with self.assertRaises(ValueError):
            authorize({}, timeout=1801)
        options, _ = authorize({"memory_mb": 2048, "network": "bridge"},
                               {"max_memory_mb": 2048, "networks": ["none", "bridge"]})
        self.assertEqual(options["memory_mb"], 2048)

    def test_invalid_types_paths_and_docker_escape_hatches(self):
        for request in (
            {"cpus": True}, {"cpus": float("nan")}, {"memory_mb": 0}, {"pids_limit": -1},
            {"privileged": True}, {"image_pull": "always"},
            {"network": "host"}, {"network": "container:abc"},
            {"user": "1000:1000"}, {"read_only": "false"},
            {"checkout_path": "/tmp/source"}, {"checkout_path": "/"},
            {"checkout_path": "/source,readonly"}, {"workdir": "/source/../etc"},
            {"tmpfs": [{"target": "/etc", "size_mb": 1}]},
            {"mounts": [{"source": "/var/run/docker.sock", "target": "/socket"}]},
            {"mounts": [{"source": "checkout", "target": "/workspace/subdir"}]},
            {"mounts": [{"source": "secret:sql", "target": "/sql", "read_only": False}]},
        ):
            with self.subTest(request=request), self.assertRaises(ValueError):
                profile(request)

    def test_tmpfs_budget_is_aggregate_and_mounts_must_not_overlap(self):
        request = {"tmpfs": [{"target": "/work", "size_mb": 256}]}
        with self.assertRaises(ValueError):
            authorize(request)
        authorize(request, {"max_tmpfs_mb": 512})
        with self.assertRaises(ValueError):
            profile({"tmpfs": [{"target": "/work", "size_mb": 1},
                              {"target": "/work/nested", "size_mb": 1}]})

    def test_generated_mounts_network_resources_and_nonroot_uid(self):
        with tempfile.TemporaryDirectory() as root:
            command = docker_command("test", root, "/safe/env", {
                "image": "wine-tests", "command": "true", "timeout_seconds": 3600,
                "docker": {"cpus": 2, "memory_mb": 2048, "checkout_path": "/source",
                           "checkout_read_only": True, "network": "ci-sql",
                           "tmpfs": [{"target": "/work", "size_mb": 512}],
                           "mounts": [{"source": "results", "target": "/results"}]},
                "_worker_policy": {"max_cpus": 2, "max_memory_mb": 2048,
                                   "max_tmpfs_mb": 1024, "max_timeout_seconds": 3600,
                                   "networks": ["none", "ci-sql"]}})
            self.assertIn("--network=ci-sql", command)
            self.assertIn("--memory=2g", command)
            self.assertIn(f"type=bind,src={root},dst=/source,readonly", command)
            self.assertIn(f"type=bind,src={root}/.ci-results,dst=/results", command)
            self.assertTrue((Path(root) / ".ci-results").is_dir())
            self.assertIn("/source", command)

    def test_secret_mounts_require_exact_repository_and_trusted_event(self):
        with tempfile.TemporaryDirectory() as root:
            secret = Path(root) / "authorized-test.config"
            secret.write_text("PRIVATE")
            limits = {"secrets": {"sql": {"path": str(secret), "repositories": ["root/project"],
                                        "events": ["manual", "push"]}}}
            request = {"mounts": [{"source": "secret:sql", "target": "/test-config/App.config"}]}
            for repository, event in (("other/project", "manual"), ("root/project", "pull_request"),
                                      ("root/project", "pull_request_updated")):
                with self.assertRaises(ValueError):
                    authorize(request, limits, repository=repository, event=event)
            _, resolved = authorize(request, limits, repository="root/project", event="manual")
            self.assertEqual(resolved["sql"], str(secret))
            alias = Path(root) / "alias.config"
            alias.symlink_to(secret)
            limits["secrets"]["sql"]["path"] = str(alias)
            with self.assertRaises(ValueError):
                authorize(request, limits, repository="root/project", event="manual")

    def test_results_mount_cannot_follow_repository_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / ".ci-results").symlink_to("/etc", target_is_directory=True)
            with self.assertRaises(ValueError):
                docker_command("test", root, "/safe/env", {
                    "image": "python", "command": "true",
                    "docker": {"mounts": [{"source": "results", "target": "/results"}]}})

    def test_invalid_worker_policy_is_rejected(self):
        for raw in ({"privileged": True}, {"networks": ["host"]},
                    {"allow_root": "yes"}, {"max_timeout_seconds": 0},
                    {"secrets": {"sql": {"path": "/private/sql"}}}):
            with self.assertRaises(ValueError):
                policy(raw)

    def test_documented_profiles_policy_and_new_server_smoke_are_valid_and_rendered(self):
        from pygithost.ci_docs import manual_content
        root = Path(__file__).resolve().parents[1]
        def examples(name):
            return [json.loads(part.split("```", 1)[0]) for part in
                    (root / "docs" / name).read_text().split("```json\n")[1:]]
        configuration, limits, mounts, secrets = examples("docker-profiles.md")
        compiled = compile_document(configuration)
        authorize(compiled["docker"], limits, timeout=compiled["timeout_seconds"])
        profile(mounts)
        policy(secrets)
        default_policy, smoke = examples("remote-runner-setup.md")
        compiled_smoke = compile_document(smoke)
        authorize(compiled_smoke["docker"], default_policy, timeout=compiled_smoke["timeout_seconds"])
        for guide, title in (("docker-profiles", "Configurable Docker limits"),
                             ("runner-setup", "Verify the server requirements")):
            rendered = str(manual_content(guide, None, "/r/root/demo"))
            self.assertIn(title, rendered)


class DockerPolicyWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def test_denied_job_reports_failure_without_source_download_or_execution(self):
        class Client:
            calls = []
            def request(self, action, document):
                self.calls.append((action, document))
                return {"accepted": True}
        client = Client()
        job = {"run_id": 42, "attempt": "a" * 64,
               "row": [42, "root", "project", "manual", "main", "b" * 40, "{}"],
               "config": {"runner": "docker", "docker": {"network": "bridge"}, "timeout_seconds": 600}}
        with tempfile.TemporaryDirectory() as root:
            await run_job(client, job, Path(root))
            self.assertFalse(list(Path(root).glob("job-*")))
        self.assertEqual([call[0] for call in client.calls], ["complete"])
        progress = client.calls[0][1]["progress"]
        self.assertEqual(progress["status"], "failed")
        self.assertEqual(progress["phase"], "runner policy")
