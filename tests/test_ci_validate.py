import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from pygithost.cli import main
from pygithost.repository_ci import (
    ConfigurationInspection,
    inspect_configuration,
    inspect_working_configuration,
    read_working_document,
)


class RepositoryCIValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ci-validate-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repository"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "ci@example.invalid")
        self.git("config", "user.name", "CI tests")
        self.bare = str(self.repo / ".git")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args]).decode().strip()

    def write(self, files):
        for name, content in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def commit(self, files=None):
        self.write(files or {"README.md": "No CI configured."})
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", "CI fixture")
        return self.git("rev-parse", "HEAD")

    def document(self, *, child=None, policies=None):
        pipeline = {
            "name": "tests",
            "execution": {"runner": "docker"},
            "triggers": {"push": {"enabled": True}},
        }
        if child is None:
            pipeline["steps"] = [{"name": "Tests", "run": "echo repository"}]
        else:
            pipeline["file"] = child
        document = {"version": 1, "pipelines": [pipeline], "deployments": []}
        if policies is not None:
            document["policies"] = policies
        return json.dumps(document)

    def run_cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                main(["ci", "validate", *args])
        return raised.exception.code, stdout.getvalue(), stderr.getvalue()

    def test_valid_repository_configuration_is_inspected_once(self):
        commit = self.commit({"ci/config.json": self.document()})
        result = inspect_configuration(self.bare)
        self.assertIsInstance(result, ConfigurationInspection)
        self.assertEqual(result.commit, commit)
        self.assertEqual(result.document["version"], 1)
        self.assertEqual(result.config["steps"][0]["run"], "echo repository")
        self.assertIsNone(result.error)

    def test_missing_configuration_is_distinct_from_invalid(self):
        commit = self.commit()
        result = inspect_configuration(self.bare)
        self.assertEqual(result.commit, commit)
        self.assertIsNone(result.document)
        self.assertIsNone(result.config)
        self.assertIsNone(result.error)

    def test_unborn_head_and_unknown_revision_are_unavailable(self):
        empty = Path(self.temp.name) / "empty.git"
        subprocess.check_call(["git", "init", "-q", "--bare", str(empty)])
        for revision in ("HEAD", "refs/heads/main"):
            with self.subTest(revision=revision):
                result = inspect_configuration(str(empty), revision)
                self.assertEqual(result, ConfigurationInspection(None, None, None, None))
                self.assertFalse(result.git_error)

        self.commit({"ci/config.json": self.document()})
        for revision in ("refs/heads/missing", "not-a-supported-revision"):
            with self.subTest(revision=revision):
                result = inspect_configuration(self.bare, revision)
                self.assertIsNone(result.commit)
                self.assertIsNone(result.config)
                self.assertIsNone(result.error)
                self.assertFalse(result.git_error)

    def test_git_read_failures_are_distinct_from_verified_unborn(self):
        missing = inspect_configuration(str(Path(self.temp.name) / "missing.git"))
        self.assertIsNone(missing.commit)
        self.assertTrue(missing.git_error)

        empty = Path(self.temp.name) / "empty.git"
        subprocess.check_call(["git", "init", "-q", "--bare", str(empty)])
        self.assertFalse(inspect_configuration(str(empty)).git_error)

        self.commit({"ci/config.json": self.document()})
        with mock.patch(
            "pygithost.repository_ci.subprocess.run", side_effect=OSError("git unavailable")
        ):
            failed = inspect_configuration(self.bare)
        self.assertIsNone(failed.commit)
        self.assertTrue(failed.git_error)

    def test_git_failure_reading_root_config_preserves_resolved_commit(self):
        commit = self.commit({"ci/config.json": self.document()})
        run = subprocess.run

        def fail_tree_read(args, **kwargs):
            if "ls-tree" in args:
                return subprocess.CompletedProcess(args, 128, b"", b"private Git error")
            return run(args, **kwargs)

        with mock.patch("pygithost.repository_ci.subprocess.run", side_effect=fail_tree_read):
            failed = inspect_configuration(self.bare)
        self.assertEqual(failed.commit, commit)
        self.assertTrue(failed.git_error)
        self.assertNotIn("private Git error", failed.error)

    def test_invalid_root_configuration_has_safe_error(self):
        commit = self.commit(
            {"ci/config.json": '{"version":1,"steps":[{"name":"Tests","run":"INVALID_SECRET"'}
        )
        result = inspect_configuration(self.bare)
        self.assertEqual(result.commit, commit)
        self.assertIsNone(result.config)
        self.assertIn("invalid", result.error.lower())
        self.assertIn("line 1 column", result.error)
        self.assertNotIn("INVALID_SECRET", result.error)

    def test_invalid_schema_has_safe_error_without_repository_values(self):
        raw = json.dumps(
            {
                "version": 1,
                "pipelines": {
                    "tests": {
                        "steps": [{"name": "Tests", "run": "echo SCHEMA_SECRET"}],
                        "unsupported_SECRET_field": True,
                    }
                },
            }
        )
        commit = self.commit({"ci/config.json": raw})
        result = inspect_configuration(self.bare)
        self.assertEqual(result.commit, commit)
        self.assertIsNotNone(result.document)
        self.assertIsNone(result.config)
        self.assertIn("schema", result.error)
        self.assertNotIn("SCHEMA_SECRET", result.error)

    def test_referenced_pipeline_files_are_validated_too(self):
        child = {"version": 1, "steps": [{"name": "Tests", "run": "echo child"}]}
        commit = self.commit(
            {
                "ci/config.json": self.document(child="ci/pipelines/tests.json"),
                "ci/pipelines/tests.json": json.dumps(child),
            }
        )
        result = inspect_configuration(self.bare)
        self.assertEqual(result.commit, commit)
        self.assertIsNotNone(result.config)
        self.assertIsNone(result.error)

    def test_missing_child_keeps_parsed_root_policy_and_reports_error(self):
        policies = {
            "require_ci": True,
            "block_direct_pushes": True,
            "protected_branches": ["release/*"],
        }
        commit = self.commit(
            {"ci/config.json": self.document(child="ci/pipelines/missing.json", policies=policies)}
        )
        result = inspect_configuration(self.bare)
        self.assertEqual(result.commit, commit)
        self.assertIsNotNone(result.document)
        self.assertIsNotNone(result.config)
        self.assertIn("missing", result.error)
        self.assertIn("'tests'", result.error)
        self.assertIn("'ci/pipelines/missing.json'", result.error)
        self.assertTrue(result.config["block_direct_pushes"])
        self.assertEqual(result.config["protected_branches"], "release/*")

    def test_malformed_child_keeps_parsed_root_configuration(self):
        commit = self.commit(
            {
                "ci/config.json": self.document(child="ci/pipelines/tests.json"),
                "ci/pipelines/tests.json": '{"version":1,\n"steps":[{"run":"CHILD_SECRET"',
            }
        )
        result = inspect_configuration(self.bare)
        self.assertEqual(result.commit, commit)
        self.assertIsNotNone(result.config)
        self.assertIn("'tests'", result.error)
        self.assertIn("'ci/pipelines/tests.json'", result.error)
        self.assertIn("line 2 column", result.error)
        self.assertNotIn("CHILD_SECRET", result.error)

    def test_child_must_match_pipeline_schema_and_timeout(self):
        invalid_children = (
            {"version": 1, "steps": [{"name": "", "run": "echo child"}]},
            {"version": 1, "timeout_seconds": 601, "steps": []},
            {"version": 1, "file": "ci/other.json"},
            {"version": 2, "steps": [{"name": "Tests", "run": "echo child"}]},
        )
        for child in invalid_children:
            with self.subTest(child=child):
                self.commit(
                    {
                        "ci/config.json": self.document(child="ci/pipelines/tests.json"),
                        "ci/pipelines/tests.json": json.dumps(child),
                    }
                )
                result = inspect_configuration(self.bare)
                self.assertIsNotNone(result.config)
                self.assertIn("'tests'", result.error)
                self.assertIn("'ci/pipelines/tests.json'", result.error)
                self.assertIn("schema", result.error)

    def test_duplicate_keys_in_child_are_rejected_by_the_shared_parser(self):
        self.commit(
            {
                "ci/config.json": self.document(child="ci/pipelines/tests.json"),
                "ci/pipelines/tests.json": '{"version":1,"steps":[],"steps":[]}',
            }
        )
        result = inspect_configuration(self.bare)
        self.assertIsNotNone(result.config)
        self.assertIn("duplicate JSON key", result.error)
        self.assertIn("'ci/pipelines/tests.json'", result.error)

    def test_secondaries_must_be_regular_files_inside_ci(self):
        for filename in ("README.md", "ci/dir", "ci/../README.md", "ci/config.json"):
            with self.subTest(filename=filename):
                document = self.document(child=filename)
                self.commit(
                    {
                        "ci/config.json": document,
                        "README.md": "outside",
                        "ci/dir/placeholder": "directory",
                    }
                )
                result = inspect_configuration(self.bare)
                self.assertIsNotNone(result.error)

    def test_working_tree_configuration_includes_uncommitted_changes(self):
        self.commit()
        self.write({"ci/config.json": self.document()})
        result = inspect_working_configuration(self.repo)
        self.assertIsNone(result.commit)
        self.assertIsNotNone(result.document)
        self.assertIsNotNone(result.config)
        self.assertIsNone(result.error)

        self.write({"ci/config.json": '{"version":1,"steps":['})
        result = inspect_working_configuration(self.repo)
        self.assertIsNotNone(result.error)
        self.assertIsNone(result.config)

    def test_working_tree_child_is_validated_and_symlinks_are_rejected(self):
        self.commit()
        self.write(
            {
                "ci/config.json": self.document(child="ci/pipelines/tests.json"),
                "ci/pipelines/tests.json": json.dumps(
                    {"version": 1, "steps": [{"name": "Tests", "run": "echo child"}]}
                ),
            }
        )
        result = inspect_working_configuration(self.repo)
        self.assertIsNotNone(result.config)
        self.assertIsNone(result.error)

        child = self.repo / "ci" / "pipelines" / "tests.json"
        child.unlink()
        try:
            child.symlink_to("../../README.md")
        except OSError:
            self.skipTest("Symlinks are unavailable.")
        result = inspect_working_configuration(self.repo)
        self.assertIsNotNone(result.config)
        self.assertIn("regular file", result.error)
        self.assertIn("'ci/pipelines/tests.json'", result.error)

    def test_working_tree_reader_rejects_directories_and_outside_paths(self):
        (self.repo / "ci" / "config.json").mkdir(parents=True)
        with self.assertRaises(ValueError):
            read_working_document(self.repo)
        with self.assertRaises(ValueError):
            read_working_document(self.repo, "../README.md")

    def test_cli_validates_the_working_tree_by_default(self):
        commit = self.commit()
        self.write({"ci/config.json": self.document()})
        code, out, err = self.run_cli("--repository", str(self.repo))
        self.assertEqual(code, 0)
        self.assertIn("valid in the working tree", out)
        self.assertEqual(err, "")
        # The default must not silently switch to the (missing) committed file.
        self.assertIsNone(inspect_configuration(self.bare).config)
        self.assertEqual(len(commit), 40)

        subdirectory = self.repo / "src"
        subdirectory.mkdir()
        code, out, err = self.run_cli("--repository", str(subdirectory))
        self.assertEqual(code, 0)
        self.assertIn("valid in the working tree", out)
        self.assertEqual(err, "")

    def test_cli_revision_mode_validates_committed_configuration(self):
        self.commit({"ci/config.json": self.document()})
        self.write({"ci/config.json": '{"version":1,"steps":['})
        code, out, err = self.run_cli("--repository", str(self.repo), "--rev", "HEAD")
        self.assertEqual(code, 0)
        self.assertIn("valid at HEAD", out)
        self.assertEqual(err, "")

        code, _out, err = self.run_cli(
            "--repository", str(self.repo), "--rev", "refs/heads/missing"
        )
        self.assertEqual(code, 1)
        self.assertIn("Cannot resolve revision", err)

    def test_cli_bare_repository_defaults_to_committed_head(self):
        self.commit({"ci/config.json": self.document()})
        code, out, err = self.run_cli("--repository", self.bare)
        self.assertEqual(code, 0)
        self.assertIn("valid at HEAD", out)
        self.assertEqual(err, "")

    def test_cli_exits_nonzero_for_missing_and_invalid_configuration(self):
        self.commit()
        code, _out, err = self.run_cli("--repository", str(self.repo))
        self.assertEqual(code, 1)
        self.assertIn("No ci/config.json", err)

        self.write({"ci/config.json": '{"version":1,"steps":['})
        code, _out, err = self.run_cli("--repository", str(self.repo))
        self.assertEqual(code, 1)
        self.assertIn("invalid", err)

    def test_cli_never_executes_configured_steps(self):
        marker = self.repo / "executed"
        self.write(
            {
                "ci/config.json": json.dumps(
                    {
                        "version": 1,
                        "steps": [{"name": "Must not run", "run": f"touch {marker}"}],
                    }
                )
            }
        )
        code, _out, _err = self.run_cli("--repository", str(self.repo))
        self.assertEqual(code, 0)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
