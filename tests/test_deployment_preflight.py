import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from pygithost.api.preflight import inspect


class DeploymentPreflightTests(unittest.TestCase):
    def test_missing_and_repository_local_script_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repo"
            repository.mkdir()
            self.assertFalse(inspect({"deploy_script": str(repository / "missing")}, repository)["ok"])
            script = repository / "script"
            script.write_text("#!/bin/sh\nexit 0\n")
            script.chmod(0o700)
            result = inspect({"deploy_script": str(script)}, repository)
            self.assertFalse(result["ok"])
            self.assertFalse(next(c for c in result["checks"] if c["name"] == "script_outside_repository")["ok"])

    def test_inline_interpreter_and_shebang_checks_do_not_run_commands(self):
        with mock.patch("pygithost.api.preflight.shutil.which", return_value=None):
            self.assertFalse(inspect({"deploy_script_content": "#!/missing-runtime\n",
                                      "deploy_interpreter": "direct"}, "/repo")["ok"])
            self.assertFalse(inspect({"deploy_script_content": "print('no execution')",
                                      "deploy_interpreter": "missing-runtime"}, "/repo")["ok"])

    @unittest.skipUnless(os.name == "posix", "POSIX executable permissions")
    def test_readable_script_with_explicit_interpreter_need_not_be_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "helper"
            script.write_text("echo never-executed\n")
            script.chmod(0o600)
            result = inspect({"deploy_script": str(script), "deploy_interpreter": "/bin/sh"},
                             Path(directory) / "repo")
            self.assertTrue(result["ok"], result)
            self.assertFalse(inspect({"deploy_script": str(script)}, Path(directory) / "repo")["ok"])

    def test_advanced_env_shebang_is_reported_conservatively(self):
        with mock.patch("pygithost.api.preflight.shutil.which", return_value="/usr/bin/env"):
            result = inspect({"deploy_script_content": "#!/usr/bin/env -S python -u\n"}, "/repo")
            self.assertFalse(result["ok"])
