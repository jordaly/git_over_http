"""REST equivalents of web-only actions: delete repo, multi-file commit, CI variables,
conflict resolution and CI notification retry."""

import base64
import shutil
import unittest
from pathlib import Path

from pygithost import database
from tests import test_api_writes as writes
from tests.ci_fixtures import commit_file
from tests.test_server import _which_git_backend


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


@unittest.skipUnless(shutil.which("git") and _which_git_backend(), "requires Git HTTP backend")
class RepositoryOperationTests(unittest.TestCase):
    git = writes.APIWriteTests.git
    user = writes.APIWriteTests.user
    request = writes.APIWriteTests.request
    mutate = writes.APIWriteTests.mutate
    tearDown = writes.APIWriteTests.tearDown
    setUp = writes.APIWriteTests.setUp
    save_config = writes.APIWriteTests.save_config

    def head(self, branch="main"):
        return self.git("--git-dir", self.bare, "rev-parse", "refs/heads/" + branch)

    # ---------------------------------------------------------------- commits
    def test_multi_file_commit_matches_web_ide(self):
        path = self.base + "/commits"
        doc = {
            "branch": "feature/api",
            "expected_head": self.head("feature/api"),
            "message": "Edit two files",
            "changes": {"README.md": b64("Changed\n"), "src/new.py": b64("print(1)\n")},
        }
        status, _h, result = self.mutate(path, doc)
        self.assertEqual(status, 201, result)
        sha = result["commit"]["sha"]
        self.assertEqual(self.head("feature/api"), sha)
        self.assertEqual(self.git("--git-dir", self.bare, "show", f"{sha}:src/new.py"), "print(1)")
        # Stale base, delete, invalid content.
        self.assertEqual(self.mutate(path, doc)[0], 409)
        delete = {**doc, "expected_head": sha, "changes": {"src/new.py": None}}
        status, _h, result = self.mutate(path, delete)
        self.assertEqual(status, 201, result)
        self.assertNotIn(
            "src/new.py",
            self.git(
                "--git-dir", self.bare, "ls-tree", "-r", "--name-only", self.head("feature/api")
            ),
        )
        bad = {**doc, "expected_head": self.head("feature/api"), "changes": {"x": "%%%"}}
        self.assertEqual(self.mutate(path, bad)[0], 422)
        self.assertEqual(self.mutate(path, {**doc, "changes": {}})[0], 422)

    def test_commit_respects_protected_branches_and_read_only_tokens(self):
        self.save_config({"command": "true", "block_direct_pushes": True})
        doc = {
            "branch": "main",
            "expected_head": self.head(),
            "message": "Direct",
            "changes": {"README.md": b64("x\n")},
        }
        status, _h, result = self.mutate(self.base + "/commits", doc)
        self.assertEqual((status, result["code"]), (403, "protected_branch"))
        status, _h, _r = self.mutate(self.base + "/commits", doc, token=self.token)
        self.assertEqual(status, 403)

    # ---------------------------------------------------------------- CI variables
    def test_ci_variables_round_trip_and_validation(self):
        path = self.base + "/ci/variables"
        self.assertEqual(self.request(path, token=self.write_token)[0], 403)
        doc = {
            "variables": [
                {"name": "MODE", "value": "fast"},
                {"name": "TOKEN", "value": "s3cret", "scope": "protected"},
                {"name": "ONLY", "value": "1", "pipeline": "checks", "scope": "deployment"},
            ]
        }
        status, _h, result = self.mutate(path, doc, method="PUT", token=self.admin_write_token)
        self.assertEqual(status, 200, result)
        by_name = {v["name"]: v for v in result["variables"]}
        self.assertEqual(by_name["MODE"]["scope"], "ordinary")
        self.assertEqual(by_name["TOKEN"]["scope"], "protected")
        self.assertEqual(by_name["ONLY"]["pipeline"], "checks")
        status, _h, read = self.request(path, token=self.admin_write_token)
        self.assertEqual((status, read), (200, result))
        dup = {"variables": [{"name": "A", "value": "1"}, {"name": "A", "value": "2"}]}
        status, _h, error = self.mutate(path, dup, method="PUT", token=self.admin_write_token)
        self.assertEqual(status, 422, error)
        bad_scope = {"variables": [{"name": "A", "value": "1", "scope": "everyone"}]}
        self.assertEqual(
            self.mutate(path, bad_scope, method="PUT", token=self.admin_write_token)[0], 422
        )
        self.assertEqual(self.mutate(path, doc, method="PUT")[0], 403)

    # ---------------------------------------------------------------- repository delete
    def test_repository_delete_requires_admin_and_confirmation(self):
        path = self.base
        database.db_ci_run_update(self.run, status="success")
        self.assertEqual(self.mutate(path, {"confirm": "alice/project"}, method="DELETE")[0], 403)
        status, _h, result = self.mutate(
            path, {"confirm": "alice/other"}, method="DELETE", token=self.admin_write_token
        )
        self.assertEqual(status, 422, result)
        delete = {"confirm": "alice/project"}
        options = {
            "method": "DELETE",
            "token": self.admin_write_token,
            "key": "archive-project",
        }
        status, _h, result = self.mutate(path, delete, **options)
        self.assertEqual(status, 200, result)
        self.assertTrue(result["deleted"])
        self.assertFalse(self.bare.exists())
        self.assertTrue((Path(result["archive"]) / "manifest.json").exists())
        self.assertEqual(self.request(path, token=self.admin_token)[0], 404)
        status, headers, replay = self.mutate(path, delete, **options)
        self.assertEqual((status, replay), (200, result))
        self.assertEqual(headers["X-Idempotent-Replay"], "true")

    # ---------------------------------------------------------------- conflicts
    def test_conflicts_listed_and_resolved_like_the_web_page(self):
        base_sha = self.head()
        commit_file(self.bare, "README.md", "main side\n", branch="main")
        self.git("--git-dir", self.bare, "update-ref", "refs/heads/feature/api", base_sha)
        commit_file(self.bare, "README.md", "feature side\n", branch="feature/api")
        pull = database.db_pr_create(
            "alice", "project", "Conflicting", "", "feature/api", "main", self.alice
        )
        path = self.base + f"/pulls/{pull}/conflicts"
        status, _h, listing = self.request(path, token=self.write_token)
        self.assertEqual(status, 200, listing)
        self.assertEqual([f["path"] for f in listing["files"]], ["README.md"])
        self.assertIn(b"<<<<<<<", base64.b64decode(listing["files"][0]["preview"]))
        doc = {
            "files": [{"path": "README.md", "content": b64("resolved\n")}],
            "expected_head": listing["head"]["sha"],
            "expected_base": listing["base"]["sha"],
        }
        stale = {**doc, "expected_head": "0" * 40}
        self.assertEqual(self.mutate(path + "/resolution", stale)[0], 409)
        status, _h, result = self.mutate(path + "/resolution", doc)
        self.assertEqual(status, 201, result)
        head = self.head("feature/api")
        self.assertEqual(result["commit"]["sha"], head)
        self.assertEqual(self.git("--git-dir", self.bare, "show", f"{head}:README.md"), "resolved")
        parents = self.git("--git-dir", self.bare, "rev-list", "--parents", "-n1", head).split()
        self.assertEqual(len(parents), 3)  # merge commit: head + two parents

    # ---------------------------------------------------------------- notify
    def test_notify_is_admin_only(self):
        run = database.db_ci_run_create("alice", "project", "manual", "main", self.sha, "{}")
        database.db_ci_run_update(run, status="success")
        path = self.base + f"/ci/runs/{run}/notify"
        self.assertEqual(self.mutate(path, {})[0], 403)
        status, _h, result = self.mutate(path, {}, token=self.admin_write_token)
        self.assertIn(status, (202, 409), result)


if __name__ == "__main__":
    unittest.main()
