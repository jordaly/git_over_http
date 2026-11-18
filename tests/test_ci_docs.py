import os
import subprocess
import tempfile
import unittest

from pygithost.ci_docs import EXAMPLES, GUIDES, manual_content, render_manual


class DocumentationPageTests(unittest.TestCase):
    def test_ci_directory_guidance_and_links_are_rendered_in_page(self):
        base = "/r/team/repo/ci/docs"
        start = str(manual_content("start", "", base))
        self.assertIn('id="repository-ci-directory"', start)
        self.assertIn("ci/config.json", start)
        self.assertIn("sh ci/test.sh", start)
        self.assertIn(base + "?guide=examples", start)
        self.assertIn(base + "?guide=migration#move-root-files-into-ci", start)
        recipes = str(manual_content("examples", "", base))
        self.assertIn('id="multiple-git-managed-pipelines"', recipes)
        self.assertIn("ci/tests.json", recipes)
        migration = str(manual_content("migration", "", base))
        self.assertIn('id="move-root-files-into-ci"', migration)
        self.assertIn("git mv .ci-config.json ci/config.json", migration)

    def test_current_settings_workflow_and_file_reference_are_linked_in_page(self):
        base = "/r/team/repo/ci/docs"
        start = str(manual_content("start", "", base))
        self.assertIn(base + "?guide=migration", start)
        self.assertIn("ci/config.json", start)
        self.assertIn("no project JSON editor", start)
        recipes = str(manual_content("examples", "", base))
        self.assertIn(base + "?example=repository-pipeline", recipes)
        self.assertIn("Commit it as", recipes)
        self.assertIn("do not paste it into a page", recipes)
        self.assertNotIn("repository-reference", recipes)
        settings = str(manual_content("settings", "", base))
        self.assertIn("There is no project JSON editor", settings)
        self.assertIn("only environment variables/secrets", settings)
        self.assertIn("PUT /ci/settings", settings)
        self.assertIn("is disabled", settings)
        self.assertIn("project retention has no separate page form", settings)
        migration = str(manual_content("migration", "", base))
        self.assertIn("Database definitions are ignored for execution", migration)
        self.assertIn("The old page retention form is removed", migration)
        self.assertIn(
            "Current administrator authorization and page-managed values still apply", migration
        )
        workflow = str(manual_content("workflow", "", base))
        self.assertIn("Collapse all folders", workflow)
        self.assertIn("Ctrl/⌘+S", workflow)
        self.assertIn("FOREIGN KEY constraint failed", workflow)
        self.assertIn("Discussion", workflow)
        self.assertIn("merge base", workflow)
        # The obsolete Settings-only reference is not a registry entry or file.
        self.assertIsNone(manual_content("reference", "repository-reference", base))
        self.assertNotIn("repository-reference", EXAMPLES)
        reference = str(manual_content("reference", "all-options", base))
        self.assertIn("Commit this configuration as ci/config.json", reference)
        self.assertIn('class="language-json"', reference)

    def test_current_json_examples_use_page_controls_for_variables_and_retention(self):
        import json
        from pathlib import Path

        for _title, path in EXAMPLES.values():
            document = json.loads(Path(path).read_text())
            self.assertNotIn("env", document, path)
            if "retention" in document:
                # Project retention belongs only in a full grouped Git document.
                self.assertIsInstance(document.get("pipelines"), list, path)
                self.assertNotIn("retention", document.get("settings", {}), path)
            for pipeline in document.get("pipelines", []):
                self.assertNotIn("env", pipeline.get("execution", {}), path)
                self.assertNotIn("manual", pipeline.get("triggers", {}), path)

    def test_every_manual_and_example_is_available(self):
        for guide in GUIDES:
            with self.subTest(guide=guide):
                self.assertTrue(str(manual_content(guide, "", "/r/team/repo/ci/docs")))
        for example in EXAMPLES:
            with self.subTest(example=example):
                self.assertIn(
                    "<pre", str(manual_content("reference", example, "/r/team/repo/ci/docs"))
                )

    def test_tables_anchors_code_and_internal_links(self):
        html = str(
            render_manual(
                """# Example

| Option | Example |
| --- | --- |
| `events` | **Enabled** |

[Full example](examples/ci/all-options.json)

```json
{"env": {"X": "<script>unsafe</script>"}}
```
""",
                "docs/ci-options.md",
                "/r/team/repo/ci/docs",
            )
        )
        self.assertIn('id="example"', html)
        self.assertIn("<th>Option</th>", html)
        self.assertIn("<td><code>events</code></td>", html)
        self.assertIn('href="/r/team/repo/ci/docs?example=all-options"', html)
        self.assertIn("&lt;script&gt;unsafe&lt;/script&gt;", html)
        self.assertNotIn("<script>unsafe</script>", html)

    def test_unsafe_links_and_html_are_not_executable(self):
        html = str(
            render_manual(
                "[bad](javascript:alert) [file](../../secret)\n\n<img src=x onerror=alert(1)>",
                "docs/ci-options.md",
                "/docs",
            )
        )
        self.assertNotIn("href=", html)
        self.assertNotIn("<img", html)
        self.assertIsNone(manual_content("../README", "", "/docs"))
        self.assertIsNone(manual_content("reference", "../README", "/docs"))

    def test_json_is_pretty_printed_and_marked_for_highlighting(self):
        html = str(
            render_manual(
                '```json\n{"pipelines":[{"name":"checks"}],"deployments":[]}\n```',
                "docs/pipelines.md",
                "/docs",
            )
        )
        self.assertIn('class="language-json"', html)
        self.assertIn(
            "\n  &quot;pipelines&quot;: [\n    {\n      &quot;name&quot;: &quot;checks&quot;", html
        )
        example = str(manual_content("reference", "all-options", "/docs"))
        self.assertIn('<code class="language-json">', example)
        self.assertIn("\n      &quot;execution&quot;: {\n        &quot;runner&quot;", example)

    def test_invalid_json_and_non_json_fences_remain_readable(self):
        html = str(
            render_manual(
                '```json\n{"incomplete":\n```\n\n```sh\necho hello\n```',
                "docs/pipelines.md",
                "/docs",
            )
        )
        self.assertIn("{&quot;incomplete&quot;:", html)
        self.assertIn("<code>echo hello</code>", html)


@unittest.skipUnless(
    os.environ.get("PYGITHOST_TEST_BROWSER"), "set PYGITHOST_TEST_BROWSER to a Chromium executable"
)
class DocumentationBrowserTests(unittest.TestCase):
    def test_documentation_and_settings_examples_execute_highlighting(self):
        from tests.test_repository_ui import RepositoryUITests

        fixture = RepositoryUITests()
        fixture.setUp()
        try:
            with tempfile.TemporaryDirectory(prefix="ci-browser-", dir="/tmp/opencode") as profile:
                for path in (
                    "/ci/docs?example=all-options",
                    "/ci/docs?example=git-managed",
                ):
                    with self.subTest(path=path):
                        url = f"http://127.0.0.1:{fixture.server.port}{fixture.base}{path}"
                        result = subprocess.run(
                            [
                                os.environ["PYGITHOST_TEST_BROWSER"],
                                "--headless",
                                "--no-sandbox",
                                "--disable-gpu",
                                "--no-first-run",
                                "--no-default-browser-check",
                                "--disable-dev-shm-usage",
                                f"--user-data-dir={profile}",
                                "--dump-dom",
                                "--virtual-time-budget=5000",
                                url,
                            ],
                            capture_output=True,
                            text=True,
                            timeout=45,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr[-3000:])
                        self.assertIn('class="token property"', result.stdout)
                        self.assertIn('class="token string"', result.stdout)
                        self.assertIn('class="language-json"', result.stdout)
                url = f"http://127.0.0.1:{fixture.server.port}{fixture.base}/ci/config"
                result = subprocess.run(
                    [
                        os.environ["PYGITHOST_TEST_BROWSER"],
                        "--headless",
                        "--no-sandbox",
                        "--disable-gpu",
                        "--no-first-run",
                        "--no-default-browser-check",
                        "--disable-dev-shm-usage",
                        f"--user-data-dir={profile}",
                        "--dump-dom",
                        "--virtual-time-budget=5000",
                        url,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=45,
                )
                self.assertEqual(result.returncode, 0, result.stderr[-3000:])
                self.assertIn("ci/config.json", result.stdout)
                self.assertIn("settings-env-form", result.stdout)
                self.assertNotIn('class="language-json"', result.stdout)
        finally:
            fixture.tearDown()
