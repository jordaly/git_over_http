import unittest
import os
import subprocess
import tempfile

from pygithost.ci_docs import EXAMPLES, GUIDES, manual_content, render_manual


class DocumentationPageTests(unittest.TestCase):
    def test_every_manual_and_example_is_available(self):
        for guide in GUIDES:
            with self.subTest(guide=guide):
                self.assertTrue(str(manual_content(guide, "", "/r/team/repo/ci/docs")))
        for example in EXAMPLES:
            with self.subTest(example=example):
                self.assertIn("<pre", str(manual_content("reference", example, "/r/team/repo/ci/docs")))

    def test_tables_anchors_code_and_internal_links(self):
        html = str(render_manual('''# Example

| Option | Example |
| --- | --- |
| `events` | **Enabled** |

[Full example](examples/ci/all-options.json)

```json
{"env": {"X": "<script>unsafe</script>"}}
```
''', "docs/ci-options.md", "/r/team/repo/ci/docs"))
        self.assertIn('id="example"', html)
        self.assertIn("<th>Option</th>", html)
        self.assertIn("<td><code>events</code></td>", html)
        self.assertIn('href="/r/team/repo/ci/docs?example=all-options"', html)
        self.assertIn("&lt;script&gt;unsafe&lt;/script&gt;", html)
        self.assertNotIn("<script>unsafe</script>", html)

    def test_unsafe_links_and_html_are_not_executable(self):
        html = str(render_manual('[bad](javascript:alert) [file](../../secret)\n\n<img src=x onerror=alert(1)>',
                                 "docs/ci-options.md", "/docs"))
        self.assertNotIn('href=', html)
        self.assertNotIn('<img', html)
        self.assertIsNone(manual_content("../README", "", "/docs"))
        self.assertIsNone(manual_content("reference", "../README", "/docs"))

    def test_json_is_pretty_printed_and_marked_for_highlighting(self):
        html = str(render_manual('```json\n{"pipelines":[{"name":"checks"}],"deployments":[]}\n```',
                                 "docs/pipelines.md", "/docs"))
        self.assertIn('class="language-json"', html)
        self.assertIn('\n  &quot;pipelines&quot;: [\n    {\n      &quot;name&quot;: &quot;checks&quot;', html)
        example = str(manual_content("reference", "all-options", "/docs"))
        self.assertIn('<code class="language-json">', example)
        self.assertIn('\n      &quot;execution&quot;: {\n        &quot;runner&quot;', example)

    def test_invalid_json_and_non_json_fences_remain_readable(self):
        html = str(render_manual('```json\n{"incomplete":\n```\n\n```sh\necho hello\n```',
                                 "docs/pipelines.md", "/docs"))
        self.assertIn('{&quot;incomplete&quot;:', html)
        self.assertIn('<code>echo hello</code>', html)


@unittest.skipUnless(os.environ.get("PYGITHOST_TEST_BROWSER"), "set PYGITHOST_TEST_BROWSER to a Chromium executable")
class DocumentationBrowserTests(unittest.TestCase):
    def test_documentation_and_settings_examples_execute_highlighting(self):
        from tests.test_repository_ui import RepositoryUITests
        fixture = RepositoryUITests()
        fixture.setUp()
        try:
            with tempfile.TemporaryDirectory(prefix="ci-browser-", dir="/tmp/opencode") as profile:
                for path in ("/ci/docs?example=all-options", "/ci/config"):
                    with self.subTest(path=path):
                        url = f"http://127.0.0.1:{fixture.server.port}{fixture.base}{path}"
                        result = subprocess.run([
                            os.environ["PYGITHOST_TEST_BROWSER"], "--headless", "--no-sandbox", "--disable-gpu",
                            "--no-first-run", "--no-default-browser-check", "--disable-dev-shm-usage",
                            f"--user-data-dir={profile}", "--dump-dom", "--virtual-time-budget=5000", url,
                        ], capture_output=True, text=True, timeout=45)
                        self.assertEqual(result.returncode, 0, result.stderr[-3000:])
                        self.assertIn('class="token property"', result.stdout)
                        self.assertIn('class="token string"', result.stdout)
                        self.assertIn('class="language-json"', result.stdout)
        finally:
            fixture.tearDown()
