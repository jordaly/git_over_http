"""Compatibility entry point for the canonical, in-page CI manual."""

import json

from .ci_config import EXAMPLE
from .ci_schema import group_document
from .rendering import SafeHTML, html_t, safe_html

EXAMPLE_PIPELINE = {"version": 1, "steps": EXAMPLE["pipelines"]["tests"]["steps"]}


def ci_configuration_guide() -> SafeHTML:
    from .ci_docs import manual_content

    try:
        content = manual_content("reference", "", "")
        if content is None:  # The fixed reference guide is always registered.
            raise OSError("CI reference guide is unavailable.")
    except OSError:
        example = json.dumps(group_document(EXAMPLE), indent=2)
        content = safe_html(
            html_t(
                t"""<h2>CI configuration</h2><p>The full manual is unavailable in this installation. Commit configuration to ci/config.json; referenced pipeline files must also be under ci/. Use separate pipelines and deployments arrays; each object requires a name. Each deployment references its pipeline.</p><p>Validate your checkout with <code>python -m pygithost ci validate</code>. In CI → Run pipeline, select a branch to inspect its committed configuration and available pipelines. Manual runs never deploy.</p><p>Manage credentials in CI → Settings, not in Git. Unmerged pull-request runs do not receive page-managed values. There is no project configuration editor or API replacement endpoint.</p><pre>{example}</pre><p>Host jobs and deployment scripts require separate administrator authorization.</p>"""
            )
        )
    return safe_html(
        html_t(t'<section id="ci-configuration-guide" class="box ci-guide">{content}</section>')
    )
