"""Compatibility entry point for the canonical, in-page CI manual."""

import json

from .ci_config import EXAMPLE
from .ci_schema import group_document
from .rendering import html_t, safe_html


EXAMPLE_PIPELINE = {"version": 1, "steps": EXAMPLE["pipelines"]["tests"]["steps"]}


def ci_configuration_guide():
    from .ci_docs import manual_content
    try:
        content = manual_content("reference", "", "")
    except OSError:
        example = json.dumps(group_document(EXAMPLE), indent=2)
        content = safe_html(html_t(t'''<h2>CI configuration</h2><p>The full manual is unavailable in this installation. Use separate pipelines and deployments arrays. Each object requires a name; each pipeline has independent execution, triggers and steps. Each deployment references its pipeline. Policies and retention remain repository-wide.</p><pre>{example}</pre><p>Host jobs and deployment scripts are trusted server-user code. Manual CI never deploys. Unsupported retries and approvals are rejected.</p>'''))
    return safe_html(html_t(t'<section id="ci-configuration-guide" class="box ci-guide">{content}</section>'))
