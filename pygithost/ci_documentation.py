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
        reference = json.dumps({"version": 1, "file": ".ci-config.json"}, indent=2)
        content = safe_html(html_t(t'''<h2>CI configuration</h2><p>The full manual is unavailable in this installation. The default Settings reference is:</p><pre>{reference}</pre><p>Commit a separate .ci-config.json with named steps at the repository root. Expanded Settings documents use separate pipelines and deployments arrays; each object requires a name. Each deployment references its pipeline. Environment variables and retention use page controls, with server defaults under Admin → Settings and repository overrides under CI → Settings. Configure execution and cancellation inside each pipeline; omitted options use built-in defaults. There is no execution-defaults settings form. Basic server configuration changes require a restart.</p><pre>{example}</pre><p>Host jobs and deployment scripts are trusted server-user code. Manual CI is always available to write-authorized users with a runnable pipeline and never deploys. Unsupported retries and approvals are rejected.</p>'''))
    return safe_html(html_t(t'<section id="ci-configuration-guide" class="box ci-guide">{content}</section>'))
