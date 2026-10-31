"""Render the checked-in CI manual safely inside repository documentation pages."""

from html import escape
import json
from pathlib import Path
import re
from urllib.parse import urlencode, urlsplit

from .rendering import safe_html


ROOT = Path(__file__).resolve().parent.parent
GUIDES = {
    "reference": ("Every option", "docs/ci-options.md"),
    "start": ("Quick start", "docs/pipelines.md"),
    "examples": ("Recipes", "docs/pipeline-examples.md"),
    "migration": ("Migration", "docs/ci-migration.md"),
    "deployment": ("Deployment", "docs/automatic-deployment.md"),
    "retention": ("Retention", "docs/ci-retention.md"),
    "settings": ("Server and repository settings", "docs/server-settings.md"),
    "workflow": ("Editing and pull requests", "docs/repository-workflow.md"),
    "operations": ("Operations", "README.md"),
    "getting-started": ("Server setup", "docs/getting-started.md"),
}
EXAMPLES = {
    "repository-reference": ("Default file reference (Settings)", "docs/examples/ci/repository-reference.json"),
    "all-options": ("All options", "docs/examples/ci/all-options.json"),
    "inline-deployment": ("Inline deployment", "docs/examples/ci/inline-deployment.json"),
    "git-managed": ("Git-managed configuration", "docs/examples/ci/git-managed.json"),
    "repository-pipeline": ("Git pipeline file", "docs/examples/ci/repository-pipeline.json"),
}


def _code_block(text, language=""):
    if language == "json":
        try:
            text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except (ValueError, RecursionError):
            pass  # Preserve incomplete illustrative snippets rather than hide them.
    css = ' class="language-json"' if language == "json" else ""
    return '<pre tabindex="0"' + css + '><code' + css + '>' + escape(text) + '</code></pre>'


def _link(value, source, base):
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme:
        return value if parsed.scheme in ("http", "https") else None
    if parsed.netloc:
        return None
    if not parsed.path:
        return "#" + parsed.fragment if parsed.fragment else None
    target = (ROOT / source).parent.joinpath(parsed.path).resolve()
    for kind, entries in (("guide", GUIDES), ("example", EXAMPLES)):
        for key, (_title, path) in entries.items():
            if target == (ROOT / path).resolve():
                return base + "?" + urlencode({kind: key}) + ("#" + parsed.fragment if parsed.fragment else "")
    return None


def _inline(text, source, base):
    result, position = [], 0
    for match in re.finditer(r"`([^`]+)`|\*\*([^*]+)\*\*|\[([^\]]+)\]\(([^\s)]+)\)", text):
        result.append(escape(text[position:match.start()]))
        code, bold, label, value = match.groups()
        if code is not None:
            result.append("<code>" + escape(code) + "</code>")
        elif bold is not None:
            result.append("<strong>" + escape(bold) + "</strong>")
        else:
            href = _link(value, source, base)
            result.append('<a href="' + escape(href, quote=True) + '">' + escape(label) + '</a>' if href else escape(label))
        position = match.end()
    result.append(escape(text[position:]))
    return "".join(result)


def render_manual(text, source, base):
    """Small Markdown renderer with tables, heading anchors and internal links.

    Raw HTML is always escaped. Files and links are selected from fixed manifests,
    never from request-controlled filesystem paths.
    """
    lines = text.splitlines()
    output, paragraph = [], []
    index = 0
    list_kind = None
    headings = {}

    def flush():
        if paragraph:
            output.append("<p>" + _inline(" ".join(paragraph), source, base) + "</p>")
            paragraph.clear()

    def close_list():
        nonlocal list_kind
        if list_kind:
            output.append("</" + list_kind + ">")
            list_kind = None

    def cells(line):
        return [part.strip() for part in line.strip().strip("|").split("|")]

    while index < len(lines):
        line = lines[index]
        if line.lstrip().startswith("```"):
            flush(); close_list()
            language = line.strip()[3:].strip().lower()
            code = []
            index += 1
            while index < len(lines) and not lines[index].lstrip().startswith("```"):
                code.append(lines[index])
                index += 1
            output.append(_code_block("\n".join(code), language))
        elif line.strip().startswith("|") and index + 1 < len(lines) and all(
            re.fullmatch(r":?-{3,}:?", cell) for cell in cells(lines[index + 1])
        ):
            flush(); close_list()
            headers = cells(line)
            output.append('<div class="ci-table-scroll"><table><thead><tr>' +
                "".join("<th>" + _inline(cell, source, base) + "</th>" for cell in headers) + "</tr></thead><tbody>")
            index += 2
            while index < len(lines) and lines[index].strip().startswith("|"):
                output.append("<tr>" + "".join("<td>" + _inline(cell, source, base) + "</td>" for cell in cells(lines[index])) + "</tr>")
                index += 1
            output.append("</tbody></table></div>")
            continue
        elif heading := re.match(r"^(#{1,6})\s+(.+)$", line):
            flush(); close_list()
            label = heading[2]
            slug = re.sub(r"[^\w\- ]", "", label.replace("`", "").lower()).replace(" ", "-")
            count = headings.get(slug, 0)
            headings[slug] = count + 1
            identity = slug + (f"-{count}" if count else "")
            level = min(6, len(heading[1]) + 1)
            output.append(f'<h{level} id="{escape(identity, quote=True)}">' + _inline(label, source, base) + f"</h{level}>")
        elif item := re.match(r"^\s*(?:[-*+] |\d+\. )(.+)$", line):
            flush()
            kind = "ol" if re.match(r"^\s*\d+\.", line) else "ul"
            if list_kind != kind:
                close_list()
                list_kind = kind
                output.append("<" + kind + ">")
            output.append("<li>" + _inline(item[1], source, base) + "</li>")
        elif line.startswith("> "):
            flush(); close_list()
            output.append('<p class="warn">' + _inline(line[2:], source, base) + "</p>")
        elif not line.strip():
            flush(); close_list()
        else:
            if list_kind and line.startswith("  ") and output[-1].endswith("</li>"):
                output[-1] = output[-1][:-5] + " " + _inline(line.strip(), source, base) + "</li>"
            else:
                close_list()
                paragraph.append(line)
        index += 1
    flush(); close_list()
    return safe_html("".join(output))


def manual_content(guide, example, base):
    if example:
        if example not in EXAMPLES:
            return None
        title, path = EXAMPLES[example]
        text = (ROOT / path).read_text(encoding="utf-8")
        warning = "Commit this as .pygithost-ci.json; it is not an administrator document." if example == "repository-pipeline" else "Copy this complete document into CI → Settings → Configuration JSON and adapt it before saving."
        return safe_html('<h2>' + escape(title) + '</h2><p>' + escape(warning) +
            '</p>' + _code_block(text, "json"))
    if guide not in GUIDES:
        return None
    _title, path = GUIDES[guide]
    return render_manual((ROOT / path).read_text(encoding="utf-8"), path, base)
