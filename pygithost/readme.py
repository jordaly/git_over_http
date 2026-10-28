"""Small safe Markdown preview for repository READMEs; no raw HTML execution."""

from html import escape
import re
from urllib.parse import urlsplit

from .rendering import safe_html


def _inline(text):
    parts, position = [], 0
    for match in re.finditer(r"`([^`]+)`|\*\*([^*]+)\*\*|\[([^\]]+)\]\(([^\s)]+)\)", text):
        parts.append(escape(text[position:match.start()]))
        code, bold, label, url = match.groups()
        if code is not None:
            parts.append("<code>" + escape(code) + "</code>")
        elif bold is not None:
            parts.append("<strong>" + escape(bold) + "</strong>")
        else:
            try:
                safe_url = urlsplit(url).scheme in ("http", "https") or url.startswith("#")
            except ValueError:
                safe_url = False
            parts.append('<a href="' + escape(url, quote=True) + '" rel="noreferrer">' + escape(label) + "</a>" if safe_url else escape(match.group()))
        position = match.end()
    parts.append(escape(text[position:]))
    return "".join(parts)


def render_readme(text):
    result, paragraph, code = [], [], []
    fenced, list_kind = False, None

    def flush():
        if paragraph:
            result.append("<p>" + _inline(" ".join(paragraph)) + "</p>")
            paragraph.clear()

    def close_list():
        nonlocal list_kind
        if list_kind:
            result.append("</" + list_kind + ">")
            list_kind = None

    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            flush(); close_list()
            if fenced:
                result.append("<pre><code>" + escape("\n".join(code)) + "</code></pre>")
                code.clear()
            fenced = not fenced
            continue
        if fenced:
            code.append(line)
            continue
        heading = re.match(r"^(#{1,6})\s+(.+)$", line)
        item = re.match(r"^\s*(?:[-*+] |\d+\. )(.+)$", line)
        if heading:
            flush(); close_list()
            level = min(6, len(heading[1]) + 1)  # Page already has a repository h1.
            result.append(f"<h{level}>" + _inline(heading[2]) + f"</h{level}>")
        elif item:
            flush()
            kind = "ol" if re.match(r"^\s*\d+\.", line) else "ul"
            if list_kind != kind:
                close_list(); list_kind = kind; result.append("<" + kind + ">")
            result.append("<li>" + _inline(item[1]) + "</li>")
        elif not line.strip():
            flush(); close_list()
        else:
            close_list(); paragraph.append(line)
    flush(); close_list()
    if fenced:
        result.append("<pre><code>" + escape("\n".join(code)) + "</code></pre>")
    return safe_html("".join(result))
