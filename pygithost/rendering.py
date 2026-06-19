"""Safe HTML and Python 3.14 t-string rendering helpers."""

import html
from string.templatelib import Interpolation, Template
from urllib.parse import quote


class SafeHTML(str):
    """A string that is already safe for insertion into HTML."""


def safe_html(value: object) -> SafeHTML:
    return SafeHTML(str(value))


def str_t(template: Template) -> str:
    """Render a t-string without escaping for non-HTML output."""
    return "".join(
        str(part.value) if isinstance(part, Interpolation) else part
        for part in template
    )


def html_t(template: Template) -> str:
    """Render a t-string, escaping interpolated values unless marked safe."""
    return "".join(
        str(part.value)
        if isinstance(part, Interpolation) and isinstance(part.value, SafeHTML)
        else html.escape(str(part.value), quote=True)
        if isinstance(part, Interpolation)
        else part
        for part in template
    )


def join_html(parts: list[str]) -> SafeHTML:
    return safe_html("".join(parts))


def q(value: str, safe: str = "") -> str:
    return quote(value, safe=safe)
