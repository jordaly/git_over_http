"""Parse unified Git diffs and render a GitHub-style "Files changed" view.

Everything here is pure: no I/O, no database access. HTML is built exclusively with
``html_t`` t-strings so interpolated values are escaped unless already ``SafeHTML``.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from hl_mappings import PRISM_LANGUAGE_BY_EXTENSION
from pygithost.rendering import SafeHTML, html_t, join_html, safe_html

LineKind = Literal["context", "add", "del"]
FileStatus = Literal["added", "deleted", "modified", "renamed", "copied"]
DiffMode = Literal["unified", "split"]
Side = Literal["LEFT", "RIGHT"]

#: Files with more rendered lines than this are deferred behind a "Load diff" button.
LARGE_DIFF_LINES = 1500


@dataclass(frozen=True, slots=True)
class DiffLine:
    kind: LineKind
    old: int | None
    new: int | None
    text: str
    no_newline: bool = False


@dataclass(frozen=True, slots=True)
class Hunk:
    header: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    section: str
    lines: tuple[DiffLine, ...]


@dataclass(frozen=True, slots=True)
class FileDiff:
    path: str
    old_path: str | None
    status: FileStatus
    binary: bool
    hunks: tuple[Hunk, ...]
    additions: int
    deletions: int
    truncated: bool
    old_mode: str | None
    new_mode: str | None


# ============================================================
# Parsing
# ============================================================

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: ?(.*))?$")
_TRUNCATED_MARKER_RE = re.compile(r"^\[\.\.\.[^\]]*truncated[^\]]*\]$", re.IGNORECASE)
_C_ESCAPES = {
    "a": 7,
    "b": 8,
    "t": 9,
    "n": 10,
    "v": 11,
    "f": 12,
    "r": 13,
    '"': 34,
    "\\": 92,
}


def _read_quoted(text: str, start: int) -> tuple[str, int]:
    """Decode a C-style quoted Git path starting at ``text[start] == '"'``.

    Returns the decoded string and the index just past the closing quote.
    """
    out = bytearray()
    i = start + 1
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            return out.decode("utf-8", "replace"), i + 1
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            octal = text[i + 1 : i + 4]
            if len(octal) == 3 and all(c in "01234567" for c in octal):
                out.append(int(octal, 8) & 0xFF)
                i += 4
                continue
            if nxt in _C_ESCAPES:
                out.append(_C_ESCAPES[nxt])
                i += 2
                continue
            out.extend(nxt.encode("utf-8"))
            i += 2
            continue
        out.extend(ch.encode("utf-8"))
        i += 1
    return out.decode("utf-8", "replace"), n


def _unquote(value: str) -> str:
    value = value.rstrip("\t")
    if value.startswith('"'):
        return _read_quoted(value, 0)[0]
    return value


def _strip_prefix(path: str) -> str:
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def _label_path(value: str) -> str | None:
    """Path from a ``---``/``+++`` label; ``None`` for /dev/null."""
    # Git appends a tab after labels containing spaces.
    raw = value[:-1] if value.endswith("\t") else value
    if raw == "/dev/null":
        return None
    return _strip_prefix(_unquote(raw))


def _git_header_paths(rest: str) -> tuple[str, str]:
    """Best-effort split of ``a/x b/y`` from a ``diff --git`` line."""
    if rest.startswith('"'):
        old, end = _read_quoted(rest, 0)
        new_raw = rest[end:].lstrip(" ")
        new = _unquote(new_raw)
        return _strip_prefix(old), _strip_prefix(new)
    quote_at = rest.find(' "')
    if quote_at != -1 and rest.endswith('"'):
        return _strip_prefix(rest[:quote_at]), _strip_prefix(_read_quoted(rest, quote_at + 1)[0])
    # Same name on both sides (the common case, also with spaces): "a/P b/P".
    if (len(rest) - 1) % 2 == 0:
        half = (len(rest) - 1) // 2
        left, sep, right = rest[:half], rest[half], rest[half + 1 :]
        if (
            sep == " "
            and left.startswith("a/")
            and right.startswith("b/")
            and left[2:] == right[2:]
        ):
            return left[2:], right[2:]
    split_at = rest.find(" b/")
    if split_at != -1:
        return _strip_prefix(rest[:split_at]), _strip_prefix(rest[split_at + 1 :])
    return _strip_prefix(rest), _strip_prefix(rest)


@dataclass(slots=True)
class _FileBuilder:
    header_old: str
    header_new: str
    max_lines: int
    old_label: str | None = None
    new_label: str | None = None
    saw_labels: bool = False
    rename_from: str | None = None
    rename_to: str | None = None
    copy_from: str | None = None
    copy_to: str | None = None
    added: bool = False
    deleted: bool = False
    binary: bool = False
    old_mode: str | None = None
    new_mode: str | None = None
    hunks: list[Hunk] = field(default_factory=list)
    additions: int = 0
    deletions: int = 0
    stored_lines: int = 0
    truncated: bool = False
    # Current hunk state.
    hunk_header: str | None = None
    hunk_values: tuple[int, int, int, int, str] = (0, 0, 0, 0, "")
    hunk_lines: list[DiffLine] = field(default_factory=list)
    old_no: int = 0
    new_no: int = 0
    old_left: int = 0
    new_left: int = 0
    in_binary_patch: bool = False

    def close_hunk(self) -> None:
        if self.hunk_header is not None:
            old_start, old_count, new_start, new_count, section = self.hunk_values
            self.hunks.append(
                Hunk(
                    header=self.hunk_header,
                    old_start=old_start,
                    old_count=old_count,
                    new_start=new_start,
                    new_count=new_count,
                    section=section,
                    lines=tuple(self.hunk_lines),
                )
            )
        self.hunk_header = None
        self.hunk_lines = []
        self.old_left = self.new_left = 0

    def in_hunk(self) -> bool:
        return self.hunk_header is not None and (self.old_left > 0 or self.new_left > 0)

    def add_line(self, line: DiffLine) -> None:
        if line.kind == "add":
            self.additions += 1
        elif line.kind == "del":
            self.deletions += 1
        if self.truncated:
            return
        if self.stored_lines >= self.max_lines:
            self.truncated = True
            return
        self.hunk_lines.append(line)
        self.stored_lines += 1

    def mark_no_newline(self) -> None:
        if self.hunk_lines:
            last = self.hunk_lines[-1]
            self.hunk_lines[-1] = DiffLine(last.kind, last.old, last.new, last.text, True)

    def build(self) -> FileDiff:
        self.close_hunk()
        status: FileStatus
        old_path: str | None = None
        if self.added:
            status = "added"
        elif self.deleted:
            status = "deleted"
        elif self.rename_from is not None or self.rename_to is not None:
            status = "renamed"
        elif self.copy_from is not None or self.copy_to is not None:
            status = "copied"
        else:
            status = "modified"
        new_side = self.rename_to or self.copy_to or self.new_label or self.header_new
        old_side = self.rename_from or self.copy_from or self.old_label or self.header_old
        path = old_side if status == "deleted" else new_side
        if status in ("renamed", "copied"):
            old_path = old_side
        return FileDiff(
            path=path,
            old_path=old_path,
            status=status,
            binary=self.binary,
            hunks=tuple(self.hunks),
            additions=self.additions,
            deletions=self.deletions,
            truncated=self.truncated,
            old_mode=self.old_mode,
            new_mode=self.new_mode,
        )


def _split_lines(text: str) -> tuple[list[str], bool]:
    """Split on ``\\n`` only (content may hold other line separators) and drop CRs."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    lines = [line[:-1] if line.endswith("\r") else line for line in lines]
    for index, line in enumerate(lines):
        if _TRUNCATED_MARKER_RE.match(line.strip()):
            kept = lines[:index]
            while kept and kept[-1] == "":
                kept.pop()
            return kept, True
    return lines, False


def parse_unified_diff(text: str, *, max_lines_per_file: int = 20000) -> list[FileDiff]:
    """Parse ``git diff --no-color -M`` output into :class:`FileDiff` objects."""
    lines, output_truncated = _split_lines(text)
    files: list[FileDiff] = []
    cur: _FileBuilder | None = None

    for line in lines:
        if line.startswith("diff --git "):
            if cur is not None:
                files.append(cur.build())
            old, new = _git_header_paths(line[len("diff --git ") :])
            cur = _FileBuilder(header_old=old, header_new=new, max_lines=max_lines_per_file)
            continue
        if cur is None:
            continue
        if cur.in_binary_patch:
            continue
        if cur.in_hunk():
            if line.startswith("\\"):
                cur.mark_no_newline()
                continue
            marker = line[:1]
            body = line[1:]
            if marker == "+":
                cur.add_line(DiffLine("add", None, cur.new_no, body))
                cur.new_no += 1
                cur.new_left -= 1
            elif marker == "-":
                cur.add_line(DiffLine("del", cur.old_no, None, body))
                cur.old_no += 1
                cur.old_left -= 1
            elif marker in (" ", ""):
                cur.add_line(DiffLine("context", cur.old_no, cur.new_no, body))
                cur.old_no += 1
                cur.new_no += 1
                cur.old_left -= 1
                cur.new_left -= 1
            else:
                # Malformed hunk: stop consuming lines as content.
                cur.close_hunk()
            continue
        if line.startswith("\\"):
            cur.mark_no_newline()
            continue
        match = _HUNK_RE.match(line)
        if match:
            cur.close_hunk()
            old_start = int(match.group(1))
            old_count = int(match.group(2)) if match.group(2) is not None else 1
            new_start = int(match.group(3))
            new_count = int(match.group(4)) if match.group(4) is not None else 1
            section = (match.group(5) or "").strip()
            cur.hunk_values = (old_start, old_count, new_start, new_count, section)
            cur.old_no, cur.new_no = old_start, new_start
            cur.old_left, cur.new_left = old_count, new_count
            cur.hunk_header = line
            continue
        if cur.hunks or cur.hunk_header is not None:
            # Header lines never follow hunks; ignore stray text.
            continue
        if line.startswith("--- "):
            cur.old_label = _label_path(line[4:])
            cur.saw_labels = True
        elif line.startswith("+++ "):
            cur.new_label = _label_path(line[4:])
            cur.saw_labels = True
        elif line.startswith("new file mode "):
            cur.added = True
            cur.new_mode = line[len("new file mode ") :].strip()
        elif line.startswith("deleted file mode "):
            cur.deleted = True
            cur.old_mode = line[len("deleted file mode ") :].strip()
        elif line.startswith("old mode "):
            cur.old_mode = line[len("old mode ") :].strip()
        elif line.startswith("new mode "):
            cur.new_mode = line[len("new mode ") :].strip()
        elif line.startswith("rename from "):
            cur.rename_from = _unquote(line[len("rename from ") :])
        elif line.startswith("rename to "):
            cur.rename_to = _unquote(line[len("rename to ") :])
        elif line.startswith("copy from "):
            cur.copy_from = _unquote(line[len("copy from ") :])
        elif line.startswith("copy to "):
            cur.copy_to = _unquote(line[len("copy to ") :])
        elif line.startswith("Binary files ") and line.endswith(" differ"):
            cur.binary = True
        elif line == "GIT binary patch":
            cur.binary = True
            cur.in_binary_patch = True

    if cur is not None:
        if output_truncated:
            cur.truncated = True
        files.append(cur.build())
    files = [_drop_empty_truncated_hunks(f) for f in files]
    return files


def _drop_empty_truncated_hunks(diff: FileDiff) -> FileDiff:
    if not diff.truncated or all(h.lines for h in diff.hunks):
        return diff
    return FileDiff(
        path=diff.path,
        old_path=diff.old_path,
        status=diff.status,
        binary=diff.binary,
        hunks=tuple(h for h in diff.hunks if h.lines),
        additions=diff.additions,
        deletions=diff.deletions,
        truncated=diff.truncated,
        old_mode=diff.old_mode,
        new_mode=diff.new_mode,
    )


# ============================================================
# Helpers
# ============================================================


def file_anchor(path: str) -> str:
    """Stable, HTML-id-safe anchor for a file path."""
    return "diff-" + hashlib.sha256(path.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def prism_language(path: str) -> str:
    """Prism language id for ``path`` or ``""`` when unknown."""
    name = path.rsplit("/", 1)[-1].lower()
    if "." in name:
        found = PRISM_LANGUAGE_BY_EXTENSION.get("." + name.rsplit(".", 1)[-1])
        if found:
            return found
    # Extensionless names such as "Dockerfile" map via ".dockerfile" when present.
    return PRISM_LANGUAGE_BY_EXTENSION.get("." + name, "")


def rendered_line_count(diff: FileDiff) -> int:
    return sum(len(h.lines) for h in diff.hunks)


def diff_line_keys(diff: FileDiff) -> set[tuple[str, int]]:
    """All ``(side, line)`` keys a thread can attach to in this diff.

    Threads whose key is absent (e.g. outdated) are not rendered by ``render_file``;
    callers can use this to show them elsewhere.
    """
    keys: set[tuple[str, int]] = set()
    for hunk in diff.hunks:
        for line in hunk.lines:
            if line.old is not None:
                keys.add(("LEFT", line.old))
            if line.new is not None:
                keys.add(("RIGHT", line.new))
    return keys


_STATUS_LABELS: dict[str, str] = {
    "added": "Added",
    "deleted": "Deleted",
    "modified": "Modified",
    "renamed": "Renamed",
    "copied": "Copied",
}
_STATUS_ICONS: dict[str, str] = {
    "added": "+",
    "deleted": "−",
    "modified": "•",
    "renamed": "→",
    "copied": "⧉",
}
_MARKERS: dict[str, str] = {"add": "+", "del": "-", "context": " "}


# ============================================================
# Diff table rendering
# ============================================================


def _add_button(side: Side, line: int) -> SafeHTML:
    return safe_html(
        html_t(
            t'<button type="button" class="diff-add-comment" data-side="{side}" data-line="{line}" aria-label="Comment on line {line}">+</button>'
        )
    )


def _num_cell(side: Side, number: int | None, kind: str) -> SafeHTML:
    if number is None:
        return safe_html(html_t(t'<td class="diff-num diff-num-{kind}" data-side="{side}"></td>'))
    return safe_html(
        html_t(
            t'<td class="diff-num diff-num-{kind}" data-side="{side}" data-line="{number}">{number}</td>'
        )
    )


def _code_cell(line: DiffLine, side: Side, can_comment: bool) -> SafeHTML:
    number = line.new if side == "RIGHT" else line.old
    button = _add_button(side, number) if can_comment and number is not None else safe_html("")
    marker = _MARKERS[line.kind]
    eol = (
        safe_html(
            '<span class="diff-no-newline" title="No newline at end of file" '
            'aria-label="No newline at end of file">⊘</span>'
        )
        if line.no_newline
        else safe_html("")
    )
    kind = line.kind
    if side == "RIGHT" and number is not None:
        return safe_html(
            html_t(
                t'<td class="diff-code-cell diff-code-{kind}" data-side="{side}" data-line="{number}" data-text="{line.text}">{button}<span class="diff-marker">{marker}</span><code class="diff-code">{line.text}</code>{eol}</td>'
            )
        )
    return safe_html(
        html_t(
            t'<td class="diff-code-cell diff-code-{kind}" data-side="{side}" data-line="{number if number is not None else ""}">{button}<span class="diff-marker">{marker}</span><code class="diff-code">{line.text}</code>{eol}</td>'
        )
    )


def _hunk_row(hunk: Hunk, colspan: int) -> SafeHTML:
    header = hunk.header
    return safe_html(
        html_t(
            t'<tr class="diff-hunk"><td class="diff-hunk-header" colspan="{colspan}">{header}</td></tr>'
        )
    )


def _row_id(anchor: str, line: DiffLine) -> str:
    if line.new is not None:
        return f"{anchor}-R{line.new}"
    return f"{anchor}-L{line.old}"


def _unified_thread_keys(line: DiffLine) -> list[tuple[str, int]]:
    keys: list[tuple[str, int]] = []
    if line.old is not None and line.kind != "add":
        keys.append(("LEFT", line.old))
    if line.new is not None and line.kind != "del":
        keys.append(("RIGHT", line.new))
    return keys


def _unified_rows(
    diff: FileDiff,
    anchor: str,
    threads: Mapping[tuple[str, int], SafeHTML],
    can_comment: bool,
) -> Iterator[str]:
    for hunk in diff.hunks:
        yield _hunk_row(hunk, 3)
        for line in hunk.lines:
            side: Side = "LEFT" if line.kind == "del" else "RIGHT"
            row_id = _row_id(anchor, line)
            kind = line.kind
            old_cell = _num_cell("LEFT", line.old, "old")
            new_cell = _num_cell("RIGHT", line.new, "new")
            code = _code_cell(line, side, can_comment)
            yield html_t(
                t'<tr class="diff-line diff-{kind}" id="{row_id}">{old_cell}{new_cell}{code}</tr>'
            )
            for thread_side, number in _unified_thread_keys(line):
                thread = threads.get((thread_side, number))
                if thread is not None:
                    yield html_t(
                        t'<tr class="diff-thread-row" data-side="{thread_side}" data-line="{number}"><td class="diff-thread-cell" colspan="3">{safe_html(thread)}</td></tr>'
                    )


def _split_pairs(hunk: Hunk) -> Iterator[tuple[DiffLine | None, DiffLine | None]]:
    lines = hunk.lines
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if line.kind == "context":
            yield line, line
            i += 1
            continue
        dels: list[DiffLine] = []
        adds: list[DiffLine] = []
        while i < n and lines[i].kind == "del":
            dels.append(lines[i])
            i += 1
        while i < n and lines[i].kind == "add":
            adds.append(lines[i])
            i += 1
        for index in range(max(len(dels), len(adds))):
            yield (
                dels[index] if index < len(dels) else None,
                adds[index] if index < len(adds) else None,
            )


_EMPTY_SIDE = safe_html(
    '<td class="diff-num diff-empty"></td><td class="diff-code-cell diff-empty"></td>'
)


def _split_side(line: DiffLine | None, side: Side, can_comment: bool) -> SafeHTML:
    if line is None:
        return _EMPTY_SIDE
    number = line.old if side == "LEFT" else line.new
    num = _num_cell(side, number, "old" if side == "LEFT" else "new")
    return safe_html(num + _code_cell(line, side, can_comment))


def _split_rows(
    diff: FileDiff,
    anchor: str,
    threads: Mapping[tuple[str, int], SafeHTML],
    can_comment: bool,
) -> Iterator[str]:
    for hunk in diff.hunks:
        yield _hunk_row(hunk, 4)
        for left, right in _split_pairs(hunk):
            if right is not None:
                row_id = f"{anchor}-R{right.new}"
            else:
                assert left is not None
                row_id = f"{anchor}-L{left.old}"
            if left is not None and right is not None and left is right:
                row_class = "diff-line diff-context"
            else:
                parts = ["diff-line"]
                if left is not None:
                    parts.append("diff-has-del")
                if right is not None:
                    parts.append("diff-has-add")
                row_class = " ".join(parts)
            left_html = _split_side(left, "LEFT", can_comment)
            right_html = _split_side(right, "RIGHT", can_comment)
            yield html_t(t'<tr class="{row_class}" id="{row_id}">{left_html}{right_html}</tr>')
            left_thread = (
                threads.get(("LEFT", left.old))
                if left is not None and left.old is not None
                else None
            )
            right_thread = (
                threads.get(("RIGHT", right.new))
                if right is not None and right.new is not None
                else None
            )
            if left_thread is None and right_thread is None:
                continue
            empty = safe_html('<td class="diff-thread-empty" colspan="2"></td>')
            left_cell = (
                safe_html(
                    html_t(
                        t'<td class="diff-thread-cell" colspan="2" data-side="LEFT">{safe_html(left_thread)}</td>'
                    )
                )
                if left_thread is not None
                else empty
            )
            right_cell = (
                safe_html(
                    html_t(
                        t'<td class="diff-thread-cell" colspan="2" data-side="RIGHT">{safe_html(right_thread)}</td>'
                    )
                )
                if right_thread is not None
                else empty
            )
            yield html_t(t'<tr class="diff-thread-row">{left_cell}{right_cell}</tr>')


def _diff_table(
    diff: FileDiff,
    anchor: str,
    mode: DiffMode,
    threads: Mapping[tuple[str, int], SafeHTML],
    can_comment: bool,
) -> SafeHTML:
    if mode == "split":
        rows = join_html(_split_rows(diff, anchor, threads, can_comment))
        cols = safe_html(
            '<colgroup><col class="diff-col-num"><col class="diff-col-code">'
            '<col class="diff-col-num"><col class="diff-col-code"></colgroup>'
        )
    else:
        rows = join_html(_unified_rows(diff, anchor, threads, can_comment))
        cols = safe_html(
            '<colgroup><col class="diff-col-num"><col class="diff-col-num">'
            '<col class="diff-col-code"></colgroup>'
        )
    return safe_html(
        html_t(
            t'<div class="diff-table-wrap"><table class="diff-table diff-{mode}">{cols}<tbody>{rows}</tbody></table></div>'
        )
    )


def _notice(text: str, extra: str = "") -> SafeHTML:
    cls = "diff-notice" + (" " + extra if extra else "")
    return safe_html(html_t(t'<div class="{cls}">{text}</div>'))


def _empty_body_text(diff: FileDiff) -> str:
    if diff.status == "renamed":
        return "File renamed without changes."
    if diff.status == "copied":
        return "File copied without changes."
    if diff.status == "deleted":
        return "Empty file deleted."
    if diff.old_mode and diff.new_mode and diff.old_mode != diff.new_mode:
        return "File mode changed."
    return "Empty file."


def _file_body(
    diff: FileDiff,
    anchor: str,
    mode: DiffMode,
    threads: Mapping[tuple[str, int], SafeHTML],
    can_comment: bool,
) -> SafeHTML:
    if diff.binary:
        return _notice("Binary file not shown.", "diff-binary")
    if not diff.hunks:
        if diff.truncated:
            return _notice("Diff truncated.", "diff-truncated")
        return _notice(_empty_body_text(diff), "diff-empty-file")
    table = _diff_table(diff, anchor, mode, threads, can_comment)
    truncated = _notice("Diff truncated.", "diff-truncated") if diff.truncated else safe_html("")
    lines = rendered_line_count(diff)
    if lines > LARGE_DIFF_LINES:
        count = f"{lines:,}"
        return safe_html(
            html_t(
                t'<div class="diff-large"><p class="diff-large-note">Large diff ({count} lines) not rendered by default.</p><button type="button" class="btn diff-load">Load diff</button><template class="diff-large-template">{table}</template></div>{truncated}'
            )
        )
    return safe_html(table + truncated)


def _header_path(diff: FileDiff) -> SafeHTML:
    if diff.old_path is not None and diff.old_path != diff.path:
        old = diff.old_path
        new = diff.path
        return safe_html(
            html_t(
                t'<span class="diff-path"><span class="diff-old-path">{old}</span> → <span class="diff-new-path">{new}</span></span>'
            )
        )
    path = diff.path
    return safe_html(html_t(t'<span class="diff-path">{path}</span>'))


def render_file(
    diff: FileDiff,
    *,
    anchor: str,
    mode: DiffMode,
    threads: Mapping[tuple[str, int], SafeHTML],
    can_comment: bool,
    viewed: bool,
    collapsed: bool = False,
) -> SafeHTML:
    """Render one changed file as a collapsible ``<details class="diff-file">``."""
    lang = prism_language(diff.path)
    open_attr = safe_html("" if viewed or collapsed else " open")
    checked = safe_html(" checked" if viewed else "")
    status = diff.status
    label = _STATUS_LABELS[status]
    path_html = _header_path(diff)
    additions = diff.additions
    deletions = diff.deletions
    if diff.old_mode and diff.new_mode and diff.old_mode != diff.new_mode:
        old_mode, new_mode = diff.old_mode, diff.new_mode
        mode_note = safe_html(
            html_t(
                t'<span class="diff-mode-note" title="File mode changed">{old_mode} → {new_mode}</span>'
            )
        )
    else:
        mode_note = safe_html("")
    body = _file_body(diff, anchor, mode, threads, can_comment)
    lines = rendered_line_count(diff)
    path = diff.path
    viewed_class = safe_html(" is-viewed" if viewed else "")
    return safe_html(
        html_t(
            t'<details class="diff-file diff-file-{status}{viewed_class}" id="{anchor}" data-path="{path}" data-lang="{lang}" data-lines="{lines}"{open_attr}>'
            t'<summary class="diff-file-header">'
            t'<span class="diff-chevron" aria-hidden="true"></span>'
            t'<span class="diff-status diff-status-{status}">{label}</span>'
            t"{path_html}"
            t'<span class="diff-stats"><span class="diff-stat-add">+{additions}</span> <span class="diff-stat-del">−{deletions}</span></span>'
            t"{mode_note}"
            t'<label class="diff-viewed-label"><input type="checkbox" class="diff-viewed" data-path="{path}"{checked}> Viewed</label>'
            t"</summary>"
            t'<div class="diff-file-body">{body}</div>'
            t"</details>"
        )
    )


# ============================================================
# File tree
# ============================================================


@dataclass(slots=True)
class _TreeDir:
    dirs: dict[str, _TreeDir] = field(default_factory=dict)
    files: list[tuple[str, FileDiff]] = field(default_factory=list)


def _collapse(name: str, node: _TreeDir) -> tuple[str, _TreeDir]:
    while not node.files and len(node.dirs) == 1:
        child_name, child = next(iter(node.dirs.items()))
        name = f"{name}/{child_name}"
        node = child
    return name, node


def _render_tree(
    node: _TreeDir, anchors: Mapping[str, str], viewed: set[str], prefix: str
) -> SafeHTML:
    items: list[str] = []
    for raw_name in sorted(node.dirs, key=str.lower):
        name, child = _collapse(raw_name, node.dirs[raw_name])
        full = f"{prefix}{name}"
        inner = _render_tree(child, anchors, viewed, full + "/")
        items.append(
            html_t(
                t'<li class="diff-tree-dir" data-dir="{full}"><span class="diff-tree-dirname" title="{full}">{name}</span><ul class="diff-tree-list">{inner}</ul></li>'
            )
        )
    for name, diff in sorted(node.files, key=lambda item: item[0].lower()):
        path = diff.path
        anchor = anchors.get(path) or file_anchor(path)
        status = diff.status
        icon = _STATUS_ICONS[status]
        label = _STATUS_LABELS[status]
        is_viewed = safe_html(" is-viewed" if path in viewed else "")
        items.append(
            html_t(
                t'<li class="diff-tree-file diff-tree-{status}{is_viewed}" data-path="{path}"><a href="#{anchor}" title="{path}"><span class="diff-tree-icon" title="{label}" aria-label="{label}">{icon}</span><span class="diff-tree-name">{name}</span><span class="diff-tree-tick" aria-label="Viewed">✓</span></a></li>'
            )
        )
    return join_html(items)


def render_file_tree(
    files: Sequence[FileDiff], *, anchors: Mapping[str, str], viewed: set[str]
) -> SafeHTML:
    """Nested changed-files tree with a filter box; single-child dirs are collapsed."""
    root = _TreeDir()
    for diff in files:
        parts = diff.path.split("/")
        node = root
        for part in parts[:-1]:
            node = node.dirs.setdefault(part, _TreeDir())
        node.files.append((parts[-1], diff))
    tree = _render_tree(root, anchors, viewed, "")
    return safe_html(
        html_t(
            t'<nav class="diff-tree" aria-label="Changed files">'
            t'<input type="search" class="diff-tree-filter" placeholder="Filter changed files" aria-label="Filter changed files">'
            t'<ul class="diff-tree-list diff-tree-root">{tree}</ul>'
            t'<p class="diff-tree-empty" hidden>No matching files.</p>'
            t"</nav>"
        )
    )


# ============================================================
# Suggestions and comment forms
# ============================================================

_SUGGESTION_RE = re.compile(
    r"^[ \t]*```suggestion[ \t]*\r?\n(.*?)^[ \t]*```[ \t]*\r?$", re.MULTILINE | re.DOTALL
)


def extract_suggestion(body: str) -> str | None:
    """Contents of the first ```suggestion block (``""`` = delete the lines), else None."""
    match = _SUGGESTION_RE.search(body)
    if match is None:
        return None
    content = match.group(1).replace("\r\n", "\n")
    if content.endswith("\n"):
        content = content[:-1]
    return content


def render_suggestion(original: Sequence[str], suggestion: str) -> SafeHTML:
    """Small diff box showing original lines removed and suggested lines added."""
    rows: list[str] = []
    for text in original:
        rows.append(
            html_t(
                t'<tr class="diff-line diff-del"><td class="diff-code-cell diff-code-del"><span class="diff-marker">-</span><code class="diff-code">{text}</code></td></tr>'
            )
        )
    added = suggestion.split("\n") if suggestion != "" else []
    for text in added:
        rows.append(
            html_t(
                t'<tr class="diff-line diff-add"><td class="diff-code-cell diff-code-add"><span class="diff-marker">+</span><code class="diff-code">{text}</code></td></tr>'
            )
        )
    body = join_html(rows)
    return safe_html(
        html_t(
            t'<div class="suggestion-box"><div class="suggestion-header">Suggested change</div>'
            t'<table class="diff-table suggestion-table"><tbody>{body}</tbody></table></div>'
        )
    )


def comment_form(
    *,
    action: str,
    review_pending: bool,
    cancel: bool = True,
    reply_to_thread: int | None = None,
) -> SafeHTML:
    """POST form for a new line comment or a thread reply (CSRF is injected server-side)."""
    if reply_to_thread is not None:
        hidden = safe_html(
            html_t(t'<input type="hidden" name="thread_id" value="{reply_to_thread}">')
        )
        suggestion_button = safe_html("")
        placeholder = "Reply…"
    else:
        hidden = safe_html(
            '<input type="hidden" name="path" value="">'
            '<input type="hidden" name="side" value="">'
            '<input type="hidden" name="line" value="">'
            '<input type="hidden" name="start_line" value="">'
            '<input type="hidden" name="start_side" value="">'
        )
        suggestion_button = safe_html(
            '<button type="button" class="btn btn-sm diff-insert-suggestion" '
            'title="Insert a code suggestion for the selected lines">Insert suggestion</button>'
        )
        placeholder = "Leave a comment"
    if review_pending:
        submits = safe_html(
            '<button type="submit" name="mode" value="review">Add review comment</button>'
        )
    else:
        submits = safe_html(
            '<button type="submit" class="secondary" name="mode" value="single">'
            "Add single comment</button>"
            '<button type="submit" name="mode" value="review">Start a review</button>'
        )
    cancel_html = (
        safe_html('<button type="button" class="btn diff-cancel">Cancel</button>')
        if cancel
        else safe_html("")
    )
    return safe_html(
        html_t(
            t'<form method="POST" action="{action}" class="diff-comment-form">'
            t"{hidden}"
            t'<textarea name="body" required rows="4" placeholder="{placeholder}" aria-label="Comment body"></textarea>'
            t'<div class="diff-comment-actions">{suggestion_button}<span class="diff-comment-spacer"></span>{cancel_html}{submits}</div>'
            t"</form>"
        )
    )


def comment_form_template(
    *,
    action: str,
    review_pending: bool,
    cancel: bool = True,
) -> SafeHTML:
    """``comment_form`` wrapped in ``<template id="diff-comment-template">`` for JS cloning."""
    form = comment_form(action=action, review_pending=review_pending, cancel=cancel)
    return safe_html(html_t(t'<template id="diff-comment-template">{form}</template>'))
