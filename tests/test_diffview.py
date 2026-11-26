import re
import unittest

from pygithost.diffview import (
    LARGE_DIFF_LINES,
    DiffLine,
    FileDiff,
    comment_form,
    comment_form_template,
    diff_line_keys,
    extract_suggestion,
    file_anchor,
    parse_unified_diff,
    render_file,
    render_file_tree,
    render_suggestion,
)
from pygithost.rendering import SafeHTML, safe_html

MODIFIED = """\
diff --git a/f.txt b/f.txt
index 988f966..52c7308 100644
--- a/f.txt
+++ b/f.txt
@@ -1,5 +1,5 @@
 a
-b
+B
 c
 d
 e
@@ -9,5 +9,6 @@ def section():
 i
 j
 k
-l
+L
 m
+n
\\ No newline at end of file
"""

ADDED = """\
diff --git a/new.py b/new.py
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+print(1)
+print(2)
"""

DELETED = """\
diff --git a/gone.txt b/gone.txt
deleted file mode 100644
index abaddc0..0000000
--- a/gone.txt
+++ /dev/null
@@ -1 +0,0 @@
-del
"""

RENAME_PURE = """\
diff --git a/old.txt b/new name.txt
similarity index 100%
rename from old.txt
rename to new name.txt
"""

RENAME_CHANGED = """\
diff --git a/ren.txt b/ren2.txt
similarity index 83%
rename from ren.txt
rename to ren2.txt
index b3c5a95..5fcb7b1 100644
--- a/ren.txt
+++ b/ren2.txt
@@ -3,3 +3,4 @@ line2
 line3
 line4
 line5
+line6
"""

COPIED = """\
diff --git a/src.c b/dst.c
similarity index 90%
copy from src.c
copy to dst.c
index 1..2 100644
--- a/src.c
+++ b/dst.c
@@ -1 +1 @@
-int a;
+int b;
"""

MODE_ONLY = """\
diff --git a/run.sh b/run.sh
old mode 100644
new mode 100755
"""

BINARY = """\
diff --git a/img.png b/img.png
index bdc955b..8835708 100644
Binary files a/img.png and b/img.png differ
"""

GIT_BINARY_PATCH = """\
diff --git a/blob.bin b/blob.bin
new file mode 100644
index 0000000..aaaaaaa
GIT binary patch
literal 4
LcmZQzWMT#Y01f~L

literal 0
HcmV?d00001

diff --git a/after.txt b/after.txt
--- a/after.txt
+++ b/after.txt
@@ -1 +1 @@
-x
+y
"""

QUOTED = """\
diff --git "a/sp\\303\\251cial \\"q\\".txt" "b/sp\\303\\251cial \\"q\\".txt"
index 45b983b..7cc3903 100644
--- "a/sp\\303\\251cial \\"q\\".txt"\t
+++ "b/sp\\303\\251cial \\"q\\".txt"\t
@@ -1 +1 @@
-hi
+hi2
"""

SPACES = """\
diff --git a/dir with space/file name.txt b/dir with space/file name.txt
index 1..2 100644
--- a/dir with space/file name.txt\t
+++ b/dir with space/file name.txt\t
@@ -1 +1 @@
-x
+y
"""

EMPTY_ADDED = """\
diff --git a/empty.txt b/empty.txt
new file mode 100644
index 0000000..e69de29
"""

CRLF = "diff --git a/c.txt b/c.txt\r\n--- a/c.txt\r\n+++ b/c.txt\r\n@@ -1,2 +1,2 @@\r\n x\r\n-y\r\n+z\r\n"


def parse_one(text: str) -> FileDiff:
    files = parse_unified_diff(text)
    assert len(files) == 1, files
    return files[0]


def render(diff: FileDiff, **kwargs: object) -> str:
    options: dict[str, object] = {
        "anchor": "diff-x",
        "mode": "unified",
        "threads": {},
        "can_comment": True,
        "viewed": False,
    }
    options.update(kwargs)
    return render_file(diff, **options)  # type: ignore[arg-type]


class ParseTests(unittest.TestCase):
    def test_modified_multiple_hunks(self) -> None:
        diff = parse_one(MODIFIED)
        self.assertEqual(diff.path, "f.txt")
        self.assertEqual(diff.status, "modified")
        self.assertIsNone(diff.old_path)
        self.assertEqual((diff.additions, diff.deletions), (3, 2))
        self.assertEqual(len(diff.hunks), 2)
        first, second = diff.hunks
        self.assertEqual(
            (first.old_start, first.old_count, first.new_start, first.new_count), (1, 5, 1, 5)
        )
        self.assertEqual(second.section, "def section():")
        self.assertEqual(first.lines[1], DiffLine("del", 2, None, "b"))
        self.assertEqual(first.lines[2], DiffLine("add", None, 2, "B"))
        self.assertEqual(first.lines[3], DiffLine("context", 3, 3, "c"))
        self.assertEqual(
            [(line.kind, line.old, line.new) for line in second.lines],
            [
                ("context", 9, 9),
                ("context", 10, 10),
                ("context", 11, 11),
                ("del", 12, None),
                ("add", None, 12),
                ("context", 13, 13),
                ("add", None, 14),
            ],
        )
        self.assertTrue(second.lines[-1].no_newline)
        self.assertFalse(any(line.no_newline for line in second.lines[:-1]))

    def test_added_and_deleted(self) -> None:
        added = parse_one(ADDED)
        self.assertEqual((added.status, added.path, added.new_mode), ("added", "new.py", "100644"))
        self.assertEqual(added.additions, 2)
        self.assertEqual([line.new for line in added.hunks[0].lines], [1, 2])
        deleted = parse_one(DELETED)
        self.assertEqual(
            (deleted.status, deleted.path, deleted.old_mode), ("deleted", "gone.txt", "100644")
        )
        self.assertEqual(deleted.hunks[0].lines[0], DiffLine("del", 1, None, "del"))
        self.assertEqual((deleted.hunks[0].new_start, deleted.hunks[0].new_count), (0, 0))

    def test_renames(self) -> None:
        pure = parse_one(RENAME_PURE)
        self.assertEqual(
            (pure.status, pure.path, pure.old_path), ("renamed", "new name.txt", "old.txt")
        )
        self.assertEqual(pure.hunks, ())
        changed = parse_one(RENAME_CHANGED)
        self.assertEqual(
            (changed.status, changed.path, changed.old_path), ("renamed", "ren2.txt", "ren.txt")
        )
        self.assertEqual(changed.additions, 1)
        self.assertEqual(changed.hunks[0].lines[-1], DiffLine("add", None, 6, "line6"))

    def test_copied(self) -> None:
        diff = parse_one(COPIED)
        self.assertEqual((diff.status, diff.path, diff.old_path), ("copied", "dst.c", "src.c"))
        self.assertEqual((diff.additions, diff.deletions), (1, 1))

    def test_mode_change_only(self) -> None:
        diff = parse_one(MODE_ONLY)
        self.assertEqual(diff.status, "modified")
        self.assertEqual((diff.old_mode, diff.new_mode), ("100644", "100755"))
        self.assertEqual(diff.hunks, ())
        self.assertIn("100644 → 100755", render(diff))

    def test_binary(self) -> None:
        diff = parse_one(BINARY)
        self.assertTrue(diff.binary)
        self.assertIn("Binary file not shown.", render(diff))
        files = parse_unified_diff(GIT_BINARY_PATCH)
        self.assertEqual([f.path for f in files], ["blob.bin", "after.txt"])
        self.assertTrue(files[0].binary)
        self.assertEqual(files[0].status, "added")
        self.assertEqual(files[0].hunks, ())
        self.assertEqual((files[1].additions, files[1].deletions), (1, 1))

    def test_quoted_and_space_paths(self) -> None:
        diff = parse_one(QUOTED)
        self.assertEqual(diff.path, 'spécial "q".txt')
        self.assertEqual(diff.additions, 1)
        spaced = parse_one(SPACES)
        self.assertEqual(spaced.path, "dir with space/file name.txt")
        # Header-only (no ---/+++ lines) still resolves paths with spaces.
        header_only = parse_one("diff --git a/a b/c b/a b/c\nold mode 100644\nnew mode 100755\n")
        self.assertEqual(header_only.path, "a b/c")

    def test_omitted_counts(self) -> None:
        diff = parse_one(DELETED)
        hunk = diff.hunks[0]
        self.assertEqual((hunk.old_start, hunk.old_count), (1, 1))
        quoted = parse_one(QUOTED).hunks[0]
        self.assertEqual((quoted.old_count, quoted.new_count), (1, 1))

    def test_empty_added_file(self) -> None:
        diff = parse_one(EMPTY_ADDED)
        self.assertEqual((diff.status, diff.hunks, diff.binary), ("added", (), False))
        self.assertIn("Empty file.", render(diff))

    def test_crlf(self) -> None:
        diff = parse_one(CRLF)
        texts = [line.text for line in diff.hunks[0].lines]
        self.assertEqual(texts, ["x", "y", "z"])
        self.assertEqual(diff.path, "c.txt")

    def test_truncation_per_file(self) -> None:
        body = "".join(f"+line {i}\n" for i in range(50))
        text = f"diff --git a/big b/big\n--- a/big\n+++ b/big\n@@ -0,0 +1,50 @@\n{body}" + ADDED
        files = parse_unified_diff(text, max_lines_per_file=10)
        self.assertEqual(len(files), 2)
        self.assertTrue(files[0].truncated)
        self.assertEqual(sum(len(h.lines) for h in files[0].hunks), 10)
        self.assertEqual(files[0].additions, 50)
        self.assertFalse(files[1].truncated)
        self.assertIn("Diff truncated.", render(files[0]))
        exact = parse_unified_diff(ADDED, max_lines_per_file=2)[0]
        self.assertFalse(exact.truncated)

    def test_truncated_marker(self) -> None:
        text = MODIFIED + ADDED[: ADDED.index("+print(2)")] + "+pri\n\n[... truncated ...]\n"
        files = parse_unified_diff(text)
        self.assertEqual([f.path for f in files], ["f.txt", "new.py"])
        self.assertFalse(files[0].truncated)
        self.assertTrue(files[1].truncated)
        self.assertEqual([line.text for line in files[1].hunks[0].lines], ["print(1)", "pri"])

    def test_deleted_line_looking_like_header(self) -> None:
        text = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +1,1 @@\n--- not a header\n keep\n"
        diff = parse_one(text)
        self.assertEqual(diff.hunks[0].lines[0], DiffLine("del", 1, None, "-- not a header"))
        self.assertEqual(diff.deletions, 1)


class RenderTests(unittest.TestCase):
    def test_unified_attributes(self) -> None:
        diff = parse_one(MODIFIED)
        html = render(diff, anchor="diff-abc")
        self.assertIsInstance(html, SafeHTML)
        self.assertIn('<table class="diff-table diff-unified">', html)
        self.assertIn('data-side="LEFT" data-line="2"', html)
        self.assertIn('data-side="RIGHT" data-line="2"', html)
        self.assertIn('id="diff-abc-R2"', html)
        self.assertIn('id="diff-abc-L12"', html.replace('id="diff-abc-R12"', ""))
        self.assertIn(
            '<button type="button" class="diff-add-comment" data-side="LEFT" data-line="2" '
            'aria-label="Comment on line 2">+</button>',
            html,
        )
        self.assertIn('data-text="B"', html)
        self.assertIn('<span class="diff-marker">+</span><code class="diff-code">B</code>', html)
        self.assertIn(
            '<td class="diff-hunk-header" colspan="3">@@ -9,5 +9,6 @@ def section():</td>', html
        )
        self.assertIn(" open>", html)
        self.assertIn('data-path="f.txt"', html)
        self.assertIn('<input type="checkbox" class="diff-viewed" data-path="f.txt">', html)

    def test_split_pairs_and_attributes(self) -> None:
        diff = parse_one(MODIFIED)
        html = render(diff, mode="split")
        self.assertIn('<table class="diff-table diff-split">', html)
        self.assertIn('colspan="4"', html)
        # The deleted "b" (old 2) and added "B" (new 2) share a row.
        row = re.search(
            r'<tr class="diff-line diff-has-del diff-has-add" id="diff-x-R2">.*?</tr>', html
        )
        assert row is not None
        self.assertIn('data-side="LEFT" data-line="2"', row.group(0))
        self.assertIn('data-side="RIGHT" data-line="2"', row.group(0))
        # The unpaired added "n" has an empty left side.
        row14 = re.search(r'<tr class="diff-line diff-has-add" id="diff-x-R14">.*?</tr>', html)
        assert row14 is not None
        self.assertIn("diff-empty", row14.group(0))
        self.assertIn('class="diff-add-comment" data-side="LEFT"', html)
        self.assertIn('class="diff-add-comment" data-side="RIGHT"', html)

    def test_threads_unified(self) -> None:
        diff = parse_one(MODIFIED)
        threads = {
            ("RIGHT", 12): safe_html('<div class="review-thread">RIGHT12</div>'),
            ("LEFT", 2): safe_html('<div class="review-thread">LEFT2</div>'),
        }
        html = render(diff, threads=threads)
        right = html.index("RIGHT12")
        self.assertLess(html.index('id="diff-x-R12"'), right)
        self.assertLess(right, html.index('id="diff-x-R13"'))
        left = html.index("LEFT2")
        self.assertLess(html.index('id="diff-x-L2"'), left)
        self.assertLess(left, html.index('id="diff-x-R2"'))
        self.assertIn(
            '<td class="diff-thread-cell" colspan="3"><div class="review-thread">RIGHT12', html
        )

    def test_threads_split(self) -> None:
        diff = parse_one(MODIFIED)
        threads = {
            ("LEFT", 2): safe_html("<p>OLD</p>"),
            ("RIGHT", 14): safe_html("<p>NEW</p>"),
        }
        html = render(diff, mode="split", threads=threads)
        self.assertIn(
            '<tr class="diff-thread-row"><td class="diff-thread-cell" colspan="2" data-side="LEFT"><p>OLD</p></td>'
            '<td class="diff-thread-empty" colspan="2"></td></tr>',
            html,
        )
        self.assertIn(
            '<tr class="diff-thread-row"><td class="diff-thread-empty" colspan="2"></td>'
            '<td class="diff-thread-cell" colspan="2" data-side="RIGHT"><p>NEW</p></td></tr>',
            html,
        )
        self.assertLess(html.index('id="diff-x-R2"'), html.index("OLD"))
        self.assertLess(html.index('id="diff-x-R14"'), html.index("NEW"))

    def test_escaping(self) -> None:
        text = (
            'diff --git "a/x\\"<b>.js" "b/x\\"<b>.js"\n'
            '--- "a/x\\"<b>.js"\n+++ "b/x\\"<b>.js"\n'
            "@@ -1 +1 @@ <img src=x onerror=alert(1)>\n-</script>\n+<script>alert('x')</script>\n"
        )
        diff = parse_one(text)
        self.assertEqual(diff.path, 'x"<b>.js')
        html = render(diff, mode="split") + render(diff)
        self.assertNotIn("<script>", html)
        self.assertNotIn("</script>", html)
        self.assertNotIn("<img", html)
        self.assertNotIn("<b>", html)
        self.assertIn("&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;", html)
        self.assertIn('data-path="x&quot;&lt;b&gt;.js"', html)
        self.assertIn('data-lang="javascript"', html)
        tree = render_file_tree([diff], anchors={}, viewed=set())
        self.assertNotIn("<b>", tree)

    def test_can_comment_false(self) -> None:
        diff = parse_one(MODIFIED)
        self.assertNotIn("diff-add-comment", render(diff, can_comment=False))
        self.assertNotIn("diff-add-comment", render(diff, can_comment=False, mode="split"))

    def test_viewed_and_collapsed(self) -> None:
        diff = parse_one(MODIFIED)
        viewed = render(diff, viewed=True)
        opening = viewed[: viewed.index(">")]
        self.assertNotIn(" open", opening)
        self.assertIn('class="diff-viewed" data-path="f.txt" checked>', viewed)
        collapsed = render(diff, collapsed=True)
        self.assertNotIn(" open", collapsed[: collapsed.index(">")])

    def test_large_diff_placeholder(self) -> None:
        count = LARGE_DIFF_LINES + 1
        body = "".join(f"+{i}\n" for i in range(count))
        diff = parse_one(
            f"diff --git a/b.txt b/b.txt\n--- a/b.txt\n+++ b/b.txt\n@@ -0,0 +1,{count} @@\n{body}"
        )
        html = render(diff)
        self.assertIn('<div class="diff-large">', html)
        self.assertIn('<button type="button" class="btn diff-load">Load diff</button>', html)
        template = html.index("<template")
        self.assertLess(template, html.index("<table"))
        small = render(parse_one(ADDED))
        self.assertNotIn("diff-large", small)

    def test_rename_header(self) -> None:
        html = render(parse_one(RENAME_PURE))
        self.assertIn(
            '<span class="diff-old-path">old.txt</span> → <span class="diff-new-path">new name.txt</span>',
            html,
        )
        self.assertIn("File renamed without changes.", html)
        self.assertIn("diff-status-renamed", html)

    def test_file_anchor(self) -> None:
        self.assertEqual(file_anchor("a/b.py"), file_anchor("a/b.py"))
        self.assertNotEqual(file_anchor("a/b.py"), file_anchor("a/c.py"))
        self.assertRegex(file_anchor("x"), r"^diff-[0-9a-f]{16}$")

    def test_diff_line_keys(self) -> None:
        keys = diff_line_keys(parse_one(MODIFIED))
        self.assertIn(("LEFT", 12), keys)
        self.assertIn(("RIGHT", 14), keys)
        self.assertNotIn(("RIGHT", 7), keys)


class TreeTests(unittest.TestCase):
    def test_nesting_and_collapse(self) -> None:
        files = [
            FileDiff("src/pkg/deep/a.py", None, "modified", False, (), 1, 0, False, None, None),
            FileDiff("src/pkg/deep/b.py", None, "added", False, (), 1, 0, False, None, None),
            FileDiff("README.md", None, "deleted", False, (), 0, 1, False, None, None),
            FileDiff("docs/x.md", "docs/y.md", "renamed", False, (), 0, 0, False, None, None),
        ]
        html = render_file_tree(files, anchors={"README.md": "custom-anchor"}, viewed={"README.md"})
        self.assertIn(
            '<input type="search" class="diff-tree-filter" placeholder="Filter changed files"', html
        )
        self.assertIn(
            '<span class="diff-tree-dirname" title="src/pkg/deep">src/pkg/deep</span>', html
        )
        self.assertNotIn('title="src">src<', html)
        self.assertIn('href="#custom-anchor"', html)
        self.assertIn(f'href="#{file_anchor("src/pkg/deep/a.py")}"', html)
        self.assertIn(
            'class="diff-tree-file diff-tree-deleted is-viewed" data-path="README.md"', html
        )
        self.assertIn('class="diff-tree-file diff-tree-added" data-path="src/pkg/deep/b.py"', html)
        self.assertIn("diff-tree-renamed", html)
        # a.py and b.py are nested inside the collapsed directory's list.
        directory = html.index('data-dir="src/pkg/deep"')
        self.assertLess(directory, html.index('data-path="src/pkg/deep/a.py"'))


class SuggestionTests(unittest.TestCase):
    def test_extract(self) -> None:
        body = "Try this:\n```suggestion\nfoo()\nbar()\n```\nthanks\n```suggestion\nother\n```"
        self.assertEqual(extract_suggestion(body), "foo()\nbar()")
        self.assertEqual(extract_suggestion("```suggestion\n```"), "")
        self.assertEqual(extract_suggestion("x\r\n```suggestion\r\na\r\n```\r\n"), "a")
        self.assertIsNone(extract_suggestion("no suggestion here\n```python\nx\n```"))
        self.assertIsNone(extract_suggestion("```suggestion\nunterminated"))

    def test_render(self) -> None:
        html = render_suggestion(["old <1>", "old 2"], "new <x>")
        self.assertIn('class="suggestion-box"', html)
        self.assertEqual(html.count("diff-code-del"), 2)
        self.assertEqual(html.count("diff-code-add"), 1)
        self.assertIn("new &lt;x&gt;", html)
        self.assertNotIn("<x>", html)
        deletion = render_suggestion(["gone"], "")
        self.assertEqual(deletion.count("diff-code-add"), 0)


class CommentFormTests(unittest.TestCase):
    def test_new_comment_form(self) -> None:
        html = comment_form(action="/r/o/p/pull/1/comments", review_pending=False)
        self.assertIn(
            '<form method="POST" action="/r/o/p/pull/1/comments" class="diff-comment-form">', html
        )
        for name in ("path", "side", "line", "start_line", "start_side"):
            self.assertIn(f'<input type="hidden" name="{name}" value="">', html)
        self.assertNotIn("csrf", html)
        self.assertNotIn("thread_id", html)
        self.assertIn('<textarea name="body" required', html)
        self.assertIn("diff-insert-suggestion", html)
        self.assertIn('name="mode" value="single">Add single comment</button>', html)
        self.assertIn('name="mode" value="review">Start a review</button>', html)
        self.assertNotIn("Add review comment", html)
        self.assertIn("diff-cancel", html)

    def test_pending_review_and_reply(self) -> None:
        html = comment_form(
            action="/c?a=1&b=2", review_pending=True, cancel=False, reply_to_thread=7
        )
        self.assertIn('action="/c?a=1&amp;b=2"', html)
        self.assertIn('<input type="hidden" name="thread_id" value="7">', html)
        self.assertNotIn('name="path"', html)
        self.assertIn('name="mode" value="review">Add review comment</button>', html)
        self.assertNotIn('value="single"', html)
        self.assertNotIn("diff-cancel", html)
        self.assertNotIn("csrf", html)

    def test_template(self) -> None:
        html = comment_form_template(action="/x", review_pending=False)
        self.assertTrue(html.startswith('<template id="diff-comment-template"><form method="POST"'))
        self.assertTrue(html.endswith("</form></template>"))


if __name__ == "__main__":
    unittest.main()
