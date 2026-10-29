import unittest

from pygithost.application import _html_page, _pagination


class PageLayoutTests(unittest.TestCase):
    def test_pagination_has_clear_boundary_states(self):
        first = str(_pagination("/items", {}, 1, True))
        self.assertIn('class="pagination"', first)
        self.assertIn('aria-disabled="true"', first)
        self.assertNotIn('rel="prev"', first)
        self.assertIn('rel="next"', first)
        self.assertIn('aria-current="page">Page 1', first)
        last = str(_pagination("/items", {"q": "a&b"}, 8, False))
        self.assertIn('rel="prev"', last)
        self.assertNotIn('rel="next"', last)
        self.assertIn('aria-label="Go to first page"', last)
        self.assertIn("q=a%26b&amp;page=1", last)
        self.assertIn('class="pagination-ellipsis"', last)

    def test_pagination_includes_first_last_totals_without_extra_forms(self):
        markup = str(_pagination("/items", {"q": "needle"}, 5, True, total=95, per_page=10))
        self.assertIn('aria-label="Go to first page"', markup)
        self.assertIn('aria-label="Go to last page"', markup)
        self.assertIn("page=10&amp;per_page=10", markup)
        self.assertIn("Showing 41–50 of 95", markup)
        self.assertIn("Page 5 of 10", markup)
        self.assertIn("q=needle&amp;page=10", markup)
        self.assertNotIn("<form", markup)
        self.assertNotIn("Rows per page", markup)
        self.assertNotIn("Go to page <input", markup)

    def test_wide_page_uses_full_width_body_class(self):
        page = _html_page("Source", "content", wide=True).decode("utf-8")
        self.assertIn('<body class="wide-page">', page)

    def test_regular_page_keeps_constrained_layout(self):
        page = _html_page("Home", "content").decode("utf-8")
        self.assertIn('<body class="">', page)

    def test_shared_header_and_style_order(self):
        page = _html_page("Settings", "page-content").decode("utf-8")
        header = page.split('<header class="app-header">', 1)[1].split("</header>", 1)[0]
        self.assertIn('aria-label="Workspace navigation"', header)
        self.assertIn('id="theme-toggle"', header)
        self.assertLess(page.index("</header>"), page.index("page-content"))
        self.assertLess(page.index('/static/ui.css'), page.index('/static/ci.css'))
        self.assertLess(page.index('/static/ui.css'), page.index('/static/repository.css'))
