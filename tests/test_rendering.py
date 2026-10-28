import unittest

from pygithost.application import _html_page


class PageLayoutTests(unittest.TestCase):
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
