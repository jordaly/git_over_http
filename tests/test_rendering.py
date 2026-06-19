import unittest

from pygithost.application import _html_page


class PageLayoutTests(unittest.TestCase):
    def test_wide_page_uses_full_width_body_class(self):
        page = _html_page("Source", "content", wide=True).decode("utf-8")
        self.assertIn('<body class="wide-page">', page)

    def test_regular_page_keeps_constrained_layout(self):
        page = _html_page("Home", "content").decode("utf-8")
        self.assertIn('<body class="">', page)
