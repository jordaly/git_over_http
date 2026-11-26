"""Every web form that changes state has a documented REST equivalent."""

import ast
import inspect
import textwrap
import unittest

from pygithost import application, pull_pages
from pygithost.api import parity
from pygithost.api.schema import specification


def _ui_post_routes() -> set[str]:
    """Literal paths and regexes routed by GitHTTPHandler.do_POST."""
    source = textwrap.dedent(inspect.getsource(application.GitHTTPHandler.do_POST))
    routes: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "match"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "re"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            routes.add(node.args[0].value)
        if isinstance(node, ast.Compare) and ast.unparse(node.left) == "parsed.path":
            for comparator in node.comparators:
                if isinstance(comparator, ast.Constant):
                    routes.add(comparator.value)
                elif isinstance(comparator, ast.Tuple):
                    routes.update(c.value for c in comparator.elts if isinstance(c, ast.Constant))
                elif isinstance(comparator, ast.Name):
                    routes.add(comparator.id)
    # The generic repository prefix check is a guard, not a route.
    routes.discard(r"^/r/([^/]+)/([^/]+)/")
    return routes


class APIParityTests(unittest.TestCase):
    def setUp(self):
        self.paths = specification()["paths"]

    def assertDocumented(self, endpoints, route):
        for method, path in endpoints:
            with self.subTest(route=route, endpoint=f"{method.upper()} {path}"):
                self.assertIn(path, self.paths, f"{path} is not in the OpenAPI document")
                self.assertIn(method, self.paths[path], f"{method.upper()} {path} is missing")

    def test_every_web_form_route_has_an_api_decision(self):
        routes = _ui_post_routes()
        self.assertGreater(len(routes), 40)
        missing = sorted(routes - set(parity.UI_ROUTES))
        self.assertEqual(missing, [], "Add these UI POST routes to pygithost/api/parity.py")
        stale = sorted(set(parity.UI_ROUTES) - routes)
        self.assertEqual(stale, [], "parity.py lists routes the UI no longer has")

    def test_every_pull_request_form_action_has_an_api_endpoint(self):
        self.assertEqual(set(pull_pages.ACTIONS), set(parity.PULL_ACTIONS))
        for action, endpoints in parity.PULL_ACTIONS.items():
            self.assertTrue(endpoints, action)
            self.assertDocumented(endpoints, action)

    def test_mapped_endpoints_exist_in_the_api(self):
        for route, endpoints in parity.UI_ROUTES.items():
            if isinstance(endpoints, str):
                self.assertTrue(endpoints.strip(), f"{route} needs a reason")
                continue
            self.assertDocumented(endpoints, route)


if __name__ == "__main__":
    unittest.main()
