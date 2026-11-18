"""Runtime coverage for generalized, statically typed helper interfaces."""

import asyncio
import tempfile
import unittest
from pathlib import Path

from pygithost.config import AppConfig
from pygithost.rendering import SafeHTML, join_html, safe_html


class _ConfigPath:
    def __init__(self, path: Path) -> None:
        self.path = path

    def __fspath__(self) -> str:
        return str(self.path)


class TypingContractTests(unittest.TestCase):
    def test_configuration_accepts_pathlike_implementations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = _ConfigPath(Path(directory) / "config.json")
            original = AppConfig.default_for_platform("Linux")
            self.assertEqual(original.write(path), Path(path))
            self.assertEqual(AppConfig.from_file(path), original)

    def test_platform_defaults_keep_their_path_shapes(self) -> None:
        for platform in ("Linux", "Darwin", "Windows"):
            with self.subTest(platform=platform):
                config = AppConfig.default_for_platform(platform)
                self.assertIsInstance(config.git_project_root, str)
                self.assertIsInstance(config.git_http_backend, str)
                self.assertIsInstance(config.db_path, str)
                self.assertIsInstance(config.log_file, str)
                self.assertTrue(config.trace_log is None or isinstance(config.trace_log, str))

    def test_join_html_accepts_safe_html_iterables(self) -> None:
        fragments = [safe_html("<b>one</b>"), safe_html("<i>two</i>")]
        result = join_html(fragment for fragment in fragments)
        self.assertIsInstance(result, SafeHTML)
        self.assertEqual(result, "<b>one</b><i>two</i>")

    def test_join_html_accepts_immutable_sequences(self) -> None:
        self.assertEqual(join_html(("<b>", "text", "</b>")), "<b>text</b>")


class ReaderTypingContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_body_reader_keeps_keyword_read_size(self) -> None:
        from pygithost.application import BodyReader

        stream = asyncio.StreamReader()
        stream.feed_data(b"body")
        stream.feed_eof()
        reader = BodyReader(stream, b"prefix")
        self.assertEqual(await reader.read(n=3), b"pre")
        self.assertEqual(await reader.readexactly(n=4), b"fixb")
        self.assertEqual(await reader.read(), b"ody")
