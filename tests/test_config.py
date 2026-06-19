import json
import tempfile
import unittest
from pathlib import Path

from pygithost.config import AppConfig


class AppConfigTests(unittest.TestCase):
    def test_mapping_merges_defaults_and_normalizes_ips(self):
        config = AppConfig.from_mapping({
            "platform": "Linux",
            "port": "9000",
            "allowed_client_ips": "127.0.0.1, 10.0.0.2",
        })
        self.assertEqual(config.port, 9000)
        self.assertEqual(config.allowed_client_ips, ("127.0.0.1", "10.0.0.2"))

    def test_file_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = AppConfig.default_for_platform("Linux")
            original.write(path)
            loaded = AppConfig.from_file(path)
            self.assertEqual(loaded, original)
            self.assertIsInstance(json.loads(path.read_text()), dict)

    def test_invalid_port_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "port"):
            AppConfig.from_mapping({"platform": "Linux", "port": 70000})
