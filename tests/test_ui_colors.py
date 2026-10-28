from pathlib import Path
import re
import unittest


def contrast(first, second):
    def luminance(color):
        channels = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [value / 12.92 if value <= .04045 else ((value + .055) / 1.055) ** 2.4 for value in channels]
        return sum(weight * value for weight, value in zip((.2126, .7152, .0722), linear))
    light, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (light + .05) / (dark + .05)


class UIColorTests(unittest.TestCase):
    def test_light_and_dark_palettes_have_readable_text(self):
        css = (Path(__file__).resolve().parent.parent / "static" / "ui.css").read_text()
        light = dict(re.findall(r"(--[\w-]+):\s*(#[\da-f]{6})", re.search(r":root\s*\{([^}]+)\}", css)[1]))
        dark = {**light, **dict(re.findall(r"(--[\w-]+):\s*(#[\da-f]{6})", re.search(r'html\[data-theme="dark"\]\s*\{([^}]+)\}', css)[1]))}
        for theme, palette in (("light", light), ("dark", dark)):
            for foreground, background in (("--fg", "--bg"), ("--fg", "--box"),
                    ("--muted", "--bg"), ("--muted", "--box"), ("--link", "--bg"),
                    ("--link", "--accent-bg"), ("--button-fg", "--button-bg"),
                    ("--button-fg", "--button-hover"), ("--danger-fg", "--danger-bg"),
                    ("--ok-fg", "--ok-bg"), ("--warn-fg", "--warn-bg"),
                    ("--error-fg", "--error-bg"), ("--input-fg", "--input-bg")):
                with self.subTest(theme=theme, foreground=foreground, background=background):
                    self.assertGreaterEqual(contrast(palette[foreground], palette[background]), 4.5)
            with self.subTest(theme=theme, control="input border"):
                self.assertGreaterEqual(contrast(palette["--control-border"], palette["--input-bg"]), 3)
