"""Starter files (.gitignore templates and licenses) for newly created repositories."""

import datetime
from pathlib import Path

_ROOT = Path(__file__).parent

# Display name -> template file. Keys are also the accepted API values.
GITIGNORE_TEMPLATES: dict[str, str] = {
    name: name + ".gitignore" for name in ("C", "C#", "C++", "Go", "Java", "Node", "Python", "Rust")
}
LICENSES: dict[str, str] = {
    "MIT": "MIT License",
    "Apache-2.0": "Apache License 2.0",
    "GPL-3.0": "GNU General Public License v3.0",
    "MPL-2.0": "Mozilla Public License 2.0",
    "BSD-3-Clause": "BSD 3-Clause License",
    "Unlicense": "The Unlicense",
}


def initial_files(
    repo: str,
    *,
    readme: bool = False,
    gitignore: str = "",
    license: str = "",
    holder: str = "",
) -> dict[str, bytes]:
    """Return the requested starter files; unknown template names raise KeyError."""
    files: dict[str, bytes] = {}
    if readme:
        files["README.md"] = f"# {repo}\n".encode()
    if gitignore:
        files[".gitignore"] = (_ROOT / "gitignore" / GITIGNORE_TEMPLATES[gitignore]).read_bytes()
    if license:
        if license not in LICENSES:
            raise KeyError(license)
        text = (_ROOT / "licenses" / (license + ".txt")).read_text("utf-8")
        year = str(datetime.date.today().year)
        text = text.replace("[year]", year).replace("[fullname]", holder or repo)
        files["LICENSE"] = text.encode()
    return files
