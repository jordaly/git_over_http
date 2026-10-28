"""Dependency-free, metadata-only repository language estimates."""

import asyncio
import json
from pathlib import PurePosixPath

from . import database


# Intentionally conservative: data files, lockfiles, images and unknown suffixes
# do not contribute. This is an estimate, not GitHub Linguist's full classifier.
LANGUAGES = {
    "Python": ("#3572a5", ".py .pyw .pyi"),
    "C#": ("#178600", ".cs .csx"),
    "Visual Basic .NET": ("#945db7", ".vb .vbhtml"),
    "JavaScript": ("#a88600", ".js .mjs .cjs .jsx"),
    "TypeScript": ("#3178c6", ".ts .tsx .mts .cts"),
    "HTML": ("#c74b28", ".html .htm .xhtml"),
    "Razor": ("#8250df", ".cshtml .razor"),
    "CSS": ("#663399", ".css"),
    "SCSS": ("#c6538c", ".scss .sass"),
    "Less": ("#1d365d", ".less"),
    "SQL": ("#b07219", ".sql"),
    "C": ("#707070", ".c .h"),
    "C++": ("#c44378", ".cpp .cc .cxx .hpp .hh .hxx"),
    "Java": ("#b07219", ".java"),
    "Kotlin": ("#a069e8", ".kt .kts"),
    "Go": ("#007d9c", ".go"),
    "Rust": ("#a85c34", ".rs"),
    "Ruby": ("#a91c1c", ".rb .rake .gemspec"),
    "PHP": ("#4f5d95", ".php .phtml"),
    "Swift": ("#d65b3b", ".swift"),
    "Objective-C": ("#438eff", ".m .mm"),
    "Scala": ("#c22d40", ".scala .sc"),
    "Dart": ("#008596", ".dart"),
    "Shell": ("#5a7829", ".sh .bash .zsh"),
    "PowerShell": ("#2863a6", ".ps1 .psm1 .psd1"),
    "Batchfile": ("#607a35", ".bat .cmd"),
    "Lua": ("#5353a5", ".lua"),
    "R": ("#198ce7", ".r"),
    "Perl": ("#306780", ".pl .pm"),
    "Elixir": ("#6e4a7e", ".ex .exs"),
    "Erlang": ("#b83998", ".erl .hrl"),
    "Haskell": ("#5e5086", ".hs .lhs"),
    "F#": ("#378bba", ".fs .fsx .fsi"),
    "Vue": ("#287c54", ".vue"),
    "Svelte": ("#c44216", ".svelte"),
    "Dockerfile": ("#287a9a", ".dockerfile"),
    "Makefile": ("#427819", ".mk"),
}
EXTENSIONS = {extension: name for name, (_color, extensions) in LANGUAGES.items() for extension in extensions.split()}
EXCLUDED_FOLDERS = frozenset({
    ".git", ".venv", "venv", "env", "node_modules", "vendor", "vendors", "packages",
    "third_party", "third-party", "thirdparty", "bower_components", "site-packages",
    "bin", "obj", "dist", "build", "coverage", "__pycache__", ".next", ".nuxt", "prismjs",
})
GENERATED_SUFFIXES = (".min.js", ".min.css", ".designer.cs", ".designer.vb", ".g.cs", ".g.i.cs",
                      ".generated.cs", ".generated.ts", ".generated.js", "_pb2.py", ".pb.go")


def language_totals(tree):
    totals = {}
    for entry in tree.split(b"\0"):
        metadata, separator, filename = entry.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 4 or fields[0] not in (b"100644", b"100755") or fields[1] != b"blob":
            continue
        path = PurePosixPath(filename.decode("utf-8", "replace").casefold())
        if any(part in EXCLUDED_FOLDERS for part in path.parts[:-1]) or path.name.endswith(GENERATED_SUFFIXES):
            continue
        if path.name == "dockerfile" or path.name.startswith("dockerfile."):
            name = "Dockerfile"
        elif path.name in ("makefile", "gnumakefile"):
            name = "Makefile"
        else:
            name = EXTENSIONS.get(path.suffix)
        if not name:
            continue
        try:
            size = int(fields[3])
        except ValueError:
            continue
        if size <= 0:
            continue
        item = totals.setdefault(name, {"name": name, "bytes": 0, "files": 0, "color": LANGUAGES[name][0]})
        item["bytes"] += size
        item["files"] += 1
    total = sum(item["bytes"] for item in totals.values())
    return [{**item, "percentage": item["bytes"] * 100 / total}
            for item in sorted(totals.values(), key=lambda item: (-item["bytes"], item["name"]))]


async def repository_languages(owner, repo, bare, commit):
    if not commit:
        return []
    cached = await asyncio.to_thread(database.db_repository_languages_get, owner, repo, commit)
    if cached is not None:
        return json.loads(cached)
    process = None
    try:
        process = await asyncio.create_subprocess_exec("git", "--git-dir=" + bare, "ls-tree", "-r", "-l", "-z", "--full-tree", commit,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        tree = bytearray()
        async with asyncio.timeout(15):
            while chunk := await process.stdout.read(65536):
                tree.extend(chunk)
                if len(tree) > 32 * 1024 * 1024:
                    return None
            await process.wait()
        if process.returncode:
            return None
        result = await asyncio.to_thread(language_totals, bytes(tree))
        await asyncio.to_thread(database.db_repository_languages_set, owner, repo, commit, json.dumps(result))
        return result
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        if process is not None and process.returncode is None:
            process.kill()
            await process.communicate()
