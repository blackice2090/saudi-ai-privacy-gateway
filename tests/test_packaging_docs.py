"""Guard against the old distribution name resurfacing (PKG-001).

The PyPI project was renamed to ``tabayyan-privacy`` in 0.9.1 (the import
namespace stays ``tabayyan``). Any *active* instruction that still says
``pip install tabayyan`` or ``tabayyan[extra]`` sends users to the stale
pre-rename distribution, which collides with this one in the same package
directory. The legacy name may appear only in explicit migration text
(``pip uninstall tabayyan``).
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Files/dirs whose text is user-facing or shipped.
SCAN_DIRS = ["src", "docs", "examples", "playground", "benchmarks"]
SCAN_FILES = [
    "README.md", "README.ar.md", "CHANGELOG.md", "RELEASE.md",
    "PROJECT_REVIEW.md", "pyproject.toml", "Makefile", "Dockerfile",
]
TEXT_SUFFIXES = {".py", ".md", ".txt", ".toml", ".html", ".ipynb", ".yml", ".yaml", ""}

FORBIDDEN = [
    # old extras form: tabayyan[crypto] etc. (the bracket makes it a pip spec)
    re.compile(r"(?<![\w-])tabayyan\["),
    # old install command not followed by -privacy
    re.compile(r"pip install ['\"]?tabayyan(?![\w-])"),
    # old PyPI project links
    re.compile(r"pypi\.org/project/tabayyan/"),
]

ALLOWED_LINE = re.compile(r"pip uninstall tabayyan")  # migration text


def _iter_scanned_files():
    for name in SCAN_FILES:
        p = REPO / name
        if p.is_file():
            yield p
    for d in SCAN_DIRS:
        root = REPO / d
        if not root.is_dir():
            continue
        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in TEXT_SUFFIXES:
                yield p


def test_no_active_references_to_the_old_distribution_name():
    offenders: list[str] = []
    for path in _iter_scanned_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if ALLOWED_LINE.search(line):
                continue
            for pattern in FORBIDDEN:
                if pattern.search(line):
                    offenders.append(f"{path.relative_to(REPO)}:{lineno}: {line.strip()}")
    assert not offenders, (
        "Old 'tabayyan' distribution references found (use 'tabayyan-privacy'):\n"
        + "\n".join(offenders)
    )
