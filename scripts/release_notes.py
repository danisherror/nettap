#!/usr/bin/env python3
"""Check a release tag and print its CHANGELOG section.

    python scripts/release_notes.py v0.1.0 > notes.md

Fails (exit 1, reason on stderr) unless the tag is v<nettap.__version__>,
the version is X.Y.Z, and CHANGELOG.md has a "## [X.Y.Z] - YYYY-MM-DD"
section. A section still marked "Unreleased" fails too, so the release
commit has to set the date. Used by .github/workflows/release.yml.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def package_version(root: Path = ROOT) -> str:
    text = (root / "nettap" / "__init__.py").read_text()
    m = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        raise ValueError("no __version__ in nettap/__init__.py")
    return m.group(1)


def changelog_section(changelog: str, version: str) -> tuple[str, str]:
    """(date or "Unreleased", body) of the section for version."""
    m = re.search(rf"^## \[{re.escape(version)}\] - (\S+)[ \t]*\n(.*?)(?=^## \[|^\[[^\]]+\]: |\Z)",
                  changelog, re.M | re.S)
    if not m:
        raise ValueError(f"CHANGELOG.md has no '## [{version}] - <date>' section")
    return m.group(1), m.group(2).strip()


def check(tag: str, root: Path = ROOT) -> str:
    """The release notes for tag, or ValueError saying what's wrong."""
    version = package_version(root)
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError(f"version {version!r} isn't X.Y.Z")
    if tag != f"v{version}":
        raise ValueError(f"tag {tag!r} doesn't match nettap/__init__.py (v{version})")
    date, body = changelog_section((root / "CHANGELOG.md").read_text(), version)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise ValueError(f"CHANGELOG.md section for {version} is dated {date!r} - "
                         f"set the release date (YYYY-MM-DD) before tagging")
    return body


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        print(check(argv[1]))
    except ValueError as e:
        print(f"release check failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
