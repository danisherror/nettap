"""Versioning: one version everywhere, and the release check in
scripts/release_notes.py (run by .github/workflows/release.yml)."""
import importlib.util
from pathlib import Path

import pytest
from click.testing import CliRunner

import nettap
from nettap import cli as cli_mod

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("release_notes", ROOT / "scripts" / "release_notes.py")
release_notes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_notes)


def test_version_flag():
    r = CliRunner().invoke(cli_mod.cli, ["--version"])
    assert r.exit_code == 0
    assert r.output.strip() == f"nettap {nettap.__version__}"


def test_current_version_has_a_changelog_section():
    date, body = release_notes.changelog_section((ROOT / "CHANGELOG.md").read_text(),
                                                 nettap.__version__)
    assert body


def _repo(tmp_path, version="1.2.3", heading="## [1.2.3] - 2026-01-02"):
    (tmp_path / "nettap").mkdir()
    (tmp_path / "nettap" / "__init__.py").write_text(f'__version__ = "{version}"\n')
    (tmp_path / "CHANGELOG.md").write_text(
        f"# Changelog\n\n{heading}\n\n### Fixed\n\n- a bug\n\n"
        "## [1.2.2] - 2026-01-01\n\n- older\n\n[1.2.3]: https://example.com\n")
    return tmp_path


def test_release_check_returns_only_that_versions_notes(tmp_path):
    assert release_notes.check("v1.2.3", _repo(tmp_path)) == "### Fixed\n\n- a bug"


@pytest.mark.parametrize("tag,kw,why", [
    ("v1.2.4", {}, "doesn't match"),
    ("1.2.3", {}, "doesn't match"),
    ("v1.2.3", {"heading": "## [1.2.3] - Unreleased"}, "set the release date"),
    ("v1.2.3", {"heading": "## [1.2.0] - 2026-01-02"}, "no '## [1.2.3]"),
    ("v1.2.3rc1", {"version": "1.2.3rc1"}, "isn't X.Y.Z"),
])
def test_release_check_refuses(tmp_path, tag, kw, why):
    with pytest.raises(ValueError, match=__import__("re").escape(why)):
        release_notes.check(tag, _repo(tmp_path, **kw))
