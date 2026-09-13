"""Version lockstep test — every release surface must agree.

``binrev.__version__`` is the single source of truth; this test fails CI the
moment a bump touches only some surfaces. All checks are in-process
(tomllib + json + click's CliRunner) — no subprocesses, no binaries.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

from click.testing import CliRunner

from binrev import __version__
from binrev.cli import cli

REPO_ROOT = Path(__file__).resolve().parent.parent
_REPO_URL = "https://github.com/SuperMarioYL/binrev"


def test_version_surfaces_agree():
    version_file = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert version_file == __version__

    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == __version__

    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"binrev, version {__version__}"


def test_site_json_content_version_matches():
    site = json.loads((REPO_ROOT / "web" / "site.json").read_text(encoding="utf-8"))
    assert site["meta"]["content_version"] == f"v{__version__}"


def test_changelog_covers_current_version():
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{__version__}]" in changelog
    assert f"[{__version__}]: {_REPO_URL}/releases/tag/v{__version__}" in changelog
    assert f"[Unreleased]: {_REPO_URL}/compare/v{__version__}...HEAD" in changelog
