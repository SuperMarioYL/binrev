"""Tests for the binrev CLI surface — invoked in-process via click's CliRunner.

Covers the backend routing of ``binrev inspect``: a configured + available
Ghidra is honored, and the capstone path stays the automatic fallback.  The
GhidraBridge is stubbed so no Ghidra install (or real binary) is needed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("capstone", reason="capstone not installed in this env")

from click.testing import CliRunner  # noqa: E402

from binrev import build_from_bytes  # noqa: E402
from binrev.cli import cli  # noqa: E402
from binrev.models import ISAKind  # noqa: E402


class _StubBridge:
    """Replaces binrev.cli.GhidraBridge; `available` decides the routing."""

    available: bool = True

    def __init__(self, ghidra_path=None):
        pass

    def is_available(self) -> bool:
        return self.available

    def dump(self, binary: Path, isa_kind: ISAKind):
        state = build_from_bytes(binary.read_bytes(), ISAKind.ARM, base_addr=0, entry=0)
        state.source = "ghidra"
        return state


class _StubConfig:
    """Replaces binrev.cli.Config so no ~/.binrev/config.json is read."""

    def __init__(self):
        self.ghidra_path = None

    @classmethod
    def load(cls) -> "_StubConfig":
        return cls()


def _invoke_inspect(monkeypatch, available: bool, raw_file: Path):
    _StubBridge.available = available
    monkeypatch.setattr("binrev.cli.GhidraBridge", _StubBridge)
    monkeypatch.setattr("binrev.cli.Config", _StubConfig)
    return CliRunner().invoke(cli, ["inspect", str(raw_file), "--isa", "arm"])


def test_inspect_uses_ghidra_when_available(arm_raw_file, monkeypatch):
    result = _invoke_inspect(monkeypatch, available=True, raw_file=arm_raw_file)
    assert result.exit_code == 0
    assert "ghidra" in result.output


def test_inspect_falls_back_to_capstone(arm_raw_file, monkeypatch):
    result = _invoke_inspect(monkeypatch, available=False, raw_file=arm_raw_file)
    assert result.exit_code == 0
    assert "capstone" in result.output
