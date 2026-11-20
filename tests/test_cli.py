"""Tests for the binrev CLI surface — invoked in-process via click's CliRunner.

Covers the backend routing of ``binrev inspect``: a configured + available
Ghidra is honored, and the capstone path stays the automatic fallback.  The
GhidraBridge is stubbed so no Ghidra install (or real binary) is needed.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

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

    ghidra_path = None
    llm = SimpleNamespace(api_key="fake-stub-key", base_url="http://stub.local", model="stub")

    @classmethod
    def load(cls) -> "_StubConfig":
        return cls()

    def is_llm_ready(self) -> bool:
        return bool(self.llm.api_key)


class _StubConfigNoKey(_StubConfig):
    """A config whose LLM key is unset — `run` must exit 1 with a clean hint."""

    llm = SimpleNamespace(api_key="", base_url="http://stub.local", model="stub")


class _StubAgentClient:
    """Replaces binrev.cli.OpenAICompatibleClient; answers with one done call."""

    def __init__(self, llm=None, model=None):
        pass

    def chat_completions_create(self, *, messages, tools, model):
        msg = SimpleNamespace(
            content="",
            tool_calls=[
                SimpleNamespace(
                    id="c1",
                    function=SimpleNamespace(
                        name="done",
                        arguments=json.dumps({"summary": "firmware drives a UART console"}),
                    ),
                )
            ],
        )
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


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


def test_inspect_bad_func_addr_is_a_clean_usage_error(arm_raw_file, monkeypatch):
    """--func with a non-address fails like --isa: one line, exit 2, no traceback."""
    _StubBridge.available = True
    monkeypatch.setattr("binrev.cli.GhidraBridge", _StubBridge)
    monkeypatch.setattr("binrev.cli.Config", _StubConfig)
    result = CliRunner().invoke(
        cli, ["inspect", str(arm_raw_file), "--func", "notahexaddr"]
    )
    assert result.exit_code == 2
    assert "notahexaddr" in result.output
    assert not isinstance(result.exception, ValueError)


def test_inspect_decimal_func_addr_still_parses(arm_raw_file, monkeypatch):
    """int(x, 0) semantics kept: a decimal address keeps working."""
    _StubBridge.available = True
    monkeypatch.setattr("binrev.cli.GhidraBridge", _StubBridge)
    monkeypatch.setattr("binrev.cli.Config", _StubConfig)
    result = CliRunner().invoke(cli, ["inspect", str(arm_raw_file), "--func", "0"])
    assert result.exit_code == 0
    assert "entry" in result.output


# --------------------------------------------------------------------- config


def _use_isolated_config(monkeypatch, tmp_path: Path) -> Path:
    """Point both config-module resolution and the CLI's imported path at tmp."""
    import binrev.cli as cli_module
    import binrev.config as config_module

    cfg_path = tmp_path / "config.json"
    monkeypatch.setattr(config_module, "CONFIG_PATH", cfg_path)
    monkeypatch.setattr(cli_module, "CONFIG_PATH", cfg_path)
    return cfg_path


def test_config_set_then_show_roundtrip(tmp_path, monkeypatch):
    cfg_path = _use_isolated_config(monkeypatch, tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli, ["config", "set", "--api-key", "fakekey-123456", "--model", "qwen-plus"]
    )
    assert result.exit_code == 0
    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert data["llm"]["api_key"] == "fakekey-123456"
    assert data["llm"]["model"] == "qwen-plus"

    shown = runner.invoke(cli, ["config", "show"])
    assert shown.exit_code == 0
    assert "fakeke" in shown.output  # first 6 chars survive the mask
    assert "fakekey-123456" not in shown.output  # never the whole key


def test_config_show_without_config_is_unset(tmp_path, monkeypatch):
    _use_isolated_config(monkeypatch, tmp_path)
    result = CliRunner().invoke(cli, ["config", "show"])
    assert result.exit_code == 0
    assert "(unset)" in result.output


def test_config_set_repairs_a_corrupt_config(tmp_path, monkeypatch):
    """The repair contract: corrupt file preserved, `config set` succeeds, key saved."""
    cfg_path = _use_isolated_config(monkeypatch, tmp_path)
    cfg_path.write_text("{ broken", encoding="utf-8")

    result = CliRunner().invoke(cli, ["config", "set", "--api-key", "freshkey-99"])

    assert result.exit_code == 0
    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert data["llm"]["api_key"] == "freshkey-99"
    assert list(tmp_path.glob("config.json.corrupt-*"))  # evidence preserved


def test_config_show_leaves_a_corrupt_config_in_place(tmp_path, monkeypatch):
    """`config show` only displays: it must not move the user's file."""
    cfg_path = _use_isolated_config(monkeypatch, tmp_path)
    cfg_path.write_text("{ broken", encoding="utf-8")

    result = CliRunner().invoke(cli, ["config", "show"])

    assert result.exit_code == 0
    assert cfg_path.read_text(encoding="utf-8") == "{ broken"
    assert list(tmp_path.glob("config.json.corrupt-*")) == []



# ------------------------------------------------------------------------ run


def test_run_question_answers_through_the_agent(arm_raw_file, monkeypatch):
    """`binrev run fw.bin -q ...` — the product's main entry point, end to end."""
    _StubBridge.available = True
    monkeypatch.setattr("binrev.cli.GhidraBridge", _StubBridge)
    monkeypatch.setattr("binrev.cli.Config", _StubConfig)
    monkeypatch.setattr("binrev.cli.OpenAICompatibleClient", _StubAgentClient)

    result = CliRunner().invoke(cli, ["run", str(arm_raw_file), "-q", "what is this?"])

    assert result.exit_code == 0
    assert "firmware drives a UART console" in result.output


def test_run_without_key_exits_cleanly(arm_raw_file, monkeypatch):
    _StubBridge.available = True
    monkeypatch.setattr("binrev.cli.GhidraBridge", _StubBridge)
    monkeypatch.setattr("binrev.cli.Config", _StubConfigNoKey)

    result = CliRunner().invoke(cli, ["run", str(arm_raw_file), "-q", "hi"])

    assert result.exit_code == 1
    assert "no LLM key configured" in result.output
