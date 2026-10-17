"""Tests for the persisted configuration (~/.binrev/config.json).

Config owns the only state binrev writes on the user's machine, so its
failure contract matters: a corrupt file must be preserved (renamed to a
``.corrupt-<nanoseconds>`` sibling) and every command must keep working with
fresh defaults, so ``binrev config set`` can repair in place.  Unknown or
non-string keys inside an otherwise valid file are dropped, not fatal.
"""

from __future__ import annotations

import json
from pathlib import Path

from binrev.config import Config


def test_save_load_roundtrip(tmp_path: Path):
    cfg = Config(ghidra_path="/opt/ghidra")
    cfg.llm.api_key = "fake-key-for-tests"
    cfg.llm.model = "qwen-plus"
    p = tmp_path / "config.json"
    cfg.save(p)

    loaded = Config.load(p)
    assert loaded.ghidra_path == "/opt/ghidra"
    assert loaded.llm.api_key == "fake-key-for-tests"
    assert loaded.llm.model == "qwen-plus"
    assert loaded.is_llm_ready()


def test_load_missing_file_returns_defaults(tmp_path: Path):
    cfg = Config.load(tmp_path / "absent.json")
    assert cfg.ghidra_path is None
    assert cfg.llm.api_key == ""
    assert not cfg.is_llm_ready()


def test_corrupt_config_preserved_and_fresh_defaults(tmp_path: Path, capsys):
    p = tmp_path / "config.json"
    p.write_text("{ not valid json !!", encoding="utf-8")

    cfg = Config.load(p)

    assert cfg.ghidra_path is None
    assert cfg.llm.api_key == ""
    siblings = list(tmp_path.glob("config.json.corrupt-*"))
    assert len(siblings) == 1
    assert siblings[0].read_text(encoding="utf-8") == "{ not valid json !!"
    assert "unreadable" in capsys.readouterr().err


def test_non_object_config_quarantined(tmp_path: Path):
    p = tmp_path / "config.json"
    p.write_text("[1, 2, 3]", encoding="utf-8")

    cfg = Config.load(p)

    assert cfg.llm.api_key == ""
    assert len(list(tmp_path.glob("config.json.corrupt-*"))) == 1


def test_unknown_llm_key_and_non_str_values_dropped(tmp_path: Path):
    p = tmp_path / "config.json"
    p.write_text(
        json.dumps({"llm": {"model": "qwen-plus", "typo_key": True, "api_key": 12345}}),
        encoding="utf-8",
    )

    cfg = Config.load(p)

    assert cfg.llm.model == "qwen-plus"
    assert cfg.llm.api_key == ""
    assert not cfg.is_llm_ready()
