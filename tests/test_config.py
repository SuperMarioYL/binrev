"""Tests for the persisted configuration (~/.binrev/config.json).

Config owns the only state binrev writes on the user's machine, so its
failure contract matters: reading never moves the user's file, a write
preserves unparseable bytes (renamed to a ``.corrupt-<nanoseconds>``
sibling) before overwriting them, and every command keeps working with
fresh defaults so ``binrev config set`` can repair in place.  Unknown or
non-string keys inside an otherwise valid file are dropped, not fatal.  The
file carries an API key, so it is created 0600.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

from binrev.config import Config


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


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


def test_corrupt_config_load_leaves_file_and_warns(tmp_path: Path, capsys):
    """Reading config must not move the user's file; it only falls back to defaults."""
    p = tmp_path / "config.json"
    p.write_text("{ not valid json !!", encoding="utf-8")

    cfg = Config.load(p)

    assert cfg.ghidra_path is None
    assert cfg.llm.api_key == ""
    assert "unreadable" in capsys.readouterr().err
    assert p.read_text(encoding="utf-8") == "{ not valid json !!"
    assert list(tmp_path.glob("config.json.corrupt-*")) == []


def test_non_object_config_load_leaves_file(tmp_path: Path):
    p = tmp_path / "config.json"
    p.write_text("[1, 2, 3]", encoding="utf-8")

    cfg = Config.load(p)

    assert cfg.llm.api_key == ""
    assert p.exists()
    assert list(tmp_path.glob("config.json.corrupt-*")) == []


def test_save_preserves_corrupt_file_before_overwriting_it(tmp_path: Path, capsys):
    """The write that would destroy the bytes is the one that preserves them."""
    p = tmp_path / "config.json"
    p.write_text("{ not valid json !!", encoding="utf-8")

    cfg = Config(ghidra_path="/opt/ghidra")
    cfg.llm.api_key = "fresh-key-for-tests"
    cfg.save(p)

    siblings = list(tmp_path.glob("config.json.corrupt-*"))
    assert len(siblings) == 1
    assert siblings[0].read_text(encoding="utf-8") == "{ not valid json !!"
    assert Config.load(p).llm.api_key == "fresh-key-for-tests"
    assert "unreadable" in capsys.readouterr().err


def test_saved_config_is_not_group_or_world_readable(tmp_path: Path):
    """The file holds the LLM API key; only its owner may read it."""
    p = tmp_path / "config.json"
    cfg = Config()
    cfg.llm.api_key = "fake-key-for-tests"
    cfg.save(p)

    assert _mode(p) == 0o600


def test_save_tightens_an_existing_world_readable_config(tmp_path: Path):
    p = tmp_path / "config.json"
    p.write_text("{}\n", encoding="utf-8")
    p.chmod(0o644)

    Config().save(p)

    assert _mode(p) == 0o600


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
