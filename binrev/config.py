"""Configuration — Ghidra path, LLM endpoint and API key.

Stored as a small JSON file (``~/.binrev/config.json``) so ``binrev config
set`` persists across sessions.  The LLM section targets the OpenAI-compatible
APIs offered by Qwen (DashScope) and DeepSeek.

The file is user-editable, so :meth:`Config.load` treats it as untrusted
input: an unreadable file is left where the user put it and fresh defaults
are returned instead of a traceback, so read-only commands (``inspect``,
``config show``) never mutate ``~/.binrev``.  The bytes that cannot be parsed
are preserved as a ``<name>.corrupt-<nanoseconds>`` sibling by
:meth:`Config.save`, at the moment a write would otherwise destroy a possibly
recoverable API key, and ``binrev config set`` repairs in place.  Inside an
otherwise valid file, keys with unknown names or non-string values are
dropped, degrading to the CLI's clean "no LLM key configured" message rather
than crashing.
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, asdict, fields
from pathlib import Path
from typing import Optional

CONFIG_DIR = Path.home() / ".binrev"
CONFIG_PATH = CONFIG_DIR / "config.json"

# Sensible defaults for the two supported model families.
_MODEL_TARGETS = {
    "qwen": {"model": "qwen-plus", "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1"},
    "deepseek": {"model": "deepseek-chat", "base_url": "https://api.deepseek.com"},
}


@dataclass
class LLMConfig:
    """OpenAI-compatible LLM endpoint (Qwen / DeepSeek)."""

    base_url: str = _MODEL_TARGETS["qwen"]["base_url"]
    api_key: str = ""
    model: str = _MODEL_TARGETS["qwen"]["model"]

    @property
    def target(self) -> str:
        """Which model family this endpoint points at."""
        if "deepseek" in self.base_url:
            return "deepseek"
        if "dashscope" in self.base_url or "qwen" in self.model:
            return "qwen"
        return "custom"


_LLM_FIELDS = {f.name for f in fields(LLMConfig)}


def _clean_llm(raw: object) -> LLMConfig:
    """Accept only known, string-valued llm keys; drop anything else."""
    if not isinstance(raw, dict):
        return LLMConfig()
    return LLMConfig(**{k: v for k, v in raw.items() if k in _LLM_FIELDS and isinstance(v, str)})


def _parse(text: str) -> dict:
    """Decode a config document, rejecting anything that is not a JSON object."""
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    return data


@dataclass
class Config:
    """Persisted binrev configuration."""

    ghidra_path: Optional[str] = None
    llm: LLMConfig = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.llm is None:
            self.llm = LLMConfig()

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Config":
        path = path or CONFIG_PATH
        if not path.exists():
            return cls()
        try:
            data = _parse(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:  # JSONDecodeError / UnicodeDecodeError / unreadable
            # Reading is not writing: the file stays where the user put it and
            # the next save preserves it before overwriting.
            print(
                f"warning: {path} is unreadable ({exc}); using defaults — "
                "`binrev config set` preserves it before rewriting",
                file=sys.stderr,
            )
            return cls()
        ghidra = data.get("ghidra_path")
        return cls(
            ghidra_path=ghidra if isinstance(ghidra, str) else None,
            llm=_clean_llm(data.get("llm", {})),
        )

    @classmethod
    def _preserve_unreadable(cls, path: Path) -> None:
        """Rename an unparseable config out of the way before it is overwritten.

        The write is the moment the bytes would be lost — possibly a
        recoverable API key — so preservation belongs here, not on load.
        Best-effort: if the rename fails we warn and continue rather than
        turning this into a new crash path.
        """
        if not path.exists():
            return
        try:
            _parse(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            backup = path.with_name(f"{path.name}.corrupt-{time.time_ns()}")
            try:
                path.rename(backup)
                note = f"preserved as {backup.name}"
            except OSError:
                note = "it could not be preserved"
            print(
                f"warning: {path} is unreadable ({exc}); {note} — writing a fresh config",
                file=sys.stderr,
            )

    def save(self, path: Optional[Path] = None) -> None:
        path = path or CONFIG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        self._preserve_unreadable(path)
        # The file holds an API key: create it 0600, and chmod afterwards
        # because O_CREAT leaves an existing file's (possibly 0644) mode alone.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(self), indent=2, ensure_ascii=False))
        os.chmod(path, 0o600)

    def apply_target(self, target: str) -> None:
        """Point the LLM config at a known model family (qwen / deepseek)."""
        if target not in _MODEL_TARGETS:
            raise ValueError(f"unknown model target {target!r}; pick one of {list(_MODEL_TARGETS)}")
        preset = _MODEL_TARGETS[target]
        self.llm.base_url = preset["base_url"]
        self.llm.model = preset["model"]

    def is_llm_ready(self) -> bool:
        return bool(self.llm.api_key)
