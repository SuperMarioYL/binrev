"""Configuration — Ghidra path, LLM endpoint and API key.

Stored as a small JSON file (``~/.binrev/config.json``) so ``binrev config
set`` persists across sessions.  The LLM section targets the OpenAI-compatible
APIs offered by Qwen (DashScope) and DeepSeek.

The file is user-editable, so :meth:`Config.load` treats it as untrusted
input: an unreadable file is preserved as a ``<name>.corrupt-<nanoseconds>``
sibling (a broken API key may still be recoverable) and fresh defaults are
returned instead of a traceback, letting ``binrev config set`` repair in
place.  Inside an otherwise valid file, keys with unknown names or
non-string values are dropped, degrading to the CLI's clean "no LLM key
configured" message rather than crashing.
"""

from __future__ import annotations

import json
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
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("config must be a JSON object")
        except (ValueError, OSError) as exc:  # JSONDecodeError / UnicodeDecodeError / unreadable
            return cls._quarantine(path, exc)
        ghidra = data.get("ghidra_path")
        return cls(
            ghidra_path=ghidra if isinstance(ghidra, str) else None,
            llm=_clean_llm(data.get("llm", {})),
        )

    @classmethod
    def _quarantine(cls, path: Path, exc: Exception) -> "Config":
        """Preserve an unreadable config beside itself and start fresh.

        The next successful ``config set`` would otherwise overwrite the
        corrupt bytes — possibly a recoverable API key — so they are renamed
        out of the way first.  Preservation is best-effort: if the rename
        fails we warn and continue rather than turning this into a new crash
        path.
        """
        backup = path.with_name(f"{path.name}.corrupt-{time.time_ns()}")
        try:
            path.rename(backup)
            note = f"preserved as {backup.name}"
        except OSError:
            note = "it could not be preserved"
        print(
            f"warning: {path} is unreadable ({exc}); {note} — starting fresh",
            file=sys.stderr,
        )
        return cls()

    def save(self, path: Optional[Path] = None) -> None:
        path = path or CONFIG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(asdict(self), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def apply_target(self, target: str) -> None:
        """Point the LLM config at a known model family (qwen / deepseek)."""
        if target not in _MODEL_TARGETS:
            raise ValueError(f"unknown model target {target!r}; pick one of {list(_MODEL_TARGETS)}")
        preset = _MODEL_TARGETS[target]
        self.llm.base_url = preset["base_url"]
        self.llm.model = preset["model"]

    def is_llm_ready(self) -> bool:
        return bool(self.llm.api_key)
