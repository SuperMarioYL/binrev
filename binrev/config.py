"""Configuration — Ghidra path, LLM endpoint and API key.

Stored as a small JSON file (``~/.binrev/config.json``) so ``binrev config
set`` persists across sessions.  The LLM section targets the OpenAI-compatible
APIs offered by Qwen (DashScope) and DeepSeek.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
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


@dataclass
class Config:
    """Persisted binrev configuration."""

    ghidra_path: Optional[str] = None
    llm: LLMConfig = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.llm is None:
            self.llm = LLMConfig()

    @classmethod
    def load(cls, path: Path = CONFIG_PATH) -> "Config":
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        llm_raw = data.get("llm", {})
        return cls(
            ghidra_path=data.get("ghidra_path"),
            llm=LLMConfig(**llm_raw),
        )

    def save(self, path: Path = CONFIG_PATH) -> None:
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
