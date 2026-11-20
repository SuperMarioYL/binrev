"""The agent loop — Qwen/DeepSeek over a binary action space.

The agent holds a :class:`~binrev.binst.BinState` and lets the LLM drive a
binary action space: it decompiles functions, follows cross-references,
searches strings and records notes across steps, then emits a conclusion
that cites function addresses.  This is the half of the primitive that a
text/shell agent (one that only reads Ghidra stdout) cannot reach.

The LLM is any OpenAI-compatible endpoint (Qwen DashScope, DeepSeek).  The
client is injected so tests can mock it without real API keys — the response
schema from the provider is currently unverified, hence the defensive
parsing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from .binst import BinState
from .config import LLMConfig
from .models import ToolCall, ToolResult
from .tools import ToolRegistry

SYSTEM_PROMPT = """You are binrev, a binary-action-space reverse-engineering agent.
You operate on a BinState: decompiled functions, cross-references, ISA metadata and a string table held as first-class objects — not a Ghidra CLI stdout log.

Use the tools to investigate the binary. Cite function addresses (0x...) in your conclusions. Write notes (set_note) for findings you want to persist across steps. Call `done` with your final conclusion when you have answered the user's question.

BinState summary: {summary}
"""


class LLMClient(Protocol):
    """Minimal chat-completions interface the agent needs.

    Any OpenAI-compatible client (real or mock) that exposes
    ``chat_completions_create`` satisfies this.
    """

    def chat_completions_create(
        self, *, messages: list[dict], tools: list[dict], model: str
    ) -> Any: ...


@dataclass
class OpenAICompatibleClient:
    """Adapter over the ``openai`` SDK for Qwen / DeepSeek endpoints."""

    llm: LLMConfig

    def __post_init__(self) -> None:
        from openai import OpenAI  # local import: not needed for inspect/tests

        self._client = OpenAI(base_url=self.llm.base_url, api_key=self.llm.api_key or "unset")

    def chat_completions_create(
        self, *, messages: list[dict], tools: list[dict], model: str
    ) -> Any:
        return self._client.chat.completions.create(
            model=model, messages=messages, tools=tools, tool_choice="auto"
        )


@dataclass
class BinrevAgent:
    """Drives an LLM over the binary action space of a BinState."""

    state: BinState
    client: LLMClient
    model: str = "qwen-plus"
    max_steps: int = 12
    registry: ToolRegistry = field(init=False)
    history: list[dict] = field(init=False, default_factory=list)
    steps_log: list[tuple[list[ToolCall], list[ToolResult]]] = field(init=False, default_factory=list)
    final_summary: Optional[str] = None

    def __post_init__(self) -> None:
        self.registry = ToolRegistry(state=self.state)
        self.history.append(
            {"role": "system", "content": SYSTEM_PROMPT.format(summary=self.state.summary())}
        )

    def ask(self, question: str) -> str:
        """Answer a user question by running the tool-calling loop."""
        self.history.append({"role": "user", "content": question})
        # Each question owns its answer: a stale summary from an earlier turn
        # must never be returned as this turn's result.
        self.final_summary = None
        for _ in range(self.max_steps):
            response = self.client.chat_completions_create(
                messages=self.history,
                tools=self.registry.schemas(),
                model=self.model,
            )
            msg = _response_message(response)
            tool_calls = _parse_tool_calls(msg)
            # Always record the assistant turn so the model sees its own history.
            self.history.append(_assistant_turn(msg, tool_calls))
            if not tool_calls:
                self.final_summary = _content(msg)
                return self.final_summary
            results = self.registry.dispatch_many(tool_calls)
            self.steps_log.append((tool_calls, results))
            self.history.extend(_tool_messages(results))
            if any(tc.name == "done" for tc in tool_calls):
                done_call = next(tc for tc in tool_calls if tc.name == "done")
                self.final_summary = done_call.arguments.get("summary", "")
                return self.final_summary
        self.final_summary = "(agent reached step limit without a done call)"
        return self.final_summary


# ---------------------------------------------------------------------------
# Defensive parsing of the LLM response.  The provider schema is unverified,
# so every accessor tolerates missing keys / attribute fallbacks.
# ---------------------------------------------------------------------------


def _response_message(response: Any) -> Any:
    """Extract the assistant ``message`` object from a chat completion."""
    choices = getattr(response, "choices", None)
    if choices is None and isinstance(response, dict):
        choices = response.get("choices")
    if not choices:
        return {}
    choice = choices[0]
    return getattr(choice, "message", None) or (choice.get("message") if isinstance(choice, dict) else {})


def _content(msg: Any) -> str:
    if isinstance(msg, dict):
        return msg.get("content") or ""
    return getattr(msg, "content", "") or ""


def _parse_tool_calls(msg: Any) -> list[ToolCall]:
    raw = getattr(msg, "tool_calls", None) if not isinstance(msg, dict) else msg.get("tool_calls")
    if not raw:
        return []
    calls: list[ToolCall] = []
    for tc in raw:
        tid = getattr(tc, "id", None) or tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", "")
        fn = getattr(tc, "function", None)
        if fn is None and isinstance(tc, dict):
            fn = tc.get("function", {})
        if fn is None:
            fn = {}
        name = getattr(fn, "name", None) or (fn.get("name") if isinstance(fn, dict) else "")
        args_raw = getattr(fn, "arguments", None) if not isinstance(fn, dict) else fn.get("arguments")
        if args_raw is None:
            args_raw = "{}"
        if isinstance(args_raw, str):
            try:
                args = json.loads(args_raw)
            except json.JSONDecodeError:
                args = {}
        elif isinstance(args_raw, dict):
            args = args_raw
        else:
            args = {}
        calls.append(ToolCall(id=tid or "", name=name, arguments=args))
    return calls


def _assistant_turn(msg: Any, tool_calls: list[ToolCall]) -> dict:
    """Rebuild the assistant message dict for history (serializable)."""
    return {
        "role": "assistant",
        "content": _content(msg),
        "tool_calls": [
            {"id": tc.id, "type": "function", "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)}}
            for tc in tool_calls
        ]
        or None,
    }


def _tool_messages(results: list[ToolResult]) -> list[dict]:
    return [{"role": "tool", "tool_call_id": r.tool_call_id, "content": r.content} for r in results]
