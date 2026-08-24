"""Binary action space — the tools the agent calls on a BinState.

Unlike a text/shell agent that reads Ghidra stdout, binrev's agent operates on
*first-class binary objects*: it decompiles a function, follows a cross
reference, enumerates functions, searches the string table and records its own
reasoning notes — all as structured reads/writes against :class:`BinState`.

Each tool here has a stable name, a JSON-schema argument description (so the
OpenAI-compatible function-calling API can call it) and a dispatcher that
returns a string the LLM reads back as tool output.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .binst import BinState
from .models import Addr, ToolCall, ToolResult

# A tool callable: takes the BinState + parsed args, returns a string.
ToolFn = Callable[[BinState, dict[str, Any]], str]


@dataclass
class Tool:
    """One binary action-space tool."""

    name: str
    description: str
    parameters: dict[str, Any]  # JSON-schema for the function-calling API
    fn: ToolFn


def _fmt_func(state: BinState, addr: int) -> str:
    f = state.decompile(addr)
    if f is None:
        return f"no function at 0x{addr:08x}; known funcs: " + ", ".join(
            f"0x{a:08x}" for a in state.list_funcs()[:8]
        )
    refs = state.xrefs_to(addr)
    callers = "\n".join(f"  0x{x.from_addr:08x} ({x.kind.value})" for x in refs) or "  (none)"
    note = state.notes.get(addr, "")
    parts = [
        f"function {f.name} @ 0x{f.addr:08x}  ({f.size} bytes, src={state.source})",
        f"callers:\n{callers}",
        "decompilation:",
        f.decompilation or "  (empty)",
    ]
    if note:
        parts.append(f"note: {note}")
    return "\n".join(parts)


def _tool_decompile(state: BinState, args: dict[str, Any]) -> str:
    addr = int(args["addr"], 0) if isinstance(args.get("addr"), str) else int(args["addr"])
    return _fmt_func(state, addr)


def _tool_xrefs(state: BinState, args: dict[str, Any]) -> str:
    addr = int(args["addr"], 0) if isinstance(args.get("addr"), str) else int(args["addr"])
    refs = state.xrefs_to(addr)
    if not refs:
        return f"no xrefs to 0x{addr:08x}"
    return "xrefs to 0x{:08x}:\n".format(addr) + "\n".join(
        f"  0x{x.from_addr:08x}  {x.kind.value}" for x in refs
    )


def _tool_list_funcs(state: BinState, args: dict[str, Any]) -> str:
    flt = args.get("filter", "")
    addrs = state.list_funcs(flt)
    if not addrs:
        return "no functions match"
    return f"{len(addrs)} functions:\n" + "\n".join(
        f"  0x{a:08x}  {state.functions[a].name}" for a in addrs[:64]
    ) + (f"\n... ({len(addrs) - 64} more)" if len(addrs) > 64 else "")


def _tool_search_strings(state: BinState, args: dict[str, Any]) -> str:
    pat = args.get("pattern", "")
    hits = state.search_strings(pat)
    if not hits:
        return f'no strings matching "{pat}"'
    return f"{len(hits)} strings:\n" + "\n".join(
        f"  0x{s.addr:08x}  {s.value!r}" for s in hits[:64]
    ) + (f"\n... ({len(hits) - 64} more)" if len(hits) > 64 else "")


def _tool_set_note(state: BinState, args: dict[str, Any]) -> str:
    addr = int(args["addr"], 0) if isinstance(args.get("addr"), str) else int(args["addr"])
    text = args.get("text", "")
    state.set_note(addr, text)
    return f"noted 0x{addr:08x}: {text}"


# ``done`` is a sentinel: the agent calls it to emit its final conclusion.  It
# carries no BinState read; the agent loop treats a ``done`` call as the stop
# signal and surfaces the summary to the user.
def _tool_done(state: BinState, args: dict[str, Any]) -> str:
    return args.get("summary", "")


def _schema_addr(desc: str) -> dict[str, Any]:
    return {"type": "string", "description": desc}


_TOOLS: list[Tool] = [
    Tool(
        name="decompile",
        description="Return the decompilation/disassembly of the function at the given address, plus its callers.",
        parameters={
            "type": "object",
            "properties": {"addr": _schema_addr("function entry address, e.g. 0x1000")},
            "required": ["addr"],
        },
        fn=_tool_decompile,
    ),
    Tool(
        name="xrefs",
        description="List every cross reference that targets the given address (who calls / references it).",
        parameters={
            "type": "object",
            "properties": {"addr": _schema_addr("address to look up references to")},
            "required": ["addr"],
        },
        fn=_tool_xrefs,
    ),
    Tool(
        name="list_funcs",
        description="Enumerate function entry addresses, optionally filtered by a name substring.",
        parameters={
            "type": "object",
            "properties": {"filter": {"type": "string", "description": "optional name substring", "default": ""}},
        },
        fn=_tool_list_funcs,
    ),
    Tool(
        name="search_strings",
        description="Search the binary's string table for a substring.",
        parameters={
            "type": "object",
            "properties": {"pattern": {"type": "string", "description": "substring to search for"}},
            "required": ["pattern"],
        },
        fn=_tool_search_strings,
    ),
    Tool(
        name="set_note",
        description="Record a cross-step reasoning note for an address — persisted across the session as BinState memory.",
        parameters={
            "type": "object",
            "properties": {
                "addr": _schema_addr("address the note concerns"),
                "text": {"type": "string", "description": "the reasoning note"},
            },
            "required": ["addr", "text"],
        },
        fn=_tool_set_note,
    ),
    Tool(
        name="done",
        description="Emit the final conclusion for the session and stop. The summary is shown to the user.",
        parameters={
            "type": "object",
            "properties": {"summary": {"type": "string", "description": "final conclusion, cite function addresses"}},
            "required": ["summary"],
        },
        fn=_tool_done,
    ),
]


@dataclass
class ToolRegistry:
    """Holds the binary action-space tools and dispatches LLM tool calls."""

    state: BinState
    _tools: dict[str, Tool] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        self._tools = {t.name: t for t in _TOOLS}

    def schemas(self) -> list[dict[str, Any]]:
        """Return the OpenAI-compatible function schemas for the LLM."""
        return [
            {"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.parameters}}
            for t in self._tools.values()
        ]

    def dispatch(self, call: ToolCall) -> ToolResult:
        """Run a tool call against the held BinState and return its result."""
        tool = self._tools.get(call.name)
        if tool is None:
            return ToolResult(tool_call_id=call.id, name=call.name, content=f"unknown tool: {call.name}")
        try:
            content = tool.fn(self.state, call.arguments)
        except Exception as exc:  # surface the error to the model rather than crash
            content = f"tool error: {exc}"
        return ToolResult(tool_call_id=call.id, name=call.name, content=content)

    def dispatch_many(self, calls: list[ToolCall]) -> list[ToolResult]:
        return [self.dispatch(c) for c in calls]

    @property
    def tool_names(self) -> list[str]:
        return list(self._tools)
