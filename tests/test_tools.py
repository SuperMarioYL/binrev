"""Tests for the binary action space (ToolRegistry) and the agent loop.

The LLM client is mocked — no real Qwen/DeepSeek API keys are required, and
the unverified provider schema is exercised through the agent's defensive
parsers.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

pytest.importorskip("capstone", reason="capstone not installed in this env")

from binrev.agent import BinrevAgent  # noqa: E402
from binrev.binst import build_from_bytes  # noqa: E402
from binrev.models import ISAKind, ToolCall  # noqa: E402
from binrev.tools import ToolRegistry  # noqa: E402


@pytest.fixture
def state(arm_code, base_addr):
    return build_from_bytes(arm_code, ISAKind.ARM, base_addr=base_addr, entry=base_addr)


@pytest.fixture
def entry_addr(base_addr):
    return base_addr


@pytest.fixture
def callee_addr(base_addr):
    return base_addr + 0xC


# --------------------------------------------------------------------------- ToolRegistry


def test_registry_has_six_tools(state):
    reg = ToolRegistry(state=state)
    assert set(reg.tool_names) == {
        "decompile", "xrefs", "list_funcs", "search_strings", "set_note", "done"
    }
    assert len(reg.schemas()) == 6


def test_tool_decompile(state, entry_addr):
    reg = ToolRegistry(state=state)
    res = reg.dispatch(ToolCall(id="t1", name="decompile", arguments={"addr": hex(entry_addr)}))
    assert res.tool_call_id == "t1"
    assert "push" in res.content
    assert "bl" in res.content


def test_tool_xrefs(state, callee_addr):
    reg = ToolRegistry(state=state)
    res = reg.dispatch(ToolCall(id="t2", name="xrefs", arguments={"addr": hex(callee_addr)}))
    assert "call" in res.content
    assert hex(callee_addr) in res.content or f"{callee_addr:08x}" in res.content


def test_tool_list_funcs(state):
    reg = ToolRegistry(state=state)
    res = reg.dispatch(ToolCall(id="t3", name="list_funcs", arguments={}))
    assert "functions" in res.content
    assert "entry" in res.content


def test_tool_search_strings(state):
    reg = ToolRegistry(state=state)
    res = reg.dispatch(ToolCall(id="t4", name="search_strings", arguments={"pattern": "notfound"}))
    assert "no strings" in res.content


def test_tool_set_note_writes_to_binstate(state, entry_addr):
    reg = ToolRegistry(state=state)
    res = reg.dispatch(ToolCall(
        id="t5", name="set_note", arguments={"addr": hex(entry_addr), "text": "entry fn"}
    ))
    assert "noted" in res.content
    assert state.notes[entry_addr] == "entry fn"


def test_tool_done_returns_summary(state):
    reg = ToolRegistry(state=state)
    res = reg.dispatch(ToolCall(id="t6", name="done", arguments={"summary": "all clear"}))
    assert res.content == "all clear"


def test_unknown_tool_returns_error(state):
    reg = ToolRegistry(state=state)
    res = reg.dispatch(ToolCall(id="t7", name="nope", arguments={}))
    assert "unknown tool" in res.content


# --------------------------------------------------------------------------- helpers


def _msg(content="", tool_calls=None):
    """Build a fake openai-style assistant message."""
    return SimpleNamespace(content=content, tool_calls=tool_calls)


def _call(cid, name, args):
    return SimpleNamespace(id=cid, function=SimpleNamespace(name=name, arguments=json.dumps(args)))


def _resp(msg):
    return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


# --------------------------------------------------------------------------- agent loop


class _ScriptedClient:
    """Replays a queue of canned chat-completion responses."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def chat_completions_create(self, *, messages, tools, model):
        self.calls.append({"messages": messages, "tools": tools, "model": model})
        if not self._responses:
            return _resp(_msg(content="(no more scripted responses)"))
        return self._responses.pop(0)


def test_agent_loop_reaches_done(state, entry_addr, callee_addr):
    """The agent walks list_funcs → decompile → done using a mocked LLM."""
    client = _ScriptedClient([
        _resp(_msg(tool_calls=[_call("c1", "list_funcs", {})])),
        _resp(_msg(tool_calls=[_call("c2", "decompile", {"addr": hex(entry_addr)})])),
        _resp(_msg(tool_calls=[_call("c3", "done", {"summary": "binary has an entry that calls a helper"})])),
    ])
    agent = BinrevAgent(state=state, client=client, model="qwen-plus")
    out = agent.ask("what does this binary do?")
    assert out == "binary has an entry that calls a helper"
    assert agent.final_summary == out
    # three LLM round-trips
    assert len(client.calls) == 3
    # the agent surfaced tool schemas to the model
    assert client.calls[0]["tools"]


def test_agent_loop_persists_set_note(state, entry_addr):
    """set_note writes through the registry into BinState.notes."""
    client = _ScriptedClient([
        _resp(_msg(tool_calls=[_call("c1", "set_note", {"addr": hex(entry_addr), "text": "entry is the root"})])),
        _resp(_msg(tool_calls=[_call("c2", "done", {"summary": "done"})])),
    ])
    agent = BinrevAgent(state=state, client=client)
    agent.ask("explain")
    assert state.notes[entry_addr] == "entry is the root"


def test_agent_loop_no_tool_calls_returns_text(state):
    """If the LLM answers directly with text, the loop returns it."""
    client = _ScriptedClient([
        _resp(_msg(content="it is a small ARM stub", tool_calls=None)),
    ])
    agent = BinrevAgent(state=state, client=client)
    out = agent.ask("what is it?")
    assert out == "it is a small ARM stub"


def test_agent_loop_step_limit(state):
    """If the model never calls done, the loop stops at max_steps."""
    forever = _resp(_msg(tool_calls=[_call("c1", "list_funcs", {})]))
    client = _ScriptedClient([forever] * 20)
    agent = BinrevAgent(state=state, client=client, max_steps=3)
    out = agent.ask("loop")
    assert "step limit" in out
    assert len(client.calls) == 3
