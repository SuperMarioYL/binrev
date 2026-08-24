"""Pydantic data models for binrev's binary action space.

These models are the structural skeleton of :class:`~binrev.binst.BinState`:
decompiled function graph, cross-references, ISA metadata, the string table
and the agent's cross-step reasoning notes.  They are the *first-class
objects* the LLM tool-calls operate on, not text logs scraped from a CLI.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


# An address is a 32/64-bit code or data offset into the binary under analysis.
# Stored as ``int`` for fast lookups; rendered as hex when surfaced to the model.
Addr = int


class ISAKind(str, Enum):
    """Instruction set family understood by the v0.1 ARM scope."""

    ARM = "arm"          # A32 (ARM) 4-byte aligned
    THUMB = "thumb"      # T32 (Thumb-2) 2/4-byte mixed
    AARCH64 = "aarch64"  # A64

    @property
    def pretty(self) -> str:
        return {
            ISAKind.ARM: "ARM (A32)",
            ISAKind.THUMB: "Thumb-2 (T32)",
            ISAKind.AARCH64: "AArch64 (A64)",
        }[self]


class XrefKind(str, Enum):
    """How one address references another."""

    CALL = "call"   # a branch-with-link / direct call
    JUMP = "jump"   # an unconditional/conditional branch
    DATA = "data"   # a data reference (e.g. literal-pool load)


class Instruction(BaseModel):
    """A single disassembled instruction."""

    model_config = ConfigDict(frozen=True)

    addr: Addr
    mnemonic: str
    operands: str = ""
    bytes_hex: str = Field(default="", description="raw bytes as hex")


class Xref(BaseModel):
    """A single cross reference: ``from`` references ``to``."""

    model_config = ConfigDict(frozen=True)

    from_addr: Addr
    to_addr: Addr
    kind: XrefKind


class Func(BaseModel):
    """A decompiled / disassembled function.

    ``decompilation`` holds the Ghidra-produced C-ish text when available,
    otherwise the capstone disassembly listing.  This is what the agent reads
    via the ``decompile`` tool.
    """

    addr: Addr
    name: str
    size: int = 0
    decompilation: str = ""
    instructions: list[Instruction] = Field(default_factory=list)


class StringEntry(BaseModel):
    """An extracted string from the binary's string table."""

    addr: Addr
    value: str


class ISA(BaseModel):
    """Instruction-set metadata surfaced to the agent as context."""

    kind: ISAKind
    registers: list[str] = Field(default_factory=list)
    calling_convention: str = ""


# Default ISA metadata per family.  Enough for the agent to reason about
# argument registers and return conventions without a full ABI encyclopedia.
_DEFAULT_ISA: dict[ISAKind, ISA] = {
    ISAKind.ARM: ISA(
        kind=ISAKind.ARM,
        registers=["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "fp", "ip", "sp", "lr", "pc"],
        calling_convention="AAPCS: r0-r3 in, r0 return, lr return-addr",
    ),
    ISAKind.THUMB: ISA(
        kind=ISAKind.THUMB,
        registers=["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "fp", "ip", "sp", "lr", "pc"],
        calling_convention="AAPCS: r0-r3 in, r0 return, lr return-addr",
    ),
    ISAKind.AARCH64: ISA(
        kind=ISAKind.AARCH64,
        registers=[f"x{i}" for i in range(31)] + ["sp", "pc", "pstate"],
        calling_convention="AAPCS64: x0-x7 in, x0 return, x30 return-addr",
    ),
}


def default_isa(kind: ISAKind) -> ISA:
    """Return the built-in ISA metadata for a family."""
    return _DEFAULT_ISA[kind].model_copy()


class ToolCall(BaseModel):
    """A tool invocation requested by the LLM."""

    id: str
    name: str
    arguments: dict = Field(default_factory=dict)


class ToolResult(BaseModel):
    """The structured result returned to the LLM for a tool call."""

    tool_call_id: str
    name: str
    content: str


class AgentStep(BaseModel):
    """One reasoning step of the agent loop."""

    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    assistant_text: str = ""
