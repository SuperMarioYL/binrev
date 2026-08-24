"""binrev — binary-action-space reverse-engineering agent.

Extends a text/shell coding agent's action space into a *binary* action
space: decompiled function graph, cross-references and ISA state held as
first-class objects the LLM tool-calls against, not a Ghidra stdout log.

v0.1 scope: ARM (A32 / Thumb-2 / A64), single binary per session,
OpenAI-compatible LLM (Qwen / DeepSeek).
"""

__version__ = "0.1.0"

from .binst import BinState, build_from_bytes, load_binary, render_inspect
from .models import ISAKind, XrefKind

__all__ = [
    "__version__",
    "BinState",
    "build_from_bytes",
    "load_binary",
    "render_inspect",
    "ISAKind",
    "XrefKind",
]
