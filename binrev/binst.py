"""BinState — binrev's core primitive.

``BinState`` holds the decompiled function graph, cross-references, ISA
state, the string table and the agent's cross-step notes as *queryable
objects*, not a CLI stdout log.  The agent's binary action space
(``decompile`` / ``xref`` / ``list_funcs`` / ``search_strings`` /
``set_note``) reads and mutates this structure.

Two backends can populate a ``BinState``:

* **capstone** (default, no external tool) — disassembles raw ARM bytes,
  derives function boundaries and call/jump xrefs from instruction decoding.
  Good enough to inspect a blob without Ghidra installed.
* **ghidra** — :mod:`binrev.ghidra_bridge` runs ``analyzeHeadless`` and dumps
  real decompiled C + rich xrefs; loaded back here from JSON.

This module owns the BinState concept end-to-end: data model, query methods,
loaders and the ``inspect`` renderer.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator, Optional

from pydantic import BaseModel, ConfigDict, Field

from .models import (
    Addr,
    Func,
    ISA,
    ISAKind,
    Instruction,
    StringEntry,
    Xref,
    XrefKind,
    default_isa,
)


# Branch-with-link opcodes → call xrefs + function entries.
_CALL_MNEMONICS = {"bl", "blx"}
# Plain branches → jump xrefs.
_JUMP_MNEMONICS = {"b", "bcc", "bcs", "beq", "bne", "bge", "blt", "bgt", "ble", "bhi", "bls", "bvc", "bvs", "bpl", "bmi"}


class BinState(BaseModel):
    """The structured binary state — the core primitive of binrev.

    Holds the decompiled function graph, cross-references, ISA state and the
    string table as queryable objects rather than a CLI stdout log.  The
    agent's binary action space reads and mutates this structure.
    """

    model_config = ConfigDict()

    isa: ISA
    base_addr: Addr = 0
    entry: Optional[Addr] = None
    functions: dict[Addr, Func] = Field(default_factory=dict)
    xrefs: list[Xref] = Field(default_factory=list)
    strings: list[StringEntry] = Field(default_factory=list)
    notes: dict[Addr, str] = Field(default_factory=dict)
    source: str = Field(default="capstone", description="who produced this state: capstone | ghidra")

    # ------------------------------------------------------------------ queries

    def decompile(self, addr: Addr) -> Optional[Func]:
        """Return the function (decompilation/disassembly) at ``addr``."""
        return self.functions.get(addr)

    def xrefs_to(self, addr: Addr) -> list[Xref]:
        """Return every reference that targets ``addr``."""
        return [x for x in self.xrefs if x.to_addr == addr]

    def list_funcs(self, filter: str = "") -> list[Addr]:
        """Return function entry addresses, optionally filtered by name."""
        if not filter:
            return sorted(self.functions)
        needle = filter.lower()
        return sorted(a for a, f in self.functions.items() if needle in f.name.lower())

    def search_strings(self, pattern: str) -> list[StringEntry]:
        """Return string-table entries whose value contains ``pattern``."""
        if not pattern:
            return list(self.strings)
        needle = pattern.lower()
        return [s for s in self.strings if needle in s.value.lower()]

    def set_note(self, addr: Addr, text: str) -> None:
        """Record a cross-step reasoning note for ``addr``."""
        self.notes[addr] = text

    # ------------------------------------------------------------------ summary

    def summary(self) -> str:
        """A compact one-line snapshot of the held binary state."""
        return (
            f"{self.isa.kind.pretty} · {len(self.functions)} funcs · "
            f"{len(self.xrefs)} xrefs · {len(self.strings)} strings · "
            f"{len(self.notes)} notes · src={self.source}"
        )

    def to_json(self) -> str:
        """Serialize the full state for caching / the agent context window."""
        return self.model_dump_json(indent=2)


# ---------------------------------------------------------------------------
# Minimal ELF reader — extracts the executable code bytes + entry point.
# Pure stdlib, enough for the "tiny real ELF/ARM blob" the tests feed in.
# ---------------------------------------------------------------------------

_ELF_MAGIC = b"\x7fELF"


def _read_elf_code(data: bytes) -> tuple[bytes, int, int]:
    """Return ``(code_bytes, base_addr, entry)`` from an ELF image.

    Falls back to ``(data, 0, 0)`` if the input is not an ELF (raw blob).
    """
    if len(data) < 24 or data[:4] != _ELF_MAGIC:
        return data, 0, 0

    is_64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"  # EI_DATA: 1=little, 2=big

    if is_64:
        # Elf64_Ehdr: e_entry@18, e_shoff@40, e_shentsize@58, e_shnum@60, e_shstrndx@62
        e_entry = struct.unpack_from(endian + "Q", data, 24)[0]
        e_shoff = struct.unpack_from(endian + "Q", data, 40)[0]
        e_shentsize = struct.unpack_from(endian + "H", data, 58)[0]
        e_shnum = struct.unpack_from(endian + "H", data, 60)[0]
        e_shstrndx = struct.unpack_from(endian + "H", data, 62)[0]
    else:
        # Elf32_Ehdr: e_entry@24, e_shoff@32, e_shentsize@46, e_shnum@48, e_shstrndx@50
        e_entry = struct.unpack_from(endian + "I", data, 24)[0]
        e_shoff = struct.unpack_from(endian + "I", data, 32)[0]
        e_shentsize = struct.unpack_from(endian + "H", data, 46)[0]
        e_shnum = struct.unpack_from(endian + "H", data, 48)[0]
        e_shstrndx = struct.unpack_from(endian + "H", data, 50)[0]

    if not e_shoff or not e_shnum:
        # No section headers — hand back the whole image as code.
        return data, 0, e_entry

    # Read the section-header-string-table to locate .text by name.
    shstr_off = e_shoff + e_shstrndx * e_shentsize
    if is_64:
        shstr_sh_offset = struct.unpack_from(endian + "Q", data, shstr_off + 24)[0]
        shstr_sh_size = struct.unpack_from(endian + "Q", data, shstr_off + 32)[0]
    else:
        shstr_sh_offset = struct.unpack_from(endian + "I", data, shstr_off + 16)[0]
        shstr_sh_size = struct.unpack_from(endian + "I", data, shstr_off + 20)[0]
    strtab = data[shstr_sh_offset : shstr_sh_offset + shstr_sh_size]

    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name = struct.unpack_from(endian + "I", data, off)[0]
        name_end = strtab.find(b"\x00", sh_name)
        name = strtab[sh_name:name_end].decode("ascii", "replace") if name_end > sh_name else ""
        if name != ".text":
            continue
        if is_64:
            sh_addr = struct.unpack_from(endian + "Q", data, off + 16)[0]
            sh_offset = struct.unpack_from(endian + "Q", data, off + 24)[0]
            sh_size = struct.unpack_from(endian + "Q", data, off + 32)[0]
        else:
            sh_addr = struct.unpack_from(endian + "I", data, off + 12)[0]
            sh_offset = struct.unpack_from(endian + "I", data, off + 16)[0]
            sh_size = struct.unpack_from(endian + "I", data, off + 20)[0]
        return data[sh_offset : sh_offset + sh_size], sh_addr, e_entry

    # No .text found — return the raw image.
    return data, 0, e_entry


# ---------------------------------------------------------------------------
# Capstone loader — builds a BinState from raw ARM bytes without Ghidra.
# ---------------------------------------------------------------------------


def _disasm_instructions(data: bytes, isa_kind: ISAKind, base_addr: Addr) -> list[Instruction]:
    """Disassemble ``data`` into :class:`Instruction` records via capstone."""
    from capstone import (  # local import: keeps the module importable without capstone
        CS_ARCH_ARM,
        CS_ARCH_ARM64,
        CS_MODE_ARM,
        CS_MODE_THUMB,
        Cs,
    )

    arch_map = {
        ISAKind.ARM: (CS_ARCH_ARM, CS_MODE_ARM),
        ISAKind.THUMB: (CS_ARCH_ARM, CS_MODE_THUMB),
        ISAKind.AARCH64: (CS_ARCH_ARM64, CS_MODE_ARM),
    }
    cs_arch, cs_mode = arch_map[isa_kind]
    cs = Cs(cs_arch, cs_mode)
    cs.detail = False
    out: list[Instruction] = []
    for insn in cs.disasm(data, base_addr):
        out.append(
            Instruction(
                addr=insn.address,
                mnemonic=insn.mnemonic,
                operands=insn.op_str,
                bytes_hex=insn.bytes.hex(),
            )
        )
    return out


def _is_call(insn: Instruction) -> bool:
    return insn.mnemonic.lower() in _CALL_MNEMONICS


def _is_jump(insn: Instruction) -> bool:
    return insn.mnemonic.lower() in _JUMP_MNEMONICS


def _extract_strings(data: bytes, base_addr: Addr, min_len: int = 4) -> list[StringEntry]:
    """Pull printable ASCII runs (>= min_len) out of the blob."""
    strings: list[StringEntry] = []
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F:
            if not cur:
                start = i
            cur.append(b)
        else:
            if b == 0 and len(cur) >= min_len:
                strings.append(StringEntry(addr=base_addr + start, value=cur.decode("ascii", "replace")))
            cur = bytearray()
    if len(cur) >= min_len:
        strings.append(StringEntry(addr=base_addr + start, value=cur.decode("ascii", "replace")))
    return strings


def _parse_branch_target(operands: str) -> Optional[int]:
    """Parse a branch/call target like ``#0x1000`` / ``0x4080`` into an int."""
    operands = operands.strip()
    token = operands.split(",")[0].strip().lstrip("#")
    try:
        return int(token, 0)
    except ValueError:
        return None


def build_from_bytes(
    data: bytes,
    isa_kind: ISAKind,
    base_addr: Addr = 0,
    *,
    entry: Optional[Addr] = None,
) -> BinState:
    """Build a :class:`BinState` from raw code bytes using capstone.

    Derives function boundaries (call targets + return-terminated runs),
    call/jump xrefs and the string table.  When a real ELF image is passed,
    its ``.text`` section and entry point are extracted first.
    """
    code, elf_base, elf_entry = _read_elf_code(data)
    if base_addr == 0:
        base_addr = elf_base
    if entry is None and elf_entry:
        entry = elf_entry
    # For a raw blob with no entry metadata, treat the code start as the entry
    # so the first function is always discovered (most code blobs begin there).
    if entry is None:
        entry = base_addr

    instructions = _disasm_instructions(code, isa_kind, base_addr)

    # Function-entry candidates: the entry point + every call target in range.
    addrs_by_offset = {insn.addr: idx for idx, insn in enumerate(instructions)}
    max_addr = base_addr + len(code)
    func_starts: set[Addr] = set()
    if entry is not None and base_addr <= entry < max_addr:
        func_starts.add(entry)
    xrefs: list[Xref] = []
    for insn in instructions:
        target = _parse_branch_target(insn.operands)
        if target is None:
            continue
        if _is_call(insn):
            xrefs.append(Xref(from_addr=insn.addr, to_addr=target, kind=XrefKind.CALL))
            if base_addr <= target < max_addr:
                func_starts.add(target)
        elif _is_jump(insn):
            xrefs.append(Xref(from_addr=insn.addr, to_addr=target, kind=XrefKind.JUMP))

    # Carve contiguous instruction runs into functions, bounded by the next
    # function start (no precise symbol sizes without Ghidra, so each
    # function spans start_i .. start_{i+1}).
    functions: dict[Addr, Func] = {}
    if not func_starts:
        # No call targets — treat the whole run as one function at base.
        func_starts = {base_addr} if instructions else set()

    sorted_starts = sorted(func_starts)
    for i, start in enumerate(sorted_starts):
        end = sorted_starts[i + 1] if i + 1 < len(sorted_starts) else max_addr
        idx0 = addrs_by_offset.get(start, 0)
        body: list[Instruction] = []
        for j in range(idx0, len(instructions)):
            ins = instructions[j]
            if ins.addr >= end:
                break
            body.append(ins)
        func_name = f"sub_{start:08x}"
        if start == entry:
            func_name = "entry"
        # Disassembly listing is the "decompilation" surface when capstone is
        # the backend (Ghidra would supply real C here).
        listing = "\n".join(
            f"  0x{ins.addr:08x}:  {ins.mnemonic:<6} {ins.operands}" for ins in body
        )
        functions[start] = Func(
            addr=start,
            name=func_name,
            size=sum(len(ins.bytes_hex) // 2 for ins in body) if body else (end - start),
            decompilation=listing,
            instructions=body,
        )

    # Strings are pulled from the same mapped region the disassembler consumed,
    # so their addresses share the .text vaddr space of functions/xrefs (scanning
    # the raw image would offset every string by the ELF header).
    strings = _extract_strings(code, base_addr)
    return BinState(
        isa=default_isa(isa_kind),
        base_addr=base_addr,
        entry=entry,
        functions=functions,
        xrefs=xrefs,
        strings=strings,
        source="capstone",
    )


def build_from_ghidra_json(path: str | Path) -> BinState:
    """Load a Ghidra headless JSON dump (from :mod:`binrev.ghidra_bridge`).

    The dump schema is the JSON form of :class:`BinState`; this is a thin
    loader that re-hydrates the pydantic model and marks ``source='ghidra'``.
    """
    raw = Path(path).read_text(encoding="utf-8")
    state = BinState.model_validate_json(raw)
    state.source = "ghidra"
    return state


def load_binary(path: str | Path, isa_kind: ISAKind, *, base_addr: int = 0) -> BinState:
    """Load a binary file into a BinState via the capstone backend."""
    data = Path(path).read_bytes()
    return build_from_bytes(data, isa_kind, base_addr=base_addr)


# ---------------------------------------------------------------------------
# inspect renderer — what `binrev inspect` prints.
# ---------------------------------------------------------------------------


def render_inspect(state: BinState, *, func_addr: Optional[Addr] = None, limit: int = 40) -> str:
    """Render a human-readable inspect view of the held binary state.

    Prints the function table by default, or the decompilation of a specific
    function when ``func_addr`` is given.
    """
    lines: list[str] = []
    lines.append(f"binrev inspect · {state.summary()}")
    lines.append("")

    if func_addr is not None:
        f = state.decompile(func_addr)
        if f is None:
            lines.append(f"no function at 0x{func_addr:08x}")
            return "\n".join(lines)
        lines.append(f"function {f.name} @ 0x{f.addr:08x}  ({f.size} bytes)")
        lines.append("")
        refs = state.xrefs_to(func_addr)
        if refs:
            lines.append("callers:")
            for x in refs:
                lines.append(f"  0x{x.from_addr:08x}  ({x.kind.value})")
            lines.append("")
        note = state.notes.get(func_addr)
        lines.append("decompilation:")
        for ln in f.decompilation.splitlines():
            lines.append(ln)
        if note:
            lines.append("")
            lines.append(f"note: {note}")
        return "\n".join(lines)

    # function table
    lines.append(f"{'addr':<12} {'name':<18} {'size':>8}  callers")
    lines.append("-" * 56)
    for addr in state.list_funcs()[:limit]:
        f = state.functions[addr]
        n_callers = len(state.xrefs_to(addr))
        lines.append(f"0x{addr:08x}  {f.name:<18} {f.size:>8}  {n_callers}")
    remaining = len(state.functions) - limit
    if remaining > 0:
        lines.append(f"... ({remaining} more, use --func to read one)")
    return "\n".join(lines)
