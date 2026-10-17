"""Tests for the BinState capstone loader and read-only query methods.

Uses a tiny real ARM ELF + raw blob (see conftest) — no external binary
download, no Ghidra, no real LLM keys.
"""

from __future__ import annotations

import struct

import pytest

# Skip the whole module if capstone (a key dep) is not importable here.
pytest.importorskip("capstone", reason="capstone not installed in this env")

from binrev.binst import build_from_bytes, load_binary, render_inspect  # noqa: E402
from binrev.models import ISAKind, XrefKind  # noqa: E402


def test_build_from_bytes_detects_two_functions(arm_code, base_addr):
    state = build_from_bytes(arm_code, ISAKind.ARM, base_addr=base_addr, entry=base_addr)
    # entry + the bl-call target => two functions
    assert len(state.functions) == 2
    assert base_addr in state.functions
    callee = base_addr + 0xC
    assert callee in state.functions
    assert state.functions[base_addr].name == "entry"


def test_build_from_bytes_records_call_xref(arm_code, base_addr):
    state = build_from_bytes(arm_code, ISAKind.ARM, base_addr=base_addr, entry=base_addr)
    callee = base_addr + 0xC
    refs = state.xrefs_to(callee)
    assert len(refs) == 1
    assert refs[0].kind == XrefKind.CALL
    assert refs[0].from_addr == base_addr + 4
    assert refs[0].to_addr == callee


def test_decompile_returns_listing(arm_code, base_addr):
    state = build_from_bytes(arm_code, ISAKind.ARM, base_addr=base_addr, entry=base_addr)
    f = state.decompile(base_addr)
    assert f is not None
    assert "push" in f.decompilation
    assert "bl" in f.decompilation
    assert "pop" in f.decompilation


def test_decompile_unknown_addr(arm_code, base_addr):
    state = build_from_bytes(arm_code, ISAKind.ARM, base_addr=base_addr, entry=base_addr)
    assert state.decompile(0xDEADBEEF) is None


def test_list_funcs_sorted_and_filtered(arm_code, base_addr):
    state = build_from_bytes(arm_code, ISAKind.ARM, base_addr=base_addr, entry=base_addr)
    addrs = state.list_funcs()
    assert addrs == sorted(addrs)
    assert len(addrs) == 2
    # name filter
    assert state.list_funcs("entry") == [base_addr]
    assert state.list_funcs("sub_") == [base_addr + 0xC]


def test_xrefs_empty_for_unreferenced(arm_code, base_addr):
    state = build_from_bytes(arm_code, ISAKind.ARM, base_addr=base_addr, entry=base_addr)
    assert state.xrefs_to(base_addr) == []


def test_set_note_persists(arm_code, base_addr):
    state = build_from_bytes(arm_code, ISAKind.ARM, base_addr=base_addr, entry=base_addr)
    assert state.notes == {}
    state.set_note(base_addr, "entry calls helper at +0xc")
    assert state.notes[base_addr] == "entry calls helper at +0xc"


def test_search_strings_in_data_blob():
    data = b"\x00firmware\x00version 1.0\x00\x01\x02ABCD\x00"
    state = build_from_bytes(data, ISAKind.ARM, base_addr=0)
    hits = state.search_strings("firmware")
    assert len(hits) == 1
    assert hits[0].value == "firmware"
    hits2 = state.search_strings("version")
    assert any("version" in s.value for s in hits2)


def test_elf_text_section_extraction(arm_elf_file, arm_code, base_addr):
    """A real ELF: .text bytes + entry point are extracted, not the headers."""
    state = load_binary(arm_elf_file, ISAKind.ARM)
    # entry + callee recovered from the .text bytes only
    assert state.entry == base_addr
    assert len(state.functions) == 2
    assert state.functions[base_addr].name == "entry"
    callee = base_addr + 0xC
    assert callee in state.functions


def test_elf_string_addr_shares_code_address_space(arm_code, base_addr, tmp_path):
    """A string inside .text reports a .text vaddr, not a file offset + base.

    Regression: extraction used to scan the raw ELF image, so every string
    address was off by the ELF header (52 bytes) and could not be
    cross-referenced against function/xref addresses.
    """
    from conftest import make_arm_elf

    code = arm_code + b"UART boot\x00"
    elf = tmp_path / "head_unit.elf"
    elf.write_bytes(make_arm_elf(code, base_addr))
    state = load_binary(elf, ISAKind.ARM)
    hits = state.search_strings("UART")
    assert len(hits) == 1
    assert hits[0].addr == base_addr + len(arm_code)


def test_raw_file_load(arm_raw_file, base_addr):
    state = load_binary(arm_raw_file, ISAKind.ARM, base_addr=base_addr)
    assert len(state.functions) >= 1
    assert base_addr in state.functions


def test_summary_string(arm_code, base_addr):
    state = build_from_bytes(arm_code, ISAKind.ARM, base_addr=base_addr, entry=base_addr)
    s = state.summary()
    assert "ARM" in s
    assert "funcs" in s
    assert "capstone" in s


def test_render_inspect_table(arm_code, base_addr):
    state = build_from_bytes(arm_code, ISAKind.ARM, base_addr=base_addr, entry=base_addr)
    out = render_inspect(state)
    assert "binrev inspect" in out
    assert "entry" in out
    assert f"0x{base_addr:08x}" in out


def test_render_inspect_single_func(arm_code, base_addr):
    state = build_from_bytes(arm_code, ISAKind.ARM, base_addr=base_addr, entry=base_addr)
    callee = base_addr + 0xC
    out = render_inspect(state, func_addr=callee)
    assert "decompilation" in out
    assert "callers" in out
    assert "call" in out
    assert "push" in out


def test_to_json_roundtrip(arm_code, base_addr):
    state = build_from_bytes(arm_code, ISAKind.ARM, base_addr=base_addr, entry=base_addr)
    state.set_note(base_addr, "test note")
    j = state.to_json()
    assert "test note" in j
    assert "functions" in j


# ------------------------------------------------------------------ corrupt ELF
# A truncated firmware download or any file starting with \x7fELF is ordinary
# user input; the capstone backend must degrade to the raw-blob fallback
# instead of raising struct.error from header unpacks.


def _arm_ehdr(e_shoff: int, e_shnum: int, e_shstrndx: int) -> bytes:
    """Minimal 32-bit LE ARM ELF header with caller-controlled section table."""
    return (
        b"\x7fELF"
        + struct.pack("<BBB", 1, 1, 1)  # class=32, data=LE, version
        + bytes(7)  # osabi + padding
        + struct.pack(
            "<HHIIIIIHHHHHH",
            2,        # e_type = ET_EXEC
            40,       # e_machine = EM_ARM
            1,        # e_version
            0x1000,   # e_entry
            0,        # e_phoff
            e_shoff,  # e_shoff
            0,        # e_flags
            52,       # e_ehsize
            32,       # e_phentsize
            0,        # e_phnum
            40,       # e_shentsize
            e_shnum,  # e_shnum
            e_shstrndx,  # e_shstrndx
        )
    )


def test_elf_shoff_past_eof_falls_back_instead_of_crashing(tmp_path, arm_code):
    """e_shoff claiming a section table past EOF → raw-blob handling, no struct.error."""
    bad = tmp_path / "truncated.elf"
    bad.write_bytes(_arm_ehdr(e_shoff=0xFFFFFF, e_shnum=3, e_shstrndx=2) + arm_code)

    state = load_binary(bad, ISAKind.ARM)

    assert state.source == "capstone"
    assert len(state.functions) >= 1


def test_elf_truncated_section_table_falls_back(tmp_path, arm_code):
    """A section table whose later entries run past EOF stops at the guard."""
    bad = tmp_path / "half-table.elf"
    bad.write_bytes(_arm_ehdr(e_shoff=76, e_shnum=3, e_shstrndx=0) + arm_code + bytes(40))

    state = load_binary(bad, ISAKind.ARM)

    assert state.source == "capstone"
    assert len(state.functions) >= 1


def test_elf_header_shorter_than_ehdr_falls_back(tmp_path, arm_code):
    """A file of 24..51 bytes starting with ELF magic cannot hold an Ehdr."""
    short = tmp_path / "stub.elf"
    short.write_bytes(b"\x7fELF" + struct.pack("<BBB", 1, 1, 1) + bytes(7) + bytes(20))

    state = load_binary(short, ISAKind.ARM)

    assert state.source == "capstone"
