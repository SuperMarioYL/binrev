"""Shared test fixtures — a tiny real ARM ELF / raw blob the capstone
backend disassembles.  No external binary download needed.

The blob encodes two real A32 functions: an ``entry`` that ``bl``-calls a
``sub_...`` helper, which returns.  capstone resolves the call target to an
absolute address so the xref/function-carving logic has something real to
chew on.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest


def arm_code_bytes(base: int = 0x1000) -> bytes:
    """Two A32 functions: entry bl-calls sub at base+0xc, both return."""
    target = base + 0xC
    # bl offset = (target - (pc+8)) >> 2; pc = base+4 → (target-(base+4+8))>>2
    bl_off = (target - (base + 4 + 8)) >> 2
    bl_word = 0xEB000000 | (bl_off & 0x00FFFFFF)
    return (
        struct.pack("<I", 0xE92D4010)  # push {r4, lr}     @ base
        + struct.pack("<I", bl_word)   # bl  base+0xc      @ base+4
        + struct.pack("<I", 0xE8BD8010)  # pop {r4, pc}    @ base+8
        + struct.pack("<I", 0xE92D4010)  # push {r4, lr}   @ base+0xc  (callee)
        + struct.pack("<I", 0xE3A00001)  # mov r0, #1      @ base+0x10
        + struct.pack("<I", 0xE8BD8010)  # pop {r4, pc}    @ base+0x14
    )


def make_arm_elf(code: bytes, base: int = 0x1000) -> bytes:
    """Build a minimal 32-bit little-endian ARM ELF with one .text section."""
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    # file layout: ehdr(52) | .text | .shstrtab | shdrs(3*40)
    ehdr_size = 52
    text_off = ehdr_size
    shstr_off = text_off + len(code)
    shdr_off = shstr_off + len(shstrtab)
    shdr_size = 40

    ehdr = struct.pack(
        "<4sBBBBB7sHHIIIIIHHHHHH",
        b"\x7fELF",        # e_ident magic
        1, 1, 1, 0, 0,     # class=32, data=LE, ver=1, osabi=0, pad...
        b"\x00" * 7,
        2,                  # e_type = ET_EXEC
        40,                 # e_machine = EM_ARM
        1,                  # e_version
        base,               # e_entry
        0,                  # e_phoff (no program headers)
        shdr_off,           # e_shoff
        0,                  # e_flags
        ehdr_size,          # e_ehsize
        32,                 # e_phentsize
        0,                  # e_phnum
        shdr_size,          # e_shentsize
        3,                  # e_shnum (null + .text + .shstrtab)
        2,                  # e_shstrndx
    )

    def shdr(name, stype, flags, addr, off, size):
        return struct.pack("<IIIIIIIIII", name, stype, flags, addr, off, size, 0, 0, 4, 0)

    null_sh = shdr(0, 0, 0, 0, 0, 0)
    text_sh = shdr(1, 1, 6, base, text_off, len(code))      # .text PROGBITS|ALLOC|EXEC
    shstr_sh = shdr(7, 3, 0, 0, shstr_off, len(shstrtab))   # .shstrtab STRTAB

    return ehdr + code + shstrtab + null_sh + text_sh + shstr_sh


@pytest.fixture
def arm_code() -> bytes:
    return arm_code_bytes()


@pytest.fixture
def base_addr() -> int:
    return 0x1000


@pytest.fixture
def arm_raw_file(tmp_path: Path, arm_code: bytes) -> Path:
    p = tmp_path / "fw.bin"
    p.write_bytes(arm_code)
    return p


@pytest.fixture
def arm_elf_file(tmp_path: Path, arm_code: bytes, base_addr: int) -> Path:
    p = tmp_path / "head_unit.elf"
    p.write_bytes(make_arm_elf(arm_code, base_addr))
    return p
