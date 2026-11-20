# ARM ISA reference

binrev targets the ARM family — A32, Thumb-2 and A64. This document is
the quick ABI reference surfaced to the agent as ISA context when reversing a
domestic-SoC / head-unit firmware blob.

## Supported modes

| mode | capstone arch | capstone mode | instruction width | typical use |
|---|---|---|---|---|
| A32 (`arm`)    | `CS_ARCH_ARM`   | `CS_MODE_ARM`   | 4 bytes       | classic ARM firmware, older SoCs |
| Thumb-2 (`thumb`) | `CS_ARCH_ARM` | `CS_MODE_THUMB` | 2 / 4 bytes   | Cortex-M / compact firmware |
| A64 (`aarch64`) | `CS_ARCH_ARM64`| `CS_MODE_ARM`   | 4 bytes       | Cortex-A 64-bit SoCs |

Select with `binrev inspect ./fw.bin --isa arm|thumb|aarch64`.

## AArch32 (A32 / Thumb-2) — AAPCS

- **Argument registers (in)**: `r0`–`r3` (first four integer/pointer args).
- **Return value**: `r0` (a 64-bit result uses `r0`:`r1`).
- **Callee-saved**: `r4`–`r11`, `sp` (`r13`).
- **Caller-saved**: `r0`–`r3`, `r12` (ip), `lr` (`r14`) is restored by callee.
- **Frame pointer**: `r11` (fp) when present; `r7` in Thumb.
- **Return address**: `lr` (`r14`); return via `bx lr` or `pop {.., pc}`.

### Common prologue / epilogue

```
push {r4-r7, lr}      ; 0xe92d 40f0   — save callee regs + lr
...
pop  {r4-r7, pc}      ; 0xe8bd 80f0   — restore + return via pc
```

In Thumb:
```
push {r4, r5, lr}     ; 0xb530
pop  {r4, r5, pc}     ; 0xbd30
```

### Call instruction (the xref source)

`bl <target>` — branch with link. The PC pipeline offset is
`(target - (pc + 8)) >> 2` for A32, `(target - (pc + 4)) >> 1` for Thumb.
capstone resolves the absolute target, which binrev records as a `CALL`
xref and uses as a function-entry candidate.

## A64 — AAPCS64

- **Argument registers (in)**: `x0`–`x7` (first eight).
- **Return value**: `x0`.
- **Callee-saved**: `x19`–`x28`, `x29` (fp), `x30` (lr), `sp`.
- **Return**: `ret` (alias of `br x30`).
- **SP**: `sp` (`x31` as zero in most encodings).

```
stp  x29, x30, [sp, #-16]!   ; prologue
mov  x29, sp
...
ldp  x29, x30, [sp], #16     ; epilogue
ret
```

## Why domestic-SoC firmware is harder

Domestic SoCs (and many head-unit ECUs) ship firmware without public symbol
tables or reference docs — the IP-protection / immature-ecosystem gap that
makes xref recovery and struct reconstruction a multi-day manual job in
IDA/Ghidra. binrev's value is that the agent holds the *recovered* graph and
xrefs as first-class objects it can traverse itself, rather than a human
pasting Ghidra stdout into a chat.

## Beyond ARM

x86, LoongArch, MIPS and RISC-V are out of scope; the `ISA` model
and capstone loader are designed so adding a family is mostly a new
`arch_map` entry plus ISA metadata.
