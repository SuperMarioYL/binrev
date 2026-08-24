"""Minimal programmatic use of binrev's BinState.

    from binrev import build_from_bytes, ISAKind
    state = build_from_bytes(open("fw.bin","rb").read(), ISAKind.ARM, base_addr=0x8000)
    print(state.summary(), state.decompile(0x8000).decompilation[:60])
"""
from binrev import ISAKind, build_from_bytes

data = open("fw.bin", "rb").read() if __import__("os").path.exists("fw.bin") else b""
if data:
    state = build_from_bytes(data, ISAKind.ARM, base_addr=0x8000, entry=0x8000)
    print(state.summary())
    for addr in state.list_funcs()[:5]:
        print(f"0x{addr:08x}  {state.functions[addr].name}")
