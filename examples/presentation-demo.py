import struct
from binrev import ISAKind,build_from_bytes
words=[0xE92D4010,0xEB000000,0xE8BD8010,0xE92D4010,0xE3A00001,0xE8BD8010]
data=b''.join(struct.pack('<I',w) for w in words)
state=build_from_bytes(data,ISAKind.ARM,base_addr=0x1000,entry=0x1000)
print(state.summary())
for address in state.list_funcs():
 f=state.functions[address];print(f'0x{address:08x} {f.name}: {len(state.xrefs_to(address))} callers')
print(state.decompile(0x100c).decompilation)
