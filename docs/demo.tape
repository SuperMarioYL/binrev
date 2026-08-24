# binrev demo tape — renders assets/demo.gif via vhs.
# Drives the real `binrev` binary reversing a tiny ARM firmware blob.
Output assets/demo.gif

Set Width 960
Set Height 620
Set FontSize 14
Set Theme {"background": "#1D1D1F", "foreground": "#F5F5F7", "name": "binrev-dark"}
Set Padding 20

# Build a tiny ARM firmware sample (entry bl-calls a helper).
Type "python3 -c \"import struct; open('fw.bin','wb').write(b''.join(struct.pack('<I',i) for i in [0xE92D4010,0xEB000001,0xE59F0010,0xE8BD8010,0xE92D4010,0xE3A0002A,0xE8BD8010]))\""
Enter
Sleep 1

# Inspect the binary's structured state.
Type "binrev inspect ./fw.bin --isa arm"
Enter
Sleep 3

# Drill into the callee that entry calls.
Type "binrev inspect ./fw.bin --isa arm --func 0x10"
Enter
Sleep 3

# Ask the agent what the firmware does.
Type 'binrev ./fw.bin --isa arm -q "这个固件在干什么"'
Enter
Sleep 4
