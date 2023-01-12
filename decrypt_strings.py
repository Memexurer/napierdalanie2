import angr
import time

proj = angr.Project("sus", auto_load_libs=False)

symbols = []
for decrypt in proj.loader.symbols:
  if len(decrypt.name) < 18:
    continue
  if decrypt.rebased_addr in symbols:
    continue
  symbols.append(decrypt.rebased_addr)
  mnemonic = proj.factory.block(decrypt.rebased_addr).disassembly.insns[0].mnemonic
  op_str = proj.factory.block(decrypt.rebased_addr).disassembly.insns[0].op_str
  if (mnemonic == "mov" and "al, byte ptr" in op_str) or mnemonic == "movaps":
    symbols.append(decrypt.rebased_addr)
    state = proj.factory.call_state(decrypt.rebased_addr)

    data_addr = int(op_str.split("0x")[1][:-1],16)
    rip1 = state.regs.rip.args[0]
    
    while True:
      state = state.step().successors[0]
      try:
        block = state.block()
      except:
        break

    print(state.memory.hex_dump(rip1 + data_addr, 2000))