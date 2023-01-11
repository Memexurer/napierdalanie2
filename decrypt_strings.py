import angr
import time

proj = angr.Project("sus", auto_load_libs=False)
decrypt = next(filter(lambda x: x.name.startswith("3Qa"), proj.loader.symbols))
state = proj.factory.call_state(decrypt.rebased_addr)

while True:
  state = state.step().successors[0]
  try:
    block = state.block()
  except:
    break
print(state.memory.hex_dump(0x7763b0 - 1000, 2000))
