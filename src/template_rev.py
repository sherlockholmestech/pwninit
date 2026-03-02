#!/usr/bin/env python3

import angr
import claripy
import z3

{bindings}


def main():
    project = angr.Project({bin_name}, auto_load_libs=False)

    input_len = 32
    sym_input = claripy.BVS("sym_input", input_len * 8)
    state = project.factory.full_init_state(stdin=sym_input)

    for i in range(input_len):
        byte = sym_input.get_byte(i)
        state.solver.add(byte >= 0x20)
        state.solver.add(byte <= 0x7E)

    simgr = project.factory.simgr(state)

    find_addr = None
    avoid_addr = None

    if find_addr is not None:
        simgr.explore(find=find_addr, avoid=avoid_addr)
    else:
        simgr.explore()

    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(sym_input, cast_to=bytes)
        print(solution)
    else:
        print("no solution found")


if __name__ == "__main__":
    main()
