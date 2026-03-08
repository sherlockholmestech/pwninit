#!/usr/bin/env python3

import angr
import claripy
import z3

{bindings}


def main():
    project = angr.Project({bin_name}, auto_load_libs=False)
    state = project.factory.entry_state()
    simgr = project.factory.simgr(state)

    # Customize these for your target
    find_addr = None
    avoid_addr = None

    simgr.explore(find=find_addr, avoid=avoid_addr)

    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(flag, cast_to=bytes)
        print(f"found a solution: {solution}")
    else:
        print("no solution found")


if __name__ == "__main__":
    main()
