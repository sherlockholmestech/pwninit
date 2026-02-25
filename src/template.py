#!/usr/bin/env python3

from pwn import *

{bindings}

context.binary = {bin_name}
context.terminal = "kitty"
context.gdb_binary = "/usr/bin/pwndbg"


def conn():
    if args.LOCAL:
        r = process({proc_args})
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
