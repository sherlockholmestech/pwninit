[![Build Status](https://github.com/io12/pwninit/workflows/Build/badge.svg)](https://github.com/io12/pwninit/actions)
[![](https://img.shields.io/crates/v/pwninit)](https://crates.io/crates/pwninit)
[![](https://docs.rs/pwninit/badge.svg)](https://docs.rs/pwninit)

# `pwninit`

A tool for automating starting binary exploit challenges, as well as reverse engineering ones.


## Features

- Set challenge binary to be executable
- Download a linker (`ld-linux.so.*`) that can segfaultlessly load the provided libc
- Optionally download additional libraries from the same libc package
- Download debug symbols and unstrip the libc
- Patch the binary with [`patchelf`](https://github.com/NixOS/patchelf) to use
  the correct RPATH and interpreter for the provided libc
- Optional manual patch mode that rewrites `PT_INTERP` and `DT_NEEDED`
  directly without invoking `patchelf`
- Fill in a template pwntools solve script
- Fill in a template angr + z3 solve script for rev challenges
- Create a local `uv` virtual environment in `.venv` and install `pwntools` (pwn) or `angr` + `z3-solver` (rev)

## Usage

### Short version

Run `pwninit`

### Long version

Run `pwninit` in a directory with the relevant files and it will detect which ones are the binary, libc, and linker. If the detection is wrong, you can specify the locations with `--bin`, `--libc`, and `--ld`.

Run `pwninit rev` in a directory with the relevant files and it will detect the reverse engineering binary. If the detection is wrong, you can specify the location with `--bin`.

Use `--uv` to create a local `uv` virtual environment in `.venv` and install `pwntools` for pwn challenges or `angr` + `z3-solver` for rev challenges. By default, no virtual environment is created.

Use `pwninit fetch-libc <version> --lib <name>` to download additional libraries from the same libc package. The option is repeatable, accepts sonames such as `libm.so.6`, `libdl.so.2`, or `libnss_dns.so.2`, and also accepts `libm` and `libpthread` as aliases for `libm.so.6` and `libpthread.so.0`.

By default, binary patching uses `patchelf` to set the RPATH to `.` and the interpreter to `./ld`. Use `--no-patchelf` to instead patch the binary directly by rewriting `PT_INTERP` and `DT_NEEDED` entries in place to short local names (e.g. `./ld`, `./libc`). Both modes create the same symlinks (`ld`, `libc`, etc.) in the challenge directory.

`--no-patchelf` only applies replacements that fit in the original ELF string slot. Oversized or unresolved entries are skipped with a warning.

#### Custom `solve.py` template

If you don't like the default template, you can use your own. Just specify `--template-path <path>`. Check [template.py](src/template.py) for the template format. The names of the `exe`, `libc`, and `ld` bindings can be customized with `--template-bin-name`, `--template-libc-name`, and `--template-ld-name`.

##### Persisting custom `solve.py`

You can make `pwninit` load your custom template automatically by adding an alias to your `~/.bashrc`.

###### Example

```bash
alias pwninit='pwninit --template-path ~/.config/pwninit-template.py --template-bin-name e'
```

## Install
Run

```sh
cargo build --release
```

To build the binary in the target/release folder.

Note that `openssl`, `liblzma`, and `pkg-config` are required for the build.

## Example

```sh
$ ls
hunter  libc.so.6  readme

$ pwninit
bin: ./hunter
libc: ./libc.so.6

setting ./hunter executable
fetching linker
https://launchpad.net/ubuntu/+archive/primary/+files//libc6_2.23-0ubuntu10_i386.deb
unstripping libc
https://launchpad.net/ubuntu/+archive/primary/+files//libc6-dbg_2.23-0ubuntu10_i386.deb
setting ./ld-2.23.so executable
copying ./hunter to ./hunter_patched
running patchelf on ./hunter_patched
writing solve.py stub

$ ls
hunter	hunter_patched	ld-2.23.so  libc.so.6  readme  solve.py
```
