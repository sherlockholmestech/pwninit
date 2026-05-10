# pwninit

[![Build Status](https://github.com/sherlockholmestech/pwninit/workflows/Build/badge.svg)](https://github.com/sherlockholmestech/pwninit/actions)
[![Crates.io](https://img.shields.io/crates/v/pwninit)](https://crates.io/crates/pwninit)
[![Docs.rs](https://docs.rs/pwninit/badge.svg)](https://docs.rs/pwninit)

A tool for automating starting binary exploit challenges, as well as reverse engineering ones.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Features](#features)
- [Usage](#usage)
  - [Pwn Challenges](#pwn-challenges)
  - [Reverse Engineering Challenges](#reverse-engineering-challenges)
  - [Fetching Additional Libraries](#fetching-additional-libraries)
- [Advanced Configuration](#advanced-configuration)
  - [Virtual Environments](#virtual-environments)
  - [Patching Modes](#patching-modes)
  - [Custom Templates](#custom-templates)

## Installation

You can build `pwninit` from source using `cargo`. Note that `openssl`, `liblzma`, and `pkg-config` are required system dependencies for the build process.

```sh
cargo build --release
```

The compiled binary will be available in the `target/release` directory.

## Quick Start

Run `pwninit` in a directory containing your challenge files. It will automatically detect the binary and libc, fetch the appropriate linker, patch the binary, and generate a solve script.

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

## Features

- Automatically sets challenge binaries as executable.
- Downloads a matching linker (`ld-linux.so.*`) to segfaultlessly load the provided libc.
- Fetches debug symbols and unstrips the libc automatically.
- Patches binaries using `patchelf` (or natively) to set the correct `RPATH` and `PT_INTERP`.
- Downloads additional libraries from the same libc package on demand.
- Generates template solve scripts for both `pwntools` and `angr` / `z3`.
- Supports creating local `uv` virtual environments (`.venv`) for python dependencies.

## Usage

### Pwn Challenges

Simply run `pwninit` in a directory with the relevant files. It automatically detects the binary, libc, and linker.

```sh
pwninit
```

If the automatic detection is incorrect, you can manually specify the file paths:

```sh
pwninit --bin ./challenge_bin --libc ./libc.so.6 --ld ./ld-linux.so.2
```

### Reverse Engineering Challenges

For reverse engineering tasks, run the `rev` subcommand. It will detect the reverse engineering binary and generate an `angr` + `z3` template.

```sh
pwninit rev
```

Manual binary specification is also supported:

```sh
pwninit rev --bin ./challenge_bin
```

### Fetching Additional Libraries

You can fetch extra libraries from a specific libc package using the `fetch-libc` subcommand.

```sh
pwninit fetch-libc <version> --lib <name>
```

- This option is repeatable.
- It accepts sonames such as `libm.so.6`, `libdl.so.2`, or `libnss_dns.so.2`.
- It also supports aliases like `libm` and `libpthread` (mapping to `libm.so.6` and `libpthread.so.0`).

## Advanced Configuration

### Virtual Environments

You can instruct `pwninit` to automatically create a local `uv` virtual environment in `.venv` and install required packages (`pwntools` for pwn, `angr` + `z3-solver` for rev).

```sh
pwninit --uv
```

By default, no virtual environment is created.

### Patching Modes

By default, binary patching relies on [`patchelf`](https://github.com/NixOS/patchelf) to set the `RPATH` to `.` and the interpreter to `./ld`.

You can opt for a manual patching mode that directly rewrites `PT_INTERP` and `DT_NEEDED` entries in place to short local names (e.g. `./ld`, `./libc`).

```sh
pwninit --no-patchelf
```

*Note:* Both modes create the necessary symlinks (`ld`, `libc`, etc.) in the challenge directory. The `--no-patchelf` flag only applies replacements that fit within the original ELF string slot; oversized or unresolved entries are skipped with a warning.

### Custom Templates

If you prefer a different `solve.py` boilerplate, you can provide a custom template path. The names of the `exe`, `libc`, and `ld` bindings can also be customized.

```sh
pwninit --template-path <path> \
        --template-bin-name exe \
        --template-libc-name libc \
        --template-ld-name ld
```

For the exact template format and available variables, refer to [`src/template.py`](src/template.py).

#### Persisting Custom Templates

To automatically load your custom template on every run, you can add an alias to your shell configuration file (e.g., `~/.bashrc` or `~/.zshrc`).

```bash
alias pwninit='pwninit --template-path ~/.config/pwninit-template.py --template-bin-name e'
```
