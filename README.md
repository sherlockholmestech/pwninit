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
  - [Output and Automation](#output-and-automation)

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

$ pwninit pwn
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
- Fetches debug symbols and unstrips libc plus related glibc shared libraries in the challenge directory automatically.
- Patches binaries using `patchelf` (or natively) to set the correct `RPATH` and `PT_INTERP`.
- Downloads additional libraries from the same libc package on demand.
- Generates template solve scripts for both `pwntools` and `angr` / `z3`.
- Supports creating local `uv` virtual environments (`.venv`) for python dependencies.

## Usage

### Pwn Challenges

Run the `pwn` subcommand in a directory with the relevant files. It automatically detects the binary, libc, and linker.

```sh
pwninit pwn
```

Bare `pwninit` remains supported for compatibility and performs the same pwn workflow.

If the automatic detection is incorrect, you can manually specify the file paths:

```sh
pwninit pwn --bin ./challenge_bin --libc ./libc.so.6 --ld ./ld-linux.so.2
```

During pwn initialization, debug symbols are selected automatically based on the detected glibc package. Override the repository when needed with `--debug-source`:

```sh
pwninit pwn --debug-source launchpad
pwninit pwn --debug-source debian
```

Use `--no-unstrip` to skip downloading debug symbols entirely. The standalone `fetch-libc` command only downloads packaged runtime files and does not unstrip them.

The command fails before changing files when no binary is found. If multiple candidate binaries, libcs, or linkers are present, specify the intended path explicitly instead of relying on directory order.

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

The `fetch-libc` subcommand supports Launchpad, Docker, and Debian sources. Launchpad is the default:

```sh
pwninit fetch-libc 2.31 --lib libm.so.6
```

Use Docker by supplying an image or a distro/release pair:

```sh
pwninit fetch-libc --source docker --image ubuntu:22.04
pwninit fetch-libc --source docker --distro debian --release bookworm
```

Use a Debian repository by supplying both a version prefix and release:

```sh
pwninit fetch-libc 2.36 --source debian --release bookworm
```

When multiple package versions match, the Launchpad and Debian sources prompt for a selection. For scripts, disable prompts and optionally select the complete package version:

```sh
pwninit fetch-libc 2.31 --non-interactive
pwninit fetch-libc 2.31 --exact-version 2.31-0ubuntu9.18
```

An ambiguous `--non-interactive` lookup fails and lists the available versions. EOF during an interactive selection also produces an error instead of retrying indefinitely.

`--lib` is repeatable and accepts sonames such as `libm.so.6`, `libdl.so.2`, or `libnss_dns.so.2`. Aliases such as `libm` and `libpthread` are normalized automatically. Use `--from-bin` to inspect one binary and fetch its missing glibc package dependencies explicitly:

```sh
pwninit fetch-libc 2.31 --from-bin ./challenge
```

Place every downloaded artifact in one directory with `--output-dir`. Use `--libc-output` to change the libc path relative to that directory:

```sh
pwninit fetch-libc 2.31 --output-dir ./runtime --libc-output libc-custom.so.6
```

The previous `--output` option remains an alias for `--libc-output`.

## Advanced Configuration

### Virtual Environments

You can instruct `pwninit` to automatically create a local `uv` virtual environment in `.venv` and install required packages (`pwntools` for pwn, `angr` + `z3-solver` for rev).

```sh
pwninit pwn --uv
```

By default, no virtual environment is created.

### Patching Modes

Select the patching strategy with `--patch-mode`:

```sh
pwninit pwn --patch-mode patchelf
pwninit pwn --patch-mode manual
pwninit pwn --patch-mode none
```

The default `patchelf` mode sets the `RPATH` to `.` whenever local shared libraries are present and sets the interpreter to `./ld`. Manual mode rewrites each matching `DT_NEEDED` entry to a short local alias such as `./libm` and rewrites `PT_INTERP` to `./ld`. This applies to downloaded companions such as `libm.so.6`, `libpthread.so.0`, and `libnss_*.so.2`, not only libc.

Both active modes create the necessary symlinks. Manual replacements must fit within the original ELF string slot; oversized or unresolved entries are skipped with a warning. The deprecated `--no-patchelf` and `--no-patch-bin` options remain available as compatibility aliases.

### Custom Templates

If you prefer a different `solve.py` boilerplate, you can provide a custom template path. The names of the `exe`, `libc`, and `ld` bindings can also be customized.

```sh
pwninit pwn --template-path <path> \
        --template-bin-name exe \
        --template-libc-name libc \
        --template-ld-name ld
```

Binding names must be valid, distinct Python identifiers and cannot be Python keywords.

By default, the solve script is written to `solve.py`. Existing files are preserved and reported as skipped:

```sh
pwninit pwn --solve-path scripts/solve.py
pwninit pwn --solve-path scripts/solve.py --force
```

For the exact template format and available variables, refer to [`src/template.py`](src/template.py).

#### Persisting Custom Templates

To automatically load your custom template on every run, you can add an alias to your shell configuration file (e.g., `~/.bashrc` or `~/.zshrc`).

```bash
alias pwninit-pwn='pwninit pwn --template-path ~/.config/pwninit-template.py --template-bin-name e'
```

### Output and Automation

Every workflow prints a final completed, skipped, and failed step summary. Required step failures return a nonzero exit status. `--best-effort` continues independent steps after a failure but still returns a failure status when a required step did not complete.

```sh
pwninit pwn --best-effort
```

Use `--quiet` for a count-only summary, `--verbose` for additional diagnostics, or `--json` for one machine-readable result on stdout:

```sh
pwninit pwn --quiet
pwninit pwn --verbose
pwninit pwn --json
```

JSON package fetching requires `--non-interactive` or `--exact-version`. The installed version is available through `pwninit --version`.
