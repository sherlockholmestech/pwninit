# AGENTS.md

## Build

```sh
cargo build --release
```

Requires system packages: `openssl`, `liblzma`, `pkg-config`.

## Test

```sh
cargo test
```

Unit tests only (in-module `#[cfg(test)]` blocks). No CI test suite — tests run locally.

## Lint / Typecheck

No lint or format config in the repo. Rust `cargo check` is the closest to typecheck:

```sh
cargo check
```

## Architecture

Single crate, flat module structure under `src/`. Entry points:

| File | Role |
|---|---|
| `src/main.rs` | Minimal main, calls `pwninit::run(opts)` |
| `src/pwninit.rs` | Top-level orchestration — dispatches to pwn / rev / fetch-libc flows |
| `src/opts.rs` | CLI parsing via `structopt` (not clap 3+). 3 subcommands: default pwn, `rev`, `fetch-libc` |
| `src/lib.rs` | Shared helpers: ELF-based file detection (`is_bin`, `is_libc`, `is_ld`), `visit_libc` pipeline |
| `src/elf/` | Internal ELF parsing and detection (32/64 bit) |
| `src/patch_bin.rs` | Binary patching: `patchelf` mode (default) or manual `--no-patchelf` mode that rewrites `PT_INTERP` / `DT_NEEDED` in-place |
| `src/solvepy.rs` | Template solve script generation using `strfmt` with `{bindings}`, `{bin_name}`, `{proc_args}` placeholders |
| `src/uv_venv.rs` | `uv` virtual env setup (`.venv/`), installs `pwntools` (pwn) or `angr` + `z3-solver` (rev) |
| `src/template.py` / `src/template_rev.py` | Built-in Python solve script templates (embedded via `include_str!`) |

## Key Conventions

- **File detection** is by name substring: libc must contain `libc`, linker must contain `ld-`, binary is any other ELF not ending in `_patched`.
- **Template variables** use `strfmt`/`{key}` syntax, not Python `.format()` or Jinja. Custom templates must respect the existing keys.
- **`--no-patchelf`** switches to manual ELF patching that only works when the new string fits in the original slot. Oversized entries are skipped with a warning.
- **`uv`** is an external dependency — `pwninit` shell-outs to it; the `--uv` flag makes it required.
- **Error handling** uses `snafu` for structured errors, `colored` for terminal output.
- **Release profile** is aggressive: `opt-level = 'z'` + `lto = true`.
