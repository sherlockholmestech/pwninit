//! Utility functions that provide the bulk of `pwninit` functionality

mod cpu_arch;
mod elf;
mod fetch_ld;
mod fetch_libc;
mod http_retry;
mod libc_deb;
mod libc_search;
mod libc_version;
pub mod opts;
mod patch_bin;
mod pwninit;
mod set_exec;
mod solvepy;
mod unstrip_libc;
mod uv_venv;
mod warn;

pub use crate::pwninit::run;
pub use crate::pwninit::Result;

use crate::elf::detect::is_elf;
pub use crate::fetch_ld::fetch_ld;
pub use crate::fetch_libc::fetch_libc;
pub use crate::fetch_libc::fetch_libc_lib;
pub use crate::fetch_libc::fetch_libm;
pub use crate::fetch_libc::fetch_libpthread;
use crate::libc_version::LibcVersion;
use crate::opts::{PwnOpts, RevOpts};
pub use crate::set_exec::set_exec;
pub use crate::unstrip_libc::unstrip_libc;
use crate::warn::Warn;
use crate::warn::WarnResult;

use std::path::{Path, PathBuf};

use colored::Color;
use colored::Colorize;
use ex::io;
use is_executable::IsExecutable;

/// Detect if `path` is the provided pwn binary
pub fn is_bin(path: &Path) -> elf::detect::Result<bool> {
    let is_patched = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with("_patched"))
        .unwrap_or(false);
    Ok(!is_patched && is_elf(path)? && !is_libc(path)? && !is_ld(path)?)
}

/// Detect whether the filename of `path` starts with one of `prefixes`.
fn path_name_starts_with(path: &Path, prefixes: &[&str]) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| prefixes.iter().any(|prefix| name.starts_with(prefix)))
        .unwrap_or(false)
}

/// Detect if `path` is the provided libc
pub fn is_libc(path: &Path) -> elf::detect::Result<bool> {
    Ok(is_elf(path)? && path_name_starts_with(path, &["libc.", "libc-"]))
}

/// Detect if `path` is the provided linker
pub fn is_ld(path: &Path) -> elf::detect::Result<bool> {
    Ok(is_elf(path)? && path_name_starts_with(path, &["ld-"]))
}

/// Same as `fetch_ld()`, but doesn't do anything if an existing linker is
/// detected
fn maybe_fetch_ld(opts: &PwnOpts, ver: &LibcVersion) -> fetch_ld::Result {
    match opts.ld {
        Some(_) => Ok(()),
        None => fetch_ld(ver),
    }
}

/// Top-level function for libc-dependent tasks
///   1. Download linker if not found
///   2. Unstrip libc if libc is stripped
fn visit_libc(opts: &PwnOpts, libc: &Path) {
    let ver = match LibcVersion::detect(libc) {
        Ok(ver) => ver,
        Err(err) => {
            err.warn("failed detecting libc version (is the libc an Ubuntu glibc?)");
            return;
        }
    };
    maybe_fetch_ld(opts, &ver).warn("failed fetching ld");
    unstrip_libc(libc, &ver).warn("failed unstripping libc");
}

/// Same as `visit_libc()`, but doesn't do anything if no libc is found
pub fn maybe_visit_libc(opts: &PwnOpts) {
    if let Some(libc) = &opts.libc {
        visit_libc(opts, libc)
    }
}

fn set_exec_if_needed(
    path: &Option<PathBuf>,
    label: &str,
    color: Color,
    warn_on_missing: bool,
) -> io::Result<()> {
    match path {
        Some(path) if !path.is_executable() => {
            println!(
                "{}",
                format!("setting {} executable", path.to_string_lossy().bold()).color(color)
            );
            set_exec(path)
        }
        None if warn_on_missing => {
            format!("{} not found", label).warn("failed setting executable");
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Set the binary executable (pwn)
pub fn set_bin_exec_pwn(opts: &PwnOpts) -> io::Result<()> {
    set_exec_if_needed(&opts.bin, "binary", Color::BrightBlue, true)
}

/// Set the binary executable (rev)
pub fn set_bin_exec_rev(opts: &RevOpts) -> io::Result<()> {
    set_exec_if_needed(&opts.bin, "binary", Color::BrightBlue, true)
}

/// Set the detected linker executable
pub fn set_ld_exec(opts: &PwnOpts) -> io::Result<()> {
    set_exec_if_needed(&opts.ld, "linker", Color::Green, false)
}
