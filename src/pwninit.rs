use crate::fetch_libc;
use crate::maybe_visit_libc;
use crate::opts::{self, Command, Opts};
use crate::patch_bin;
use crate::set_bin_exec_pwn;
use crate::set_bin_exec_rev;
use crate::set_ld_exec;
use crate::solvepy;
use crate::uv_venv;

use ex::io;
use snafu::ResultExt;
use snafu::Snafu;

/// Top-level `pwninit` error
#[derive(Debug, Snafu)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed setting binary executable: {}", source))]
    SetBinExec { source: io::Error },

    #[snafu(display("failed locating provided files (binary, libc, linker): {}", source))]
    Find { source: opts::Error },

    #[snafu(display("failed setting linker executable: {}", source))]
    SetLdExec { source: io::Error },

    #[snafu(display("failed patching binary: {}", source))]
    PatchBin { source: patch_bin::Error },

    #[snafu(display("failed setting up uv virtual environment: {}", source))]
    UvVenv { source: uv_venv::Error },

    #[snafu(display("failed making template solve script: {}", source))]
    Solvepy { source: solvepy::Error },

    #[snafu(display("failed downloading libc: {}", source))]
    FetchLibc { source: fetch_libc::Error },
}

pub type Result = std::result::Result<(), Error>;

fn run_fetch_libc(fetch_opts: crate::opts::FetchLibcOpts) -> Result {
    fetch_libc::fetch_libc_interactive(&fetch_opts.version, fetch_opts.arch, &fetch_opts.output)
        .context(FetchLibcSnafu)
}

fn run_rev_flow(rev_opts: crate::opts::RevOpts) -> Result {
    set_bin_exec_rev(&rev_opts).context(SetBinExecSnafu)?;

    if rev_opts.uv {
        uv_venv::ensure_uv_venv(&["angr[unicorn]", "z3-solver"]).context(UvVenvSnafu)?;
    }

    if !rev_opts.no_template {
        solvepy::write_stub_rev(&rev_opts).context(SolvepySnafu)?;
    }

    Ok(())
}

fn run_pwn_flow(mut pwn_opts: crate::opts::PwnOpts) -> Result {
    set_bin_exec_pwn(&pwn_opts).context(SetBinExecSnafu)?;
    maybe_visit_libc(&pwn_opts);

    // Redo detection in case the ld was downloaded.
    pwn_opts = Opts {
        pwn: pwn_opts,
        cmd: None,
    }
    .find_if_unspec()
    .context(FindSnafu)?
    .pwn;

    set_ld_exec(&pwn_opts).context(SetLdExecSnafu)?;

    if pwn_opts.uv {
        uv_venv::ensure_uv_venv(&["pwntools"]).context(UvVenvSnafu)?;
    }

    if !pwn_opts.no_patch_bin {
        patch_bin::patch_bin(&pwn_opts).context(PatchBinSnafu)?;
    }

    if !pwn_opts.no_template {
        solvepy::write_stub_pwn(&pwn_opts).context(SolvepySnafu)?;
    }

    Ok(())
}

/// Run `pwninit` with specified options
pub fn run(opts: Opts) -> Result {
    // Detect unspecified files
    let opts = opts.find_if_unspec().context(FindSnafu)?;

    // Print detected files
    opts.print();
    println!();

    match opts.cmd {
        Some(Command::FetchLibc(fetch_opts)) => run_fetch_libc(fetch_opts),
        Some(Command::Rev(rev_opts)) => run_rev_flow(rev_opts),
        None => run_pwn_flow(opts.pwn),
    }
}
