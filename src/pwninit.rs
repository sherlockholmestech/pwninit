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
}

pub type Result = std::result::Result<(), Error>;

/// Run `pwninit` with specified options
pub fn run(opts: Opts) -> Result {
    // Detect unspecified files
    let opts = opts.find_if_unspec().context(FindSnafu)?;

    // Print detected files
    opts.print();
    println!();

    match opts.cmd {
        Some(Command::Rev(rev_opts)) => {
            set_bin_exec_rev(&rev_opts).context(SetBinExecSnafu)?;

            if rev_opts.uv {
                uv_venv::ensure_uv_venv(&["angr", "z3-solver"]).context(UvVenvSnafu)?;
            }

            if !rev_opts.no_template {
                solvepy::write_stub_rev(&rev_opts).context(SolvepySnafu)?;
            }
        }
        None => {
            let pwn_opts = opts.pwn;
            set_bin_exec_pwn(&pwn_opts).context(SetBinExecSnafu)?;
            maybe_visit_libc(&pwn_opts);

            // Redo detection in case the ld was downloaded
            let opts = Opts {
                pwn: pwn_opts,
                cmd: None,
            }
            .find_if_unspec()
            .context(FindSnafu)?;

            let pwn_opts = opts.pwn;

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
        }
    }

    Ok(())
}
