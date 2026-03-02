//! uv virtual environment setup helper

use std::io;
use std::path::Path;
use std::process::Command;

use colored::Colorize;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("uv failed to start; please install uv: {}", source))]
    UvExec { source: io::Error },

    #[snafu(display("uv venv failed with nonzero exit status"))]
    UvVenv,

    #[snafu(display("uv pip install failed with nonzero exit status"))]
    UvPipInstall,
}

pub type Result<T = ()> = std::result::Result<T, Error>;

fn run_uv(args: &[&str]) -> Result<()> {
    let status = Command::new("uv")
        .args(args)
        .status()
        .context(UvExecSnafu)?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::UvPipInstall)
    }
}

/// Ensure a local uv virtual environment exists and has required packages installed.
/// This creates `.venv` if it does not already exist.
pub fn ensure_uv_venv(packages: &[&str]) -> Result {
    let venv_path = Path::new(".venv");
    if !venv_path.exists() {
        println!("{}", "creating uv virtual environment".cyan().bold());
        let status = Command::new("uv")
            .args(["venv", ".venv"])
            .status()
            .context(UvExecSnafu)?;
        if !status.success() {
            return Err(Error::UvVenv);
        }
    }

    println!("{}", "installing packages with uv".cyan().bold());
    let mut args = vec!["pip", "install", "--python", ".venv/bin/python"];
    args.extend_from_slice(packages);
    run_uv(&args)
}
