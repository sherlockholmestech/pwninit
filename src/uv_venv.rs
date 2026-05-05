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
    Exec { source: io::Error },

    #[snafu(display("uv command failed with nonzero exit status"))]
    CommandFailed,
}

pub type Result<T = ()> = std::result::Result<T, Error>;

fn run_uv(args: &[&str]) -> Result<()> {
    let status = Command::new("uv").args(args).status().context(ExecSnafu)?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::CommandFailed)
    }
}

/// Ensure a local uv virtual environment exists and has required packages installed.
/// This creates `.venv` if it does not already exist.
pub fn ensure_uv_venv(packages: &[&str]) -> Result {
    let venv_path = Path::new(".venv");
    if !venv_path.exists() {
        println!("{}", "creating uv virtual environment".cyan().bold());
        run_uv(&["venv", ".venv"])?;
    }

    println!("{}", "installing packages with uv".cyan().bold());
    let mut args = vec!["pip", "install", "--python", ".venv/bin/python"];
    args.extend_from_slice(packages);
    run_uv(&args)
}
