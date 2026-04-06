//! Command-line option handling

use crate::cpu_arch::CpuArch;
use crate::elf;
use crate::is_bin;
use crate::is_ld;
use crate::is_libc;

use std::path::Path;
use std::path::PathBuf;

use colored::Color;
use colored::Colorize;
use derive_setters::Setters;
use ex::fs;
use ex::io;
use snafu::ResultExt;
use snafu::Snafu;
use structopt::StructOpt;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("ELF detection error: {}", source))]
    ElfDetect { source: elf::detect::Error },

    #[snafu(display("failed reading current directory entry: {}", source))]
    DirEnt { source: io::Error },

    #[snafu(display("failed reading current directory: {}", source))]
    ReadDir { source: io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

fn fold_current_dir<T, F>(init: T, mut merge: F) -> Result<T>
where
    F: FnMut(T, fs::DirEntry) -> elf::detect::Result<T>,
{
    fs::read_dir(".")
        .context(ReadDirSnafu)?
        .try_fold(init, |acc, dir_ent| {
            let dir_ent = dir_ent.context(DirEntSnafu)?;
            merge(acc, dir_ent).context(ElfDetectSnafu)
        })
}

fn detect_path_if(
    dir_ent: &fs::DirEntry,
    pred: fn(&Path) -> elf::detect::Result<bool>,
) -> elf::detect::Result<Option<PathBuf>> {
    let path = dir_ent.path();
    Ok(if pred(&path)? { Some(path) } else { None })
}

/// automate starting binary exploit and reverse engineering challenges
#[derive(StructOpt, Clone)]
pub struct Opts {
    /// Pwn challenge options (default when no subcommand is provided)
    #[structopt(flatten)]
    pub pwn: PwnOpts,

    /// Challenge type to initialize
    #[structopt(subcommand)]
    pub cmd: Option<Command>,
}

/// Supported challenge types
#[derive(StructOpt, Clone)]
pub enum Command {
    /// Reverse engineering challenge
    Rev(RevOpts),

    /// Download a libc by version without a local libc file
    FetchLibc(FetchLibcOpts),
}

/// Options for pwn challenge initialization
#[derive(StructOpt, Setters, Clone)]
#[setters(generate = "false")]
#[setters(prefix = "with_")]
pub struct PwnOpts {
    /// Binary to pwn
    #[structopt(long)]
    #[setters(generate)]
    pub bin: Option<PathBuf>,

    /// Challenge libc
    #[structopt(long)]
    #[setters(generate)]
    pub libc: Option<PathBuf>,

    /// A linker to preload the libc
    #[structopt(long)]
    #[setters(generate)]
    pub ld: Option<PathBuf>,

    /// Path to custom pwntools solve script template. Check the README for more
    /// information.
    #[structopt(long)]
    pub template_path: Option<PathBuf>,

    /// Name of binary variable for pwntools solve script
    #[structopt(long)]
    #[structopt(default_value = "exe")]
    pub template_bin_name: String,

    /// Name of libc variable for pwntools solve script
    #[structopt(long)]
    #[structopt(default_value = "libc")]
    pub template_libc_name: String,

    /// Name of linker variable for pwntools solve script
    #[structopt(long)]
    #[structopt(default_value = "ld")]
    pub template_ld_name: String,

    /// Create a uv virtual environment with pwntools
    #[structopt(long)]
    pub uv: bool,

    /// Disable running patchelf on binary
    #[structopt(long)]
    pub no_patch_bin: bool,

    /// Disable generating template solve script
    #[structopt(long)]
    pub no_template: bool,
}

/// Options for rev challenge initialization
#[derive(StructOpt, Setters, Clone)]
#[setters(generate = "false")]
#[setters(prefix = "with_")]
pub struct RevOpts {
    /// Binary to reverse
    #[structopt(long)]
    #[setters(generate)]
    pub bin: Option<PathBuf>,

    /// Path to custom solve script template. Check the README for more
    /// information.
    #[structopt(long)]
    pub template_path: Option<PathBuf>,

    /// Name of binary variable for solve script
    #[structopt(long)]
    #[structopt(default_value = "exe")]
    pub template_bin_name: String,

    /// Create a uv virtual environment with angr + z3
    #[structopt(long)]
    pub uv: bool,

    /// Disable generating template solve script
    #[structopt(long)]
    pub no_template: bool,
}

/// Options for downloading a libc by version
#[derive(StructOpt, Clone)]
pub struct FetchLibcOpts {
    /// Short glibc version to search for, e.g. "2.31"
    #[structopt(long)]
    pub version: String,

    /// Target architecture: "amd64" (default) or "i386"
    #[structopt(long, default_value = "amd64")]
    pub arch: CpuArch,

    /// Output path for the downloaded libc (default: "libc.so.6")
    #[structopt(long, default_value = "libc.so.6")]
    pub output: PathBuf,
}

impl Default for PwnOpts {
    fn default() -> Self {
        Self {
            bin: None,
            libc: None,
            ld: None,
            template_path: None,
            template_bin_name: "exe".to_string(),
            template_libc_name: "libc".to_string(),
            template_ld_name: "ld".to_string(),
            uv: false,
            no_patch_bin: false,
            no_template: false,
        }
    }
}

impl Default for RevOpts {
    fn default() -> Self {
        Self {
            bin: None,
            template_path: None,
            template_bin_name: "exe".to_string(),
            uv: false,
            no_template: false,
        }
    }
}

impl Opts {
    /// Print the locations of known files (binary, libc, linker)
    pub fn print(&self) {
        let f = |opt_path: &Option<PathBuf>, header: &str, color| {
            if let Some(path) = opt_path {
                println!(
                    "{}: {}",
                    header.color(color),
                    path.to_string_lossy().bold().color(color)
                )
            }
        };

        match &self.cmd {
            Some(Command::Rev(opts)) => {
                f(&opts.bin, "bin", Color::BrightBlue);
            }
            Some(Command::FetchLibc(_)) => {}
            None => {
                f(&self.pwn.bin, "bin", Color::BrightBlue);
                f(&self.pwn.libc, "libc", Color::Yellow);
                f(&self.pwn.ld, "ld", Color::Green);
            }
        }
    }

    /// For the unspecified files, try to guess their path
    pub fn find_if_unspec(self) -> Result<Self> {
        match self.cmd {
            Some(Command::Rev(opts)) => {
                let opts = fold_current_dir(opts, RevOpts::merge_entry)?;
                Ok(Opts {
                    pwn: self.pwn,
                    cmd: Some(Command::Rev(opts)),
                })
            }
            Some(Command::FetchLibc(opts)) => Ok(Opts {
                pwn: self.pwn,
                cmd: Some(Command::FetchLibc(opts)),
            }),
            None => {
                let pwn = fold_current_dir(self.pwn, PwnOpts::merge_entry)?;
                Ok(Opts { pwn, cmd: None })
            }
        }
    }
}

impl PwnOpts {
    /// Helper for `find_if_unspec()`, merging the options with a directory entry.
    fn merge_entry(self, dir_ent: fs::DirEntry) -> elf::detect::Result<Self> {
        Ok(self
            .clone()
            .with_bin(self.bin.or(detect_path_if(&dir_ent, is_bin)?))
            .with_libc(self.libc.or(detect_path_if(&dir_ent, is_libc)?))
            .with_ld(self.ld.or(detect_path_if(&dir_ent, is_ld)?)))
    }
}

impl RevOpts {
    /// Helper for `find_if_unspec()`, merging the options with a directory entry.
    fn merge_entry(self, dir_ent: fs::DirEntry) -> elf::detect::Result<Self> {
        Ok(self
            .clone()
            .with_bin(self.bin.or(detect_path_if(&dir_ent, is_bin)?)))
    }
}
