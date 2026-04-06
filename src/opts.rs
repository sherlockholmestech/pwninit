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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchMode {
    Patchelf,
    Manual,
}

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

/// Challenge type to initialize (default: pwn)
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
    /// Path to the challenge binary (auto-detected if not set)
    #[structopt(long)]
    #[setters(generate)]
    pub bin: Option<PathBuf>,

    /// Path to the challenge libc (auto-detected if not set)
    #[structopt(long)]
    #[setters(generate)]
    pub libc: Option<PathBuf>,

    /// Path to the ELF interpreter / dynamic linker (auto-detected if not set)
    #[structopt(long)]
    #[setters(generate)]
    pub ld: Option<PathBuf>,

    /// Path to a custom pwntools solve script template (uses built-in template if not set)
    #[structopt(long)]
    pub template_path: Option<PathBuf>,

    /// Variable name for the binary in the solve script template
    #[structopt(long, default_value = "exe")]
    pub template_bin_name: String,

    /// Variable name for the libc in the solve script template
    #[structopt(long, default_value = "libc")]
    pub template_libc_name: String,

    /// Variable name for the linker in the solve script template
    #[structopt(long, default_value = "ld")]
    pub template_ld_name: String,

    /// Create a uv virtual environment with pwntools installed
    #[structopt(long)]
    pub uv: bool,

    /// Skip patching the binary entirely
    #[structopt(long)]
    pub no_patch_bin: bool,

    /// Use manual ELF byte patching instead of patchelf
    #[structopt(long)]
    pub no_patchelf: bool,

    /// Skip generating the solve script template
    #[structopt(long)]
    pub no_template: bool,
}

/// Options for rev challenge initialization
#[derive(StructOpt, Setters, Clone)]
#[setters(generate = "false")]
#[setters(prefix = "with_")]
pub struct RevOpts {
    /// Path to the challenge binary (auto-detected if not set)
    #[structopt(long)]
    #[setters(generate)]
    pub bin: Option<PathBuf>,

    /// Path to a custom angr solve script template (uses built-in template if not set)
    #[structopt(long)]
    pub template_path: Option<PathBuf>,

    /// Variable name for the binary in the solve script template
    #[structopt(long, default_value = "exe")]
    pub template_bin_name: String,

    /// Create a uv virtual environment with angr + z3 installed
    #[structopt(long)]
    pub uv: bool,

    /// Skip generating the solve script template
    #[structopt(long)]
    pub no_template: bool,
}

/// Options for downloading a libc by version
#[derive(StructOpt, Clone)]
pub struct FetchLibcOpts {
    /// glibc version to download, e.g. "2.31"
    pub version: String,

    /// Target architecture
    #[structopt(long, default_value = "amd64", possible_values = &["amd64", "i386"])]
    pub arch: CpuArch,

    /// Output path for the downloaded libc
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
            no_patchelf: false,
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
    pub fn resolved_patch_mode(&self) -> PatchMode {
        if self.no_patchelf {
            PatchMode::Manual
        } else {
            PatchMode::Patchelf
        }
    }

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
