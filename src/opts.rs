//! Command-line option handling

use crate::cpu_arch::CpuArch;
use crate::elf;
use crate::is_bin;
use crate::is_ld;
use crate::is_libc;

use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use clap::{Args, Parser, Subcommand, ValueEnum};
use colored::Color;
use colored::Colorize;
use derive_setters::Setters;
use ex::fs;
use ex::io;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchMode {
    Patchelf,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FetchLibcSource {
    Launchpad,
    Docker,
}

impl FromStr for FetchLibcSource {
    type Err = String;

    fn from_str(source: &str) -> std::result::Result<Self, Self::Err> {
        match source {
            "launchpad" => Ok(Self::Launchpad),
            "docker" => Ok(Self::Docker),
            _ => Err(format!(
                "unknown fetch source: {}, expected launchpad or docker",
                source
            )),
        }
    }
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

pub(crate) fn fold_current_dir<T, F>(init: T, mut merge: F) -> Result<T>
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
#[derive(Parser, Clone)]
pub struct Opts {
    /// Pwn challenge options (default when no subcommand is provided)
    #[command(flatten)]
    pub pwn: PwnOpts,

    /// Challenge type to initialize
    #[command(subcommand)]
    pub cmd: Option<Command>,
}

/// Challenge type to initialize (default: pwn)
#[derive(Subcommand, Clone)]
pub enum Command {
    /// Reverse engineering challenge
    Rev(RevOpts),

    /// Download a libc by version without a local libc file
    FetchLibc(FetchLibcOpts),
}

/// Options for pwn challenge initialization
#[derive(Args, Setters, Clone)]
#[setters(generate = "false")]
#[setters(prefix = "with_")]
pub struct PwnOpts {
    /// Path to the challenge binary (auto-detected if not set)
    #[arg(long)]
    #[setters(generate)]
    pub bin: Option<PathBuf>,

    /// Path to the challenge libc (auto-detected if not set)
    #[arg(long)]
    #[setters(generate)]
    pub libc: Option<PathBuf>,

    /// Path to the ELF interpreter / dynamic linker (auto-detected if not set)
    #[arg(long)]
    #[setters(generate)]
    pub ld: Option<PathBuf>,

    /// Path to a custom pwntools solve script template (uses built-in template if not set)
    #[arg(long)]
    pub template_path: Option<PathBuf>,

    /// Variable name for the binary in the solve script template
    #[arg(long, default_value = "exe")]
    pub template_bin_name: String,

    /// Variable name for the libc in the solve script template
    #[arg(long, default_value = "libc")]
    pub template_libc_name: String,

    /// Variable name for the linker in the solve script template
    #[arg(long, default_value = "ld")]
    pub template_ld_name: String,

    /// Create a uv virtual environment with pwntools installed
    #[arg(long)]
    pub uv: bool,

    /// Skip patching the binary entirely
    #[arg(long)]
    pub no_patch_bin: bool,

    /// Use manual ELF byte patching instead of patchelf
    #[arg(long)]
    pub no_patchelf: bool,

    /// Skip generating the solve script template
    #[arg(long)]
    pub no_template: bool,
}

/// Options for rev challenge initialization
#[derive(Args, Setters, Clone)]
#[setters(generate = "false")]
#[setters(prefix = "with_")]
pub struct RevOpts {
    /// Path to the challenge binary (auto-detected if not set)
    #[arg(long)]
    #[setters(generate)]
    pub bin: Option<PathBuf>,

    /// Path to a custom angr solve script template (uses built-in template if not set)
    #[arg(long)]
    pub template_path: Option<PathBuf>,

    /// Variable name for the binary in the solve script template
    #[arg(long, default_value = "exe")]
    pub template_bin_name: String,

    /// Create a uv virtual environment with angr + z3 installed
    #[arg(long)]
    pub uv: bool,

    /// Skip generating the solve script template
    #[arg(long)]
    pub no_template: bool,
}

/// Options for downloading a libc by version
#[derive(Args, Clone)]
pub struct FetchLibcOpts {
    /// glibc version to download from Launchpad, e.g. "2.31"
    pub version: Option<String>,

    /// libc fetch backend
    #[arg(long, default_value = "launchpad", value_enum)]
    pub source: FetchLibcSource,

    /// Target architecture
    #[arg(long, default_value = "amd64", value_enum)]
    pub arch: CpuArch,

    /// Output path for the downloaded libc
    #[arg(long, default_value = "libc.so.6")]
    pub output: PathBuf,

    /// Additional libc package library to download (repeatable; accepts sonames like libm.so.6)
    #[arg(long = "lib", value_name = "NAME")]
    pub extra_libs: Vec<String>,

    /// Docker image to extract libc files from, e.g. ubuntu:22.04
    #[arg(long)]
    pub image: Option<String>,

    /// Docker image distro name, used with --release, e.g. ubuntu
    #[arg(long)]
    pub distro: Option<String>,

    /// Docker image distro release/tag, used with --distro, e.g. 22.04
    #[arg(long)]
    pub release: Option<String>,
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
            Some(Command::FetchLibc(opts)) => {
                let pwn = fold_current_dir(self.pwn, PwnOpts::merge_entry)?;
                Ok(Opts {
                    pwn,
                    cmd: Some(Command::FetchLibc(opts)),
                })
            }
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

    /// Re-scan the current directory for a linker if one is not already specified.
    pub fn detect_ld(self) -> Result<Self> {
        if self.ld.is_some() {
            return Ok(self);
        }
        fold_current_dir(self, |opts, dir_ent| {
            let ld = detect_path_if(&dir_ent, is_ld)?;
            Ok(opts.with_ld(ld))
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_libc_accepts_repeated_extra_libs() {
        let opts = Opts::try_parse_from([
            "pwninit",
            "fetch-libc",
            "2.31",
            "--lib",
            "libm.so.6",
            "--lib",
            "libnss_dns.so.2",
        ])
        .expect("fetch-libc should parse repeated --lib values");

        let Some(Command::FetchLibc(fetch_opts)) = opts.cmd else {
            panic!("expected fetch-libc command");
        };
        assert_eq!(fetch_opts.extra_libs, ["libm.so.6", "libnss_dns.so.2"]);
    }

    #[test]
    fn fetch_libc_defaults_to_no_extra_libs() {
        let opts = Opts::try_parse_from(["pwninit", "fetch-libc", "2.31"])
            .expect("fetch-libc should parse without --lib");

        let Some(Command::FetchLibc(fetch_opts)) = opts.cmd else {
            panic!("expected fetch-libc command");
        };
        assert!(fetch_opts.extra_libs.is_empty());
    }

    #[test]
    fn pwn_flow_does_not_accept_extra_libs() {
        assert!(Opts::try_parse_from(["pwninit", "--lib", "libm.so.6"]).is_err());
    }

    // -------------------------------------------------------------------
    // VAL-CLI-003: additional `fetch-libc` argument parsing coverage.
    // -------------------------------------------------------------------

    fn parse_fetch_libc(args: &[&str]) -> crate::opts::FetchLibcOpts {
        let mut full = vec!["pwninit", "fetch-libc"];
        full.extend_from_slice(args);
        let opts = Opts::try_parse_from(&full).expect("fetch-libc should parse");
        match opts.cmd {
            Some(Command::FetchLibc(fetch_opts)) => fetch_opts,
            Some(Command::Rev(_)) => panic!("expected fetch-libc command, got rev"),
            None => panic!("expected fetch-libc command, got default pwn"),
        }
    }

    #[test]
    fn fetch_libc_arch_amd64_parses() {
        let fetch_opts = parse_fetch_libc(&["2.31", "--arch", "amd64"]);
        assert_eq!(fetch_opts.arch, CpuArch::Amd64);
        assert_eq!(fetch_opts.version.as_deref(), Some("2.31"));
    }

    #[test]
    fn fetch_libc_arch_i386_parses() {
        let fetch_opts = parse_fetch_libc(&["2.31", "--arch", "i386"]);
        assert_eq!(fetch_opts.arch, CpuArch::I386);
    }

    #[test]
    fn fetch_libc_default_arch_is_amd64() {
        let fetch_opts = parse_fetch_libc(&["2.31"]);
        assert_eq!(fetch_opts.arch, CpuArch::Amd64);
    }

    #[test]
    fn fetch_libc_invalid_arch_is_rejected() {
        assert!(
            Opts::try_parse_from(["pwninit", "fetch-libc", "2.31", "--arch", "armhf"]).is_err(),
            "fetch-libc should reject architectures other than amd64 and i386"
        );
    }

    #[test]
    fn fetch_libc_output_path_is_preserved() {
        let fetch_opts = parse_fetch_libc(&["2.31", "--output", "my/libc/path.so"]);
        assert_eq!(fetch_opts.output, PathBuf::from("my/libc/path.so"));
    }

    #[test]
    fn fetch_libc_default_output_is_libc_so_6() {
        let fetch_opts = parse_fetch_libc(&["2.31"]);
        assert_eq!(fetch_opts.output, PathBuf::from("libc.so.6"));
    }

    #[test]
    fn fetch_libc_positional_version_is_required() {
        let fetch_opts = parse_fetch_libc(&[]);
        assert_eq!(fetch_opts.source, FetchLibcSource::Launchpad);
        assert!(fetch_opts.version.is_none());
    }

    #[test]
    fn fetch_libc_combined_flags_parse_together() {
        let fetch_opts = parse_fetch_libc(&[
            "2.31",
            "--arch",
            "i386",
            "--output",
            "libc.so.6",
            "--lib",
            "libm.so.6",
            "--lib",
            "libdl.so.2",
        ]);
        assert_eq!(fetch_opts.version.as_deref(), Some("2.31"));
        assert_eq!(fetch_opts.arch, CpuArch::I386);
        assert_eq!(fetch_opts.output, PathBuf::from("libc.so.6"));
        assert_eq!(fetch_opts.extra_libs, ["libm.so.6", "libdl.so.2"]);
    }

    #[test]
    fn fetch_libc_docker_image_source_parses_without_version() {
        let fetch_opts = parse_fetch_libc(&["--source", "docker", "--image", "ubuntu:22.04"]);
        assert_eq!(fetch_opts.source, FetchLibcSource::Docker);
        assert!(fetch_opts.version.is_none());
        assert_eq!(fetch_opts.image.as_deref(), Some("ubuntu:22.04"));
    }

    #[test]
    fn fetch_libc_docker_distro_release_source_parses() {
        let fetch_opts = parse_fetch_libc(&[
            "--source",
            "docker",
            "--distro",
            "debian",
            "--release",
            "bookworm",
        ]);
        assert_eq!(fetch_opts.source, FetchLibcSource::Docker);
        assert_eq!(fetch_opts.distro.as_deref(), Some("debian"));
        assert_eq!(fetch_opts.release.as_deref(), Some("bookworm"));
    }

    #[test]
    fn pwn_flow_does_not_accept_fetch_libc_only_flags() {
        // `--arch` belongs to `fetch-libc`, not the pwn flow. A user
        // passing it to the default pwn flow must get a parse error.
        assert!(
            Opts::try_parse_from(["pwninit", "--arch", "amd64"]).is_err(),
            "pwn flow should not accept --arch"
        );
        // `--output` is also fetch-libc-only.
        assert!(
            Opts::try_parse_from(["pwninit", "--output", "libc.so.6"]).is_err(),
            "pwn flow should not accept --output"
        );
    }

    #[test]
    fn rev_subcommand_does_not_accept_fetch_libc_flags() {
        assert!(
            Opts::try_parse_from(["pwninit", "rev", "--lib", "libm.so.6"]).is_err(),
            "rev should not accept --lib"
        );
        assert!(
            Opts::try_parse_from(["pwninit", "rev", "--arch", "amd64"]).is_err(),
            "rev should not accept --arch"
        );
    }

    #[test]
    fn fetch_libc_lib_outside_subcommand_is_rejected() {
        // `--lib` lives under `fetch-libc`; passing it to `rev` or to the
        // pwn flow must fail parsing.
        assert!(Opts::try_parse_from(["pwninit", "rev", "--lib", "libm.so.6"]).is_err());
        assert!(Opts::try_parse_from(["pwninit", "--lib", "libm.so.6"]).is_err());
    }
}
