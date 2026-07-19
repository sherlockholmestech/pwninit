//! Command-line option handling

use crate::cpu_arch::CpuArch;
use crate::elf;
use crate::is_bin;
use crate::is_ld;
use crate::is_libc;
use crate::output;

use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
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
pub enum PatchStrategy {
    Patchelf,
    Manual,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FetchLibcSource {
    Launchpad,
    Docker,
    Debian,
}

/// Repository used to locate debug symbols while initializing a pwn challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DebugSource {
    /// Select Launchpad for Ubuntu glibc and Debian repositories otherwise.
    Auto,
    Launchpad,
    Debian,
}

impl FromStr for FetchLibcSource {
    type Err = String;

    fn from_str(source: &str) -> std::result::Result<Self, Self::Err> {
        match source {
            "launchpad" => Ok(Self::Launchpad),
            "docker" => Ok(Self::Docker),
            "debian" => Ok(Self::Debian),
            _ => Err(format!(
                "unknown fetch source: {}, expected launchpad, docker, or debian",
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

    #[snafu(display(
        "multiple {} candidates found: {}; specify one explicitly",
        kind,
        candidates
    ))]
    Ambiguous {
        kind: &'static str,
        candidates: String,
    },

    #[snafu(display(
        "no challenge binary found; use --bin PATH or run from the challenge directory"
    ))]
    MissingBinary,
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

/// Automate starting binary exploit and reverse engineering challenges
#[derive(Parser, Clone)]
#[command(version)]
pub struct Opts {
    /// Pwn challenge options used when no subcommand is provided
    #[command(flatten)]
    pub pwn: PwnOpts,

    /// Challenge type to initialize
    #[command(subcommand)]
    pub cmd: Option<Command>,

    /// Suppress progress output
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Show additional diagnostic output
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// Emit a machine-readable JSON result
    #[arg(long, global = true)]
    pub json: bool,
}

/// Challenge type to initialize (default: pwn)
#[derive(Subcommand, Clone)]
pub enum Command {
    /// Binary exploitation challenge
    Pwn(PwnOpts),

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
    #[arg(short = 'b', long)]
    #[setters(generate)]
    pub bin: Option<PathBuf>,

    /// Path to the challenge libc (auto-detected if not set)
    #[arg(short = 'l', long)]
    #[setters(generate)]
    pub libc: Option<PathBuf>,

    /// Path to the ELF interpreter / dynamic linker (auto-detected if not set)
    #[arg(short = 'd', long)]
    #[setters(generate)]
    pub ld: Option<PathBuf>,

    /// Path to a custom pwntools solve script template (uses built-in template if not set)
    #[arg(short = 't', long)]
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
    #[arg(short = 'u', long)]
    pub uv: bool,

    /// Binary patching strategy
    #[arg(short = 'p', long, value_enum)]
    pub patch_mode: Option<PatchStrategy>,

    /// Skip patching the binary entirely (deprecated: use --patch-mode none)
    #[arg(long, hide = true, conflicts_with = "patch_mode")]
    pub no_patch_bin: bool,

    /// Use manual ELF byte patching (deprecated: use --patch-mode manual)
    #[arg(long, hide = true, conflicts_with = "patch_mode")]
    pub no_patchelf: bool,

    /// Skip generating the solve script template
    #[arg(long, conflicts_with = "solve_path")]
    pub no_template: bool,

    /// Path for the generated solve script
    #[arg(short = 's', long, default_value = "solve.py")]
    pub solve_path: PathBuf,

    /// Overwrite an existing solve script
    #[arg(short = 'f', long, conflicts_with = "no_template")]
    pub force: bool,

    /// Skip downloading debug symbols and unstripping libc
    #[arg(long)]
    pub no_unstrip: bool,

    /// Repository used to download glibc debug symbols
    #[arg(long, value_enum, default_value = "auto")]
    pub debug_source: DebugSource,

    /// Continue independent setup steps after a failure
    #[arg(long)]
    pub best_effort: bool,
}

/// Options for rev challenge initialization
#[derive(Args, Setters, Clone)]
#[setters(generate = "false")]
#[setters(prefix = "with_")]
pub struct RevOpts {
    /// Path to the challenge binary (auto-detected if not set)
    #[arg(short = 'b', long)]
    #[setters(generate)]
    pub bin: Option<PathBuf>,

    /// Path to a custom angr solve script template (uses built-in template if not set)
    #[arg(short = 't', long)]
    pub template_path: Option<PathBuf>,

    /// Variable name for the binary in the solve script template
    #[arg(long, default_value = "exe")]
    pub template_bin_name: String,

    /// Create a uv virtual environment with angr + z3 installed
    #[arg(short = 'u', long)]
    pub uv: bool,

    /// Skip generating the solve script template
    #[arg(long, conflicts_with = "solve_path")]
    pub no_template: bool,

    /// Path for the generated solve script
    #[arg(short = 's', long, default_value = "solve.py")]
    pub solve_path: PathBuf,

    /// Overwrite an existing solve script
    #[arg(short = 'f', long, conflicts_with = "no_template")]
    pub force: bool,

    /// Continue independent setup steps after a failure
    #[arg(long)]
    pub best_effort: bool,
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
    #[arg(short = 'a', long, default_value = "amd64", value_enum)]
    pub arch: CpuArch,

    /// Directory for all downloaded artifacts
    #[arg(short = 'o', long, default_value = ".")]
    pub output_dir: PathBuf,

    /// File name or path for the downloaded libc
    #[arg(
        short = 'O',
        long,
        visible_alias = "output",
        default_value = "libc.so.6"
    )]
    pub libc_output: PathBuf,

    /// Additional libc package library to download (repeatable; accepts sonames like libm.so.6)
    #[arg(short = 'L', long = "lib", value_name = "NAME")]
    pub extra_libs: Vec<String>,

    /// Read additional required libraries from this binary
    #[arg(short = 'b', long)]
    pub from_bin: Option<PathBuf>,

    /// Docker image to extract libc files from, e.g. ubuntu:22.04
    #[arg(short = 'i', long)]
    pub image: Option<String>,

    /// Docker image distro name, used with --release, e.g. ubuntu
    #[arg(long)]
    pub distro: Option<String>,

    /// Docker image distro release/tag, used with --distro, e.g. 22.04
    #[arg(short = 'r', long)]
    pub release: Option<String>,

    /// Debian repository base URL, used with --source debian
    #[arg(long, default_value = "https://deb.debian.org/debian")]
    pub repo_url: String,

    /// Never prompt when multiple package versions match
    #[arg(long)]
    pub non_interactive: bool,

    /// Select one exact package version without prompting
    #[arg(long, value_name = "VERSION")]
    pub exact_version: Option<String>,
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
            patch_mode: None,
            no_patch_bin: false,
            no_patchelf: false,
            no_template: false,
            solve_path: PathBuf::from("solve.py"),
            force: false,
            no_unstrip: false,
            debug_source: DebugSource::Auto,
            best_effort: false,
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
            solve_path: PathBuf::from("solve.py"),
            force: false,
            best_effort: false,
        }
    }
}

impl Opts {
    pub fn validate(&self) -> std::result::Result<(), String> {
        let validate_pwn = |opts: &PwnOpts| {
            validate_python_identifier(&opts.template_bin_name)?;
            validate_python_identifier(&opts.template_libc_name)?;
            validate_python_identifier(&opts.template_ld_name)?;
            if opts.template_bin_name == opts.template_libc_name
                || opts.template_bin_name == opts.template_ld_name
                || opts.template_libc_name == opts.template_ld_name
            {
                return Err("template binding names must be distinct".to_string());
            }
            if opts.no_patch_bin && opts.no_patchelf {
                return Err("--no-patch-bin cannot be combined with --no-patchelf".to_string());
            }
            Ok(())
        };

        if self.cmd.is_some() && self.pwn.has_explicit_values() {
            return Err(
                "pwn options placed before a subcommand cannot be combined with an explicit subcommand"
                    .to_string(),
            );
        }

        match &self.cmd {
            Some(Command::Pwn(opts)) => validate_pwn(opts)?,
            Some(Command::Rev(opts)) => validate_python_identifier(&opts.template_bin_name)?,
            Some(Command::FetchLibc(opts)) => {
                const DEFAULT_REPO: &str = "https://deb.debian.org/debian";
                match opts.source {
                    FetchLibcSource::Launchpad => {
                        if opts.version.is_none() {
                            return Err("fetch-libc launchpad source requires VERSION".to_string());
                        }
                        if opts.image.is_some() || opts.distro.is_some() || opts.release.is_some() {
                            return Err(
                                "launchpad source does not accept --image, --distro, or --release"
                                    .to_string(),
                            );
                        }
                        if opts.repo_url != DEFAULT_REPO {
                            return Err("launchpad source does not accept --repo-url".to_string());
                        }
                    }
                    FetchLibcSource::Docker => {
                        if opts.version.is_some() {
                            return Err("docker source does not accept VERSION".to_string());
                        }
                        if opts.exact_version.is_some() {
                            return Err("docker source does not accept --exact-version".to_string());
                        }
                        if opts.repo_url != DEFAULT_REPO {
                            return Err("docker source does not accept --repo-url".to_string());
                        }
                        let image = opts.image.is_some();
                        let pair = opts.distro.is_some() && opts.release.is_some();
                        if image == pair || (opts.distro.is_some() != opts.release.is_some()) {
                            return Err(
                                "docker source requires exactly one of --image or --distro with --release"
                                    .to_string(),
                            );
                        }
                    }
                    FetchLibcSource::Debian => {
                        if opts.version.is_none() {
                            return Err("debian source requires VERSION".to_string());
                        }
                        if opts.release.is_none() {
                            return Err("debian source requires --release".to_string());
                        }
                        if opts.image.is_some() || opts.distro.is_some() {
                            return Err(
                                "debian source does not accept --image or --distro".to_string()
                            );
                        }
                    }
                }
                if self.json
                    && opts.source != FetchLibcSource::Docker
                    && !opts.non_interactive
                    && opts.exact_version.is_none()
                {
                    return Err(
                        "--json requires --non-interactive for package version selection"
                            .to_string(),
                    );
                }
            }
            None => validate_pwn(&self.pwn)?,
        }
        Ok(())
    }

    /// Print the locations of known files (binary, libc, linker)
    pub fn print(&self) {
        let f = |opt_path: &Option<PathBuf>, header: &str, color| {
            if let Some(path) = opt_path {
                output::progress(format!(
                    "{}: {}",
                    header.color(color),
                    path.to_string_lossy().bold().color(color)
                ));
            }
        };

        match &self.cmd {
            Some(Command::Pwn(opts)) => {
                f(&opts.bin, "bin", Color::BrightBlue);
                f(&opts.libc, "libc", Color::Yellow);
                f(&opts.ld, "ld", Color::Green);
            }
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
            Some(Command::Pwn(opts)) => {
                let opts = resolve_pwn(opts)?;
                Ok(Opts {
                    pwn: self.pwn,
                    cmd: Some(Command::Pwn(opts)),
                    quiet: self.quiet,
                    verbose: self.verbose,
                    json: self.json,
                })
            }
            Some(Command::Rev(opts)) => {
                let opts = resolve_rev(opts)?;
                Ok(Opts {
                    pwn: self.pwn,
                    cmd: Some(Command::Rev(opts)),
                    quiet: self.quiet,
                    verbose: self.verbose,
                    json: self.json,
                })
            }
            Some(Command::FetchLibc(opts)) => Ok(Opts {
                pwn: self.pwn,
                cmd: Some(Command::FetchLibc(opts)),
                quiet: self.quiet,
                verbose: self.verbose,
                json: self.json,
            }),
            None => {
                let pwn = resolve_pwn(self.pwn)?;
                Ok(Opts {
                    pwn,
                    cmd: None,
                    quiet: self.quiet,
                    verbose: self.verbose,
                    json: self.json,
                })
            }
        }
    }
}

impl PwnOpts {
    fn has_explicit_values(&self) -> bool {
        self.bin.is_some()
            || self.libc.is_some()
            || self.ld.is_some()
            || self.template_path.is_some()
            || self.template_bin_name != "exe"
            || self.template_libc_name != "libc"
            || self.template_ld_name != "ld"
            || self.uv
            || self.patch_mode.is_some()
            || self.no_patch_bin
            || self.no_patchelf
            || self.no_template
            || self.solve_path != Path::new("solve.py")
            || self.force
            || self.no_unstrip
            || self.debug_source != DebugSource::Auto
            || self.best_effort
    }

    pub fn resolved_patch_mode(&self) -> Option<PatchMode> {
        if self.no_patch_bin {
            None
        } else if self.no_patchelf {
            Some(PatchMode::Manual)
        } else {
            match self.patch_mode.unwrap_or(PatchStrategy::Patchelf) {
                PatchStrategy::Patchelf => Some(PatchMode::Patchelf),
                PatchStrategy::Manual => Some(PatchMode::Manual),
                PatchStrategy::None => None,
            }
        }
    }

    /// Re-scan the current directory for a linker if one is not already specified.
    pub fn detect_ld(self) -> Result<Self> {
        if self.ld.is_some() {
            return Ok(self);
        }
        let detected = scan_current_dir()?;
        Ok(self.with_ld(select_candidate("linker", detected.ld)?))
    }
}

#[derive(Default)]
struct DetectedPaths {
    bin: Vec<PathBuf>,
    libc: Vec<PathBuf>,
    ld: Vec<PathBuf>,
}

fn scan_current_dir() -> Result<DetectedPaths> {
    fold_current_dir(DetectedPaths::default(), |mut found, dir_ent| {
        if let Some(path) = detect_path_if(&dir_ent, is_bin)? {
            found.bin.push(path);
        }
        if let Some(path) = detect_path_if(&dir_ent, is_libc)? {
            found.libc.push(path);
        }
        if let Some(path) = detect_path_if(&dir_ent, is_ld)? {
            found.ld.push(path);
        }
        Ok(found)
    })
}

fn select_candidate(kind: &'static str, mut candidates: Vec<PathBuf>) -> Result<Option<PathBuf>> {
    candidates.sort();
    candidates.dedup();
    match candidates.as_slice() {
        [] => Ok(None),
        [path] => Ok(Some(path.clone())),
        _ => Err(Error::Ambiguous {
            kind,
            candidates: candidates
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        }),
    }
}

fn resolve_pwn(mut opts: PwnOpts) -> Result<PwnOpts> {
    let detected = scan_current_dir()?;
    if opts.bin.is_none() {
        opts.bin = select_candidate("binary", detected.bin)?;
    }
    if opts.libc.is_none() {
        opts.libc = select_candidate("libc", detected.libc)?;
    }
    if opts.ld.is_none() {
        opts.ld = select_candidate("linker", detected.ld)?;
    }
    if opts.bin.is_none() {
        return Err(Error::MissingBinary);
    }
    Ok(opts)
}

fn resolve_rev(mut opts: RevOpts) -> Result<RevOpts> {
    if opts.bin.is_none() {
        opts.bin = select_candidate("binary", scan_current_dir()?.bin)?;
    }
    if opts.bin.is_none() {
        return Err(Error::MissingBinary);
    }
    Ok(opts)
}

fn validate_python_identifier(value: &str) -> std::result::Result<(), String> {
    const KEYWORDS: &[&str] = &[
        "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class",
        "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", "global",
        "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return",
        "try", "while", "with", "yield", "match", "case",
    ];
    let mut chars = value.chars();
    let valid_start = chars
        .next()
        .map(|ch| ch == '_' || ch.is_alphabetic())
        .unwrap_or(false);
    if !valid_start || !chars.all(|ch| ch == '_' || ch.is_alphanumeric()) {
        return Err(format!("invalid Python identifier: {value}"));
    }
    if KEYWORDS.contains(&value) {
        return Err(format!(
            "Python keyword cannot be used as an identifier: {value}"
        ));
    }
    Ok(())
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

    #[test]
    fn pwn_no_unstrip_flag_parses() {
        let opts =
            Opts::try_parse_from(["pwninit", "--no-unstrip"]).expect("--no-unstrip should parse");

        assert!(opts.pwn.no_unstrip);
    }

    #[test]
    fn pwn_unstrip_is_enabled_by_default() {
        let opts = Opts::try_parse_from(["pwninit"]).expect("default pwn flow should parse");

        assert!(!opts.pwn.no_unstrip);
    }

    #[test]
    fn pwn_debug_source_defaults_to_auto_and_accepts_explicit_sources() {
        let defaults = Opts::try_parse_from(["pwninit"]).expect("default pwn flow should parse");
        assert_eq!(defaults.pwn.debug_source, DebugSource::Auto);

        for (value, expected) in [
            ("launchpad", DebugSource::Launchpad),
            ("debian", DebugSource::Debian),
        ] {
            let opts = Opts::try_parse_from(["pwninit", "pwn", "--debug-source", value])
                .expect("explicit debug source should parse");
            let Some(Command::Pwn(pwn_opts)) = opts.cmd else {
                panic!("expected pwn command");
            };
            assert_eq!(pwn_opts.debug_source, expected);
        }
    }

    #[test]
    fn fetch_libc_does_not_accept_debug_source() {
        assert!(Opts::try_parse_from([
            "pwninit",
            "fetch-libc",
            "2.36",
            "--debug-source",
            "debian",
        ])
        .is_err());
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
            Some(Command::Pwn(_)) => panic!("expected fetch-libc command, got pwn"),
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
        assert_eq!(fetch_opts.libc_output, PathBuf::from("my/libc/path.so"));
    }

    #[test]
    fn fetch_libc_default_output_is_libc_so_6() {
        let fetch_opts = parse_fetch_libc(&["2.31"]);
        assert_eq!(fetch_opts.libc_output, PathBuf::from("libc.so.6"));
    }

    #[test]
    fn fetch_libc_positional_version_is_required() {
        let opts = Opts::try_parse_from(["pwninit", "fetch-libc"])
            .expect("conditional requirements are validated after parsing");
        assert!(opts.validate().is_err());
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
        assert_eq!(fetch_opts.libc_output, PathBuf::from("libc.so.6"));
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
    fn fetch_libc_debian_source_parses_release_and_repo_url() {
        let fetch_opts = parse_fetch_libc(&[
            "2.36",
            "--source",
            "debian",
            "--release",
            "bookworm",
            "--repo-url",
            "https://deb.debian.org/debian",
        ]);
        assert_eq!(fetch_opts.source, FetchLibcSource::Debian);
        assert_eq!(fetch_opts.version.as_deref(), Some("2.36"));
        assert_eq!(fetch_opts.release.as_deref(), Some("bookworm"));
        assert_eq!(fetch_opts.repo_url, "https://deb.debian.org/debian");
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

    #[test]
    fn explicit_pwn_subcommand_parses() {
        let opts = Opts::try_parse_from(["pwninit", "pwn", "--patch-mode", "manual"])
            .expect("explicit pwn command should parse");
        let Some(Command::Pwn(pwn)) = opts.cmd else {
            panic!("expected explicit pwn command");
        };
        assert_eq!(pwn.resolved_patch_mode(), Some(PatchMode::Manual));
    }

    #[test]
    fn legacy_and_explicit_command_options_cannot_mix() {
        let opts = Opts::try_parse_from(["pwninit", "--bin", "a", "pwn"])
            .expect("clap accepts legacy root options before normalization");
        assert!(opts.validate().is_err());
    }

    #[test]
    fn invalid_python_identifiers_are_rejected() {
        let opts = Opts::try_parse_from(["pwninit", "pwn", "--template-bin-name", "not-valid"])
            .expect("identifier validation occurs after parsing");
        assert!(opts.validate().is_err());

        let opts = Opts::try_parse_from(["pwninit", "rev", "--template-bin-name", "class"])
            .expect("keyword validation occurs after parsing");
        assert!(opts.validate().is_err());
    }

    #[test]
    fn fetch_backend_combinations_are_validated() {
        let docker = Opts::try_parse_from([
            "pwninit",
            "fetch-libc",
            "2.31",
            "--source",
            "docker",
            "--image",
            "ubuntu:22.04",
        ])
        .expect("conditional validation occurs after parsing");
        assert!(docker.validate().is_err());

        let debian = Opts::try_parse_from(["pwninit", "fetch-libc", "2.36", "--source", "debian"])
            .expect("conditional validation occurs after parsing");
        assert!(debian.validate().is_err());
    }

    #[test]
    fn ambiguous_candidates_are_sorted_in_error() {
        let err = select_candidate("binary", vec![PathBuf::from("b"), PathBuf::from("a")])
            .expect_err("multiple candidates should fail");
        assert!(err.to_string().contains("a, b"));
    }
}
