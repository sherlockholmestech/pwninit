use crate::cpu_arch::CpuArch;
use crate::fetch_ld;
use crate::libc_deb;
use crate::libc_search;
use crate::libc_version::LibcVersion;

use std::io::{self, BufRead, Write};
use std::path::Path;

use colored::Colorize;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("libc deb error: {}", source))]
    Deb { source: libc_deb::Error },

    #[snafu(display("libc search error: {}", source))]
    Search { source: libc_search::Error },

    #[snafu(display("libc version error: {}", source))]
    Version { source: crate::libc_version::Error },

    #[snafu(display("no libc6 packages found for the given version and architecture"))]
    NoVersionsFound,

    #[snafu(display("failed to read user input: {}", source))]
    Stdin { source: io::Error },

    #[snafu(display("failed fetching linker: {}", source))]
    FetchLd { source: fetch_ld::Error },
}

pub type Result = std::result::Result<(), Error>;

pub fn fetch_libc(ver: &LibcVersion, out_path: &Path) -> Result {
    println!("{}", "fetching libc".yellow().bold());

    let deb_file_name = format!("libc6_{}.deb", ver);

    // Older glibc ships the versioned filename (e.g. libc-2.31.so);
    // newer glibc (>=2.34) ships only libc.so.6 inside the package.
    let versioned_name = format!("libc-{}.so", ver.string_short);
    let standard_name = "libc.so.6";

    let file_names: &[&str] = if ver.is_pre_234() {
        &[versioned_name.as_str(), standard_name]
    } else {
        &[standard_name, versioned_name.as_str()]
    };

    libc_deb::write_ubuntu_pkg_file(&deb_file_name, file_names, out_path).context(DebSnafu)?;
    Ok(())
}

/// Search for available libc6 versions matching `short_version`, prompt the
/// user to select one, then download it to `out_path`.
pub fn fetch_libc_interactive(short_version: &str, arch: CpuArch, out_path: &Path) -> Result {
    let versions = libc_search::search_versions(short_version, &arch).context(SearchSnafu)?;

    if versions.is_empty() {
        return Err(Error::NoVersionsFound);
    }

    let choice = if versions.len() == 1 {
        println!("  {}", versions[0].bold());
        0
    } else {
        println!();
        for (i, v) in versions.iter().enumerate() {
            println!("  {}  {}", format!("[{}]", i + 1).bold(), v);
        }
        println!();

        loop {
            print!("{}", "select version: ".bold());
            io::stdout().flush().context(StdinSnafu)?;

            let mut line = String::new();
            io::stdin()
                .lock()
                .read_line(&mut line)
                .context(StdinSnafu)?;

            let trimmed = line.trim();
            if let Ok(n) = trimmed.parse::<usize>() {
                if n >= 1 && n <= versions.len() {
                    break n - 1;
                }
            }
            eprintln!(
                "{}",
                format!("please enter a number between 1 and {}", versions.len()).red()
            );
        }
    };

    let full_version = versions[choice].clone();
    let ver = LibcVersion::from_parts(full_version, arch).context(VersionSnafu)?;
    fetch_libc(&ver, out_path)?;
    fetch_ld::fetch_ld_canonical(&ver).context(FetchLdSnafu)?;
    Ok(())
}
