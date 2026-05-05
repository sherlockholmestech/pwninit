use crate::cpu_arch::CpuArch;
use crate::fetch_ld;
use crate::libc_deb;
use crate::libc_search;
use crate::libc_version::LibcVersion;

use std::collections::HashSet;
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

    #[snafu(display("invalid extra libc library name: {}", name))]
    InvalidExtraLibName { name: String },
}

pub type Result<T = ()> = std::result::Result<T, Error>;

const LIBC_SONAME: &str = "libc.so.6";
const LIBM_SONAME: &str = "libm.so.6";
const LIBPTHREAD_SONAME: &str = "libpthread.so.0";

pub fn fetch_libc(ver: &LibcVersion, out_path: &Path) -> Result {
    println!("{}", "fetching libc".yellow().bold());

    fetch_libc_package_file(ver, LIBC_SONAME, out_path)
}

fn fetch_libc_package_file(ver: &LibcVersion, soname: &str, out_path: &Path) -> Result {
    let deb_file_name = format!("libc6_{}.deb", ver);
    let versioned_name = versioned_lib_name(soname, ver);
    let file_names = package_file_candidates(ver, soname, &versioned_name);
    libc_deb::write_ubuntu_pkg_file(&deb_file_name, &file_names, out_path).context(DebSnafu)
}

fn package_file_candidates<'a>(
    ver: &LibcVersion,
    soname: &'a str,
    versioned_name: &'a str,
) -> [&'a str; 2] {
    // Older glibc ships versioned filenames (e.g. libc-2.31.so);
    // newer glibc (>=2.34) ships canonical sonames.
    if ver.is_pre_234() {
        [versioned_name, soname]
    } else {
        [soname, versioned_name]
    }
}

fn versioned_lib_name(soname: &str, ver: &LibcVersion) -> String {
    let base = soname
        .find(".so")
        .map(|idx| &soname[..idx])
        .unwrap_or(soname);
    format!("{}-{}.so", base, ver.string_short)
}

fn normalize_extra_lib_name(lib_name: &str) -> &str {
    match lib_name {
        "libm" => LIBM_SONAME,
        "libpthread" => LIBPTHREAD_SONAME,
        _ => lib_name,
    }
}

fn validate_extra_lib_name(lib_name: &str) -> Result {
    if lib_name.is_empty() || lib_name.contains('/') || lib_name.contains('\0') {
        return Err(Error::InvalidExtraLibName {
            name: lib_name.to_string(),
        });
    }
    Ok(())
}

/// Download a library from the same libc6 package as `ver`.
pub fn fetch_libc_lib(ver: &LibcVersion, lib_name: &str) -> Result {
    validate_extra_lib_name(lib_name)?;
    let soname = normalize_extra_lib_name(lib_name);

    println!("{}", format!("fetching {}", soname).yellow().bold());
    fetch_libc_package_file(ver, soname, Path::new(soname))
}

/// Download libm.so.6 matching the given libc version.
pub fn fetch_libm(ver: &LibcVersion) -> Result {
    fetch_libc_lib(ver, LIBM_SONAME)
}

/// Download libpthread.so.0 matching the given libc version.
pub fn fetch_libpthread(ver: &LibcVersion) -> Result {
    fetch_libc_lib(ver, LIBPTHREAD_SONAME)
}

/// Search for available libc6 versions matching `short_version`, prompt the
/// user to select one, then download it to `out_path`.
pub fn fetch_libc_interactive(
    short_version: &str,
    arch: CpuArch,
    out_path: &Path,
    extra_libs: &[String],
) -> Result {
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
    let extra_libs = normalize_extra_libs(extra_libs)?;

    fetch_libc(&ver, out_path)?;
    fetch_ld::fetch_ld_canonical(&ver).context(FetchLdSnafu)?;
    fetch_extra_libs(&ver, &extra_libs)?;
    Ok(())
}

fn normalize_extra_libs(extra_libs: &[String]) -> std::result::Result<Vec<&str>, Error> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for extra_lib in extra_libs {
        validate_extra_lib_name(extra_lib)?;
        let soname = normalize_extra_lib_name(extra_lib);
        if seen.insert(soname) {
            normalized.push(soname);
        }
    }

    Ok(normalized)
}

fn fetch_extra_libs(ver: &LibcVersion, extra_libs: &[&str]) -> Result {
    for extra_lib in extra_libs {
        fetch_libc_lib(ver, extra_lib)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(short: &str) -> LibcVersion {
        LibcVersion {
            string: format!("{}-0ubuntu1", short),
            string_short: short.to_string(),
            arch: CpuArch::Amd64,
        }
    }

    #[test]
    fn versioned_lib_name_rewrites_sonames_to_versioned_package_names() {
        let ver = version("2.31");
        assert_eq!(versioned_lib_name("libm.so.6", &ver), "libm-2.31.so");
        assert_eq!(versioned_lib_name("libm", &ver), "libm-2.31.so");
        assert_eq!(
            versioned_lib_name("libnss_dns.so.2", &ver),
            "libnss_dns-2.31.so"
        );
    }

    #[test]
    fn package_candidates_prefer_versioned_names_for_old_glibc() {
        let ver = version("2.31");
        assert_eq!(
            package_file_candidates(&ver, "libm.so.6", "libm-2.31.so"),
            ["libm-2.31.so", "libm.so.6"]
        );
    }

    #[test]
    fn package_candidates_prefer_sonames_for_new_glibc() {
        let ver = version("2.34");
        assert_eq!(
            package_file_candidates(&ver, "libm.so.6", "libm-2.34.so"),
            ["libm.so.6", "libm-2.34.so"]
        );
    }

    #[test]
    fn extra_lib_aliases_normalize_to_sonames() {
        assert_eq!(normalize_extra_lib_name("libm"), "libm.so.6");
        assert_eq!(normalize_extra_lib_name("libpthread"), "libpthread.so.0");
        assert_eq!(normalize_extra_lib_name("libdl.so.2"), "libdl.so.2");
    }

    #[test]
    fn extra_lib_list_normalizes_and_deduplicates_aliases() {
        let extra_libs = vec![
            "libm".to_string(),
            "libm.so.6".to_string(),
            "libdl.so.2".to_string(),
        ];

        assert_eq!(
            normalize_extra_libs(&extra_libs).expect("valid extra libs"),
            ["libm.so.6", "libdl.so.2"]
        );
    }

    #[test]
    fn extra_lib_name_validation_rejects_paths() {
        assert!(validate_extra_lib_name("libdl.so.2").is_ok());
        assert!(validate_extra_lib_name("../libdl.so.2").is_err());
        assert!(validate_extra_lib_name("nested/libdl.so.2").is_err());
        assert!(validate_extra_lib_name("").is_err());
    }
}
