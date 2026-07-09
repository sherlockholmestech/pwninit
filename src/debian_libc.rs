//! Search Debian package repositories for libc6 packages.

use crate::cpu_arch::CpuArch;
use crate::http_retry::{self, RetryPolicy, Sleeper, StdSleeper};

use flate2::read::GzDecoder;
use snafu::ResultExt;
use snafu::Snafu;
use std::collections::BTreeMap;
use std::io::Read;

pub(crate) const DEBIAN_REPO_URL: &str = "https://deb.debian.org/debian";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DebianLibcPackage {
    pub version: String,
    pub deb_url: String,
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to query Debian package index: {}", source))]
    Request { source: http_retry::Error },

    #[snafu(display("failed decompressing Debian package index: {}", source))]
    Decompress { source: std::io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

#[allow(dead_code)]
pub(crate) fn search_versions(
    short_version: &str,
    arch: CpuArch,
    release: &str,
    repo_url: &str,
) -> Result<Vec<DebianLibcPackage>> {
    let mut sleeper = StdSleeper;
    search_versions_with(
        short_version,
        arch,
        release,
        repo_url,
        RetryPolicy::default(),
        &mut sleeper,
    )
}

pub(crate) fn search_versions_with(
    short_version: &str,
    arch: CpuArch,
    release: &str,
    repo_url: &str,
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
) -> Result<Vec<DebianLibcPackage>> {
    let repo_url = repo_url.trim_end_matches('/');
    let packages_url = format!(
        "{}/dists/{}/main/binary-{}/Packages.gz",
        repo_url, release, arch
    );
    let (bytes, _trace) = http_retry::get_bytes(&packages_url, policy, sleeper)
        .map_err(|source| Error::Request { source })?;

    let mut decoder = GzDecoder::new(bytes.as_slice());
    let mut packages = String::new();
    decoder
        .read_to_string(&mut packages)
        .context(DecompressSnafu)?;

    Ok(parse_versioned_package_index(
        &packages,
        "libc6",
        short_version,
        &format!("{}/", repo_url),
    ))
}

pub(crate) fn search_exact_package(
    package_name: &str,
    version: &str,
    arch: CpuArch,
    release: &str,
    repo_url: &str,
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
) -> Result<Option<DebianLibcPackage>> {
    let repo_url = repo_url.trim_end_matches('/');
    let packages_url = format!(
        "{}/dists/{}/main/binary-{}/Packages.gz",
        repo_url, release, arch
    );
    let (bytes, _trace) = http_retry::get_bytes(&packages_url, policy, sleeper)
        .map_err(|source| Error::Request { source })?;

    let mut decoder = GzDecoder::new(bytes.as_slice());
    let mut packages = String::new();
    decoder
        .read_to_string(&mut packages)
        .context(DecompressSnafu)?;

    Ok(parse_exact_package_index(
        &packages,
        package_name,
        version,
        &format!("{}/", repo_url),
    ))
}

fn parse_versioned_package_index(
    packages: &str,
    package_name: &str,
    short_version: &str,
    repo_url: &str,
) -> Vec<DebianLibcPackage> {
    let prefix = format!("{}-", short_version);
    let mut matches = BTreeMap::new();

    for stanza in packages.split("\n\n") {
        let mut package = None;
        let mut version = None;
        let mut filename = None;

        for line in stanza.lines() {
            if let Some(value) = line.strip_prefix("Package: ") {
                package = Some(value);
            } else if let Some(value) = line.strip_prefix("Version: ") {
                version = Some(value);
            } else if let Some(value) = line.strip_prefix("Filename: ") {
                filename = Some(value);
            }
        }

        let (Some(package), Some(version), Some(filename)) = (package, version, filename) else {
            continue;
        };
        if package != package_name {
            continue;
        }
        if !version.starts_with(&prefix) {
            continue;
        }

        matches.insert(
            version.to_string(),
            DebianLibcPackage {
                version: version.to_string(),
                deb_url: format!("{}{}", repo_url, filename),
            },
        );
    }

    let mut packages: Vec<_> = matches.into_values().collect();
    packages.sort_by(|a, b| {
        version_compare::compare(&a.version, &b.version)
            .map(|ord| match ord {
                version_compare::Cmp::Lt => std::cmp::Ordering::Less,
                version_compare::Cmp::Gt => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            })
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    packages
}

fn parse_exact_package_index(
    packages: &str,
    package_name: &str,
    expected_version: &str,
    repo_url: &str,
) -> Option<DebianLibcPackage> {
    parse_versioned_package_index(
        packages,
        package_name,
        expected_version
            .split('-')
            .next()
            .unwrap_or(expected_version),
        repo_url,
    )
    .into_iter()
    .find(|package| package.version == expected_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packages_index_parser_finds_libc6_versions() {
        let packages = "\
Package: libc6
Version: 2.36-9+deb12u10
Filename: pool/main/g/glibc/libc6_2.36-9+deb12u10_amd64.deb

Package: libc6
Version: 2.36-9+deb12u13
Filename: pool/main/g/glibc/libc6_2.36-9+deb12u13_amd64.deb

Package: libc6-dev
Version: 2.36-9+deb12u13
Filename: pool/main/g/glibc/libc6-dev_2.36-9+deb12u13_amd64.deb

Package: libc6
Version: 2.37-1
Filename: pool/main/g/glibc/libc6_2.37-1_amd64.deb
";

        let matches = parse_versioned_package_index(
            packages,
            "libc6",
            "2.36",
            "https://deb.debian.org/debian/",
        );

        assert_eq!(
            matches,
            vec![
                DebianLibcPackage {
                    version: "2.36-9+deb12u10".to_string(),
                    deb_url:
                        "https://deb.debian.org/debian/pool/main/g/glibc/libc6_2.36-9+deb12u10_amd64.deb"
                            .to_string(),
                },
                DebianLibcPackage {
                    version: "2.36-9+deb12u13".to_string(),
                    deb_url:
                        "https://deb.debian.org/debian/pool/main/g/glibc/libc6_2.36-9+deb12u13_amd64.deb"
                            .to_string(),
                },
            ]
        );
    }

    #[test]
    fn exact_package_parser_finds_libc6_dbg() {
        let packages = "\
Package: libc6-dbg
Version: 2.36-9+deb12u13
Filename: pool/main/g/glibc/libc6-dbg_2.36-9+deb12u13_amd64.deb

Package: libc6-dbg
Version: 2.37-1
Filename: pool/main/g/glibc/libc6-dbg_2.37-1_amd64.deb
";

        let package = parse_exact_package_index(
            packages,
            "libc6-dbg",
            "2.36-9+deb12u13",
            "https://deb.debian.org/debian/",
        )
        .expect("matching package");

        assert_eq!(
            package.deb_url,
            "https://deb.debian.org/debian/pool/main/g/glibc/libc6-dbg_2.36-9+deb12u13_amd64.deb"
        );
    }
}
