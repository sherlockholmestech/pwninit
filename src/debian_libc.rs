//! Search Debian package repositories for libc6 packages.

use crate::cpu_arch::CpuArch;
use crate::http_retry::{self, RetryPolicy, Sleeper, StdSleeper};

use flate2::read::GzDecoder;
use snafu::ResultExt;
use snafu::Snafu;
use std::collections::BTreeMap;
use std::io::Read;

pub(crate) const DEBIAN_REPO_URL: &str = "https://deb.debian.org/debian";
const GLIBC_POOL_PATH: &str = "pool/main/g/glibc";

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
    let mut packages = search_package_index(
        "libc6",
        short_version,
        arch,
        release,
        repo_url,
        policy,
        sleeper,
    )?;
    match search_pool_index("libc6", short_version, arch, repo_url, policy, sleeper) {
        Ok(pool_packages) => packages.extend(pool_packages),
        Err(err) if packages.is_empty() => return Err(err),
        Err(_) => {}
    }

    Ok(dedupe_and_sort(packages))
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
    let package_index_result = search_exact_package_index(
        package_name,
        version,
        arch,
        release,
        repo_url,
        policy,
        sleeper,
    );
    if let Some(package) = package_index_result
        .as_ref()
        .ok()
        .and_then(|package| package.clone())
    {
        return Ok(Some(package));
    }

    let pool_result = search_pool_index(
        package_name,
        version.split('-').next().unwrap_or(version),
        arch,
        repo_url,
        policy,
        sleeper,
    )
    .map(|packages| {
        packages
            .into_iter()
            .find(|package| package.version == version)
    });

    match (package_index_result, pool_result) {
        (_, Ok(package)) => Ok(package),
        (Ok(package), Err(_)) => Ok(package),
        (Err(err), Err(_)) => Err(err),
    }
}

fn search_package_index(
    package_name: &str,
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
        package_name,
        short_version,
        &format!("{}/", repo_url),
    ))
}

fn search_exact_package_index(
    package_name: &str,
    version: &str,
    arch: CpuArch,
    release: &str,
    repo_url: &str,
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
) -> Result<Option<DebianLibcPackage>> {
    Ok(search_package_index(
        package_name,
        version.split('-').next().unwrap_or(version),
        arch,
        release,
        repo_url,
        policy,
        sleeper,
    )?
    .into_iter()
    .find(|package| package.version == version))
}

fn parse_versioned_package_index(
    packages: &str,
    package_name: &str,
    short_version: &str,
    repo_url: &str,
) -> Vec<DebianLibcPackage> {
    let mut matches = Vec::new();
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
        if !version_matches(version, short_version) {
            continue;
        }

        matches.push(DebianLibcPackage {
            version: version.to_string(),
            deb_url: format!("{}{}", repo_url, filename),
        });
    }

    dedupe_and_sort(matches)
}

fn search_pool_index(
    package_name: &str,
    short_version: &str,
    arch: CpuArch,
    repo_url: &str,
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
) -> Result<Vec<DebianLibcPackage>> {
    let repo_url = repo_url.trim_end_matches('/');
    let pool_url = format!("{}/{}/", repo_url, GLIBC_POOL_PATH);
    let (bytes, _trace) = http_retry::get_bytes(&pool_url, policy, sleeper)
        .map_err(|source| Error::Request { source })?;
    let index = String::from_utf8_lossy(&bytes);

    Ok(parse_pool_index(
        &index,
        package_name,
        short_version,
        &arch,
        &pool_url,
    ))
}

fn parse_pool_index(
    index: &str,
    package_name: &str,
    short_version: &str,
    arch: &CpuArch,
    pool_url: &str,
) -> Vec<DebianLibcPackage> {
    let mut matches = Vec::new();
    let prefix = format!("{}_", package_name);
    let suffix = format!("_{}.deb", arch);

    for candidate in pool_index_candidates(index) {
        let decoded_href = percent_decode(candidate);
        let file_name = decoded_href.rsplit('/').next().unwrap_or(&decoded_href);
        let Some(version) = file_name
            .strip_prefix(&prefix)
            .and_then(|name| name.strip_suffix(&suffix))
        else {
            continue;
        };
        if !version_matches(version, short_version) {
            continue;
        }

        matches.push(DebianLibcPackage {
            version: version.to_string(),
            deb_url: if candidate.starts_with("http://") || candidate.starts_with("https://") {
                decoded_href
            } else {
                format!("{}{}", pool_url, decoded_href)
            },
        });
    }

    dedupe_and_sort(matches)
}

fn pool_index_candidates(index: &str) -> Vec<&str> {
    let hrefs = index
        .split("href=\"")
        .skip(1)
        .filter_map(|part| Some(&part[..part.find('"')?]));

    let visible_names = index
        .split_whitespace()
        .filter(|part| part.ends_with(".deb"));

    hrefs.chain(visible_names).collect()
}

fn version_matches(version: &str, short_version: &str) -> bool {
    version == short_version || version.starts_with(&format!("{}-", short_version))
}

fn dedupe_and_sort(packages: Vec<DebianLibcPackage>) -> Vec<DebianLibcPackage> {
    let mut matches = BTreeMap::new();
    for package in packages {
        matches.insert(package.version.clone(), package);
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

fn percent_decode(input: &str) -> String {
    let mut output = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    output.push(value);
                    i += 3;
                    continue;
                }
            }
        }
        output.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&output).into_owned()
}

#[allow(dead_code)]
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
Version: 2.36-9+deb12u14
Filename: pool/main/g/glibc/libc6_2.36-9+deb12u14_amd64.deb

Package: libc6-dev
Version: 2.36-9+deb12u14
Filename: pool/main/g/glibc/libc6-dev_2.36-9+deb12u14_amd64.deb

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
                    version: "2.36-9+deb12u14".to_string(),
                    deb_url:
                        "https://deb.debian.org/debian/pool/main/g/glibc/libc6_2.36-9+deb12u14_amd64.deb"
                            .to_string(),
                },
            ]
        );
    }

    #[test]
    fn pool_index_parser_finds_debian_file_names() {
        let index = r#"
<a href="libc6_2.36-9%2Bdeb12u14_amd64.deb">libc6_2.36-9+deb12u14_amd64.deb</a>
[ ] libc6_2.41-12+deb13u3_amd64.deb 2026-05-03
[ ] libc6-dbg_2.36-9+deb12u14_amd64.deb 2026-05-03
"#;

        let matches = parse_pool_index(
            index,
            "libc6",
            "2.36",
            &CpuArch::Amd64,
            "https://deb.debian.org/debian/pool/main/g/glibc/",
        );

        assert_eq!(
            matches,
            vec![DebianLibcPackage {
                version: "2.36-9+deb12u14".to_string(),
                deb_url:
                    "https://deb.debian.org/debian/pool/main/g/glibc/libc6_2.36-9+deb12u14_amd64.deb"
                        .to_string(),
            }]
        );
    }

    #[test]
    fn exact_package_parser_finds_libc6_dbg() {
        let packages = "\
Package: libc6-dbg
Version: 2.36-9+deb12u14
Filename: pool/main/g/glibc/libc6-dbg_2.36-9+deb12u14_amd64.deb

Package: libc6-dbg
Version: 2.37-1
Filename: pool/main/g/glibc/libc6-dbg_2.37-1_amd64.deb
";

        let package = parse_exact_package_index(
            packages,
            "libc6-dbg",
            "2.36-9+deb12u14",
            "https://deb.debian.org/debian/",
        )
        .expect("matching package");

        assert_eq!(
            package.deb_url,
            "https://deb.debian.org/debian/pool/main/g/glibc/libc6-dbg_2.36-9+deb12u14_amd64.deb"
        );
    }
}
