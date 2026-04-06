//! Search Ubuntu Launchpad for available libc6 package versions

use crate::cpu_arch::CpuArch;

use colored::Colorize;
use serde::Deserialize;
use snafu::ResultExt;
use snafu::Snafu;

const LAUNCHPAD_API: &str = "https://api.launchpad.net/1.0/ubuntu/+archive/primary\
     ?ws.op=getPublishedBinaries\
     &binary_name=libc6\
     &exact_match=true\
     &status=Published\
     &ws.size=300";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to query Launchpad API: {}", source))]
    Request { source: reqwest::Error },

    #[snafu(display("failed to parse Launchpad API response: {}", source))]
    Parse { source: reqwest::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Deserialize)]
struct Page {
    entries: Vec<Entry>,
    next_collection_link: Option<String>,
}

#[derive(Deserialize)]
struct Entry {
    binary_package_version: String,
    distro_arch_series_link: String,
}

/// Return all published libc6 versions whose version string starts with
/// `short_version` followed by `-`, matching the given architecture.
/// Results are deduplicated and sorted in ascending order.
pub fn search_versions(short_version: &str, arch: &CpuArch) -> Result<Vec<String>> {
    println!(
        "{}",
        format!(
            "searching Launchpad for libc6 {}* ({})",
            short_version, arch
        )
        .cyan()
        .bold()
    );

    let arch_str = arch.to_string();
    let prefix = format!("{}-", short_version);
    let mut versions: Vec<String> = Vec::new();
    let mut url: Option<String> = Some(LAUNCHPAD_API.to_string());

    while let Some(next_url) = url {
        let page: Page = reqwest::blocking::get(&next_url)
            .context(RequestSnafu)?
            .json()
            .context(ParseSnafu)?;

        for entry in page.entries {
            // Filter by architecture: the distro_arch_series_link ends with the arch name
            if !entry
                .distro_arch_series_link
                .ends_with(&format!("/{}", arch_str))
            {
                continue;
            }
            // Filter by version prefix
            if entry.binary_package_version.starts_with(&prefix) {
                let v = entry.binary_package_version;
                if !versions.contains(&v) {
                    versions.push(v);
                }
            }
        }

        url = page.next_collection_link;
    }

    versions.sort_by(|a, b| {
        version_compare::compare(a, b)
            .map(|ord| match ord {
                version_compare::Cmp::Lt => std::cmp::Ordering::Less,
                version_compare::Cmp::Gt => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            })
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(versions)
}
