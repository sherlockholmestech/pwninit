//! Search Ubuntu Launchpad for available libc6 package versions

use crate::cpu_arch::CpuArch;

use colored::Colorize;
use serde::Deserialize;
use snafu::ResultExt;
use snafu::Snafu;

const LAUNCHPAD_API_BASE: &str = "https://api.launchpad.net/1.0/ubuntu/+archive/primary";
const LAUNCHPAD_PAGE_SIZE: &str = "300";

fn launchpad_api_url() -> String {
    let mut url = reqwest::Url::parse(LAUNCHPAD_API_BASE).expect("Launchpad API URL is valid");
    url.query_pairs_mut()
        .append_pair("ws.op", "getPublishedBinaries")
        .append_pair("binary_name", "libc6")
        .append_pair("exact_match", "true")
        .append_pair("status", "Published")
        .append_pair("ws.size", LAUNCHPAD_PAGE_SIZE);
    url.to_string()
}

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
    let mut versions: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut url: Option<String> = Some(launchpad_api_url());

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
                versions.insert(entry.binary_package_version);
            }
        }

        url = page.next_collection_link;
    }

    let mut versions: Vec<String> = versions.into_iter().collect();
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
