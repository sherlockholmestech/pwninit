//! Search Ubuntu Launchpad for available libc6 package versions

use crate::cpu_arch::CpuArch;
use crate::http_retry::{self, RetryPolicy, Sleeper, StdSleeper};
use crate::output;

use colored::Colorize;
use serde::Deserialize;
use snafu::Snafu;

pub(crate) const LAUNCHPAD_API_BASE: &str = "https://api.launchpad.net/1.0/ubuntu/+archive/primary";
const LAUNCHPAD_PAGE_SIZE: &str = "300";

fn launchpad_api_url_with_base(base: &str) -> String {
    let mut url = reqwest::Url::parse(base).expect("Launchpad API URL is valid");
    url.query_pairs_mut()
        .append_pair("ws.op", "getPublishedBinaries")
        .append_pair("binary_name", "libc6")
        .append_pair("exact_match", "true")
        .append_pair("status", "Published")
        .append_pair("ws.size", LAUNCHPAD_PAGE_SIZE);
    url.to_string()
}

#[allow(dead_code)]
fn launchpad_api_url() -> String {
    launchpad_api_url_with_base(LAUNCHPAD_API_BASE)
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to query Launchpad API: {}", source))]
    Request { source: http_retry::Error },

    #[snafu(display("failed to parse Launchpad API response: {}", message))]
    Parse { message: String },
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
#[allow(dead_code)]
pub fn search_versions(short_version: &str, arch: &CpuArch) -> Result<Vec<String>> {
    let policy = RetryPolicy::default();
    let mut sleeper = StdSleeper;
    search_versions_with(
        short_version,
        arch,
        LAUNCHPAD_API_BASE,
        policy,
        &mut sleeper,
    )
}

/// Same as [`search_versions`] but lets callers inject the API base URL,
/// retry policy, and sleeper. Used by tests to drive a local fake server
/// with deterministic responses.
pub(crate) fn search_versions_with(
    short_version: &str,
    arch: &CpuArch,
    api_base: &str,
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
) -> Result<Vec<String>> {
    output::progress(
        format!(
            "searching Launchpad for libc6 {}* ({})",
            short_version, arch
        )
        .cyan()
        .bold(),
    );

    let arch_str = arch.to_string();
    let prefix = format!("{}-", short_version);
    let mut versions: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut url: Option<String> = Some(launchpad_api_url_with_base(api_base));

    while let Some(next_url) = url {
        let (page, _trace): (Page, _) =
            http_retry::get_json(&next_url, policy, sleeper).map_err(map_retry_error)?;

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

fn map_retry_error(err: http_retry::Error) -> Error {
    match err {
        http_retry::Error::Parse { message } => Error::Parse { message },
        other => Error::Request { source: other },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    /// [`Sleeper`] that records scheduled delays without blocking.
    #[derive(Default)]
    struct RecordingSleeper {
        sleeps: Vec<Duration>,
    }

    impl Sleeper for RecordingSleeper {
        fn sleep(&mut self, dur: Duration) {
            self.sleeps.push(dur);
        }
    }

    /// One scripted response the fake server returns for the next request.
    enum FakeResponse {
        /// Return a fixed status line and body.
        Status { status: u16, body: String },
        /// Return `200 OK` with a `Content-Length` larger than the body that
        /// is actually written, then close the connection. The client sees a
        /// truncated body and classifies it as a body-read failure.
        TruncatedBody {
            content_length: usize,
            body: Vec<u8>,
        },
    }

    /// Tiny single-threaded HTTP/1.0 server used to drive `search_versions`
    /// in tests. Serves a scripted queue of [`FakeResponse`] values, one
    /// per request, then falls back to `500 Internal Server Error` for any
    /// extra request that the test did not expect.
    struct FakeLaunchpadServer {
        base_url: String,
        responses: Arc<Mutex<VecDeque<FakeResponse>>>,
        shutdown: Arc<AtomicBool>,
        join_handle: Option<JoinHandle<()>>,
    }

    impl FakeLaunchpadServer {
        fn new() -> Self {
            Self::with_responses(Vec::new())
        }

        fn with_responses(responses: Vec<FakeResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake server");
            let port = listener.local_addr().expect("local_addr").port();
            let base_url = format!("http://127.0.0.1:{}", port);
            listener.set_nonblocking(true).expect("set nonblocking");

            let queue = Arc::new(Mutex::new(VecDeque::from(responses)));
            let queue_clone = queue.clone();
            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_clone = shutdown.clone();

            let join_handle = thread::spawn(move || loop {
                if shutdown_clone.load(Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => handle_connection(&mut stream, &queue_clone),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            });

            Self {
                base_url,
                responses: queue,
                shutdown,
                join_handle: Some(join_handle),
            }
        }

        /// Append a scripted response to the back of the queue. Useful when
        /// the test needs the server's base URL before it can construct
        /// page bodies that reference the server.
        fn push(&self, response: FakeResponse) {
            self.responses
                .lock()
                .expect("lock poisoned")
                .push_back(response);
        }

        /// Number of scripted responses that have not yet been consumed.
        #[allow(dead_code)]
        fn remaining(&self) -> usize {
            self.responses.lock().expect("lock poisoned").len()
        }
    }

    impl Drop for FakeLaunchpadServer {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::SeqCst);
            if let Some(handle) = self.join_handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn handle_connection(stream: &mut TcpStream, queue: &Arc<Mutex<VecDeque<FakeResponse>>>) {
        // Drain the request. The exact bytes do not matter for our tests
        // because reqwest sends a well-formed HTTP/1.1 GET line.
        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }

        let response = queue.lock().expect("lock poisoned").pop_front();
        match response {
            Some(FakeResponse::Status { status, body }) => {
                let reason = match status {
                    200 => "OK",
                    400 => "Bad Request",
                    401 => "Unauthorized",
                    403 => "Forbidden",
                    404 => "Not Found",
                    408 => "Request Timeout",
                    422 => "Unprocessable Entity",
                    429 => "Too Many Requests",
                    500 => "Internal Server Error",
                    502 => "Bad Gateway",
                    503 => "Service Unavailable",
                    504 => "Gateway Timeout",
                    _ => "Status",
                };
                let raw = format!(
                    "HTTP/1.0 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    reason,
                    body.len(),
                    body
                );
                let _ = stream.write_all(raw.as_bytes());
            }
            Some(FakeResponse::TruncatedBody {
                content_length,
                body,
            }) => {
                let headers = format!(
                    "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    content_length
                );
                let _ = stream.write_all(headers.as_bytes());
                let _ = stream.write_all(&body);
            }
            None => {
                let _ = stream.write_all(
                    b"HTTP/1.0 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        }
        let _ = stream.flush();
    }

    fn fast_policy() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
        }
    }

    fn entry(version: &str, arch: &str) -> serde_json::Value {
        serde_json::json!({
            "binary_package_version": version,
            "distro_arch_series_link": format!(
                "https://api.launchpad.net/1.0/ubuntu/+archive/primary/{}",
                arch
            ),
        })
    }

    fn page(entries: Vec<serde_json::Value>, next: Option<&str>) -> String {
        serde_json::json!({
            "entries": entries,
            "next_collection_link": next,
        })
        .to_string()
    }

    fn status(status: u16, body: &str) -> FakeResponse {
        FakeResponse::Status {
            status,
            body: body.to_string(),
        }
    }

    #[test]
    fn single_page_returns_sorted_unique_versions() {
        let body = page(
            vec![
                entry("2.35-0ubuntu3", "amd64"),
                entry("2.31-0ubuntu9.16", "amd64"),
                entry("2.31-0ubuntu9", "amd64"),
                entry("2.31-0ubuntu9", "amd64"), // duplicate
            ],
            None,
        );
        let server = FakeLaunchpadServer::with_responses(vec![status(200, &body)]);

        let mut sleeper = RecordingSleeper::default();
        let versions = search_versions_with(
            "2.31",
            &CpuArch::Amd64,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("lookup should succeed");

        // Only amd64 versions starting with `2.31-`, deduplicated, sorted ascending.
        assert_eq!(
            versions,
            vec!["2.31-0ubuntu9".to_string(), "2.31-0ubuntu9.16".to_string()]
        );
        assert!(sleeper.sleeps.is_empty(), "no retries expected");
    }

    #[test]
    fn paginated_lookup_collects_all_pages_and_deduplicates() {
        // Start the server first so we can reference its base URL in the
        // page 1 `next_collection_link`. The fake server ignores the path
        // and just consumes the queue in order.
        let server = FakeLaunchpadServer::new();
        let next_link = format!("{}/page2", server.base_url);

        let page1_body = page(
            vec![
                entry("2.31-0ubuntu9", "amd64"),
                entry("2.35-0ubuntu3", "amd64"),
            ],
            Some(&next_link),
        );
        let page2_body = page(
            vec![
                entry("2.31-0ubuntu9", "amd64"), // duplicate from page 1
                entry("2.31-0ubuntu9.16", "amd64"),
            ],
            None,
        );

        server.push(status(200, &page1_body));
        server.push(status(200, &page2_body));

        let mut sleeper = RecordingSleeper::default();
        let versions = search_versions_with(
            "2.31",
            &CpuArch::Amd64,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("paginated lookup should succeed");

        assert_eq!(
            versions,
            vec!["2.31-0ubuntu9".to_string(), "2.31-0ubuntu9.16".to_string()]
        );
        assert!(sleeper.sleeps.is_empty(), "no retries expected");
    }

    #[test]
    fn architecture_filter_excludes_other_arch_entries() {
        let body = page(
            vec![
                entry("2.31-0ubuntu9", "amd64"),
                entry("2.31-0ubuntu9", "i386"),
                entry("2.31-0ubuntu9.16", "i386"),
            ],
            None,
        );
        let server = FakeLaunchpadServer::with_responses(vec![status(200, &body)]);

        let mut sleeper = RecordingSleeper::default();
        let versions = search_versions_with(
            "2.31",
            &CpuArch::Amd64,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("lookup should succeed");

        assert_eq!(versions, vec!["2.31-0ubuntu9".to_string()]);
    }

    #[test]
    fn version_prefix_filter_excludes_non_matching_entries() {
        let body = page(
            vec![
                entry("2.31-0ubuntu9", "amd64"),
                entry("2.35-0ubuntu3", "amd64"),
                entry("2.31-0ubuntu9.16", "amd64"),
            ],
            None,
        );
        let server = FakeLaunchpadServer::with_responses(vec![status(200, &body)]);

        let mut sleeper = RecordingSleeper::default();
        let versions = search_versions_with(
            "2.31",
            &CpuArch::Amd64,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("lookup should succeed");

        // Only `2.31-*` entries (with the `-` separator enforced).
        assert_eq!(
            versions,
            vec!["2.31-0ubuntu9".to_string(), "2.31-0ubuntu9.16".to_string()]
        );
    }

    #[test]
    fn version_prefix_filter_requires_dash_separator() {
        let body = page(
            vec![
                // Starts with the short version but without a `-` separator:
                // must be filtered out so that a search for `2.31` does not
                // also pull in `2.31somethingweird`.
                entry("2.31rolling", "amd64"),
                entry("2.31-0ubuntu9", "amd64"),
            ],
            None,
        );
        let server = FakeLaunchpadServer::with_responses(vec![status(200, &body)]);

        let mut sleeper = RecordingSleeper::default();
        let versions = search_versions_with(
            "2.31",
            &CpuArch::Amd64,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("lookup should succeed");

        assert_eq!(versions, vec!["2.31-0ubuntu9".to_string()]);
    }

    #[test]
    fn retries_after_5xx_then_succeeds() {
        let body = page(vec![entry("2.31-0ubuntu9", "amd64")], None);
        let server = FakeLaunchpadServer::with_responses(vec![status(503, ""), status(200, &body)]);

        let mut sleeper = RecordingSleeper::default();
        let versions = search_versions_with(
            "2.31",
            &CpuArch::Amd64,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("lookup should succeed after retry");

        assert_eq!(versions, vec!["2.31-0ubuntu9".to_string()]);
        assert_eq!(
            sleeper.sleeps.len(),
            1,
            "expected exactly one backoff between the two attempts"
        );
        assert!(sleeper.sleeps[0] > Duration::ZERO);
        assert_eq!(server.remaining(), 0);
    }

    #[test]
    fn retries_after_408_then_succeeds() {
        let body = page(vec![entry("2.31-0ubuntu9", "amd64")], None);
        let server = FakeLaunchpadServer::with_responses(vec![status(408, ""), status(200, &body)]);

        let mut sleeper = RecordingSleeper::default();
        let versions = search_versions_with(
            "2.31",
            &CpuArch::Amd64,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("lookup should succeed after retry on 408");

        assert_eq!(versions, vec!["2.31-0ubuntu9".to_string()]);
        assert_eq!(sleeper.sleeps.len(), 1);
    }

    #[test]
    fn retries_after_429_then_succeeds() {
        let body = page(vec![entry("2.31-0ubuntu9", "amd64")], None);
        let server = FakeLaunchpadServer::with_responses(vec![status(429, ""), status(200, &body)]);

        let mut sleeper = RecordingSleeper::default();
        let versions = search_versions_with(
            "2.31",
            &CpuArch::Amd64,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("lookup should succeed after retry on 429");

        assert_eq!(versions, vec!["2.31-0ubuntu9".to_string()]);
        assert_eq!(sleeper.sleeps.len(), 1);
    }

    #[test]
    fn retries_after_500_then_succeeds() {
        let body = page(vec![entry("2.31-0ubuntu9", "amd64")], None);
        let server = FakeLaunchpadServer::with_responses(vec![status(500, ""), status(200, &body)]);

        let mut sleeper = RecordingSleeper::default();
        let versions = search_versions_with(
            "2.31",
            &CpuArch::Amd64,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("lookup should succeed after retry on 500");

        assert_eq!(versions, vec!["2.31-0ubuntu9".to_string()]);
        assert_eq!(sleeper.sleeps.len(), 1);
    }

    #[test]
    fn retries_after_502_then_succeeds() {
        let body = page(vec![entry("2.31-0ubuntu9", "amd64")], None);
        let server = FakeLaunchpadServer::with_responses(vec![status(502, ""), status(200, &body)]);

        let mut sleeper = RecordingSleeper::default();
        let versions = search_versions_with(
            "2.31",
            &CpuArch::Amd64,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("lookup should succeed after retry on 502");

        assert_eq!(versions, vec!["2.31-0ubuntu9".to_string()]);
    }

    #[test]
    fn retries_after_truncated_body_then_succeeds() {
        let body = page(vec![entry("2.31-0ubuntu9", "amd64")], None);
        let server = FakeLaunchpadServer::with_responses(vec![
            FakeResponse::TruncatedBody {
                content_length: 1024,
                body: b"<html>oops".to_vec(),
            },
            status(200, &body),
        ]);

        let mut sleeper = RecordingSleeper::default();
        let versions = search_versions_with(
            "2.31",
            &CpuArch::Amd64,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("lookup should succeed after retrying the truncated body");

        assert_eq!(versions, vec!["2.31-0ubuntu9".to_string()]);
        assert_eq!(sleeper.sleeps.len(), 1);
        assert_eq!(server.remaining(), 0);
    }

    #[test]
    fn permanent_4xx_does_not_retry() {
        let server = FakeLaunchpadServer::with_responses(vec![status(404, "not found")]);

        let mut sleeper = RecordingSleeper::default();
        let err = search_versions_with(
            "2.31",
            &CpuArch::Amd64,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect_err("404 must not be retried");

        assert!(sleeper.sleeps.is_empty(), "no backoff for permanent status");
        match err {
            Error::Request {
                source: http_retry::Error::PermanentStatus { status },
            } => assert_eq!(status, reqwest::StatusCode::NOT_FOUND),
            other => panic!("expected PermanentStatus(404), got {:?}", other),
        }
        assert_eq!(server.remaining(), 0);
    }

    #[test]
    fn malformed_json_fails_as_parse_error_without_retry() {
        // The body is not valid JSON; reqwest's JSON decoder returns a
        // permanent parse error which our retry layer must not retry.
        let server =
            FakeLaunchpadServer::with_responses(vec![status(200, "<html>not json</html>")]);

        let mut sleeper = RecordingSleeper::default();
        let err = search_versions_with(
            "2.31",
            &CpuArch::Amd64,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect_err("malformed JSON must fail");

        assert!(sleeper.sleeps.is_empty(), "malformed JSON must not retry");
        match err {
            Error::Parse { .. } => {}
            other => panic!("expected Parse error, got {:?}", other),
        }
        assert_eq!(server.remaining(), 0);
    }

    #[test]
    fn retry_exhaustion_returns_useful_error() {
        let server = FakeLaunchpadServer::with_responses(vec![
            status(503, ""),
            status(503, ""),
            status(503, ""),
        ]);

        let policy = RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
        };
        let mut sleeper = RecordingSleeper::default();
        let err = search_versions_with(
            "2.31",
            &CpuArch::Amd64,
            &server.base_url,
            policy,
            &mut sleeper,
        )
        .expect_err("retry exhaustion should fail");

        assert_eq!(
            sleeper.sleeps.len(),
            2,
            "one backoff between each pair of attempts"
        );
        match err {
            Error::Request {
                source: http_retry::Error::RetryableStatus { status },
            } => assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE),
            other => panic!("expected RetryableStatus(503), got {:?}", other),
        }
    }

    #[test]
    fn transient_status_on_paginated_request_is_retried_and_filtering_is_preserved() {
        // First page fails transiently, second page contains a mix of
        // architectures and a duplicate. The retry must only resend the
        // first page, and the final list must be filtered, deduplicated,
        // and sorted.
        let server = FakeLaunchpadServer::new();
        let next_link = format!("{}/page2", server.base_url);

        let page1_body = page(vec![entry("2.31-0ubuntu9", "amd64")], Some(&next_link));
        let page2_body = page(
            vec![
                entry("2.31-0ubuntu9.16", "amd64"),
                entry("2.31-0ubuntu9.16", "amd64"), // duplicate
                entry("2.31-0ubuntu9.16", "i386"),  // wrong arch
            ],
            None,
        );

        server.push(status(503, ""));
        server.push(status(200, &page1_body));
        server.push(status(200, &page2_body));

        let mut sleeper = RecordingSleeper::default();
        let versions = search_versions_with(
            "2.31",
            &CpuArch::Amd64,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("paginated lookup should succeed after retry");

        assert_eq!(
            versions,
            vec!["2.31-0ubuntu9".to_string(), "2.31-0ubuntu9.16".to_string()]
        );
        // Only one backoff (between the 503 and the successful page1 attempt).
        // No backoff between page1 and page2 because page1 already succeeded.
        assert_eq!(sleeper.sleeps.len(), 1);
    }
}
