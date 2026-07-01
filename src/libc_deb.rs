use std::ffi::OsStr;
use std::io::copy;
use std::io::Cursor;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use colored::Colorize;
use ex::fs::File;
use ex::io;
use flate2::read::GzDecoder;
use lzma::LzmaReader;
use snafu::OptionExt;
use snafu::ResultExt;
use snafu::Snafu;

use crate::http_retry::{self, RetryPolicy, Sleeper, StdSleeper};

/// Ubuntu primary archive package file endpoint used for glibc deb downloads.
pub const PKG_URL: &str = "https://launchpad.net/ubuntu/+archive/primary/+files";

pub type Result<T> = std::result::Result<T, Error>;

/// Helper function that decides whether the tar file `entry` matches
/// one of the `file_names`
fn tar_entry_matches_any<R: Read>(
    entry: &std::io::Result<tar::Entry<R>>,
    file_names: &[&str],
) -> bool {
    let Ok(entry) = entry else { return false };
    let Ok(path) = entry.path() else { return false };

    let res = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| file_names.contains(&name))
        .unwrap_or(false);
    if res {
        println!(
            "{}",
            format!("Found matching file: {}", path.display())
                .bold()
                .green()
        );
    }
    res
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to download package from Ubuntu mirror: {}", source))]
    Download { source: reqwest::Error },

    #[snafu(display(
        "failed to download package from Ubuntu mirror: status code: {}",
        status
    ))]
    DownloadStatus { status: reqwest::StatusCode },

    #[snafu(display("failed decompressing data.tar.xz: {}", source))]
    DataUnzipLzma { source: lzma::LzmaError },

    #[snafu(display("failed decompressing data.tar.zst: {}", source))]
    DataUnzipZstd { source: std::io::Error },

    #[snafu(display("failed getting data.tar entries: {}", source))]
    DataEntries { source: std::io::Error },

    #[snafu(display("failed to find file in data.tar"))]
    FileNotFound,

    #[snafu(display("failed reading file entry in data.tar: {}", source))]
    Read { source: std::io::Error },

    #[snafu(display("failed to write file from deb: {}", source))]
    Write { source: std::io::Error },

    #[snafu(display("failed to create file: {}", source))]
    Create { source: io::Error },

    #[snafu(display("failed to find data.tar in package"))]
    DataNotFound,

    #[snafu(display(
        "data.tar in package has unknown extension: {}",
        String::from_utf8_lossy(ext)
    ))]
    DataExt { ext: Vec<u8> },
}

/// Download the glibc deb package with a given name, find a file inside it, and
/// extract the file. The full package body is fetched through the shared
/// retry layer before archive parsing so transient transport, status, and
/// body-read failures are all retryable.
#[allow(dead_code)]
pub fn write_ubuntu_pkg_file<P: AsRef<Path>>(
    deb_file_name: &str,
    file_names: &[&str],
    out_path: P,
) -> Result<()> {
    write_ubuntu_pkg_file_with(
        deb_file_name,
        file_names,
        out_path,
        PKG_URL,
        RetryPolicy::default(),
        &mut StdSleeper,
    )
}

/// Same as [`write_ubuntu_pkg_file`] but lets callers inject the base URL,
/// retry policy, and sleeper. Used by tests to drive a local fake server
/// with deterministic responses.
pub(crate) fn write_ubuntu_pkg_file_with<P: AsRef<Path>>(
    deb_file_name: &str,
    file_names: &[&str],
    out_path: P,
    base_url: &str,
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
) -> Result<()> {
    let out_path = out_path.as_ref();
    let url = format!("{}/{}", base_url, deb_file_name);
    println!("{}", url.green().bold());

    let deb_bytes = match http_retry::get_bytes(&url, policy, sleeper) {
        Ok((bytes, _trace)) => bytes,
        Err(http_retry::Error::Request { source }) => {
            return Err(Error::Download { source });
        }
        Err(http_retry::Error::PermanentStatus { status })
        | Err(http_retry::Error::RetryableStatus { status }) => {
            return Err(Error::DownloadStatus { status });
        }
        // `get_bytes` reads the body and never parses JSON, so the `Parse`
        // variant is unreachable for the package download surface.
        Err(http_retry::Error::Parse { .. }) => unreachable!(),
    };

    let mut deb = ar::Archive::new(Cursor::new(deb_bytes));

    // Try to find data.tar in package
    while let Some(Ok(entry)) = deb.next_entry() {
        let path = entry.header().identifier();
        let path = Path::new(OsStr::from_bytes(path));

        let stem = path.file_stem().map(OsStr::as_bytes);
        if stem != Some(b"data.tar") {
            continue;
        }

        // Detect extension and decompress
        let ext = path
            .extension()
            .map(OsStr::as_bytes)
            .context(DataNotFoundSnafu)?;
        match ext {
            b"gz" => {
                let data = GzDecoder::new(entry);
                write_ubuntu_data_tar_file(data, file_names, out_path)
            }
            b"xz" => {
                let data = LzmaReader::new_decompressor(entry).context(DataUnzipLzmaSnafu)?;
                write_ubuntu_data_tar_file(data, file_names, out_path)
            }
            b"zst" => {
                let data = zstd::stream::read::Decoder::new(entry).context(DataUnzipZstdSnafu)?;
                write_ubuntu_data_tar_file(data, file_names, out_path)
            }
            ext => None.context(DataExtSnafu { ext }),
        }?;

        return Ok(());
    }

    Err(Error::DataNotFound)
}

/// Given the bytes of a data.tar in a glibc deb package, find a file inside it,
/// and extract the file.
fn write_ubuntu_data_tar_file<R: Read>(
    data_tar_bytes: R,
    file_names: &[&str],
    out_path: &Path,
) -> Result<()> {
    let mut data_tar = tar::Archive::new(data_tar_bytes);
    let mut entry = data_tar
        .entries()
        .context(DataEntriesSnafu)?
        .find(|entry| tar_entry_matches_any(entry, file_names))
        .context(FileNotFoundSnafu)?
        .context(ReadSnafu)?;
    let mut out_file = File::create(out_path).context(CreateSnafu)?;
    copy(&mut entry, &mut out_file).context(WriteSnafu)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use flate2::write::GzEncoder;
    use flate2::Compression;

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
        Status { status: u16, body: Vec<u8> },
        /// Return `200 OK` with a `Content-Length` larger than the body that
        /// is actually written, then close the connection. The client sees a
        /// truncated body and classifies it as a body-read failure.
        TruncatedBody {
            content_length: usize,
            body: Vec<u8>,
        },
    }

    impl FakeResponse {
        fn ok(body: &[u8]) -> Self {
            FakeResponse::Status {
                status: 200,
                body: body.to_vec(),
            }
        }
    }

    /// Tiny single-threaded HTTP/1.0 server used to drive `write_ubuntu_pkg_file`
    /// in tests. Serves a scripted queue of [`FakeResponse`] values, one
    /// per request, then falls back to `500 Internal Server Error` for any
    /// extra request that the test did not expect.
    struct FakePackageServer {
        base_url: String,
        responses: Arc<Mutex<VecDeque<FakeResponse>>>,
        shutdown: Arc<AtomicBool>,
        join_handle: Option<JoinHandle<()>>,
    }

    impl FakePackageServer {
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
        #[allow(dead_code)]
        fn push(&self, response: FakeResponse) {
            self.responses
                .lock()
                .expect("lock poisoned")
                .push_back(response);
        }

        /// Number of scripted responses that have not yet been consumed.
        fn remaining(&self) -> usize {
            self.responses.lock().expect("lock poisoned").len()
        }
    }

    impl Drop for FakePackageServer {
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
                    "HTTP/1.0 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status,
                    reason,
                    body.len(),
                );
                let _ = stream.write_all(raw.as_bytes());
                let _ = stream.write_all(&body);
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

    /// Build a tiny in-memory Ubuntu `.deb` package whose `data.tar.gz`
    /// contains a single file at `content_path` with the given bytes.
    /// `content_path` is the path *inside* the tarball (e.g. `libc.so.6` or
    /// `usr/lib/x86_64-linux-gnu/libc.so.6`); only the file name is matched
    /// by the extraction logic.
    fn make_tiny_deb_gz(content_path: &str, content: &[u8]) -> Vec<u8> {
        // 1. Build data.tar.gz in memory
        let mut data_tar_gz = Vec::new();
        {
            let enc = GzEncoder::new(&mut data_tar_gz, Compression::default());
            let mut tar_builder = tar::Builder::new(enc);
            let mut header = tar::Header::new_gnu();
            header.set_path(content_path).expect("set tar path");
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            tar_builder
                .append(&header, content)
                .expect("append tar entry");
            tar_builder.finish().expect("finish tar");
        }

        // 2. Wrap in the .deb ar archive
        let mut deb = Vec::new();
        {
            let mut builder = ar::Builder::new(&mut deb);
            let debian_binary: &[u8] = b"2.0\n";
            let header = ar::Header::new(b"debian-binary".to_vec(), debian_binary.len() as u64);
            builder
                .append(&header, debian_binary)
                .expect("append debian-binary");
            let header = ar::Header::new(b"data.tar.gz".to_vec(), data_tar_gz.len() as u64);
            builder
                .append(&header, data_tar_gz.as_slice())
                .expect("append data.tar.gz");
        }
        deb
    }

    fn write_ubuntu_pkg(
        server: &FakePackageServer,
        deb_file_name: &str,
        file_names: &[&str],
        out_path: &Path,
    ) -> Result<()> {
        let mut sleeper = RecordingSleeper::default();
        write_ubuntu_pkg_file_with(
            deb_file_name,
            file_names,
            out_path,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
    }

    fn status(status: u16, body: &[u8]) -> FakeResponse {
        FakeResponse::Status {
            status,
            body: body.to_vec(),
        }
    }

    // --------------------------------------------------------------------
    // Happy path: download the package once and extract the requested file.
    // --------------------------------------------------------------------

    #[test]
    fn extracts_requested_file_from_valid_deb() {
        let deb = make_tiny_deb_gz("libc.so.6", b"hello libc");
        let server = FakePackageServer::with_responses(vec![FakeResponse::ok(&deb)]);

        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let out_path: PathBuf = tmp.path().join("libc.so.6");
        write_ubuntu_pkg(
            &server,
            "libc6_2.31-0ubuntu9_amd64.deb",
            &["libc.so.6"],
            &out_path,
        )
        .expect("extraction should succeed");

        let written = std::fs::read(&out_path).expect("read extracted file");
        assert_eq!(written, b"hello libc");
        assert_eq!(server.remaining(), 0, "single request expected");
    }

    // --------------------------------------------------------------------
    // VAL-DOWNLOAD-001 / VAL-DOWNLOAD-002: transient status retries.
    // --------------------------------------------------------------------

    #[test]
    fn retries_transient_status_then_extracts() {
        let deb = make_tiny_deb_gz("libc.so.6", b"libc bytes");
        let server =
            FakePackageServer::with_responses(vec![status(503, b""), FakeResponse::ok(&deb)]);

        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let out_path: PathBuf = tmp.path().join("libc.so.6");
        write_ubuntu_pkg(
            &server,
            "libc6_2.31-0ubuntu9_amd64.deb",
            &["libc.so.6"],
            &out_path,
        )
        .expect("extraction should succeed after retry");

        let written = std::fs::read(&out_path).expect("read extracted file");
        assert_eq!(written, b"libc bytes");
        assert_eq!(server.remaining(), 0, "both scripted responses consumed");
    }

    #[test]
    fn retries_after_408_429_and_5xx_statuses() {
        for transient_status in [408u16, 429, 500, 502, 503, 504] {
            let deb = make_tiny_deb_gz("libc.so.6", b"ok");
            let server = FakePackageServer::with_responses(vec![
                status(transient_status, b""),
                FakeResponse::ok(&deb),
            ]);

            let tmp = tempfile::TempDir::new().expect("tmpdir");
            let out_path: PathBuf = tmp.path().join("libc.so.6");
            write_ubuntu_pkg(
                &server,
                "libc6_2.31-0ubuntu9_amd64.deb",
                &["libc.so.6"],
                &out_path,
            )
            .unwrap_or_else(|err| {
                panic!(
                    "status {} should retry and succeed, got {:?}",
                    transient_status, err
                )
            });

            let written = std::fs::read(&out_path).expect("read extracted file");
            assert_eq!(written, b"ok", "status {}", transient_status);
            assert_eq!(
                server.remaining(),
                0,
                "status {}: both responses should be consumed",
                transient_status
            );
        }
    }

    // --------------------------------------------------------------------
    // VAL-DOWNLOAD-003: mid-body failure retries the whole package.
    // --------------------------------------------------------------------

    #[test]
    fn retries_after_truncated_body_then_extracts() {
        let deb = make_tiny_deb_gz("libc.so.6", b"complete bytes");

        // First response advertises a 4 KiB body but only writes a fraction
        // of it, then closes the connection. reqwest surfaces this as a
        // body-read failure when the body does not match the content-length.
        let partial = deb[..deb.len() / 2].to_vec();
        let server = FakePackageServer::with_responses(vec![
            FakeResponse::TruncatedBody {
                content_length: deb.len(),
                body: partial,
            },
            FakeResponse::ok(&deb),
        ]);

        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let out_path: PathBuf = tmp.path().join("libc.so.6");
        write_ubuntu_pkg(
            &server,
            "libc6_2.31-0ubuntu9_amd64.deb",
            &["libc.so.6"],
            &out_path,
        )
        .expect("extraction should succeed after retrying truncated body");

        let written = std::fs::read(&out_path).expect("read extracted file");
        assert_eq!(written, b"complete bytes");
        assert_eq!(server.remaining(), 0);
    }

    // --------------------------------------------------------------------
    // VAL-DOWNLOAD-004: retry exhaustion is bounded and returns a useful
    // failure that preserves the final retryable status.
    // --------------------------------------------------------------------

    #[test]
    fn retry_exhaustion_preserves_final_status_and_does_not_sleep_unboundedly() {
        let server = FakePackageServer::with_responses(vec![
            status(503, b""),
            status(503, b""),
            status(503, b""),
        ]);

        let policy = fast_policy();
        let mut sleeper = RecordingSleeper::default();
        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let out_path: PathBuf = tmp.path().join("libc.so.6");
        let err = write_ubuntu_pkg_file_with(
            "libc6_2.31-0ubuntu9_amd64.deb",
            &["libc.so.6"],
            &out_path,
            &server.base_url,
            policy,
            &mut sleeper,
        )
        .expect_err("retry exhaustion should fail");

        assert_eq!(sleeper.sleeps.len() as u32, policy.max_attempts - 1);
        match err {
            Error::DownloadStatus { status } => {
                assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE);
            }
            other => panic!("expected DownloadStatus(503), got {:?}", other),
        }
        assert_eq!(server.remaining(), 0);
    }

    // --------------------------------------------------------------------
    // VAL-DOWNLOAD-005: permanent 4xx statuses are not retried and the
    // status code is preserved.
    // --------------------------------------------------------------------

    #[test]
    fn permanent_4xx_is_not_retried() {
        for permanent in [400u16, 401, 403, 404, 422] {
            let server = FakePackageServer::with_responses(vec![status(permanent, b"nope")]);

            let mut sleeper = RecordingSleeper::default();
            let tmp = tempfile::TempDir::new().expect("tmpdir");
            let out_path: PathBuf = tmp.path().join("libc.so.6");
            let err = match write_ubuntu_pkg_file_with(
                "libc6_2.31-0ubuntu9_amd64.deb",
                &["libc.so.6"],
                &out_path,
                &server.base_url,
                fast_policy(),
                &mut sleeper,
            ) {
                Ok(()) => panic!(
                    "status {} should be permanent but download succeeded",
                    permanent
                ),
                Err(err) => err,
            };

            assert!(
                sleeper.sleeps.is_empty(),
                "permanent status {} should not sleep",
                permanent
            );
            match err {
                Error::DownloadStatus { status } => {
                    assert_eq!(
                        status.as_u16(),
                        permanent,
                        "status {} should be preserved",
                        permanent
                    );
                }
                other => panic!(
                    "status {}: expected DownloadStatus, got {:?}",
                    permanent, other
                ),
            }
            assert_eq!(server.remaining(), 0);
        }
    }

    // --------------------------------------------------------------------
    // VAL-DOWNLOAD-006: malformed content / missing archive members /
    // missing requested files do not retry.
    // --------------------------------------------------------------------

    #[test]
    fn malformed_package_content_is_not_retried() {
        // Valid HTTP response but the body is not an ar archive. The retry
        // layer succeeds with bytes and then ar parsing fails, which is a
        // permanent content failure (no network retry).
        let server =
            FakePackageServer::with_responses(vec![FakeResponse::ok(b"this is not an ar archive")]);

        let mut sleeper = RecordingSleeper::default();
        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let out_path: PathBuf = tmp.path().join("libc.so.6");
        let err = write_ubuntu_pkg_file_with(
            "libc6_2.31-0ubuntu9_amd64.deb",
            &["libc.so.6"],
            &out_path,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect_err("malformed package should fail without retry");

        assert!(
            sleeper.sleeps.is_empty(),
            "malformed package content must not retry"
        );
        // The ar reader returns `None` for `next_entry` on a non-ar body,
        // which the extraction code maps to `DataNotFound`.
        assert!(matches!(err, Error::DataNotFound));
        assert_eq!(server.remaining(), 0);
    }

    #[test]
    fn missing_data_tar_member_is_not_retried() {
        // Build a .deb that only has `debian-binary` and no data.tar.
        let mut deb = Vec::new();
        {
            let mut builder = ar::Builder::new(&mut deb);
            let payload: &[u8] = b"2.0\n";
            let header = ar::Header::new(b"debian-binary".to_vec(), payload.len() as u64);
            builder
                .append(&header, payload)
                .expect("append debian-binary");
        }
        let server = FakePackageServer::with_responses(vec![FakeResponse::ok(&deb)]);

        let mut sleeper = RecordingSleeper::default();
        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let out_path: PathBuf = tmp.path().join("libc.so.6");
        let err = write_ubuntu_pkg_file_with(
            "libc6_2.31-0ubuntu9_amd64.deb",
            &["libc.so.6"],
            &out_path,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect_err("missing data.tar should fail without retry");

        assert!(sleeper.sleeps.is_empty(), "missing data.tar must not retry");
        assert!(matches!(err, Error::DataNotFound));
        assert_eq!(server.remaining(), 0);
    }

    #[test]
    fn missing_requested_file_is_not_retried() {
        // data.tar.gz has a file with a different name than the candidate.
        let deb = make_tiny_deb_gz("not-the-libc.so.6", b"some other file");
        let server = FakePackageServer::with_responses(vec![FakeResponse::ok(&deb)]);

        let mut sleeper = RecordingSleeper::default();
        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let out_path: PathBuf = tmp.path().join("libc.so.6");
        let err = write_ubuntu_pkg_file_with(
            "libc6_2.31-0ubuntu9_amd64.deb",
            &["libc.so.6"],
            &out_path,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect_err("missing requested file should fail without retry");

        assert!(sleeper.sleeps.is_empty(), "missing file must not retry");
        assert!(matches!(err, Error::FileNotFound));
        assert_eq!(server.remaining(), 0);
    }

    // --------------------------------------------------------------------
    // VAL-DOWNLOAD-008: old and new glibc package filename candidate
    // behavior is unchanged.
    // --------------------------------------------------------------------

    #[test]
    fn candidate_prefers_versioned_name_for_old_glibc_payload() {
        // For glibc < 2.34 the candidate list is ["libc-2.31.so", "libc.so.6"].
        // A package that only ships the versioned file must still be
        // accepted, and the output bytes must match.
        let deb = make_tiny_deb_gz("libc-2.31.so", b"versioned libc bytes");
        let server = FakePackageServer::with_responses(vec![FakeResponse::ok(&deb)]);

        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let out_path: PathBuf = tmp.path().join("libc.so.6");
        write_ubuntu_pkg_file_with(
            "libc6_2.31-0ubuntu9_amd64.deb",
            // Same candidate order as `fetch_libc` for pre-2.34 glibc.
            &["libc-2.31.so", "libc.so.6"],
            &out_path,
            &server.base_url,
            fast_policy(),
            &mut RecordingSleeper::default(),
        )
        .expect("old-glibc candidate should match versioned file");

        let written = std::fs::read(&out_path).expect("read extracted file");
        assert_eq!(written, b"versioned libc bytes");
        assert_eq!(server.remaining(), 0);
    }

    #[test]
    fn candidate_prefers_soname_for_new_glibc_payload() {
        // For glibc >= 2.34 the candidate list is ["libc.so.6", "libc-2.34.so"].
        // A package that only ships the soname must still be accepted.
        let deb = make_tiny_deb_gz("libc.so.6", b"soname libc bytes");
        let server = FakePackageServer::with_responses(vec![FakeResponse::ok(&deb)]);

        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let out_path: PathBuf = tmp.path().join("libc.so.6");
        write_ubuntu_pkg_file_with(
            "libc6_2.34-0ubuntu1_amd64.deb",
            &["libc.so.6", "libc-2.34.so"],
            &out_path,
            &server.base_url,
            fast_policy(),
            &mut RecordingSleeper::default(),
        )
        .expect("new-glibc candidate should match soname");

        let written = std::fs::read(&out_path).expect("read extracted file");
        assert_eq!(written, b"soname libc bytes");
    }

    // --------------------------------------------------------------------
    // First-attempt success must not sleep, even if the retry policy is
    // configured to allow more attempts.
    // --------------------------------------------------------------------

    #[test]
    fn first_attempt_success_does_not_sleep() {
        let deb = make_tiny_deb_gz("libc.so.6", b"libc");
        let server = FakePackageServer::with_responses(vec![FakeResponse::ok(&deb)]);

        let mut sleeper = RecordingSleeper::default();
        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let out_path: PathBuf = tmp.path().join("libc.so.6");
        write_ubuntu_pkg_file_with(
            "libc6_2.31-0ubuntu9_amd64.deb",
            &["libc.so.6"],
            &out_path,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("first-attempt success");

        assert!(
            sleeper.sleeps.is_empty(),
            "first-attempt success must not sleep"
        );
        assert_eq!(server.remaining(), 0);
    }

    // --------------------------------------------------------------------
    // Sanity check: a RecordingSleeper never blocks the test even if the
    // scheduled delay is large.
    // --------------------------------------------------------------------

    #[test]
    fn recording_sleeper_does_not_block() {
        let mut sleeper = RecordingSleeper::default();
        sleeper.sleep(Duration::from_secs(3600));
        assert_eq!(sleeper.sleeps, vec![Duration::from_secs(3600)]);
    }
}
