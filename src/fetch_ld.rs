use crate::cpu_arch::CpuArch;
use crate::debian_libc;
use crate::http_retry::{RetryPolicy, Sleeper, StdSleeper};
use crate::libc_deb;
use crate::libc_version::LibcVersion;
use crate::output;

use std::path::Path;

use colored::Colorize;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("libc deb error: {}", source))]
    Deb { source: libc_deb::Error },

    #[snafu(display("Debian libc search error: {}", source))]
    Debian { source: debian_libc::Error },

    #[snafu(display("no Debian libc6 package found for version {} ({})", version, arch))]
    DebianPackageNotFound { version: String, arch: CpuArch },
}

pub type Result<T = ()> = std::result::Result<T, Error>;

pub(crate) fn ld_name_in_deb(ver: &LibcVersion) -> String {
    if ver.is_pre_234() {
        format!("ld-{}.so", ver.string_short)
    } else {
        canonical_ld_name(&ver.arch).to_string()
    }
}

pub(crate) fn canonical_ld_name(arch: &CpuArch) -> &'static str {
    match arch {
        CpuArch::I386 => "ld-linux.so.2",
        CpuArch::Amd64 => "ld-linux-x86-64.so.2",
    }
}

fn fetch_ld_to(ver: &LibcVersion, out_name: impl AsRef<Path>) -> Result {
    if ver.string.contains("ubuntu") {
        return fetch_ld_to_with(
            ver,
            out_name,
            libc_deb::PKG_URL,
            RetryPolicy::default(),
            &mut StdSleeper,
        );
    }

    let policy = RetryPolicy::default();
    let mut sleeper = StdSleeper;
    let package = debian_libc::search_snapshot_binary(
        "libc6",
        &ver.string,
        ver.arch,
        debian_libc::DEBIAN_SNAPSHOT_URL,
        policy,
        &mut sleeper,
    )
    .context(DebianSnafu)?;
    let Some(package) = package else {
        return Err(Error::DebianPackageNotFound {
            version: ver.string.clone(),
            arch: ver.arch,
        });
    };

    let ld_name = ld_name_in_deb(ver);
    libc_deb::write_deb_url_file_with(
        &package.deb_url,
        &[&ld_name],
        out_name,
        policy,
        &mut sleeper,
    )
    .context(DebSnafu)
}

/// Same as [`fetch_ld_to`] but lets callers inject the base URL, retry
/// policy, and sleeper. Used by tests to drive a local fake server with
/// deterministic responses.
pub(crate) fn fetch_ld_to_with(
    ver: &LibcVersion,
    out_name: impl AsRef<Path>,
    base_url: &str,
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
) -> Result {
    let deb_file_name = format!("libc6_{}.deb", ver);
    let ld_name = ld_name_in_deb(ver);
    libc_deb::write_ubuntu_pkg_file_with(
        &deb_file_name,
        &[&ld_name],
        out_name,
        base_url,
        policy,
        sleeper,
    )
    .context(DebSnafu)
}

/// Download linker compatible with libc version `ver`, saved as `ld-{short}.so`
pub fn fetch_ld(ver: &LibcVersion) -> Result {
    output::progress("fetching linker".green().bold());
    fetch_ld_to(ver, format!("ld-{}.so", ver.string_short))
}

/// Download the linker for `ver` and save it under the canonical runtime name
/// (`ld-linux-x86-64.so.2` or `ld-linux.so.2`).
#[allow(dead_code)]
pub fn fetch_ld_canonical(ver: &LibcVersion) -> Result {
    output::progress("fetching linker".green().bold());
    fetch_ld_to(ver, canonical_ld_name(&ver.arch))
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

    use flate2::write::GzEncoder;
    use flate2::Compression;

    use crate::http_retry::Sleeper;

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

    #[derive(Clone)]
    enum ScriptedResponse {
        Status { status: u16, body: Vec<u8> },
        Body(Vec<u8>),
    }

    impl ScriptedResponse {
        fn status(status: u16, body: &[u8]) -> Self {
            ScriptedResponse::Status {
                status,
                body: body.to_vec(),
            }
        }
    }

    #[derive(Default)]
    struct ScriptedServer {
        base_url: String,
        responses: Arc<Mutex<VecDeque<ScriptedResponse>>>,
        shutdown: Arc<AtomicBool>,
        join_handle: Option<JoinHandle<()>>,
    }

    impl ScriptedServer {
        fn with(responses: Vec<ScriptedResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let base_url = format!("http://127.0.0.1:{}", port);
            listener.set_nonblocking(true).expect("nonblocking");

            let queue = Arc::new(Mutex::new(VecDeque::from(responses)));
            let queue_clone = queue.clone();
            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_clone = shutdown.clone();

            let join_handle = thread::spawn(move || loop {
                if shutdown_clone.load(Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => drain_request(&mut stream, &queue_clone),
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

        fn remaining(&self) -> usize {
            self.responses.lock().expect("lock").len()
        }
    }

    impl Drop for ScriptedServer {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::SeqCst);
            if let Some(handle) = self.join_handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn drain_request(stream: &mut TcpStream, queue: &Arc<Mutex<VecDeque<ScriptedResponse>>>) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        let response = queue.lock().expect("lock").pop_front();
        let (status, body) = match response {
            Some(ScriptedResponse::Status { status, body }) => (status, body),
            Some(ScriptedResponse::Body(body)) => (200, body),
            None => (500, Vec::new()),
        };
        let reason = match status {
            200 => "OK",
            404 => "Not Found",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
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

    fn make_tiny_deb_gz(content_path: &str, content: &[u8]) -> Vec<u8> {
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

    fn fast_policy() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
        }
    }

    fn new_version(short: &str) -> LibcVersion {
        LibcVersion {
            string: format!("{}-0ubuntu1", short),
            string_short: short.to_string(),
            arch: CpuArch::Amd64,
        }
    }

    /// Linker fetches (both `ld-{short}.so` and canonical
    /// `ld-linux-x86-64.so.2` variants) must use the same retry-enabled
    /// deb download path. A transient 503 is retried and a later valid
    /// response extracts the linker with the expected bytes.
    #[test]
    fn linker_fetch_retries_transient_status_and_extracts() {
        let deb = make_tiny_deb_gz("ld-linux-x86-64.so.2", b"linker bytes");
        let server = ScriptedServer::with(vec![
            ScriptedResponse::status(503, b""),
            ScriptedResponse::Body(deb),
        ]);

        let mut sleeper = RecordingSleeper::default();
        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let out_path = tmp.path().join("ld-linux-x86-64.so.2");

        fetch_ld_to_with(
            &new_version("2.34"),
            &out_path,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("linker fetch should succeed after retry");

        let written = std::fs::read(&out_path).expect("read linker");
        assert_eq!(written, b"linker bytes");
        assert_eq!(sleeper.sleeps.len(), 1, "expected one backoff");
        assert_eq!(server.remaining(), 0);
    }

    /// The fetch flow downloads `libc6_{ver}.deb` and looks for the linker
    /// file inside it. The retry layer must not change which package the
    /// linker fetch targets.
    #[test]
    fn linker_fetch_targets_libc6_deb() {
        // Use a server that records the requested URL path.
        let recorded = Arc::new(Mutex::new(Vec::<String>::new()));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        listener.set_nonblocking(true).expect("nonblocking");
        let recorded_clone = recorded.clone();
        let deb = make_tiny_deb_gz("ld-linux-x86-64.so.2", b"linker");
        let deb_clone = deb.clone();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let join = thread::spawn(move || loop {
            if shutdown_clone.load(Ordering::SeqCst) {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                    let mut buf = [0u8; 1024];
                    let mut path = String::new();
                    let mut bytes_read = 0;
                    while let Ok(n) = stream.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        bytes_read += n;
                        if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                            path.push_str(s);
                        }
                        if bytes_read > 4096 {
                            break;
                        }
                    }
                    let request_line = path.lines().next().unwrap_or("").to_string();
                    recorded_clone.lock().expect("lock").push(request_line);
                    let body = deb_clone.clone();
                    let raw = format!(
                        "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len(),
                    );
                    let _ = stream.write_all(raw.as_bytes());
                    let _ = stream.write_all(&body);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        });

        let mut sleeper = RecordingSleeper::default();
        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let out_path = tmp.path().join("ld-linux-x86-64.so.2");

        fetch_ld_to_with(
            &new_version("2.34"),
            &out_path,
            &format!("http://127.0.0.1:{}", port),
            fast_policy(),
            &mut sleeper,
        )
        .expect("linker fetch should succeed");

        shutdown.store(true, Ordering::SeqCst);
        let _ = join.join();

        let requests = recorded.lock().expect("lock");
        assert_eq!(requests.len(), 1, "single request expected");
        // The request should target the libc6 deb with the version suffix.
        assert!(
            requests[0].contains("libc6_2.34-0ubuntu1_amd64.deb"),
            "expected libc6 deb URL, got {}",
            requests[0]
        );
    }
}
