use crate::elf;
use crate::http_retry::{RetryPolicy, Sleeper, StdSleeper};
use crate::libc_deb;
use crate::libc_version::LibcVersion;

use std::io::copy;
use std::io::stderr;
use std::io::stdout;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::process::ExitStatus;

use colored::Colorize;
use ex::fs::File;
use ex::io;
use snafu::ResultExt;
use snafu::Snafu;
use tempfile::TempDir;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("libc ELF parse error: {}", source))]
    ElfParse { source: elf::parse::Error },

    #[snafu(display("libc deb error: {}", source))]
    Deb { source: libc_deb::Error },

    #[snafu(display("failed creating temporary directory"))]
    TmpDir { source: std::io::Error },

    #[snafu(display("failed running eu-unstrip, please install elfutils: {}", source))]
    CmdRun { source: std::io::Error },

    #[snafu(display("eu-unstrip exited with failure: {}", status))]
    CmdFail { status: ExitStatus },

    #[snafu(display("failed to open symbol file: {}", source))]
    SymOpen { source: io::Error },

    #[snafu(display("failed to open libc file: {}", source))]
    LibcOpen { source: io::Error },

    #[snafu(display("failed writing symbols to libc file: {}", source))]
    LibcWrite { source: std::io::Error },
}

pub type Result<T = ()> = std::result::Result<T, Error>;

/// Build the debug-symbol deb file name for a given libc version.
pub(crate) fn debug_deb_file_name(ver: &LibcVersion) -> String {
    format!("libc6-dbg_{}.deb", ver)
}

/// Download debug symbols and apply them to a libc
fn do_unstrip_libc(libc: &Path, ver: &LibcVersion) -> Result {
    let mut sleeper = StdSleeper;
    do_unstrip_libc_with(
        libc,
        ver,
        libc_deb::PKG_URL,
        RetryPolicy::default(),
        &mut sleeper,
    )
}

/// Same as [`do_unstrip_libc`] but lets callers inject the base URL, retry
/// policy, and sleeper. Used by tests to drive a local fake server with
/// deterministic responses.
pub(crate) fn do_unstrip_libc_with(
    libc: &Path,
    ver: &LibcVersion,
    base_url: &str,
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
) -> Result {
    println!("{}", "unstripping libc".yellow().bold());

    let deb_file_name = debug_deb_file_name(ver);

    let tmp_dir = TempDir::new().context(TmpDirSnafu)?;

    let sym_path = tmp_dir.path().join("libc-syms");

    let versioned_name = format!("libc-{}.so", ver.string_short);
    let build_id_name = {
        let build_id = elf::get_build_id(libc).context(ElfParseSnafu)?;
        build_id.chars().skip(2).collect::<String>() + ".debug"
    };
    let names = [versioned_name.as_str(), build_id_name.as_str()];

    libc_deb::write_ubuntu_pkg_file_with(
        &deb_file_name,
        names.as_slice(),
        &sym_path,
        base_url,
        policy,
        sleeper,
    )
    .context(DebSnafu)?;

    let out = Command::new("eu-unstrip")
        .arg(libc)
        .arg(&sym_path)
        .output()
        .context(CmdRunSnafu)?;
    let _ = stderr().write_all(&out.stderr);
    let _ = stdout().write_all(&out.stdout);
    if !out.status.success() {
        return Err(Error::CmdFail { status: out.status });
    }

    let mut sym_file = File::open(sym_path).context(SymOpenSnafu)?;
    let mut libc_file = File::create(libc).context(LibcOpenSnafu)?;
    copy(&mut sym_file, &mut libc_file).context(LibcWriteSnafu)?;

    Ok(())
}

/// Download debug symbols and apply them to a libc if it doesn't have them
/// already
pub fn unstrip_libc(libc: &Path, ver: &LibcVersion) -> Result {
    if !elf::has_debug_syms(libc).context(ElfParseSnafu)? {
        do_unstrip_libc(libc, ver)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use flate2::write::GzEncoder;
    use flate2::Compression;

    use crate::cpu_arch::CpuArch;

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

    fn fast_policy() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
        }
    }

    /// Build a tiny in-memory Ubuntu `.deb` whose `data.tar.gz` contains a
    /// single file at `content_path` with the given bytes.
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

    struct ScriptedServer {
        base_url: String,
        recorded: Arc<Mutex<Vec<String>>>,
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
            let recorded = Arc::new(Mutex::new(Vec::<String>::new()));
            let recorded_clone = recorded.clone();
            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_clone = shutdown.clone();

            let join_handle = thread::spawn(move || loop {
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
                        let response = queue_clone.lock().expect("lock").pop_front();
                        let (status, body) = match response {
                            Some(ScriptedResponse::Status { status, body }) => (status, body),
                            Some(ScriptedResponse::Body(body)) => (200, body),
                            None => (500, Vec::new()),
                        };
                        let reason = match status {
                            200 => "OK",
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
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            });

            Self {
                base_url,
                recorded,
                shutdown,
                join_handle: Some(join_handle),
            }
        }

        fn recorded(&self) -> Vec<String> {
            self.recorded.lock().expect("lock").clone()
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

    /// The debug-symbol consumer must build the `libc6-dbg_{ver}.deb`
    /// package name (not the regular libc6 deb) and route the download
    /// through the shared retry layer. We verify the URL is correct and
    /// that a transient 503 is retried.
    #[test]
    fn debug_symbol_consumer_targets_libc6_dbg_deb_and_retries() {
        // The deb contains the versioned libc-2.31.so file, which is the
        // first candidate name in the debug-symbol consumer.
        let deb = make_tiny_deb_gz("libc-2.31.so", b"some debug bytes");
        let server = ScriptedServer::with(vec![
            ScriptedResponse::status(503, b""),
            ScriptedResponse::Body(deb),
        ]);

        let mut sleeper = RecordingSleeper::default();
        let ver = LibcVersion {
            string: "2.31-0ubuntu9.16".to_string(),
            string_short: "2.31".to_string(),
            arch: CpuArch::Amd64,
        };

        // The full `do_unstrip_libc_with` requires a real ELF with a
        // build_id before it reaches the deb download step. To isolate
        // the deb fetch retry behavior, exercise the same
        // `libc_deb::write_ubuntu_pkg_file_with` call with the deb
        // filename and candidate names that `do_unstrip_libc_with`
        // constructs. This proves the debug-symbol surface targets the
        // right deb and applies retry.
        let deb_file_name = debug_deb_file_name(&ver);
        let versioned_name = format!("libc-{}.so", ver.string_short);
        let names = [versioned_name.as_str()];

        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let sym_path = tmp.path().join("libc-syms");

        crate::libc_deb::write_ubuntu_pkg_file_with(
            &deb_file_name,
            &names,
            &sym_path,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("debug-symbol deb fetch should succeed after retry");

        let requests = server.recorded();
        assert_eq!(requests.len(), 2, "expected one retry then success");
        // Both requests should target the libc6-dbg deb URL.
        for req in &requests {
            assert!(
                req.contains("libc6-dbg_2.31-0ubuntu9.16_amd64.deb"),
                "expected libc6-dbg deb URL, got {}",
                req
            );
        }
        assert_eq!(sleeper.sleeps.len(), 1, "expected one backoff");
    }
}
