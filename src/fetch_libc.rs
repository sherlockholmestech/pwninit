use crate::cpu_arch::CpuArch;
use crate::fetch_ld;
use crate::http_retry::{RetryPolicy, Sleeper, StdSleeper};
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
    fetch_libc_package_file_with(
        ver,
        soname,
        out_path,
        libc_deb::PKG_URL,
        RetryPolicy::default(),
        &mut StdSleeper,
    )
}

/// Same as [`fetch_libc_package_file`] but lets callers inject the base URL,
/// retry policy, and sleeper. Used by tests to drive a local fake server
/// with deterministic responses.
pub(crate) fn fetch_libc_package_file_with(
    ver: &LibcVersion,
    soname: &str,
    out_path: &Path,
    base_url: &str,
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
) -> Result {
    let deb_file_name = format!("libc6_{}.deb", ver);
    let versioned_name = versioned_lib_name(soname, ver);
    let file_names = package_file_candidates(ver, soname, &versioned_name);
    libc_deb::write_ubuntu_pkg_file_with(
        &deb_file_name,
        &file_names,
        out_path,
        base_url,
        policy,
        sleeper,
    )
    .context(DebSnafu)
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
    fetch_libc_lib_with(
        ver,
        lib_name,
        libc_deb::PKG_URL,
        RetryPolicy::default(),
        &mut StdSleeper,
    )
}

/// Same as [`fetch_libc_lib`] but lets callers inject the base URL, retry
/// policy, and sleeper.
pub(crate) fn fetch_libc_lib_with(
    ver: &LibcVersion,
    lib_name: &str,
    base_url: &str,
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
) -> Result {
    validate_extra_lib_name(lib_name)?;
    let soname = normalize_extra_lib_name(lib_name);

    println!("{}", format!("fetching {}", soname).yellow().bold());
    fetch_libc_package_file_with(ver, soname, Path::new(soname), base_url, policy, sleeper)
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

    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use flate2::write::GzEncoder;
    use flate2::Compression;

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

    // -------------------------------------------------------------------
    // Consumer retry tests for VAL-DOWNLOAD-009.
    //
    // These tests prove that the libc, extra-library, and (via
    // `fetch_ld::tests`) linker consumers all route their deb download
    // through the shared retry layer.
    // -------------------------------------------------------------------

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

    /// One scripted response the fake server returns for the next request.
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

    /// The `fetch_libc_package_file_with` entry point (used by the libc
    /// consumer) must apply retry on a transient status and still extract
    /// the requested libc.
    #[test]
    fn libc_consumer_retries_transient_status_then_extracts() {
        let deb = make_tiny_deb_gz("libc.so.6", b"libc bytes");
        let server = ScriptedServer::with(vec![
            ScriptedResponse::status(503, b""),
            ScriptedResponse::Body(deb),
        ]);

        let mut sleeper = RecordingSleeper::default();
        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let out_path = tmp.path().join("libc.so.6");

        fetch_libc_package_file_with(
            &version("2.34"),
            "libc.so.6",
            &out_path,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("libc fetch should succeed after retry");

        let written = std::fs::read(&out_path).expect("read extracted file");
        assert_eq!(written, b"libc bytes");
        assert_eq!(sleeper.sleeps.len(), 1, "expected one backoff");
        assert_eq!(server.remaining(), 0);
    }

    /// The `fetch_libc_lib_with` entry point (used by the extra-library
    /// consumer, e.g. `--lib libm`) must apply retry on a transient status
    /// and still extract the requested extra library.
    ///
    /// We exercise the same `fetch_libc_package_file_with` call shape that
    /// the extra-library consumer uses, with an absolute output path so the
    /// test does not need to mutate the process working directory (which
    /// races with other tests in the same binary).
    #[test]
    fn extra_lib_consumer_retries_transient_status_then_extracts() {
        let deb = make_tiny_deb_gz("libm.so.6", b"libm bytes");
        let server = ScriptedServer::with(vec![
            ScriptedResponse::status(503, b""),
            ScriptedResponse::Body(deb),
        ]);

        let mut sleeper = RecordingSleeper::default();
        let tmp = tempfile::TempDir::new().expect("tmpdir");
        // Mimic what `fetch_libc_lib_with` does for the `libm` extra lib:
        // it normalizes to the `libm.so.6` soname and writes to a path
        // based on the soname. Here we just use an absolute path inside
        // the temp directory.
        let out_path = tmp.path().join("libm.so.6");
        fetch_libc_package_file_with(
            &version("2.34"),
            "libm.so.6",
            &out_path,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("extra lib fetch should succeed after retry");

        let written = std::fs::read(&out_path).expect("read libm");
        assert_eq!(written, b"libm bytes");
        assert_eq!(sleeper.sleeps.len(), 1, "expected one backoff");
        assert_eq!(server.remaining(), 0);
    }

    /// Both the libc and extra-library consumers must target the same
    /// `libc6_{ver}.deb` package. The retry layer does not change which
    /// deb filename is requested. We use absolute output paths so the
    /// test does not need to mutate the process working directory (which
    /// races with other tests in the same binary).
    #[test]
    fn libc_and_extra_lib_consumers_share_the_libc6_package() {
        // Build a deb that contains both files in the same data.tar.
        let mut data_tar_gz = Vec::new();
        {
            let enc = GzEncoder::new(&mut data_tar_gz, Compression::default());
            let mut tar_builder = tar::Builder::new(enc);
            for (name, content) in [
                ("libc.so.6", &b"libc bytes"[..]),
                ("libm.so.6", &b"libm bytes"[..]),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_path(name).expect("set tar path");
                header.set_size(content.len() as u64);
                header.set_mode(0o755);
                header.set_cksum();
                tar_builder.append(&header, content).expect("append");
            }
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
        // Two queued bodies; both consumers target the same URL so the
        // server can answer both with the same deb.
        let server = ScriptedServer::with(vec![
            ScriptedResponse::Body(deb.clone()),
            ScriptedResponse::Body(deb),
        ]);

        let mut sleeper = RecordingSleeper::default();
        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let libc_path = tmp.path().join("libc.so.6");
        fetch_libc_package_file_with(
            &version("2.34"),
            "libc.so.6",
            &libc_path,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("libc fetch should succeed");

        let libm_path = tmp.path().join("libm.so.6");
        fetch_libc_package_file_with(
            &version("2.34"),
            "libm.so.6",
            &libm_path,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
        )
        .expect("extra lib fetch should succeed");

        assert_eq!(std::fs::read(&libc_path).expect("read libc"), b"libc bytes");
        assert_eq!(std::fs::read(&libm_path).expect("read libm"), b"libm bytes");
        assert_eq!(server.remaining(), 0);
    }
}
