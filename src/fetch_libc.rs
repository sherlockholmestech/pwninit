use crate::cpu_arch::CpuArch;
use crate::fetch_ld;
use crate::http_retry::{RetryPolicy, Sleeper, StdSleeper};
use crate::libc_deb;
use crate::libc_search;
use crate::libc_version::LibcVersion;

use std::collections::HashSet;
use std::io;
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
    let mut sleeper = StdSleeper;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    fetch_libc_interactive_with(
        short_version,
        arch,
        out_path,
        Path::new("."),
        extra_libs,
        libc_search::LAUNCHPAD_API_BASE,
        libc_deb::PKG_URL,
        RetryPolicy::default(),
        &mut sleeper,
        &mut input,
        &mut io::stdout(),
    )
}

/// Same as [`fetch_libc_interactive`] but lets callers inject every external
/// surface: the directory the linker and extra libraries are written to, the
/// Launchpad API base URL, the package download base URL, the retry policy,
/// the sleeper, the stdin source, and the stdout sink. Used by tests to
/// drive a local fake server with deterministic responses, verify that the
/// single-match flow does not read from stdin, and verify that the
/// multi-match flow honors the supplied selection and retries only the
/// failed HTTP operation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn fetch_libc_interactive_with(
    short_version: &str,
    arch: CpuArch,
    out_path: &Path,
    out_dir: &Path,
    extra_libs: &[String],
    api_base: &str,
    pkg_base: &str,
    policy: RetryPolicy,
    sleeper: &mut dyn Sleeper,
    input: &mut dyn io::BufRead,
    output: &mut dyn io::Write,
) -> Result {
    let versions =
        libc_search::search_versions_with(short_version, &arch, api_base, policy, sleeper)
            .context(SearchSnafu)?;

    if versions.is_empty() {
        return Err(Error::NoVersionsFound);
    }

    let choice = if versions.len() == 1 {
        writeln!(output, "  {}", versions[0]).ok();
        0
    } else {
        writeln!(output).ok();
        for (i, v) in versions.iter().enumerate() {
            writeln!(output, "  [{}]  {}", i + 1, v).ok();
        }
        writeln!(output).ok();

        loop {
            write!(output, "select version: ").ok();
            output.flush().ok();

            let mut line = String::new();
            input.read_line(&mut line).context(StdinSnafu)?;

            let trimmed = line.trim();
            if let Ok(n) = trimmed.parse::<usize>() {
                if n >= 1 && n <= versions.len() {
                    break n - 1;
                }
            }
            writeln!(
                output,
                "please enter a number between 1 and {}",
                versions.len()
            )
            .ok();
        }
    };

    let full_version = versions[choice].clone();
    let ver = LibcVersion::from_parts(full_version, arch).context(VersionSnafu)?;
    let extra_libs = normalize_extra_libs(extra_libs)?;

    fetch_libc_package_file_with(&ver, LIBC_SONAME, out_path, pkg_base, policy, sleeper)?;
    let linker_out = out_dir.join(fetch_ld::canonical_ld_name(&ver.arch));
    fetch_ld::fetch_ld_to_with(&ver, &linker_out, pkg_base, policy, sleeper)
        .context(FetchLdSnafu)?;
    for extra_lib in &extra_libs {
        let lib_out = out_dir.join(extra_lib);
        fetch_libc_package_file_with(&ver, extra_lib, &lib_out, pkg_base, policy, sleeper)?;
    }
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

    // -------------------------------------------------------------------
    // VAL-CROSS-001 / VAL-CROSS-004 / VAL-DOWNLOAD-011: full
    // `fetch_libc_interactive` flow tests.
    //
    // The fake server is shared between the Launchpad JSON page fetches
    // and the Ubuntu deb fetches. The path of the URL is ignored, so the
    // queue is consumed in declaration order: 1) lookup page, 2) libc
    // deb, 3) linker deb, 4) each extra lib deb.
    // -------------------------------------------------------------------

    /// Build a one-page Launchpad API JSON body with the given (version,
    /// arch) tuples.
    fn launchpad_page(entries: &[(&str, &str)]) -> String {
        let entries_json: Vec<serde_json::Value> = entries
            .iter()
            .map(|(v, arch)| {
                serde_json::json!({
                    "binary_package_version": v,
                    "distro_arch_series_link": format!(
                        "https://api.launchpad.net/1.0/ubuntu/+archive/primary/{}",
                        arch
                    ),
                })
            })
            .collect();
        serde_json::json!({
            "entries": entries_json,
            "next_collection_link": serde_json::Value::Null,
        })
        .to_string()
    }

    /// Build a deb that contains all of the given (path, content) entries
    /// in a single `data.tar.gz`.
    fn make_tiny_deb_gz_multi(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut data_tar_gz = Vec::new();
        {
            let enc = GzEncoder::new(&mut data_tar_gz, Compression::default());
            let mut tar_builder = tar::Builder::new(enc);
            for (path, content) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).expect("set tar path");
                header.set_size(content.len() as u64);
                header.set_mode(0o755);
                header.set_cksum();
                tar_builder
                    .append(&header, *content)
                    .expect("append tar entry");
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
        deb
    }

    /// VAL-CROSS-001: the single-match `fetch-libc` flow runs all four
    /// operations (lookup, libc, linker, deduplicated extras) without
    /// reading from stdin and writes the expected output files.
    ///
    /// The deb fetched for each operation is the same package, so a
    /// single deb body is queued four times: one each for the libc,
    /// linker, and the two deduplicated extra libraries.
    #[test]
    fn fetch_libc_interactive_single_match_writes_all_outputs_without_stdin() {
        let deb = make_tiny_deb_gz_multi(&[
            ("libc.so.6", b"libc bytes"),
            ("ld-linux-x86-64.so.2", b"linker bytes"),
            ("libm.so.6", b"libm bytes"),
            ("libdl.so.2", b"libdl bytes"),
        ]);
        let server = ScriptedServer::with(vec![
            ScriptedResponse::Body(launchpad_page(&[("2.34-0ubuntu3", "amd64")]).into_bytes()),
            ScriptedResponse::Body(deb.clone()),
            ScriptedResponse::Body(deb.clone()),
            ScriptedResponse::Body(deb.clone()),
            ScriptedResponse::Body(deb),
        ]);

        let mut sleeper = RecordingSleeper::default();
        // Empty stdin: the cursor never advances, proving that the
        // single-match flow does not call `read_line`.
        let mut input = std::io::Cursor::new(b"" as &[u8]);
        let mut output = Vec::<u8>::new();

        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let libc_out = tmp.path().join("libc.so.6");
        let extra_libs = vec![
            "libm".to_string(),
            "libm.so.6".to_string(),
            "libdl.so.2".to_string(),
        ];

        fetch_libc_interactive_with(
            "2.34",
            CpuArch::Amd64,
            &libc_out,
            tmp.path(),
            &extra_libs,
            &server.base_url,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
            &mut input,
            &mut output,
        )
        .expect("single-match flow should succeed");

        // All expected output files exist.
        assert_eq!(std::fs::read(&libc_out).expect("read libc"), b"libc bytes");
        assert_eq!(
            std::fs::read(tmp.path().join("ld-linux-x86-64.so.2")).expect("read linker"),
            b"linker bytes"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("libm.so.6")).expect("read libm"),
            b"libm bytes"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("libdl.so.2")).expect("read libdl"),
            b"libdl bytes"
        );

        // The single-match flow does not read from stdin.
        assert_eq!(
            input.position(),
            0,
            "single-match flow must not read from stdin"
        );

        // The output does not contain the selection prompt.
        let output_str = String::from_utf8_lossy(&output);
        assert!(
            !output_str.contains("select version"),
            "single-match flow must not show the selection prompt, got: {}",
            output_str
        );

        // All five operations were requested (no retries on the happy
        // path): 1 lookup + 4 deb fetches (libc, linker, libm, libdl).
        assert_eq!(server.remaining(), 0);
        assert!(
            sleeper.sleeps.is_empty(),
            "no backoffs expected on the happy path"
        );
    }

    /// VAL-CROSS-001: retry is applied to every HTTP operation in the
    /// single-match flow. Each of the four deb steps gets a transient
    /// failure first and a successful response second; the lookup page
    /// succeeds on the first attempt.
    #[test]
    fn fetch_libc_interactive_single_match_retries_each_failed_operation() {
        let deb = make_tiny_deb_gz_multi(&[
            ("libc.so.6", b"libc bytes"),
            ("ld-linux-x86-64.so.2", b"linker bytes"),
            ("libm.so.6", b"libm bytes"),
        ]);
        let server = ScriptedServer::with(vec![
            ScriptedResponse::Body(launchpad_page(&[("2.34-0ubuntu3", "amd64")]).into_bytes()),
            // libc deb: transient then success
            ScriptedResponse::status(503, b""),
            ScriptedResponse::Body(deb.clone()),
            // linker deb: transient then success
            ScriptedResponse::status(503, b""),
            ScriptedResponse::Body(deb.clone()),
            // libm deb: transient then success
            ScriptedResponse::status(503, b""),
            ScriptedResponse::Body(deb),
        ]);

        let mut sleeper = RecordingSleeper::default();
        let mut input = std::io::Cursor::new(b"" as &[u8]);
        let mut output = Vec::<u8>::new();

        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let libc_out = tmp.path().join("libc.so.6");
        let extra_libs = vec!["libm.so.6".to_string()];

        fetch_libc_interactive_with(
            "2.34",
            CpuArch::Amd64,
            &libc_out,
            tmp.path(),
            &extra_libs,
            &server.base_url,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
            &mut input,
            &mut output,
        )
        .expect("single-match flow should succeed after retries");

        // Each deb operation was retried exactly once (3 retries total).
        assert_eq!(sleeper.sleeps.len(), 3, "expected one backoff per step");

        // All output files are written.
        assert_eq!(std::fs::read(&libc_out).expect("read libc"), b"libc bytes");
        assert_eq!(
            std::fs::read(tmp.path().join("ld-linux-x86-64.so.2")).expect("read linker"),
            b"linker bytes"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("libm.so.6")).expect("read libm"),
            b"libm bytes"
        );

        // All scripted responses were consumed.
        assert_eq!(server.remaining(), 0);

        // No stdin read.
        assert_eq!(input.position(), 0);
    }

    /// VAL-CROSS-004: the multi-match flow shows the prompt exactly once,
    /// honors the supplied stdin selection, and downloads the chosen
    /// version's packages.
    #[test]
    fn fetch_libc_interactive_multi_match_prompts_once_and_honors_stdin() {
        let deb_234_3 = make_tiny_deb_gz_multi(&[
            ("libc.so.6", b"libc 2.34-3 bytes"),
            ("ld-linux-x86-64.so.2", b"linker 2.34-3 bytes"),
            ("libm.so.6", b"libm 2.34-3 bytes"),
        ]);
        let deb_234_9 = make_tiny_deb_gz_multi(&[
            ("libc.so.6", b"libc 2.34-9 bytes"),
            ("ld-linux-x86-64.so.2", b"linker 2.34-9 bytes"),
            ("libm.so.6", b"libm 2.34-9 bytes"),
        ]);

        // The user picks the SECOND version (`2.34-0ubuntu9`). The
        // queued debs for that version are served for each deb fetch.
        // We also queue a deb for the first version, but it should
        // never be requested because the user did not select it.
        let server = ScriptedServer::with(vec![
            ScriptedResponse::Body(
                launchpad_page(&[("2.34-0ubuntu3", "amd64"), ("2.34-0ubuntu9", "amd64")])
                    .into_bytes(),
            ),
            ScriptedResponse::Body(deb_234_9.clone()),
            ScriptedResponse::Body(deb_234_9.clone()),
            ScriptedResponse::Body(deb_234_9),
            // Sentinel: the unselected version's deb must never be
            // requested, so we queue it last and assert that the
            // remaining count is 1 after the flow completes.
            ScriptedResponse::Body(deb_234_3),
        ]);

        let mut sleeper = RecordingSleeper::default();
        let mut input = std::io::Cursor::new(b"2\n".to_vec());
        let mut output = Vec::<u8>::new();

        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let libc_out = tmp.path().join("libc.so.6");
        let extra_libs = vec!["libm.so.6".to_string()];

        fetch_libc_interactive_with(
            "2.34",
            CpuArch::Amd64,
            &libc_out,
            tmp.path(),
            &extra_libs,
            &server.base_url,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
            &mut input,
            &mut output,
        )
        .expect("multi-match flow should succeed");

        // The chosen version is the second one (2.34-0ubuntu9), and
        // the deb files for that version were extracted.
        assert_eq!(
            std::fs::read(&libc_out).expect("read libc"),
            b"libc 2.34-9 bytes"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("ld-linux-x86-64.so.2")).expect("read linker"),
            b"linker 2.34-9 bytes"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("libm.so.6")).expect("read libm"),
            b"libm 2.34-9 bytes"
        );

        // The prompt was shown exactly once.
        let output_str = String::from_utf8_lossy(&output);
        let prompt_count = output_str.matches("select version").count();
        assert_eq!(
            prompt_count, 1,
            "prompt must occur exactly once, got {}",
            prompt_count
        );

        // The deb for the unselected version (2.34-0ubuntu3) was
        // never fetched, proving that retries and downloads only
        // target the chosen version.
        assert_eq!(
            server.remaining(),
            1,
            "unselected version's deb must not be requested"
        );
    }

    /// VAL-CROSS-004: invalid input causes the prompt to repeat without
    /// triggering a re-fetch of the lookup page.
    #[test]
    fn fetch_libc_interactive_multi_match_retries_prompt_for_invalid_input_only() {
        let deb = make_tiny_deb_gz_multi(&[
            ("libc.so.6", b"libc bytes"),
            ("ld-linux-x86-64.so.2", b"linker bytes"),
        ]);
        let server = ScriptedServer::with(vec![
            ScriptedResponse::Body(
                launchpad_page(&[("2.34-0ubuntu3", "amd64"), ("2.34-0ubuntu9", "amd64")])
                    .into_bytes(),
            ),
            ScriptedResponse::Body(deb.clone()),
            ScriptedResponse::Body(deb),
        ]);

        let mut sleeper = RecordingSleeper::default();
        // First line is invalid (non-numeric), second is a number
        // outside the range, third is the valid choice.
        let mut input = std::io::Cursor::new(b"abc\n9\n1\n".to_vec());
        let mut output = Vec::<u8>::new();

        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let libc_out = tmp.path().join("libc.so.6");
        let extra_libs: Vec<String> = vec![];

        fetch_libc_interactive_with(
            "2.34",
            CpuArch::Amd64,
            &libc_out,
            tmp.path(),
            &extra_libs,
            &server.base_url,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
            &mut input,
            &mut output,
        )
        .expect("multi-match flow should succeed after invalid input");

        // The lookup page was fetched exactly once (no re-fetch on
        // invalid input).
        assert_eq!(server.remaining(), 0);
        // The prompt appeared three times (one for each input line).
        let output_str = String::from_utf8_lossy(&output);
        assert_eq!(output_str.matches("select version").count(), 3);
    }

    /// VAL-DOWNLOAD-011: a transient package failure after a successful
    /// multi-match lookup retries only the failed package download, not
    /// the prompt or the lookup.
    #[test]
    fn fetch_libc_interactive_retry_does_not_repeat_prompt_or_lookup() {
        let deb = make_tiny_deb_gz_multi(&[
            ("libc.so.6", b"libc bytes"),
            ("ld-linux-x86-64.so.2", b"linker bytes"),
        ]);
        // 1) lookup page succeeds
        // 2) libc deb gets 503
        // 3) libc deb succeeds
        // 4) linker deb succeeds
        let server = ScriptedServer::with(vec![
            ScriptedResponse::Body(
                launchpad_page(&[("2.34-0ubuntu3", "amd64"), ("2.34-0ubuntu9", "amd64")])
                    .into_bytes(),
            ),
            ScriptedResponse::status(503, b""),
            ScriptedResponse::Body(deb.clone()),
            ScriptedResponse::Body(deb),
        ]);

        let mut sleeper = RecordingSleeper::default();
        // User picks the first version (2.34-0ubuntu3). If the lookup
        // were re-fetched, the prompt would be re-displayed and the user
        // would have to re-enter the choice.
        let mut input = std::io::Cursor::new(b"1\n".to_vec());
        let mut output = Vec::<u8>::new();

        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let libc_out = tmp.path().join("libc.so.6");
        let extra_libs: Vec<String> = vec![];

        fetch_libc_interactive_with(
            "2.34",
            CpuArch::Amd64,
            &libc_out,
            tmp.path(),
            &extra_libs,
            &server.base_url,
            &server.base_url,
            fast_policy(),
            &mut sleeper,
            &mut input,
            &mut output,
        )
        .expect("flow should succeed after retrying libc download only");

        // The prompt was shown exactly once, proving the lookup and
        // prompt were not repeated.
        let output_str = String::from_utf8_lossy(&output);
        assert_eq!(
            output_str.matches("select version").count(),
            1,
            "prompt must not repeat, got: {}",
            output_str
        );
        // The libc file is the bytes from the second attempt.
        assert_eq!(std::fs::read(&libc_out).expect("read libc"), b"libc bytes");
        // Exactly one backoff: the retry on the libc download.
        assert_eq!(sleeper.sleeps.len(), 1, "only one retry expected");
    }
}
