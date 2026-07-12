use crate::cpu_arch::CpuArch;
use crate::fetch_ld;
use crate::output;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use colored::Colorize;
use ex::fs;
use ex::io;
use snafu::OptionExt;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("docker failed to start for {}: {}", action, source))]
    DockerExec {
        action: String,
        source: std::io::Error,
    },

    #[snafu(display("docker {} failed with nonzero exit status: {}", action, status))]
    DockerStatus { action: String, status: ExitStatus },

    #[snafu(display("docker {} did not produce stdout", action))]
    DockerStdout { action: String },

    #[snafu(display("docker create returned an empty container id"))]
    EmptyContainerId,

    #[snafu(display("failed reading exported image filesystem tar: {}", source))]
    Tar { source: std::io::Error },

    #[snafu(display("failed reading tar entry path: {}", source))]
    TarPath { source: std::io::Error },

    #[snafu(display("failed reading {} from exported image filesystem: {}", path.display(), source))]
    ReadEntry {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed writing extracted library {}: {}", path.display(), source))]
    Write { path: PathBuf, source: io::Error },

    #[snafu(display("failed to find {} in exported image filesystem", soname))]
    FileNotFound { soname: String },
}

pub type Result<T = ()> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
struct ExtractTarget {
    label: String,
    candidates: Vec<String>,
    outputs: Vec<ExtractOutput>,
}

#[derive(Clone, Debug)]
enum ExtractOutput {
    Fixed(PathBuf),
    MatchedFileNameIn(PathBuf),
}

#[derive(Debug)]
struct Candidate {
    score: u8,
    path: PathBuf,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LibcFamily {
    Gnu,
    Musl,
}

struct ContainerGuard {
    id: String,
}

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn docker_platform(arch: CpuArch) -> &'static str {
    match arch {
        CpuArch::Amd64 => "linux/amd64",
        CpuArch::I386 => "linux/386",
    }
}

fn musl_arch_name(arch: CpuArch) -> &'static str {
    match arch {
        CpuArch::Amd64 => "x86_64",
        CpuArch::I386 => "i386",
    }
}

fn run_docker_status(action: &str, args: &[&str]) -> Result {
    let mut command = Command::new("docker");
    command.args(args);
    if output::is_json() {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let status = command.status().context(DockerExecSnafu {
        action: action.to_string(),
    })?;

    if status.success() {
        Ok(())
    } else {
        Err(Error::DockerStatus {
            action: action.to_string(),
            status,
        })
    }
}

fn run_docker_stdout(action: &str, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("docker")
        .args(args)
        .output()
        .context(DockerExecSnafu {
            action: action.to_string(),
        })?;

    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(Error::DockerStatus {
            action: action.to_string(),
            status: out.status,
        })
    }
}

fn create_container(image: &str, platform: &str) -> Result<ContainerGuard> {
    let out = run_docker_stdout("create", &["create", "--platform", platform, image])?;
    let id = String::from_utf8_lossy(&out).trim().to_string();
    if id.is_empty() {
        return Err(Error::EmptyContainerId);
    }
    Ok(ContainerGuard { id })
}

fn export_container(container: &ContainerGuard, plan: &ExtractionPlan) -> Result {
    let mut child = Command::new("docker")
        .args(["export", &container.id])
        .stdout(Stdio::piped())
        .spawn()
        .context(DockerExecSnafu {
            action: "export".to_string(),
        })?;

    let stdout = child.stdout.take().context(DockerStdoutSnafu {
        action: "export".to_string(),
    })?;
    let extract_result = extract_from_tar(stdout, plan);
    let status = child.wait().context(DockerExecSnafu {
        action: "export".to_string(),
    })?;
    if !status.success() {
        return Err(Error::DockerStatus {
            action: "export".to_string(),
            status,
        });
    }

    extract_result
}

fn runtime_library_path(path: &Path) -> bool {
    let mut components = path.components().filter_map(|component| match component {
        Component::Normal(part) => part.to_str(),
        _ => None,
    });

    matches!(
        (components.next(), components.next()),
        (Some("lib" | "lib32" | "lib64"), _) | (Some("usr"), Some("lib" | "lib32" | "lib64"))
    )
}

fn versioned_match_score(soname: &str, file_name: &str) -> Option<u8> {
    if file_name == soname {
        return Some(0);
    }

    if soname.starts_with("ld-linux") && file_name.starts_with("ld-") && file_name.ends_with(".so")
    {
        return Some(1);
    }

    let base = soname
        .find(".so")
        .map(|idx| &soname[..idx])
        .unwrap_or(soname);
    if file_name.starts_with(&format!("{}-", base)) && file_name.ends_with(".so") {
        return Some(1);
    }

    None
}

struct ExtractionPlan {
    gnu_targets: Vec<ExtractTarget>,
    musl_targets: Vec<ExtractTarget>,
}

impl ExtractionPlan {
    fn all_targets(&self) -> impl Iterator<Item = &ExtractTarget> {
        self.gnu_targets.iter().chain(self.musl_targets.iter())
    }

    fn targets_for(&self, family: LibcFamily) -> &[ExtractTarget] {
        match family {
            LibcFamily::Gnu => &self.gnu_targets,
            LibcFamily::Musl => &self.musl_targets,
        }
    }
}

fn musl_runtime_name(file_name: &str) -> bool {
    (file_name.starts_with("ld-musl-") && file_name.ends_with(".so.1"))
        || (file_name.starts_with("libc.musl-") && file_name.ends_with(".so.1"))
}

fn detect_family(file_names: impl IntoIterator<Item = String>) -> LibcFamily {
    if file_names.into_iter().any(|name| musl_runtime_name(&name)) {
        LibcFamily::Musl
    } else {
        LibcFamily::Gnu
    }
}

fn output_paths(output: &[ExtractOutput], matched_file_name: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for out in output {
        let path = match out {
            ExtractOutput::Fixed(path) => path.clone(),
            ExtractOutput::MatchedFileNameIn(dir) => dir.join(matched_file_name),
        };
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    paths
}

fn extract_from_tar(reader: impl Read, plan: &ExtractionPlan) -> Result {
    let mut candidates: HashMap<String, Vec<Candidate>> = HashMap::new();
    let mut runtime_file_names = Vec::new();
    let mut archive = tar::Archive::new(reader);

    for entry in archive.entries().context(TarSnafu)? {
        let mut entry = entry.context(TarSnafu)?;
        let path = entry.path().context(TarPathSnafu)?.into_owned();
        if !runtime_library_path(&path) {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        runtime_file_names.push(file_name.to_string());

        let matches = plan
            .all_targets()
            .filter_map(|target| {
                target
                    .candidates
                    .iter()
                    .filter_map(|candidate| versioned_match_score(candidate, file_name))
                    .min()
                    .map(|score| (target.label.clone(), score))
            })
            .collect::<Vec<_>>();
        if matches.is_empty() {
            continue;
        }

        if !entry.header().entry_type().is_file() {
            continue;
        }

        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .context(ReadEntrySnafu { path: path.clone() })?;

        for (soname, score) in matches {
            candidates.entry(soname).or_default().push(Candidate {
                score,
                path: path.clone(),
                bytes: bytes.clone(),
            });
        }
    }

    let family = detect_family(runtime_file_names);
    for target in plan.targets_for(family) {
        let Some(found) = candidates.get_mut(&target.label) else {
            return Err(Error::FileNotFound {
                soname: target.label.clone(),
            });
        };
        found.sort_by(|a, b| a.score.cmp(&b.score).then_with(|| a.path.cmp(&b.path)));
        let matched_file_name = found[0]
            .path
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or(&target.label);
        for out_path in output_paths(&target.outputs, matched_file_name) {
            output::progress(
                format!(
                    "extracting {} from {} to {}",
                    target.label,
                    found[0].path.display(),
                    out_path.display()
                )
                .yellow()
                .bold(),
            );
            fs::write(&out_path, &found[0].bytes).context(WriteSnafu { path: out_path })?;
        }
    }

    Ok(())
}

fn fixed_target(label: &str, candidates: &[&str], out_path: impl Into<PathBuf>) -> ExtractTarget {
    ExtractTarget {
        label: label.to_string(),
        candidates: candidates.iter().map(|name| (*name).to_string()).collect(),
        outputs: vec![ExtractOutput::Fixed(out_path.into())],
    }
}

fn extraction_plan(
    arch: CpuArch,
    libc_out: &Path,
    out_dir: &Path,
    extra_libs: &[&str],
) -> ExtractionPlan {
    let gnu_ld_name = fetch_ld::canonical_ld_name(&arch);
    let musl_arch = musl_arch_name(arch);
    let musl_ld_name = format!("ld-musl-{}.so.1", musl_arch);
    let musl_libc_name = format!("libc.musl-{}.so.1", musl_arch);

    let mut gnu_targets = vec![
        fixed_target("libc.so.6", &["libc.so.6"], libc_out),
        fixed_target(gnu_ld_name, &[gnu_ld_name], out_dir.join(gnu_ld_name)),
    ];
    let mut musl_targets = vec![
        ExtractTarget {
            label: musl_ld_name.clone(),
            candidates: vec![musl_ld_name.clone()],
            outputs: vec![ExtractOutput::MatchedFileNameIn(out_dir.to_path_buf())],
        },
        ExtractTarget {
            label: musl_libc_name.clone(),
            candidates: vec![musl_libc_name.clone(), musl_ld_name.clone()],
            outputs: vec![
                ExtractOutput::Fixed(libc_out.to_path_buf()),
                ExtractOutput::Fixed(out_dir.join(&musl_libc_name)),
                ExtractOutput::MatchedFileNameIn(out_dir.to_path_buf()),
            ],
        },
    ];

    for lib in extra_libs {
        if gnu_targets.iter().all(|target| target.label != *lib) {
            gnu_targets.push(fixed_target(lib, &[*lib], out_dir.join(lib)));
        }
        if musl_targets.iter().all(|target| target.label != *lib) {
            musl_targets.push(fixed_target(lib, &[*lib], out_dir.join(lib)));
        }
    }

    ExtractionPlan {
        gnu_targets,
        musl_targets,
    }
}

pub fn extract_libc_files(
    image: &str,
    arch: CpuArch,
    libc_out: &Path,
    out_dir: &Path,
    extra_libs: &[&str],
) -> Result {
    let platform = docker_platform(arch);
    let plan = extraction_plan(arch, libc_out, out_dir, extra_libs);

    output::progress(
        format!("pulling docker image {} ({})", image, platform)
            .cyan()
            .bold(),
    );
    run_docker_status("pull", &["pull", "--platform", platform, image])?;
    let container = create_container(image, platform)?;
    export_container(&container, &plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Cursor;
    use tempfile::TempDir;

    fn tiny_fs_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut data = Vec::new();
        {
            let enc = GzEncoder::new(&mut data, Compression::default());
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
        data
    }

    #[test]
    fn extracts_runtime_libraries_from_exported_filesystem() {
        let tmp = TempDir::new().expect("tmpdir");
        let libc_out = tmp.path().join("libc.so.6");
        let plan = extraction_plan(CpuArch::Amd64, &libc_out, tmp.path(), &["libm.so.6"]);
        let tar = tiny_fs_tar(&[
            ("usr/share/doc/libc.so.6", b"wrong"),
            ("usr/lib/x86_64-linux-gnu/libc.so.6", b"libc bytes"),
            ("usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", b"ld bytes"),
            ("usr/lib/x86_64-linux-gnu/libm-2.35.so", b"libm bytes"),
        ]);

        let decoder = flate2::read::GzDecoder::new(Cursor::new(tar));
        extract_from_tar(decoder, &plan).expect("extract filesystem");

        assert_eq!(std::fs::read(libc_out).expect("read libc"), b"libc bytes");
        assert_eq!(
            std::fs::read(tmp.path().join("libm.so.6")).expect("read libm"),
            b"libm bytes"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("ld-linux-x86-64.so.2")).expect("read ld"),
            b"ld bytes"
        );
    }

    #[test]
    fn extracts_musl_runtime_from_exported_filesystem() {
        let tmp = TempDir::new().expect("tmpdir");
        let libc_out = tmp.path().join("libc.so.6");
        let plan = extraction_plan(CpuArch::Amd64, &libc_out, tmp.path(), &[]);
        let tar = tiny_fs_tar(&[("lib/ld-musl-x86_64.so.1", b"musl bytes")]);

        let decoder = flate2::read::GzDecoder::new(Cursor::new(tar));
        extract_from_tar(decoder, &plan).expect("extract musl filesystem");

        assert_eq!(std::fs::read(libc_out).expect("read libc"), b"musl bytes");
        assert_eq!(
            std::fs::read(tmp.path().join("ld-musl-x86_64.so.1")).expect("read musl ld"),
            b"musl bytes"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("libc.musl-x86_64.so.1")).expect("read musl libc soname"),
            b"musl bytes"
        );
    }

    #[test]
    fn reports_missing_requested_library() {
        let tmp = TempDir::new().expect("tmpdir");
        let plan = extraction_plan(
            CpuArch::Amd64,
            &tmp.path().join("libc.so.6"),
            tmp.path(),
            &[],
        );
        let tar = tiny_fs_tar(&[("usr/lib/x86_64-linux-gnu/libm.so.6", b"libm")]);
        let decoder = flate2::read::GzDecoder::new(Cursor::new(tar));
        let err = extract_from_tar(decoder, &plan).expect_err("missing libc should fail");

        match err {
            Error::FileNotFound { soname } => assert_eq!(soname, "libc.so.6"),
            other => panic!("expected FileNotFound, got {:?}", other),
        }
    }
}
