use crate::opts::{PatchMode, PwnOpts};
use crate::warn::Warn;

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use colored::Colorize;
use goblin::elf::dynamic::DT_NEEDED;
use goblin::elf::program_header::PT_INTERP;
use goblin::elf::program_header::PT_LOAD;
use goblin::elf::section_header::SHT_STRTAB;
use goblin::elf::Elf;
use snafu::OptionExt;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("patchelf failed with nonzero exit status"))]
    Patchelf,

    #[snafu(display("patchelf failed to start; please install patchelf: {}", source))]
    PatchelfExec { source: io::Error },

    #[snafu(display("failed copying file to patch: {}", source))]
    CopyPatched { source: io::Error },

    #[snafu(display("failed reading binary {}: {}", path.display(), source))]
    ReadBin { path: PathBuf, source: io::Error },

    #[snafu(display("failed parsing ELF {}: {}", path.display(), source))]
    ParseElf {
        path: PathBuf,
        source: goblin::error::Error,
    },

    #[snafu(display("invalid ELF string offset {} in {}", offset, path.display()))]
    InvalidOffset { path: PathBuf, offset: usize },

    #[snafu(display("failed writing patched binary {}: {}", path.display(), source))]
    WritePatched { path: PathBuf, source: io::Error },

    #[snafu(display("path has no file name: {}", path.display()))]
    FileName { path: PathBuf },

    #[snafu(display("failed scanning current directory for libraries: {}", source))]
    ScanLibs { source: io::Error },

    #[snafu(display("cannot locate .dynstr file offset in {}", path.display()))]
    DynstrOffset { path: PathBuf },

    #[snafu(display("failed symlinking {} -> {}: {}", link.display(), target.display(), source))]
    Symlink {
        link: PathBuf,
        target: PathBuf,
        source: io::Error,
    },

    #[snafu(display("failed removing existing symlink {}: {}", link.display(), source))]
    RemoveLink { link: PathBuf, source: io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

const LIBC_FILE_NAME: &str = "libc.so.6";

#[derive(Debug)]
struct PatchTarget {
    offset: usize,
    slot_len: usize,
    original: String,
    replacement: String,
}

/// Run `patchelf` on the binary `bin`.
///
/// Sets RPATH to "." and interpreter to "./ld" so the result matches manual
/// mode — both rely on the short-named symlinks created alongside the patch.
///
/// Run `patchelf` once per option to avoid broken offsets/symbols (#297)
fn patch_with_patchelf(bin: &Path, opts: &PwnOpts) -> Result<()> {
    println!(
        "{}",
        format!("running patchelf on {}", bin.to_string_lossy().bold()).green()
    );

    if opts.libc.is_some() {
        run_patchelf_option(bin, "--set-rpath", &PathBuf::from("."))?;
    }
    if opts.ld.is_some() {
        run_patchelf_option(bin, "--set-interpreter", &PathBuf::from("./ld"))?;
    }

    Ok(())
}

fn cstr_slot_len(bytes: &[u8], start: usize) -> Option<usize> {
    bytes
        .get(start..)
        .and_then(|tail| tail.iter().position(|&byte| byte == 0).map(|idx| idx + 1))
}

fn logical_lib_name(name: &str) -> Option<String> {
    if name.starts_with("ld-") || name.starts_with("ld-linux") {
        return Some("ld".to_string());
    }
    // Match "libc.so.6", "libc-2.31.so", etc. but NOT "libcrypto", "libcap", ...
    if name.starts_with("libc.") || name.starts_with("libc-") {
        return Some("libc".to_string());
    }
    if !name.starts_with("lib") {
        return None;
    }

    let rest = &name[3..];
    if let Some(pos) = rest.find(".so") {
        let base = &rest[..pos];
        if !base.is_empty() {
            return Some(format!("lib{}", base));
        }
    }

    if let Some(pos) = rest.find('-') {
        let base = &rest[..pos];
        if !base.is_empty() && rest[pos..].contains(".so") {
            return Some(format!("lib{}", base));
        }
    }

    None
}

fn discover_local_libs() -> io::Result<HashMap<String, PathBuf>> {
    let mut libs = HashMap::new();

    for dir_ent in fs::read_dir(".")? {
        let dir_ent = dir_ent?;
        let path = dir_ent.path();
        let file_name = match path.file_name().and_then(OsStr::to_str) {
            Some(name) => name,
            None => continue,
        };

        if let Some(logical) = logical_lib_name(file_name) {
            libs.insert(logical, path);
        }
    }

    Ok(libs)
}

/// Compute the file offset of the dynamic string table (.dynstr).
///
/// Tries section headers first (most reliable); falls back to translating the
/// `DT_STRTAB` virtual address through the PT_LOAD segments for stripped binaries.
fn dynstr_file_offset(elf: &Elf) -> Option<usize> {
    // Section-header path (present in non-stripped binaries)
    for shdr in &elf.section_headers {
        if shdr.sh_type == SHT_STRTAB && elf.shdr_strtab.get_at(shdr.sh_name) == Some(".dynstr") {
            return Some(shdr.sh_offset as usize);
        }
    }

    // PT_LOAD fallback: convert DT_STRTAB virtual address to file offset
    let vaddr = elf.dynamic.as_ref()?.info.strtab;
    for phdr in &elf.program_headers {
        if phdr.p_type == PT_LOAD {
            let seg_start = phdr.p_vaddr as usize;
            let seg_end = seg_start + phdr.p_filesz as usize;
            if vaddr >= seg_start && vaddr < seg_end {
                return Some(phdr.p_offset as usize + (vaddr - seg_start));
            }
        }
    }

    None
}

fn collect_manual_targets(
    bin_patched: &Path,
    bytes: &[u8],
    elf: &Elf,
    local_libs: &HashMap<String, PathBuf>,
) -> Result<(Vec<PatchTarget>, BTreeMap<String, PathBuf>)> {
    let mut targets = Vec::new();
    let mut symlinks = BTreeMap::new();

    if let Some(interp_hdr) = elf
        .program_headers
        .iter()
        .find(|hdr| hdr.p_type == PT_INTERP)
    {
        if let Some(ld) = local_libs.get("ld") {
            let offset = interp_hdr.p_offset as usize;
            let slot_len = interp_hdr.p_filesz as usize;
            if offset + slot_len > bytes.len() || slot_len == 0 {
                return Err(Error::InvalidOffset {
                    path: bin_patched.to_path_buf(),
                    offset,
                });
            }

            targets.push(PatchTarget {
                offset,
                slot_len,
                original: elf.interpreter.unwrap_or("<missing>").to_string(),
                replacement: "./ld".to_string(),
            });
            symlinks.insert("ld".to_string(), ld.clone());
        } else {
            "ld not found in current directory"
                .to_string()
                .warn("skipping PT_INTERP patch");
        }
    }

    if let Some(dynamic) = &elf.dynamic {
        let dynstr_base = dynstr_file_offset(elf).context(DynstrOffsetSnafu {
            path: bin_patched.to_path_buf(),
        })?;
        for dyn_entry in dynamic.dyns.iter().filter(|ent| ent.d_tag == DT_NEEDED) {
            let idx = dyn_entry.d_val as usize;
            let Some(original) = elf.dynstrtab.get_at(idx) else {
                format!("DT_NEEDED dynstr index {}", idx).warn("skipping invalid DT_NEEDED");
                continue;
            };

            let Some(logical) = logical_lib_name(original) else {
                format!("{} has unsupported library naming", original)
                    .warn("skipping DT_NEEDED patch");
                continue;
            };

            let Some(target_path) = local_libs.get(&logical) else {
                format!("{} ({}) not found locally", original, logical)
                    .warn("skipping DT_NEEDED patch");
                continue;
            };

            let Some(offset) = dynstr_base.checked_add(idx) else {
                return Err(Error::InvalidOffset {
                    path: bin_patched.to_path_buf(),
                    offset: idx,
                });
            };
            let Some(slot_len) = cstr_slot_len(bytes, offset) else {
                return Err(Error::InvalidOffset {
                    path: bin_patched.to_path_buf(),
                    offset,
                });
            };

            targets.push(PatchTarget {
                offset,
                slot_len,
                original: original.to_string(),
                replacement: format!("./{}", logical),
            });
            symlinks.insert(logical, target_path.clone());
        }
    }

    Ok((targets, symlinks))
}

fn apply_in_place_patch(bytes: &mut [u8], target: &PatchTarget) -> bool {
    let replacement = target.replacement.as_bytes();
    if replacement.len() + 1 > target.slot_len {
        format!(
            "{} -> {} ({} bytes into {}-byte slot)",
            target.original,
            target.replacement,
            replacement.len() + 1,
            target.slot_len
        )
        .warn("skipping oversized replacement");
        return false;
    }

    if target.offset + target.slot_len > bytes.len() {
        format!("offset {} is out of file bounds", target.offset).warn("skipping patch target");
        return false;
    }

    let replacement_end = target.offset + replacement.len();
    bytes[target.offset..replacement_end].copy_from_slice(replacement);
    bytes[replacement_end] = 0;
    true
}

/// Create a symlink at `link` pointing to `target`.
///
/// - If `link` is already a symlink to `target`: no-op.
/// - If `link` is a symlink to something else: replace it.
/// - If `link` exists but is not a symlink (regular file/dir): warn and skip.
/// - If `link` does not exist: create it.
fn make_symlink(link: &Path, target: &Path) -> Result<()> {
    match fs::symlink_metadata(link) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                if fs::read_link(link).ok().as_deref() == Some(target) {
                    return Ok(());
                }
                fs::remove_file(link).context(RemoveLinkSnafu {
                    link: link.to_path_buf(),
                })?;
            } else {
                format!("{} already exists", link.display()).warn("skipping symlink overwrite");
                return Ok(());
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(Error::Symlink {
                link: link.to_path_buf(),
                target: target.to_path_buf(),
                source,
            })
        }
    }

    println!(
        "{}",
        format!(
            "symlinking {} -> {}",
            link.to_string_lossy().bold(),
            target.to_string_lossy().bold()
        )
        .green()
    );
    std::os::unix::fs::symlink(target, link).context(SymlinkSnafu {
        link: link.to_path_buf(),
        target: target.to_path_buf(),
    })
}

fn ensure_symlink(logical_name: &str, target_path: &Path) -> Result<()> {
    make_symlink(Path::new(logical_name), target_path)
}

fn patch_manually(bin_patched: &Path, opts: &PwnOpts) -> Result<()> {
    println!(
        "{}",
        format!("patching {} manually", bin_patched.to_string_lossy().bold()).green()
    );

    let mut bytes = fs::read(bin_patched).context(ReadBinSnafu {
        path: bin_patched.to_path_buf(),
    })?;

    let mut local_libs = discover_local_libs().context(ScanLibsSnafu)?;
    if let Some(ld) = &opts.ld {
        local_libs.insert("ld".to_string(), ld.clone());
    }
    if let Some(libc) = &opts.libc {
        local_libs.insert("libc".to_string(), libc.clone());
    }

    let (targets, symlinks) = {
        let elf = Elf::parse(&bytes).context(ParseElfSnafu {
            path: bin_patched.to_path_buf(),
        })?;
        collect_manual_targets(bin_patched, &bytes, &elf, &local_libs)?
    };

    for target in &targets {
        if apply_in_place_patch(&mut bytes, target) {
            println!(
                "{}",
                format!(
                    "patched {} -> {}",
                    target.original.bold(),
                    target.replacement.bold()
                )
                .green()
            );
        }
    }

    for (logical_name, target_path) in symlinks {
        ensure_symlink(&logical_name, &target_path)?;
    }

    fs::write(bin_patched, bytes).context(WritePatchedSnafu {
        path: bin_patched.to_path_buf(),
    })?;
    Ok(())
}

/// Run `patchelf` on the binary `bin` using the option `option` with the path `argument`.
fn run_patchelf_option(bin: &Path, option: &str, argument: &PathBuf) -> Result<()> {
    let mut cmd = Command::new("patchelf");
    cmd.arg(bin);
    cmd.arg(option).arg(argument);

    let status = cmd.status().context(PatchelfExecSnafu)?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Patchelf)
    }
}

/// Create a symlink `libc.so.6` pointing to `libc`'s filename.
///
/// If `libc` already has the filename `libc.so.6`, this is a no-op.
fn symlink_libc(libc: &Path) -> Result<()> {
    let libc_file_name = libc.file_name().context(FileNameSnafu { path: libc })?;
    if libc_file_name != LIBC_FILE_NAME {
        let link = libc.with_file_name(LIBC_FILE_NAME);
        make_symlink(&link, Path::new(libc_file_name))?;
    }
    Ok(())
}

/// Add "_patched" to the end of the binary file name.
///
/// This is like `bin_patched_path()`,
/// but it takes the original paths as input instead of `Opts`.
fn bin_patched_path_from_bin(bin: &Path) -> Result<PathBuf> {
    Ok(bin.with_file_name(
        [
            bin.file_name().context(FileNameSnafu { path: bin })?,
            OsStr::new("_patched"),
        ]
        .iter()
        .map(AsRef::as_ref)
        .collect::<OsString>(),
    ))
}

/// Add "_patched" to the end of the binary file name if the binary got patched.
pub fn bin_patched_path(opts: &PwnOpts) -> Option<PathBuf> {
    match opts.no_patch_bin {
        true => None,
        false => opts
            .bin
            .as_ref()
            .and_then(|bin| bin_patched_path_from_bin(bin).ok()),
    }
}

/// Copy the file `bin` to a file with "_patched" appended to the file name.
/// Return the path to the new file.
fn copy_patched(bin: &Path) -> Result<PathBuf> {
    let bin_patched = bin_patched_path_from_bin(bin)?;
    println!(
        "{}",
        format!(
            "copying {} to {}",
            bin.to_string_lossy().bold(),
            bin_patched.to_string_lossy().bold()
        )
        .green()
    );
    fs::copy(bin, &bin_patched).context(CopyPatchedSnafu)?;

    Ok(bin_patched)
}

/// If `opts` has a binary, patch its RPATH and interpreter.
///
/// Specifically, symlink "libc.so.6" to the libc,
/// copy the binary,
/// and run patchelf on the copied binary.
pub fn patch_bin(opts: &PwnOpts) -> Result<()> {
    if let Some(bin) = &opts.bin {
        let bin_patched = copy_patched(bin)?;

        match opts.resolved_patch_mode() {
            PatchMode::Patchelf => {
                if let Some(libc) = &opts.libc {
                    symlink_libc(libc)?;
                    ensure_symlink("libc", libc)?;
                }
                if let Some(ld) = &opts.ld {
                    ensure_symlink("ld", ld)?;
                }
                patch_with_patchelf(&bin_patched, opts)?;
            }
            PatchMode::Manual => {
                patch_manually(&bin_patched, opts)?;
            }
        }
    }

    Ok(())
}
