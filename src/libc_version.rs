//! Libc version operations

use crate::cpu_arch;
use crate::cpu_arch::CpuArch;

use std::fmt;
use std::path::Path;
use std::str;

use ex::fs;
use ex::io;
use snafu::OptionExt;
use snafu::ResultExt;
use snafu::Snafu;
use twoway::find_bytes;
use version_compare::Cmp;

/// Libc version information
pub struct LibcVersion {
    /// Long string representation of a libc version
    ///
    /// Example: `"2.23-0ubuntu10"`
    pub string: String,

    /// Short string representation of a libc version
    ///
    /// Example: `"2.23"`
    pub string_short: String,

    /// Architecture of libc
    pub arch: CpuArch,
}

impl fmt::Display for LibcVersion {
    /// Write libc version in format used by Ubuntu repositories
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", self.string, self.arch)
    }
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed reading file: {}", source))]
    Read { source: io::Error },

    #[snafu(display("failed finding version string"))]
    NotFound,

    #[snafu(display("invalid architecture: {}", source))]
    Arch { source: cpu_arch::Error },

    #[snafu(display("invalid UTF-8 in version string: {}", source))]
    Utf8 { source: str::Utf8Error },
}

pub type Result<T> = std::result::Result<T, Error>;

impl LibcVersion {
    /// Construct a `LibcVersion` directly from a version string and architecture
    ///
    /// `version` should be the long form, e.g. `"2.31-0ubuntu9.9"`.
    pub fn from_parts(version: String, arch: CpuArch) -> Result<Self> {
        let string_short = version
            .split('-')
            .next()
            .context(NotFoundSnafu)?
            .to_string();
        Ok(Self {
            string: version,
            string_short,
            arch,
        })
    }

    /// Returns true if this libc version is older than 2.34.
    ///
    /// Older glibc ships versioned filenames (e.g. `ld-2.31.so`, `libc-2.31.so`);
    /// glibc >= 2.34 ships only the canonical soname.
    pub fn is_pre_234(&self) -> bool {
        match version_compare::compare_to(&self.string_short, "2.34", Cmp::Lt) {
            Ok(is_pre_234) => is_pre_234,
            Err(()) => {
                eprintln!(
                    "warning: failed parsing libc version {}; assuming glibc >= 2.34",
                    self.string_short
                );
                false
            }
        }
    }

    /// Detect the version of a libc
    pub fn detect(libc: &Path) -> Result<Self> {
        let bytes = fs::read(libc).context(ReadSnafu)?;
        let string = Self::version_string_from_bytes(&bytes)?;
        let string_short = string.split('-').next().context(NotFoundSnafu)?.to_string();

        Ok(Self {
            string,
            string_short,
            arch: CpuArch::from_elf_bytes(libc, &bytes).context(ArchSnafu)?,
        })
    }

    /// Extract the long version string from the bytes of a libc
    fn version_string_from_bytes(libc: &[u8]) -> Result<String> {
        let split: [&[u8]; 3] = [
            b"GNU C Library (Ubuntu GLIBC ",
            b"GNU C Library (Ubuntu EGLIBC ",
            b"GNU C Library (Debian GLIBC ",
        ];
        let pos = split
            .iter()
            .find_map(|cut| {
                let pos = find_bytes(libc, cut);
                Some(pos? + cut.len())
            })
            .context(NotFoundSnafu)?;
        let ver_str = &libc[pos..];
        let pos = ver_str
            .iter()
            .position(|&c| c == b')')
            .context(NotFoundSnafu)?;
        let ver_str = &ver_str[..pos];
        let ver_str = std::str::from_utf8(ver_str).context(Utf8Snafu)?.to_string();
        Ok(ver_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_string_detects_debian_glibc() {
        let bytes = b"GNU C Library (Debian GLIBC 2.36-9+deb12u13) stable release";

        let version = LibcVersion::version_string_from_bytes(bytes).expect("Debian version");

        assert_eq!(version, "2.36-9+deb12u13");
    }
}
