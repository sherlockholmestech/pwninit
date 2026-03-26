//! CPU architectures

use crate::elf;

use std::fmt;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use goblin::elf::header::EM_386;
use goblin::elf::header::EM_X86_64;
use snafu::ResultExt;
use snafu::Snafu;

/// The CPU architectures supported by `pwninit`
#[derive(Clone)]
pub enum CpuArch {
    I386,
    Amd64,
}

impl fmt::Display for CpuArch {
    /// Architecture names fitting the spec for Ubuntu repositories
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CpuArch::I386 => "i386",
            CpuArch::Amd64 => "amd64",
        })
    }
}

#[derive(Debug, Snafu)]
pub enum Error {
    ElfParse {
        source: elf::parse::Error,
    },

    #[snafu(display("{}: architecture is not x86", path.display()))]
    BadArch {
        path: PathBuf,
    },

    #[snafu(display("unknown architecture: \"{}\", expected \"amd64\" or \"i386\"", arch))]
    UnknownArch {
        arch: String,
    },
}

pub type Result = std::result::Result<CpuArch, Error>;

impl FromStr for CpuArch {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "amd64" => Ok(CpuArch::Amd64),
            "i386" => Ok(CpuArch::I386),
            _ => Err(Error::UnknownArch {
                arch: s.to_string(),
            }),
        }
    }
}

impl CpuArch {
    /// Detect `CpuArch` from the bytes of an ELF file
    pub fn from_elf_bytes(path: &Path, bytes: &[u8]) -> Result {
        let elf = elf::parse::parse(path, bytes).context(ElfParseSnafu)?;
        let arch = elf.header.e_machine;
        match arch {
            EM_386 => Ok(CpuArch::I386),
            EM_X86_64 => Ok(CpuArch::Amd64),
            _ => Err(Error::BadArch {
                path: path.to_path_buf(),
            }),
        }
    }
}
