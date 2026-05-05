use std::path::Path;
use std::path::PathBuf;

use ex::io;
use goblin::elf::Elf;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum Error {
    #[snafu(display("could not read {}: {}", path.display(), source))]
    Read { source: io::Error, path: PathBuf },
    #[snafu(display("could not parse {}: {}", path.display(), source))]
    Goblin {
        path: PathBuf,
        source: goblin::error::Error,
    },
    #[snafu(display("ELF {} has no .note.gnu.build-id section", path.display()))]
    NoBuildId { path: PathBuf },
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn parse<'a>(path: &Path, bytes: &'a [u8]) -> Result<Elf<'a>> {
    Elf::parse(bytes).context(GoblinSnafu { path })
}
