use crate::elf;

use std::path::Path;

use ex::fs;
use snafu::OptionExt;
use snafu::ResultExt;

/// Get the build id of the given elf file
pub fn get_build_id(path: &Path) -> elf::parse::Result<String> {
    let bytes = fs::read(path).context(elf::parse::ReadSnafu {
        path: path.to_path_buf(),
    })?;
    let elf = elf::parse(path, &bytes)?;

    let build_id_note = elf
        .iter_note_sections(&bytes, Some(".note.gnu.build-id"))
        .and_then(|mut iter| iter.next())
        .context(elf::parse::NoBuildIdSnafu {
            path: path.to_path_buf(),
        })?;

    let section = build_id_note.context(elf::parse::GoblinSnafu { path })?;
    Ok(hex::encode(section.desc))
}
