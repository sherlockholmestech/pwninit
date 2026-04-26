use crate::cpu_arch::CpuArch;
use crate::libc_deb;
use crate::libc_version::LibcVersion;

use colored::Colorize;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("libc deb error: {}", source))]
    Deb { source: libc_deb::Error },
}

pub type Result = std::result::Result<(), Error>;

fn ld_name_in_deb(ver: &LibcVersion) -> String {
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

fn fetch_ld_to(ver: &LibcVersion, out_name: impl AsRef<std::path::Path>) -> Result {
    let deb_file_name = format!("libc6_{}.deb", ver);
    let ld_name = ld_name_in_deb(ver);
    libc_deb::write_ubuntu_pkg_file(&deb_file_name, &[&ld_name], out_name).context(DebSnafu)
}

/// Download linker compatible with libc version `ver`, saved as `ld-{short}.so`
pub fn fetch_ld(ver: &LibcVersion) -> Result {
    println!("{}", "fetching linker".green().bold());
    fetch_ld_to(ver, format!("ld-{}.so", ver.string_short))
}

/// Download the linker for `ver` and save it under the canonical runtime name
/// (`ld-linux-x86-64.so.2` or `ld-linux.so.2`).
pub fn fetch_ld_canonical(ver: &LibcVersion) -> Result {
    println!("{}", "fetching linker".green().bold());
    fetch_ld_to(ver, canonical_ld_name(&ver.arch))
}
