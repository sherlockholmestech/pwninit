use crate::opts::{PwnOpts, RevOpts};
use crate::patch_bin;
use crate::set_exec;

use std::path::Path;
use std::string;

use colored::Colorize;
use ex::fs;
use ex::io;
use maplit::hashmap;
use snafu::ResultExt;
use snafu::Snafu;
use strfmt::strfmt;

#[derive(Debug, Snafu)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("solve script template is not valid UTF-8: {}", source))]
    Utf8 { source: string::FromUtf8Error },

    #[snafu(display("error writing solve script template: {}", source))]
    Write { source: io::Error },

    #[snafu(display("error reading solve script template: {}", source))]
    Read { source: io::Error },

    #[snafu(display("error filling in solve script template: {}", source))]
    Fmt { source: strfmt::FmtError },

    #[snafu(display("error setting solve script template executable: {}", source))]
    SetExec { source: io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

fn read_template(path: Option<&Path>, default_template: &str) -> Result<String> {
    match path {
        Some(path) => {
            let data = fs::read(path).context(ReadSnafu)?;
            String::from_utf8(data).context(Utf8Snafu)
        }
        None => Ok(default_template.to_string()),
    }
}

fn write_stub_file(stub: String) -> Result<()> {
    let path = Path::new("solve.py");
    if !path.exists() {
        println!("{}", "writing solve.py stub".cyan().bold());
        fs::write(path, stub).context(WriteSnafu)?;
        set_exec(path).context(SetExecSnafu)?;
    }
    Ok(())
}

fn make_pwn_elf_binding(name: &str, path: Option<&Path>) -> Option<String> {
    path.map(|path| format!("{} = ELF(\"{}\")", name, path.display()))
}

fn make_rev_path_binding(name: &str, path: Option<&Path>) -> Option<String> {
    path.map(|path| format!("{} = \"{}\"", name, path.display()))
}

fn join_bindings(bindings: impl IntoIterator<Item = Option<String>>) -> String {
    bindings
        .into_iter()
        .flatten()
        .collect::<Vec<String>>()
        .join("\n")
}

/// Make pwntools script that binds the (binary, libc, linker) to `ELF`
/// variables
fn make_bindings_pwn(opts: &PwnOpts) -> String {
    let patched_bin = patch_bin::bin_patched_path(opts);
    let bin_path = patched_bin.as_deref().or(opts.bin.as_deref());

    join_bindings([
        make_pwn_elf_binding(&opts.template_bin_name, bin_path),
        make_pwn_elf_binding(&opts.template_libc_name, opts.libc.as_deref()),
        make_pwn_elf_binding(&opts.template_ld_name, opts.ld.as_deref()),
    ])
}

/// Make angr script that binds the binary path for analysis
fn make_bindings_rev(opts: &RevOpts) -> String {
    join_bindings([make_rev_path_binding(
        &opts.template_bin_name,
        opts.bin.as_deref(),
    )])
}

/// Make arguments to pwntools `process()` function
fn make_proc_args_pwn(opts: &PwnOpts) -> String {
    format!("[{}.path]", opts.template_bin_name)
}

/// Fill in template pwntools solve script with (binary, libc, linker) paths
fn make_stub_pwn(opts: &PwnOpts) -> Result<String> {
    let templ = read_template(opts.template_path.as_deref(), include_str!("template.py"))?;
    strfmt(
        &templ,
        &hashmap! {
        "bindings".to_string() => make_bindings_pwn(opts),
        "proc_args".to_string() => make_proc_args_pwn(opts),
        "bin_name".to_string() => opts.template_bin_name.clone(),
        },
    )
    .context(FmtSnafu)
}

/// Fill in template angr solve script with binary path
fn make_stub_rev(opts: &RevOpts) -> Result<String> {
    let templ = read_template(
        opts.template_path.as_deref(),
        include_str!("template_rev.py"),
    )?;
    strfmt(
        &templ,
        &hashmap! {
        "bindings".to_string() => make_bindings_rev(opts),
        "bin_name".to_string() => opts.template_bin_name.clone(),
        },
    )
    .context(FmtSnafu)
}

/// Write script produced with `make_stub_pwn()` to `solve.py` in the
/// specified directory, unless a `solve.py` already exists
pub fn write_stub_pwn(opts: &PwnOpts) -> Result<()> {
    let stub = make_stub_pwn(opts)?;
    write_stub_file(stub)
}

/// Write script produced with `make_stub_rev()` to `solve.py` in the
/// specified directory, unless a `solve.py` already exists
pub fn write_stub_rev(opts: &RevOpts) -> Result<()> {
    let stub = make_stub_rev(opts)?;
    write_stub_file(stub)
}
