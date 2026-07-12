use crate::opts::{PwnOpts, RevOpts};
use crate::output;
use crate::patch_bin;
use crate::set_exec;

use std::collections::HashMap;
use std::io::ErrorKind;
use std::io::Write;
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
pub enum Error {
    #[snafu(display("solve script template is not valid UTF-8: {}", source))]
    Utf8 { source: string::FromUtf8Error },

    #[snafu(display("error writing solve script template: {}", source))]
    Write { source: io::Error },

    #[snafu(display("error writing solve script template: {}", source))]
    WriteStd { source: std::io::Error },

    #[snafu(display("error reading solve script template: {}", source))]
    Read { source: io::Error },

    #[snafu(display("error filling in solve script template: {}", source))]
    Fmt { source: strfmt::FmtError },

    #[snafu(display("error setting solve script template executable: {}", source))]
    SetExec { source: io::Error },

    #[snafu(display("error creating solve script directory: {}", source))]
    CreateDir { source: io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) trait StubOptions {
    fn default_template() -> &'static str;
    fn make_bindings(&self) -> String;
    fn extra_vars(&self) -> HashMap<String, String> {
        HashMap::new()
    }
    fn bin_name(&self) -> &str;
    fn template_path(&self) -> Option<&Path>;
    fn solve_path(&self) -> &Path;
    fn force(&self) -> bool;
}

fn read_template(path: Option<&Path>, default_template: &str) -> Result<String> {
    match path {
        Some(path) => {
            let data = fs::read(path).context(ReadSnafu)?;
            String::from_utf8(data).context(Utf8Snafu)
        }
        None => Ok(default_template.to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteStubOutcome {
    Written,
    Overwritten,
    SkippedExisting,
}

fn write_stub_file(path: &Path, stub: String, force: bool) -> Result<WriteStubOutcome> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).context(CreateDirSnafu)?;
    }

    let outcome = if force {
        let outcome = if path.exists() {
            WriteStubOutcome::Overwritten
        } else {
            WriteStubOutcome::Written
        };
        fs::write(path, stub).context(WriteSnafu)?;
        outcome
    } else {
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => file,
            Err(source) if source.kind() == ErrorKind::AlreadyExists => {
                output::progress(
                    format!("leaving existing solve script {}", path.display())
                        .cyan()
                        .bold(),
                );
                return Ok(WriteStubOutcome::SkippedExisting);
            }
            Err(source) => return Err(Error::WriteStd { source }),
        };
        file.write_all(stub.as_bytes()).context(WriteStdSnafu)?;
        WriteStubOutcome::Written
    };
    output::progress(
        format!("writing solve script {}", path.display())
            .cyan()
            .bold(),
    );
    set_exec(path).context(SetExecSnafu)?;
    Ok(outcome)
}

fn make_pwn_elf_binding(name: &str, path: Option<&Path>) -> Option<String> {
    path.map(|path| format!("{} = ELF({:?})", name, path.to_string_lossy()))
}

fn make_rev_path_binding(name: &str, path: Option<&Path>) -> Option<String> {
    path.map(|path| format!("{} = {:?}", name, path.to_string_lossy()))
}

fn join_bindings(bindings: impl IntoIterator<Item = Option<String>>) -> String {
    bindings
        .into_iter()
        .flatten()
        .collect::<Vec<String>>()
        .join("\n")
}

fn make_bindings_pwn(opts: &PwnOpts) -> String {
    let patched_bin = patch_bin::bin_patched_path(opts);
    let bin_path = patched_bin.as_deref().or(opts.bin.as_deref());

    let patch_active = opts.resolved_patch_mode().is_some();
    let libc_path: Option<&Path> = if patch_active && opts.libc.is_some() {
        Some(Path::new("libc"))
    } else {
        opts.libc.as_deref()
    };
    let ld_path: Option<&Path> = if patch_active && opts.ld.is_some() {
        Some(Path::new("ld"))
    } else {
        opts.ld.as_deref()
    };

    join_bindings([
        make_pwn_elf_binding(&opts.template_bin_name, bin_path),
        make_pwn_elf_binding(&opts.template_libc_name, libc_path),
        make_pwn_elf_binding(&opts.template_ld_name, ld_path),
    ])
}

fn make_bindings_rev(opts: &RevOpts) -> String {
    join_bindings([make_rev_path_binding(
        &opts.template_bin_name,
        opts.bin.as_deref(),
    )])
}

fn make_proc_args_pwn(opts: &PwnOpts) -> String {
    format!("[{}.path]", opts.template_bin_name)
}

impl StubOptions for PwnOpts {
    fn default_template() -> &'static str {
        include_str!("template.py")
    }

    fn make_bindings(&self) -> String {
        make_bindings_pwn(self)
    }

    fn extra_vars(&self) -> HashMap<String, String> {
        hashmap! {
            "proc_args".to_string() => make_proc_args_pwn(self),
        }
    }

    fn bin_name(&self) -> &str {
        &self.template_bin_name
    }

    fn template_path(&self) -> Option<&Path> {
        self.template_path.as_deref()
    }

    fn solve_path(&self) -> &Path {
        &self.solve_path
    }

    fn force(&self) -> bool {
        self.force
    }
}

impl StubOptions for RevOpts {
    fn default_template() -> &'static str {
        include_str!("template_rev.py")
    }

    fn make_bindings(&self) -> String {
        make_bindings_rev(self)
    }

    fn bin_name(&self) -> &str {
        &self.template_bin_name
    }

    fn template_path(&self) -> Option<&Path> {
        self.template_path.as_deref()
    }

    fn solve_path(&self) -> &Path {
        &self.solve_path
    }

    fn force(&self) -> bool {
        self.force
    }
}

fn make_stub<T: StubOptions>(opts: &T) -> Result<String> {
    let templ = read_template(opts.template_path(), T::default_template())?;
    let mut vars = hashmap! {
        "bindings".to_string() => opts.make_bindings(),
        "bin_name".to_string() => opts.bin_name().to_string(),
    };
    vars.extend(opts.extra_vars());
    strfmt(&templ, &vars).context(FmtSnafu)
}

pub fn write_stub<T: StubOptions>(opts: &T) -> Result<WriteStubOutcome> {
    if opts.solve_path().exists() && !opts.force() {
        output::progress(
            format!(
                "leaving existing solve script {}",
                opts.solve_path().display()
            )
            .cyan()
            .bold(),
        );
        return Ok(WriteStubOutcome::SkippedExisting);
    }
    let stub = make_stub(opts)?;
    write_stub_file(opts.solve_path(), stub, opts.force())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_solve_script_is_preserved_without_force() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("solve.py");
        std::fs::write(&path, "original").expect("write original");

        let outcome =
            write_stub_file(&path, "replacement".to_string(), false).expect("write outcome");

        assert_eq!(outcome, WriteStubOutcome::SkippedExisting);
        assert_eq!(std::fs::read_to_string(path).expect("read"), "original");
    }

    #[test]
    fn force_overwrites_existing_solve_script() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("nested/solve.py");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        std::fs::write(&path, "original").expect("write original");

        let outcome =
            write_stub_file(&path, "replacement".to_string(), true).expect("write outcome");

        assert_eq!(outcome, WriteStubOutcome::Overwritten);
        assert_eq!(std::fs::read_to_string(path).expect("read"), "replacement");
    }
}
