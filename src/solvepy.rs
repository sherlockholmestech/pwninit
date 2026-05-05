use crate::opts::{PwnOpts, RevOpts};
use crate::patch_bin;
use crate::set_exec;

use std::collections::HashMap;
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

    #[snafu(display("error reading solve script template: {}", source))]
    Read { source: io::Error },

    #[snafu(display("error filling in solve script template: {}", source))]
    Fmt { source: strfmt::FmtError },

    #[snafu(display("error setting solve script template executable: {}", source))]
    SetExec { source: io::Error },
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

fn make_bindings_pwn(opts: &PwnOpts) -> String {
    let patched_bin = patch_bin::bin_patched_path(opts);
    let bin_path = patched_bin.as_deref().or(opts.bin.as_deref());

    let patch_active = !opts.no_patch_bin;
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

pub fn write_stub<T: StubOptions>(opts: &T) -> Result<()> {
    let stub = make_stub(opts)?;
    write_stub_file(stub)
}
