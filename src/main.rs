//! Top-level main code for `pwninit`

use pwninit::opts::Opts;

use clap::{CommandFactory, Parser};

fn main() {
    let opts = Opts::parse();
    pwninit::output::configure(opts.quiet, opts.verbose, opts.json);

    if let Err(message) = opts.validate() {
        if opts.json {
            pwninit::output::error(message);
            std::process::exit(2);
        }
        Opts::command()
            .error(clap::error::ErrorKind::InvalidValue, message)
            .exit();
    }

    match pwninit::run_with_summary(opts) {
        Ok(summary) => {
            let success = summary.success();
            pwninit::output::render_summary(&summary);
            if !success {
                std::process::exit(1);
            }
        }
        Err(err) => {
            pwninit::output::error(err.to_string());
            std::process::exit(1);
        }
    }
}
