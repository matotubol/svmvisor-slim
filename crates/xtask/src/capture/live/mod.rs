//! Explicit closure of the retired direct guest reader command.

use std::{
    io::{self, Write},
    process::ExitCode,
};

const DISABLED: &str = "live-read is disabled: the legacy guest interface is retired and the authenticated reader is not available";
const USAGE: &str = "usage: cargo xtask live-read --help

Live reading is disabled while the authenticated same-PC interface is being designed.
The legacy --live, --local-runtime-v2, --stdio, --hex and --output paths are retired.
No legacy option enables access. No profile, input stream or output file is opened.
Exit codes: 0 help, 1 reader disabled or output failure.";

pub(crate) fn command(args: &[String]) -> ExitCode {
    run(args, &mut io::stdout().lock(), &mut io::stderr().lock())
}

fn run(args: &[String], output: &mut impl Write, errors: &mut impl Write) -> ExitCode {
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        return if writeln!(output, "{USAGE}").is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    let _ = writeln!(errors, "error: {DISABLED}");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests;
