//! `cargo xtask`: the one host-side entry point of the build pipeline.
//!
//! * `cargo xtask resident --output <fresh-dir> [--entry-trial]` builds, links,
//!   packages and audits the resident payload and its DXE shim.
//! * `cargo xtask sources` prints the current source manifest (the same JSON a
//!   build records as `source-manifest.json`).
//! * `cargo xtask card-dev [--entry-trial] [--flash] [--adapter-khz N]`,
//!   `cargo xtask card-snapshot [read_snapshot.py options]` and
//!   `cargo xtask card-loader-dev`: the development-loader iteration loop
//!   (see `card.rs` and firmware/card/README.md).
//! * `cargo xtask rompack --input <driver.efi> --output <driver.rom> ...` wraps
//!   a loader image in its PCI option ROM (see `rompack.rs`).
//! * `cargo xtask capture --help` describes bounded offline process-memory reads.
//! * `cargo xtask live-read --help` describes explicit local VMMCALL process samples.
//! * `cargo xtask entry-trial --help` describes the one-shot Windows GMET client.

use std::{path::PathBuf, process::ExitCode};

mod audit;
mod capture;
mod card;
mod entry;
mod json;
mod relocations;
mod resident;
mod rompack;

const USAGE: &str = "usage: cargo xtask resident --output <fresh-dir> [--entry-trial]\n       cargo xtask sources\n       \
cargo xtask card-dev [--entry-trial] [--flash] [--adapter-khz N]\n       \
cargo xtask card-snapshot [--input <log>] [--manifest <manifest.json>]\n       \
cargo xtask card-loader-dev\n       \
cargo xtask rompack --input <driver.efi> --output <driver.rom> --vendor <hex> --device <hex> \
--class <hex> [--memory-output <driver.mem> --memory-size <bytes>]\n       \
cargo xtask capture --help\n       cargo xtask live-read --help\n       cargo xtask entry-trial --help";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("capture") {
        return capture::command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("live-read") {
        return capture::live_command(&args[1..]);
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("entry-trial") => entry::command(&args[1..]),
        Some("resident") => {
            let mut output = None;
            let mut entry_trial = false;
            let mut rest = args[1..].iter();
            while let Some(arg) = rest.next() {
                match arg.as_str() {
                    "--output" => {
                        output =
                            Some(PathBuf::from(rest.next().ok_or("--output needs a directory")?))
                    }
                    "--entry-trial" => entry_trial = true,
                    // Baseline profile; accepted for existing command lines.
                    "--boot" => {}
                    other => match other.strip_prefix("--output=") {
                        Some(path) => output = Some(PathBuf::from(path)),
                        None => return Err(format!("unknown argument {other}\n{USAGE}")),
                    },
                }
            }
            let output = output.ok_or(format!("--output is required\n{USAGE}"))?;
            if entry_trial {
                resident::build_entry_trial(&output)
            } else {
                resident::build(&output)
            }
        }
        Some("sources") if args.len() == 1 => {
            println!("{}", resident::manifest_json(&resident::sources(&resident::root())?));
            Ok(())
        }
        Some("card-dev") => {
            // This repository targets one board, whose firmware only retains a
            // runtime allocation below 1 GiB.
            let (mut flash, mut adapter_khz) = (false, 1000);
            let mut entry_trial = false;
            let mut rest = args[1..].iter();
            while let Some(arg) = rest.next() {
                match arg.as_str() {
                    // The only switch that reaches hardware; never implied.
                    "--flash" => flash = true,
                    "--entry-trial" => entry_trial = true,
                    "--adapter-khz" => {
                        adapter_khz = card::parse_adapter_khz(
                            rest.next().ok_or("--adapter-khz needs a number")?,
                        )?
                    }
                    other => match other.strip_prefix("--adapter-khz=") {
                        Some(khz) => adapter_khz = card::parse_adapter_khz(khz)?,
                        None => return Err(format!("unknown argument {other}\n{USAGE}")),
                    },
                }
            }
            card::dev(flash, adapter_khz, entry_trial)
        }
        Some("card-snapshot") => card::snapshot(&args[1..]),
        Some("card-loader-dev") if args.len() == 1 => card::loader_dev(),
        Some("rompack") => rompack::command(&args[1..]),
        _ => Err(USAGE.into()),
    }
}
