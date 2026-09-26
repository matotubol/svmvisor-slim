//! Explicit Windows hardware smoke test of a single user-to-kernel transition.

use std::{fs::OpenOptions, io::Write, path::PathBuf};

use svmvisor_card_abi::entry;

#[cfg(all(windows, target_arch = "x86_64"))]
mod native;

const USAGE: &str = "cargo xtask entry-trial --live --entry-trial-v1 --cpu N --output FILE.jsonl\nBoot the --entry-trial runtime first. One attempt per CPU per boot; no retries.";

#[repr(C, align(4096))]
#[derive(Default)]
struct Record {
    arm_rax: u64,
    arm_status: u64,
    syscall_status: u64,
    syscall_called: u64,
    query_rax: u64,
    status: u64,
    exit_code: u64,
    rip: u64,
    info1: u64,
    info2: u64,
    sequence: u64,
    stack: u64,
}

const _: () = {
    assert!(std::mem::offset_of!(Record, arm_rax) == 0);
    assert!(std::mem::offset_of!(Record, arm_status) == 8);
    assert!(std::mem::offset_of!(Record, syscall_status) == 16);
    assert!(std::mem::offset_of!(Record, syscall_called) == 24);
    assert!(std::mem::offset_of!(Record, query_rax) == 32);
    assert!(std::mem::offset_of!(Record, status) == 40);
    assert!(std::mem::offset_of!(Record, exit_code) == 48);
    assert!(std::mem::offset_of!(Record, rip) == 56);
    assert!(std::mem::offset_of!(Record, info1) == 64);
    assert!(std::mem::offset_of!(Record, info2) == 72);
    assert!(std::mem::offset_of!(Record, sequence) == 80);
    assert!(std::mem::offset_of!(Record, stack) == 88);
    assert!(size_of::<Record>() == 4096);
};

struct Options {
    cpu: u16,
    output: PathBuf,
}

pub(super) fn command(args: &[String]) -> Result<(), String> {
    if args == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    let options = parse(args)?;
    // Reserve the destination before consuming the CPU's only attempt.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&options.output)
        .map_err(|error| format!("create result file: {error}"))?;
    writeln!(file, "{{\"state\":\"prepared\",\"cpu\":{}}}", options.cpu)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    #[cfg(all(windows, target_arch = "x86_64"))]
    let result = native::run(options.cpu);
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    let result: Result<(u64, Box<Record>), String> = Err("requires native x64 Windows".into());
    let document = match &result {
        Ok((nonce, record)) => document(options.cpu, *nonce, record),
        Err(error) => serde_json::json!({"state": "preparation_failed", "error": error}),
    };
    // Append a final record: a crash or runtime stop leaves the prepared line intact.
    writeln!(file, "{document}")
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("save result (do not retry): {error}; result={document}"))?;
    println!("{document}");
    let (_, record) = result?;
    if expected(&record) {
        Ok(())
    } else {
        Err("trial did not establish the expected smoke-test result; do not retry".into())
    }
}

fn parse(args: &[String]) -> Result<Options, String> {
    let (mut live, mut acknowledged, mut cpu, mut output) = (false, false, None, None);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--live" if !live => live = true,
            "--entry-trial-v1" if !acknowledged => acknowledged = true,
            "--cpu" if cpu.is_none() => {
                cpu = Some(args.next().ok_or(USAGE)?.parse::<u16>().map_err(|_| USAGE)?)
            }
            "--output" if output.is_none() => {
                output = Some(PathBuf::from(args.next().ok_or(USAGE)?))
            }
            _ => return Err(USAGE.into()),
        }
    }
    if !live || !acknowledged || cpu.is_none_or(|cpu| cpu >= 32) {
        return Err(USAGE.into());
    }
    Ok(Options { cpu: cpu.unwrap(), output: output.ok_or(USAGE)? })
}

fn expected(record: &Record) -> bool {
    record.arm_rax == 0
        && record.arm_status == entry::ENTERED
        && record.syscall_called == 1
        && record.query_rax == 0
        && record.status == entry::GATED
        && record.exit_code == 0x400
        && record.info1 & !(1 << 2) == (1 | (1 << 4) | (1 << 32))
        && record.sequence != 0
}

fn document(cpu: u16, nonce: u64, record: &Record) -> serde_json::Value {
    let outcome = if record.arm_rax != 0 {
        "activation_refused"
    } else if record.query_rax != 0 {
        "query_rejected"
    } else {
        match record.status {
            entry::GATED => "supervisor_fetch_gated",
            entry::REFLECTED => "user_page_fault_reflected",
            entry::INTERRUPTED => "physical_interrupt_first",
            entry::REFUSED => "activation_refused",
            entry::FAILED => "failed",
            _ => "incomplete_or_unknown",
        }
    };
    serde_json::json!({
        "state": "returned", "version": entry::VERSION, "cpu_group": 0, "cpu": cpu,
        "nonce": format!("{nonce:#018x}"), "syscall": "NtYieldExecution",
        "arm_rax": record.arm_rax, "arm_status": record.arm_status,
        "syscall_called": record.syscall_called != 0,
        "syscall_ntstatus": if record.syscall_called != 0 { Some(format!("{:#010x}", record.syscall_status as u32)) } else { None },
        "query_rax": record.query_rax, "experiment_status": record.status,
        "exit_code": format!("{:#x}", record.exit_code), "rip": format!("{:#018x}", record.rip),
        "info1": format!("{:#018x}", record.info1), "info2": format!("{:#018x}", record.info2),
        "entry_sequence": format!("{:#x}", record.sequence), "outcome": outcome,
        "hardware_smoke_test": expected(record), "independent_boundary_trace": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_explicit_runtime_and_cpu() {
        let args = ["--live", "--entry-trial-v1", "--cpu", "31", "--output", "trial.json"]
            .map(String::from);
        assert!(parse(&args).is_ok());
        assert!(parse(&args[1..]).is_err());
        let mut invalid = args.clone();
        invalid[3] = "32".into();
        assert!(parse(&invalid).is_err());
    }

    #[test]
    fn only_correlated_expected_exit_is_success() {
        let mut record = Record {
            arm_status: entry::ENTERED,
            syscall_called: 1,
            status: entry::GATED,
            exit_code: 0x400,
            info1: 0x1_0000_0011,
            sequence: 1,
            ..Record::default()
        };
        assert!(expected(&record));
        record.query_rax = 1;
        assert!(!expected(&record));
        record.query_rax = 0;
        record.status = entry::INTERRUPTED;
        assert!(!expected(&record));
        record.arm_rax = 1;
        assert_eq!(document(0, 1, &record)["outcome"], "activation_refused");
    }
}
