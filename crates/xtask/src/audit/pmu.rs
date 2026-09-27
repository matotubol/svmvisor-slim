//! Verify the one-time PMU commit in the linked nonreturning entry path.

use crate::{
    audit::{branch, instruction, label, lines, matches, normalized},
    json::Value,
};

const ENTER: &str = "svmvisor_resident_enter";
const COMMIT: &str = "svmvisor_resident_pmu_commit";
const INITIALIZE: &str = "svmvisor_resident_pmu_initialize";
const RATIO: &str = "svmvisor_resident_tsc_ratio_init";
const CAPTURE: &str = "svmvisor_resident_entry_capture";
const RUN: &str = "svmvisor_resident_vmrun";
const TERMINAL: &str = "svmvisor_resident_terminal";

/// Pin the first-entry call, its Win64 home space and its terminal failure edge.
/// No branch may enter the commit block again, and no other call may recapture
/// the selectors after guest execution. Hardware profile admission and selector
/// translation are checked by the PMU owner and its conformance tests.
pub fn audit_pmu_commit(text: &str) -> Result<Value, String> {
    let mut labels = Vec::new();
    let mut owner = None;
    let mut body = Vec::new();
    let mut calls = 0;
    let mut unexpected_entry = false;
    let mut premature_vmrun = false;
    for line in lines(text) {
        if let Some(name) = label(line) {
            owner = Some(name);
            labels.push(name);
        } else if let Some(raw) = instruction(line) {
            let value = normalized(raw.split('#').next().unwrap_or(raw));
            if value.contains(&format!("<{COMMIT}")) {
                unexpected_entry = true;
            }
            if value.starts_with("call") && value.contains(&format!("<{INITIALIZE}>")) {
                calls += 1;
                unexpected_entry |= owner != Some(COMMIT);
            }
            if value.contains(&format!("<{INITIALIZE}"))
                && owner != Some(COMMIT)
                && owner != Some(INITIALIZE)
            {
                unexpected_entry = true;
            }
            if labels.contains(&ENTER) && !labels.contains(&COMMIT) && value == "vmrun" {
                premature_vmrun = true;
            }
            if owner == Some(COMMIT) {
                body.push(value);
            }
        }
    }
    let position = |name| labels.iter().position(|&label| label == name);
    let ordered = match (
        position(ENTER),
        position(COMMIT),
        position(RATIO),
        position(CAPTURE),
        position(RUN),
    ) {
        (Some(enter), Some(commit), Some(ratio), Some(capture), Some(run)) => {
            enter < commit && commit + 1 == ratio && ratio < capture && capture < run
        }
        _ => false,
    };
    let valid_body = body.len() == 8
        && body[..3] == ["cld", "movq (%rsp), %rcx", "subq $0x20, %rsp"]
        && matches(&branch("callq", INITIALIZE), &body[3])
        && body[4..6] == ["addq $0x20, %rsp", "testb %al, %al"]
        && matches(&branch("je", TERMINAL), &body[6])
        && body[7] == "movq (%rsp), %r10";
    if !ordered
        || !valid_body
        || calls != 1
        || unexpected_entry
        || premature_vmrun
        || !labels.contains(&INITIALIZE)
        || !labels.contains(&TERMINAL)
    {
        return Err("PMU selectors are not committed once before guest entry".into());
    }
    Ok(Value::Map(vec![
        ("symbol".into(), Value::str(COMMIT)),
        ("before_first_vmrun".into(), Value::Bool(true)),
        ("capture_calls".into(), Value::Int(1)),
        ("failure_is_terminal".into(), Value::Bool(true)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        format!(
            "1000 <{ENTER}>:\n  1000: cli\n\
             1100 <{COMMIT}>:\n\
               1100: cld\n\
               1101: movq (%rsp), %rcx\n\
               1105: subq $0x20, %rsp\n\
               1109: callq 0x2000 <{INITIALIZE}>\n\
               110e: addq $0x20, %rsp\n\
               1112: testb %al, %al\n\
               1114: je 0x1800 <{TERMINAL}>\n\
               111a: movq (%rsp), %r10\n\
             1200 <{RATIO}>:\n  1200: nop\n\
             1300 <{CAPTURE}>:\n  1300: vmload\n\
             1400 <{RUN}>:\n  1400: vmrun\n\
             1800 <{TERMINAL}>:\n  1800: hlt\n\
             2000 <{INITIALIZE}>:\n  2000: retq\n"
        )
    }

    #[test]
    fn linked_pmu_commit_requires_owned_call_and_terminal_failure_before_entry() {
        let text = fixture();
        assert!(audit_pmu_commit(&text).is_ok());
        assert!(audit_pmu_commit(&text.replace("$0x20, %rsp", "$0x20, %rsp # imm = 0x20")).is_ok());
        for (from, to) in [
            ("movq (%rsp), %rcx", "movq (%rsp), %rdx"),
            ("subq $0x20", "subq $0x18"),
            ("addq $0x20", "addq $0x18"),
            ("testb %al, %al", "testb %cl, %cl"),
            ("je 0x1800", "jne 0x1800"),
            ("movq (%rsp), %r10", "movq (%rsp), %r11"),
            ("  1000: cli", "  1000: vmrun"),
            ("  1400: vmrun", "  1400: jmp 0x1100 <svmvisor_resident_pmu_commit>"),
            ("  1400: vmrun", "  1400: callq 0x2000 <svmvisor_resident_pmu_initialize>"),
            ("  1400: vmrun", "  1400: jmp 0x2000 <svmvisor_resident_pmu_initialize>"),
        ] {
            assert!(audit_pmu_commit(&text.replace(from, to)).is_err(), "{from}");
        }
        for symbol in [ENTER, COMMIT, INITIALIZE, RATIO, CAPTURE, RUN, TERMINAL] {
            assert!(
                audit_pmu_commit(&text.replace(&format!("<{symbol}>:"), "<missing>:")).is_err()
            );
        }
        assert!(audit_pmu_commit("").is_err());
    }
}
