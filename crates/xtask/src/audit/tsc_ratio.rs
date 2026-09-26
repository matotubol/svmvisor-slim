//! Verify unity TSC scaling in the linked nonreturning entry path.

use crate::{
    audit::{instruction, label, lines, normalized},
    json::Value,
};

const ENTER: &str = "svmvisor_resident_enter";
const INIT: &str = "svmvisor_resident_tsc_ratio_init";
const CAPTURE: &str = "svmvisor_resident_entry_capture";
const RUN: &str = "svmvisor_resident_vmrun";
const SETUP: &[&str] = &[
    "movl $0xc0000104, %ecx",
    "xorl %eax, %eax",
    "movl $0x1, %edx",
    "wrmsr",
    "movq 0x20(%r10), %rax",
    "vmsave",
    "movq (%rsp), %r10",
    "movq 0x10(%r10), %rax",
];

/// Pin the full initialization block through guest-entry capture. This establishes
/// the physical 8.32 unity multiplier before first VMRUN, independently of the
/// software shadow's value. CPU feature admission and the shadow's capture are
/// owned by the preceding arm path; this audit does not establish those facts.
pub fn audit_tsc_ratio_init(text: &str) -> Result<Value, String> {
    let mut owner = None;
    let mut labels = Vec::new();
    let mut setup = Vec::new();
    let mut premature_vmrun = false;
    for line in lines(text) {
        if let Some(name) = label(line) {
            owner = Some(name);
            labels.push(name);
        } else if let Some(raw) = instruction(line) {
            // LLVM annotates large immediate operands with `# imm = ...`.
            // Check the instruction itself, independently of that presentation.
            let value = normalized(raw.split('#').next().unwrap_or(raw));
            if owner == Some(INIT) {
                setup.push(value);
            } else if labels.contains(&ENTER) && !labels.contains(&INIT) && value == "vmrun" {
                premature_vmrun = true;
            }
        }
    }
    let position = |name| labels.iter().position(|&label| label == name);
    let ordered = match (position(ENTER), position(INIT), position(CAPTURE), position(RUN)) {
        (Some(enter), Some(init), Some(capture), Some(run)) => {
            enter < init && init + 1 == capture && capture < run
        }
        _ => false,
    };
    if !ordered || premature_vmrun || setup != SETUP {
        return Err("physical TSC ratio is not initialized to unity before guest entry".into());
    }
    Ok(Value::Map(vec![
        ("symbol".into(), Value::str(INIT)),
        ("physical_ratio".into(), Value::Int(1 << 32)),
        ("before_first_vmrun".into(), Value::Bool(true)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        let mut text = format!("1000 <{ENTER}>:\n  1000: cli\n1100 <{INIT}>:\n");
        for value in SETUP {
            text.push_str(&format!("  1100: {value}\n"));
        }
        text.push_str(&format!("1200 <{CAPTURE}>:\n  1200: nop\n1300 <{RUN}>:\n  1300: vmrun\n"));
        text
    }

    #[test]
    fn linked_ratio_audit_rejects_wrong_register_value_and_entry_order() {
        let text = fixture();
        assert!(audit_tsc_ratio_init(&text).is_ok());
        let annotated = text.replace("$0xc0000104, %ecx", "$0xc0000104, %ecx # imm = 0xC0000104");
        assert!(audit_tsc_ratio_init(&annotated).is_ok());
        assert!(audit_tsc_ratio_init(&annotated.replace("$0xc0000104", "$0xc0000103")).is_err());
        for (from, to) in [
            ("$0xc0000104", "$0xc0000103"),
            ("xorl %eax, %eax", "movl $0x1, %eax"),
            ("movl $0x1, %edx", "xorl %edx, %edx"),
            ("wrmsr", "rdmsr"),
            ("vmsave", "wrmsr"),
            ("  1000: cli", "  1000: vmrun"),
            ("svmvisor_resident_tsc_ratio_init", "unowned_init"),
            ("svmvisor_resident_entry_capture", "missing_capture"),
            ("svmvisor_resident_vmrun", "missing_run"),
        ] {
            assert!(audit_tsc_ratio_init(&text.replace(from, to)).is_err(), "{from}");
        }
        let late = text.replacen(&format!("1000 <{ENTER}>:"), &format!("1000 <{RUN}>:"), 1);
        assert!(audit_tsc_ratio_init(&late).is_err());
        assert!(audit_tsc_ratio_init("").is_err());
    }
}
