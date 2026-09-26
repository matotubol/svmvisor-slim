//! Pin the narrow physical cache diagnostic path in the linked world switch.

use crate::{
    audit::{instruction, label, lines, normalized},
    json::Value,
};

const SAMPLE: &str = "svmvisor_resident_msr_capture";
const EXIT_START: &str = "svmvisor_resident_vmexit";
const COMMIT: &str = "svmvisor_resident_raw_capture_commit";
const END: &str = "svmvisor_resident_exit_capture_end";
// Empty entries are forward rejection branches to COMMIT, checked separately.
const EXPECTED: &[&str] = &[
    "cmpq $0x7c, 0x38(%rdi)",
    "",
    "cmpl $0xc0010010, 0x80(%rdi)",
    "",
    "movl $0x1, %eax",
    "xorl %ecx, %ecx",
    "cpuid",
    "shrl $0x18, %ebx",
    "movq %rbx, 0x78(%rdi)",
    "cmpl $0xb40f40, %eax",
    "",
    "movl $0x2ff, %ecx",
    "rdmsr",
    "shlq $0x20, %rdx",
    "orq %rdx, %rax",
    "movq %rax, 0x60(%rdi)",
    "movl $0xc0010010, %ecx",
    "rdmsr",
    "shlq $0x20, %rdx",
    "orq %rdx, %rax",
    "movq %rax, 0x68(%rdi)",
    "movq $0x1, 0x98(%rdi)",
];

pub fn audit_msr_capture(text: &str) -> Result<Value, String> {
    let mut labels = Vec::new();
    let mut owner = None;
    let mut sample = Vec::new();
    let mut commit = Vec::new();
    let mut capturing = false;
    let mut premature_sample = false;
    for line in lines(text) {
        if let Some(name) = label(line) {
            owner = Some(name);
            labels.push(name);
            if name == EXIT_START {
                capturing = true;
            } else if name == END {
                capturing = false;
            }
        } else if let Some(raw) = instruction(line) {
            let value = normalized(raw.split('#').next().unwrap_or(raw));
            if capturing && owner != Some(SAMPLE) && matches!(value.as_str(), "cpuid" | "rdmsr") {
                premature_sample = true;
            }
            match owner {
                Some(SAMPLE) => sample.push(value),
                Some(COMMIT) => commit.push(value),
                _ => {}
            }
        }
    }
    let rejects =
        |value: &str| value.starts_with("jne 0x") && value.ends_with(&format!(" <{COMMIT}>"));
    let ordered = matches!(
        (labels.iter().position(|&name| name == EXIT_START), labels.iter().position(|&name| name == SAMPLE)),
        (Some(start), Some(sample)) if start < sample
    );
    if !ordered
        || premature_sample
        || !labels.windows(3).any(|names| names == [SAMPLE, COMMIT, END])
        || sample.len() != EXPECTED.len()
        || !sample.iter().zip(EXPECTED).all(|(actual, expected)| {
            if expected.is_empty() { rejects(actual) } else { actual == expected }
        })
        || commit != ["movq (%rdi), %r11", "movq %r11, 0x8(%rdi)"]
    {
        return Err("physical MSR evidence is not gated by SYS_CFG before CPUID".into());
    }
    Ok(Value::Map(vec![
        ("symbol".into(), Value::str(SAMPLE)),
        ("sampled_msr".into(), Value::Int(0xc0010010)),
        ("cpuid_only_for_sys_cfg".into(), Value::Bool(true)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_serialization_before_selection_and_unguarded_physical_reads() {
        let mut text = format!("900 <{EXIT_START}>:\n  900: cli\n1000 <{SAMPLE}>:\n");
        for value in EXPECTED {
            let value =
                if value.is_empty() { format!("jne 0x1200 <{COMMIT}>") } else { value.to_string() };
            text.push_str(&format!("  1000: {value}\n"));
        }
        text.push_str(&format!(
            "1200 <{COMMIT}>:\n  1200: movq (%rdi), %r11\n  1203: movq %r11, 0x8(%rdi)\n1300 <{END}>:\n"
        ));
        assert!(audit_msr_capture(&text).is_ok());
        for (from, to) in [
            ("cmpl $0xc0010010, 0x80(%rdi)", "cpuid"),
            ("  900: cli", "  900: cli\n  901: cpuid"),
            ("  900: cli", "  900: cli\n  901: rdmsr"),
            ("0x80(%rdi)", "0x78(%rdi)"),
            ("jne 0x1200", "je 0x1200"),
            ("movl $0x1, %eax", "movl $0x0, %eax"),
            ("cmpl $0xb40f40, %eax", "nop"),
            ("movl $0x2ff, %ecx", "movl $0x200, %ecx"),
            ("movq %r11, 0x8(%rdi)", "movq %r11, (%rdi)"),
        ] {
            assert!(audit_msr_capture(&text.replace(from, to)).is_err(), "{from}");
        }
        assert!(audit_msr_capture(&text.replacen("  1000:", "  1000: cpuid\n  1002:", 1)).is_err());
        assert!(audit_msr_capture("").is_err());
    }
}
