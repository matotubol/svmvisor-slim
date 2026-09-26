//! Pin the native branch-record capture and recording freeze in linked entry.

use crate::{
    audit::{branch, instruction, label, lines, matches, normalized},
    json::Value,
};

const ENTER: &str = "svmvisor_resident_enter";
const CAPTURE: &str = "svmvisor_resident_lbr_capture";
const STACK: &str = "svmvisor_resident_lbr_stack_capture";
const END: &str = "svmvisor_resident_lbr_capture_end";
const RUN: &str = "svmvisor_resident_vmrun";
const PREAMBLE: &[&str] = &["cli", "clgi", "movq %rcx, %r10"];
const CAPTURE_BODY: &[&str] = &[
    "movq 0x10(%r10), %r11",
    "movl $0x1d9, %ecx",
    "rdmsr",
    "movl %eax, 0x670(%r11)",
    "movl %edx, 0x674(%r11)",
    "andl $-0x2, %eax",
    "wrmsr",
    "movl $0xc000010f, %ecx",
    "rdmsr",
    "movl %eax, 0x698(%r11)",
    "movl %edx, 0x69c(%r11)",
    "andl $-0x41, %eax",
    "wrmsr",
    "movl $0x1db, %ecx",
    "rdmsr",
    "movl %eax, 0x678(%r11)",
    "movl %edx, 0x67c(%r11)",
    "incl %ecx",
    "rdmsr",
    "movl %eax, 0x680(%r11)",
    "movl %edx, 0x684(%r11)",
    "incl %ecx",
    "rdmsr",
    "movl %eax, 0x688(%r11)",
    "movl %edx, 0x68c(%r11)",
    "incl %ecx",
    "rdmsr",
    "movl %eax, 0x690(%r11)",
    "movl %edx, 0x694(%r11)",
    "movl $0xc000010e, %ecx",
    "rdmsr",
    "movl %eax, 0xb70(%r11)",
    "movl %edx, 0xb74(%r11)",
    "leaq 0xa70(%r11), %rdi",
    "movl $0xc0010300, %ecx",
];
const STACK_BODY: &[&str] = &[
    "rdmsr",
    "movl %eax, (%rdi)",
    "movl %edx, 0x4(%rdi)",
    "addq $0x8, %rdi",
    "incl %ecx",
    "cmpl $0xc0010320, %ecx",
];

/// The bounded block stores both native controls before clearing only their
/// recording enables, then captures every record with recording frozen. No call,
/// branch or VMRUN precedes the freeze. Native mapping/feature admission belongs
/// to the caller; this checks emitted instructions and the exact VMCB geometry.
pub fn audit_lbr_capture(text: &str) -> Result<Value, String> {
    let mut labels = Vec::new();
    let mut owner = None;
    let mut preamble = Vec::new();
    let mut capture = Vec::new();
    let mut stack = Vec::new();
    let mut unexpected_entry = false;
    for line in lines(text) {
        if let Some(name) = label(line) {
            owner = Some(name);
            labels.push(name);
        } else if let Some(raw) = instruction(line) {
            let value = normalized(raw.split('#').next().unwrap_or(raw));
            // Capture is entered once by fallthrough from resident_enter. Only
            // the frozen stack loop may branch back to its own first RDMSR.
            if value.contains(&format!("<{CAPTURE}"))
                || (value.contains(&format!("<{STACK}")) && owner != Some(STACK))
            {
                unexpected_entry = true;
            }
            match owner {
                Some(ENTER) => preamble.push(value),
                Some(CAPTURE) => capture.push(value),
                Some(STACK) => stack.push(value),
                _ => {}
            }
        }
    }
    let ordered = labels.windows(4).any(|names| names == [ENTER, CAPTURE, STACK, END]);
    let before_run = matches!(
        (labels.iter().position(|&name| name == END), labels.iter().position(|&name| name == RUN)),
        (Some(end), Some(run)) if end < run
    );
    let complete_stack = stack
        .split_last()
        .is_some_and(|(last, body)| body == STACK_BODY && matches(&branch("jb", STACK), last));
    if !ordered
        || !before_run
        || unexpected_entry
        || preamble != PREAMBLE
        || capture != CAPTURE_BODY
        || !complete_stack
    {
        return Err("native LBR controls/records are not frozen and captured before VMRUN".into());
    }
    Ok(Value::Map(vec![
        ("symbol".into(), Value::str(CAPTURE)),
        ("stack_entries".into(), Value::Int(16)),
        ("captured_msrs".into(), Value::Int(39)),
        ("host_recording_disabled".into(), Value::Bool(true)),
        ("before_first_vmrun".into(), Value::Bool(true)),
    ]))
}

#[cfg(test)]
mod tests;
