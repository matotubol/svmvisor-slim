//! Verify the linked entry snapshot before any guest registers become live.

use crate::{
    audit::{instruction, label, lines, normalized},
    json::Value,
};

const ENTRY: &str = "svmvisor_resident_entry_capture";
const RUN: &str = "svmvisor_resident_vmrun";
const EXIT: &str = "svmvisor_resident_exit_capture_end";
const AUXILIARY_SAVE: &[&str] =
    &["movq 0x10(%r10), %rax", "vmsave", "movq 0x20(%r10), %rax", "vmload", "cld"];
const SNAPSHOT_AND_RESTORE: &[&str] = &[
    "movq %rax, 0x10(%r11)",
    "movq 0x578(%rax), %rdx",
    "movq %rdx, 0x18(%r11)",
    "movq 0x558(%rax), %rdx",
    "movq %rdx, 0x88(%r11)",
    "vmload",
    "movq 0x28(%r10), %rsi",
    "movq (%rsi), %rcx",
    "movq 0x8(%rsi), %rdx",
    "movq 0x10(%rsi), %rbx",
    "movq 0x18(%rsi), %rbp",
    "movq 0x28(%rsi), %rdi",
    "movq 0x30(%rsi), %r8",
    "movq 0x38(%rsi), %r9",
    "movq 0x40(%rsi), %r10",
    "movq 0x48(%rsi), %r11",
    "movq 0x50(%rsi), %r12",
    "movq 0x58(%rsi), %r13",
    "movq 0x60(%rsi), %r14",
    "movq 0x68(%rsi), %r15",
    "movq 0x20(%rsi), %rsi",
];

pub fn audit_entry_capture(text: &str) -> Result<Value, String> {
    let mut owner = None;
    let mut entry = Vec::new();
    let mut run = Vec::new();
    let mut exit = Vec::new();
    let mut labels = Vec::new();
    for line in lines(text) {
        if let Some(name) = label(line) {
            owner = Some(name);
            labels.push(name);
        } else if let Some(raw) = instruction(line) {
            match owner {
                Some(ENTRY) => entry.push(normalized(raw)),
                Some(RUN) => run.push(normalized(raw)),
                Some(EXIT) => exit.push(normalized(raw)),
                _ => {}
            }
        }
    }
    let adjacent = labels.windows(2).any(|pair| pair == [ENTRY, RUN]);
    let valid = adjacent
        && entry.len() == SNAPSHOT_AND_RESTORE.len() + 4
        && entry[0].starts_with("leaq ")
        && entry[0].contains("(%rip), %r11 # 0x")
        && entry[0].ends_with("<svmvisor_resident_raw_vmexit>")
        && entry[1] == "addq $0x1, (%r11)"
        && entry[2].starts_with("jne 0x")
        && entry[2].ends_with("<svmvisor_resident_entry_capture+0x11>")
        && entry[3] == "addq $0x1, (%r11)"
        && entry[4..] == *SNAPSHOT_AND_RESTORE
        && run == ["sti", "vmrun"]
        && exit.len() >= AUXILIARY_SAVE.len()
        && exit[..AUXILIARY_SAVE.len()] == *AUXILIARY_SAVE;
    if !valid {
        return Err(
            "native entry capture or guest-register restoration differs from audited sequence"
                .into(),
        );
    }
    Ok(Value::Map(vec![
        ("symbol".into(), Value::str(ENTRY)),
        ("captured_before_guest_registers".into(), Value::strs(&["vmcb_pa", "rip", "cr0"])),
        ("guest_auxiliary_saved_before_host_restore".into(), Value::Bool(true)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        let mut text = format!(
            "1000 <{ENTRY}>:\n  1000: leaq 0x100(%rip), %r11 # 0x1107 <svmvisor_resident_raw_vmexit>\n  1007: addq $0x1, (%r11)\n  100b: jne 0x1011 <{ENTRY}+0x11>\n  100d: addq $0x1, (%r11)\n"
        );
        for value in SNAPSHOT_AND_RESTORE {
            text.push_str(&format!("  1011: {value}\n"));
        }
        text.push_str(&format!("1100 <{RUN}>:\n  1100: sti\n  1101: vmrun\n"));
        text.push_str(&format!("1200 <{EXIT}>:\n"));
        for value in AUXILIARY_SAVE {
            text.push_str(&format!("  1200: {value}\n"));
        }
        text
    }

    #[test]
    fn entry_audit_rejects_wrong_width_offsets_and_late_mutations() {
        let text = fixture();
        assert!(audit_entry_capture(&text).is_ok());
        for (from, to) in [
            ("movq 0x578", "movl 0x578"),
            ("movq 0x558", "movq 0x550"),
            ("0x88(%r11)", "0x80(%r11)"),
            ("+0x11>", "+0x12>"),
            ("  1101: vmrun", "  1101: movq %rax, (%r11)\n  1104: vmrun"),
            ("movq 0x68(%rsi), %r15", "movq 0x60(%rsi), %r15"),
            ("vmsave", "vmload"),
            ("movq 0x10(%r10), %rax", "movq 0x20(%r10), %rax"),
        ] {
            assert!(audit_entry_capture(&text.replace(from, to)).is_err(), "{from}");
        }
        assert!(audit_entry_capture("").is_err());
    }
}
