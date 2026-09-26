use super::*;

fn fixture() -> String {
    let mut text = String::new();
    for (name, body) in [(ENTER, PREAMBLE), (CAPTURE, CAPTURE_BODY), (STACK, STACK_BODY)] {
        text.push_str(&format!("1000 <{name}>:\n"));
        for instruction in body {
            text.push_str(&format!("  1000: {instruction}\n"));
        }
    }
    text.push_str(&format!(
        "  1100: jb 0x1000 <{STACK}>\n1200 <{END}>:\n  1200: nop\n1300 <{RUN}>:\n  1300: vmrun\n"
    ));
    text
}

#[test]
fn linked_capture_requires_freeze_before_record_reads_and_exact_stack_geometry() {
    let text = fixture();
    assert!(audit_lbr_capture(&text).is_ok());
    for (from, to) in [
        ("movl $0x1d9, %ecx", "movl $0x1db, %ecx"),
        ("andl $-0x2, %eax", "andl $-0x3, %eax"),
        ("andl $-0x41, %eax", "xorl %eax, %eax"),
        ("0x674(%r11)", "0x670(%r11)"),
        ("0x69c(%r11)", "0x698(%r11)"),
        ("0x684(%r11)", "0x694(%r11)"),
        ("0xb74(%r11)", "0xb70(%r11)"),
        ("0xa70(%r11)", "0x670(%r11)"),
        ("$0xc0010300", "$0xc0010301"),
        ("$0xc0010320", "$0xc001031f"),
        ("addq $0x8, %rdi", "addq $0x10, %rdi"),
        ("jb 0x1000", "je 0x1000"),
        ("movq %rcx, %r10", "vmrun"),
        ("  1000: wrmsr", "  1000: nop"),
        ("  1000: rdmsr", "  1000: callq 0x1400 <helper>\n  1001: rdmsr"),
    ] {
        assert!(audit_lbr_capture(&text.replace(from, to)).is_err(), "{from}");
    }
    assert!(
        audit_lbr_capture(&text.replace(&format!("0x1000 <{STACK}>"), "0x1200 <wrong>")).is_err()
    );
    assert!(audit_lbr_capture("").is_err());
}

#[test]
fn linked_capture_rejects_reentry_and_moved_blocks() {
    let text = fixture();
    let reentered = format!("{text}1400 <elsewhere>:\n  1400: jmp 0x1000 <{CAPTURE}>\n");
    assert!(audit_lbr_capture(&reentered).is_err());
    let stack_entry = format!("{text}1400 <elsewhere>:\n  1400: jmp 0x1000 <{STACK}>\n");
    assert!(audit_lbr_capture(&stack_entry).is_err());
    let moved = text.replace(&format!("1000 <{ENTER}>:"), &format!("1000 <{RUN}>:"));
    assert!(audit_lbr_capture(&moved).is_err());
    let annotated = text.replace("$0xc000010f, %ecx", "$0xc000010f, %ecx # imm = 0xC000010F");
    assert!(audit_lbr_capture(&annotated).is_ok());
}
