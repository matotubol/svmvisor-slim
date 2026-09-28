use super::*;

fn fixture() -> String {
    let mut text = format!("1000 <{ENTER}>:\n  1000: cli\n1100 <{PAGING}>:\n");
    for value in SWITCH {
        text.push_str(&format!("  1100: {value}\n"));
    }
    text.push_str(&format!(
        "1200 <{END}>:\n  1200: movq %cr0, %rax\n  1204: callq 0x2000 <initialize>\n\
         1300 <{RUN}>:\n  1300: sti\n  1301: vmrun\n"
    ));
    text
}

#[test]
fn linked_host_paging_requires_the_global_flush_before_the_private_root() {
    let text = fixture();
    assert!(audit_host_paging(&text).is_ok());
    let annotated = text.replace("$-0x81, %rax", "$-0x81, %rax # imm = 0xFFFFFFFFFFFFFF7F");
    assert!(audit_host_paging(&annotated).is_ok());
    for (from, to) in [
        ("movq %cr4, %rax", "movq %cr0, %rax"),
        ("andq $-0x81, %rax", "andq $-0x41, %rax"),
        ("andq $-0x81, %rax", "andl $-0x81, %eax"),
        ("andq $-0x81, %rax", "orq $0x80, %rax"),
        ("movq %rax, %cr4", "movq %rax, %cr0"),
        ("movq 0x8(%r10), %rax", "movq 0x10(%r10), %rax"),
        ("movq %rax, %cr3", "movq %cr3, %rax"),
        (
            "movq %rax, %cr4\n  1100: movq 0x8(%r10), %rax",
            "movq 0x8(%r10), %rax\n  1100: movq %rax, %cr4",
        ),
        (
            "movq 0x8(%r10), %rax",
            "orq $0x80, %rax\n  1100: movq %rax, %cr4\n  1100: movq 0x8(%r10), %rax",
        ),
    ] {
        assert!(audit_host_paging(&text.replace(from, to)).is_err(), "{from} -> {to}");
    }
    for value in SWITCH {
        assert!(audit_host_paging(&text.replace(&format!("  1100: {value}\n"), "")).is_err());
    }
}

#[test]
fn linked_host_paging_rejects_premature_calls_entries_and_missing_boundaries() {
    let text = fixture();
    for operation in [
        "callq 0x2000 <initialize>",
        "callq *%rax",
        "vmrun",
        "jmp 0x1200 <svmvisor_resident_host_paging_end>",
    ] {
        let changed = text.replace("1000: cli", &format!("1000: {operation}"));
        assert!(audit_host_paging(&changed).is_err(), "{operation}");
    }
    for symbol in [ENTER, PAGING, END, RUN] {
        assert!(audit_host_paging(&text.replace(&format!("<{symbol}>:"), "<missing>:")).is_err());
        assert!(audit_host_paging(&format!("{text}1400 <{symbol}>:\n")).is_err());
    }
    let reversed = text
        .replace(&format!("<{PAGING}>:"), "<temporary>:")
        .replace(&format!("<{END}>:"), &format!("<{PAGING}>:"))
        .replace("<temporary>:", &format!("<{END}>:"));
    assert!(audit_host_paging(&reversed).is_err());
    assert!(audit_host_paging("").is_err());
}
