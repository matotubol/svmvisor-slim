use svmvisor_hypervisor::host::resident::terminal;

#[test]
fn postboot_init_refusal_exports_its_distinct_stage_and_target_identity() {
    let (tag, value) = terminal::startup_failure(
        7,
        terminal::StartupStage::PostbootInitUnsupported as u8,
        0,
        0x25,
    );
    assert_eq!(tag, 0x005f_f10c);
    for exit in [0x63, 0x7c, 0x400] {
        let words = terminal::stop_words(3, exit, 0xffff_8000_0000_1000, tag, value).unwrap();
        assert_eq!((words[0] >> 24) & 15, 15);
        assert_eq!((words[0] >> 13) & 0x7ff, 0x5f);
        assert_eq!((words[0] >> 8) & 31, 3);
        assert_eq!([words[1], words[2]], [0, 0x25]);
    }
}

#[test]
fn interrupted_injection_stop_keeps_rip_and_does_not_claim_a_fault_address() {
    let rip = 0xffff_f800_1234_5678;
    let interrupted = 0x0000_0030_8000_0b0d;
    for (slot, code) in [(0, 0x400), (31, 0x7c)] {
        let words = terminal::stop_words(slot, code, rip, 0xf115, interrupted).unwrap();
        assert_eq!((words[0] >> 24) & 15, 0);
        assert_eq!((words[0] >> 13) & 0x7ff, code as u32);
        assert_eq!((words[0] >> 8) & 31, slot as u32);
        assert_eq!(u64::from(words[1]) | (u64::from(words[2]) << 32), rip);
    }
}

#[test]
fn malformed_startup_payloads_do_not_fall_back_to_generic_exit_records() {
    for detail in [0_u64, 8, 0x800, 1 << 32] {
        for code in [0x63, 0x400] {
            assert!(
                terminal::stop_words(0, code, 0x1234, 0xf10c | (detail << 16), u64::MAX).is_none()
            );
        }
    }
}

#[test]
fn missing_ack_owner_on_msr_exit_is_not_a_malformed_syscfg_record() {
    let words = terminal::stop_words(0, 0x7c, 0x1234, 0xf116, 0).unwrap();
    assert_eq!(words[0] & 255, 0x83);
    assert_eq!((words[0] >> 24) & 15, 0);
    assert_eq!((words[0] >> 13) & 0x7ff, 0x7c);
    assert_eq!([words[1], words[2]], [0x1234, 0]);
    // An empty packed SYS_CFG payload must still be refused, not reclassified.
    assert!(terminal::stop_words(0, 0x7c, 0x1234, 0xf10d, 0).is_none());
}

/// Startup-target records through the three-DWORD export; the retired
/// startup-route record (kind 14) is never exported, so its vectors are gone.
#[test]
fn refusal_wire_preserves_evidence_and_exports_decoder_vectors() {
    let mut vectors = Vec::new();
    for value in [0x100, u32::MAX as u64, 0x1_0000_0000, u64::MAX] {
        let (tag, v) = terminal::startup_failure(4, 0x10, value, 16);
        let w = terminal::stop_words(2, 0x63, 0, tag, v).unwrap();
        assert_eq!((w[0] >> 24) & 15, 15);
        vectors.push(format!("{{\"name\":\"target\",\"words\":{:?},\"value\":{}}}", w, value));
    }
    // A stalled physical-NMI drain (F113h, `info2` = consecutive misses) is
    // likewise an unhandled exit 61h with the guest RIP.
    let w = terminal::stop_words(3, 0x61, 0xffff_f800_0000_1000, 0xf113, 3).unwrap();
    assert_eq!(
        ((w[0] >> 24) & 15, (w[0] >> 13) & 0x7ff, w[1], w[2]),
        (0, 0x61, 0x1000, 0xffff_f800)
    );
    if let Some(path) = std::env::var_os("SVMVISOR_REFUSAL_VECTORS") {
        std::fs::write(path, format!("[{}]\n", vectors.join(",\n"))).unwrap();
    }
}
