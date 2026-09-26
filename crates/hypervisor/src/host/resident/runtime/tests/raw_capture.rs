use crate::host::resident::runtime::RawVmexitCapture;

#[test]
fn raw_boundary_requires_same_generation_vmcb_and_physical_cpu() {
    let mut raw: RawVmexitCapture = unsafe { core::mem::zeroed() };
    raw.entry_sequence = 19;
    raw.exit_sequence = 19;
    raw.entry_vmcb_pa = 0x123000;
    raw.exit_vmcb_pa = 0x123000;
    raw.context_vmcb_pa = 0x123000;
    raw.physical_apic_id = 21;
    raw.code = 0x7c;
    raw.guest_rcx = 0xc001_0010;
    raw.physical_cache_valid = 1;
    raw.exit_rip = 0xffff800000001111;
    raw.nrip = 0xffff800000002222;
    raw.entry_rip = 0xffff800000003333;
    raw.guest_cr0 = 0xe0000011;
    raw.mtrr_def_type = 0xc06;
    raw.host_cr0 = 0x80010011;
    assert_eq!(
        raw.stop_record(0x123000, 21),
        Some((
            10,
            [
                0xffff800000001111,
                0xffff800000002222,
                0xffff800000003333,
                0xe0000011,
                0xc06,
                0x80010011
            ]
        ))
    );
    for failure in 0..6 {
        let mut bad = raw;
        match failure {
            0 => bad.entry_sequence = 0,
            1 => bad.exit_sequence = 18,
            2 => bad.entry_vmcb_pa += 4096,
            3 => bad.exit_vmcb_pa += 4096,
            4 => bad.context_vmcb_pa += 4096,
            _ => bad.physical_apic_id = 13,
        }
        let record = bad.stop_record(0x123000, 21).unwrap();
        assert_eq!(record.0, 11);
        assert_eq!(
            record.1,
            [
                bad.exit_vmcb_pa,
                0x123000,
                (bad.physical_apic_id << 32) | 21,
                raw.exit_rip,
                raw.nrip,
                raw.entry_rip
            ]
        );
    }
    raw.physical_cache_valid = 0;
    assert_eq!(raw.stop_record(0x123000, 21), None);
    raw.physical_cache_valid = 1;
    raw.guest_rcx = 0xc0000080;
    assert_eq!(raw.stop_record(0x123000, 21), None);
}
