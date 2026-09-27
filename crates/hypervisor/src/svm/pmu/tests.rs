use super::*;

fn evidence() -> PmuEvidence {
    PmuEvidence {
        signature: 0x00b4_0f40,
        extended01_ecx: 1 << 23,
        extended21_eax: 1 << 12,
        extended22_eax: 1,
        extended22_ebx: 6,
    }
}

fn state(controls: [u64; 6]) -> PmuState {
    PmuState::new(PmuProfile::admit(evidence()).unwrap(), controls)
}

#[test]
fn admission_requires_exact_target_and_each_enumerated_capability() {
    assert!(PmuProfile::admit(evidence()).is_some());
    for signature in [0, 0x00b4_0f41, u32::MAX] {
        assert!(PmuProfile::admit(PmuEvidence { signature, ..evidence() }).is_none());
    }
    for candidate in [
        PmuEvidence { extended01_ecx: 0, ..evidence() },
        PmuEvidence { extended21_eax: 0, ..evidence() },
        PmuEvidence { extended22_eax: 0, ..evidence() },
    ] {
        assert!(PmuProfile::admit(candidate).is_none());
    }
    for count in 0..=15 {
        let candidate = PmuEvidence { extended22_ebx: 0xffff_fff0 | count, ..evidence() };
        assert_eq!(PmuProfile::admit(candidate).is_some(), count == 6);
    }
}

#[test]
fn selector_mapping_excludes_counters_global_registers_and_neighbors() {
    for index in 0..6 {
        assert_eq!(control_msr(index), Some(0xc001_0200 + index as u32 * 2));
        assert_eq!(control_index(0xc001_0200 + index as u32 * 2), Some(index));
        assert_eq!(control_index(0xc001_0201 + index as u32 * 2), None);
    }
    for index in 0..4 {
        assert_eq!(control_index(0xc001_0000 + index as u32), Some(index));
        assert_eq!(control_index(0xc001_0004 + index as u32), None);
    }
    for msr in [0, 0xc000_0300, 0xc000_0301, 0xc000_0302, 0xc000_0303, 0xc001_01ff, 0xc001_020c] {
        assert_eq!(control_index(msr), None);
    }
    assert_eq!(control_msr(6), None);
    assert_eq!(control_msr(usize::MAX), None);
}

#[test]
fn native_svme_zero_suppresses_each_nonzero_filter_for_every_counter() {
    for index in 0..6 {
        for filter in 0..4u64 {
            let logical = (1 << 22) | (3 << 16) | 0xc0 | (filter << 40);
            let mut controls = [0; 6];
            controls[index] = logical;
            let pmu = state(controls);
            let effective = pmu.effective_control(index, 0x4d01 & !(1 << 12)).unwrap();
            assert_eq!(effective & (1 << 22) != 0, filter == 0);
            assert_eq!(effective & (3 << 40), 1 << 40);
            assert_eq!(pmu.read(0xc001_0200 + index as u32 * 2), Some(logical));
        }
    }
}

#[test]
fn virtual_host_svme_one_suppresses_only_guest_filter() {
    for index in 0..6 {
        for filter in 0..4u64 {
            let logical = (1 << 22) | (filter << 40) | 0x0013_01c1;
            let mut controls = [0; 6];
            controls[index] = logical;
            let pmu = state(controls);
            let effective = pmu.effective_control(index, 1 << 12).unwrap();
            assert_eq!(effective & (1 << 22) != 0, filter != 1);
            assert_eq!(effective & (3 << 40), 1 << 40);
        }
    }
}

#[test]
fn disabled_selectors_stay_disabled_across_all_modes_and_efer_transitions() {
    for filter in 0..4u64 {
        let logical = (filter << 40) | 0x0013_00c0;
        let pmu = state([logical; 6]);
        for efer in [0, 1 << 12, 0] {
            for index in 0..6 {
                assert_eq!(pmu.effective_control(index, efer).unwrap() & (1 << 22), 0);
            }
        }
    }
}

#[test]
fn efer_transitions_reinterpret_existing_controls_without_changing_readback() {
    let logical = (3 << 40) | 0x0043_00c0;
    let pmu = state([logical; 6]);
    for efer in [0, 1 << 12, 0, 1 << 12] {
        assert_eq!(pmu.effective_control(5, efer).unwrap() & (1 << 22) != 0, efer != 0);
        assert_eq!(pmu.read(0xc001_020a), Some(logical));
    }
    assert_eq!(pmu.effective_control(6, 0), None);
}

#[test]
fn both_aliases_share_readback_without_exposing_physical_filter() {
    let mut pmu = state([0; 6]);
    for index in 0..4u32 {
        let value = 0x0043_00c0 | (3 << 40) | ((index as u64) << 8);
        let plan = pmu.prepare_write(0xc001_0000 + index, value, 0).unwrap();
        assert_eq!(plan.index(), index as usize);
        assert_eq!(plan.msr(), 0xc001_0200 + index * 2);
        assert_eq!(plan.logical(), value);
        assert_eq!(plan.effective() & (1 << 22), 0);
        pmu.commit_write(plan).unwrap();
        assert_eq!(pmu.read(0xc001_0000 + index), Some(value));
        assert_eq!(pmu.read(0xc001_0200 + index * 2), Some(value));
        let plan = pmu.prepare_write(0xc001_0200 + index * 2, value ^ 1, 1 << 12).unwrap();
        pmu.commit_write(plan).unwrap();
        assert_eq!(pmu.read(0xc001_0000 + index), Some(value ^ 1));
    }
}

#[test]
fn every_defined_field_survives_except_hg_and_suppressed_enable() {
    for index in 0..6 {
        let precise = if index == 2 { 1 << 43 } else { 0 };
        let logical = 0x0000_030f_7fd7_ffff | precise;
        let mut pmu = state([0; 6]);
        let plan = pmu.prepare_write(0xc001_0200 + index as u32 * 2, logical, 0).unwrap();
        let expected = (logical & !((3 << 40) | (1 << 22))) | (1 << 40);
        assert_eq!(plan.effective(), expected);
        pmu.commit_write(plan).unwrap();
        assert_eq!(pmu.read(0xc001_0200 + index as u32 * 2), Some(logical));
    }
}

#[test]
fn precise_retire_is_writable_only_on_counter_two_and_its_alias() {
    let pmu = state([0; 6]);
    for index in 0..6u32 {
        assert_eq!(pmu.prepare_write(0xc001_0200 + index * 2, 1 << 43, 0).is_some(), index == 2);
    }
    assert!(pmu.prepare_write(0xc001_0002, 1 << 43, 0).is_some());
}

#[test]
fn reserved_fields_are_written_as_captured_without_inventing_faults() {
    let reserved = (1 << 63) | (1 << 42) | (1 << 37) | (1 << 31) | (1 << 21) | (1 << 19);
    let mut pmu = state([reserved; 6]);
    let plan = pmu.prepare_write(0xc001_0200, reserved | 0x0043_00c0, 0).unwrap();
    assert_eq!(plan.effective() & reserved, reserved);
    pmu.commit_write(plan).unwrap();
    assert!(pmu.prepare_write(0xc001_0200, 0x0043_00c0, 0).is_none());
    assert!(state([0; 6]).prepare_write(0xc001_0200, 1 << 31, 0).is_none());
    assert!(pmu.prepare_write(0xc001_0201, 0, 0).is_none());
}

#[test]
fn stale_write_plan_does_not_overwrite_a_newer_alias_write() {
    let mut pmu = state([0; 6]);
    let old = pmu.prepare_write(0xc001_0002, 0x0043_00c0, 0).unwrap();
    let latest = pmu.prepare_write(0xc001_0204, 0x0043_00c1, 0).unwrap();
    pmu.commit_write(latest).unwrap();
    assert_eq!(pmu.commit_write(old), Err(PmuError::StaleWritePlan));
    assert_eq!(pmu.read(0xc001_0002), Some(0x0043_00c1));
}

#[test]
fn odd_merge_helpers_keep_all_non_event_bits_clear_while_even_control_filters() {
    let merge = 0x0000_000f_0040_00ff;
    for even in [0, 2, 4] {
        for filter in 0..4u64 {
            let mut controls = [0; 6];
            controls[even] = (filter << 40) | 0x0043_0103;
            controls[even + 1] = merge;
            let pmu = state(controls);
            for efer in [0, 1 << 12] {
                assert_eq!(pmu.effective_control(even + 1, efer), Some(merge));
                let counts = if efer == 0 { filter == 0 } else { filter != 1 };
                assert_eq!(pmu.effective_control(even, efer).unwrap() & (1 << 22) != 0, counts);
            }
        }
    }
}

#[test]
fn leaving_merge_mode_restores_ordinary_selector_filtering() {
    let merge = 0x0000_000f_0040_00ff;
    let mut controls = [0; 6];
    controls[1] = merge;
    let mut pmu = state(controls);
    let plan = pmu.prepare_write(0xc001_0001, 0x0043_00c0, 0).unwrap();
    assert_eq!(plan.effective(), 0x0000_0100_0043_00c0);
    pmu.commit_write(plan).unwrap();
    assert_eq!(pmu.read(0xc001_0202), Some(0x0043_00c0));
}
