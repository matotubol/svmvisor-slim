use super::*;

fn admitted() -> Vmcb {
    let mut vmcb = Vmcb::new();
    assert!(vmcb.configure_native_eraps(ERAPS_LEAF, ERAPS_FEATURE));
    vmcb
}

fn completed_entry(vmcb: &mut Vmcb, exit_code: u64) {
    vmcb.write_u64::<0x070>(exit_code);
    // Inert unit-test simulation of the real entry owner's post-exit call.
    unsafe { vmcb.consume_rap_clear_after_exit() };
}

#[test]
fn unsupported_or_unavailable_cpuid_leaf_is_inert() {
    for (maximum, features) in [(ERAPS_LEAF - 1, ERAPS_FEATURE), (ERAPS_LEAF, 0), (0, 0)] {
        let mut vmcb = Vmcb::new();
        vmcb.bytes[0x058..0x060].copy_from_slice(&[7, 0, 0, 0, 3, 0, 0, 0]);
        vmcb.bytes[0x0c0..0x0c4].fill(0xff);
        let before = *vmcb.bytes();
        assert!(!vmcb.configure_native_eraps(maximum, features));
        vmcb.request_guest_rap_clear();
        unsafe { vmcb.consume_rap_clear_after_exit() };
        assert_eq!(vmcb.bytes(), &before);
    }
}

#[test]
fn configuration_preserves_asid_tlb_and_reserved_bytes() {
    let mut vmcb = Vmcb::new();
    vmcb.bytes[0x058..0x060].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 3, 0, 0, 0]);
    vmcb.bytes[0x0c0..0x0c4].fill(0xff);
    let mut expected = *vmcb.bytes();
    expected[ERAP_CONTROL] = ALLOW_LARGER_RAP | CLEAR_RAP;
    expected[0x0c0..0x0c4].fill(0);
    assert!(vmcb.configure_native_eraps(ERAPS_LEAF, ERAPS_FEATURE));
    assert_eq!(vmcb.bytes(), &expected);
}

#[test]
fn clear_is_consumed_once_and_invalid_entry_cannot_consume_it() {
    let mut vmcb = admitted();
    for invalid in [u64::MAX, u32::MAX as u64] {
        completed_entry(&mut vmcb, invalid);
        assert_eq!(vmcb.bytes[ERAP_CONTROL], ALLOW_LARGER_RAP | CLEAR_RAP);
    }
    completed_entry(&mut vmcb, 0x7c);
    assert_eq!(vmcb.bytes[ERAP_CONTROL], ALLOW_LARGER_RAP);

    // A routine exit with no pending request must not dirty the cached VMCB.
    vmcb.bytes[0x0c0..0x0c4].fill(0xff);
    let before = *vmcb.bytes();
    unsafe { vmcb.consume_rap_clear_after_exit() };
    assert_eq!(vmcb.bytes(), &before);
}

#[test]
fn a_committed_guest_clear_is_preserved_until_its_own_entry() {
    let mut vmcb = admitted();
    completed_entry(&mut vmcb, 0x7c);
    vmcb.request_guest_rap_clear();
    vmcb.request_guest_rap_clear();
    assert_eq!(vmcb.bytes[ERAP_CONTROL], ALLOW_LARGER_RAP | CLEAR_RAP);
    completed_entry(&mut vmcb, 0x81);
    assert_eq!(vmcb.bytes[ERAP_CONTROL], ALLOW_LARGER_RAP);
    vmcb.request_guest_rap_clear();
    assert_eq!(vmcb.bytes[ERAP_CONTROL], ALLOW_LARGER_RAP | CLEAR_RAP);
}

#[test]
fn monitor_tlb_maintenance_does_not_request_a_guest_rap_clear() {
    let mut vmcb = admitted();
    completed_entry(&mut vmcb, 0x400);
    vmcb.request_full_tlb_flush();
    assert_eq!(vmcb.bytes[ERAP_CONTROL], ALLOW_LARGER_RAP);
}

#[test]
fn emulated_mtrr_and_iorr_writes_clear_without_treating_all_cache_msrs_as_context_changes() {
    let msrs = (0x200..=0x20f)
        .chain([0x250, 0x258, 0x259])
        .chain(0x268..=0x26f)
        .chain([0x2ff])
        .chain(0xc001_0016..=0xc001_0019);
    for index in msrs {
        let mut vmcb = admitted();
        completed_entry(&mut vmcb, 0x7c);
        vmcb.request_rap_clear_after_cache_msr_write(index);
        assert_ne!(vmcb.bytes[ERAP_CONTROL] & CLEAR_RAP, 0, "MSR {index:x}");
    }
    for index in [0xfe, 0x277, 0xc001_0010, 0xc001_001a, 0xc001_001d, 0xc000_0104] {
        let mut vmcb = admitted();
        completed_entry(&mut vmcb, 0x7c);
        vmcb.request_rap_clear_after_cache_msr_write(index);
        assert_eq!(vmcb.bytes[ERAP_CONTROL], ALLOW_LARGER_RAP, "MSR {index:x}");
    }
}

#[test]
fn init_clears_the_guest_rap_without_losing_native_size_admission() {
    for enabled in [false, true] {
        let mut vmcb = if enabled { admitted() } else { Vmcb::new() };
        completed_entry(&mut vmcb, 0x63);
        vmcb.initialize_ap_after_init();
        assert_eq!(
            vmcb.bytes[ERAP_CONTROL],
            if enabled { ALLOW_LARGER_RAP | CLEAR_RAP } else { 0 }
        );
    }
}

#[test]
fn efer_paging_changes_request_clear_but_unrelated_writes_do_not() {
    const SVME: u64 = 1 << 12;
    for (before, logical, clears) in [
        (SVME, 1 << 8, true),  // LME enters a different paging regime.
        (SVME, 1 << 11, true), // NXE changes page execute permissions.
        (SVME | (1 << 11), 0, true),
        (SVME, 0, false),
        (SVME, 1, false),       // SYSCALL enable does not change paging.
        (SVME, 1 << 14, false), // FFXSE does not change paging.
    ] {
        let mut vmcb = admitted();
        completed_entry(&mut vmcb, 0x7c);
        vmcb.write_u64::<0x4d0>(before);
        vmcb.commit_native_efer(logical);
        assert_eq!(vmcb.bytes[ERAP_CONTROL] & CLEAR_RAP != 0, clears);
        assert_eq!(vmcb.guest_efer(), logical | SVME);
    }
}

#[cfg(feature = "svm-entry-trial")]
#[test]
fn trial_restoration_cannot_restore_an_already_consumed_rap_clear() {
    use crate::svm::vmcb::trial::{Outcome, Ticket};

    let mut vmcb = admitted();
    vmcb.write_u64::<0x090>(1); // NPT, with GMET disabled before the trial.
    vmcb.write_u32::<0x058>(7);
    vmcb.write_u64::<0x550>(0x1000);
    vmcb.write_u64::<0x0b0>(0x2000);
    vmcb.bytes[0x4cb] = 3;
    vmcb.write_u64::<0x4d0>((1 << 10) | (1 << 12));
    vmcb.bytes[0x413] = 2;
    // Inert trial boundary, with the caller's external stop proof assumed by
    // the fixture exactly as in the existing Ticket tests; no VMRUN executes.
    let ticket = unsafe { Ticket::arm(&mut vmcb, (1 << 17) | 1) }.unwrap();
    completed_entry(&mut vmcb, 0x60);
    assert_eq!(unsafe { ticket.finish(&mut vmcb, None) }, Ok(Outcome::InterruptPending));
    assert_eq!(vmcb.bytes[ERAP_CONTROL], ALLOW_LARGER_RAP);
    assert_ne!(vmcb.bytes[0x05c], 0, "trial restoration still owes its NPT flush");
}
