use svmvisor_hypervisor::svm::vmcb::{Vmcb, native_pause_retry_ready};

fn write(vmcb: &mut Vmcb, offset: usize, bytes: &[u8]) {
    // Test-only construction of fields normally written by VMRUN/VMEXIT.
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (vmcb as *mut Vmcb).cast::<u8>().add(offset),
            bytes.len(),
        );
    }
}

#[test]
fn unsupported_filter_configuration_is_inert() {
    let mut v = Vmcb::new();
    let before = *v.bytes();
    assert!(!v.configure_native_pause_filter(0));
    assert_eq!(v.bytes(), &before);
}

#[test]
fn pause_retries_preserve_debug_pending_and_all_guest_state() {
    for mode in [0u64, 1, 0x80000001] {
        let mut v = Vmcb::new();
        assert!(v.configure_native_pause_filter(1 << 10));
        write(&mut v, 0x070, &0x77u64.to_le_bytes());
        write(&mut v, 0x558, &mode.to_le_bytes());
        write(&mut v, 0x570, &0x10302u64.to_le_bytes()); // TF,IF,RF remain hardware-owned.
        write(&mut v, 0x578, &0x1234u64.to_le_bytes());
        write(&mut v, 0x0a8, &0x8000030du64.to_le_bytes());
        let before = *v.bytes();
        assert!(native_pause_retry_ready(&v));
        assert_eq!(v.bytes(), &before);
    }
}

#[test]
fn zero_or_advanced_filters_and_wrong_exit_cannot_retry() {
    for (offset, bytes) in [
        (0x03e, vec![0, 0]), // A zero count makes every PAUSE exit.
        (0x03c, vec![1, 0]), // A cycle threshold is not count-only filtering.
        (0x070, vec![0x78]), // Not a PAUSE exit.
        (0x00e, vec![0]),    // The intercept itself is off.
    ] {
        let mut v = Vmcb::new();
        v.configure_native_pause_filter(1 << 10);
        write(&mut v, 0x070, &0x77u64.to_le_bytes());
        write(&mut v, offset, &bytes);
        assert!(!native_pause_retry_ready(&v));
    }
}

#[test]
fn a_configured_filter_carries_a_nonzero_count_and_no_threshold() {
    let mut v = Vmcb::new();
    assert!(v.configure_native_pause_filter(1 << 10));
    let field =
        |v: &Vmcb, offset: usize| u16::from_le_bytes([v.bytes()[offset], v.bytes()[offset + 1]]);
    // The count is the budget the hardware loads its internal counter with, so a
    // zero count would exit on every PAUSE instruction rather than once per budget.
    // APM2 rev3.44 Table B-1 (physical page 801): 03Ch threshold, 03Eh count.
    assert_ne!(field(&v, 0x03e), 0, "the PAUSE budget must be nonzero");
    assert_eq!(field(&v, 0x03c), 0, "count-only filtering needs a zero threshold");
}
