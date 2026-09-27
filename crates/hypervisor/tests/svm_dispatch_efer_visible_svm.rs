use core::ptr;

use svmvisor_hypervisor::{
    arch::x86_64::registers::GuestRegisters,
    svm::{
        dispatch::{NativeEfer, NativeEferError, NativeMsrOutcome, handle_native_efer},
        vmcb::Vmcb,
    },
};

fn owner() -> NativeEfer {
    NativeEfer::admit_native_visible_svm(
        0x500,
        1 << 2,
        (1 << 11) | (1 << 20) | (1 << 29),
        1 << 20,
        None,
    )
    .unwrap()
}

fn stopped() -> (Vmcb, GuestRegisters) {
    let mut vmcb = Vmcb::new();
    for (offset, value) in [
        (0x70, 0x7c),
        (0x78, 1),
        (0x410, 0x29b << 16),
        (0x4d0, 0x1500),
        (0x558, 0x8000_0011),
        (0x570, 2),
        (0x578, 0x4000),
        (0x5f8, 0x1500),
    ] {
        put(&mut vmcb, offset, value);
    }
    (vmcb, GuestRegisters { rcx: 0xc000_0080, rbx: 0x1234, ..GuestRegisters::default() })
}

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: tests exclusively own the inert VMCB; each listed field is an in-bounds qword.
    unsafe {
        ptr::write_unaligned(ptr::from_mut(vmcb).cast::<u8>().add(offset).cast(), value);
    }
}

#[test]
fn visible_svm_requires_advertised_capability_and_keeps_full_admission_unchanged() {
    assert_eq!(
        NativeEfer::admit_native_visible_svm(0x500, 0, (1 << 20) | (1 << 29), 0, None),
        Err(NativeEferError::UnsupportedInitialState)
    );
    assert!(
        NativeEfer::admit_native_visible_svm(0x1500, 1 << 2, (1 << 20) | (1 << 29), 0, None)
            .is_ok()
    );
    assert_eq!(
        NativeEfer::admit_native(0x1500, 1 << 2, (1 << 20) | (1 << 29), 0, None),
        Err(NativeEferError::UnsupportedInitialState)
    );
}

#[test]
fn logical_svme_writes_and_reads_preserve_mandatory_hardware_backing() {
    let mut owner = owner();
    let (mut vmcb, mut frame) = stopped();
    for value in [0x1500, 0x500, 0x1500] {
        put(&mut vmcb, 0x78, 1);
        put(&mut vmcb, 0x5f8, value);
        let before = frame;
        assert_eq!(
            handle_native_efer(&mut owner, &mut vmcb, &mut frame, &[0x0f, 0x30]),
            Ok(NativeMsrOutcome::Completed)
        );
        assert_eq!(frame, before);
        assert_eq!(owner.logical(), value);
        assert_eq!(vmcb.guest_efer(), 0x1500);
        assert_eq!(vmcb.event_injection(), 0);

        put(&mut vmcb, 0x78, 0);
        assert_eq!(
            handle_native_efer(&mut owner, &mut vmcb, &mut frame, &[0x0f, 0x32]),
            Ok(NativeMsrOutcome::Completed)
        );
        assert_eq!(vmcb.guest_rax(), value);
        assert_eq!(frame.rdx, 0);
    }
}

#[test]
fn full_svm_unavailable_owner_keeps_its_existing_general_protection_outcome() {
    let mut owner = NativeEfer::admit_native(0x500, 1 << 2, 1 << 29, 0, None).unwrap();
    let (mut vmcb, mut frame) = stopped();
    assert_eq!(
        handle_native_efer(&mut owner, &mut vmcb, &mut frame, &[0x0f, 0x30]),
        Ok(NativeMsrOutcome::GeneralProtectionPrepared)
    );
    assert_eq!(vmcb.guest_rip(), 0x4000);
    assert_eq!(owner.logical(), 0x500);
}

#[test]
fn rejected_efer_write_preserves_state_through_modeled_delivery_and_later_read() {
    let mut owner = owner();
    let (mut vmcb, mut frame) = stopped();
    // Clearing LME while paging remains enabled must fault without committing the write.
    put(&mut vmcb, 0x5f8, 0x400);
    let before = (*vmcb.bytes(), frame, owner);
    assert_eq!(
        handle_native_efer(&mut owner, &mut vmcb, &mut frame, &[0x0f, 0x30]),
        Ok(NativeMsrOutcome::GeneralProtectionPrepared)
    );
    let mut expected = before.0;
    expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0b0du64.to_le_bytes());
    assert_eq!((*vmcb.bytes(), frame, owner), (expected, before.1, before.2));

    // Model a later ordinary exit after successful delivery. This fixture does not execute
    // VMRUN or a guest handler and cannot establish physical exception recovery.
    put(&mut vmcb, 0x070, 0x77);
    put(&mut vmcb, 0x088, 0);
    put(&mut vmcb, 0x0a8, 0);
    let after_exit = *vmcb.bytes();
    let mut pending = true;
    assert_eq!(vmcb.complete_event_delivery(&mut pending), Ok(()));
    assert!(!pending);
    assert_eq!((*vmcb.bytes(), frame, owner), (after_exit, before.1, before.2));

    // Model the handler reaching a subsequent EFER read: the rejected write is still absent.
    put(&mut vmcb, 0x070, 0x7c);
    put(&mut vmcb, 0x078, 0);
    put(&mut vmcb, 0x578, 0x5000);
    assert_eq!(
        handle_native_efer(&mut owner, &mut vmcb, &mut frame, &[0x0f, 0x32]),
        Ok(NativeMsrOutcome::Completed)
    );
    assert_eq!(owner, before.2);
    assert_eq!(vmcb.guest_efer(), 0x1500);
    assert_eq!(vmcb.guest_rax(), 0x500);
    assert_eq!(vmcb.guest_rip(), 0x5002);
    assert_eq!(frame, before.1);
    assert_eq!(vmcb.event_injection(), 0);
}

#[test]
fn interrupted_efer_fault_delivery_replays_without_committing_the_rejected_write() {
    let mut owner = owner();
    let (mut vmcb, mut frame) = stopped();
    put(&mut vmcb, 0x5f8, 0x400);
    assert_eq!(
        handle_native_efer(&mut owner, &mut vmcb, &mut frame, &[0x0f, 0x30]),
        Ok(NativeMsrOutcome::GeneralProtectionPrepared)
    );
    let fault = vmcb.event_injection();
    let logical = owner;
    let registers = frame;
    let mut pending = true;
    // APM2 physical pp571-573: valid EXITINTINFO describes an unfinished delivery.
    // Model VMEXIT clearing EVENTINJ on both the first attempt and its replay.
    for code in [0x400, 0x60] {
        put(&mut vmcb, 0x070, code);
        put(&mut vmcb, 0x088, fault);
        put(&mut vmcb, 0x0a8, 0);
        let mut expected = *vmcb.bytes();
        expected[0x0a8..0x0b0].copy_from_slice(&fault.to_le_bytes());

        assert_eq!(vmcb.complete_event_delivery(&mut pending), Ok(()));
        assert!(pending);
        assert_eq!((*vmcb.bytes(), frame, owner), (expected, registers, logical));
        assert_eq!(vmcb.guest_rip(), 0x4000);
    }

    // A completed delivery and another ordinary exit cannot inject the fault again.
    put(&mut vmcb, 0x070, 0x77);
    put(&mut vmcb, 0x088, 0);
    put(&mut vmcb, 0x0a8, 0);
    let completed = *vmcb.bytes();
    for _ in 0..2 {
        assert_eq!(vmcb.complete_event_delivery(&mut pending), Ok(()));
        assert!(!pending);
        assert_eq!((*vmcb.bytes(), frame, owner), (completed, registers, logical));
    }

    // Model a subsequent read after the guest handler: the invalid EFER write
    // never committed, and replay did not advance the faulting instruction.
    put(&mut vmcb, 0x070, 0x7c);
    put(&mut vmcb, 0x078, 0);
    put(&mut vmcb, 0x578, 0x5000);
    assert_eq!(
        handle_native_efer(&mut owner, &mut vmcb, &mut frame, &[0x0f, 0x32]),
        Ok(NativeMsrOutcome::Completed)
    );
    assert_eq!((owner, frame), (logical, registers));
    assert_eq!(vmcb.guest_efer(), 0x1500);
    assert_eq!(vmcb.guest_rax(), 0x500);
    assert_eq!(vmcb.guest_rip(), 0x5002);
    assert_eq!(vmcb.event_injection(), 0);
}

#[test]
fn visible_svm_init_and_native_cr0_changes_reuse_the_same_lma_lifecycle() {
    let mut owner = owner();
    owner.enable_guest_startup();
    owner.reset_after_init().unwrap();
    let (mut vmcb, mut frame) = stopped();
    put(&mut vmcb, 0x410, (0x49b << 16) | (0xffff << 32));
    put(&mut vmcb, 0x558, 0x11);
    put(&mut vmcb, 0x4d0, 0x1000);
    put(&mut vmcb, 0x5f8, 0x1900);
    assert_eq!(
        handle_native_efer(&mut owner, &mut vmcb, &mut frame, &[0x0f, 0x30]),
        Ok(NativeMsrOutcome::Completed)
    );
    assert_eq!(owner.logical(), 0x1900);

    // Model direct MOV CR0.PG and the long-mode far jump; CR3 itself is not intercepted.
    put(&mut vmcb, 0x558, 0x8000_0011);
    put(&mut vmcb, 0x410, (0x29b << 16) | (0xffff << 32));
    put(&mut vmcb, 0x4d0, 0x1d00);
    put(&mut vmcb, 0x78, 0);
    assert_eq!(
        handle_native_efer(&mut owner, &mut vmcb, &mut frame, &[0x0f, 0x32]),
        Ok(NativeMsrOutcome::Completed)
    );
    assert_eq!(owner.logical(), 0x1d00);
    assert_eq!(vmcb.guest_rax(), 0x1d00);

    put(&mut vmcb, 0x4d0, 0x1d01);
    let before = (*vmcb.bytes(), frame, owner);
    assert_eq!(
        handle_native_efer(&mut owner, &mut vmcb, &mut frame, &[0x0f, 0x32]),
        Err(NativeEferError::BackingMismatch)
    );
    assert_eq!((*vmcb.bytes(), frame, owner), before);
}

#[test]
fn native_paging_disable_updates_lma_before_a_legal_lme_clear() {
    let mut owner = owner();
    owner.enable_guest_startup();
    let (mut vmcb, mut frame) = stopped();
    // Model the stopped state after hardware disables paging and clears LMA.
    // APM2 physical pp118-119/553: LMA follows mode state; LME may change with PG=0.
    // The fixture supplies the completed mode transition, not an executed MOV CR0.
    put(&mut vmcb, 0x410, (0x49b << 16) | (0xffff << 32));
    put(&mut vmcb, 0x558, 0x11);
    put(&mut vmcb, 0x4d0, 0x1100);
    put(&mut vmcb, 0x078, 0);
    assert_eq!(
        handle_native_efer(&mut owner, &mut vmcb, &mut frame, &[0x0f, 0x32]),
        Ok(NativeMsrOutcome::Completed)
    );
    assert_eq!(owner.logical(), 0x100);
    assert_eq!(vmcb.guest_rax(), 0x100);
    assert_eq!(vmcb.guest_efer(), 0x1100);

    put(&mut vmcb, 0x078, 1);
    put(&mut vmcb, 0x5f8, 0);
    let before = frame;
    assert_eq!(
        handle_native_efer(&mut owner, &mut vmcb, &mut frame, &[0x0f, 0x30]),
        Ok(NativeMsrOutcome::Completed)
    );
    assert_eq!(frame, before);
    assert_eq!(owner.logical(), 0);
    assert_eq!(vmcb.guest_efer(), 0x1000);
    assert_eq!(vmcb.guest_rip(), 0x4004);
    assert_eq!(vmcb.event_injection(), 0);
}
