use core::ptr;

use svmvisor_hypervisor::svm::{
    events::{DeliveryError, ReflectionError},
    vmcb::Vmcb,
};

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: tests own this inert VMCB; listed offsets are in-bounds qwords.
    unsafe {
        ptr::write_unaligned(ptr::from_mut(vmcb).cast::<u8>().add(offset).cast(), value);
    }
}

#[test]
fn interrupted_delivery_preserves_each_callers_independent_interrupt_profile() {
    // These are inert control images, not proof that any whole runtime is ready to run.
    for control in [0, 1 << 26, (3 << 30) | (1 << 26) | (1 << 24)] {
        let mut vmcb = Vmcb::new();
        put(&mut vmcb, 0x060, control);
        put(&mut vmcb, 0x070, 0x400);
        put(&mut vmcb, 0x088, 0x8000_0202);
        put(&mut vmcb, 0x578, 0x1234);
        let mut pending = false;

        assert_eq!(vmcb.complete_event_delivery(&mut pending), Ok(()));
        assert!(pending);
        assert_eq!(vmcb.virtual_interrupt_control(), control);
        assert_eq!(vmcb.event_injection(), 0x8000_0202);
        assert_eq!(vmcb.guest_rip(), 0x1234);
    }
}

#[test]
fn successful_reinjection_changes_only_eventinj_in_the_complete_vmcb() {
    // APM2 physical pp571-572: EXITINTINFO.ERRORCODE is defined only with EV=1.
    // Physical p594: EVENTINJ bits 30:12 are SBZ; p590: EVENTINJ is uncached.
    for (interrupted, event) in [
        (0xfedc_ba98_ffff_fb0d, 0xfedc_ba98_8000_0b0du64), // TYPE3 #GP, EV=1.
        (0xdead_beef_ffff_f306, 0x0000_0000_8000_0306),    // TYPE3 #UD, EV=0.
    ] {
        let mut vmcb = Vmcb::new();
        // Poison every qword in this inert image so accidental clearing is visible too.
        // These byte-exact fixtures never represent a guest authorized for VMRUN.
        for offset in (0..vmcb.bytes().len()).step_by(8) {
            put(&mut vmcb, offset, 0x5a5a_a5a5_d3c3_b7a7 ^ offset as u64);
        }
        for (offset, value) in [
            (0x070, 0x400),
            (0x088, interrupted),
            (0x0a8, 0),
            (0x0c0, 0x1122_3344_a5a5_5a5a), // CLEAN_BITS and adjacent reserved bytes.
            (0x570, 0x246),                 // RFLAGS.
            (0x578, 0xffff_f800_1234_5678), // RIP.
            (0x5d8, 0xffff_9000_8765_4320), // RSP.
            (0x5f8, 0xa1b2_c3d4_e5f6_0718), // RAX.
            (0x640, 0xffff_c000_3141_5920), // CR2.
        ] {
            put(&mut vmcb, offset, value);
        }
        let mut expected = *vmcb.bytes();
        expected[0x0a8..0x0b0].copy_from_slice(&event.to_le_bytes());
        for initial_pending in [false, true] {
            put(&mut vmcb, 0x0a8, 0);
            let mut pending = initial_pending;
            assert_eq!(vmcb.complete_event_delivery(&mut pending), Ok(()));
            assert!(pending);
            assert_eq!(vmcb.bytes(), &expected);
        }
    }
}

#[test]
fn owned_faults_survive_repeated_interruptions_and_retire_without_duplicate_delivery() {
    for event in [0x0000_0030_8000_0b0du64, 0x8000_0306] {
        let mut vmcb = Vmcb::new();
        put(&mut vmcb, 0x0a8, event);
        put(&mut vmcb, 0x578, 0xffff_f800_1234_5678);
        let mut pending = true;

        for code in [0x400, 0x60, 0x61] {
            // Model each VMEXIT clearing the preceding EVENTINJ input and reporting
            // the unfinished delivery. These fixtures execute no VMRUN or handler.
            put(&mut vmcb, 0x070, code);
            put(&mut vmcb, 0x088, event);
            put(&mut vmcb, 0x0a8, 0);
            let mut expected = *vmcb.bytes();
            expected[0x0a8..0x0b0].copy_from_slice(&event.to_le_bytes());

            assert_eq!(vmcb.complete_event_delivery(&mut pending), Ok(()));
            assert!(pending);
            assert_eq!(vmcb.bytes(), &expected);
        }

        // Delivery completed before this exit. Neither this completion nor a later
        // exit may recreate the previous fault or advance its saved instruction.
        put(&mut vmcb, 0x070, 0x77);
        put(&mut vmcb, 0x088, 0);
        put(&mut vmcb, 0x0a8, 0);
        let expected = *vmcb.bytes();
        for _ in 0..2 {
            assert_eq!(vmcb.complete_event_delivery(&mut pending), Ok(()));
            assert!(!pending);
            assert_eq!(vmcb.bytes(), &expected);
        }
    }
}

#[test]
fn hardware_reported_double_fault_supersedes_the_original_injection() {
    let mut vmcb = Vmcb::new();
    put(&mut vmcb, 0x0a8, 0x8000_0b0d);
    let mut pending = true;
    // The processor can promote an injected #GP into #DF before an intercept.
    // EXITINTINFO is the saved delivery authority; the previous input is gone.
    put(&mut vmcb, 0x070, 0x400);
    put(&mut vmcb, 0x088, 0x8000_0b08);
    put(&mut vmcb, 0x0a8, 0);
    let mut expected = *vmcb.bytes();
    expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0b08u64.to_le_bytes());

    assert_eq!(vmcb.complete_event_delivery(&mut pending), Ok(()));
    assert!(pending);
    assert_eq!(vmcb.bytes(), &expected);
}

#[test]
fn unsupported_or_conflicting_delivery_preserves_image_and_ownership() {
    for (interrupted, queued, error) in [
        (0x8000_0451, 0, DeliveryError::UnsupportedInterruptedEvent { interrupted: 0x8000_0451 }),
        (0x8000_0551, 0, DeliveryError::UnsupportedInterruptedEvent { interrupted: 0x8000_0551 }),
        (
            0x8000_0b0d,
            0x8000_0306,
            DeliveryError::ConflictingInterruptedEvent { interrupted: 0x8000_0b0d },
        ),
    ] {
        for initial_pending in [false, true] {
            let mut vmcb = Vmcb::new();
            put(&mut vmcb, 0x070, 0x400);
            put(&mut vmcb, 0x088, interrupted);
            put(&mut vmcb, 0x0a8, queued);
            put(&mut vmcb, 0x0c0, u64::MAX);
            let before = *vmcb.bytes();
            let mut pending = initial_pending;

            assert_eq!(vmcb.complete_event_delivery(&mut pending), Err(error));
            assert_eq!(pending, initial_pending);
            assert_eq!(vmcb.bytes(), &before);
        }
    }
}

#[test]
fn completion_cannot_clear_a_request_queued_after_the_exit() {
    let mut vmcb = Vmcb::new();
    put(&mut vmcb, 0x070, 0x77);
    put(&mut vmcb, 0x0a8, 0x8000_0306);
    let mut pending = true;
    let before = *vmcb.bytes();

    assert_eq!(
        vmcb.complete_event_delivery(&mut pending),
        Err(DeliveryError::InjectionCompletion(ReflectionError::PendingInjection))
    );
    assert!(pending);
    assert_eq!(vmcb.bytes(), &before);
}

#[test]
fn invalid_entry_and_shutdown_preserve_poisoned_state_and_pending_obligation() {
    for code in [0x7f, u64::MAX] {
        for initial_pending in [false, true] {
            let mut vmcb = Vmcb::new();
            put(&mut vmcb, 0x070, code);
            put(&mut vmcb, 0x088, u64::MAX);
            put(&mut vmcb, 0x0a8, u64::MAX);
            let before = *vmcb.bytes();
            let mut pending = initial_pending;

            assert_eq!(
                vmcb.complete_event_delivery(&mut pending),
                Err(DeliveryError::UnusableGuestState)
            );
            assert_eq!(pending, initial_pending);
            assert_eq!(vmcb.bytes(), &before);
        }
    }
}
