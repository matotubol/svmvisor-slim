use core::ptr;

use crate::{
    host::resident::runtime::{
        INITIAL_STATE,
        exit::{check_exit_event, record_unexplained_stop},
    },
    svm::vmcb::Vmcb,
};

#[test]
fn interrupted_fault_replay_survives_repeated_exits_then_completes_once() {
    for event in [0x0000_0030_8000_0b0d_u64, 0x8000_0306] {
        let mut vmcb = Vmcb::new();
        for (offset, value) in [
            (0x0c0, 0x1122_3344_a5a5_5a5a),
            (0x570, 0x10102),
            (0x578, 0xffff_f800_1234_5678),
            (0x5d8, 0xffff_9000_8765_4320),
            (0x5f8, 0xa1b2_c3d4_e5f6_0718),
            (0x640, 0xffff_c000_3141_5920),
        ] {
            put(&mut vmcb, offset, value);
        }
        let mut state = INITIAL_STATE;
        state.pending_fault = true;
        // Model successive hardware exits while delivering the same fault. This
        // tests event bookkeeping, not authorization to resume every NPF.
        for code in [0x63, 0x400, 0x63] {
            put(&mut vmcb, 0x70, code);
            put(&mut vmcb, 0x88, event);
            // #VMEXIT clears EVENTINJ, including when delivery is unfinished
            // (APM3 physical p540); EXITINTINFO is the recovery authority.
            put(&mut vmcb, 0xa8, 0);
            let mut expected = *vmcb.bytes();
            expected[0xa8..0xb0].copy_from_slice(&event.to_le_bytes());
            assert!(check_exit_event(&mut state, &mut vmcb));
            assert!(state.pending_fault && !state.stopped_valid);
            assert_eq!(*vmcb.bytes(), expected);
        }

        // Successful delivery and later exits must neither replay the completed
        // fault nor mutate the hardware-saved RIP, flags, stack, RAX or CR2.
        put(&mut vmcb, 0x70, 0x77);
        put(&mut vmcb, 0x88, 0);
        put(&mut vmcb, 0xa8, 0);
        let delivered = *vmcb.bytes();
        for _ in 0..2 {
            assert!(check_exit_event(&mut state, &mut vmcb));
            assert!(!state.pending_fault && !state.stopped_valid);
            assert_eq!(*vmcb.bytes(), delivered);
        }
    }
}

#[test]
fn fresh_injection_refusal_preserves_request_and_exportable_terminal_reason() {
    let mut vmcb = Vmcb::new();
    for (offset, value) in [(0x70, 0x400u64), (0xa8, 0x8000_0b0d), (0x578, 0x1234)] {
        put(&mut vmcb, offset, value);
    }
    let before = *vmcb.bytes();
    let mut state = INITIAL_STATE;
    state.pending_fault = true;
    // A valid EVENTINJ surviving here was queued after the exit. Consuming the
    // preceding entry's obligation must not erase this new request.
    assert!(!check_exit_event(&mut state, &mut vmcb));
    assert!(state.pending_fault && state.stopped_valid);
    assert_eq!((state.stopped, state.stopped_info1, state.stopped_info2), (0x400, 0xf115, 0));
    let words = crate::host::resident::terminal::stop_words(
        state.slot,
        state.stopped,
        state.stopped_rip,
        state.stopped_info1,
        state.stopped_info2,
    )
    .expect("injection completion refusal must remain exportable");
    assert_eq!(((words[0] >> 24) & 15, (words[0] >> 13) & 0x7ff), (0, 0x400));
    assert_eq!(*vmcb.bytes(), before);
}

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: this fixture exclusively owns its inert VMCB and all offsets are in bounds.
    unsafe {
        ptr::from_mut(vmcb).cast::<u8>().add(offset).cast::<u64>().write_unaligned(value);
    }
}

#[test]
fn interrupted_delivery_is_reinjected_through_eventinj_before_resume() {
    // Saved interrupted external delivery (TYPE 0, vector 51h) must survive
    // the exit, independently of which exit code captured it.
    for code in [0x400_u64, 0x60, 0x61, 0x401] {
        let mut vmcb = Vmcb::new();
        let interrupted = 0x8000_0051_u64;
        for (offset, value) in
            [(0x70, code), (0x88, interrupted), (0x578, 0x1234), (0xc0, u64::from(u32::MAX))]
        {
            unsafe {
                ptr::copy_nonoverlapping(
                    value.to_le_bytes().as_ptr(),
                    (&mut vmcb as *mut Vmcb).cast::<u8>().add(offset),
                    8,
                );
            }
        }
        let mut state = INITIAL_STATE;
        assert!(check_exit_event(&mut state, &mut vmcb));
        assert!(state.pending_fault && !state.stopped_valid);
        // EXITINTINFO is retained; EVENTINJ now carries the same event and
        // cached state remains reusable because EVENTINJ is explicitly uncached.
        assert_eq!(vmcb.event_injection(), interrupted);
        assert_eq!(u64::from_le_bytes(vmcb.bytes()[0x88..0x90].try_into().unwrap()), interrupted);
        assert_eq!(vmcb.bytes()[0xc0..0xc4], u32::MAX.to_le_bytes());
    }
}

#[test]
fn interrupted_virtual_nmi_replay_preserves_a_second_pending_nmi() {
    let mut vmcb = Vmcb::new();
    vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
    let mut state = INITIAL_STATE;
    let interrupted_nmi = 0x8000_0202;
    // Hardware clears V_NMI_MASK on an exit during NMI delivery and reports
    // that unfinished event in EXITINTINFO (APM2 physical p599).
    put(&mut vmcb, 0x70, 0x61);
    put(&mut vmcb, 0x88, interrupted_nmi);
    assert!(check_exit_event(&mut state, &mut vmcb));
    assert!(state.pending_fault);
    assert_eq!(vmcb.event_injection(), interrupted_nmi);
    assert!(!vmcb.virtual_nmi_masked());

    // A separately acknowledged physical NMI is pending beside the replay,
    // never substituted for it. EVENTINJ(TYPE2) with VNMI enabled causes
    // hardware to establish blocking for the replay at the next VMRUN.
    vmcb.queue_native_nmi().unwrap();
    assert!(vmcb.virtual_nmi_pending());
    assert_eq!(vmcb.event_injection(), interrupted_nmi);
    for _ in 0..2 {
        put(&mut vmcb, 0xa8, 0);
        let mut expected = *vmcb.bytes();
        expected[0xa8..0xb0].copy_from_slice(&interrupted_nmi.to_le_bytes());
        assert!(check_exit_event(&mut state, &mut vmcb));
        assert_eq!(*vmcb.bytes(), expected);
        assert!(state.pending_fault && vmcb.virtual_nmi_pending());
    }

    // Model completed replay while the handler is still running: its NMI
    // mask stays set and the second request remains pending until guest IRET.
    put(&mut vmcb, 0xa8, 0);
    put(&mut vmcb, 0x88, 0);
    let masked_control = vmcb.virtual_interrupt_control() | (1 << 12);
    put(&mut vmcb, 0x60, masked_control);
    let completed = *vmcb.bytes();
    for _ in 0..2 {
        assert!(check_exit_event(&mut state, &mut vmcb));
        assert!(!state.pending_fault && !state.stopped_valid);
        assert!(vmcb.virtual_nmi_masked() && vmcb.virtual_nmi_pending());
        assert_eq!(*vmcb.bytes(), completed);
    }
}

#[test]
fn software_interrupt_and_conflicting_delivery_stay_terminal() {
    for pending_fault in [false, true] {
        for (interrupted, queued, reason) in [
            // TYPE 4 (INTn) is outside this bounded recovery path.
            (0x8000_0451u64, 0, 0xf10f),
            // A different pending EVENTINJ conflicts with re-injection.
            (0x8000_0051, 0x8000_0b0d, 0xf112),
        ] {
            let mut vmcb = Vmcb::new();
            for (offset, value) in
                [(0x70, 0x400u64), (0x88, interrupted), (0xa8, queued), (0x578, 0x1234)]
            {
                put(&mut vmcb, offset, value);
            }
            let before = *vmcb.bytes();
            let mut state = INITIAL_STATE;
            state.pending_fault = pending_fault;
            assert!(!check_exit_event(&mut state, &mut vmcb));
            assert_eq!(state.pending_fault, pending_fault);
            assert!(state.stopped_valid);
            assert_eq!(
                (state.stopped, state.stopped_rip, state.stopped_info1, state.stopped_info2),
                (0x400, 0x1234, reason, interrupted)
            );
            assert_eq!(*vmcb.bytes(), before);
        }
    }
}

#[test]
fn shutdown_and_invalid_entry_do_not_interpret_poisoned_saved_event_or_rip() {
    for pending_fault in [false, true] {
        for code in [0x7f_u64, u64::MAX] {
            let mut vmcb = Vmcb::new();
            for (offset, value) in
                [(0x70, code), (0x88, u64::MAX), (0xa8, u64::MAX), (0x578, u64::MAX)]
            {
                put(&mut vmcb, offset, value);
            }
            let before = *vmcb.bytes();
            let mut state = INITIAL_STATE;
            state.pending_fault = pending_fault;
            assert!(!check_exit_event(&mut state, &mut vmcb));
            assert_eq!(
                (state.stopped, state.stopped_rip, state.stopped_info1, state.stopped_info2),
                (code, 0, 0xf110, 0)
            );
            assert_eq!(state.pending_fault, pending_fault);
            assert!(state.stopped_valid);
            assert_eq!(*vmcb.bytes(), before);
        }
    }
}

#[test]
fn unexplained_refusal_records_exit_without_changing_guest_or_existing_reason() {
    let vmcb = Vmcb::new();
    let before = *vmcb.bytes();
    let exit = vmcb.exit_snapshot();
    let mut state = INITIAL_STATE;
    record_unexplained_stop(&mut state, true, exit);
    assert!(!state.stopped_valid);
    record_unexplained_stop(&mut state, false, exit);
    assert!(state.stopped_valid);
    assert_eq!(
        (state.stopped, state.stopped_rip, state.stopped_info1, state.stopped_info2),
        (exit.code, exit.rip, 0xf10e, exit.info1)
    );
    state.stopped_info1 = 0xf400;
    state.stopped_info2 = 16;
    record_unexplained_stop(&mut state, false, exit);
    assert_eq!((state.stopped_info1, state.stopped_info2), (0xf400, 16));
    assert_eq!(*vmcb.bytes(), before);
}
