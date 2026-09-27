use crate::svm::{events::ExternalInterruptError, vmcb::*};

const VNMI_FEATURE: u32 = 1 << 25;
const CLEAN: u32 = 0x03ff;
const NMI_EVENT: u64 = (1 << 31) | (2 << 8) | 2;

fn armed_vmcb() -> Vmcb {
    let mut vmcb = Vmcb::new();
    vmcb.configure_native_boot_intercepts().unwrap();
    vmcb.configure_native_nmi_virtualization(VNMI_FEATURE).unwrap();
    vmcb
}

#[test]
fn nmi_virtualization_admission_changes_only_owned_controls_and_cache_groups() {
    let mut vmcb = Vmcb::new();
    vmcb.configure_native_boot_intercepts().unwrap();
    vmcb.write_u64::<VIRTUAL_INTERRUPT_CONTROL>(0x5 | V_IRQ | (3 << 16) | (0x51 << 32));
    vmcb.write_u64::<0x0a8>(0x8000_0b0d);
    vmcb.write_u64::<0x088>(NMI_EVENT);
    vmcb.set_clean_bits(CLEAN);
    let mut expected = *vmcb.bytes();
    expected[INTERCEPT_MISC1] |= 1 << 1;
    expected[VIRTUAL_INTERRUPT_CONTROL + 3] |= 1 << 2;
    expected[CLEAN_BITS..CLEAN_BITS + 4].copy_from_slice(&(CLEAN & !9).to_le_bytes());

    vmcb.configure_native_nmi_virtualization(VNMI_FEATURE).unwrap();

    assert_eq!(vmcb.bytes(), &expected);
    assert!(vmcb.event_intercept(EventIntercept::Nmi));
    assert!(vmcb.nmi_virtualization_enabled());
    assert!(!vmcb.virtual_nmi_pending());
    assert!(!vmcb.virtual_nmi_masked());
}

#[test]
fn nmi_virtualization_admission_refuses_missing_capability_or_malformed_controls_atomically() {
    for (features, control, nested, nmi_intercept) in [
        (0, 0, 0, false),
        (VNMI_FEATURE, V_NMI, 0, true),
        (VNMI_FEATURE, V_NMI_MASK, 0, true),
        (VNMI_FEATURE, V_NMI_ENABLE, 0, false),
        (VNMI_FEATURE, 1 << 25, 0, true),
        (VNMI_FEATURE, 1 << 10, 0, true),
        (VNMI_FEATURE, 0, 2, true),
    ] {
        let mut vmcb = Vmcb::new();
        vmcb.write_u64::<VIRTUAL_INTERRUPT_CONTROL>(control);
        vmcb.write_u64::<0x090>(nested);
        vmcb.set_event_intercept(EventIntercept::Nmi, nmi_intercept);
        vmcb.set_clean_bits(CLEAN);
        let before = *vmcb.bytes();
        assert!(vmcb.configure_native_nmi_virtualization(features).is_err());
        assert_eq!(vmcb.bytes(), &before);
    }
}

#[test]
fn nmi_request_coalesces_while_masked_without_replacing_irq_exception_or_replay() {
    let mut vmcb = armed_vmcb();
    let control = V_NMI_ENABLE | V_NMI_MASK | V_IRQ | 7 | (4 << 16) | (0x41 << 32);
    vmcb.write_u64::<VIRTUAL_INTERRUPT_CONTROL>(control);
    vmcb.write_u64::<0x070>(0x61);
    vmcb.write_u64::<0x088>(NMI_EVENT);
    vmcb.write_u64::<0x0a8>(0x8000_0b0d);
    vmcb.write_u64::<GUEST_RIP>(0xffff_8000_1234_5678);
    vmcb.write_u64::<GUEST_RFLAGS>(2);
    vmcb.set_clean_bits(CLEAN);
    let mut expected = *vmcb.bytes();
    expected[VIRTUAL_INTERRUPT_CONTROL..VIRTUAL_INTERRUPT_CONTROL + 8]
        .copy_from_slice(&(control | V_NMI).to_le_bytes());
    expected[CLEAN_BITS..CLEAN_BITS + 4].copy_from_slice(&(CLEAN & !8).to_le_bytes());

    for _ in 0..3 {
        vmcb.queue_native_nmi().unwrap();
        assert_eq!(vmcb.bytes(), &expected);
        assert!(vmcb.virtual_nmi_pending());
        assert!(vmcb.virtual_nmi_masked());
    }
}

#[test]
fn nmi_request_refusals_preserve_all_state() {
    for (code, control, intercepted, expected) in [
        (0x61, 0, true, ExternalInterruptError::ControlMismatch),
        (0x61, V_NMI_ENABLE, false, ExternalInterruptError::ControlMismatch),
        (0x61, V_NMI_MASK, true, ExternalInterruptError::ControlMismatch),
        (
            0x61,
            V_NMI_ENABLE | (1 << 25),
            true,
            ExternalInterruptError::UnsupportedControl { control: V_NMI_ENABLE | (1 << 25) },
        ),
        (u64::MAX, V_NMI_ENABLE, true, ExternalInterruptError::InvalidEntry),
        (0xffff_ffff, V_NMI_ENABLE, true, ExternalInterruptError::InvalidEntry),
        (0x7f, V_NMI_ENABLE, true, ExternalInterruptError::GuestShutdown),
    ] {
        let mut vmcb = armed_vmcb();
        vmcb.write_u64::<0x070>(code);
        vmcb.write_u64::<VIRTUAL_INTERRUPT_CONTROL>(control);
        vmcb.set_event_intercept(EventIntercept::Nmi, intercepted);
        vmcb.write_u64::<0x088>(NMI_EVENT);
        vmcb.write_u64::<0x0a8>(0x8000_0b0d);
        vmcb.set_clean_bits(CLEAN);
        let before = *vmcb.bytes();

        assert_eq!(vmcb.queue_native_nmi(), Err(expected));
        assert_eq!(vmcb.bytes(), &before);
    }
}

#[test]
fn exception_queueing_preserves_the_pending_and_masked_nmi() {
    let mut vmcb = armed_vmcb();
    vmcb.write_u64::<VIRTUAL_INTERRUPT_CONTROL>(V_NMI_ENABLE | V_NMI_MASK | V_NMI);
    vmcb.set_clean_bits(CLEAN);
    let mut expected = *vmcb.bytes();
    expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0b0du64.to_le_bytes());

    vmcb.queue_native_general_protection().unwrap();

    assert_eq!(vmcb.bytes(), &expected);
    assert!(vmcb.virtual_nmi_pending());
    assert!(vmcb.virtual_nmi_masked());
}

#[test]
fn interrupted_nmi_replay_preserves_a_later_request_and_hardware_mask_lifecycle() {
    let mut vmcb = armed_vmcb();
    let mut pending_injection = false;
    for code in [0x61, 0x63, 0x400] {
        // Model a hardware exit during NMI delivery: EVENTINJ and V_NMI_MASK
        // are cleared, EXITINTINFO records the NMI (APM2 physical p599).
        // A later physical NMI has already set the separate pending latch.
        vmcb.write_u64::<0x070>(code);
        vmcb.write_u64::<0x088>(NMI_EVENT);
        vmcb.write_u64::<0x0a8>(0);
        vmcb.write_u64::<VIRTUAL_INTERRUPT_CONTROL>(V_NMI_ENABLE | V_NMI);
        vmcb.set_clean_bits(CLEAN);
        let mut expected = *vmcb.bytes();
        expected[0x0a8..0x0b0].copy_from_slice(&NMI_EVENT.to_le_bytes());

        vmcb.complete_event_delivery(&mut pending_injection).unwrap();

        assert_eq!(vmcb.bytes(), &expected);
        assert!(pending_injection);
        assert!(vmcb.virtual_nmi_pending());
        assert!(!vmcb.virtual_nmi_masked());
    }

    // Model successful NMI replay followed by an unrelated exit before IRET.
    // Hardware sets the mask on replay and retains the later pending NMI.
    vmcb.write_u64::<0x070>(0x72);
    vmcb.write_u64::<0x088>(0);
    vmcb.write_u64::<0x0a8>(0);
    vmcb.write_u64::<VIRTUAL_INTERRUPT_CONTROL>(V_NMI_ENABLE | V_NMI | V_NMI_MASK);
    vmcb.set_clean_bits(CLEAN);
    let before = *vmcb.bytes();
    for _ in 0..2 {
        vmcb.complete_event_delivery(&mut pending_injection).unwrap();
        assert_eq!(vmcb.bytes(), &before);
        assert!(!pending_injection);
        assert!(vmcb.virtual_nmi_pending());
        assert!(vmcb.virtual_nmi_masked());
    }

    // A faulting/unfinished IRET does not authorize software to drop the mask.
    // The preceding preserved state therefore also covers its later exits.
    // Now model successful first IRET and recognition of the waiting second
    // NMI (MASK=1, PENDING=0), then successful second IRET (both zero). These
    // are hardware writebacks, not proof that host tests executed an IRET.
    for state in [V_NMI_MASK, 0] {
        vmcb.write_u64::<VIRTUAL_INTERRUPT_CONTROL>(V_NMI_ENABLE | state);
        vmcb.set_clean_bits(CLEAN);
        let before = *vmcb.bytes();
        vmcb.complete_event_delivery(&mut pending_injection).unwrap();
        assert_eq!(vmcb.bytes(), &before);
        assert!(!pending_injection);
        assert!(!vmcb.virtual_nmi_pending());
        assert_eq!(vmcb.virtual_nmi_masked(), state != 0);
        assert_eq!(vmcb.event_injection(), 0);
    }
}

#[test]
fn init_clears_virtual_nmi_pending_and_mask_but_retains_enable_and_intercept() {
    let mut vmcb = armed_vmcb();
    vmcb.write_u64::<VIRTUAL_INTERRUPT_CONTROL>(
        V_NMI_ENABLE | V_NMI_MASK | V_NMI | V_IRQ | (1 << 24) | 9,
    );

    vmcb.initialize_ap_after_init();

    assert_eq!(vmcb.virtual_interrupt_control(), V_NMI_ENABLE | (1 << 24));
    assert!(vmcb.event_intercept(EventIntercept::Nmi));
    assert!(!vmcb.virtual_nmi_pending());
    assert!(!vmcb.virtual_nmi_masked());
    assert_eq!(vmcb.read_u32::<CLEAN_BITS>(), 0);
    vmcb.queue_native_nmi().unwrap();
    assert!(vmcb.virtual_nmi_pending());
    assert!(!vmcb.virtual_nmi_masked());
}
