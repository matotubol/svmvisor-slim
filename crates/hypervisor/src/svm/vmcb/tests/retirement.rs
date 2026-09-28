use crate::svm::{
    events::ExternalInterruptError,
    vmcb::{CLEAN_BITS, NativeRetirementError, Vmcb},
};

fn vmcb(flags: u64, debug_control: u64) -> Vmcb {
    let mut vmcb = Vmcb::new();
    vmcb.write_u64::<0x070>(0x7c);
    vmcb.write_u64::<0x570>(flags);
    vmcb.write_u64::<0x568>(0xffff_afff);
    vmcb.write_u64::<0x560>(0x24ff);
    vmcb.write_u64::<0x670>(debug_control);
    vmcb.write_u64::<0x698>(1 << 6);
    assert!(vmcb.configure_native_lbr(0x8000_0022, 2, 7, 0x2106));
    vmcb.write_u32::<CLEAN_BITS>(0x3ff);
    vmcb
}

#[test]
fn pure_single_step_sets_its_cause_without_inventing_address_or_bus_lock_causes() {
    for previous in [0xffff_a7ff, 0xffff_afff, 0xffff_e7ff, 0xffff_efff] {
        let mut vmcb = vmcb(0x10302, 1);
        vmcb.write_u64::<0x568>(previous);
        vmcb.write_u32::<CLEAN_BITS>(0x3ff);
        let before = *vmcb.bytes();
        let prepared = vmcb.prepare_native_msr_retirement().unwrap();
        assert_eq!(*vmcb.bytes(), before, "preparation must be inert");

        assert!(vmcb.complete_native_msr_retirement(prepared));
        let mut expected = before;
        expected[0x568..0x570].copy_from_slice(&((previous & !0xf) | 0x4000).to_le_bytes());
        expected[0x570..0x578].copy_from_slice(&0x302u64.to_le_bytes());
        expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0301u64.to_le_bytes());
        expected[0x0c0..0x0c4].copy_from_slice(&0x3bfu32.to_le_bytes());
        assert_eq!(*vmcb.bytes(), expected);
        // TF/GD/LBR/LBRSE are entry side effects, so they remain until VMRUN.
        assert_eq!(vmcb.read_u64::<0x560>(), 0x24ff);
        assert_eq!(vmcb.read_u64::<0x670>(), 1);
        assert_eq!(vmcb.read_u64::<0x698>(), 1 << 6);
    }
}

#[test]
fn branch_single_step_does_not_trap_a_sequential_msr_or_clear_debug_status() {
    let mut vmcb = vmcb(0x10302, 3);
    let mut expected = *vmcb.bytes();
    let prepared = vmcb.prepare_native_msr_retirement().unwrap();
    assert!(!vmcb.complete_native_msr_retirement(prepared));
    expected[0x570..0x578].copy_from_slice(&0x302u64.to_le_bytes());
    assert_eq!(*vmcb.bytes(), expected);
}

#[test]
fn ordinary_retirement_consumes_shadow_and_rf_without_requiring_debug_control() {
    let mut vmcb = vmcb(0x10202, 0);
    vmcb.write_u64::<0x0b8>(0);
    vmcb.write_u64::<0x068>(1);
    let mut expected = *vmcb.bytes();
    let prepared = vmcb.prepare_native_msr_retirement().unwrap();
    assert!(!vmcb.complete_native_msr_retirement(prepared));
    expected[0x570..0x578].copy_from_slice(&0x202u64.to_le_bytes());
    expected[0x068..0x070].copy_from_slice(&0u64.to_le_bytes());
    assert_eq!(*vmcb.bytes(), expected);
}

#[test]
fn unknown_debug_control_and_shadow_refuse_before_any_state_changes() {
    for debug_control in [0, 2] {
        let mut vmcb = vmcb(0x10302, debug_control);
        vmcb.write_u64::<0x0b8>(0);
        let before = *vmcb.bytes();
        assert!(matches!(
            vmcb.prepare_native_msr_retirement(),
            Err(NativeRetirementError::DebugControlUnavailable)
        ));
        assert_eq!(*vmcb.bytes(), before);

        vmcb.write_u64::<0x0b8>(1);
        vmcb.write_u64::<0x068>(1);
        let before = *vmcb.bytes();
        assert!(matches!(
            vmcb.prepare_native_msr_retirement(),
            Err(NativeRetirementError::InterruptShadow)
        ));
        assert_eq!(*vmcb.bytes(), before);
    }
}

#[test]
fn new_debug_trap_never_replaces_an_event_or_interrupted_delivery() {
    for (offset, error) in [
        (0x0a8, ExternalInterruptError::PendingInjection),
        (0x088, ExternalInterruptError::NestedDeliveryUnsupported),
    ] {
        for flags in [0x10202, 0x10302] {
            let mut vmcb = vmcb(flags, 0);
            vmcb.bytes[offset..offset + 8].copy_from_slice(&0x8000_030eu64.to_le_bytes());
            let before = *vmcb.bytes();
            assert!(matches!(
                vmcb.prepare_native_msr_retirement(),
                Err(NativeRetirementError::EventState(actual)) if actual == error
            ));
            assert_eq!(*vmcb.bytes(), before);
        }
    }
}

#[test]
fn pending_nmi_survives_debug_retirement_and_interrupted_debug_delivery_replays_once() {
    let mut vmcb = vmcb(0x10302, 1);
    vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
    vmcb.queue_native_nmi().unwrap();
    let nmi_control = vmcb.virtual_interrupt_control();
    let prepared = vmcb.prepare_native_msr_retirement().unwrap();
    assert!(vmcb.complete_native_msr_retirement(prepared));
    assert_eq!(vmcb.virtual_interrupt_control(), nmi_control);

    // Hardware clears EVENTINJ on exit. An NPF interrupted the first #DB delivery.
    vmcb.write_u64::<0x070>(0x400);
    vmcb.write_u64::<0x0a8>(0);
    vmcb.write_u64::<0x088>(0x8000_0301);
    let debug_status = vmcb.read_u64::<0x568>();
    let mut pending = true;
    vmcb.complete_event_delivery(&mut pending).unwrap();
    assert!(pending);
    assert_eq!(vmcb.event_injection(), 0x8000_0301);
    assert_eq!(vmcb.read_u64::<0x568>(), debug_status);

    vmcb.write_u64::<0x0a8>(0);
    vmcb.write_u64::<0x088>(0);
    vmcb.write_u64::<0x070>(0x72);
    vmcb.complete_event_delivery(&mut pending).unwrap();
    assert!(!pending);
    assert_eq!(vmcb.event_injection(), 0);
    assert_eq!(vmcb.virtual_interrupt_control(), nmi_control);
}
