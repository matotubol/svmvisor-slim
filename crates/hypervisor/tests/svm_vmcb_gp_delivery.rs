use core::ptr;

use svmvisor_hypervisor::svm::{
    events::{DeliveryError, ReflectedException, ReflectionError},
    vmcb::Vmcb,
};

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: the test exclusively owns this inert page; all offsets are in bounds.
    unsafe {
        ptr::write_unaligned(ptr::from_mut(vmcb).cast::<u8>().add(offset).cast(), value);
    }
}

fn stopped(error_code: u64, interrupted: u64) -> Vmcb {
    let mut vmcb = Vmcb::new();
    for (offset, value) in [
        (0x008, 1 << 13),
        (0x070, 0x4d),
        (0x078, error_code),
        (0x080, u64::MAX),
        (0x088, interrupted),
        (0x090, 1),
        (0x0c0, u64::from(u32::MAX)),
        (0x0c8, u64::MAX),
        (0x558, 0x8000_0011),
        (0x570, 0x10302),
        (0x578, 0x1234_5678),
        (0x5d8, 0x8765_4321),
        (0x5f8, 0xdead_beef),
        (0x640, 0xabcd),
    ] {
        put(&mut vmcb, offset, value);
    }
    vmcb
}

fn interrupted_exception(vector: u8) -> u64 {
    let error = matches!(vector, 8 | 10..=14 | 17 | 21 | 29 | 30);
    0x8000_0300 | u64::from(vector) | if error { 1 << 11 } else { 0 }
}

fn assert_only_injection_changed(vmcb: &Vmcb, before: &[u8; 4096], injection: u64) {
    let mut expected = *before;
    expected[0x0a8..0x0b0].copy_from_slice(&injection.to_le_bytes());
    assert_eq!(vmcb.bytes(), &expected);
}

#[test]
fn ordinary_gp_preserves_its_error_code_and_all_saved_instruction_state() {
    for error_code in [0u32, 1, 0x28, 0xffff, u32::MAX] {
        for was_pending in [false, true] {
            let mut vmcb = stopped(u64::from(error_code), 0);
            let before = *vmcb.bytes();
            let mut pending = was_pending;
            assert_eq!(
                vmcb.reflect_general_protection_after_exit(&mut pending, false),
                Ok(ReflectedException::GeneralProtection { error_code }),
            );
            assert!(pending);
            assert_only_injection_changed(
                &vmcb,
                &before,
                (u64::from(error_code) << 32) | 0x8000_0b0d,
            );
        }
    }
}

#[test]
fn proven_instruction_gp_can_become_ud_only_without_delivery_or_selector_error() {
    let mut vmcb = stopped(0, 0);
    let before = *vmcb.bytes();
    let mut pending = false;
    assert_eq!(
        vmcb.reflect_general_protection_after_exit(&mut pending, true),
        Ok(ReflectedException::InvalidOpcode),
    );
    assert!(pending);
    assert_only_injection_changed(&vmcb, &before, 0x8000_0306);
    for (error_code, interrupted) in [(0x28, 0), (0, 0x8000_0306), (0, 0x8000_0051)] {
        let mut vmcb = stopped(error_code, interrupted);
        let before = *vmcb.bytes();
        let mut pending = false;
        assert!(vmcb.reflect_general_protection_after_exit(&mut pending, true).is_err());
        assert!(!pending);
        assert_eq!(vmcb.bytes(), &before);
    }
}

#[test]
fn contributory_and_page_fault_delivery_followed_by_gp_become_double_fault() {
    for vector in [0, 10, 11, 12, 13, 14, 21, 29, 30] {
        for was_pending in [false, true] {
            let mut vmcb = stopped(0x2b, interrupted_exception(vector));
            let before = *vmcb.bytes();
            let mut pending = was_pending;
            assert_eq!(
                vmcb.reflect_general_protection_after_exit(&mut pending, false),
                Ok(ReflectedException::DoubleFault),
            );
            assert!(pending);
            assert_only_injection_changed(&vmcb, &before, 0x8000_0b08);
        }
    }
}

#[test]
fn benign_exception_delivery_gp_replaces_the_prior_event_including_injected_ud() {
    for vector in [1, 3, 4, 5, 6, 7, 16, 17, 18, 19, 28] {
        let mut vmcb = stopped(0x28, interrupted_exception(vector));
        let before = *vmcb.bytes();
        let mut pending = true;
        assert_eq!(
            vmcb.reflect_general_protection_after_exit(&mut pending, false),
            Ok(ReflectedException::GeneralProtection { error_code: 0x28 }),
        );
        assert!(pending);
        assert_only_injection_changed(&vmcb, &before, 0x28_8000_0b0d);
    }
}

#[test]
fn event_type_keeps_external_nmi_and_intn_benign_even_with_exception_vectors() {
    for kind in [0u64, 2, 4] {
        for vector in [0, 2, 8, 13, 14, 0xff] {
            // EV=0 makes the old error half undefined; reserved bits are never
            // reused. INTn need not be re-injected: the actual GP replaces it.
            let interrupted = 0xdead_beef_8000_7000 | (kind << 8) | vector;
            let mut vmcb = stopped(0x83, interrupted);
            let before = *vmcb.bytes();
            let mut pending = false;
            assert_eq!(
                vmcb.reflect_general_protection_after_exit(&mut pending, false),
                Ok(ReflectedException::GeneralProtection { error_code: 0x83 }),
            );
            assert!(pending);
            assert_only_injection_changed(&vmcb, &before, 0x83_8000_0b0d);
        }
    }
}

#[test]
fn double_fault_delivery_gp_reports_shutdown_without_mutating_saved_evidence() {
    for was_pending in [false, true] {
        let mut vmcb = stopped(0x28, 0x8000_0b08);
        let before = *vmcb.bytes();
        let mut pending = was_pending;
        assert_eq!(
            vmcb.reflect_general_protection_after_exit(&mut pending, false),
            Err(ReflectionError::GuestShutdown),
        );
        assert_eq!(pending, was_pending);
        assert_eq!(vmcb.bytes(), &before);
    }
}

#[test]
fn real_and_paged_real_delivery_never_push_an_error_code() {
    for cr0 in [0x10, 0x8000_0010] {
        for (interrupted, expected, vector) in [
            (0, ReflectedException::GeneralProtection { error_code: 0x28 }, 13),
            (0xdead_beef_8000_030d, ReflectedException::DoubleFault, 8),
            (0xdead_beef_8000_030e, ReflectedException::DoubleFault, 8),
            (0xdead_beef_8000_0306, ReflectedException::GeneralProtection { error_code: 0x28 }, 13),
        ] {
            let mut vmcb = stopped(0x28, interrupted);
            put(&mut vmcb, 0x558, cr0);
            let before = *vmcb.bytes();
            let mut pending = true;
            assert_eq!(
                vmcb.reflect_general_protection_after_exit(&mut pending, false),
                Ok(expected),
            );
            assert!(pending);
            assert_only_injection_changed(&vmcb, &before, 0x8000_0300 | vector);
        }
        let mut vmcb = stopped(0, 0xdead_beef_8000_0308);
        put(&mut vmcb, 0x558, cr0);
        let before = *vmcb.bytes();
        let mut pending = false;
        assert_eq!(
            vmcb.reflect_general_protection_after_exit(&mut pending, false),
            Err(ReflectionError::GuestShutdown),
        );
        assert!(!pending);
        assert_eq!(vmcb.bytes(), &before);
    }
}

#[test]
fn virtual8086_faults_use_the_protected_mode_error_frame() {
    let mut vmcb = stopped(0x28, 0);
    put(&mut vmcb, 0x570, 0x2_0002);
    let before = *vmcb.bytes();
    let mut pending = false;
    assert_eq!(
        vmcb.reflect_general_protection_after_exit(&mut pending, false),
        Ok(ReflectedException::GeneralProtection { error_code: 0x28 }),
    );
    assert_only_injection_changed(&vmcb, &before, 0x28_8000_0b0d);
}

#[test]
fn invalid_exit_error_event_or_profile_and_new_injections_refuse_transactionally() {
    for (offset, value) in [
        (0x070, 0x7f),
        (0x070, u64::MAX),
        (0x070, 0x7c),
        (0x078, 1 << 32),
        (0x0a8, 0x8000_0306),
        (0x060, 1 << 8),
        (0x060, 1 << 25),
        (0x090, 3),
        (0x088, 0x8000_0100),
        (0x088, 0x8000_0500),
        (0x088, 0x8000_080d),
        (0x088, 0x8000_0a02),
        (0x088, 0x8000_0c03),
        (0x088, 0x8000_0302),
        (0x088, 0x8000_0309),
        (0x088, 0x8000_030f),
        (0x088, 0x8000_031f),
        (0x088, 0x8000_030d),
        (0x088, 0x8000_0b06),
        (0x088, 0x1_8000_0b08),
        (0x088, 0x1_8000_0b11),
    ] {
        for was_pending in [false, true] {
            let mut vmcb = stopped(0, 0);
            put(&mut vmcb, offset, value);
            let before = *vmcb.bytes();
            let mut pending = was_pending;
            assert!(vmcb.reflect_general_protection_after_exit(&mut pending, false).is_err());
            assert_eq!(pending, was_pending);
            assert_eq!(vmcb.bytes(), &before);
        }
    }
}

#[test]
fn generic_delivery_cannot_blindly_reinject_an_event_after_a_gp_exit() {
    let mut vmcb = stopped(0, 0x8000_0306);
    let before = *vmcb.bytes();
    let mut pending = true;
    assert_eq!(
        vmcb.complete_event_delivery(&mut pending),
        Err(DeliveryError::InjectionCompletion(ReflectionError::UnsupportedExit { code: 0x4d })),
    );
    assert!(pending);
    assert_eq!(vmcb.bytes(), &before);
}

#[test]
fn reflected_injection_interrupted_by_nonexception_exit_is_retried_then_consumed() {
    let mut vmcb = stopped(0x28, 0);
    let mut pending = false;
    vmcb.reflect_general_protection_after_exit(&mut pending, false).unwrap();
    let fault = vmcb.event_injection();
    // Model the subsequent real VMEXIT during the injected GP's delivery.
    put(&mut vmcb, 0x070, 0x400);
    put(&mut vmcb, 0x088, fault);
    put(&mut vmcb, 0x0a8, 0);
    let before = *vmcb.bytes();
    assert_eq!(vmcb.complete_event_delivery(&mut pending), Ok(()));
    assert!(pending);
    assert_only_injection_changed(&vmcb, &before, fault);
    // Delivery succeeds before a later unrelated exit.
    put(&mut vmcb, 0x070, 0x77);
    put(&mut vmcb, 0x088, 0);
    put(&mut vmcb, 0x0a8, 0);
    let before = *vmcb.bytes();
    assert_eq!(vmcb.complete_event_delivery(&mut pending), Ok(()));
    assert!(!pending);
    assert_eq!(vmcb.bytes(), &before);
}

#[test]
fn failed_retry_preserves_the_owned_injection_obligation() {
    for (interrupted, injection) in [(0x8000_0451, 0), (0x8000_0b0d, 0x8000_0b0d)] {
        let mut vmcb = stopped(0, interrupted);
        put(&mut vmcb, 0x070, 0x400);
        put(&mut vmcb, 0x0a8, injection);
        let before = *vmcb.bytes();
        let mut pending = true;
        assert!(vmcb.complete_event_delivery(&mut pending).is_err());
        assert!(pending);
        assert_eq!(vmcb.bytes(), &before);
    }
}
