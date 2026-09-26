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
        assert!(!pending);
        assert_eq!(vmcb.virtual_interrupt_control(), control);
        assert_eq!(vmcb.event_injection(), 0x8000_0202);
        assert_eq!(vmcb.guest_rip(), 0x1234);
    }
}

#[test]
fn an_unfinished_owned_injection_cannot_be_silently_consumed() {
    let mut vmcb = Vmcb::new();
    put(&mut vmcb, 0x070, 0x400);
    put(&mut vmcb, 0x088, 0x8000_0b0d);
    put(&mut vmcb, 0x0a8, 0x8000_0b0d);
    let before = *vmcb.bytes();
    let mut pending = true;

    assert_eq!(
        vmcb.complete_event_delivery(&mut pending),
        Err(DeliveryError::InjectionCompletion(ReflectionError::NestedDeliveryUnsupported))
    );
    assert!(pending);
    assert_eq!(vmcb.bytes(), &before);

    put(&mut vmcb, 0x088, 0);
    assert_eq!(vmcb.complete_event_delivery(&mut pending), Ok(()));
    assert!(!pending);
    assert_eq!(vmcb.event_injection(), 0);
}

#[test]
fn invalid_entry_and_shutdown_preserve_poisoned_state_and_pending_obligation() {
    for code in [0x7f, u64::MAX] {
        let mut vmcb = Vmcb::new();
        put(&mut vmcb, 0x070, code);
        put(&mut vmcb, 0x088, u64::MAX);
        put(&mut vmcb, 0x0a8, u64::MAX);
        let before = *vmcb.bytes();
        let mut pending = true;

        assert_eq!(
            vmcb.complete_event_delivery(&mut pending),
            Err(DeliveryError::UnusableGuestState)
        );
        assert!(pending);
        assert_eq!(vmcb.bytes(), &before);
    }
}
