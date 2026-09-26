//! PAUSE exits are retained only while existing maintenance work can use them.

use crate::svm::vmcb::{InstructionIntercept, Vmcb};

/// Native INIT notifications, rather than spin-loop exits, wake peers for
/// startup commands, cache rendezvous and terminal requests. Retain the old
/// filter through startup and while a deferred host NMI needs
/// another exit. Guests without PAUSE never had a bounded progress guarantee.
/// This changes no guest instruction, flags or pending event.
pub(super) fn prepare_pause(
    vmcb: &mut Vmcb,
    supported: bool,
    guest_started: bool,
    nmi_pending: bool,
) {
    let enabled = supported && (!guest_started || nmi_pending);
    if vmcb.instruction_intercept(InstructionIntercept::Pause) != enabled {
        vmcb.set_instruction_intercept(InstructionIntercept::Pause, enabled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steady_state_releases_pause_and_each_deferred_service_rearms_it() {
        let mut vmcb = Vmcb::new();
        vmcb.configure_native_boot_intercepts().unwrap();
        assert!(vmcb.configure_native_pause_filter(1 << 10));
        vmcb.queue_native_nmi().unwrap();
        let event = vmcb.event_injection();
        let rip = vmcb.guest_rip();
        for (started, nmi, enabled) in
            [(false, false, true), (true, false, false), (true, true, true), (true, false, false)]
        {
            prepare_pause(&mut vmcb, true, started, nmi);
            assert_eq!(vmcb.instruction_intercept(InstructionIntercept::Pause), enabled);
            assert_eq!(vmcb.event_injection(), event);
            assert_eq!(vmcb.guest_rip(), rip);
            assert!(!vmcb.instruction_intercept(InstructionIntercept::Cpuid));
            assert!(!vmcb.instruction_intercept(InstructionIntercept::Rdtsc));
        }
    }

    #[test]
    fn unsupported_filter_keeps_pause_native_even_with_work_pending() {
        let mut vmcb = Vmcb::new();
        vmcb.configure_native_boot_intercepts().unwrap();
        let before = *vmcb.bytes();
        prepare_pause(&mut vmcb, false, false, true);
        assert_eq!(*vmcb.bytes(), before);
    }
}
