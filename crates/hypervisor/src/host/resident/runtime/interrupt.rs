//! Native physical LAPIC ownership with hardware virtual-NMI blocking.

use crate::{
    arch::x86_64::{apic, capabilities::ValidatedCapabilities},
    host::resident::runtime::msr::read_msr,
    svm::{
        permission_maps::{MsrAccess, Msrpm, Permission},
        vmcb::Vmcb,
    },
};

pub(super) struct CapturedInterrupts {
    host_apic_base: u64,
    icr_value: u64,
}

impl CapturedInterrupts {
    /// # Safety
    /// Owning native CPU, IF clear, with immutable admitted CPU and optional ICR inputs.
    pub(super) unsafe fn capture(
        caps: &ValidatedCapabilities,
        ids: &[u32],
        assigned_id: u32,
        initial_icr: *const u64,
    ) -> Result<Self, InterruptError> {
        let host_apic_base = unsafe { read_msr(apic::APIC_BASE) };
        if host_apic_base & ((1 << 11) | (1 << 10)) != (1 << 11) | (1 << 10)
            || !ids.contains(&assigned_id)
            || unsafe { read_msr(apic::ID_MSR) } != u64::from(assigned_id)
            || (!initial_icr.is_null()
                && (initial_icr as usize & 7 != 0
                    || caps.address_policy().validate(initial_icr as u64, 8, 8).is_err()))
        {
            return Err(InterruptError);
        }
        // The loader may have already sent its private startup notification.
        // Preserve the original captured guest ICR when supplied.
        let icr_value = if initial_icr.is_null() {
            unsafe { read_msr(apic::ICR_MSR) }
        } else {
            unsafe { initial_icr.read() }
        };
        Ok(Self { host_apic_base, icr_value: icr_value & !(1 << 12) })
    }

    pub(super) const fn host_apic_base(&self) -> u64 {
        self.host_apic_base
    }

    pub(super) const fn icr_value(&self) -> u64 {
        self.icr_value
    }

    pub(super) fn configure_msrpm(&self, msrpm: &mut Msrpm) {
        for access in [MsrAccess::Read, MsrAccess::Write] {
            msrpm.set(apic::ICR_MSR, access, Permission::Intercept).unwrap();
        }
    }
}

pub(super) struct InterruptError;

impl InterruptError {
    pub(super) const fn code(self) -> u64 {
        8
    }
}

/// Fixed interrupts remain physical; all NMIs use the admitted VNMI lifecycle.
/// V_TPR (bits 3:0) is guest state: with V_INTR_MASKING clear, guest CR8 writes update it
/// and every #VMEXIT writes it back (APM volume 2 physical pages 569, 595 and 802).
/// VNMI pending/mask are hardware writeback, not control drift (p598–599).
pub(super) fn validate_entry(vmcb: &Vmcb) -> bool {
    use crate::svm::vmcb::EventIntercept;
    !vmcb.event_intercept(EventIntercept::PhysicalInterrupt)
        && vmcb.event_intercept(EventIntercept::Nmi)
        && vmcb.nmi_virtualization_enabled()
        && vmcb.virtual_interrupt_control() & !(0xf | (1 << 11) | (1 << 12) | (1 << 26)) == 0
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;
    use crate::svm::vmcb::EventIntercept;

    #[test]
    fn guest_tpr_written_back_at_exit_is_not_control_drift() {
        // V_TPR 0xc and 2 are the guest CR8 values seen at #VMEXIT on hardware.
        for (control, valid) in
            [(0xc, true), (2, true), (0xf, true), (0x10, false), (1 << 8, false), (1 << 24, false)]
        {
            let mut vmcb = Vmcb::new();
            vmcb.configure_native_boot_intercepts().unwrap();
            vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
            // SAFETY: exclusive inert VMCB and its in-bounds offset 60h control field.
            unsafe {
                ptr::from_mut(&mut vmcb)
                    .cast::<u8>()
                    .add(0x60)
                    .cast::<u64>()
                    .write_unaligned(control | (1 << 26));
            }
            assert_eq!(validate_entry(&vmcb), valid, "{control:#x}");
        }
    }

    #[test]
    fn native_profile_requires_vnmi_and_keeps_fixed_interrupts_physical() {
        let mut vmcb = Vmcb::new();
        vmcb.configure_native_boot_intercepts().unwrap();
        assert!(!validate_entry(&vmcb));
        vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
        assert!(validate_entry(&vmcb));
        vmcb.set_event_intercept(EventIntercept::PhysicalInterrupt, true);
        assert!(!validate_entry(&vmcb));
        vmcb.set_event_intercept(EventIntercept::PhysicalInterrupt, false);
        vmcb.set_event_intercept(EventIntercept::Nmi, false);
        assert!(!validate_entry(&vmcb));
    }

    #[test]
    fn hardware_pending_and_mask_writeback_are_admitted_without_mutation() {
        for bits in [0, 1 << 11, 1 << 12, (1 << 11) | (1 << 12)] {
            let mut vmcb = Vmcb::new();
            vmcb.configure_native_boot_intercepts().unwrap();
            vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
            // Model hardware writeback, including an in-service NMI with
            // another pending. Software must leave unmasking to guest IRET.
            unsafe {
                ptr::from_mut(&mut vmcb)
                    .cast::<u8>()
                    .add(0x60)
                    .cast::<u64>()
                    .write_unaligned((1 << 26) | bits | 0xf);
            }
            let before = *vmcb.bytes();
            assert!(validate_entry(&vmcb));
            assert_eq!(*vmcb.bytes(), before);
        }
    }
}
