//! Continuing minimal CPU policy over the shared interrupt/startup backend.
//! Native CPUID advertises physical SVM; nested execution remains unsupported.

use crate::{
    arch::x86_64::{capabilities::ValidatedCapabilities, registers::GuestRegisters},
    host::resident::runtime::State,
    svm::{
        dispatch::{NativeMsrOutcome, NativeVmCrError},
        vmcb::{InstructionIntercept, Vmcb},
        vmcr::{handle_visible_vmcr, handle_visible_vmcr_with_nrip},
    },
};

/// Refuse profile drift before another entry, without changing guest state.
pub(super) fn valid(vmcb: &Vmcb) -> bool {
    !vmcb.instruction_intercept(InstructionIntercept::Cpuid)
        && !vmcb.cr3_intercepted()
        && [
            InstructionIntercept::Vmrun,
            InstructionIntercept::Vmmcall,
            InstructionIntercept::Vmload,
            InstructionIntercept::Vmsave,
            InstructionIntercept::Stgi,
            InstructionIntercept::Clgi,
            InstructionIntercept::Skinit,
            InstructionIntercept::Invlpga,
            InstructionIntercept::Msr,
        ]
        .into_iter()
        .all(|intercept| vmcb.instruction_intercept(intercept))
}

pub(super) fn vmcr(
    state: &State,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    instruction: &[u8],
) -> Result<NativeMsrOutcome, NativeVmCrError> {
    let owner = state.vmcr.as_ref().ok_or(NativeVmCrError::UnsupportedInitialState)?;
    let efer = state.efer.as_ref().ok_or(NativeVmCrError::UnsupportedInitialState)?;
    handle_visible_vmcr(owner, efer, vmcb, frame, instruction, state.startup_owned)
}

pub(super) fn vmcr_with_nrip(
    state: &State,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    capabilities: &ValidatedCapabilities,
) -> Result<NativeMsrOutcome, NativeVmCrError> {
    let owner = state.vmcr.as_ref().ok_or(NativeVmCrError::UnsupportedInitialState)?;
    let efer = state.efer.as_ref().ok_or(NativeVmCrError::UnsupportedInitialState)?;
    handle_visible_vmcr_with_nrip(owner, efer, vmcb, frame, capabilities, state.startup_owned)
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;

    #[test]
    fn native_cpuid_preserves_cr3_and_required_svm_ownership() {
        let mut vmcb = Vmcb::new();
        vmcb.configure_native_boot_intercepts().unwrap();
        assert!(valid(&vmcb));
        vmcb.set_instruction_intercept(InstructionIntercept::Cpuid, true);
        assert!(!valid(&vmcb));
    }

    #[test]
    fn guest_init_and_sipi_preserve_native_cpuid_and_cr3_controls() {
        let mut vmcb = Vmcb::new();
        vmcb.configure_native_boot_intercepts().unwrap();
        vmcb.initialize_ap_after_init();
        assert!(valid(&vmcb));
        vmcb.start_ap_from_sipi(8);
        assert!(valid(&vmcb));
    }

    #[test]
    fn cr3_traps_and_missing_svm_ownership_refuse_without_repairing_controls() {
        for cr3 in [1u32 << 3, 1u32 << 19] {
            let mut vmcb = Vmcb::new();
            vmcb.configure_native_boot_intercepts().unwrap();
            // SAFETY: exclusive inert VMCB and its in-bounds CR intercept dword.
            unsafe { ptr::from_mut(&mut vmcb).cast::<u32>().write(cr3) };
            let before = *vmcb.bytes();
            assert!(!valid(&vmcb));
            assert_eq!(vmcb.bytes(), &before);
        }
        for intercept in [
            InstructionIntercept::Vmrun,
            InstructionIntercept::Vmmcall,
            InstructionIntercept::Vmload,
            InstructionIntercept::Vmsave,
            InstructionIntercept::Stgi,
            InstructionIntercept::Clgi,
            InstructionIntercept::Skinit,
            InstructionIntercept::Invlpga,
            InstructionIntercept::Msr,
        ] {
            let mut vmcb = Vmcb::new();
            vmcb.configure_native_boot_intercepts().unwrap();
            vmcb.set_instruction_intercept(intercept, false);
            let before = *vmcb.bytes();
            assert!(!valid(&vmcb));
            assert_eq!(vmcb.bytes(), &before);
        }
    }
}
