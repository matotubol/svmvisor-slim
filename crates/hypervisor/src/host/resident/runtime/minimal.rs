//! Continuing minimal CPU policy over the shared interrupt/startup backend.
//! Native CPUID advertises physical SVM; nested execution remains unsupported.

use crate::{
    arch::x86_64::{capabilities::ValidatedCapabilities, registers::GuestRegisters},
    host::resident::runtime::State,
    svm::{
        control_msrs::{handle_visible_svm_controls, handle_visible_svm_controls_with_nrip},
        dispatch::{NativeMsrOutcome, NativeVmCrError},
        vmcb::{InstructionIntercept, Vmcb},
        vmcr::{handle_visible_vmcr, handle_visible_vmcr_with_nrip},
    },
};

/// Refuse profile drift before another entry, without changing guest state.
pub(super) fn valid(vmcb: &Vmcb) -> bool {
    vmcb.native_lbr_enabled() && valid_intercepts(vmcb)
}

/// Cold admission precedes configuring the branch-record hardware switch.
pub(super) fn valid_intercepts(vmcb: &Vmcb) -> bool {
    !vmcb.instruction_intercept(InstructionIntercept::Cpuid)
        && !vmcb.control_registers_intercepted()
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

pub(super) fn control_msrs(
    state: &mut State,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    instruction: &[u8],
) -> Result<NativeMsrOutcome, NativeVmCrError> {
    let owner = state.svm_controls.as_mut().ok_or(NativeVmCrError::UnsupportedInitialState)?;
    let vmcr = state.vmcr.as_ref().ok_or(NativeVmCrError::UnsupportedInitialState)?;
    let efer = state.efer.as_ref().ok_or(NativeVmCrError::UnsupportedInitialState)?;
    handle_visible_svm_controls(owner, vmcr, efer, vmcb, frame, instruction, state.startup_owned)
}

pub(super) fn control_msrs_with_nrip(
    state: &mut State,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    capabilities: &ValidatedCapabilities,
) -> Result<NativeMsrOutcome, NativeVmCrError> {
    let owner = state.svm_controls.as_mut().ok_or(NativeVmCrError::UnsupportedInitialState)?;
    let vmcr = state.vmcr.as_ref().ok_or(NativeVmCrError::UnsupportedInitialState)?;
    let efer = state.efer.as_ref().ok_or(NativeVmCrError::UnsupportedInitialState)?;
    handle_visible_svm_controls_with_nrip(
        owner,
        vmcr,
        efer,
        vmcb,
        frame,
        capabilities,
        state.startup_owned,
    )
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;

    #[test]
    fn runtime_requires_branch_record_ownership_after_cold_intercept_admission() {
        let mut vmcb = Vmcb::new();
        vmcb.configure_native_boot_intercepts().unwrap();
        assert!(valid_intercepts(&vmcb));
        assert!(!valid(&vmcb));
        assert!(vmcb.configure_native_lbr(0x8000_0022, 2, 7, 0x2106));
        assert!(valid(&vmcb));
    }

    #[test]
    fn native_cpuid_preserves_control_registers_and_required_svm_ownership() {
        let mut vmcb = Vmcb::new();
        vmcb.configure_native_boot_intercepts().unwrap();
        assert!(vmcb.configure_native_lbr(0x8000_0022, 2, 7, 0x2106));
        assert!(valid(&vmcb));
        vmcb.set_instruction_intercept(InstructionIntercept::Cpuid, true);
        assert!(!valid(&vmcb));
    }

    #[test]
    fn guest_init_and_sipi_preserve_native_cpuid_and_control_registers() {
        let mut vmcb = Vmcb::new();
        vmcb.configure_native_boot_intercepts().unwrap();
        assert!(vmcb.configure_native_lbr(0x8000_0022, 2, 7, 0x2106));
        vmcb.initialize_ap_after_init();
        assert!(valid(&vmcb));
        vmcb.start_ap_from_sipi(8);
        assert!(valid(&vmcb));
    }

    #[test]
    fn cr_intercepts_and_missing_svm_ownership_refuse_without_repairing_controls() {
        let cr_intercepts = (0..32)
            .map(|bit| (0x000, 1u32 << bit))
            .chain(core::iter::once((0x00c, 1 << 5)))
            .chain((16..32).map(|bit| (0x010, 1 << bit)));
        for (offset, mask) in cr_intercepts {
            let mut vmcb = Vmcb::new();
            vmcb.configure_native_boot_intercepts().unwrap();
            assert!(vmcb.configure_native_lbr(0x8000_0022, 2, 7, 0x2106));
            // SAFETY: exclusive inert VMCB; each offset is an aligned in-bounds
            // intercept dword. Inject profile drift while preserving required bits.
            unsafe {
                let word = ptr::from_mut(&mut vmcb).cast::<u8>().add(offset).cast::<u32>();
                word.write(word.read() | mask);
            }
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
            assert!(vmcb.configure_native_lbr(0x8000_0022, 2, 7, 0x2106));
            vmcb.set_instruction_intercept(intercept, false);
            let before = *vmcb.bytes();
            assert!(!valid(&vmcb));
            assert_eq!(vmcb.bytes(), &before);
        }
    }
}
