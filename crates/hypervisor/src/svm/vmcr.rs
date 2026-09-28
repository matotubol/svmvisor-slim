//! Bounded guest VM_CR semantics when CPUID executes on the native CPU.
//!
//! This owner preserves the admitted firmware VM_CR (zero, or LOCK alone) while the host
//! separately owns R_INIT and VM_HSAVE_PA. It does not write physical VM_CR or implement
//! nested SVM. PPR 57896 physical page 37 has firmware that enables SVM set LOCK, pages
//! 215-216 make LOCK read-only and a zero SvmLockKey never clears it. APM volume 2
//! physical pages 645-646 define reserved-bit faults, LOCK and SVMDIS versus EFER.SVME.

use crate::{
    arch::x86_64::{
        capabilities::ValidatedCapabilities,
        msr::{EFER_SVME, VM_CR, VM_CR_LOCK, VM_CR_MBZ, VM_CR_SVMDIS},
        registers::GuestRegisters,
    },
    svm::{
        dispatch::{
            NativeEfer, NativeMsrOutcome, NativeVmCrError, hardware_msr_instruction,
            native_startup_instruction_mode, validate_native_msr_boundary,
        },
        exit::MsrInstruction,
        vmcb::Vmcb,
    },
};

/// Admitted initial guest control state, not proof of same-CPU hardware ownership.
///
/// The runtime must sample VM_CR before setting its private R_INIT. Admission accepts
/// zero or LOCK alone, the firmware state with SVM enabled; R_INIT, SVMDIS and reserved
/// bits must be clear. INIT leaves LOCK unchanged (APM volume 2 physical page 645), so
/// guest INIT preserves this state. A guest attempt to change R_INIT, or to disable SVM
/// while LOCK is clear, is outside this bounded profile and stops before any change; it
/// is not falsely reported as an ignored write. With LOCK set, hardware ignores SVMDIS
/// writes and so does this owner. With logical SVME set, SVMDIS instead faults as
/// required by the architecture, regardless of LOCK.
/// The caller must separately admit the exact PPR 57896 target CPU signature; LOCK's
/// read-only behavior must not be generalized to arbitrary AMD implementations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VisibleVmCr(u64);

impl VisibleVmCr {
    pub fn admit(initial: u64) -> Result<Self, NativeVmCrError> {
        if initial & !VM_CR_LOCK != 0 {
            return Err(NativeVmCrError::UnsupportedInitialState);
        }
        Ok(Self(initial))
    }

    pub const fn logical(&self) -> u64 {
        self.0
    }
}

/// Handle an exclusively stopped VM_CR access using exact fetched instruction bytes.
/// The caller owns the same CPU's EFER state, event lifecycle and interrupt profile.
/// `startup_owned` requires the existing target-owned INIT/SIPI continuation contract.
pub fn handle_visible_vmcr(
    owner: &VisibleVmCr,
    efer: &NativeEfer,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    instruction: &[u8],
    startup_owned: bool,
) -> Result<NativeMsrOutcome, NativeVmCrError> {
    complete_vmcr(owner, efer, vmcb, frame, MsrInstruction::Bytes(instruction), startup_owned)
}

/// Hardware-decoded counterpart. Rejected provenance never falls back to invented bytes.
pub fn handle_visible_vmcr_with_nrip(
    owner: &VisibleVmCr,
    efer: &NativeEfer,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    capabilities: &ValidatedCapabilities,
    startup_owned: bool,
) -> Result<NativeMsrOutcome, NativeVmCrError> {
    let instruction = hardware_msr_instruction(vmcb, capabilities)?;
    complete_vmcr(owner, efer, vmcb, frame, instruction, startup_owned)
}

fn complete_vmcr(
    owner: &VisibleVmCr,
    efer: &NativeEfer,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    instruction: MsrInstruction<'_>,
    startup_owned: bool,
) -> Result<NativeMsrOutcome, NativeVmCrError> {
    validate_native_msr_boundary(vmcb, instruction, startup_owned)?;
    let snapshot = vmcb.exit_snapshot();
    let write = snapshot.info1 == 1;
    let index = frame.rcx as u32;
    if index != VM_CR {
        return Err(NativeVmCrError::UnsupportedMsr { index, write });
    }
    let logical_efer = efer.observe_backing(vmcb.guest_cr0(), vmcb.guest_efer())?;
    let input = (u64::from(frame.rdx as u32) << 32) | u64::from(vmcb.guest_rax() as u32);
    // Architectural faults precede unsupported profile changes, including mixed operands.
    // Neither backing SVME nor the host's private R_INIT is a guest control value.
    if vmcb.guest_cpl() != 0
        || (write
            && (input & VM_CR_MBZ != 0
                || (input & VM_CR_SVMDIS != 0 && logical_efer & EFER_SVME != 0)))
    {
        vmcb.queue_validated_msr_general_protection(instruction).map_err(NativeVmCrError::Fault)?;
        return Ok(NativeMsrOutcome::GeneralProtectionPrepared);
    }
    if (!startup_owned && !vmcb.guest_in_64_bit_code())
        || (startup_owned && !native_startup_instruction_mode(vmcb, instruction.length()))
    {
        return Err(NativeVmCrError::UnsupportedMode);
    }
    // Target LOCK is read-only; writing it alone is ignored. With LOCK set, SVMDIS is
    // read-only too (APM volume 2 physical page 645, PPR 57896 physical page 215). Every
    // remaining nonzero low field would change unimplemented guest controls or reserved
    // target state.
    let ignored =
        if owner.logical() & VM_CR_LOCK != 0 { VM_CR_LOCK | VM_CR_SVMDIS } else { VM_CR_LOCK };
    if write && input & !ignored != 0 {
        return Err(NativeVmCrError::UnsupportedValue { value: input });
    }
    let next = instruction.continuation(snapshot).map_err(NativeVmCrError::Instruction)?;
    let retirement = vmcb.prepare_native_msr_retirement()?;
    if write {
        vmcb.commit_emulated_instruction(vmcb.guest_rax(), next);
    } else {
        vmcb.commit_emulated_instruction(owner.logical(), next);
        frame.rdx = 0;
    }
    if vmcb.complete_native_msr_retirement(retirement) {
        Ok(NativeMsrOutcome::DebugTrapPrepared)
    } else {
        Ok(NativeMsrOutcome::Completed)
    }
}
