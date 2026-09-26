//! Faults for intercepted SVM instructions under the native CPUID contract.
//!
//! Logical EFER.SVME is independent of the VMCB's mandatory SVME backing. This
//! owner repairs faults hidden by that backing without claiming nested execution
//! or implementing GIF/secure-launch state. Legal operations remain unsupported.
//! APM volume 3 physical pages 417, 431, 507, 514, 535, 541 and 543.

use crate::{
    arch::x86_64::{capabilities::ValidatedCapabilities, msr::EFER_SVME},
    svm::{
        dispatch::{NativeEfer, NativeEferError},
        events::ExternalInterruptError,
        vmcb::Vmcb,
    },
};

/// Same-CPU feature evidence; no CPUID result is changed by this owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeSvmInstructions {
    svm_lock: bool,
    skinit: bool,
}

impl NativeSvmInstructions {
    /// The caller supplies Fn8000_0001_ECX and Fn8000_000A_EDX from the same
    /// CPU as `capabilities` and the stopped native guest. The validated SVM
    /// capability is required independently of the two optional instruction
    /// gates. Neither SKINIT nor SVML may be inferred merely from SVM support.
    /// PPR 57896 physical pages 87 and 101 define these CPUID bit positions.
    pub fn admit_native(
        _capabilities: &ValidatedCapabilities,
        extended_cpuid_ecx: u32,
        svm_cpuid_edx: u32,
    ) -> Result<Self, NativeSvmInstructionError> {
        if extended_cpuid_ecx & (1 << 2) == 0 {
            return Err(NativeSvmInstructionError::SvmNotEnumerated);
        }
        Ok(Self {
            svm_lock: svm_cpuid_edx & (1 << 2) != 0,
            skinit: extended_cpuid_ecx & (1 << 12) != 0,
        })
    }

    /// STGI and SKINIT have independent enable gates (APM3 physical pages 507 and 514).
    /// Every other owned instruction requires logical EFER.SVME.
    pub(crate) const fn requires_svme(&self, instruction: NativeSvmInstruction) -> bool {
        !(matches!(instruction, NativeSvmInstruction::Stgi | NativeSvmInstruction::Skinit)
            && (self.svm_lock || self.skinit))
    }
}

/// Hardware-decoded instruction identities (APM volume 2 physical page 819).
/// VMMCALL is handled separately by the one-shot bootstrap and unclaimed-call dispatcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeSvmInstruction {
    Invlpga,
    Vmrun,
    Vmload,
    Vmsave,
    Stgi,
    Clgi,
    Skinit,
}

impl NativeSvmInstruction {
    pub const fn from_exit_code(code: u64) -> Option<Self> {
        Some(match code {
            0x7a => Self::Invlpga,
            0x80 => Self::Vmrun,
            0x82 => Self::Vmload,
            0x83 => Self::Vmsave,
            0x84 => Self::Stgi,
            0x85 => Self::Clgi,
            0x86 => Self::Skinit,
            _ => return None,
        })
    }

    pub const fn exit_code(self) -> u64 {
        match self {
            Self::Invlpga => 0x7a,
            Self::Vmrun => 0x80,
            Self::Vmload => 0x82,
            Self::Vmsave => 0x83,
            Self::Stgi => 0x84,
            Self::Clgi => 0x85,
            Self::Skinit => 0x86,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeSvmInstructionOutcome {
    /// Fault queued at the original RIP; actual delivery has not executed.
    InvalidOpcodePrepared,
    /// Fault queued at the original RIP with error code zero.
    GeneralProtectionPrepared,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeSvmInstructionError {
    SvmNotEnumerated,
    UnexpectedExit {
        code: u64,
    },
    Efer(NativeEferError),
    PendingState(ExternalInterruptError),
    /// No covered architectural fault applies. This owner does not execute
    /// nested SVM, emulate GIF, launch a secure loader, or validate operands.
    UnsupportedInstruction {
        instruction: NativeSvmInstruction,
    },
}

/// Resolve the architectural state faults for an exclusively stopped SVM exit.
/// No instruction fetch, fabricated opcode or next-RIP value is needed. Faults
/// preserve the faulting RIP, all GPRs, flags, and logical/backing EFER.
///
/// The caller owns the actual exit and completes prior event-delivery accounting
/// first. Pending injection or interrupted delivery is never overwritten. APM2
/// physical page 577 checks #GP before these intercepts: hardware may fault before
/// reaching this owner, which does not rewrite separately intercepted exceptions.
/// Operand/address checks that hardware already performed are not reconstructed.
///
/// STGI and SKINIT remain recognized with SVME clear when either SVML or SKINIT
/// is enumerated (APM3 physical pages 507 and 514). A legal STGI is deliberately
/// not treated as a no-op: this owner has no guest GIF lifecycle proof.
pub fn handle_native_svm_instruction(
    owner: &NativeSvmInstructions,
    efer: &NativeEfer,
    vmcb: &mut Vmcb,
) -> Result<NativeSvmInstructionOutcome, NativeSvmInstructionError> {
    let code = vmcb.exit_snapshot().code;
    let instruction = NativeSvmInstruction::from_exit_code(code)
        .ok_or(NativeSvmInstructionError::UnexpectedExit { code })?;
    let logical_efer = efer
        .observe_backing(vmcb.guest_cr0(), vmcb.guest_efer())
        .map_err(NativeSvmInstructionError::Efer)?;
    // Mode and enable faults precede privilege faults. VM86 is not an admitted
    // protected execution mode for these instructions (APM3 exception tables).
    let fault = if vmcb.guest_cr0() & 1 == 0
        || vmcb.guest_rflags() & (1 << 17) != 0
        || (logical_efer & EFER_SVME == 0 && owner.requires_svme(instruction))
    {
        NativeSvmInstructionOutcome::InvalidOpcodePrepared
    } else if vmcb.guest_cpl() != 0 {
        NativeSvmInstructionOutcome::GeneralProtectionPrepared
    } else {
        return Err(NativeSvmInstructionError::UnsupportedInstruction { instruction });
    };
    vmcb.queue_svm_instruction_fault(instruction, fault)
        .map_err(NativeSvmInstructionError::PendingState)?;
    Ok(fault)
}
