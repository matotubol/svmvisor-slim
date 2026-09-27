//! Transactional synthetic instruction emulation over retained state.
//! Caller must supply the snapshot and frame from the same stopped guest.
//! RIP equality detects a stale instruction, not hardware provenance. No CPU
//! entry, interrupt delivery, state capture or physical teardown happens here.

use crate::{
    arch::x86_64::{
        capabilities::ValidatedCapabilities,
        msr::{EFER, EFER_SVME},
        registers::GuestRegisters,
    },
    svm::{exit::ResumeError, vmcb::Vmcb},
};

const NATIVE_EFER_MASK: u64 = 0xd01;
const CPUID_EXTENDED_SVM: u32 = 1 << 2;

/// Logical native EFER, separate from the VMCB's mandatory SVME backing.
/// Admission matches the native long-mode continuation, not a general CPU
/// model. APM2 rev3.44 3.1.7, 14.6.2/Table14-5, 15.5 and 15.11.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeEfer {
    logical: u64,
    native_features: u64,
    unsupported_features: u64,
    nx_supported: bool,
    startup_owned: bool,
}

impl NativeEfer {
    /// Same-CPU native CPUID evidence: Fn80000001 ECX/EDX, Fn80000008 EBX and optional
    /// Fn80000021 EAX, read only when that leaf is enumerated. The caller owns
    /// direct guest FXSR/TLB execution and VMRUN/VMEXIT EFER switching; this
    /// constructor does not establish that execution contract itself.
    /// PPR57896 rev3.00 pp87-88/117/186; APM2 rev3.44 pp57-58/68/502/507.
    pub fn admit_native(
        original_efer: u64,
        extended_ecx: u32,
        extended_edx: u32,
        extended8_ebx: u32,
        extended21_eax: Option<u32>,
    ) -> Result<Self, NativeEferError> {
        Self::admit_native_profile(
            original_efer,
            extended_ecx,
            extended_edx,
            extended8_ebx,
            extended21_eax,
            false,
        )
    }

    /// EFER semantics for a guest whose native CPUID exposes SVM.
    ///
    /// The caller must intercept EFER reads/writes and all guest SVM instructions. Logical
    /// SVME transitions are allowed while the actual VMCB always retains required SVME.
    /// This is register-state emulation, not nested virtualization: attempting a nested
    /// SVM operation still requires an explicit unsupported-execution stop policy.
    /// No CPUID result is changed by this owner.
    ///
    /// APM volume 2 physical pages 117–119 and 566–567; PPR 57896 physical page 186.
    /// Same-CPU SVM support must be present in Fn8000_0001_ECX[2]; VM_CR must already
    /// have been admitted with SVMDIS clear by the runtime's independent capability owner.
    pub fn admit_native_visible_svm(
        original_efer: u64,
        extended_ecx: u32,
        extended_edx: u32,
        extended8_ebx: u32,
        extended21_eax: Option<u32>,
    ) -> Result<Self, NativeEferError> {
        if extended_ecx & CPUID_EXTENDED_SVM == 0 {
            return Err(NativeEferError::UnsupportedInitialState);
        }
        Self::admit_native_profile(
            original_efer,
            extended_ecx,
            extended_edx,
            extended8_ebx,
            extended21_eax,
            true,
        )
    }

    fn admit_native_profile(
        original_efer: u64,
        extended_ecx: u32,
        extended_edx: u32,
        extended8_ebx: u32,
        extended21_eax: Option<u32>,
        svm_visible: bool,
    ) -> Result<Self, NativeEferError> {
        let features = if extended_edx & (1 << 25) != 0 { 1 << 14 } else { 0 }
            | if extended_ecx & (1 << 17) != 0 { 1 << 15 } else { 0 }
            | if extended8_ebx & (1 << 13) != 0 { 1 << 18 } else { 0 }
            | if extended21_eax.is_some_and(|eax| eax & (1 << 7) != 0) { 1 << 20 } else { 0 }
            | if extended21_eax.is_some_and(|eax| eax & (1 << 8) != 0) { 1 << 21 } else { 0 }
            | if svm_visible { EFER_SVME } else { 0 };
        // APM2 p55: enabling a processor-absent feature faults. Keep that
        // distinct from a supported feature outside our execution coverage.
        // PPR99: LMSLE unsupported is explicit MBZ; MCOMMIT has its own gate.
        let available = features
            | if extended_edx & (1 << 11) != 0 { 1 } else { 0 }
            | if extended_edx & (1 << 29) != 0 { 1 << 8 } else { 0 }
            | if extended_edx & (1 << 20) != 0 { 1 << 11 } else { 0 }
            | if extended8_ebx & (1 << 8) != 0 { 1 << 17 } else { 0 };
        let unsupported = ((1
            | (1 << 8)
            | (1 << 11)
            | (1 << 14)
            | (1 << 15)
            | (1 << 17)
            | (1 << 18)
            | (1 << 20)
            | (1 << 21))
            & !available)
            | if svm_visible { 0 } else { EFER_SVME }
            | if extended8_ebx & (1 << 20) != 0 { 1 << 13 } else { 0 };
        Self::admit_mask(original_efer, extended_edx & (1 << 20) != 0, features, unsupported)
    }

    fn admit_mask(
        original_efer: u64,
        nx_supported: bool,
        native_features: u64,
        unsupported_features: u64,
    ) -> Result<Self, NativeEferError> {
        if original_efer & !(NATIVE_EFER_MASK | native_features) != 0
            || original_efer & unsupported_features != 0
            || original_efer & 0x500 != 0x500
            || (!nx_supported && original_efer & 0x800 != 0)
        {
            return Err(NativeEferError::UnsupportedInitialState);
        }
        Ok(Self {
            logical: original_efer,
            native_features,
            unsupported_features,
            nx_supported,
            startup_owned: false,
        })
    }

    pub const fn logical(&self) -> u64 {
        self.logical
    }

    /// Observe hardware-derived LMA after native CR0 changes without committing the owner.
    /// Every other stored EFER bit must still match the last owned write. This lifecycle
    /// check is independent of how CPUID exposes SVM and of the interrupt profile.
    pub(crate) fn observe_backing(&self, cr0: u64, backing: u64) -> Result<u64, NativeEferError> {
        let logical = if self.startup_owned {
            let expected_lma =
                if cr0 & (1 << 31) != 0 && self.logical & (1 << 8) != 0 { 1 << 10 } else { 0 };
            (self.logical & !(1 << 10)) | expected_lma
        } else {
            self.logical
        };
        if backing != (logical | EFER_SVME) {
            return Err(NativeEferError::BackingMismatch);
        }
        Ok(logical)
    }

    /// Opt in only with target-owned INIT and the native startup IRQ owner.
    /// This permits legacy unpaged execution; paging/segment fetch admission
    /// remains the caller's responsibility. APM2 14.6 and 15.13.1.
    pub fn enable_guest_startup(&mut self) {
        self.startup_owned = true;
    }

    /// Target owner calls after committing the matching VMCB INIT state.
    /// INIT clears logical EFER; mandatory SVM backing remains private.
    pub fn reset_after_init(&mut self) -> Result<(), NativeEferError> {
        if !self.startup_owned {
            return Err(NativeEferError::UnsupportedMode);
        }
        self.logical = 0;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeMsrOutcome {
    Completed,
    /// Fault retry at the original RIP. Delivery has not yet executed.
    GeneralProtectionPrepared,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeEferError {
    UnsupportedInitialState,
    BackingMismatch,
    UnsupportedMode,
    UnsupportedDebugState,
    UnsupportedMsr {
        index: u32,
        write: bool,
    },
    /// Legal or feature-dependent settings outside the current owner are a
    /// terminal refusal, never an invented architectural #GP.
    UnsupportedValue {
        value: u64,
    },
    Instruction(ResumeError),
    PendingState(super::events::ExternalInterruptError),
    Fault(super::events::MsrFaultError),
}

pub type NativeVmCrError = NativeEferError;

/// Exact unprefixed EFER RDMSR/WRMSR, using this stopped guest's owned bytes.
/// No hardware MSR access occurs. Writes preserve all GPRs; reads zero-extend
/// EDX:EAX. Refusal preserves the owner, VMCB and frame. Guest faults only
/// queue #GP(0), preserving RIP and registers; caller must account for EVENTINJ
/// after actual entry before another dispatch. Other intercepted MSRs stop.
pub fn handle_native_efer(
    owner: &mut NativeEfer,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    instruction: &[u8],
) -> Result<NativeMsrOutcome, NativeEferError> {
    native_efer_inner(owner, vmcb, frame, super::exit::MsrInstruction::Bytes(instruction))
}

/// Complete a hardware-decoded EFER MSR using same-CPU NRIPS evidence.
/// Caller supplies the actual exclusively stopped native VMCB/frame and its
/// CPU capabilities. Common opcode/CPL faults precede MSR interception; EFER
/// value faults still belong to the shared semantic owner (APM2 15.11).
/// No instruction memory is read and no opcode bytes are fabricated.
pub fn handle_native_efer_with_nrip(
    owner: &mut NativeEfer,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    caps: &ValidatedCapabilities,
) -> Result<NativeMsrOutcome, NativeEferError> {
    let evidence = hardware_msr_instruction(vmcb, caps)?;
    native_efer_inner(owner, vmcb, frame, evidence)
}

pub(crate) fn hardware_msr_instruction(
    vmcb: &Vmcb,
    caps: &ValidatedCapabilities,
) -> Result<super::exit::MsrInstruction<'static>, NativeEferError> {
    let bytes = vmcb.bytes();
    let cr0 = u64::from_le_bytes(bytes[0x558..0x560].try_into().unwrap());
    let cr4 = u64::from_le_bytes(bytes[0x548..0x550].try_into().unwrap());
    let cs = u16::from_le_bytes(bytes[0x412..0x414].try_into().unwrap());
    if !vmcb.guest_in_64_bit_code()
        || bytes[0x4cb] != 0
        || cs & 0x600 != 0x200
        || cr0 & 0x8000_0001 != 0x8000_0001
        || cr4 & (1 << 5) == 0
        || cr4 & (1 << 12) != 0
        || vmcb.guest_rflags() & (1 << 17) != 0
    {
        return Err(NativeEferError::UnsupportedMode);
    }
    let evidence = super::exit::MsrInstruction::hardware(vmcb.exit_snapshot(), caps)
        .map_err(NativeEferError::Instruction)?;
    Ok(evidence)
}

pub(crate) fn validate_native_msr_boundary(
    vmcb: &Vmcb,
    instruction: super::exit::MsrInstruction<'_>,
    startup_owned: bool,
) -> Result<(), NativeEferError> {
    use NativeEferError as E;
    let snapshot = vmcb.exit_snapshot();
    instruction.validate(snapshot).map_err(E::Instruction)?;
    vmcb.validate_external_interrupt_conflicts().map_err(E::PendingState)?;
    validate_native_interrupt_profile(vmcb, startup_owned).map_err(E::PendingState)?;
    Ok(())
}

/// Bounded sequential legacy completion: refuse segment/IP wrap rather than
/// applying long64 RIP arithmetic to a 16/32-bit instruction. Actual opcode
/// provenance and physical backing are checked by the caller's fetch owner.
pub(crate) fn native_startup_instruction_mode(vmcb: &Vmcb, length: usize) -> bool {
    let bytes = vmcb.bytes();
    let cr0 = u64::from_le_bytes(bytes[0x558..0x560].try_into().unwrap());
    let efer = u64::from_le_bytes(bytes[0x4d0..0x4d8].try_into().unwrap());
    let cs = u16::from_le_bytes(bytes[0x412..0x414].try_into().unwrap());
    if vmcb.guest_in_64_bit_code() {
        return true;
    }
    if cr0 & (1 << 31) != 0
        || efer & (1 << 10) != 0
        || cs & 0x200 != 0
        || cs & 0x98 != 0x98
        || vmcb.guest_rflags() & (1 << 17) != 0
    {
        return false;
    }
    let limit = u32::from_le_bytes(bytes[0x414..0x418].try_into().unwrap()) as u64;
    let ip_limit = if cs & 0x400 != 0 { u32::MAX as u64 } else { u16::MAX as u64 };
    vmcb.guest_rip().checked_add(length as u64).is_some_and(|next| next <= limit.min(ip_limit))
}

fn native_efer_inner(
    owner: &mut NativeEfer,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    instruction: super::exit::MsrInstruction<'_>,
) -> Result<NativeMsrOutcome, NativeEferError> {
    use NativeEferError as E;
    let snapshot = vmcb.exit_snapshot();
    validate_native_msr_boundary(vmcb, instruction, owner.startup_owned)?;
    let backing = u64::from_le_bytes(vmcb.bytes()[0x4d0..0x4d8].try_into().unwrap());
    let cr0 = u64::from_le_bytes(vmcb.bytes()[0x558..0x560].try_into().unwrap());
    // A direct guest MOV CR0 derives LMA in hardware. Only that read-only bit
    // may differ from the last owned EFER write; validate it before committing
    // a new logical observation. Failed emulation leaves the owner unchanged.
    let logical = owner.observe_backing(cr0, backing)?;
    let index = frame.rcx as u32;
    let write = snapshot.info1 == 1;
    if index != EFER {
        return Err(E::UnsupportedMsr { index, write });
    }
    let input = ((frame.rdx as u32 as u64) << 32) | vmcb.guest_rax() as u32 as u64;
    // Fig3-9 MBZ is distinct from RAZ7:1. LMA writes must preserve hardware
    // state; changing LME while PG=1 faults (Table14-5). Unadmitted defined
    // controls and RAZ writes are explicitly outside this owner. SVME follows
    // the constructor's CPUID contract.
    const MBZ: u64 = !0x0036_fdff;
    let fault = vmcb.bytes()[0x4cb] != 0
        || (write
            && (input & (MBZ | owner.unsupported_features) != 0
                || (input ^ logical) & (1 << 10) != 0
                || ((input ^ logical) & (1 << 8) != 0 && cr0 & (1 << 31) != 0)));
    if fault {
        vmcb.queue_validated_msr_general_protection(instruction).map_err(E::Fault)?;
        return Ok(NativeMsrOutcome::GeneralProtectionPrepared);
    }
    if (!owner.startup_owned && (cr0 & (1 << 31) == 0 || backing & 0x500 != 0x500))
        || (owner.startup_owned && !native_startup_instruction_mode(vmcb, instruction.length()))
    {
        return Err(E::UnsupportedMode);
    }
    // Target PPR57896 p186 permits OS enable of FFXSE once, then preservation.
    // Refuse clearing an enabled bit outside target-owned INIT; no invented #GP.
    // Other admitted controls use hardware's guest EFER; VMEXIT restores host
    // EFER (APM2 pp502/507). Direct guest INVLPG retains hardware TCE semantics.
    if write
        && (input & !(NATIVE_EFER_MASK | owner.native_features) != 0
            || (!owner.nx_supported && input & 0x800 != 0)
            || (logical & (1 << 14) != 0 && input & (1 << 14) == 0))
    {
        return Err(E::UnsupportedValue { value: input });
    }
    if vmcb.guest_rflags() & (1 << 8) != 0 {
        return Err(E::UnsupportedDebugState);
    }
    let next = instruction.continuation(snapshot).map_err(E::Instruction)?;
    if write {
        if input != logical {
            vmcb.commit_native_efer(input);
        }
        owner.logical = input;
        vmcb.commit_emulated_instruction(vmcb.guest_rax(), next);
    } else {
        vmcb.commit_emulated_instruction(logical as u32 as u64, next);
        frame.rdx = logical >> 32;
        owner.logical = logical;
    }
    vmcb.complete_native_instruction_state();
    Ok(NativeMsrOutcome::Completed)
}

pub(crate) fn validate_native_interrupt_profile(
    vmcb: &Vmcb,
    startup_owned: bool,
) -> Result<(), super::events::ExternalInterruptError> {
    let control = vmcb.virtual_interrupt_control();
    vmcb.validate_virtual_interrupt_controls()?;
    // Pending/masked virtual NMIs are independent of instruction completion.
    // The common validator above proves ENABLE is paired with NMI interception.
    let permitted =
        0xf | (1 << 11) | (1 << 12) | (1 << 26) | if startup_owned { 1 << 24 } else { 0 };
    if control & !permitted != 0 {
        return Err(super::events::ExternalInterruptError::ControlMismatch);
    }
    Ok(())
}
