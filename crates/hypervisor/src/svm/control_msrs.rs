//! Guest-owned SVM control MSRs for the native-CPUID target profile.
//!
//! VM_HSAVE_PA and TSC_RATIO hold guest state only; no handler accesses physical MSRs
//! or guest memory. TSC_RATIO controls a future nested guest, not this conceptual
//! host's own TSC/MPERF reads (APM2 physical pages 647-648; PPR physical page 189).
//! This provides register semantics, not nested VMRUN. The target-specific address checks
//! follow PPR 57896 physical pages 213-216 and APM volume 2 physical page 647. SVM key
//! reads return zero (PPR physical page 216; APM physical pages 648-649).

use x86_64::registers::rflags::RFlags;

use crate::{
    arch::x86_64::{
        capabilities::ValidatedCapabilities,
        msr::{TARGET_PHYSICAL_BITS, TARGET_SIGNATURE, TSC_RATIO, TSC_RATIO_DEFINED, VM_CR_LOCK},
        registers::GuestRegisters,
    },
    svm::{
        dispatch::{
            NativeEfer, NativeEferError, NativeMsrOutcome, hardware_msr_instruction,
            native_startup_instruction_mode, validate_native_msr_boundary,
        },
        exit::MsrInstruction,
        vmcb::Vmcb,
        vmcr::VisibleVmCr,
    },
};

pub const VM_HSAVE_PA: u32 = 0xc001_0117;
pub const SVM_LOCK_KEY: u32 = 0xc001_0118;
pub const SMM_ADDR: u32 = 0xc001_0112;
pub const SMM_MASK: u32 = 0xc001_0113;

pub const fn owned_msr(index: u32) -> bool {
    matches!(index, VM_HSAVE_PA | SVM_LOCK_KEY | TSC_RATIO)
}

const HSAVE_ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;
const TSEG_ADDRESS_MASK: u64 = 0x0000_ffff_fffe_0000;
const SMM_MASK_DEFINED: u64 = TSEG_ADDRESS_MASK | 0x773f;
const ASEG_START: u64 = 0x000a_0000;
const ASEG_END: u64 = 0x000c_0000;
// PPR216 gives bounds on the 36-bit VM_HSAVE_PA[47:12] field, not byte addresses.
const FORBIDDEN_HSAVE_START: u64 = 0x0000_fffd_0000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SvmControlAdmissionError {
    UnsupportedProcessor,
    UnlockedSmram,
    ReservedSmramBits,
    OverlappingSmram,
    InvalidInitialHsave,
    InvalidInitialTscRatio,
}

/// Immutable SMRAM evidence from the same CPU whose controls are being owned.
///
/// Read HWCR, SMM_ADDR and SMM_MASK only after admitting the exact target CPU. SmmLock
/// (HWCR bit 0) must already protect these registers; the runtime must continue intercepting
/// guest writes to the SMM registers and lock key. Capturing a policy does not establish
/// CPU affinity, protect against firmware changing its own configuration, or enable SMM
/// emulation. No allocation/RAM check is imposed on HSAVE writes: hardware's MSR write
/// checks address legality, not whether memory is allocated by the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HsaveAddressPolicy {
    tseg_base: u64,
    tseg_mask: u64,
    tseg_enabled: bool,
    aseg_enabled: bool,
}

impl HsaveAddressPolicy {
    pub fn admit_target(
        signature: u32,
        physical_bits: u8,
        hwcr: u64,
        smm_addr: u64,
        smm_mask: u64,
    ) -> Result<Self, SvmControlAdmissionError> {
        if signature != TARGET_SIGNATURE || physical_bits != TARGET_PHYSICAL_BITS {
            return Err(SvmControlAdmissionError::UnsupportedProcessor);
        }
        // PPR 57896 physical page 204: firmware initializes SmmLock to one.
        if hwcr & 1 == 0 {
            return Err(SvmControlAdmissionError::UnlockedSmram);
        }
        if smm_addr & !TSEG_ADDRESS_MASK != 0 || smm_mask & !SMM_MASK_DEFINED != 0 {
            return Err(SvmControlAdmissionError::ReservedSmramBits);
        }
        let policy = Self {
            tseg_base: smm_addr,
            tseg_mask: smm_mask & TSEG_ADDRESS_MASK,
            tseg_enabled: smm_mask & 2 != 0,
            aseg_enabled: smm_mask & 1 != 0,
        };
        // Both ranges are 128-KiB aligned at minimum. PPR214 forbids their overlap.
        if policy.aseg_enabled && policy.in_tseg(ASEG_START) {
            return Err(SvmControlAdmissionError::OverlappingSmram);
        }
        Ok(policy)
    }

    /// APM647 alignment/width plus PPR216 target restrictions. All 4096 bytes have
    /// the same TSEG masked address (its lowest compare bit is 17); ASEG boundaries
    /// are page aligned. Testing a legal page base therefore covers the entire page.
    pub const fn permits(&self, value: u64) -> bool {
        value & !HSAVE_ADDRESS_MASK == 0
            && value < FORBIDDEN_HSAVE_START
            && !(self.aseg_enabled && value >= ASEG_START && value < ASEG_END)
            && !self.in_tseg(value)
    }

    const fn in_tseg(&self, value: u64) -> bool {
        self.tseg_enabled && value & self.tseg_mask == self.tseg_base & self.tseg_mask
    }
}

/// Per-vCPU software state retained across guest INIT (APM2 physical page 544,
/// Table 14-1: other MSRs are not modified). A processor RESET needs fresh admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VisibleSvmControls {
    hsave_pa: u64,
    tsc_ratio: u64,
    svm_lock_key: u64,
    vmcr_locked: bool,
    address_policy: HsaveAddressPolicy,
}

impl VisibleSvmControls {
    /// Preserve physical HSAVE and TSC_RATIO sampled before monitor-owned values.
    /// The caller must first verify CPUID Fn8000_000A EDX[TscRateMsr] (bit 4).
    /// Keep physical TSC_RATIO at unity while this conceptual native host executes;
    /// guest writes here never change its own TSC, MPERF or MPerfReadOnly scaling.
    ///
    /// The caller admits the firmware-enabled profile in PPR57896 physical page 37:
    /// SVMDIS clear and a zero SVM key. Hardware RDMSR cannot verify the hidden key
    /// because it always returns zero; this is an explicit firmware-profile assumption.
    /// With LOCK clear the guest may set its software key. LOCK is target read-only
    /// and this profile has no guest instruction that sets it. With LOCK set the admitted
    /// zero key makes every key write ignored and preserves LOCK. Any future writable
    /// LOCK/SKINIT owner must extend this owner before admitting that transition.
    /// Initial capture validates the register format, not write-time SMRAM restrictions:
    /// HSAVE may still hold its reset zero when firmware subsequently protects that page.
    /// Reading that retained value is legal; writing it again may raise #GP.
    pub fn admit_firmware_zero_key(
        initial_hsave_pa: u64,
        initial_tsc_ratio: u64,
        address_policy: HsaveAddressPolicy,
        vmcr: &VisibleVmCr,
    ) -> Result<Self, SvmControlAdmissionError> {
        if initial_hsave_pa & !HSAVE_ADDRESS_MASK != 0 {
            return Err(SvmControlAdmissionError::InvalidInitialHsave);
        }
        if initial_tsc_ratio & !TSC_RATIO_DEFINED != 0 {
            return Err(SvmControlAdmissionError::InvalidInitialTscRatio);
        }
        Ok(Self {
            hsave_pa: initial_hsave_pa,
            tsc_ratio: initial_tsc_ratio,
            svm_lock_key: 0,
            vmcr_locked: vmcr.logical() & VM_CR_LOCK != 0,
            address_policy,
        })
    }

    pub const fn hsave_pa(&self) -> u64 {
        self.hsave_pa
    }

    pub const fn tsc_ratio(&self) -> u64 {
        self.tsc_ratio
    }
}

pub type NativeSvmControlError = NativeEferError;

/// Complete one exclusively stopped control-MSR access with exact fetched bytes.
/// Both ordinary and startup callers retain the same guest EFER and VM_CR owners.
pub fn handle_visible_svm_controls(
    owner: &mut VisibleSvmControls,
    vmcr: &VisibleVmCr,
    efer: &NativeEfer,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    instruction: &[u8],
    startup_owned: bool,
) -> Result<NativeMsrOutcome, NativeSvmControlError> {
    complete_control_msr(
        owner,
        vmcr,
        efer,
        vmcb,
        frame,
        MsrInstruction::Bytes(instruction),
        startup_owned,
    )
}

/// Hardware-decoded counterpart, using the same CPU's validated NRIP capability.
pub fn handle_visible_svm_controls_with_nrip(
    owner: &mut VisibleSvmControls,
    vmcr: &VisibleVmCr,
    efer: &NativeEfer,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    capabilities: &ValidatedCapabilities,
    startup_owned: bool,
) -> Result<NativeMsrOutcome, NativeSvmControlError> {
    let instruction = hardware_msr_instruction(vmcb, capabilities)?;
    complete_control_msr(owner, vmcr, efer, vmcb, frame, instruction, startup_owned)
}

fn complete_control_msr(
    owner: &mut VisibleSvmControls,
    vmcr: &VisibleVmCr,
    efer: &NativeEfer,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    instruction: MsrInstruction<'_>,
    startup_owned: bool,
) -> Result<NativeMsrOutcome, NativeSvmControlError> {
    use NativeSvmControlError as E;
    validate_native_msr_boundary(vmcb, instruction, startup_owned)?;
    let snapshot = vmcb.exit_snapshot();
    let write = snapshot.info1 == 1;
    let index = frame.rcx as u32;
    if !owned_msr(index) {
        return Err(E::UnsupportedMsr { index, write });
    }
    efer.observe_backing(vmcb.guest_cr0(), vmcb.guest_efer())?;
    if owner.vmcr_locked != (vmcr.logical() & VM_CR_LOCK != 0) {
        return Err(E::BackingMismatch);
    }
    let input = (u64::from(frame.rdx as u32) << 32) | u64::from(vmcb.guest_rax() as u32);
    if vmcb.guest_cpl() != 0
        || (write && index == VM_HSAVE_PA && !owner.address_policy.permits(input))
        || (write && index == TSC_RATIO && input & !TSC_RATIO_DEFINED != 0)
    {
        vmcb.queue_validated_msr_general_protection(instruction).map_err(E::Fault)?;
        return Ok(NativeMsrOutcome::GeneralProtectionPrepared);
    }
    if (!startup_owned && !vmcb.guest_in_64_bit_code())
        || (startup_owned && !native_startup_instruction_mode(vmcb, instruction.length()))
    {
        return Err(E::UnsupportedMode);
    }
    if vmcb.guest_rflags() & RFlags::TRAP_FLAG.bits() != 0 {
        return Err(E::UnsupportedDebugState);
    }
    let next = instruction.continuation(snapshot).map_err(E::Instruction)?;
    if write {
        if index == VM_HSAVE_PA {
            owner.hsave_pa = input;
        } else if index == TSC_RATIO {
            // All 40-bit values, including zero, are valid. No write is forwarded
            // to physical hardware: the logical caller is not its own nested guest.
            owner.tsc_ratio = input;
        } else if !owner.vmcr_locked {
            owner.svm_lock_key = input;
        }
        vmcb.commit_emulated_instruction(vmcb.guest_rax(), next);
    } else {
        let value = match index {
            VM_HSAVE_PA => owner.hsave_pa,
            TSC_RATIO => owner.tsc_ratio,
            _ => 0,
        };
        vmcb.commit_emulated_instruction(u64::from(value as u32), next);
        frame.rdx = value >> 32;
    }
    vmcb.complete_native_instruction_state();
    Ok(NativeMsrOutcome::Completed)
}
