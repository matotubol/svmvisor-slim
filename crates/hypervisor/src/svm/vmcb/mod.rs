//! Inert, byte-exact VMCB storage for the unencrypted SVM foundation.
//!
//! Offsets and widths follow AMD APM volume 2 revision 3.44, Appendix B,
//! tables B-1 and B-2. State-save offsets include the 0x400 area base.
//! Zero initialization preserves reserved bytes; it does not create a guest
//! that can run. This module provides no launch, allocation, physical-address
//! translation, guest-state completeness check, or hardware access.

use crate::{
    arch::x86_64::descriptors::SegmentState,
    svm::{
        events::{self, ExternalInterruptError, ReflectedException},
        exit::ExitSnapshot,
    },
};

pub use crate::svm::vmcb::{control::native_pause_retry_ready, reflection::ReinjectOutcome};
pub use cache::VmcbCacheOwner;

mod cache;
mod continuation;
mod control;
mod eraps;
mod interrupt;
mod reflection;
#[cfg(test)]
mod tests;
#[cfg(feature = "svm-entry-trial")]
pub mod trial;

pub const VMCB_BYTES: usize = 4096;
/// Control-area extent before the state-save area (APM volume 2, Appendix B).
pub const VMCB_CONTROL_BYTES: usize = 0x400;

const INTERCEPT_MISC1: usize = 0x00c;
/// #GP is mediated to reconcile logical SVM state; all other exceptions are native.
pub(crate) const NATIVE_EXCEPTION_INTERCEPTS: u32 = 1 << 13;
const INTERCEPT_MISC2: usize = 0x010;
const PAUSE_FILTER_THRESHOLD: usize = 0x03c;
const PAUSE_FILTER_COUNT: usize = 0x03e;
/// PAUSE budget the intercept fires once per. VMRUN loads the internal counter
/// from `PAUSE_FILTER_COUNT`, so the count must be nonzero: a zero count makes
/// every PAUSE instruction exit. A zero threshold selects the manual's simpler
/// count-only filtering. APM2 rev3.44 15.14.4, physical page 587.
const PAUSE_FILTER_BUDGET: u16 = 0xffff;
const IOPM_BASE: usize = 0x040;
const MSRPM_BASE: usize = 0x048;
const TSC_OFFSET: usize = 0x050;
const GUEST_ASID: usize = 0x058;
const VIRTUAL_INTERRUPT_CONTROL: usize = 0x060;
const V_IRQ: u64 = 1 << 8;
const SUPPORTED_VIRTUAL_INTERRUPT_CONTROL: u64 =
    0xf | V_IRQ | (0xf << 16) | (1 << 24) | (0xff << 32);
const NESTED_CR3: usize = 0x0b0;
const CLEAN_BITS: usize = 0x0c0;
const GUEST_EFER: usize = 0x4d0;
const GUEST_CR4: usize = 0x548;
const GUEST_CR3: usize = 0x550;
const GUEST_CR0: usize = 0x558;
const GUEST_RFLAGS: usize = 0x570;
const GUEST_RIP: usize = 0x578;
const GUEST_RSP: usize = 0x5d8;
const GUEST_S_CET: usize = 0x5e0;
const GUEST_ISST_ADDR: usize = 0x5f0;
const GUEST_RAX: usize = 0x5f8;
#[cfg(test)]
const GUEST_LSTAR: usize = 0x608;

/// CPU layout alignment only: the object's address is not a physical address.
/// No writable byte view is exposed, so callers cannot modify reserved fields.
#[repr(C, align(4096))]
pub struct Vmcb {
    bytes: [u8; VMCB_BYTES],
}

// Storage, retained-state accessors and raw field access.
impl Vmcb {
    pub const fn new() -> Self {
        Self { bytes: [0; VMCB_BYTES] }
    }

    pub const fn bytes(&self) -> &[u8; VMCB_BYTES] {
        &self.bytes
    }

    /// Read retained exit fields. Meaningful only after a separately established
    /// exit; this neither synchronizes with hardware nor captures other GPRs.
    pub fn exit_snapshot(&self) -> ExitSnapshot {
        ExitSnapshot::from_vmcb_bytes(&self.bytes)
    }

    pub fn guest_rip(&self) -> u64 {
        self.read_u64::<GUEST_RIP>()
    }

    pub fn guest_rsp(&self) -> u64 {
        self.read_u64::<GUEST_RSP>()
    }

    pub fn guest_rax(&self) -> u64 {
        self.read_u64::<GUEST_RAX>()
    }

    /// Actual hardware state, including mandatory SVME; no guest-visible masking.
    pub fn guest_efer(&self) -> u64 {
        self.read_u64::<GUEST_EFER>()
    }

    pub(crate) fn guest_cr0(&self) -> u64 {
        self.read_u64::<GUEST_CR0>()
    }

    pub(crate) fn guest_cpl(&self) -> u8 {
        self.bytes[0x4cb]
    }

    /// Stopped guest page-table root from the architectural state-save area.
    pub fn guest_cr3(&self) -> u64 {
        self.read_u64::<GUEST_CR3>()
    }

    #[cfg(test)]
    pub(crate) fn guest_cr4(&self) -> u64 {
        self.read_u64::<GUEST_CR4>()
    }

    /// Fresh only after the guest VMSAVE that precedes the resident dispatcher.
    #[cfg(test)]
    pub(crate) fn guest_lstar(&self) -> u64 {
        self.read_u64::<GUEST_LSTAR>()
    }

    pub(crate) fn guest_rflags(&self) -> u64 {
        self.read_u64::<GUEST_RFLAGS>()
    }

    /// Retained EVENTINJ bytes, not evidence of pending or completed delivery.
    pub fn event_injection(&self) -> u64 {
        self.read_u64::<0x0a8>()
    }

    /// Retained classic virtual interrupt controls (APM Appendix B, 60h).
    pub fn virtual_interrupt_control(&self) -> u64 {
        self.read_u64::<VIRTUAL_INTERRUPT_CONTROL>()
    }

    /// CR8's REX encoding requires 64-bit code, not compatibility mode.
    /// APM vol.2 rev.3.44 Appendix B: EFER.LMA and saved CS attribute L.
    pub(crate) fn guest_in_64_bit_code(&self) -> bool {
        self.read_u64::<GUEST_EFER>() & (1 << 10) != 0 && self.bytes[0x413] & 2 != 0
    }

    /// Declare all groups dirty for first use, bulk replacement or lost cache
    /// provenance. Only `VmcbCacheOwner` may publish successful-entry reuse.
    pub fn invalidate_all(&mut self) {
        self.set_clean_bits(0);
    }

    #[inline(always)]
    fn write_segment<const OFFSET: usize>(&mut self, segment: SegmentState) {
        const {
            assert!(OFFSET <= VMCB_BYTES - 16);
        }
        let bytes = segment
            .selector
            .to_le_bytes()
            .into_iter()
            .chain(segment.attributes.to_le_bytes())
            .chain(segment.limit.to_le_bytes())
            .chain(segment.base.to_le_bytes());
        for (dst, src) in self.bytes.iter_mut().skip(OFFSET).zip(bytes) {
            *dst = src;
        }
        self.dirty_for_write(OFFSET, 16);
    }

    #[inline(always)]
    fn read_u16<const OFFSET: usize>(&self) -> u16 {
        const {
            assert!(OFFSET <= VMCB_BYTES - 2);
        }
        let mut bytes = [0; 2];
        for (dst, src) in bytes.iter_mut().zip(self.bytes.iter().skip(OFFSET)) {
            *dst = *src;
        }
        u16::from_le_bytes(bytes)
    }

    #[inline(always)]
    fn read_u32<const OFFSET: usize>(&self) -> u32 {
        const {
            assert!(OFFSET <= VMCB_BYTES - 4);
        }
        let mut bytes = [0; 4];
        for (dst, src) in bytes.iter_mut().zip(self.bytes.iter().skip(OFFSET)) {
            *dst = *src;
        }
        u32::from_le_bytes(bytes)
    }

    #[inline(always)]
    fn read_u64<const OFFSET: usize>(&self) -> u64 {
        const {
            assert!(OFFSET <= VMCB_BYTES - 8);
        }
        let mut bytes = [0; 8];
        for (dst, src) in bytes.iter_mut().zip(self.bytes.iter().skip(OFFSET)) {
            *dst = *src;
        }
        u64::from_le_bytes(bytes)
    }

    #[inline(always)]
    fn write_u16<const OFFSET: usize>(&mut self, value: u16) {
        const {
            assert!(OFFSET <= VMCB_BYTES - 2);
        }
        for (dst, src) in self.bytes.iter_mut().skip(OFFSET).zip(value.to_le_bytes()) {
            *dst = src;
        }
        self.dirty_for_write(OFFSET, 2);
    }

    #[inline(always)]
    fn write_u32<const OFFSET: usize>(&mut self, value: u32) {
        const {
            assert!(OFFSET <= VMCB_BYTES - 4);
        }
        for (dst, src) in self.bytes.iter_mut().skip(OFFSET).zip(value.to_le_bytes()) {
            *dst = src;
        }
        self.dirty_for_write(OFFSET, 4);
    }

    #[inline(always)]
    fn write_u64<const OFFSET: usize>(&mut self, value: u64) {
        const {
            assert!(OFFSET <= VMCB_BYTES - 8);
        }
        for (dst, src) in self.bytes.iter_mut().skip(OFFSET).zip(value.to_le_bytes()) {
            *dst = src;
        }
        self.dirty_for_write(OFFSET, 8);
    }

    fn update_intercept<const OFFSET: usize>(&mut self, mask: u32, enabled: bool) {
        let previous = self.read_u32::<OFFSET>();
        self.write_u32::<OFFSET>(if enabled { previous | mask } else { previous & !mask });
    }
}

impl Vmcb {
    /// Queue a physical NMI taken by a private host GIF window.
    #[cfg(feature = "resident-runtime")]
    pub(crate) fn queue_native_nmi(&mut self) -> Result<(), ExternalInterruptError> {
        self.validate_external_interrupt_conflicts()?;
        self.validate_virtual_interrupt_controls()?;
        self.write_u64::<0x0a8>((1 << 31) | (2 << 8) | 2);
        Ok(())
    }
}

// Instruction-fault queueing for the stopped instruction's owner.
impl Vmcb {
    pub(crate) fn queue_validated_msr_general_protection(
        &mut self,
        instruction: super::exit::MsrInstruction<'_>,
    ) -> Result<(), events::MsrFaultError> {
        use events::MsrFaultError;
        instruction.validate(self.exit_snapshot()).map_err(MsrFaultError::Instruction)?;
        self.queue_native_general_protection().map_err(MsrFaultError::State)
    }

    /// Queue #GP(0) after a native instruction owner has validated this actual
    /// stopped exit and established the architectural fault condition. This
    /// does not validate an opcode or invent a fault for unsupported policy.
    /// APM2 15.20: fault injection preserves the faulting RIP and all GPRs.
    pub(crate) fn queue_native_general_protection(&mut self) -> Result<(), ExternalInterruptError> {
        self.queue_instruction_fault(ReflectedException::GeneralProtection { error_code: 0 })
    }

    /// The SVM instruction owner has established a mode, enable or privilege
    /// fault. Bind that decision to this stopped hardware-decoded instruction;
    /// no continuation address or guest operand is invented for fault delivery.
    pub(crate) fn queue_svm_instruction_fault(
        &mut self,
        instruction: super::instructions::NativeSvmInstruction,
        fault: super::instructions::NativeSvmInstructionOutcome,
    ) -> Result<(), ExternalInterruptError> {
        use super::instructions::NativeSvmInstructionOutcome;
        if self.exit_snapshot().code != instruction.exit_code() {
            return Err(ExternalInterruptError::ControlMismatch);
        }
        self.queue_instruction_fault(match fault {
            NativeSvmInstructionOutcome::InvalidOpcodePrepared => ReflectedException::InvalidOpcode,
            NativeSvmInstructionOutcome::GeneralProtectionPrepared => {
                ReflectedException::GeneralProtection { error_code: 0 }
            }
        })
    }

    /// Reject an intercepted VMMCALL that no installed ABI claims, using the non-intercepted
    /// #UD behavior in APM volume 2 physical page 593 and volume 3 physical page 536.
    /// The caller proves the actual stopped exit and resolves pending delivery first.
    /// No instruction fetch, NRIPS support or RIP advancement is needed for this fault.
    #[cfg(feature = "resident-runtime")]
    pub(crate) fn queue_vmmcall_invalid_opcode(&mut self) -> Result<(), ExternalInterruptError> {
        if self.exit_snapshot().code != 0x81 {
            return Err(ExternalInterruptError::ControlMismatch);
        }
        self.queue_instruction_fault(ReflectedException::InvalidOpcode)
    }

    /// Shared commit for #GP/#UD owners; neither exception changes CR2 or completes an opcode.
    fn queue_instruction_fault(
        &mut self,
        exception: ReflectedException,
    ) -> Result<(), ExternalInterruptError> {
        self.validate_external_interrupt_conflicts()?;
        self.validate_virtual_interrupt_controls()?;
        if self.virtual_interrupt_control() & V_IRQ != 0 {
            return Err(ExternalInterruptError::PendingVirtualInterrupt);
        }
        self.write_u64::<0x0a8>(exception.encoding());
        Ok(())
    }
}

// AP INIT and SIPI state.
impl Vmcb {
    /// Target-owned INIT processor state. APM2 rev3.44 Table14-1/2, printed
    /// 481-483. DR6/7 reset here; the caller resets its guest-owned live DR0-3
    /// at the same stopped commit. PAT, auxiliary MSRs, live xstate, XCR0,
    /// MTRRs and other INIT-retained resources stay with the caller.
    /// This does not implement LAPIC initialization or permit guest entry.
    pub(crate) fn initialize_ap_after_init(&mut self) {
        let data = SegmentState { selector: 0, attributes: 0x92, limit: 0xffff, base: 0 };
        self.write_segment::<0x400>(data);
        self.write_segment::<0x420>(data);
        self.write_segment::<0x430>(data);
        self.write_segment::<0x440>(data);
        self.write_segment::<0x450>(data);
        self.write_segment::<0x410>(SegmentState {
            selector: 0xf000,
            attributes: 0x9a,
            limit: 0xffff,
            base: 0xffff_0000,
        });
        self.write_segment::<0x460>(SegmentState { attributes: 0, ..data });
        self.write_segment::<0x480>(SegmentState { attributes: 0, ..data });
        self.write_segment::<0x470>(SegmentState { attributes: 0x82, ..data });
        self.write_segment::<0x490>(SegmentState { attributes: 0x83, ..data });
        self.bytes[0x4cb] = 0;
        self.write_u64::<GUEST_EFER>(0x1000);
        self.write_u64::<GUEST_CR0>((self.read_u64::<GUEST_CR0>() & 0x6000_0000) | 0x10);
        self.write_u64::<GUEST_CR3>(0);
        self.write_u64::<GUEST_CR4>(0);
        self.write_u64::<0x560>(0x400); // DR7, APM2 Table14-1 p482.
        self.write_u64::<0x568>(0xffff_0ff0); // DR6, same INIT value as RESET.
        self.write_u64::<0x640>(0); // CR2
        self.write_u64::<GUEST_RFLAGS>(2);
        self.write_u64::<GUEST_RIP>(0xfff0);
        self.write_u64::<GUEST_RSP>(0);
        self.write_u64::<GUEST_RAX>(0);
        self.write_u64::<VIRTUAL_INTERRUPT_CONTROL>(self.virtual_interrupt_control() & (1 << 24));
        // INIT clears any pending/masked virtual NMI (V_NMI, V_NMI_MASK) but
        // keeps V_NMI_ENABLE armed, matching Table 14-1's NMI reset: a fresh AP
        // takes NMIs once started (APM2 15.21.10 p537).
        self.write_u64::<0x068>(0); // interrupt shadow
        self.request_guest_rap_clear();
        self.request_full_tlb_flush();
        // Whole architectural INIT, including the raw CPL/auxiliary stores.
        self.invalidate_all();
    }

    /// APM2 15.27.8: vector gives upper8 of20-bit address,16-bit real mode,
    /// page offset0; ordinary real-mode CS formation (14.1.5) gives vector<<8.
    pub(crate) fn start_ap_from_sipi(&mut self, vector: u8) {
        self.write_segment::<0x410>(SegmentState {
            selector: (vector as u16) << 8,
            attributes: 0x9a,
            limit: 0xffff,
            base: (vector as u64) << 12,
        });
        self.write_u64::<GUEST_RIP>(0);
    }
}

impl Default for Vmcb {
    fn default() -> Self {
        Self::new()
    }
}

/// Reviewed baseline instruction intercepts; arbitrary bit masks are excluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstructionIntercept {
    Rdtsc,
    Rdtscp,
    Cpuid,
    Pause,
    Hlt,
    Vmrun,
    Vmmcall,
    Vmload,
    Vmsave,
    Stgi,
    Clgi,
    Skinit,
    Invlpga,
    Ioio,
    Msr,
    Xsetbv,
}

impl InstructionIntercept {
    const fn location(self) -> (usize, u32) {
        match self {
            Self::Rdtsc => (INTERCEPT_MISC1, 1 << 14),
            Self::Rdtscp => (INTERCEPT_MISC2, 1 << 7),
            Self::Cpuid => (INTERCEPT_MISC1, 1 << 18),
            Self::Pause => (INTERCEPT_MISC1, 1 << 23),
            Self::Hlt => (INTERCEPT_MISC1, 1 << 24),
            Self::Vmrun => (INTERCEPT_MISC2, 1),
            Self::Vmmcall => (INTERCEPT_MISC2, 1 << 1),
            Self::Vmload => (INTERCEPT_MISC2, 1 << 2),
            Self::Vmsave => (INTERCEPT_MISC2, 1 << 3),
            Self::Stgi => (INTERCEPT_MISC2, 1 << 4),
            Self::Clgi => (INTERCEPT_MISC2, 1 << 5),
            Self::Skinit => (INTERCEPT_MISC2, 1 << 6),
            Self::Invlpga => (INTERCEPT_MISC1, 1 << 26),
            Self::Ioio => (INTERCEPT_MISC1, 1 << 27),
            Self::Msr => (INTERCEPT_MISC1, 1 << 28),
            Self::Xsetbv => (INTERCEPT_MISC2, 1 << 13),
        }
    }
}

/// Event intercept controls from APM vol.2 rev.3.44 Appendix B,
/// Table B-1, offset 00Ch bits 0/1/2/3/4/31. These are distinct from instruction
/// intercepts and virtual event injection. Setting a bit does not establish
/// platform support, pending-event handling or a safe firmware return path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventIntercept {
    /// Physical maskable INTR, exit60h. APM 15.13.1: the interrupt remains
    /// pending for host acknowledgement; this does not inject a guest IRQ.
    PhysicalInterrupt,
    Nmi,
    /// APM section 15.13.3: hardware ignores this bit when HWCR.SMMLOCK is set.
    /// Internal and external SMIs have different pending-event semantics.
    Smi,
    Init,
    /// Exit just before a virtual IRQ is dispatched; V_IRQ remains pending.
    /// APM 15.13.5. This is not a physical interrupt intercept.
    VirtualInterrupt,
    /// APM15.14.3: terminal exit7fh; saved guest state is undefined.
    Shutdown,
}

impl EventIntercept {
    const fn mask(self) -> u32 {
        match self {
            Self::PhysicalInterrupt => 1,
            Self::Nmi => 1 << 1,
            Self::Smi => 1 << 2,
            Self::Init => 1 << 3,
            Self::VirtualInterrupt => 1 << 4,
            Self::Shutdown => 1 << 31,
        }
    }
}
