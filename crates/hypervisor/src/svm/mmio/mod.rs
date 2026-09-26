//! Bounded stopped-NPF MOV preparation for an explicit MMIO effect owner.
//!
//! No device, memory, NPT permission or guest state is changed by preparation.
//! APM2 physical pp574-575,613-614; APM3 pp45-65,80,276-278;
//! IOMMU 48882 physical p214. This is not a PCI forwarding policy or an owner.
#![forbid(unsafe_code)]

mod decode;
mod registers;

pub use decode::DecodeError;
pub(crate) use decode::DecodedMov;

use crate::{
    arch::x86_64::{capabilities::ValidatedCapabilities, registers::GuestRegisters},
    memory::address::{AddressError, is_canonical_48},
    svm::{
        events::ExternalInterruptError,
        exit::{ResumeCandidate, ResumeError},
        vmcb::Vmcb,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Read,
    Write,
}

/// Exact decoded guest-linear span, not permission to access its backing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinearAccess {
    pub address: u64,
    pub bytes: u8,
    pub direction: Direction,
}

/// Numeric operand bound to the reported NPF by a current guest translation.
/// The effect owner must still admit the exact device/register and operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioAccess {
    pub linear: LinearAccess,
    pub guest_physical: u64,
    /// Present only for a write; already narrowed to the decoded source lane.
    pub write_value: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmioError {
    UnsupportedExit,
    UnsupportedFault,
    DecodeAssistsUnavailable,
    InvalidInstructionBytes,
    UnsupportedMode,
    UnsupportedDebugState,
    Pending(ExternalInterruptError),
    Decode(DecodeError),
    Continuation(ResumeError),
    NoncanonicalOperand,
    UnalignedOperand,
    PhysicalSpan(AddressError),
    PageOffsetMismatch,
    OperandMismatch { reported: u64, translated: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepareError<E> {
    Boundary(MmioError),
    Translation(E),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitError {
    WrongDirection,
}

/// An exclusively borrowed stopped instruction. Dropping it changes no state.
/// Construction is not evidence that any real or virtual device effect occurred.
pub struct PreparedMmio<'a> {
    vmcb: &'a mut Vmcb,
    frame: &'a mut GuestRegisters,
    next: ResumeCandidate,
    access: MmioAccess,
    register: registers::RegisterLane,
}

impl PreparedMmio<'_> {
    pub fn access(&self) -> MmioAccess {
        self.access
    }

    /// An ECAM-specific owner additionally requires AL/AX/EAX and its own width,
    /// lane, UC and register-effect policy. This predicate grants none of those.
    pub fn accumulator_operand(&self) -> bool {
        self.register.accumulator()
    }

    pub fn instruction_bytes(&self) -> u8 {
        self.next.instruction_bytes()
    }

    /// Only after the admitted effect owner has produced the actual read value.
    /// MOV narrows it to the destination lane; a 32-bit result zero-extends.
    pub fn commit_read(self, value: u64) -> Result<(), CommitError> {
        if self.access.linear.direction != Direction::Read {
            return Err(CommitError::WrongDirection);
        }
        let rax = self.register.write(self.vmcb, self.frame, self.access.linear.bytes, value);
        self.vmcb.commit_emulated_instruction(rax, self.next);
        self.vmcb.complete_native_instruction_state();
        Ok(())
    }

    /// Only after the admitted effect owner completed this exact write. This
    /// method does not perform it, report it to hardware, or synthesize success.
    pub fn commit_write(self) -> Result<(), CommitError> {
        if self.access.linear.direction != Direction::Write {
            return Err(CommitError::WrongDirection);
        }
        self.vmcb.commit_emulated_instruction(self.vmcb.guest_rax(), self.next);
        self.vmcb.complete_native_instruction_state();
        Ok(())
    }
}

/// Prepare one naturally aligned scalar register/memory MOV from an actual
/// stopped long64 CPL0 data NPF. Native caller owns the same-CPU VMCB/frame,
/// completed event bookkeeping, hardware exit/DecodeAssists provenance and
/// instruction/paging consistency throughout preparation and the later effect.
/// Offline fixtures can exercise the API but cannot establish that provenance.
///
/// `translate_span` must validate the *whole current guest span*, including
/// permissions, cache policy and a coherent current guest translation, returning
/// its first GPA. It may inspect admitted page tables; it must not read or write
/// the MMIO operand. Its return is not device-access permission. No unchecked
/// guest pointer is dereferenced here. Natural alignment bounds the span to one
/// 4KiB page. Unknown prefixes, modes, fault stages and debug effects are refused.
/// All failures preserve both the VMCB and register frame. nRIP is never used.
pub fn prepare<'a, E>(
    vmcb: &'a mut Vmcb,
    frame: &'a mut GuestRegisters,
    capabilities: &ValidatedCapabilities,
    translate_span: impl FnOnce(&Vmcb, LinearAccess) -> Result<u64, E>,
) -> Result<PreparedMmio<'a>, PrepareError<E>> {
    use PrepareError::Boundary as B;
    let (decoded, next) = prepare_instruction(vmcb, frame, capabilities).map_err(B)?;
    let linear = decoded.access();
    let reported = vmcb.exit_snapshot().info2;
    let width = u64::from(linear.bytes);
    let last = linear.address.checked_add(width - 1).ok_or(B(MmioError::NoncanonicalOperand))?;
    if !is_canonical_48(linear.address) || !is_canonical_48(last) {
        return Err(B(MmioError::NoncanonicalOperand));
    }
    if linear.address & (width - 1) != 0 {
        return Err(B(MmioError::UnalignedOperand));
    }
    capabilities
        .address_policy()
        .validate(reported, width, width)
        .map_err(|e| B(MmioError::PhysicalSpan(e)))?;
    if linear.address & 4095 != reported & 4095 {
        return Err(B(MmioError::PageOffsetMismatch));
    }
    let translated = translate_span(vmcb, linear).map_err(PrepareError::Translation)?;
    if translated != reported {
        return Err(B(MmioError::OperandMismatch { reported, translated }));
    }
    let register = decoded.register();
    let write_value =
        (linear.direction == Direction::Write).then(|| register.read(vmcb, frame, linear.bytes));
    Ok(PreparedMmio {
        vmcb,
        frame,
        next,
        register,
        access: MmioAccess { linear, guest_physical: reported, write_value },
    })
}

fn prepare_instruction(
    vmcb: &Vmcb,
    frame: &GuestRegisters,
    capabilities: &ValidatedCapabilities,
) -> Result<(DecodedMov, ResumeCandidate), MmioError> {
    let exit = vmcb.exit_snapshot();
    if exit.code != 0x400 {
        return Err(MmioError::UnsupportedExit);
    }
    // Only baseline final-GPA data faults. U/S is not the original guest CPL.
    // Refuse reserved, instruction-fetch, page-table, shadow-stack and every
    // unowned optional fault indication rather than reinterpret them.
    if exit.info1 & (1 << 32) == 0 || exit.info1 & !((1u64 << 32) | 7) != 0 {
        return Err(MmioError::UnsupportedFault);
    }
    if !capabilities.optional_features().decode_assists {
        return Err(MmioError::DecodeAssistsUnavailable);
    }
    let cs = u16::from_le_bytes(vmcb.bytes()[0x412..0x414].try_into().unwrap());
    let cr4 = field(vmcb, 0x548);
    if !vmcb.guest_in_64_bit_code()
        || vmcb.guest_cpl() != 0
        || cs & 0x698 != 0x298
        || vmcb.guest_cr0() & 0x8000_0001 != 0x8000_0001
        || cr4 & (1 << 5) == 0
        || cr4 & (1 << 12) != 0
        || vmcb.guest_efer() & (1 << 20) != 0
        || vmcb.guest_rflags() & (1 << 17) != 0
        || field(vmcb, 0x090) != 1
    {
        return Err(MmioError::UnsupportedMode);
    }
    // Data-breakpoint traps and TF require a post-instruction #DB owner.
    // APM2 physical pp457,465-466,470; VMCB DR7 at 560h.
    if vmcb.guest_rflags() & (1 << 8) != 0 || field(vmcb, 0x560) & 0xff != 0 {
        return Err(MmioError::UnsupportedDebugState);
    }
    vmcb.validate_external_interrupt_conflicts().map_err(MmioError::Pending)?;
    vmcb.validate_virtual_interrupt_controls().map_err(MmioError::Pending)?;
    let count = vmcb.bytes()[0x0d0];
    if !(1..=15).contains(&count) {
        return Err(MmioError::InvalidInstructionBytes);
    }
    let decoded = decode::decode(&vmcb.bytes()[0x0d1..0x0d1 + usize::from(count)], vmcb, frame)
        .map_err(MmioError::Decode)?;
    if (decoded.access().direction == Direction::Write) != (exit.info1 & 2 != 0) {
        return Err(MmioError::UnsupportedFault);
    }
    let next = exit.npf_mov_continuation(&decoded).map_err(MmioError::Continuation)?;
    Ok((decoded, next))
}

fn field(vmcb: &Vmcb, offset: usize) -> u64 {
    u64::from_le_bytes(vmcb.bytes()[offset..offset + 8].try_into().unwrap())
}
