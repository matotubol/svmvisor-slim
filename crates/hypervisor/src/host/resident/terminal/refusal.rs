//! Stop reasons and their wire encodings: fetch, MSR, SYS_CFG and startup
//! refusals, and the exported stop words. No encoder reads guest memory or hardware.

/// Stable software diagnostic codes; no additional guest reads are performed.
#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FetchReadFailure {
    MemoryMap = 0x30,
    AddressPolicy = 0x31,
    MonitorRange = 0x32,
    HostPat = 0x33,
    MtrrCapture = 0x34,
    ReadShape = 0x35,
    RamAdmission = 0x36,
    FixedMtrrControl = 0x37,
    FixedMtrrRange = 0x38,
    PhysicalMemoryNotWb = 0x39,
    ScratchAliasOccupied = 0x3a,
    MemoryControlBusy = 0x3b,
}

/// Target-local startup service stages in the terminal wire record.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupStage {
    InitAcknowledgment = 1,
    RouteTable = 2,
    TargetApplication = 5,
    EferReset = 6,
    MailboxCompletion = 8,
    InitPreparation = 10,
    /// The native LAPIC backend needs a retained physical rebootstrap path.
    /// Never acknowledge a later guest INIT through the partial boot helper.
    PostbootInitUnsupported = 11,
    OwnerMissing = 15,
}

pub fn fetch_failure_code(error: crate::host::resident::fetch::FetchError) -> u16 {
    use super::fetch::FetchError as F;
    use crate::host::paging::WalkError as W;
    match error {
        F::UnsupportedExit => 1,
        F::UnsupportedMode => 2,
        F::AddressOverflow => 3,
        F::UnsupportedCacheControl => 4,
        F::NotExecutable => 5,
        F::PrivilegeMismatch => 6,
        F::NonWriteBackInstruction => 7,
        F::UnreadableInstruction { .. } => 8,
        F::SegmentLimit => 9,
        F::Walk(w) => match w {
            W::UnsupportedPhysicalWidth => 0x10,
            W::FiveLevelUnsupported => 0x11,
            W::NoncanonicalAddress => 0x12,
            W::InvalidCr3 => 0x13,
            W::UnreadableTable { level, .. } => 0x14 | ((level as u16) << 8),
            W::NotPresent { level } => 0x15 | ((level as u16) << 8),
            W::ReservedEntry { level } => 0x16 | ((level as u16) << 8),
            W::UnsupportedEntryBits { level } => 0x17 | ((level as u16) << 8),
            W::OneGiBUnsupported => 0x18,
            W::IncompleteWalk => 0x19,
        },
    }
}

/// Stable EFER diagnostic, derived only from the already stopped state.
/// The payload is one full-width operand; it does not export the whole VMCB.
pub fn efer_failure(
    error: crate::svm::dispatch::NativeEferError,
    vmcb: &crate::svm::vmcb::Vmcb,
    logical: u64,
    instruction_bytes: [u8; 2],
) -> (u64, u64) {
    msr_failure_context(error, vmcb, logical, Some(instruction_bytes), 0xf108)
}

/// Hardware NRIP diagnostics contain actual continuation evidence, never invented bytes.
pub fn efer_nrip_failure(
    error: crate::svm::dispatch::NativeEferError,
    vmcb: &crate::svm::vmcb::Vmcb,
    logical: u64,
) -> (u64, u64) {
    msr_failure_context(error, vmcb, logical, None, 0xf108)
}

/// VM_CR uses the same stopped-instruction errors but a distinct register identity.
pub fn vmcr_failure(
    error: crate::svm::dispatch::NativeEferError,
    vmcb: &crate::svm::vmcb::Vmcb,
    logical: u64,
    instruction_bytes: [u8; 2],
) -> (u64, u64) {
    msr_failure_context(error, vmcb, logical, Some(instruction_bytes), 0xf109)
}

pub fn vmcr_nrip_failure(
    error: crate::svm::dispatch::NativeEferError,
    vmcb: &crate::svm::vmcb::Vmcb,
    logical: u64,
) -> (u64, u64) {
    msr_failure_context(error, vmcb, logical, None, 0xf109)
}

/// SYSCFG stage85 carries both DWORD operands when possible, otherwise one
/// explicitly typed full-width value. No diagnostic path reads guest memory.
pub fn syscfg_failure(
    error: crate::svm::syscfg::SyscfgError,
    vmcb: &crate::svm::vmcb::Vmcb,
    instruction: Option<[u8; 2]>,
) -> (u64, u64) {
    use crate::svm::syscfg::SyscfgError as E;
    let write = vmcb.exit_snapshot().info1 == 1;
    let (reason, requested, current) = match error {
        E::Boundary(error) => {
            let (tag, value) = msr_failure_context(error, vmcb, 0, instruction, 0);
            return syscfg_context((tag >> 16) & 255, 3, write, value);
        }
        E::UnsupportedProfile { signature, physical_bits } => {
            return syscfg_context(
                0x80,
                3,
                write,
                u64::from(signature) | (u64::from(physical_bits) << 32),
            );
        }
        E::CurrentReserved { requested, current } => (0x81, requested, current),
        E::CurrentEncryption { requested, current } => (0x82, requested, current),
        E::RequestedReserved { requested, current } => (0x83, requested, current),
        E::UnsupportedChange { requested, current } => (0x84, requested, current),
    };
    syscfg_operands(reason, write, requested, current)
}

pub fn syscfg_operands(reason: u64, write: bool, requested: u64, current: u64) -> (u64, u64) {
    if current > u32::MAX as u64 {
        syscfg_context(reason, 2, write, current)
    } else if requested > u32::MAX as u64 {
        syscfg_context(reason, 1, write, requested)
    } else {
        syscfg_context(reason, 0, write, requested | (current << 32))
    }
}

/// Target-local startup evidence. Wide observations retain all 64 bits and
/// explicitly omit CPU identity. No diagnostic performs another hardware read.
pub fn startup_failure(reason: u8, detail: u8, value: u64, identity: u32) -> (u64, u64) {
    let wide = value > u32::MAX as u64;
    let code = reason as u64 | ((detail as u64) << 3) | (u64::from(wide) << 10);
    (0xf10c | (code << 16), if wide { value } else { value | ((identity as u64) << 32) })
}

/// Select one explicitly typed full-width context; full stop state remains local.
/// Kinds 8 and 13 belonged to retired xAPIC MMIO stops and kind 14 to the
/// retired startup-route record; they are never exported now, and only the
/// offline snapshot decoder still reads them from old images.
pub fn stop_words(slot: usize, code: u64, rip: u64, info1: u64, info2: u64) -> Option<[u32; 3]> {
    if slot >= 32 {
        return None;
    }
    if code == 0x7c && info1 & 0xffff == 0xf10d {
        let d = info1 >> 16;
        let reason = d & 255;
        let mode = (d >> 8) & 3;
        if d > 0x7ff
            || !is_valid_syscfg_reason(reason)
            || (mode == 3 && reason > 0x80)
            || (mode != 3 && (!(0x81..=0x85).contains(&reason) || d & 0x400 == 0))
        {
            return None;
        }
        return Some([
            0x1000_0085 | ((slot as u32) << 8) | ((d as u32) << 13),
            info2 as u32,
            (info2 >> 32) as u32,
        ]);
    }
    let (exit, kind, value) = if info1 & 0xffff == 0xf10c {
        let d = info1 >> 16;
        if d > 0x7ff || d & 7 == 0 {
            return None;
        }
        (d as u32, 15, info2)
    } else if code == 0x7c && matches!(info1 & 0xffff, 0xf108 | 0xf109) {
        let diagnostic = info1 >> 16;
        let reason = diagnostic & 0x1ff;
        let vmcr = info1 & 0xffff == 0xf109;
        // The fixed VM_CR profile has no initial-state or backing-mismatch error.
        if vmcr && matches!(reason, 1 | 2) {
            return None;
        }
        if diagnostic >> 9 > 2
            || !((1..=6).contains(&reason)
                || (0x10..=0x15).contains(&reason)
                || (0x20..=0x2d).contains(&reason)
                || (0x30..=0x35).contains(&reason)
                || (0x40..=0x4d).contains(&reason)
                || (0x50..=0x54).contains(&reason)
                || (0x60..=0x64).contains(&reason))
        {
            return None;
        }
        (diagnostic as u32, if vmcr { 12 } else { 11 }, info2)
    } else if code > 0x7ff {
        (0x7ff, 4, code)
    } else {
        let (kind, value) = match info1 {
            0xf001 => detailed_fetch(rip, info2).map_or((1, rip), |v| (10, v)),
            0xf102 => (5, rip),
            0xf103 => (6, rip),
            0xf104 => (2, info2),
            0xf105 => (7, rip),
            0xf107 => (9, info2),
            // A runtime context mismatch carries a host pointer, never a GPA.
            0xf10a => (0, rip),
            // Interrupted injected delivery carries EXITINTINFO, not an NPF
            // GPA (APM2 physical pp571-573). Keep the exact event in the full
            // stopped record; the compact unhandled-exit record retains RIP.
            0xf115 => (0, rip),
            // Missing bootstrap acknowledgment owner has no fault address.
            0xf116 => (0, rip),
            _ if code == 0x400 => (3, info2),
            _ => (0, rip),
        };
        (code as u32, kind, value)
    };
    Some([
        0x1000_0083 | ((slot as u32) << 8) | (exit << 13) | (kind << 24),
        value as u32,
        (value >> 32) as u32,
    ])
}

/// kind10 preserves canonical48 RIP and exact software predicate in 64 bits.
/// Noncanonical RIP falls back to the original full-width RIP-only record.
fn detailed_fetch(rip: u64, failure: u64) -> Option<u64> {
    let low = rip & 0xffff_ffff_ffff;
    let canonical = ((low << 16) as i64 >> 16) as u64;
    let base = failure & 255;
    let level = failure >> 8;
    let valid = if (0x14..=0x17).contains(&base) {
        (1..=4).contains(&level)
    } else {
        level == 0
            && ((1..=9).contains(&base)
                || (0x10..=0x13).contains(&base)
                || (0x18..=0x19).contains(&base)
                || (0x30..=0x3a).contains(&base))
    };
    (canonical == rip && valid).then_some(low | (failure << 48))
}

fn msr_failure_context(
    error: crate::svm::dispatch::NativeEferError,
    vmcb: &crate::svm::vmcb::Vmcb,
    logical: u64,
    instruction_bytes: Option<[u8; 2]>,
    tag: u64,
) -> (u64, u64) {
    use crate::svm::{
        dispatch::NativeEferError as E, events::MsrFaultError as M, exit::ResumeError as R,
    };
    let info = vmcb.exit_snapshot().info1;
    let instruction_value = |e| match e {
        R::UnsupportedInstructionBytes => {
            instruction_bytes.map(u16::from_le_bytes).map(u64::from).unwrap_or(0)
        }
        R::NonCanonicalRip => vmcb.exit_snapshot().rip,
        // EFER checked_instruction already proved addition does not overflow;
        // this error describes RIP+2, never the unrelated hardware NRIP field.
        R::NonCanonicalNrip => {
            if instruction_bytes.is_some() {
                vmcb.exit_snapshot().rip.wrapping_add(2)
            } else {
                vmcb.exit_snapshot().nrip
            }
        }
        R::NripNotEstablished => vmcb.exit_snapshot().nrip,
        R::InvalidInstructionLength => {
            if instruction_bytes.is_some() {
                2
            } else {
                vmcb.exit_snapshot().nrip
            }
        }
        R::ExitDoesNotPermitCandidate => info,
    };
    let (reason, value) = match error {
        E::UnsupportedInitialState => (1, logical),
        E::BackingMismatch => {
            (2, u64::from_le_bytes(vmcb.bytes()[0x4d0..0x4d8].try_into().unwrap()))
        }
        E::UnsupportedMode => {
            (3, u64::from_le_bytes(vmcb.bytes()[0x558..0x560].try_into().unwrap()))
        }
        E::UnsupportedDebugState => (4, vmcb.guest_rflags()),
        E::UnsupportedMsr { index, .. } => (5, index.into()),
        E::UnsupportedValue { value } => (6, value),
        E::Instruction(e) => (
            (if instruction_bytes.is_some() { 0x10 } else { 0x50 }) + instruction(e),
            instruction_value(e),
        ),
        E::PendingState(e) => {
            let (r, v) = pending(e);
            (0x20 + r, v)
        }
        E::Fault(M::Instruction(e)) => (
            (if instruction_bytes.is_some() { 0x30 } else { 0x60 }) + instruction(e),
            instruction_value(e),
        ),
        E::Fault(M::State(e)) => {
            let (r, v) = pending(e);
            (0x40 + r, v)
        }
    };
    let direction = match error {
        E::UnsupportedMsr { write, .. } => u64::from(write),
        _ => match info {
            0 => 0,
            1 => 1,
            _ => 2,
        },
    };
    (tag | ((reason | (direction << 9)) << 16), value)
}

fn instruction(e: crate::svm::exit::ResumeError) -> u64 {
    use crate::svm::exit::ResumeError as R;
    match e {
        R::ExitDoesNotPermitCandidate => 0,
        R::NripNotEstablished => 1,
        R::NonCanonicalRip => 2,
        R::NonCanonicalNrip => 3,
        R::InvalidInstructionLength => 4,
        R::UnsupportedInstructionBytes => 5,
    }
}

fn pending(e: crate::svm::events::ExternalInterruptError) -> (u64, u64) {
    use crate::svm::events::ExternalInterruptError as P;
    match e {
        P::PendingInjection => (5, 0),
        P::NestedDeliveryUnsupported => (6, 0),
        P::PendingVirtualInterrupt => (7, 0),
        P::UnsupportedControl { control } => (8, control),
        P::UnsupportedNestedControl { control } => (9, control),
        P::ControlMismatch => (10, 0),
        P::InvalidEntry => (11, 0),
        P::GuestShutdown => (12, 0),
    }
}

fn syscfg_context(reason: u64, mode: u64, write: bool, value: u64) -> (u64, u64) {
    (0xf10d | ((reason | (mode << 8) | (u64::from(write) << 10)) << 16), value)
}

fn is_valid_syscfg_reason(reason: u64) -> bool {
    (1..=6).contains(&reason)
        || (0x10..=0x15).contains(&reason)
        || (0x20..=0x2d).contains(&reason)
        || (0x30..=0x35).contains(&reason)
        || (0x40..=0x4d).contains(&reason)
        || (0x50..=0x55).contains(&reason)
        || (0x60..=0x65).contains(&reason)
        || (0x80..=0x85).contains(&reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retired_xapic_kinds_are_never_exported() {
        // Former kind8 is an ordinary NPF GPA observation.
        let npf = stop_words(0, 0x400, 0x1234, 0xf106, 0xfee00030).unwrap();
        assert_eq!((npf[0] >> 24) & 15, 3);
        assert_eq!(npf[1], 0xfee00030);
        // A context mismatch keeps its RIP on every exit, including NPF.
        for code in [0x400, 0x7c] {
            let words = stop_words(0, code, 0x5678, 0xf10a, 0xdead_beef).unwrap();
            assert_eq!((words[0] >> 24) & 15, 0);
            assert_eq!(words[1], 0x5678);
        }
        // Former kind13 detail tags no longer select a typed context.
        assert_eq!((stop_words(0, 0x400, 0, 0xf10a | (1 << 16), 9).unwrap()[0] >> 24) & 15, 3);
        // Nor does the retired kind-14 route record: F10Bh (the pre-arm stop,
        // or an old route detail) is an unhandled exit with its RIP.
        for info1 in [0xf10b, 0xf10b | (0x13 << 16)] {
            let words = stop_words(5, 0x7c, 0x5678, info1, 0x10_0000_c500).unwrap();
            assert_eq!(((words[0] >> 24) & 15, words[1]), (0, 0x5678));
        }
    }
    #[test]
    fn vmcr_diagnostics_preserve_distinct_identity_and_full_operand() {
        use crate::svm::{dispatch::NativeEferError as E, exit::ResumeError as R};
        let vmcb = crate::svm::vmcb::Vmcb::new();
        let before = *vmcb.bytes();
        let (tag, value) =
            vmcr_failure(E::UnsupportedValue { value: u64::MAX }, &vmcb, 0x10, [15, 48]);
        let words = stop_words(0, 0x7c, 0, tag, value).unwrap();
        assert_eq!((words[0] >> 24) & 15, 12);
        assert_eq!((words[0] >> 13) & 0x7ff, 6);
        assert_eq!([words[1], words[2]], [u32::MAX; 2]);
        let (tag, value) =
            vmcr_nrip_failure(E::Instruction(R::InvalidInstructionLength), &vmcb, 0x10);
        let words = stop_words(0, 0x7c, 0, tag, value).unwrap();
        assert_eq!((words[0] >> 13) & 0x7ff, 0x54);
        for reason in [1u64, 2, 0x55, 0x65, 0x600] {
            assert!(stop_words(0, 0x7c, 0, 0xf109 | (reason << 16), 0).is_none());
        }
        assert_eq!(vmcb.bytes(), &before);
    }
    #[test]
    fn efer_error_payload_is_full_width_and_instruction_is_explicit() {
        use crate::svm::{
            dispatch::NativeEferError as E, events::ExternalInterruptError as P,
            exit::ResumeError as R,
        };
        let vmcb = crate::svm::vmcb::Vmcb::new();
        let before = *vmcb.bytes();
        for (error, reason, value) in [
            (E::UnsupportedValue { value: 0xfedc_ba98_7654_3210 }, 6, 0xfedc_ba98_7654_3210),
            (E::Instruction(R::UnsupportedInstructionBytes), 0x15, 0x320f),
            (E::PendingState(P::UnsupportedControl { control: u64::MAX }), 0x28, u64::MAX),
            (E::PendingState(P::GuestShutdown), 0x2c, 0),
        ] {
            let (tag, payload) = efer_failure(error, &vmcb, 0xd01, [0x0f, 0x32]);
            assert_eq!(payload, value);
            let words = stop_words(23, 0x7c, 0xffff_ffff_ffff_ffff, tag, payload).unwrap();
            assert_eq!((words[0] >> 24) & 15, 11);
            assert_eq!((words[0] >> 13) & 0x7ff, reason);
            assert_eq!(words[1] as u64 | ((words[2] as u64) << 32), value);
        }
        assert_eq!(vmcb.bytes(), &before);
        let mut boundary = crate::svm::vmcb::Vmcb::new();
        // Deliberately stale hardware NRIP must not replace proposed RIP+2.
        unsafe {
            let bytes = (&mut boundary as *mut crate::svm::vmcb::Vmcb).cast::<u8>();
            core::ptr::copy_nonoverlapping(
                0x7fff_ffff_ffffu64.to_le_bytes().as_ptr(),
                bytes.add(0x578),
                8,
            );
            core::ptr::copy_nonoverlapping(0x1234u64.to_le_bytes().as_ptr(), bytes.add(0xc8), 8);
        }
        assert_eq!(
            efer_failure(E::Instruction(R::NonCanonicalNrip), &boundary, 0x500, [15, 50]).1,
            0x8000_0000_0001
        );
        for diagnostic in [0, 7, 0x16, 0x2e, 0x36, 0x4e, 0x600, 0x10000] {
            assert!(stop_words(0, 0x7c, 0, 0xf108 | (diagnostic << 16), 0).is_none());
        }
    }
    #[test]
    fn detailed_fetch_retains_rip_and_qualified_failure_only() {
        use super::super::fetch::FetchError;
        use crate::host::paging::WalkError;
        assert_eq!(
            fetch_failure_code(FetchError::Walk(WalkError::UnreadableTable {
                level: 3,
                address: 123
            })),
            0x314
        );
        for rip in [0, 0x7fff_ffff_ffff, 0xffff_8000_0000_0000, 0xffff_f800_b363_797a] {
            let words = stop_words(23, 0x7c, rip, 0xf001, 0x314).unwrap();
            assert_eq!((words[0] >> 24) & 15, 10);
            let context = words[1] as u64 | ((words[2] as u64) << 32);
            assert_eq!(context >> 48, 0x314);
            assert_eq!(((context << 16) as i64 >> 16) as u64, rip);
        }
        for failure in [0, 0x14, 0x514, 0x130, 0x3b, u64::MAX] {
            let words = stop_words(0, 0x7c, 0x1234, 0xf001, failure).unwrap();
            assert_eq!((words[0] >> 24) & 15, 1);
            assert_eq!(words[1], 0x1234);
        }
        let words = stop_words(0, 0x72, 0x8000_0000_0000, 0xf001, 4).unwrap();
        assert_eq!((words[0] >> 24) & 15, 1);
        assert_eq!(words[2], 0x8000);
    }
    #[test]
    fn fixed_record_preserves_wide_values_and_synthetic_context() {
        assert_eq!(stop_words(31, u64::MAX, 5, 0, 0), Some([0x14ff_ff83, u32::MAX, u32::MAX]));
        let words = stop_words(2, 0x7c, 0x1234, 0xf104, 0xc0010114).unwrap();
        assert_eq!((words[0] >> 24) & 15, 2);
        assert_eq!(words[1], 0xc0010114);
        assert!(stop_words(32, 0, 0, 0, 0).is_none());
    }
}
