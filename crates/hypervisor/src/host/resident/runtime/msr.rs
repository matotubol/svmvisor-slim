//! Native ICR routing, protected MSR completion and same-CPU physical accesses.
use crate::{
    arch::x86_64::{
        apic,
        msr::{HWCR, HWCR_MC_STATUS_WR_EN},
        registers::GuestRegisters,
    },
    host::resident::runtime::{
        State,
        guest_reader::fetch_instruction,
        startup::{mailboxes, route_native_startup, send_startup_notification},
        stop::stop,
    },
    svm::{
        dispatch,
        exit::{MsrInstruction, ResumeCandidate},
        vmcb::Vmcb,
    },
};
use core::arch::asm;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MsrCompletion {
    Complete { read: Option<u64> },
}

/// Intercept only the native x2APIC ICR. Startup commands use retained CPU mailboxes;
/// ordinary IPIs go to the physical LAPIC; the destination owns NMI virtualization.
pub(super) unsafe fn handle_native_icr(
    state: &mut State,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
) -> bool {
    let exit = vmcb.exit_snapshot();
    let boundary = 0xf104;
    if frame.rcx as u32 != apic::ICR_MSR || !native_msr_exit_ready(vmcb, state.startup_owned) {
        return stop(state, exit.code, exit.rip, boundary, 3);
    }
    let value = (vmcb.guest_rax() as u32 as u64) | ((frame.rdx as u32 as u64) << 32);
    if exit.info1 == 1 && (value & apic::ICR_RESERVED != 0 || matches!((value >> 8) & 7, 1 | 3 | 7))
    {
        // APM2 physical pp580,721,723: MSR-specific faults follow interception.
        // A fault retires nothing, so neither a continuation nor single-step
        // completion is required (physical pp305,470). No IPI may be sent.
        return reflect_msr_fault(state, vmcb, apic::ICR_MSR);
    }
    let Some(caps) = state.capabilities else {
        return stop(state, exit.code, exit.rip, boundary, 0);
    };
    let evidence = if caps.optional_features().nrip_save && vmcb.guest_in_64_bit_code() {
        MsrInstruction::hardware(exit, &caps)
    } else {
        Err(crate::svm::exit::ResumeError::ExitDoesNotPermitCandidate)
    };
    // Startup WRMSR also occurs in legacy code; use exact fetched instruction bytes there.
    let bytes;
    let evidence = match evidence {
        Ok(evidence) => evidence,
        Err(_) => {
            bytes = match unsafe { fetch_instruction(vmcb, state.startup_owned, state.count) } {
                Ok(bytes) => bytes,
                Err(reason) => return stop(state, exit.code, exit.rip, boundary, reason as u64),
            };
            MsrInstruction::Bytes(&bytes)
        }
    };
    let Ok(next) = evidence.continuation(exit) else {
        return stop(state, exit.code, exit.rip, boundary, 2);
    };
    if !dispatch::native_startup_instruction_mode(vmcb, evidence.length())
        || vmcb.guest_rflags() & (1 << 8) != 0
        || vmcb.validate_external_interrupt_conflicts().is_err()
    {
        return stop(state, exit.code, exit.rip, boundary, 3);
    }
    let completion = if exit.info1 == 0 {
        MsrCompletion::Complete { read: Some(state.icr_value) }
    } else if matches!((value >> 8) & 7, 5 | 6) {
        let Some(icr) = state.icr.as_mut() else {
            return stop(state, exit.code, exit.rip, boundary, 4);
        };
        // SAFETY: the armed CPU owns the retained inventory and its complete mailbox slice.
        let shared = unsafe { mailboxes(state.count) };
        if route_native_startup(icr, value, shared, |notification| {
            // SAFETY: routing admitted the peer destinations and published their queues;
            // this stopped sender owns x2APIC with IF/GIF clear and peers own R_INIT.
            unsafe { send_startup_notification(notification) }
        })
        .is_err()
        {
            return stop(state, exit.code, exit.rip, boundary, value);
        }
        MsrCompletion::Complete { read: None }
    } else {
        unsafe {
            write_msr(apic::ICR_MSR, value);
        }
        MsrCompletion::Complete { read: None }
    };
    match apply_msr_completion(vmcb, frame, completion, next) {
        Ok(fault) => {
            if !fault && exit.info1 == 1 {
                state.icr_value = value;
            }
            state.pending_fault |= fault;
            state.routing_retries = 0;
            true
        }
        Err((tag, value)) => stop(state, exit.code, exit.rip, tag, value),
    }
}

/// Intercepted MCAX machine-check MSR (`mcax`): the MSRPM cannot cover
/// C000_2000h-23FFh (APM2 rev3.44 Table 15-8 p518), so every guest access
/// exits and is repeated here on its own CPU. `None`: not an MCAX MSR, or a
/// boundary this path does not own; the caller keeps its F104h stop. All
/// instruction/profile checks precede physical MSR writes. Metadata reads
/// discover implemented banks rather than assuming all 64 banks exist.
/// # Safety
/// This CPU's armed dispatcher with its guest stopped and IF/GIF clear.
pub(super) unsafe fn handle_mcax_msr(
    state: &mut State,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
) -> Option<bool> {
    use crate::svm::mcax::{self, Access};
    let exit = vmcb.exit_snapshot();
    let index = frame.rcx as u32;
    if !(mcax::FIRST..=mcax::LAST).contains(&index)
        || state.target_msrs.is_none()
        || !native_msr_exit_ready(vmcb, state.startup_owned)
    {
        return None;
    }
    let write = (exit.info1 == 1)
        .then(|| (vmcb.guest_rax() as u32 as u64) | ((frame.rdx as u32 as u64) << 32));
    // Only documented, side-effect-free same-CPU metadata is read here.
    // Guest-controlled MSR writes occur only after continuation validation.
    let Some(access) = plan_mcax_access(index, write, |msr| unsafe { read_msr(msr) }) else {
        return Some(stop(state, exit.code, exit.rip, 0xf104, u64::from(index)));
    };
    if access == Access::GeneralProtection {
        return Some(reflect_msr_fault(state, vmcb, index));
    }
    let next = match unsafe { native_msr_continuation(state, vmcb) } {
        Ok(next) => next,
        Err(error) => return Some(msr_continuation_failure(state, vmcb, index, error)),
    };
    let completion = match access {
        // PPR57896 rev3.00 p300: unimplemented and unused registers in this
        // space are RAZ/WRIG, so neither host access can fault.
        Access::Read => MsrCompletion::Complete { read: Some(unsafe { read_msr(index) }) },
        Access::Write(value) => {
            unsafe {
                write_msr(index, value);
            }
            MsrCompletion::Complete { read: None }
        }
        Access::ReadZeroIgnoreWrite => {
            MsrCompletion::Complete { read: write.is_none().then_some(0) }
        }
        Access::GeneralProtection => unreachable!(),
    };
    Some(match apply_msr_completion(vmcb, frame, completion, next) {
        Ok(fault) => {
            state.pending_fault |= fault;
            state.routing_retries = 0;
            true
        }
        Err((tag, value)) => stop(state, exit.code, exit.rip, tag, value),
    })
}

/// Read only documented bank metadata, with no speculative access to an
/// arbitrary guest-selected MSR. PPR physical pp123,300-301,307,321.
fn plan_mcax_access(
    index: u32,
    write: Option<u64>,
    mut read: impl FnMut(u32) -> u64,
) -> Option<crate::svm::mcax::Access> {
    use crate::svm::mcax;
    if !(mcax::FIRST..=mcax::LAST).contains(&index) {
        return None;
    }
    let bank = (index - mcax::FIRST) >> 4;
    let cap = read(mcax::MCG_CAP);
    let ipid = if bank != 4 && bank < (cap & 0xff) as u32 {
        read((index & !0xf) | mcax::IPID_OFFSET)
    } else {
        0
    };
    let implemented = mcax::bank_implemented(index, cap, ipid);
    let status_writable = implemented
        && index & 0xf == 1
        && write.is_some_and(|value| value != 0)
        && read(HWCR) & HWCR_MC_STATUS_WR_EN != 0;
    mcax::plan(index, write, status_writable, implemented)
}

/// Complete documented target accesses without reading or writing the
/// corresponding physical control. Unknown contracts keep the caller's
/// diagnostic stop rather than becoming invented #GP exceptions.
/// # Safety
/// Same-CPU actual MSR exit; the stopped VMCB/frame and arm-time policy belong
/// to this admitted classic, non-SEV guest. No reference survives entry.
pub(super) unsafe fn handle_target_msr(
    state: &mut State,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
) -> Option<bool> {
    use crate::svm::target_msrs::Access;
    let exit = vmcb.exit_snapshot();
    if !native_msr_exit_ready(vmcb, state.startup_owned) {
        return None;
    }
    let index = frame.rcx as u32;
    let write = (exit.info1 == 1)
        .then(|| (vmcb.guest_rax() as u32 as u64) | ((frame.rdx as u32 as u64) << 32));
    let access = state.target_msrs?.plan(index, write)?;
    if access == Access::GeneralProtection {
        // Hardware already decoded RDMSR/WRMSR before this actual exit. A
        // proven fault retires nothing and needs neither nRIP nor guest fetch.
        return Some(reflect_msr_fault(state, vmcb, index));
    }
    let next = match unsafe { native_msr_continuation(state, vmcb) } {
        Ok(next) => next,
        Err(error) => return Some(msr_continuation_failure(state, vmcb, index, error)),
    };
    let completion =
        MsrCompletion::Complete { read: if access == Access::ReadZero { Some(0) } else { None } };
    Some(match apply_msr_completion(vmcb, frame, completion, next) {
        Ok(_) => {
            state.routing_retries = 0;
            true
        }
        Err((tag, value)) => stop(state, exit.code, exit.rip, tag, value),
    })
}

pub(super) fn native_msr_exit_ready(vmcb: &Vmcb, startup_owned: bool) -> bool {
    let exit = vmcb.exit_snapshot();
    // Common privilege faults precede the MSRPM intercept (APM2 physical p580).
    exit.code == 0x7c
        && exit.info1 <= 1
        && vmcb.guest_cpl() == 0
        && vmcb.validate_external_interrupt_conflicts().is_ok()
        && dispatch::validate_native_interrupt_profile(vmcb, startup_owned).is_ok()
}

fn msr_continuation_from_instruction(
    vmcb: &Vmcb,
    instruction: MsrInstruction<'_>,
    startup_owned: bool,
) -> Option<ResumeCandidate> {
    dispatch::validate_native_msr_boundary(vmcb, instruction, startup_owned).ok()?;
    if vmcb.guest_cpl() != 0
        || !dispatch::native_startup_instruction_mode(vmcb, instruction.length())
        || vmcb.guest_rflags() & (1 << 8) != 0
    {
        return None;
    }
    instruction.continuation(vmcb.exit_snapshot()).ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MsrContinuationError {
    Unsupported,
    Fetch(u16),
}

pub(super) unsafe fn native_msr_continuation(
    state: &State,
    vmcb: &Vmcb,
) -> Result<ResumeCandidate, MsrContinuationError> {
    use MsrContinuationError::{Fetch, Unsupported};
    let caps = state.capabilities.as_ref().ok_or(Unsupported)?;
    if caps.optional_features().nrip_save && vmcb.guest_in_64_bit_code() {
        let instruction =
            dispatch::hardware_msr_instruction(vmcb, caps).map_err(|_| Unsupported)?;
        return msr_continuation_from_instruction(vmcb, instruction, state.startup_owned)
            .ok_or(Unsupported);
    }
    let bytes =
        unsafe { fetch_instruction(vmcb, state.startup_owned, state.count) }.map_err(Fetch)?;
    msr_continuation_from_instruction(vmcb, MsrInstruction::Bytes(&bytes), state.startup_owned)
        .ok_or(Unsupported)
}

pub(super) fn msr_continuation_failure(
    state: &mut State,
    vmcb: &Vmcb,
    index: u32,
    error: MsrContinuationError,
) -> bool {
    let exit = vmcb.exit_snapshot();
    match error {
        MsrContinuationError::Fetch(reason)
            if reason
                == crate::host::resident::terminal::FetchReadFailure::MemoryControlBusy as u16 =>
        {
            // No access has committed. Retry the unchanged instruction using
            // the dispatcher budget; do not refetch and lose the first result.
            super::exit::retry_routing(state, vmcb)
        }
        MsrContinuationError::Fetch(reason) => {
            stop(state, exit.code, exit.rip, 0xf001, u64::from(reason))
        }
        MsrContinuationError::Unsupported => {
            stop(state, exit.code, exit.rip, 0xf104, u64::from(index))
        }
    }
}

fn reflect_msr_fault(state: &mut State, vmcb: &mut Vmcb, index: u32) -> bool {
    if vmcb.queue_native_general_protection().is_ok() {
        state.pending_fault = true;
        state.routing_retries = 0;
        true
    } else {
        let exit = vmcb.exit_snapshot();
        stop(state, exit.code, exit.rip, 0xf104, u64::from(index))
    }
}

/// Apply one completion to the stopped guest. A completed RDMSR loads
/// EDX:EAX (in 64-bit mode the upper halves of RAX and RDX become zero), and
/// every completed access continues at `next` with the interrupt shadow and
/// RF consumed. Faults are reflected before constructing a continuation.
/// The shared completion interface retains its result for the runtime callers.
pub(super) fn apply_msr_completion(
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    completion: MsrCompletion,
    next: ResumeCandidate,
) -> Result<bool, (u64, u64)> {
    match completion {
        MsrCompletion::Complete { read } => {
            let rax = match read {
                Some(value) => {
                    frame.rdx = value >> 32;
                    value & 0xffff_ffff
                }
                None => vmcb.guest_rax(),
            };
            vmcb.commit_emulated_instruction(rax, next);
            vmcb.complete_native_instruction_state();
            Ok(false)
        }
    }
}

/// Owning native CPU with the selected MSR enumerated/admitted: x2APIC
/// registers require the fixed enabled bus; VM_CR requires admitted AMD SVM.
/// APM2 15.30.1/16.11 and applicable PPR57896 register definitions.
pub(super) unsafe fn read_msr(index: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!("rdmsr",in("ecx")index,out("eax")low,out("edx")high,
        options(nomem,nostack,preserves_flags));
    }
    low as u64 | ((high as u64) << 32)
}

/// Same owning CPU; an admitted non-APIC MSR value checked by its owner
/// (VM_CR.R_INIT preserving every other bit, SYS_CFG, HWCR, a
/// guest MCAX write that `mcax::plan` admitted) or
/// the fixed private INIT notification ICR. Guest x2APIC state reaches the
/// physical LAPIC through its native MSRs. APM2 rev3.44 15.30.1/16.13 and
/// PPR57896 p215. No MSR may fault.
pub(super) unsafe fn write_msr(index: u32, value: u64) {
    unsafe {
        asm!("wrmsr", in("ecx") index, in("eax") value as u32,
            in("edx") (value >> 32) as u32, options(nostack, preserves_flags));
    }
}

#[cfg(test)]
mod tests;
