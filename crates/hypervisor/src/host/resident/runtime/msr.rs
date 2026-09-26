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
    Fault,
}

/// Intercept only the native x2APIC ICR. Startup commands use retained CPU mailboxes;
/// ordinary fixed/NMI IPIs go to the physical LAPIC without software interrupt delivery.
pub(super) unsafe fn handle_native_icr(
    state: &mut State,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
) -> bool {
    let exit = vmcb.exit_snapshot();
    let boundary = 0xf104;
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
    let value = (vmcb.guest_rax() as u32 as u64) | ((frame.rdx as u32 as u64) << 32);
    let fault = vmcb.bytes()[0x4cb] != 0
        || (exit.info1 == 1
            && (value & apic::ICR_RESERVED != 0 || matches!((value >> 8) & 7, 1 | 3 | 7)));
    let completion = if fault {
        MsrCompletion::Fault
    } else if exit.info1 == 0 {
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
/// boundary this path does not own (no NRIPS, outside 64-bit code, TF, a
/// changed profile or a pending event); the caller keeps its F104h stop.
/// # Safety
/// This CPU's armed dispatcher with its guest stopped and IF/GIF clear.
pub(super) unsafe fn handle_mcax_msr(
    state: &mut State,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
) -> Option<bool> {
    use crate::svm::{
        exit::MsrInstruction,
        mcax::{self, Access},
    };
    let exit = vmcb.exit_snapshot();
    let index = frame.rcx as u32;
    if !(mcax::FIRST..=mcax::LAST).contains(&index) {
        return None;
    }
    let write = (exit.info1 == 1)
        .then(|| (vmcb.guest_rax() as u32 as u64) | ((frame.rdx as u32 as u64) << 32));
    let status_writable = unsafe { read_msr(HWCR) } & HWCR_MC_STATUS_WR_EN != 0;
    let access = mcax::plan(index, write, status_writable)?;
    // RDMSR/WRMSR above CPL0 fault before the MSRPM check (15.11 p518).
    let caps = state.capabilities.filter(|caps| {
        caps.optional_features().nrip_save
            && vmcb.guest_in_64_bit_code()
            && vmcb.bytes()[0x4cb] == 0
    })?;
    let evidence = MsrInstruction::hardware(exit, &caps).ok()?;
    let next = evidence.continuation(exit).ok()?;
    if vmcb.validate_external_interrupt_conflicts().is_err()
        || !dispatch::native_startup_instruction_mode(vmcb, evidence.length())
        || vmcb.guest_rflags() & (1 << 8) != 0
    {
        return None;
    }
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
        Access::GeneralProtection => MsrCompletion::Fault,
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

/// Apply one completion to the stopped guest. A completed RDMSR loads
/// EDX:EAX (in 64-bit mode the upper halves of RAX and RDX become zero), and
/// every completed access continues at `next` with the interrupt shadow and
/// RF consumed. A fault queues #GP(0) at the unchanged RIP (`Ok(true)`).
/// `Err` is a stop reason and value; the guest is then unchanged.
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
        MsrCompletion::Fault => match vmcb.queue_native_general_protection() {
            Ok(()) => Ok(true),
            Err(_) => Err((0xf104, 4)),
        },
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
