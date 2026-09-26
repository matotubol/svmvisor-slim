//! The dispatcher: exit history, exit sequencing against the startup service and
//! the acknowledged guest's exit handlers.

use core::ptr;

use crate::{
    arch::x86_64::{
        apic,
        msr::{EFER, MMIO_CFG_BASE_ADDR, VM_CR},
        registers::GuestRegisters,
    },
    host::resident::{
        BridgeContext,
        runtime::{
            CONTEXT, EXIT_HISTORY, EXIT_HISTORY_COUNT, EXIT_HISTORY_NEXT, FRAME, NPT, STATE, State,
            VMCB, configuration,
            diagnostics::record as diagnostic_record,
            guest_reader::fetch_instruction,
            interrupt,
            msr::{handle_mcax_msr, handle_native_icr},
            startup::{
                acknowledge_init, finish_guest_startup, mailboxes, route_physical_nmi_to_guest,
                service_startup,
            },
            stop::{stop, terminal_control, terminal_enabled, terminal_finish, terminal_requested},
        },
        terminal::{self},
    },
    svm::{
        control_msrs,
        dispatch::{self, NativeMsrOutcome},
        events::DeliveryError,
        exit::{EXIT_GP, ExitSnapshot},
        instructions::handle_native_svm_instruction,
        vmcb::Vmcb,
    },
};

/// The stopped exit that `dispatch_body` is handling.
struct ExitContext<'a> {
    state: &'a mut State,
    vmcb: &'a mut Vmcb,
    frame: &'a mut GuestRegisters,
    exit: ExitSnapshot,
}

/// # Safety
/// Called only by the audited integer assembly after VMEXIT, host auxiliary
/// restore, private stack and GIF/IF clear. The one stopped guest is exclusive.
pub(super) unsafe extern "win64" fn dispatch(context: *mut BridgeContext) -> bool {
    let state = unsafe { &mut *ptr::addr_of_mut!(STATE) };
    if context != ptr::addr_of_mut!(CONTEXT) {
        let exit = unsafe { &*ptr::addr_of!(VMCB) }.exit_snapshot();
        stop(state, exit.code, exit.rip, 0xf10a, context as u64);
        unsafe { terminal_finish(state) };
        return false;
    }
    // The nonmigrating assembly returned on this image's sole VMCB. Establish
    // reusable cached groups and consume the old RAP request before event
    // handling or any emulation can change guest state.
    let vmcb = unsafe { &mut *ptr::addr_of_mut!(VMCB) };
    unsafe {
        state.vmcb_cache.after_exit(vmcb, super::ASSIGNED_APIC_ID, ptr::addr_of!(VMCB) as u64);
        vmcb.consume_rap_clear_after_exit();
    }
    if unsafe { terminal_requested(state) } {
        unsafe { terminal_finish(state) };
        return false;
    }
    let before = unsafe { &*ptr::addr_of!(VMCB) }.exit_snapshot();
    unsafe {
        let frame = ptr::read_volatile(ptr::addr_of!(FRAME));
        let rax = (&*ptr::addr_of!(VMCB)).guest_rax();
        let index = EXIT_HISTORY_NEXT;
        ptr::addr_of_mut!(EXIT_HISTORY).cast::<[u64; 6]>().add(index).write([
            before.rip,
            before.code,
            before.info1,
            before.info2,
            frame.rcx,
            (rax as u32 as u64) | ((frame.rdx as u32 as u64) << 32),
        ]);
        EXIT_HISTORY_NEXT = (index + 1) % 5;
        EXIT_HISTORY_COUNT = (EXIT_HISTORY_COUNT + 1).min(5);
    }

    // The inner body's RAII route guards must be gone before terminal work.
    let resume = unsafe { dispatch_body(context) };
    let state = unsafe { &mut *ptr::addr_of_mut!(STATE) };
    // Every terminal return needs evidence, including an unforeseen callee
    // refusal. Route guards have unwound before private stop coordination.
    if !unsafe { terminal_requested(state) } {
        record_unexplained_stop(state, resume, before);
    }
    if unsafe { terminal_requested(state) } || (!resume && state.stopped_valid) {
        unsafe { terminal_finish(state) };
        return false;
    }
    if resume && before.code != 0x77 && (before.code != 0x72 || state.exits & 0xff == 1) {
        let vmcb = unsafe { &*ptr::addr_of!(VMCB) };
        unsafe {
            diagnostic_record(
                2,
                false,
                [
                    vmcb.guest_rip(),
                    before.code,
                    before.info1,
                    before.info2,
                    vmcb.guest_cr3(),
                    state.exits,
                ],
                0,
            );
        }
    }
    if resume {
        // Requeue NMIs caught in a host GIF window after old EVENTINJ completion and
        // guest instruction/startup handling, so new injection remains pending for VMRUN.
        let vmcb = unsafe { &mut *ptr::addr_of_mut!(VMCB) };
        if !unsafe { super::cache::service(state, vmcb) } {
            unsafe { terminal_finish(state) };
            return false;
        }
        unsafe { route_physical_nmi_to_guest(vmcb) };
        // No host GIF window follows this decision on the ordinary entry path.
        // Preserve opportunistic exits only while an existing service needs them.
        super::maintenance::prepare_pause(
            vmcb,
            state.pause_filter_supported,
            state.guest_started,
            super::svmvisor_resident_nmi_pending.load(core::sync::atomic::Ordering::Acquire) != 0,
        );
        if !unsafe { configuration::verify(state, vmcb) } {
            unsafe { terminal_finish(state) };
            return false;
        }
        let sources_valid = state.capabilities.as_ref().is_some_and(|caps| {
            unsafe { super::viommu::verify_sources(vmcb, caps.address_policy()) }.is_ok()
        });
        if !sources_valid {
            let exit = vmcb.exit_snapshot();
            stop(state, exit.code, exit.rip, 0xf215, 0);
            unsafe { terminal_finish(state) };
            return false;
        }
        // Last software boundary before assembly VMLOAD/VMRUN.
        // No VMCB reference survives the world switch.
        state.vmcb_cache.prepare_entry(
            vmcb,
            unsafe { super::ASSIGNED_APIC_ID },
            ptr::addr_of!(VMCB) as u64,
        );
    }
    resume
}

/// Contention performed no guest/register/queue/hardware commit. Re-enter at
/// the unchanged faulting instruction, bounded to1024 attempts; do not turn a
/// normal concurrent AP mode transition into a falsely completed instruction.
pub(super) fn retry_routing(state: &mut State, vmcb: &Vmcb) -> bool {
    state.routing_retries = state.routing_retries.saturating_add(1);
    if state.routing_retries <= 1024 {
        return true;
    }
    let exit = vmcb.exit_snapshot();
    stop(state, exit.code, exit.rip, 0xf107, state.routing_retries as u64)
}

pub(super) fn check_exit_event(state: &mut State, vmcb: &mut Vmcb) -> bool {
    // #GP owns prior delivery and the new fault in one transaction. Reinjecting
    // EXITINTINFO here would discard the secondary fault or loop indefinitely.
    if vmcb.exit_snapshot().code == EXIT_GP {
        return true;
    }
    let error = match vmcb.complete_event_delivery(&mut state.pending_fault) {
        Ok(()) => return true,
        Err(error) => error,
    };
    let exit = vmcb.exit_snapshot();
    match error {
        DeliveryError::UnusableGuestState => stop(state, exit.code, 0, 0xf110, 0),
        DeliveryError::InjectionCompletion(_) => {
            let interrupted = u64::from_le_bytes(vmcb.bytes()[0x088..0x090].try_into().unwrap());
            stop(state, exit.code, exit.rip, 0xf10c, interrupted)
        }
        DeliveryError::UnsupportedInterruptedEvent { interrupted } => {
            stop(state, exit.code, exit.rip, 0xf10f, interrupted)
        }
        DeliveryError::ConflictingInterruptedEvent { interrupted } => {
            stop(state, exit.code, exit.rip, 0xf112, interrupted)
        }
    }
}

pub(super) fn record_unexplained_stop(
    state: &mut State,
    resume: bool,
    exit: crate::svm::exit::ExitSnapshot,
) {
    if !resume && !state.stopped_valid {
        stop(state, exit.code, exit.rip, 0xf10e, exit.info1);
    }
}

unsafe fn dispatch_body(context: *mut BridgeContext) -> bool {
    // The outer dispatcher validated context without dereferencing it.
    debug_assert!(context == ptr::addr_of_mut!(CONTEXT));
    let state = unsafe { &mut *ptr::addr_of_mut!(STATE) };
    let vmcb = unsafe { &mut *ptr::addr_of_mut!(VMCB) };
    let frame = unsafe { &mut *ptr::addr_of_mut!(FRAME) };
    state.exits = state.exits.saturating_add(1);
    if !state.armed {
        // F10Bh without detail: retain an exit-before-arm reason privately.
        let exit = vmcb.exit_snapshot();
        return stop(state, exit.code, exit.rip, 0xf10b, 0);
    }
    if !interrupt::validate_entry(vmcb) {
        let exit = vmcb.exit_snapshot();
        return stop(state, exit.code, exit.rip, 0xf114, vmcb.virtual_interrupt_control());
    }
    if !super::minimal::valid(vmcb) {
        let exit = vmcb.exit_snapshot();
        return stop(state, exit.code, exit.rip, 0xf114, 0);
    }
    let observed = vmcb.exit_snapshot();
    // Legacy progress observations remain bounded. The private record sink
    // ignores nonfault events and performs no device publication.
    if !matches!(observed.code, 0x72 | 0x77) || state.exits & 0xff == 1 {
        unsafe {
            diagnostic_record(
                1,
                false,
                [
                    observed.rip,
                    observed.code,
                    observed.info1,
                    observed.info2,
                    vmcb.guest_cr3(),
                    state.exits,
                ],
                if observed.code == 0x7c { frame.rcx as u32 } else { 0 },
            );
        }
    }
    // Audited assembly has returned from VMRUN on this CPU. Consume its old
    // flush before INIT, EFER or any other dispatcher mutation can re-arm it.
    // An invalid entry does not establish that the requested flush occurred.
    unsafe {
        super::cache::after_exit(vmcb);
        vmcb.consume_tlb_flush_after_exit();
    }
    // Permanent route state is verified before startup, cache service or guest
    // instruction effects. No ECAM write window exists to close or reopen.
    if !unsafe { configuration::verify(state, vmcb) } {
        return false;
    }
    if state.startup_owned {
        let Some(acknowledged) = (unsafe { acknowledge_init() }) else {
            return stop(state, vmcb.exit_snapshot().code, vmcb.guest_rip(), 0xf102, 0);
        };
        if vmcb.exit_snapshot().code == 0x63 && acknowledged == 0 {
            return stop(state, 0x63, vmcb.guest_rip(), 0xf105, 0);
        }
    }
    if !check_exit_event(state, vmcb) {
        return false;
    }
    if !unsafe { super::cache::service(state, vmcb) } {
        return false;
    }
    let exit = vmcb.exit_snapshot();
    let Some(ack) = state.ack.as_mut() else {
        return stop(state, exit.code, exit.rip, 0xf10d, 0);
    };
    if !ack.acknowledged() {
        if ack.acknowledge(vmcb, frame).is_ok() {
            unsafe {
                super::cache::ready(state);
            }
            if state.startup_owned {
                (unsafe { mailboxes(state.count) })[state.slot].mark_running();
                if terminal_enabled(state) {
                    // Separate monotonic initial-ACK mask, not mutable guest
                    // startup readiness. The last initial ACK admits stop coordination.
                    let _ = unsafe { terminal_control() }.initial_ack(state.slot, state.count);
                    unsafe {
                        diagnostic_record(
                            9,
                            false,
                            [
                                vmcb.guest_rip(),
                                vmcb.guest_cr3(),
                                state.slot as u64,
                                state.count as u64,
                                0,
                                0,
                            ],
                            0,
                        );
                    }
                }
            }
            return true;
        }
        return stop(state, exit.code, exit.rip, exit.info1, exit.info2);
    }
    let mut context = ExitContext { state, vmcb, frame, exit };
    // Retained intercepted instructions have not executed. Apply a queued INIT
    // first; if it changes this CPU, never complete the superseded instruction.
    let resume = match unsafe { startup_service(&mut context) } {
        Some(resume) => resume,
        None => unsafe { handle_exit(&mut context) },
    };
    // A still-intercepted ICR write in this exit has already been routed above.
    if resume {
        unsafe { finish_guest_startup(context.state, context.vmcb) };
    }
    resume
}

/// `service_startup` for one exit, with its stop fallback.
/// # Safety
/// As `service_startup`.
unsafe fn startup_service(context: &mut ExitContext<'_>) -> Option<bool> {
    let ExitContext { state, vmcb, frame, exit } = context;
    let (state, vmcb, frame, exit) = (&mut **state, &mut **vmcb, &mut **frame, *exit);
    if !state.startup_owned {
        return None;
    }
    match unsafe { service_startup(state, vmcb, frame) } {
        Some(true) => Some(true),
        Some(false) if unsafe { terminal_requested(state) } => Some(false),
        Some(false) if state.stopped_valid => Some(false),
        Some(false) => Some(stop(state, exit.code, exit.rip, 0xf103, 0)),
        None => None,
    }
}

/// The acknowledged guest's exit handlers.
/// # Safety
/// This CPU's armed dispatcher with its guest stopped and IF/GIF clear.
unsafe fn handle_exit(context: &mut ExitContext<'_>) -> bool {
    let ExitContext { state, vmcb, frame, exit } = context;
    let (state, vmcb, frame, exit) = (&mut **state, &mut **vmcb, &mut **frame, *exit);
    // A guarded destination must never reach generic device recovery or be
    // supplied from the frozen host DRAM mapping. Preserve the hardware access
    // direction in EXITINFO1 and report the exact guest physical address.
    if exit.code == 0x400 {
        match crate::memory::npt::identity_is_quarantined(
            unsafe { &(*ptr::addr_of!(NPT)).0 },
            ptr::addr_of!(NPT) as u64,
            exit.info2,
        ) {
            Ok(true) => return stop(state, exit.code, exit.rip, 0xf401, exit.info2),
            Err(_) => return stop(state, exit.code, exit.rip, 0xf400, 19),
            Ok(false) => {}
        }
    }
    match exit.code {
        EXIT_GP => return unsafe { super::protection::handle(state, vmcb) },
        0x81 => {
            // Bootstrap acknowledgement is the only VMMCALL consumed by this runtime,
            // and its one-shot owner runs before this acknowledged-guest dispatcher.
            // There is no guest service ABI. Preserve any event being re-injected
            // before retrying this instruction; never replace its delivery.
            if vmcb.event_injection() & (1 << 31) != 0 {
                return true;
            }
            // Every later VMMCALL follows native #UD behavior (APM2 physical page 593;
            // APM3 physical page 536), independent of operands or guest privilege.
            // The hardware exit identifies the instruction, and a fault retains CS:RIP.
            if vmcb.queue_vmmcall_invalid_opcode().is_ok() {
                state.pending_fault = true;
                return true;
            }
        }
        0x7a | 0x80 | 0x82..=0x86 => {
            // Complete interrupted delivery first, then retry the original
            // instruction. Never replace a pending event with a fresh fault.
            if vmcb.event_injection() & (1 << 31) != 0 {
                return true;
            }
            if let (Some(owner), Some(efer)) =
                (state.svm_instructions.as_ref(), state.efer.as_ref())
                && handle_native_svm_instruction(owner, efer, vmcb).is_ok()
            {
                state.pending_fault = true;
                return true;
            }
            // A legal instruction still needs its own execution owner. Keep
            // the actual exit intact instead of inventing an architectural fault.
        }
        0x77 => {
            // Reenter unchanged: VMRUN replenishes the nonzero PAUSE count,
            // and hardware executes this instruction, including debug state.
            unsafe {
                diagnostic_record(5, false, [exit.rip, vmcb.guest_cr3(), state.exits, 0, 0, 0], 0);
            }
            if crate::svm::vmcb::native_pause_retry_ready(vmcb) {
                return true;
            }
            return stop(state, exit.code, exit.rip, exit.info1, exit.info2);
        }
        0x63 if state.startup_owned => {
            // Actual host #SX(error1) acknowledgment was checked above. A
            // notification is only a wakeup: commands live in the mailbox,
            // and multiple notifications may coalesce without losing commands.
            // `check_exit_event` owns the pending-event state: like every
            // intercept, this one may report an interrupted delivery (15.7.2
            // p509), which it has re-injected, so EVENTINJ.V is not a refusal.
            return true;
        }
        0x7b => return unsafe { configuration::handle_io(state, vmcb) },
        0x7c => {
            if frame.rcx as u32 == MMIO_CFG_BASE_ADDR {
                return unsafe { configuration::handle_msr(state, vmcb, frame) };
            }
            if crate::svm::cache_policy::owned_msr(frame.rcx as u32) {
                return unsafe { super::cache::handle(state, vmcb, frame) };
            }
            if frame.rcx as u32 == apic::ICR_MSR {
                return unsafe { handle_native_icr(state, vmcb, frame) };
            }
            if let Some(resume) = unsafe { handle_mcax_msr(state, vmcb, frame) } {
                return resume;
            }
            let svm_control = control_msrs::owned_msr(frame.rcx as u32);
            if svm_control && vmcb.event_injection() & (1 << 31) != 0 {
                return true;
            }
            // Actual same-CPU MSR exit plus NRIPS owns the decoded instruction
            // length, including prefixes. Route owned MSRs before guest-byte fetch.
            // Other MSRs and non-long64 profiles retain their existing byte owner.
            let hardware_nrip = state.capabilities.filter(|caps| {
                caps.optional_features().nrip_save
                    && vmcb.guest_in_64_bit_code()
                    && vmcb.bytes()[0x4cb] == 0
                    && (svm_control || matches!(frame.rcx as u32, EFER | VM_CR))
            });
            if svm_control && let Some(caps) = hardware_nrip {
                let result = super::minimal::control_msrs_with_nrip(state, vmcb, frame, &caps);
                return complete_control_msr_exit(state, vmcb, frame, result);
            }
            if frame.rcx as u32 == VM_CR
                && let Some(caps) = hardware_nrip
            {
                let result = super::minimal::vmcr_with_nrip(state, vmcb, frame, &caps);
                match result {
                    Ok(NativeMsrOutcome::Completed) => {
                        state.routing_retries = 0;
                        return true;
                    }
                    Ok(NativeMsrOutcome::GeneralProtectionPrepared) => {
                        state.pending_fault = true;
                        return true;
                    }
                    Err(error) => {
                        let (reason, value) =
                            super::terminal::vmcr_nrip_failure(error, vmcb, vmcr_value(state));
                        return stop(state, exit.code, exit.rip, reason, value);
                    }
                }
            }
            if let (Some(caps), Some(efer)) = (hardware_nrip, state.efer.as_mut()) {
                match dispatch::handle_native_efer_with_nrip(efer, vmcb, frame, &caps) {
                    Ok(NativeMsrOutcome::Completed) => {
                        state.routing_retries = 0;
                        return true;
                    }
                    Ok(NativeMsrOutcome::GeneralProtectionPrepared) => {
                        state.pending_fault = true;
                        return true;
                    }
                    Err(error) => {
                        let (reason, value) =
                            super::terminal::efer_nrip_failure(error, vmcb, efer.logical());
                        return stop(state, exit.code, exit.rip, reason, value);
                    }
                }
            }
            let instruction = match unsafe {
                fetch_instruction(vmcb, state.startup_owned, state.count)
            } {
                Ok(bytes) => bytes,
                Err(reason) if reason == terminal::FetchReadFailure::MemoryControlBusy as u16 => {
                    return retry_routing(state, vmcb);
                }
                Err(reason) => return stop(state, exit.code, exit.rip, 0xf001, reason as u64),
            };
            if svm_control {
                let result = super::minimal::control_msrs(state, vmcb, frame, &instruction);
                return complete_control_msr_exit(state, vmcb, frame, result);
            }
            if frame.rcx as u32 == VM_CR {
                let result = super::minimal::vmcr(state, vmcb, frame, &instruction);
                match result {
                    Ok(NativeMsrOutcome::Completed) => {
                        state.routing_retries = 0;
                        return true;
                    }
                    Ok(NativeMsrOutcome::GeneralProtectionPrepared) => {
                        state.pending_fault = true;
                        return true;
                    }
                    Err(error) => {
                        let (reason, value) = super::terminal::vmcr_failure(
                            error,
                            vmcb,
                            vmcr_value(state),
                            instruction,
                        );
                        return stop(state, exit.code, exit.rip, reason, value);
                    }
                }
            }

            if let Some(efer) = state.efer.as_mut() {
                match dispatch::handle_native_efer(efer, vmcb, frame, &instruction) {
                    Ok(NativeMsrOutcome::Completed) => {
                        state.routing_retries = 0;
                        return true;
                    }
                    Ok(NativeMsrOutcome::GeneralProtectionPrepared) => {
                        state.pending_fault = true;
                        return true;
                    }
                    Err(error) if frame.rcx as u32 == EFER => {
                        let (reason, value) =
                            super::terminal::efer_failure(error, vmcb, efer.logical(), instruction);
                        return stop(state, exit.code, exit.rip, reason, value);
                    }
                    Err(_) => {}
                }
            }
            // A decoded but unsupported/failed MSR exit remains stopped. Keep
            // its operand index in the typed terminal record; VMCB/GPR state
            // and the raw architectural exit fields remain untouched.
            return stop(state, exit.code, exit.rip, 0xf104, frame.rcx);
        }
        0x400 if state.startup_owned => {
            let tracked = state
                .capabilities
                .as_ref()
                .map(|caps| unsafe { super::viommu::tracked_write(vmcb, caps.address_policy()) });
            if !matches!(tracked, Some(Ok(false))) {
                // Arbitrary table mutation requires the complete all-CPU and
                // DMA source barrier. Never reopen the page or commit a MOV
                // approximation while that protocol is unavailable.
                return stop(state, exit.code, exit.rip, 0xf215, 1);
            }
            if state.configuration.is_some_and(|route| route.contains(exit.info2)) {
                return configuration::refuse_ecam(state, vmcb);
            }
            return stop(state, exit.code, exit.rip, exit.info1, exit.info2);
        }
        _ => {}
    }
    stop(state, exit.code, exit.rip, exit.info1, exit.info2)
}

fn vmcr_value(state: &State) -> u64 {
    state.vmcr.as_ref().map_or(0, |owner| owner.logical())
}

fn complete_control_msr_exit(
    state: &mut State,
    vmcb: &Vmcb,
    frame: &GuestRegisters,
    result: Result<NativeMsrOutcome, dispatch::NativeEferError>,
) -> bool {
    match result {
        Ok(NativeMsrOutcome::Completed) => {
            state.routing_retries = 0;
            true
        }
        Ok(NativeMsrOutcome::GeneralProtectionPrepared) => {
            state.pending_fault = true;
            true
        }
        Err(_) => {
            let exit = vmcb.exit_snapshot();
            stop(state, exit.code, exit.rip, 0xf104, frame.rcx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        arch::x86_64::msr::{
            AVIC_DOORBELL, SMM_CTL, TSC_RATIO, TSC_RATIO_DEFINED, TSC_RATIO_UNITY, VIRTUAL_TOM,
        },
        guest::continuation::{NATIVE_BOOTSTRAP_ACK, NativeBootstrapAck},
        host::resident::runtime::INITIAL_STATE,
        svm::{
            control_msrs::{SVM_LOCK_KEY, VM_HSAVE_PA},
            events::ExternalInterruptError,
        },
    };

    // Historical wire values are test inputs only. No production feature may
    // turn them back into a callable reader or experiment interface.
    const RETIRED_CALLS: [(u64, u64); 7] = [
        (0x5356_4d4c_4f43_414c, 0), // Reader PROBE.
        (0x5356_4d4c_4f43_414c, 1), // Reader SUBMIT, including HELLO.
        (0x5356_4d4c_4f43_414c, 2), // Reader STEP.
        (0x5356_4d4c_4f43_414c, 3), // Reader ABORT.
        (0x5356_4d4c_4f43_414c, 4), // Reader CONTEXT.
        (0x3154_454d_4756_4d53, 1), // Experiment ARM.
        (0x3154_454d_4756_4d53, 2), // Experiment QUERY.
    ];

    fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
        // SAFETY: tests exclusively own these inert VMCB bytes and use in-bounds field offsets.
        unsafe {
            ptr::from_mut(vmcb).cast::<u8>().add(offset).cast::<u64>().write_unaligned(value);
        }
    }

    fn stopped(magic: u64, cpl: u8) -> (State, Vmcb, GuestRegisters) {
        let state = INITIAL_STATE;
        let mut vmcb = Vmcb::new();
        for (offset, value) in [
            (0x070, 0x81),
            (0x078, u64::MAX), // Undefined exit information must not become an operand.
            (0x080, u64::MAX),
            (0x0c0, u64::from(u32::MAX)),
            (0x0c8, u64::MAX), // Fault delivery requires neither NRIPS nor instruction bytes.
            (0x410, 0x2fb << 16),
            (0x4c8, u64::from(cpl) << 24),
            (0x4d0, 0x1500),
            (0x548, 0x20),
            (0x550, 0x4000),
            (0x558, 0x8000_0011),
            (0x570, 0x10102), // Retain TF/RF; the faulted instruction has not completed.
            (0x578, 0x2ffe),  // No instruction-memory read, even across a page boundary.
            (0x5d8, 0x8000),
            (0x5f8, magic),
            (0x640, 0x1234), // CR2 is not part of #UD delivery.
        ] {
            put(&mut vmcb, offset, value);
        }
        let frame = GuestRegisters {
            rcx: 1,
            rdx: 2,
            rbx: 3,
            rbp: 4,
            rsi: 5,
            rdi: 6,
            r8: 7,
            r9: 8,
            r10: 9,
            r11: 10,
            r12: 11,
            r13: 12,
            r14: 13,
            r15: 14,
        };
        (state, vmcb, frame)
    }

    fn dispatch_unclaimed(state: &mut State, vmcb: &mut Vmcb, frame: &mut GuestRegisters) -> bool {
        let exit = vmcb.exit_snapshot();
        let mut context = ExitContext { state, vmcb, frame, exit };
        // SAFETY: these tests select only inert instruction/MSR emulation or refusal paths.
        // They never activate SVM, fetch guest memory or touch a resident channel.
        unsafe { handle_exit(&mut context) }
    }

    fn stopped_svm() -> (State, Vmcb, GuestRegisters) {
        use crate::{
            arch::x86_64::{
                capabilities::{CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures},
                msr::TARGET_SIGNATURE,
            },
            memory::address::EncryptionState,
            svm::{
                control_msrs::{HsaveAddressPolicy, VisibleSvmControls},
                dispatch::NativeEfer,
                instructions::NativeSvmInstructions,
                vmcr::VisibleVmCr,
            },
        };
        let (mut state, mut vmcb, frame) = stopped(0, 0);
        let caps = CapabilityEvidence {
            vendor: CpuVendor::Amd,
            svm: EvidenceFlag::Set,
            nested_paging: EvidenceFlag::Set,
            svm_revision: Some(1),
            asid_count: Some(16),
            physical_address_bits: Some(48),
            vm_cr_svmdis: EvidenceFlag::Clear,
            hypervisor_present: EvidenceFlag::Clear,
            encryption: EncryptionState::Unencrypted { encryption_bit: None },
            optional: OptionalFeatures { nrip_save: true, ..OptionalFeatures::default() },
        }
        .validate()
        .unwrap();
        state.efer = Some(
            NativeEfer::admit_native_visible_svm(
                0x500,
                1 << 2,
                (1 << 11) | (1 << 20) | (1 << 29),
                0,
                None,
            )
            .unwrap(),
        );
        let vmcr = VisibleVmCr::admit(8).unwrap();
        let policy = HsaveAddressPolicy::admit_target(TARGET_SIGNATURE, 48, 1, 0, 0).unwrap();
        state.svm_controls = Some(
            VisibleSvmControls::admit_firmware_zero_key(
                0x1234_5000,
                TSC_RATIO_UNITY,
                policy,
                &vmcr,
            )
            .unwrap(),
        );
        state.vmcr = Some(vmcr);
        state.svm_instructions =
            Some(NativeSvmInstructions::admit_native(&caps, (1 << 2) | (1 << 12), 1 << 2).unwrap());
        state.capabilities = Some(caps);
        put(&mut vmcb, 0x078, 0);
        put(&mut vmcb, 0x080, 0);
        put(&mut vmcb, 0x0c8, 0x3000);
        put(&mut vmcb, 0x570, 2);
        (state, vmcb, frame)
    }

    #[test]
    fn gp_dispatch_repairs_disabled_svm_for_kernel_and_user_without_completing_it() {
        for cpl in 0..=3 {
            for (instruction, expected) in [
                ([0x0f, 0x01, 0xda], 0x8000_0306u64), // VMLOAD -> #UD
                ([0x0f, 0x01, 0xd8], 0x8000_0306),    // VMRUN operand #GP -> #UD
                ([0x0f, 0x01, 0xdc], 0x8000_0b0d),    // STGI independently enabled
                ([0x0f, 0x30, 0x90], 0x8000_0b0d),    // Ordinary WRMSR #GP
            ] {
                let (mut state, mut vmcb, frame) = stopped_svm();
                put(&mut vmcb, 0x070, 0x4d);
                put(&mut vmcb, 0x0c8, 0); // #GP has no continuation evidence.
                put(&mut vmcb, 0x4c8, cpl << 24);
                put(&mut vmcb, 0x570, 0x10102);
                put(&mut vmcb, 0x5f8, u64::MAX); // Illegal physical operand at CPL0.
                let before = (state.svm_controls, frame);
                let mut expected_bytes = *vmcb.bytes();
                expected_bytes[0x0a8..0x0b0].copy_from_slice(&expected.to_le_bytes());
                assert!(check_exit_event(&mut state, &mut vmcb));
                assert!(super::super::protection::handle_with_reader(
                    &mut state,
                    &mut vmcb,
                    |_, index| Ok(instruction[index]),
                ));
                assert_eq!(*vmcb.bytes(), expected_bytes);
                assert_eq!((state.svm_controls, frame), before);
                assert!(state.pending_fault && !state.stopped_valid);
            }
        }
    }

    #[test]
    fn gp_dispatch_combines_delivery_faults_without_reading_the_instruction() {
        for (prior, expected) in [
            (0x8000_0306u64, Some(0x0010_8000_0b0du64)), // #UD delivery -> #GP
            (0x8000_0b0d, Some(0x8000_0b08)),            // #GP delivery -> #DF
            (0x8000_0b08, None),                         // #DF delivery -> shutdown policy
        ] {
            let (mut state, mut vmcb, _) = stopped_svm();
            state.pending_fault = true;
            put(&mut vmcb, 0x070, 0x4d);
            put(&mut vmcb, 0x078, 0x10);
            put(&mut vmcb, 0x088, prior);
            let mut expected_bytes = *vmcb.bytes();
            assert!(check_exit_event(&mut state, &mut vmcb));
            let resume =
                super::super::protection::handle_with_reader(&mut state, &mut vmcb, |_, _| {
                    panic!("delivery faults have no faulting SVM instruction")
                });
            if let Some(event) = expected {
                expected_bytes[0x0a8..0x0b0].copy_from_slice(&event.to_le_bytes());
            }
            assert_eq!(resume, expected.is_some());
            assert_eq!(*vmcb.bytes(), expected_bytes);
            assert!(state.pending_fault);
            assert_eq!(state.stopped_valid, expected.is_none());
        }
    }

    #[test]
    fn gp_dispatch_preserves_enabled_svm_and_refuses_a_queued_event_before_fetch() {
        for queued in [false, true] {
            let (mut state, mut vmcb, _) = stopped_svm();
            put(&mut vmcb, 0x070, 0x4d);
            state.efer = Some(
                dispatch::NativeEfer::admit_native_visible_svm(
                    0x1500,
                    1 << 2,
                    (1 << 11) | (1 << 20) | (1 << 29),
                    0,
                    None,
                )
                .unwrap(),
            );
            if queued {
                put(&mut vmcb, 0x0a8, 0x8000_0306);
            }
            let mut expected = *vmcb.bytes();
            assert_eq!(
                super::super::protection::handle_with_reader(&mut state, &mut vmcb, |_, _| panic!(
                    "enabled SVM or queued delivery requires no opcode fetch"
                ),),
                !queued
            );
            if !queued {
                expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0b0du64.to_le_bytes());
            }
            assert_eq!(*vmcb.bytes(), expected);
            assert_eq!(state.stopped_valid, queued);
        }
    }

    #[test]
    fn gp_dispatch_refuses_unreadable_evidence_and_retries_a_busy_reader_transactionally() {
        for error in [3, 8, terminal::FetchReadFailure::MemoryControlBusy as u16] {
            let (mut state, mut vmcb, _) = stopped_svm();
            state.pending_fault = true;
            put(&mut vmcb, 0x070, 0x4d);
            let before = *vmcb.bytes();
            let resume =
                super::super::protection::handle_with_reader(&mut state, &mut vmcb, |_, _| {
                    Err(error)
                });
            let busy = error == terminal::FetchReadFailure::MemoryControlBusy as u16;
            assert_eq!(resume, busy);
            assert_eq!(*vmcb.bytes(), before);
            assert!(state.pending_fault);
            assert_eq!(state.stopped_valid, !busy);
            if busy {
                assert!(super::super::protection::handle_with_reader(
                    &mut state,
                    &mut vmcb,
                    |_, index| Ok([0x0f, 0x01, 0xda][index]),
                ));
                assert_eq!(vmcb.event_injection(), 0x8000_0306);
                assert_eq!(state.routing_retries, 0);
            }
        }
    }

    #[test]
    fn invalid_control_msrs_dispatch_faults_and_preserve_pending_delivery() {
        for (index, write) in [
            (AVIC_DOORBELL, false),
            (SMM_CTL, false),
            (SMM_CTL, true),
            (VIRTUAL_TOM, false),
            (VIRTUAL_TOM, true),
        ] {
            for pending in [false, true] {
                let (mut state, mut vmcb, mut frame) = stopped_svm();
                put(&mut vmcb, 0x070, 0x7c);
                put(&mut vmcb, 0x078, u64::from(write));
                put(&mut vmcb, 0x570, 0x10102);
                if pending {
                    put(&mut vmcb, 0x0a8, 0x8000_0306);
                    put(&mut vmcb, 0x0c8, u64::MAX);
                }
                frame.rcx = u64::from(index);
                let before = (state.svm_controls, frame);
                let mut expected = *vmcb.bytes();
                if !pending {
                    expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0b0d_u64.to_le_bytes());
                }
                assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
                assert_eq!((state.svm_controls, frame), before);
                assert_eq!(*vmcb.bytes(), expected);
                assert_eq!(state.pending_fault, !pending);
                assert!(!state.stopped_valid);
            }
        }
    }

    #[test]
    fn doorbell_write_dispatch_remains_an_unsupported_stop() {
        let (mut state, mut vmcb, mut frame) = stopped_svm();
        put(&mut vmcb, 0x070, 0x7c);
        put(&mut vmcb, 0x078, 1);
        frame.rcx = u64::from(AVIC_DOORBELL);
        let before = (state.svm_controls, *vmcb.bytes(), frame);
        assert!(!dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        assert_eq!((state.svm_controls, *vmcb.bytes(), frame), before);
        assert!(state.stopped_valid && !state.pending_fault);
    }

    #[test]
    fn svm_instruction_dispatch_faults_disabled_vmrun_but_keeps_legal_stgi_unsupported() {
        let (mut state, mut vmcb, mut frame) = stopped_svm();
        put(&mut vmcb, 0x070, 0x80);
        let registers = frame;
        assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        assert_eq!(vmcb.event_injection(), 0x8000_0306);
        assert_eq!(vmcb.guest_rip(), 0x2ffe);
        assert_eq!(frame, registers);
        assert!(state.pending_fault && !state.stopped_valid);

        let (mut state, mut vmcb, mut frame) = stopped_svm();
        put(&mut vmcb, 0x070, 0x84);
        let before = *vmcb.bytes();
        assert!(!dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        assert_eq!(*vmcb.bytes(), before);
        assert!(state.stopped_valid && !state.pending_fault);
    }

    #[test]
    fn hsave_and_key_dispatch_use_guest_owner_and_hardware_nrip() {
        let (mut state, mut vmcb, mut frame) = stopped_svm();
        put(&mut vmcb, 0x070, 0x7c);
        frame.rcx = u64::from(VM_HSAVE_PA);
        assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        assert_eq!(vmcb.guest_rax(), 0x1234_5000);
        assert_eq!(frame.rdx, 0);
        assert_eq!(vmcb.guest_rip(), 0x3000);

        put(&mut vmcb, 0x078, 1);
        put(&mut vmcb, 0x0c8, 0x3002);
        put(&mut vmcb, 0x5f8, 0x8765_4000);
        assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        assert_eq!(state.svm_controls.unwrap().hsave_pa(), 0x8765_4000);
        assert_eq!(vmcb.guest_efer(), 0x1500);
        let (other, _, _) = stopped_svm();
        assert_eq!(other.svm_controls.unwrap().hsave_pa(), 0x1234_5000);

        put(&mut vmcb, 0x078, 0);
        put(&mut vmcb, 0x0c8, 0x3004);
        frame.rcx = u64::from(SVM_LOCK_KEY);
        assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        assert_eq!((vmcb.guest_rax(), frame.rdx), (0, 0));
        assert!(!state.pending_fault && !state.stopped_valid);
    }

    #[test]
    fn tsc_ratio_dispatch_reads_and_writes_guest_state_without_changing_clock_controls() {
        let (mut state, mut vmcb, mut frame) = stopped_svm();
        put(&mut vmcb, 0x070, 0x7c);
        frame.rcx = u64::from(TSC_RATIO);
        assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        assert_eq!((vmcb.guest_rax(), frame.rdx), (0, 1));
        assert_eq!(vmcb.guest_rip(), 0x3000);
        let clock_offset: [u8; 8] = vmcb.bytes()[0x050..0x058].try_into().unwrap();
        for value in [0, 1, 0x2_8000_0000, TSC_RATIO_DEFINED] {
            put(&mut vmcb, 0x078, 1);
            let next = vmcb.guest_rip() + 2;
            put(&mut vmcb, 0x0c8, next);
            put(&mut vmcb, 0x5f8, u64::from(value as u32));
            frame.rdx = value >> 32;
            assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
            assert_eq!(state.svm_controls.unwrap().tsc_ratio(), value);
            assert_eq!(vmcb.guest_rip(), next);

            put(&mut vmcb, 0x078, 0);
            put(&mut vmcb, 0x0c8, next + 2);
            assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
            assert_eq!(vmcb.guest_rax() | (frame.rdx << 32), value);
            assert_eq!(&vmcb.bytes()[0x050..0x058], &clock_offset);
            assert!(!state.pending_fault && !state.stopped_valid);
        }
        let (other, _, _) = stopped_svm();
        assert_eq!(other.svm_controls.unwrap().tsc_ratio(), TSC_RATIO_UNITY);
    }

    #[test]
    fn tsc_ratio_dispatch_preserves_events_and_faults_reserved_writes_transactionally() {
        let (mut state, mut vmcb, mut frame) = stopped_svm();
        put(&mut vmcb, 0x070, 0x7c);
        put(&mut vmcb, 0x078, 1);
        put(&mut vmcb, 0x5f8, 0);
        frame.rcx = u64::from(TSC_RATIO);
        frame.rdx = 1 << 8; // Reserved ratio bit 40.
        put(&mut vmcb, 0x0a8, 0x8000_0051);
        let before = *vmcb.bytes();
        let owner = state.svm_controls;
        let registers = frame;
        assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        assert_eq!(*vmcb.bytes(), before);
        assert_eq!(state.svm_controls, owner);
        assert_eq!(frame, registers);
        assert!(!state.pending_fault && !state.stopped_valid);

        put(&mut vmcb, 0x0a8, 0);
        assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        assert_eq!(vmcb.event_injection(), 0x8000_0b0d);
        assert_eq!(vmcb.guest_rip(), 0x2ffe);
        assert_eq!(state.svm_controls, owner);
        assert_eq!(frame, registers);
        assert!(state.pending_fault && !state.stopped_valid);
    }

    #[test]
    fn hsave_dispatch_faults_invalid_write_and_refuses_invalid_nrip_without_fetch() {
        let (mut state, mut vmcb, mut frame) = stopped_svm();
        put(&mut vmcb, 0x070, 0x7c);
        put(&mut vmcb, 0x078, 1);
        put(&mut vmcb, 0x5f8, 1);
        frame.rcx = u64::from(VM_HSAVE_PA);
        frame.rdx = 0;
        let owner = state.svm_controls;
        let registers = frame;
        assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        assert_eq!(vmcb.event_injection(), 0x8000_0b0d);
        assert_eq!(vmcb.guest_rip(), 0x2ffe);
        assert_eq!(state.svm_controls, owner);
        assert_eq!(frame, registers);
        assert!(state.pending_fault && !state.stopped_valid);

        let (mut state, mut vmcb, mut frame) = stopped_svm();
        put(&mut vmcb, 0x070, 0x7c);
        put(&mut vmcb, 0x0c8, 0);
        frame.rcx = u64::from(VM_HSAVE_PA);
        let before = *vmcb.bytes();
        assert!(!dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        assert_eq!(*vmcb.bytes(), before);
        assert!(state.stopped_valid && !state.pending_fault);
    }

    #[test]
    fn svm_dispatch_retries_pending_delivery_without_mutating_controls_or_operands() {
        for code in [0x7a, 0x80, 0x82, 0x83, 0x84, 0x85, 0x86, 0x7c] {
            let (mut state, mut vmcb, mut frame) = stopped_svm();
            put(&mut vmcb, 0x070, code);
            put(&mut vmcb, 0x088, 0x8000_0051);
            put(&mut vmcb, 0x0a8, 0x8000_0051);
            frame.rcx = u64::from(VM_HSAVE_PA);
            let before = *vmcb.bytes();
            let registers = frame;
            let owner = state.svm_controls;
            assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
            assert_eq!(*vmcb.bytes(), before);
            assert_eq!(frame, registers);
            assert_eq!(state.svm_controls, owner);
            assert!(!state.pending_fault && !state.stopped_valid);
        }
    }

    #[test]
    fn unclaimed_hypercall_fault_preserves_saved_state_and_all_registers() {
        for magic in [0, u64::MAX, 0x1234_5678_9abc_def0] {
            for cpl in [0, 3] {
                let (mut state, mut vmcb, mut frame) = stopped(magic, cpl);
                let mut expected = *vmcb.bytes();
                let registers = frame;
                expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0306u64.to_le_bytes());
                // EVENTINJ is uncached; queuing #UD preserves cached state.
                assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
                assert_eq!(*vmcb.bytes(), expected);
                assert_eq!(frame, registers);
                assert!(state.pending_fault);
                assert!(!state.stopped_valid);
            }
        }
    }

    #[test]
    fn unclaimed_hypercall_preserves_pending_delivery_before_retry() {
        for (rax, operation) in RETIRED_CALLS.into_iter().chain([(0, 0)]) {
            for event in [0x8000_0051, 0x8000_0202, 0x0000_0030_8000_0b0d] {
                for cpl in 0..=3 {
                    let (mut state, mut vmcb, mut frame) = stopped(rax, cpl);
                    frame.rcx = operation;
                    put(&mut vmcb, 0x088, event);
                    put(&mut vmcb, 0x0a8, event);
                    let before = *vmcb.bytes();
                    let registers = frame;
                    assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
                    assert_eq!(*vmcb.bytes(), before);
                    assert_eq!(frame, registers);
                    assert!(!state.pending_fault && !state.stopped_valid);
                }
            }
        }
    }

    #[test]
    fn retired_interfaces_fault_at_every_privilege_without_reading_operands_or_completing() {
        for (rax, operation) in RETIRED_CALLS {
            for cpl in 0..=3 {
                for flags in [2, 0x102, 0x10002, 0x10102] {
                    for nrip in [0, u64::MAX, 0x3001] {
                        let (mut state, mut vmcb, mut frame) = stopped(rax, cpl);
                        frame.rcx = operation;
                        // Poison former request/result pointers. Even a valid former operation
                        // cannot read guest memory, inspect a session, or return protocol data.
                        frame.rdx = u64::MAX;
                        frame.r8 = u64::MAX;
                        frame.r9 = u64::MAX;
                        frame.r10 = 9;
                        state.exits = 41;
                        state.routing_retries = 7;
                        put(&mut vmcb, 0x570, flags);
                        put(&mut vmcb, 0x0c8, nrip);
                        let mut expected = *vmcb.bytes();
                        expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0306u64.to_le_bytes());
                        let registers = frame;
                        assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
                        assert_eq!(*vmcb.bytes(), expected);
                        assert_eq!(frame, registers);
                        assert!(state.pending_fault && !state.stopped_valid);
                        assert_eq!((state.exits, state.routing_retries), (41, 7));

                        // Successful fault delivery does not complete the rejected instruction.
                        put(&mut vmcb, 0x070, 0x77);
                        assert!(check_exit_event(&mut state, &mut vmcb));
                        assert!(!state.pending_fault && !state.stopped_valid);
                        assert_eq!(vmcb.event_injection(), 0);
                        assert_eq!(vmcb.guest_rip(), 0x2ffe);
                    }
                }
            }
        }
    }

    #[test]
    fn post_ack_dispatcher_rejects_bootstrap_operands() {
        let (mut state, mut vmcb, mut frame) = stopped(NATIVE_BOOTSTRAP_ACK, 0);
        put(&mut vmcb, 0x570, 2);
        put(&mut vmcb, 0x578, 0x1000);
        let mut ack = NativeBootstrapAck::new(&vmcb, &frame, 0x1000, 0x1005, 0x1008).unwrap();
        put(&mut vmcb, 0x578, 0x1005);
        ack.acknowledge(&mut vmcb, &frame).unwrap();
        assert_eq!(vmcb.guest_rip(), 0x1008);
        state.ack = Some(ack);

        // Even replay at the exact linked ACK site reaches the closed post-ACK dispatcher.
        put(&mut vmcb, 0x578, 0x1005);
        let mut expected = *vmcb.bytes();
        expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0306u64.to_le_bytes());
        let registers = frame;
        assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        assert_eq!(*vmcb.bytes(), expected);
        assert_eq!(frame, registers);
        assert!(state.ack.as_ref().unwrap().acknowledged());
        assert!(state.pending_fault && !state.stopped_valid);
    }

    #[test]
    fn unclaimed_fault_uses_existing_injection_completion_bookkeeping() {
        let (mut state, mut vmcb, mut frame) = stopped(0, 3);
        assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        // Model the subsequent completed entry/exit with no interrupted event. This is a
        // bookkeeping fixture, not evidence of hardware delivery or a Windows exception handler.
        put(&mut vmcb, 0x070, 0x77);
        assert!(check_exit_event(&mut state, &mut vmcb));
        assert!(!state.pending_fault && !state.stopped_valid);
        assert_eq!(vmcb.event_injection(), 0);
    }

    #[test]
    fn invalid_opcode_queue_refuses_wrong_exit_and_conflicting_controls_without_mutation() {
        for (offset, value, error) in [
            (0x070, u64::MAX, ExternalInterruptError::ControlMismatch),
            (0x070, 0x7f, ExternalInterruptError::ControlMismatch),
            (0x070, 0x80, ExternalInterruptError::ControlMismatch),
            (0x0a8, 0x8000_0051, ExternalInterruptError::PendingInjection),
            (0x088, 0x8000_0051, ExternalInterruptError::NestedDeliveryUnsupported),
            (0x060, 1 << 8, ExternalInterruptError::PendingVirtualInterrupt),
            (0x060, 1 << 63, ExternalInterruptError::UnsupportedControl { control: 1 << 63 }),
            (0x090, 2, ExternalInterruptError::UnsupportedNestedControl { control: 2 }),
        ] {
            let (_, mut vmcb, _) = stopped(0, 3);
            put(&mut vmcb, offset, value);
            let before = *vmcb.bytes();
            assert_eq!(vmcb.queue_vmmcall_invalid_opcode(), Err(error));
            assert_eq!(*vmcb.bytes(), before);
        }
    }
}
