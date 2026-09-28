//! The dispatcher: exit history, exit sequencing against the startup service and
//! the acknowledged guest's exit handlers.

use core::{ptr, sync::atomic::Ordering};

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
            diagnostics::{self, record as diagnostic_record},
            guest_reader::fetch_instruction,
            interrupt, local,
            msr::{handle_mcax_msr, handle_native_icr, handle_target_msr},
            pmu,
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
        exit::ExitSnapshot,
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
    // Capture before trial completion or any other path can open a host GIF
    // window. A stale pending bit cannot prove this exit's physical NMI was
    // acknowledged; the same-CPU NMI gate must advance this generation.
    let nmi_acks_before = super::svmvisor_resident_nmi_acks.load(Ordering::Acquire);
    let state = unsafe { &mut *ptr::addr_of_mut!(STATE) };
    if context != ptr::addr_of_mut!(CONTEXT) {
        let exit = unsafe { &*ptr::addr_of!(VMCB) }.exit_snapshot();
        stop(state, exit.code, exit.rip, 0xf10a, context as u64);
        unsafe { terminal_finish(state) };
        return false;
    }
    // The nonmigrating assembly returned on this image's sole VMCB. Establish
    // reusable cached groups and consume the old RAP request before trial
    // restoration, event handling or any emulation can change guest state.
    let vmcb = unsafe { &mut *ptr::addr_of_mut!(VMCB) };
    unsafe {
        state.vmcb_cache.after_exit(vmcb, super::ASSIGNED_APIC_ID, ptr::addr_of!(VMCB) as u64);
        vmcb.consume_rap_clear_after_exit();
    }
    #[cfg(feature = "native-entry-trial")]
    let trial_exit = match unsafe { super::entry::complete(state, &mut *ptr::addr_of_mut!(VMCB)) } {
        Ok(handled) => handled,
        Err(()) => {
            unsafe { terminal_finish(state) };
            return false;
        }
    };
    #[cfg(not(feature = "native-entry-trial"))]
    let trial_exit = false;
    if unsafe { terminal_requested(state) } {
        unsafe { terminal_finish(state) };
        return false;
    }
    let before = unsafe { &*ptr::addr_of!(VMCB) }.exit_snapshot();
    // SAFETY: the stopped CPU owns this retained VMCB; no guest can change RAX here.
    let local_call = before.code == 0x81
        && unsafe { &*ptr::addr_of!(VMCB) }.guest_rax() == svmvisor_card_abi::local::MAGIC;
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
    let resume = unsafe { dispatch_body(context, trial_exit, nmi_acks_before) };
    let state = unsafe { &mut *ptr::addr_of_mut!(STATE) };
    // Every terminal return needs evidence, including an unforeseen callee
    // refusal. Route guards have unwound before publishing the stop/barrier.
    if !unsafe { terminal_requested(state) } {
        record_unexplained_stop(state, resume, before);
    }
    if unsafe { terminal_requested(state) } || (!resume && state.stopped_valid) {
        unsafe { terminal_finish(state) };
        return false;
    }
    if resume
        && !local_call
        && before.code != 0x77
        && (before.code != 0x72 || state.exits & 0xff == 1)
    {
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
        // Transfer host-acknowledged NMIs after every GIF-capable service. Hardware
        // owns V_NMI delivery and blocking independently of a queued EVENTINJ.
        let vmcb = unsafe { &mut *ptr::addr_of_mut!(VMCB) };
        if !unsafe { super::cache::service(state, vmcb) } {
            unsafe { terminal_finish(state) };
            return false;
        }
        unsafe { route_physical_nmi_to_guest(state, vmcb) };
        // No host GIF window follows this decision on the ordinary entry path.
        // Preserve opportunistic exits only while an existing service needs them.
        super::maintenance::prepare_pause(
            vmcb,
            state.pause_filter_supported,
            state.guest_started,
            super::svmvisor_resident_nmi_pending.load(core::sync::atomic::Ordering::Acquire) != 0,
            unsafe { configuration::pending(state) },
        );
        // Logical EFER may have changed through an MSR or guest INIT. Apply
        // its PMU filtering before the final trial boundary and any guest entry.
        if !unsafe { pmu::prepare_entry(state, vmcb) } {
            unsafe { terminal_finish(state) };
            return false;
        }
        #[cfg(feature = "native-entry-trial")]
        if !unsafe { super::entry::final_entry(state, vmcb) } {
            return false;
        }
        // Last software boundary before assembly VMLOAD/VMRUN, including any
        // one-shot trial edits. No VMCB reference survives the world switch.
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
    let error = match vmcb.complete_event_delivery(&mut state.pending_fault) {
        Ok(()) => return true,
        Err(error) => error,
    };
    let exit = vmcb.exit_snapshot();
    match error {
        DeliveryError::UnusableGuestState => stop(state, exit.code, 0, 0xf110, 0),
        DeliveryError::InjectionCompletion(_) => {
            let interrupted = u64::from_le_bytes(vmcb.bytes()[0x088..0x090].try_into().unwrap());
            // F10Ch belongs to packed startup failures. Keep this raw delivery
            // refusal distinct so the terminal encoder can export it.
            stop(state, exit.code, exit.rip, 0xf115, interrupted)
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

unsafe fn dispatch_body(
    context: *mut BridgeContext,
    trial_exit: bool,
    nmi_acks_before: u64,
) -> bool {
    // The outer dispatcher validated context without dereferencing it.
    debug_assert!(context == ptr::addr_of_mut!(CONTEXT));
    let state = unsafe { &mut *ptr::addr_of_mut!(STATE) };
    let vmcb = unsafe { &mut *ptr::addr_of_mut!(VMCB) };
    let frame = unsafe { &mut *ptr::addr_of_mut!(FRAME) };
    state.exits = state.exits.saturating_add(1);
    if !state.armed {
        // F10Bh without detail: an exit before arm. With the startup-route
        // record retired, `stop_words` exports it as an unhandled exit.
        let exit = vmcb.exit_snapshot();
        return stop(state, exit.code, exit.rip, 0xf10b, 0);
    }
    // Neither entry failure nor shutdown supplies a resumable event state.
    // Refuse before opening GIF or interpreting poisoned interrupt controls.
    if matches!(vmcb.exit_snapshot().code, u64::MAX | 0xffff_ffff | 0x7f) {
        return stop(state, vmcb.exit_snapshot().code, 0, 0xf110, 0);
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
    // Every unusual exit and MSR boundary; common CPUID/PAUSE samples are
    // bounded to avoid making diagnostic PCI traffic dominate guest execution.
    let local_call = observed.code == 0x81 && vmcb.guest_rax() == svmvisor_card_abi::local::MAGIC;
    if !local_call && (!matches!(observed.code, 0x72 | 0x77) || state.exits & 0xff == 1) {
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
        // Trial completion already consumed this entry's flush and requested
        // its canonical restoration flush. Keep that new request pending.
        if !trial_exit {
            vmcb.consume_tlb_flush_after_exit();
        }
    }
    // SAFETY: old flush consumed, guest stopped; close before startup or root changes.
    // Earlier diagnostics see the pending window and cannot touch the endpoint.
    if !unsafe { configuration::close(state, vmcb) } {
        return false;
    }
    if state.startup_owned || observed.code == 0x61 {
        let Some(acknowledged) = (unsafe { acknowledge_init() }) else {
            return stop(state, vmcb.exit_snapshot().code, vmcb.guest_rip(), 0xf102, 0);
        };
        if vmcb.exit_snapshot().code == 0x63 && acknowledged == 0 {
            return stop(state, 0x63, vmcb.guest_rip(), 0xf105, 0);
        }
    }
    if !check_physical_nmi_acknowledgment(
        state,
        vmcb,
        nmi_acks_before,
        super::svmvisor_resident_nmi_acks.load(Ordering::Acquire),
    ) {
        return false;
    }
    if !trial_exit && !check_exit_event(state, vmcb) {
        return false;
    }
    if !unsafe { super::cache::service(state, vmcb) } {
        return false;
    }
    let exit = vmcb.exit_snapshot();
    let Some(ack) = state.ack.as_mut() else {
        // F10Dh is the packed SYS_CFG diagnostic namespace on MSR exits.
        return stop(state, exit.code, exit.rip, 0xf116, 0);
    };
    if !ack.acknowledged() {
        if exit.code == 0x61 {
            // Physical NMI interception can precede the bootstrap VMMCALL.
            // Its source was consumed above. Reenter without pretending the
            // bootstrap handshake has completed. Retain the host pending
            // latch until ACK, before allowing firmware NMI handlers to run.
            return true;
        }
        if ack.acknowledge(vmcb, frame).is_ok() {
            unsafe {
                super::cache::ready(state);
            }
            if state.startup_owned {
                (unsafe { mailboxes(state.count) })[state.slot].mark_running();
                if terminal_enabled(state) {
                    // Separate monotonic initial-ACK mask, not mutable guest
                    // startup readiness. Last initial guest ACK opens export.
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
        None if trial_exit => true,
        None => unsafe { handle_exit(&mut context) },
    };
    // A still-intercepted ICR write in this exit has already been routed above.
    if resume {
        unsafe { finish_guest_startup(context.state) };
    }
    resume
}

fn check_physical_nmi_acknowledgment(
    state: &mut State,
    vmcb: &Vmcb,
    before: u64,
    after: u64,
) -> bool {
    let exit = vmcb.exit_snapshot();
    if exit.code == 0x61 && after == before {
        return stop(state, exit.code, exit.rip, 0xf117, after);
    }
    true
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
    #[cfg(feature = "native-entry-trial")]
    if exit.code == 0x81
        && let Some(resume) = unsafe { super::entry::request(state, vmcb, frame) }
    {
        return resume;
    }
    match exit.code {
        0x81 if vmcb.guest_rax() == svmvisor_card_abi::local::MAGIC => {
            // SAFETY: startup ACK and event handling precede this acknowledged guest branch.
            return unsafe { local::handle(state, vmcb, frame) };
        }
        0x81 => {
            // Installed ABIs have already had first refusal. Preserve any event being
            // re-injected before retrying this instruction; never replace its delivery.
            if vmcb.event_injection() & (1 << 31) != 0 {
                return true;
            }
            // Unclaimed VMMCALL follows the native #UD behavior (APM2 physical page 593).
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
        0x61 if vmcb.nmi_virtualization_enabled() => {
            // The physical source was acknowledged before dispatch. Its
            // coalesced host latch is transferred to V_NMI at final entry;
            // queueing again here would count one physical NMI twice.
            return true;
        }
        0x7b if diagnostics::available() => return unsafe { diagnostics::handle_io(state, vmcb) },
        0x7c => {
            // Recovered event delivery must finish before any retained MSR
            // instruction owner reads physical state or commits an access.
            if vmcb.event_injection() & (1 << 31) != 0 {
                return true;
            }
            if frame.rcx as u32 == MMIO_CFG_BASE_ADDR && diagnostics::available() {
                // Dynamic ECAM relocation is not yet an owned instruction path.
                // Keep the actual stopped operands before any native write.
                let requested =
                    (vmcb.guest_rax() as u32 as u64) | ((frame.rdx as u32 as u64) << 32);
                return stop(state, exit.code, exit.rip, 0xf202, requested);
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
            if let Some(resume) = unsafe { pmu::handle(state, vmcb, frame) } {
                return resume;
            }
            if let Some(resume) = unsafe { handle_target_msr(state, vmcb, frame) } {
                return resume;
            }
            let svm_control = control_msrs::owned_msr(frame.rcx as u32);
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
                    Ok(outcome) => return complete_native_msr_exit(state, outcome),
                    Err(error) => {
                        let (reason, value) =
                            super::terminal::vmcr_nrip_failure(error, vmcb, vmcr_value(state));
                        return stop(state, exit.code, exit.rip, reason, value);
                    }
                }
            }
            if let (Some(caps), Some(efer)) = (hardware_nrip, state.efer.as_mut()) {
                match dispatch::handle_native_efer_with_nrip(efer, vmcb, frame, &caps) {
                    Ok(outcome) => return complete_native_msr_exit(state, outcome),
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
                    Ok(outcome) => return complete_native_msr_exit(state, outcome),
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
                    Ok(outcome) => return complete_native_msr_exit(state, outcome),
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
            if let Some(endpoint) = unsafe { diagnostics::endpoint() }
                && let Some((base, bytes)) = endpoint.config_aperture()
                && let Ok((start, end)) = crate::memory::npt::identity_protection_range(base, bytes)
                && (start..end).contains(&exit.info2)
            {
                return unsafe { handle_diagnostic_ecam(state, vmcb, base, bytes) };
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
        Ok(outcome) => complete_native_msr_exit(state, outcome),
        Err(_) => {
            let exit = vmcb.exit_snapshot();
            stop(state, exit.code, exit.rip, 0xf104, frame.rcx)
        }
    }
}

/// Keep retirement and event ownership consistent for all logical MSR owners.
/// A trap follows a completed instruction; a fault retains its retry boundary.
fn complete_native_msr_exit(state: &mut State, outcome: NativeMsrOutcome) -> bool {
    match outcome {
        NativeMsrOutcome::Completed => state.routing_retries = 0,
        NativeMsrOutcome::DebugTrapPrepared => {
            state.routing_retries = 0;
            state.pending_fault = true;
        }
        NativeMsrOutcome::GeneralProtectionPrepared => state.pending_fault = true,
    }
    true
}

unsafe fn handle_diagnostic_ecam(
    state: &mut State,
    vmcb: &mut Vmcb,
    base: u64,
    bytes: u64,
) -> bool {
    let exit = vmcb.exit_snapshot();
    if exit.info1 & 0x1f != 7 {
        return stop(state, exit.code, exit.rip, exit.info1, exit.info2);
    }
    // SAFETY: validated write NPF in the admitted configuration aperture.
    if let Some(resume) = unsafe { configuration::open(state, vmcb, base, bytes) } {
        return resume;
    }
    let Some(guard) = (unsafe { terminal_control() }).diagnostic_lock() else {
        return retry_routing(state, vmcb);
    };
    // Remove only our write restriction after noting the first such write.
    // Hardware retries the original instruction; no GPR/RIP/event is emulated.
    unsafe {
        diagnostics::note_config_write(exit.info2, 0, 0, 1);
    }
    let result = crate::memory::npt::set_identity_write_range(
        unsafe { &mut (*ptr::addr_of_mut!(NPT)).0 },
        ptr::addr_of!(NPT) as u64,
        base,
        bytes,
        true,
    );
    drop(guard);
    if result.is_err() {
        return stop(state, exit.code, exit.rip, 0xf203, exit.info2);
    }
    vmcb.request_full_tlb_flush();
    state.routing_retries = 0;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        arch::x86_64::msr::{TSC_RATIO, TSC_RATIO_DEFINED, TSC_RATIO_UNITY},
        host::resident::runtime::INITIAL_STATE,
        svm::{
            control_msrs::{SVM_LOCK_KEY, VM_HSAVE_PA},
            events::ExternalInterruptError,
        },
    };

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

    #[test]
    fn physical_nmi_exit_requires_fresh_acknowledgment_before_reentry() {
        for (before, after, acknowledged) in [(7, 7, false), (7, 8, true), (u64::MAX, 0, true)] {
            let (mut state, mut vmcb, mut frame) = stopped(0, 0);
            vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
            put(&mut vmcb, 0x70, 0x61);
            let image = *vmcb.bytes();
            let registers = frame;
            assert_eq!(
                check_physical_nmi_acknowledgment(&mut state, &vmcb, before, after),
                acknowledged
            );
            if acknowledged {
                // The handler itself must not also schedule delivery; the
                // physical host latch transfers once at the final boundary.
                assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
                assert!(!vmcb.virtual_nmi_pending());
                assert!(!state.stopped_valid && !state.pending_fault);
            } else {
                assert_eq!((state.stopped, state.stopped_info1), (0x61, 0xf117));
            }
            assert_eq!(*vmcb.bytes(), image);
            assert_eq!(frame, registers);
        }
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
    fn logical_msr_dispatch_tracks_single_step_delivery_and_branch_only_completion() {
        for index in [EFER, VM_CR, VM_HSAVE_PA, SVM_LOCK_KEY, TSC_RATIO] {
            for branch_only in [false, true] {
                let (mut state, mut vmcb, mut frame) = stopped_svm();
                assert!(vmcb.configure_native_lbr(0x8000_0022, 2, 7, 0x2106));
                put(&mut vmcb, 0x070, 0x7c);
                put(&mut vmcb, 0x570, 0x10102);
                put(&mut vmcb, 0x568, 0xffff_2fff);
                put(&mut vmcb, 0x670, if branch_only { 2 } else { 0 });
                frame.rcx = u64::from(index);
                state.routing_retries = 7;

                assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
                assert_eq!(vmcb.guest_rip(), 0x3000);
                assert_eq!(vmcb.guest_rflags(), 0x102);
                assert_eq!(state.routing_retries, 0);
                assert_eq!(state.pending_fault, !branch_only);
                assert_eq!(vmcb.event_injection(), if branch_only { 0 } else { 0x8000_0301 });
                assert!(!state.stopped_valid);
            }
        }
    }

    #[test]
    fn completed_msr_debug_trap_replays_without_repeating_the_write() {
        let (mut state, mut vmcb, mut frame) = stopped_svm();
        assert!(vmcb.configure_native_lbr(0x8000_0022, 2, 7, 0x2106));
        vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
        vmcb.queue_native_nmi().unwrap();
        put(&mut vmcb, 0x070, 0x7c);
        put(&mut vmcb, 0x078, 1);
        put(&mut vmcb, 0x570, 0x10102);
        put(&mut vmcb, 0x5f8, 0x1234);
        frame.rcx = u64::from(TSC_RATIO);
        frame.rdx = 0;
        assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        assert_eq!(state.svm_controls.unwrap().tsc_ratio(), 0x1234);
        assert_eq!(vmcb.guest_rip(), 0x3000);
        assert_eq!(vmcb.event_injection(), 0x8000_0301);
        assert!(state.pending_fault && vmcb.virtual_nmi_pending());
        let owner = state.svm_controls;
        let registers = frame;

        // Model exits during #DB delivery, not execution of another WRMSR.
        // Hardware clears EVENTINJ and records the interrupted #DB in EXITINTINFO.
        for code in [0x400, 0x63, 0x61] {
            put(&mut vmcb, 0x070, code);
            put(&mut vmcb, 0x088, 0x8000_0301);
            put(&mut vmcb, 0x0a8, 0);
            let mut expected = *vmcb.bytes();
            expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0301u64.to_le_bytes());
            assert!(check_exit_event(&mut state, &mut vmcb));
            assert_eq!(*vmcb.bytes(), expected);
            assert_eq!((state.svm_controls, frame), (owner, registers));
            assert!(state.pending_fault && vmcb.virtual_nmi_pending());
        }

        // Delivery succeeded; hardware is now at the handler with TF cleared.
        put(&mut vmcb, 0x088, 0);
        put(&mut vmcb, 0x0a8, 0);
        put(&mut vmcb, 0x578, 0x4000);
        put(&mut vmcb, 0x570, 2);
        let delivered = *vmcb.bytes();
        for _ in 0..2 {
            assert!(check_exit_event(&mut state, &mut vmcb));
            assert_eq!(*vmcb.bytes(), delivered);
            assert_eq!((state.svm_controls, frame), (owner, registers));
            assert!(!state.pending_fault && !state.stopped_valid);
        }
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
    fn all_msr_dispatch_owners_wait_for_replay_before_access_or_fetch() {
        use crate::{
            arch::x86_64::msr::{MTRR_DEF_TYPE, TARGET_SIGNATURE},
            svm::target_msrs::{SMM_CTL, SMM_KEY, TargetMsrPolicy},
        };

        for index in [0xc000_2000, apic::ICR_MSR, MTRR_DEF_TYPE, SMM_KEY, SMM_CTL, 0xdead_beef] {
            for write in [false, true] {
                let (mut state, mut vmcb, mut frame) = stopped_svm();
                state.target_msrs =
                    TargetMsrPolicy::admit(TARGET_SIGNATURE, Some(1 << 9), 1, 0, 0, 0);
                state.pending_fault = true;
                state.routing_retries = 7;
                state.icr_value = 0x1234_5678_9abc_def0;
                state.exits = 11;
                vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
                put(&mut vmcb, 0x060, (1 << 26) | (1 << 12) | (1 << 11));
                put(&mut vmcb, 0x070, 0x7c);
                put(&mut vmcb, 0x078, u64::from(write));
                // Model the state after check_exit_event recovered an interrupted
                // #GP delivery. Neither the original access nor its retry has retired.
                put(&mut vmcb, 0x088, 0x0000_0030_8000_0b0d);
                put(&mut vmcb, 0x0a8, 0x0000_0030_8000_0b0d);
                // No continuation or guest-memory backing is available in this fixture.
                put(&mut vmcb, 0x0c8, u64::MAX);
                put(&mut vmcb, 0x5f8, 0xaaaa_bbbb_0000_0000);
                frame.rcx = 0xcccc_dddd_0000_0000 | u64::from(index);
                frame.rdx = 0xeeee_ffff_0000_0000;
                let before = (*vmcb.bytes(), frame);
                let owners = (state.efer, state.vmcr, state.svm_controls, state.target_msrs);
                let lifecycle = (
                    state.pending_fault,
                    state.routing_retries,
                    state.icr_value,
                    state.exits,
                    state.stopped_valid,
                    state.stopped,
                    state.stopped_rip,
                    state.stopped_info1,
                    state.stopped_info2,
                );

                assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
                assert_eq!((*vmcb.bytes(), frame), before, "MSR {index:#x}, write={write}");
                assert_eq!((state.efer, state.vmcr, state.svm_controls, state.target_msrs), owners);
                assert_eq!(
                    (
                        state.pending_fault,
                        state.routing_retries,
                        state.icr_value,
                        state.exits,
                        state.stopped_valid,
                        state.stopped,
                        state.stopped_rip,
                        state.stopped_info1,
                        state.stopped_info2,
                    ),
                    lifecycle
                );
                assert!(state.icr.is_none());
            }
        }
    }

    #[test]
    fn target_msr_dispatch_routes_fault_completion_and_bad_nrip_without_fallback_fetch() {
        use crate::{
            arch::x86_64::msr::TARGET_SIGNATURE,
            svm::target_msrs::{SMM_CTL, SMM_KEY, TargetMsrPolicy},
        };

        for (index, write, nrip, flags) in [
            (SMM_CTL, false, u64::MAX, 0x10102),
            (SMM_CTL, true, u64::MAX, 0x10102),
            (SMM_KEY, false, 0x3000, 2),
            (SMM_KEY, false, u64::MAX, 2),
        ] {
            let (mut state, mut vmcb, mut frame) = stopped_svm();
            state.target_msrs = TargetMsrPolicy::admit(TARGET_SIGNATURE, Some(1 << 9), 1, 0, 0, 0);
            state.routing_retries = 7;
            vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
            put(&mut vmcb, 0x060, (1 << 26) | (1 << 12) | (1 << 11));
            put(&mut vmcb, 0x070, 0x7c);
            put(&mut vmcb, 0x078, u64::from(write));
            put(&mut vmcb, 0x0c8, nrip);
            put(&mut vmcb, 0x570, flags);
            put(&mut vmcb, 0x5f8, 0xaaaa_bbbb_ffff_ffff);
            frame.rcx = 0xcccc_dddd_0000_0000 | u64::from(index);
            frame.rdx = u64::MAX;
            let mut expected = *vmcb.bytes();
            let mut registers = frame;
            let owners = (state.efer, state.vmcr, state.svm_controls, state.target_msrs);

            let resume = dispatch_unclaimed(&mut state, &mut vmcb, &mut frame);
            if index == SMM_CTL {
                // Architectural absence faults before NRIP/TF can block completion.
                assert!(resume);
                expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0b0du64.to_le_bytes());
                assert!(state.pending_fault && !state.stopped_valid);
                assert_eq!(state.routing_retries, 0);
            } else if nrip == 0x3000 {
                assert!(resume);
                expected[0x578..0x580].copy_from_slice(&nrip.to_le_bytes());
                expected[0x5f8..0x600].copy_from_slice(&0u64.to_le_bytes());
                registers.rdx = 0;
                assert!(!state.pending_fault && !state.stopped_valid);
                assert_eq!(state.routing_retries, 0);
            } else {
                // An owned MSR with unusable NRIP stops here, rather than losing
                // ownership and reaching the generic guest-fetch/F001h path.
                assert!(!resume);
                assert!(state.stopped_valid && !state.pending_fault);
                assert_eq!(
                    (state.stopped, state.stopped_rip, state.stopped_info1, state.stopped_info2),
                    (0x7c, 0x2ffe, 0xf104, u64::from(SMM_KEY))
                );
                assert_eq!(state.routing_retries, 7);
            }
            assert_eq!((*vmcb.bytes(), frame), (expected, registers));
            assert_eq!((state.efer, state.vmcr, state.svm_controls, state.target_msrs), owners);
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
        for event in [0x8000_0051, 0x8000_0202, 0x0000_0030_8000_0b0d] {
            let (mut state, mut vmcb, mut frame) = stopped(0, 3);
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

    #[test]
    fn local_hypercall_keeps_priority_over_unclaimed_fallback() {
        let (mut state, mut vmcb, mut frame) = stopped(svmvisor_card_abi::local::MAGIC, 3);
        // Local ABI's existing TF rejection queues #GP, distinguishing it from the #UD fallback.
        assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        assert_eq!(vmcb.event_injection(), 0x8000_0b0d);
        assert_eq!(vmcb.guest_rip(), 0x2ffe);
        assert!(state.pending_fault && !state.stopped_valid);
    }

    #[test]
    fn privileged_local_hypercall_dispatch_faults_without_completing_the_abi() {
        for cpl in 0..3 {
            for flags in [2, 0x10102] {
                let (mut state, mut vmcb, mut frame) =
                    stopped(svmvisor_card_abi::local::MAGIC, cpl);
                put(&mut vmcb, 0x570, flags);
                // The fixture has no capabilities and poisoned NRIP. A hardware-decoded
                // VMMCALL fault must not depend on a continuation or guest memory.
                let mut expected = *vmcb.bytes();
                expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0306u64.to_le_bytes());
                // EVENTINJ is uncached; queuing #UD preserves cached state.
                let registers = frame;
                assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
                assert_eq!(*vmcb.bytes(), expected);
                assert_eq!(frame, registers);
                assert!(state.pending_fault && !state.stopped_valid);

                // Model successful fault delivery followed by another exit. The existing
                // dispatcher lifecycle consumes the injection without completing VMMCALL.
                put(&mut vmcb, 0x070, 0x77);
                put(&mut vmcb, 0x0a8, 0); // #VMEXIT clears EVENTINJ.
                assert!(check_exit_event(&mut state, &mut vmcb));
                assert!(!state.pending_fault && !state.stopped_valid);
                assert_eq!(vmcb.event_injection(), 0);
                assert_eq!(vmcb.guest_rip(), 0x2ffe);
            }
        }
    }

    #[test]
    fn unclaimed_fault_uses_existing_injection_completion_bookkeeping() {
        let (mut state, mut vmcb, mut frame) = stopped(0, 3);
        assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
        // Model the subsequent completed entry/exit with no interrupted event. This is a
        // bookkeeping fixture, not evidence of hardware delivery or a Windows exception handler.
        put(&mut vmcb, 0x070, 0x77);
        put(&mut vmcb, 0x0a8, 0); // #VMEXIT clears EVENTINJ.
        assert!(check_exit_event(&mut state, &mut vmcb));
        assert!(!state.pending_fault && !state.stopped_valid);
        assert_eq!(vmcb.event_injection(), 0);
    }

    #[test]
    fn injected_fault_replays_across_private_init_notifications_then_completes_once() {
        for magic in [0, svmvisor_card_abi::local::MAGIC] {
            let (mut state, mut vmcb, mut frame) = stopped(magic, 3);
            // Exercise the real fault producers: unclaimed VMMCALL -> #UD;
            // the local ABI with this fixture's TF set -> #GP(0).
            assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
            let event = vmcb.event_injection();
            assert_eq!(event, if magic == 0 { 0x8000_0306 } else { 0x8000_0b0d });
            assert!(state.pending_fault);
            let registers = frame;
            state.startup_owned = true;

            for _ in 0..3 {
                // Model an acknowledged private INIT notification interrupting
                // delivery. This tests the post-ack handler, not the physical wire
                // or a queued guest INIT command. Hardware clears EVENTINJ.
                put(&mut vmcb, 0x070, 0x63);
                put(&mut vmcb, 0x088, event);
                put(&mut vmcb, 0x0a8, 0);
                let mut expected = *vmcb.bytes();
                expected[0x0a8..0x0b0].copy_from_slice(&event.to_le_bytes());
                assert!(check_exit_event(&mut state, &mut vmcb));
                assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
                assert!(state.pending_fault && !state.stopped_valid);
                assert_eq!(*vmcb.bytes(), expected);
                assert_eq!(frame, registers);
            }

            // Successful delivery followed by a notification, then another
            // completed entry/exit: neither may queue the old fault again.
            for _ in 0..2 {
                put(&mut vmcb, 0x088, 0);
                put(&mut vmcb, 0x0a8, 0);
                let expected = *vmcb.bytes();
                assert!(check_exit_event(&mut state, &mut vmcb));
                assert!(dispatch_unclaimed(&mut state, &mut vmcb, &mut frame));
                assert!(!state.pending_fault && !state.stopped_valid);
                assert_eq!(*vmcb.bytes(), expected);
                assert_eq!(frame, registers);
            }
        }
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
