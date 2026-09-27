//! Native INIT/SIPI destination service with hardware-owned ordinary interrupts.
//! The admitted logical SVM controls remain owned by this boot model. A real
//! postboot INIT additionally needs per-MSR retention and host rearm; see
//! crates/hypervisor/POSTBOOT-INIT.md for the selected physical restart design.
use crate::{
    arch::x86_64::{apic, registers::GuestRegisters},
    host::resident::{
        runtime::{
            State, diagnostics, image_base, local,
            msr::{read_msr, write_msr},
            stop::{stop, terminal_requested},
            svmvisor_resident_init_acks, svmvisor_resident_nmi_acks, svmvisor_resident_nmi_pending,
        },
        terminal::{self, StartupStage},
    },
    svm::{
        startup::{
            NativeIcr, NativeIcrError, NativeStartupCommand, NativeStartupEffect,
            NativeStartupMailbox, NativeStartupState, NativeStartupTarget, ROUTE_WAIT_ATTEMPTS,
            guest_started_all_application_processors, lock_routes_within,
        },
        vmcb::Vmcb,
    },
};
use core::{
    arch::{asm, x86_64::__cpuid_count},
    sync::atomic::{AtomicU32, Ordering},
};

/// Transfer a host-acknowledged physical NMI to the hardware virtual-NMI owner.
/// # Safety
/// The sole stopped CPU owns this VMCB with GIF clear. Its NMI gate cannot
/// publish another pending indication until the next explicit host GIF window.
pub(super) unsafe fn route_physical_nmi_to_guest(state: &State, vmcb: &mut Vmcb) -> bool {
    route_pending_nmi_after_bootstrap(state, vmcb, &svmvisor_resident_nmi_pending)
}

fn route_pending_nmi_after_bootstrap(state: &State, vmcb: &mut Vmcb, pending: &AtomicU32) -> bool {
    // The short linked bootstrap continuation must reach its VMMCALL before
    // arbitrary firmware NMI-handler instructions can encounter intercepts.
    // Host acknowledgment remains immediate; only guest delivery is deferred.
    if !state.ack.as_ref().is_some_and(|ack| ack.acknowledged()) {
        return false;
    }
    route_pending_nmi(vmcb, pending)
}

fn route_pending_nmi(vmcb: &mut Vmcb, pending: &AtomicU32) -> bool {
    if pending.load(Ordering::Acquire) == 0 {
        return false;
    }
    if vmcb.queue_native_nmi().is_ok() {
        // V_NMI is a coalescing pending latch, including while V_NMI_MASK is
        // set. EVENTINJ belongs to interrupted delivery or synchronous faults.
        pending.store(0, Ordering::Release);
        true
    } else {
        false
    }
}

/// Apply commands only on their own stopped CPU. AwaitSipi never reenters the guest.
pub(super) unsafe fn service_startup(
    state: &mut State,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
) -> Option<bool> {
    let shared = unsafe { mailboxes(state.count) };
    let mut changed = false;
    let mut polls = 0u32;
    let mut applied = 0u32;
    loop {
        if unsafe { terminal_requested(state) } {
            return Some(false);
        }
        // Refuse unsupported postboot resets before any target preparation,
        // including cache service and the GIF window. Leave the command queued
        // as evidence; a private notification alone never represents a guest INIT.
        let command = match next_startup_command(state, &shared[state.slot]) {
            Ok(command) => command,
            Err(stage) => return startup_stop(state, vmcb, stage),
        };
        if !unsafe { super::cache::service(state, vmcb) } {
            return Some(false);
        }
        let Some(command) = command else {
            if state.startup == NativeStartupState::Running {
                return changed.then_some(true);
            }
            polls = polls.wrapping_add(1);
            if polls % (1 << 16) == 0 && unsafe { acknowledge_init() }.is_none() {
                return startup_stop(state, vmcb, StartupStage::InitAcknowledgment);
            }
            core::hint::spin_loop();
            continue;
        };
        if state.startup == NativeStartupState::Running && applied == 64 {
            return changed.then_some(true);
        }
        if unsafe { acknowledge_init() }.is_none() {
            return startup_stop(state, vmcb, StartupStage::InitAcknowledgment);
        }
        let signature = __cpuid_count(1, 0).eax;
        let effect =
            match (NativeStartupTarget { vmcb, frame, state: &mut state.startup, signature })
                .validate(command)
            {
                Ok(effect) => effect,
                Err(_) => return startup_stop(state, vmcb, StartupStage::TargetApplication),
            };
        let mut efer = state.efer;
        if effect == NativeStartupEffect::Init {
            let Some(owner) = efer.as_mut() else {
                return startup_stop(state, vmcb, StartupStage::OwnerMissing);
            };
            if owner.reset_after_init().is_err() {
                return startup_stop(state, vmcb, StartupStage::EferReset);
            }
            // Native LAPIC cannot be reset by clearing a virtual backing page. Refuse
            // an active ISR/IRR rather than silently losing pending physical events.
            if !unsafe { reset_native_lapic() } {
                return startup_stop(state, vmcb, StartupStage::InitPreparation);
            }
        }
        if (NativeStartupTarget { vmcb, frame, state: &mut state.startup, signature })
            .apply(command)
            .is_err()
        {
            return startup_stop(state, vmcb, StartupStage::TargetApplication);
        }
        if effect == NativeStartupEffect::Init {
            state.efer = efer;
            // This successful target-owned commit is the model's INIT reset
            // boundary, matching the VMCB pending/mask reset. GIF stays clear.
            // Later NMIs captured while AwaitSipi must survive through SIPI
            // (APM2 physical p705); no private wake or SIPI resets this latch.
            reset_init_event_owners(state, &svmvisor_resident_nmi_pending);
            // SAFETY: INIT committed on this stopped CPU, which owns its local channel.
            unsafe { local::reset() };
            unsafe { svmvisor_resident_reset_guest_debug() };
        }
        if effect == NativeStartupEffect::Started {
            shared[state.slot].mark_started();
        }
        let Ok(routes) = lock_routes_within(shared, ROUTE_WAIT_ATTEMPTS) else {
            return startup_stop(state, vmcb, StartupStage::RouteTable);
        };
        if shared[state.slot].complete(command).is_err() {
            return startup_stop(state, vmcb, StartupStage::MailboxCompletion);
        }
        drop(routes);
        changed |= effect != NativeStartupEffect::Ignored;
        applied += 1;
    }
}

fn reset_init_event_owners(state: &mut State, pending: &AtomicU32) {
    state.pending_fault = false;
    state.icr_value = 0;
    state.routing_retries = 0;
    pending.store(0, Ordering::Release);
}

/// Read the next command without consuming it or changing any target state.
/// The boot-only LAPIC helper cannot reset a running OS's pending, in-service
/// and extended interrupt state atomically. Until physical rebootstrap owns
/// that boundary, retain and report every later INIT instead of dropping it
/// or applying a partial CPU/LAPIC reset. A locally started AP is protected
/// even before the all-AP startup milestone reaches this CPU. The captured BSP
/// role is always excluded: that CPU never uses the initial AP startup helper,
/// including if its local all-AP milestone has not yet observed peer progress.
fn next_startup_command(
    state: &State,
    mailbox: &NativeStartupMailbox,
) -> Result<Option<NativeStartupCommand>, StartupStage> {
    let command = mailbox.peek();
    if command == Some(NativeStartupCommand::Init)
        && (state.host_apic_base & apic::APIC_BASE_BSP != 0
            || state.guest_started
            || mailbox.started())
    {
        return Err(StartupStage::PostbootInitUnsupported);
    }
    Ok(command)
}

/// Latch only the initial boot milestone. This helper has no permission-map
/// or guest-state authority; later ICR accesses must keep their startup owner.
fn mark_initial_startup_finished(state: &mut State, all_started: bool) -> bool {
    if state.guest_started || !state.startup_owned || !all_started {
        return false;
    }
    state.guest_started = true;
    true
}

/// Once the guest has started every application processor, stop routine
/// progress records. ICR interception remains active for the entire runtime:
/// later guest INIT/SIPI requests must reach their target mailbox and must
/// never become indistinguishable from the host's private INIT notifications.
/// # Safety
/// This CPU's armed dispatcher with its guest stopped and IF/GIF clear.
pub(super) unsafe fn finish_guest_startup(state: &mut State) {
    if state.guest_started || !state.startup_owned {
        return;
    }
    let all_started = guest_started_all_application_processors(unsafe { mailboxes(state.count) });
    if mark_initial_startup_finished(state, all_started) {
        diagnostics::quiet_progress();
    }
}

/// Experimental software reset of writable native LAPIC state. INIT retention
/// and interrupts racing this sequence require target-hardware validation.
unsafe fn reset_native_lapic() -> bool {
    for bank in 0..8 {
        if unsafe { read_msr(apic::msr(apic::ISR + bank * 16)) } != 0
            || unsafe { read_msr(apic::msr(apic::IRR + bank * 16)) } != 0
        {
            return false;
        }
    }
    unsafe {
        write_msr(apic::msr(apic::TIMER_INITIAL_COUNT), 0);
        for lvt in apic::LVTS {
            write_msr(apic::msr(lvt), u64::from(apic::LVT_MASKED));
        }
        write_msr(apic::msr(apic::TPR), 0);
        write_msr(apic::msr(apic::SVR), 0xff);
        write_msr(apic::msr(apic::TIMER_DIVIDE), 0);
    }
    true
}

/// Drain redirected INIT notifications and physical NMIs with IF remaining clear.
/// APM2 physical p598: an intercepted physical NMI is still pending. Only the
/// host NMI gate consuming it establishes acknowledgment; queueing V_NMI alone
/// would otherwise replay the same physical interrupt on every VMRUN.
pub(super) unsafe fn acknowledge_init() -> Option<u64> {
    let before = notification_acks();
    drain_notifications(before, || {
        unsafe {
            asm!("stgi", "nop", "clgi", options(nostack));
        }
        notification_acks()
    })
    .map(|current| current.0.wrapping_sub(before.0))
}

fn notification_acks() -> (u64, u64) {
    (
        svmvisor_resident_init_acks.load(Ordering::Acquire),
        svmvisor_resident_nmi_acks.load(Ordering::Acquire),
    )
}

fn drain_notifications(
    mut previous: (u64, u64),
    mut window: impl FnMut() -> (u64, u64),
) -> Option<(u64, u64)> {
    for _ in 0..1024 {
        let current = window();
        // Each private handler closes GIF itself. If either one ran, another
        // window is required to drain the other physical source or prove quiet.
        if current == previous {
            return Some(current);
        }
        previous = current;
    }
    None
}

pub(super) unsafe fn mailboxes(count: usize) -> &'static [NativeStartupMailbox] {
    unsafe {
        core::slice::from_raw_parts(
            (image_base() + super::STARTUP_PAGE_OFFSET) as *const NativeStartupMailbox,
            count,
        )
    }
}

/// Keep the routed target through the native adapter. The callback is invoked
/// only after successful mailbox publication, with the physical wake's ICR.
pub(super) fn route_native_startup(
    icr: &mut NativeIcr,
    value: u64,
    mailboxes: &[NativeStartupMailbox],
    send: impl FnOnce(u64),
) -> Result<(), NativeIcrError> {
    icr.route_startup_write(value, mailboxes, |destination| {
        send(apic::init_notification_icr(destination));
    })
}

/// # Safety
/// The owning stopped CPU has IF/GIF clear and admitted x2APIC enabled. `icr`
/// comes from `init_notification_icr` for admitted peer mailboxes whose hosts
/// own R_INIT redirection. Their request is fully published before this call.
pub(super) unsafe fn send_startup_notification(icr: u64) {
    // SAFETY: the caller owns this x2APIC and supplies an admitted private INIT;
    // the fence orders the published request before the physical notification.
    unsafe {
        asm!("mfence", options(nostack, preserves_flags));
        write_msr(apic::ICR_MSR, icr);
    }
}

/// # Safety
/// Same ownership as `send_startup_notification`; all admitted peers must
/// participate in the already-published cache or terminal rendezvous.
pub(super) unsafe fn send_native_notification() {
    // SAFETY: the caller established the peer rendezvous; the encoder selects
    // the existing all-excluding-self physical INIT notification.
    unsafe { send_startup_notification(apic::init_notification_icr(u32::MAX)) };
}

fn startup_stop(state: &mut State, vmcb: &Vmcb, stage: StartupStage) -> Option<bool> {
    let exit = vmcb.exit_snapshot();
    let (tag, value) = terminal::startup_failure(
        7,
        stage as u8,
        u64::from(state.startup == NativeStartupState::AwaitSipi),
        unsafe { super::ASSIGNED_APIC_ID },
    );
    stop(state, exit.code, exit.rip, tag, value);
    Some(false)
}

/// Reset only the stopped target's guest-live breakpoint addresses.
/// APM2 rev3.44 Table14-1 p482,15.5.1/15.7: INIT resets DR0-3, which are
/// not part of the ordinary VMCB state switch. DR6/7 reset in the guest VMCB.
/// # Safety
/// The sole successful target-owned INIT commit (`guest_init`) calls this
/// with IF/GIF clear, after all fallible preparation and its LAPIC and CPU
/// commits, on the same nonmigrating guest CPU. Host breakpoints/GD are
/// disabled after VMEXIT; no external debugger or host DR owner exists.
/// Never call for a private wake, refused INIT or SIPI. Keep this
/// out-of-line symbol for the exact linked debug-write audit.
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn svmvisor_resident_reset_guest_debug() {
    unsafe {
        asm!(
            "xor eax, eax",
            "mov dr0, rax",
            "mov dr1, rax",
            "mov dr2, rax",
            "mov dr3, rax",
            out("rax") _,
            options(nostack),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn initial_startup_milestone_is_monotonic_and_keeps_startup_routing() {
        let mut state = super::super::INITIAL_STATE;
        assert!(!mark_initial_startup_finished(&mut state, true));
        state.startup_owned = true;
        assert!(!mark_initial_startup_finished(&mut state, false));
        assert!(mark_initial_startup_finished(&mut state, true));
        assert!(state.guest_started && state.startup_owned);
        assert!(!mark_initial_startup_finished(&mut state, true));
        assert!(!mark_initial_startup_finished(&mut state, false));
        assert!(state.guest_started && state.startup_owned);
    }

    #[test]
    fn postboot_startup_request_still_reaches_its_target_mailbox() {
        let ids = [0x102, 0x25];
        let mailboxes = ids.map(NativeStartupMailbox::new);
        for mailbox in &mailboxes {
            mailbox.mark_running();
        }
        mailboxes[1].mark_started();
        let mut state = super::super::INITIAL_STATE;
        state.startup_owned = true;
        assert!(mark_initial_startup_finished(
            &mut state,
            guest_started_all_application_processors(&mailboxes)
        ));
        let mut source = NativeIcr::admit(ids[0], &ids).unwrap();
        let mut notification = None;
        route_native_startup(&mut source, 0x25_0000_0500, &mailboxes, |icr| {
            notification = Some(icr)
        })
        .unwrap();
        assert_eq!(notification, Some(0x25_0000_0500));
        assert_eq!(mailboxes[0].peek(), None);
        assert_eq!(mailboxes[1].peek(), Some(NativeStartupCommand::Init));
        assert_eq!(
            next_startup_command(&state, &mailboxes[1]),
            Err(StartupStage::PostbootInitUnsupported)
        );
    }

    #[test]
    fn postboot_init_stays_queued_before_any_target_commit() {
        for (global_started, target_started) in [(true, false), (false, true), (true, true)] {
            let mut state = super::super::INITIAL_STATE;
            state.guest_started = global_started;
            state.pending_fault = true;
            state.icr_value = 0x1122_3344_5566_7788;
            state.routing_retries = 17;
            let mailbox = NativeStartupMailbox::new(0x25);
            mailbox.mark_running();
            if target_started {
                mailbox.mark_started();
            }
            mailbox.publish(NativeStartupCommand::Init).unwrap();
            mailbox.publish(NativeStartupCommand::Sipi(0x42)).unwrap();
            for _ in 0..2 {
                assert_eq!(
                    next_startup_command(&state, &mailbox),
                    Err(StartupStage::PostbootInitUnsupported)
                );
                assert_eq!(mailbox.peek(), Some(NativeStartupCommand::Init));
                assert_eq!(state.startup, NativeStartupState::Running);
                assert!(state.pending_fault);
                assert_eq!(state.icr_value, 0x1122_3344_5566_7788);
                assert_eq!(state.routing_retries, 17);
            }
            // The unchanged FIFO preserves the later SIPI behind the refused INIT.
            mailbox.complete(NativeStartupCommand::Init).unwrap();
            assert_eq!(mailbox.peek(), Some(NativeStartupCommand::Sipi(0x42)));
        }
        assert_eq!(StartupStage::PostbootInitUnsupported as u8, 11);
        assert_eq!(
            terminal::startup_failure(7, StartupStage::PostbootInitUnsupported as u8, 0, 0x25),
            (0x005f_f10c, 0x25_0000_0000)
        );
    }

    #[test]
    fn bsp_init_refuses_even_with_stale_local_boot_progress() {
        let mut state = super::super::INITIAL_STATE;
        state.host_apic_base = apic::APIC_BASE_X2APIC | apic::APIC_BASE_BSP;
        state.startup_owned = true;
        let mailboxes = [NativeStartupMailbox::new(0x25), NativeStartupMailbox::new(0x27)];
        for mailbox in &mailboxes {
            mailbox.mark_running();
        }
        mailboxes[0].publish(NativeStartupCommand::Init).unwrap();
        // The BSP never receives mark_started, and its all-AP observation can
        // lag peer progress until after startup service on this very exit.
        for peer_started in [false, true] {
            if peer_started {
                mailboxes[1].mark_started();
            }
            assert_eq!(guest_started_all_application_processors(&mailboxes), peer_started);
            assert!(!state.guest_started && !mailboxes[0].started());
            assert_eq!(
                next_startup_command(&state, &mailboxes[0]),
                Err(StartupStage::PostbootInitUnsupported)
            );
            assert_eq!(mailboxes[0].peek(), Some(NativeStartupCommand::Init));
            assert_eq!(state.startup, NativeStartupState::Running);
        }
    }

    #[test]
    fn initial_init_and_later_sipi_keep_existing_target_lifecycle() {
        let mut state = super::super::INITIAL_STATE;
        let mailbox = NativeStartupMailbox::new(0x25);
        mailbox.mark_running();
        assert_eq!(next_startup_command(&state, &mailbox), Ok(None));
        mailbox.publish(NativeStartupCommand::Init).unwrap();
        assert_eq!(next_startup_command(&state, &mailbox), Ok(Some(NativeStartupCommand::Init)));
        mailbox.complete(NativeStartupCommand::Init).unwrap();
        mailbox.mark_started();
        state.guest_started = true;
        assert_eq!(next_startup_command(&state, &mailbox), Ok(None));
        mailbox.publish(NativeStartupCommand::Sipi(0x42)).unwrap();
        assert_eq!(
            next_startup_command(&state, &mailbox),
            Ok(Some(NativeStartupCommand::Sipi(0x42)))
        );
    }

    #[test]
    fn host_nmi_transfer_coalesces_while_masked_and_preserves_exception_injection() {
        let mut vmcb = Vmcb::new();
        vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
        vmcb.queue_native_general_protection().unwrap();
        let exception = vmcb.event_injection();
        let control = vmcb.virtual_interrupt_control() | (1 << 12);
        // Model hardware's saved mask after the first virtual NMI was taken.
        unsafe {
            ptr::from_mut(&mut vmcb).cast::<u8>().add(0x60).cast::<u64>().write_unaligned(control);
        }
        let pending = AtomicU32::new(1);
        assert!(route_pending_nmi(&mut vmcb, &pending));
        assert_eq!(pending.load(Ordering::Acquire), 0);
        assert!(vmcb.virtual_nmi_pending() && vmcb.virtual_nmi_masked());
        assert_eq!(vmcb.event_injection(), exception);
        let queued = *vmcb.bytes();

        // A further host notification coalesces into the one hardware pending
        // latch. Software neither unblocks it nor creates an EVENTINJ replay.
        pending.store(1, Ordering::Release);
        assert!(route_pending_nmi(&mut vmcb, &pending));
        assert_eq!(*vmcb.bytes(), queued);
        assert!(!route_pending_nmi(&mut vmcb, &pending));
        assert_eq!(*vmcb.bytes(), queued);
    }

    #[test]
    fn unavailable_virtual_nmi_owner_preserves_host_pending_and_guest_bytes() {
        let mut vmcb = Vmcb::new();
        let pending = AtomicU32::new(1);
        let before = *vmcb.bytes();
        assert!(!route_pending_nmi(&mut vmcb, &pending));
        assert_eq!(pending.load(Ordering::Acquire), 1);
        assert_eq!(*vmcb.bytes(), before);
    }

    #[test]
    fn pre_bootstrap_nmi_waits_for_the_real_ack_before_guest_delivery() {
        use crate::guest::continuation::{NATIVE_BOOTSTRAP_ACK, NativeBootstrapAck};

        fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
            // SAFETY: the fixture owns this inert VMCB; each field is in bounds.
            unsafe {
                ptr::from_mut(vmcb).cast::<u8>().add(offset).cast::<u64>().write_unaligned(value);
            }
        }

        let mut state = super::super::INITIAL_STATE;
        let mut vmcb = Vmcb::new();
        vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
        let frame = GuestRegisters::default();
        put(&mut vmcb, 0x578, 0x1000);
        put(&mut vmcb, 0x570, 2);
        state.ack = Some(NativeBootstrapAck::new(&vmcb, &frame, 0x1000, 0x1005, 0x1008).unwrap());
        put(&mut vmcb, 0x70, 0x61);
        let pending = AtomicU32::new(1);
        let before = *vmcb.bytes();
        assert!(!route_pending_nmi_after_bootstrap(&state, &mut vmcb, &pending));
        assert_eq!(*vmcb.bytes(), before);
        assert_eq!(pending.load(Ordering::Acquire), 1);
        assert!(!state.ack.as_ref().unwrap().acknowledged());

        put(&mut vmcb, 0x70, 0x81);
        put(&mut vmcb, 0x578, 0x1005);
        put(&mut vmcb, 0x5f8, NATIVE_BOOTSTRAP_ACK);
        state.ack.as_mut().unwrap().acknowledge(&mut vmcb, &frame).unwrap();
        assert!(route_pending_nmi_after_bootstrap(&state, &mut vmcb, &pending));
        assert_eq!(vmcb.guest_rip(), 0x1008);
        assert!(vmcb.virtual_nmi_pending());
        assert_eq!(pending.load(Ordering::Acquire), 0);
    }

    #[test]
    fn committed_init_resets_old_delivery_but_later_waiting_nmi_survives_sipi() {
        use crate::svm::startup::NativeStartupCommand;

        let mut state = super::super::INITIAL_STATE;
        state.pending_fault = true;
        state.icr_value = 0x25_0000_0630;
        state.routing_retries = 17;
        let mut vmcb = Vmcb::new();
        vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
        vmcb.queue_native_nmi().unwrap();
        let mut frame = GuestRegisters::default();
        let pending = AtomicU32::new(1);
        assert_eq!(
            (NativeStartupTarget {
                vmcb: &mut vmcb,
                frame: &mut frame,
                state: &mut state.startup,
                signature: 0,
            })
            .apply(NativeStartupCommand::Init),
            Ok(NativeStartupEffect::Init)
        );
        reset_init_event_owners(&mut state, &pending);
        assert!(!state.pending_fault && !vmcb.virtual_nmi_pending());
        assert_eq!(state.icr_value, 0);
        assert_eq!(state.routing_retries, 0);
        assert_eq!(pending.load(Ordering::Acquire), 0);
        assert_eq!(state.startup, NativeStartupState::AwaitSipi);

        // The host consumes another NMI during AwaitSipi. Only its host latch
        // changes until SIPI establishes the next runnable guest context.
        pending.store(1, Ordering::Release);
        assert_eq!(
            (NativeStartupTarget {
                vmcb: &mut vmcb,
                frame: &mut frame,
                state: &mut state.startup,
                signature: 0,
            })
            .apply(NativeStartupCommand::Sipi(0x42)),
            Ok(NativeStartupEffect::Started)
        );
        assert_eq!(pending.load(Ordering::Acquire), 1);
        assert!(route_pending_nmi(&mut vmcb, &pending));
        assert!(vmcb.virtual_nmi_pending() && !vmcb.virtual_nmi_masked());
        assert_eq!(pending.load(Ordering::Acquire), 0);
    }

    #[test]
    fn notification_drain_reopens_after_either_handler_closes_gif() {
        let mut windows = [(4, 10), (5, 10), (5, 10)].into_iter();
        // NMI consumes the first GIF window, INIT the second, then quiet.
        assert_eq!(drain_notifications((4, 9), || windows.next().unwrap()), Some((5, 10)));
        assert!(windows.next().is_none());
        // A storm cannot leave the dispatcher in an unbounded GIF-open loop.
        let mut nmi_acks = u64::MAX;
        assert_eq!(
            drain_notifications((0, nmi_acks), || {
                nmi_acks = nmi_acks.wrapping_add(1);
                (0, nmi_acks)
            }),
            None
        );
        assert_eq!(nmi_acks, 1023);
    }

    #[test]
    fn native_startup_adapter_passes_the_selected_wake_to_its_writer() {
        let ids = [0x102, 0x25, 0x27, 0x8abc_0f07];
        for (guest_icr, expected) in [
            (0x8abc_0f07_0000_0630, 0x8abc_0f07_0000_0500),
            (0x0002_0020_0000_0d00, 0x0000_0025_0000_0500),
            (0x0002_00a0_0000_0d00, 0x0000_0000_000c_0500),
            (0x0000_0000_000c_0500, 0x0000_0000_000c_0500),
        ] {
            let mailboxes = ids.map(NativeStartupMailbox::new);
            for mailbox in &mailboxes {
                mailbox.mark_running();
            }
            let mut source = NativeIcr::admit(ids[0], &ids).unwrap();
            let mut written = None;
            route_native_startup(&mut source, guest_icr, &mailboxes, |icr| written = Some(icr))
                .unwrap();
            assert_eq!(written, Some(expected));
        }
    }
}
