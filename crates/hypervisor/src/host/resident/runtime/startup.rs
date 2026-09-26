//! Native INIT/SIPI destination service with hardware-owned ordinary interrupts.
//! Guest SVM control MSRs survive INIT (APM2 physical p544, Table 14-1);
//! only their processor RESET path requires fresh admission.
use crate::{
    arch::x86_64::{apic, registers::GuestRegisters},
    host::resident::{
        runtime::{
            MSRPM, State, diagnostics, image_base, local,
            msr::{read_msr, write_msr},
            stop::{stop, terminal_requested},
            svmvisor_resident_init_acks, svmvisor_resident_nmi_pending,
        },
        terminal::{self, StartupStage},
    },
    svm::{
        permission_maps::{MsrAccess, Permission},
        startup::{
            NativeStartupEffect, NativeStartupMailbox, NativeStartupState, NativeStartupTarget,
            ROUTE_WAIT_ATTEMPTS, guest_started_all_application_processors, lock_routes_within,
        },
        vmcb::Vmcb,
    },
};
use core::{
    arch::{asm, x86_64::__cpuid_count},
    ptr,
    sync::atomic::Ordering,
};

/// Requeue an NMI consumed by a private host GIF window, preserving it if another event is queued.
pub(super) unsafe fn route_physical_nmi_to_guest(vmcb: &mut Vmcb) -> bool {
    if svmvisor_resident_nmi_pending.load(Ordering::Acquire) == 0 {
        return false;
    }
    if vmcb.queue_native_nmi().is_ok() {
        svmvisor_resident_nmi_pending.store(0, Ordering::Release);
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
        if !unsafe { super::cache::service(state, vmcb) } {
            return Some(false);
        }
        let Some(command) = shared[state.slot].peek() else {
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

/// Once the guest has started every application processor, this CPU no longer
/// routes INIT/SIPI: its own ICR goes straight to the physical LAPIC, so IPIs
/// stop exiting, and routine progress records stop. A later guest INIT to a
/// running CPU is then taken as a private wake and dropped; the guest does not
/// re-INIT started CPUs without a platform reset. Each runtime owns its MSRPM,
/// which the next VMRUN on this CPU reads.
/// # Safety
/// This CPU's armed dispatcher with its guest stopped and IF/GIF clear.
pub(super) unsafe fn finish_guest_startup(state: &mut State, vmcb: &mut Vmcb) {
    if state.guest_started
        || !state.startup_owned
        || !guest_started_all_application_processors(unsafe { mailboxes(state.count) })
    {
        return;
    }
    let map = unsafe { &mut *ptr::addr_of_mut!(MSRPM) };
    for access in [MsrAccess::Read, MsrAccess::Write] {
        // The x2APIC ICR lies in the covered 0000_0000h-0000_1FFFh range.
        let _ = map.set(apic::ICR_MSR, access, Permission::Allow);
    }
    // Hardware may retain permission-map state even though the base is unchanged.
    vmcb.permission_maps_changed();
    diagnostics::quiet_progress();
    state.guest_started = true;
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

/// Drain only redirected private INIT notifications with IF remaining clear.
pub(super) unsafe fn acknowledge_init() -> Option<u64> {
    let before = svmvisor_resident_init_acks.load(Ordering::Acquire);
    for _ in 0..1024 {
        let previous = svmvisor_resident_init_acks.load(Ordering::Acquire);
        unsafe {
            asm!("stgi", "nop", "clgi", options(nostack));
        }
        let current = svmvisor_resident_init_acks.load(Ordering::Acquire);
        if current == previous {
            return Some(current.wrapping_sub(before));
        }
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
pub(super) unsafe fn notify_native_startup() {
    unsafe { send_native_notification() };
}
pub(super) unsafe fn send_native_notification() {
    unsafe {
        asm!("mfence", options(nostack, preserves_flags));
        write_msr(apic::ICR_MSR, 0x000c_0500);
    }
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
