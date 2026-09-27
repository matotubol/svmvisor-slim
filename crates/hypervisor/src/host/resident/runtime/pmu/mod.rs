//! Same-CPU ownership of the guest's performance event selectors.
//!
//! Counters, global controls and RDPMC retain their hardware execution. Only the
//! selectors are translated because physical SVME and guest mode are private
//! backing state. No host consumer borrows these counters.

use core::ptr;

use crate::{
    arch::x86_64::registers::GuestRegisters,
    host::resident::{
        BridgeContext,
        runtime::{
            CONTEXT, STATE, State, VMCB,
            msr::{
                self, MsrCompletion, apply_msr_completion, msr_continuation_failure,
                native_msr_continuation, native_msr_exit_ready,
            },
            stop::{stop, terminal_finish},
        },
    },
    svm::{
        pmu::{CONTROL_COUNT, PmuProfile, PmuState, control_index, control_msr},
        vmcb::Vmcb,
    },
};

const REFUSAL_BOUNDARY: u64 = 0xf104;

/// The admitted profile is inert until irreversible resident entry captures the
/// selectors. `programmed` records physical controls, never counter values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PmuRuntime {
    profile: PmuProfile,
    owner: Option<PmuState>,
    programmed: [u64; CONTROL_COUNT],
}

impl PmuRuntime {
    pub(super) const fn new(profile: PmuProfile) -> Self {
        Self { profile, owner: None, programmed: [0; CONTROL_COUNT] }
    }

    fn capture(&mut self, hardware: &mut impl PmuHardware) -> bool {
        if self.owner.is_some() {
            return false;
        }
        let mut controls = [0; CONTROL_COUNT];
        for (index, control) in controls.iter_mut().enumerate() {
            let Some(msr) = control_msr(index) else { return false };
            *control = hardware.read(msr);
        }
        self.owner = Some(PmuState::new(self.profile, controls));
        self.programmed = controls;
        true
    }

    fn synchronize(&mut self, logical_efer: u64, hardware: &mut impl PmuHardware) -> bool {
        let Some(owner) = self.owner.as_ref() else { return false };
        // Prepare all values before the first write. An unsupported transition
        // cannot leave only part of the PMU translated.
        let mut controls = [0; CONTROL_COUNT];
        for (index, control) in controls.iter_mut().enumerate() {
            let Some(effective) = owner.effective_control(index, logical_efer) else {
                return false;
            };
            *control = effective;
        }
        for (index, control) in controls.into_iter().enumerate() {
            let Some(msr) = control_msr(index) else { return false };
            if control != self.programmed[index] {
                hardware.write(msr, control);
                self.programmed[index] = control;
            }
        }
        true
    }
}

/// A same-CPU selector interface; test doubles observe every hardware access.
trait PmuHardware {
    fn read(&mut self, msr: u32) -> u64;
    fn write(&mut self, msr: u32, value: u64);
}

struct PhysicalPmu;

impl PmuHardware for PhysicalPmu {
    fn read(&mut self, msr: u32) -> u64 {
        // SAFETY: only the six selectors of the admitted target reach this
        // interface, on the owning CPU after irreversible resident entry.
        unsafe { msr::read_msr(msr) }
    }

    fn write(&mut self, msr: u32, value: u64) {
        // SAFETY: the policy admitted this target's selector and retained its
        // reserved fields. Only documented EN/HG fields were translated.
        unsafe { msr::write_msr(msr, value) }
    }
}

/// Complete one selector access after instruction, mode and event validation.
/// Unknown selectors are left to their own dispatcher owners.
///
/// # Safety
/// Actual same-CPU MSR exit, stopped VMCB/frame, IF/GIF clear and an initialized
/// PMU owner. No guest or other host consumer can change physical selectors.
pub(super) unsafe fn handle(
    state: &mut State,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
) -> Option<bool> {
    // SAFETY: caller provides the stopped native instruction boundary.
    unsafe { handle_access(state, vmcb, frame, &mut PhysicalPmu) }
}

/// Refresh selectors after logical EFER changes, including INIT. Every path
/// re-entering this CPU's guest passes this boundary before VMRUN.
///
/// # Safety
/// Initialized resident owner on its original CPU; guest stopped, IF/GIF clear.
pub(super) unsafe fn prepare_entry(state: &mut State, vmcb: &Vmcb) -> bool {
    synchronize(state, vmcb, &mut PhysicalPmu)
}

/// First and only capture occurs on the private stack after the caller has
/// committed to resident execution. Fallible firmware admission makes no PMU
/// access, and its saved state cannot become stale before this capture.
///
/// # Safety
/// Called by the audited initial entry assembly with private descriptors/root,
/// IF/GIF clear, live retained context and admitted physical SVME backing.
#[unsafe(no_mangle)]
pub(super) unsafe extern "win64" fn svmvisor_resident_pmu_initialize(
    context: *mut BridgeContext,
) -> bool {
    // SAFETY: the nonmigrating entry assembly owns this CPU's retained image.
    let state = unsafe { &mut *ptr::addr_of_mut!(STATE) };
    // SAFETY: the same entry owns the stopped VMCB, not yet exposed to VMRUN.
    let vmcb = unsafe { &*ptr::addr_of!(VMCB) };
    let ready = context == ptr::addr_of_mut!(CONTEXT) && initialize(state, vmcb, &mut PhysicalPmu);
    if !ready {
        let exit = vmcb.exit_snapshot();
        stop(state, exit.code, exit.rip, REFUSAL_BOUNDARY, 0);
        // SAFETY: private resident execution has committed; no firmware return
        // or guest entry follows this retained diagnostic stop.
        unsafe { terminal_finish(state) };
    }
    ready
}

fn initialize(state: &mut State, vmcb: &Vmcb, hardware: &mut impl PmuHardware) -> bool {
    if !state.armed || logical_efer(state, vmcb).is_none() {
        return false;
    }
    let Some(pmu) = state.pmu.as_mut() else { return false };
    if !pmu.capture(hardware) {
        return false;
    }
    synchronize(state, vmcb, hardware)
}

fn synchronize(state: &mut State, vmcb: &Vmcb, hardware: &mut impl PmuHardware) -> bool {
    let synchronized = logical_efer(state, vmcb)
        .is_some_and(|efer| state.pmu.as_mut().is_some_and(|pmu| pmu.synchronize(efer, hardware)));
    if synchronized {
        return true;
    }
    let exit = vmcb.exit_snapshot();
    stop(state, exit.code, exit.rip, REFUSAL_BOUNDARY, 0)
}

unsafe fn handle_access(
    state: &mut State,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    hardware: &mut impl PmuHardware,
) -> Option<bool> {
    let msr = frame.rcx as u32;
    control_index(msr)?;
    let exit = vmcb.exit_snapshot();
    let Some(efer) = logical_efer(state, vmcb) else {
        return Some(stop(state, exit.code, exit.rip, REFUSAL_BOUNDARY, u64::from(msr)));
    };
    if !native_msr_exit_ready(vmcb, state.startup_owned) {
        // APM2 physical p580: common exceptions, including CPL != 0 #GP,
        // precede MSRPM lookup. Such a stopped MSR exit is not native evidence.
        return Some(stop(state, exit.code, exit.rip, REFUSAL_BOUNDARY, u64::from(msr)));
    }
    // SAFETY: actual stopped MSR exit; the shared continuation owner validates
    // either architectural nRIP or exact fetched instruction bytes before access.
    let next = match unsafe { native_msr_continuation(state, vmcb) } {
        Ok(next) => next,
        Err(error) => return Some(msr_continuation_failure(state, vmcb, msr, error)),
    };
    let Some(pmu) = state.pmu.as_mut() else {
        return Some(stop(state, exit.code, exit.rip, REFUSAL_BOUNDARY, u64::from(msr)));
    };
    let Some(owner) = pmu.owner.as_mut() else {
        return Some(stop(state, exit.code, exit.rip, REFUSAL_BOUNDARY, u64::from(msr)));
    };
    let read = if exit.info1 == 0 {
        let Some(value) = owner.read(msr) else {
            return Some(stop(state, exit.code, exit.rip, REFUSAL_BOUNDARY, u64::from(msr)));
        };
        Some(value)
    } else {
        let value = u64::from(vmcb.guest_rax() as u32) | (u64::from(frame.rdx as u32) << 32);
        let Some(plan) = owner.prepare_write(msr, value, efer) else {
            return Some(stop(state, exit.code, exit.rip, REFUSAL_BOUNDARY, u64::from(msr)));
        };
        if owner.commit_write(plan).is_err() {
            return Some(stop(state, exit.code, exit.rip, REFUSAL_BOUNDARY, u64::from(msr)));
        }
        // Preserve an explicit WRMSR even when its value is unchanged. Selector
        // writes can affect internal EDGE state; only automatic entry refreshes
        // may skip a redundant write (PPR57896 physical p218).
        hardware.write(plan.msr(), plan.effective());
        pmu.programmed[plan.index()] = plan.effective();
        None
    };
    Some(match apply_msr_completion(vmcb, frame, MsrCompletion::Complete { read }, next) {
        Ok(_) => {
            state.routing_retries = 0;
            true
        }
        Err((tag, value)) => stop(state, exit.code, exit.rip, tag, value),
    })
}

fn logical_efer(state: &State, vmcb: &Vmcb) -> Option<u64> {
    state.efer.as_ref()?.observe_backing(vmcb.guest_cr0(), vmcb.guest_efer()).ok()
}

#[cfg(test)]
mod tests;
