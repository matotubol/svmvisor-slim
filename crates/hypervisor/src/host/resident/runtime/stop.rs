//! Private stop records, the terminal barrier, and the host fault entry.

use core::{arch::asm, ptr};

use crate::{
    arch::x86_64::{
        apic,
        msr::{SYS_CFG, VM_CR, VM_CR_R_INIT},
    },
    host::resident::{
        runtime::{
            ASSIGNED_APIC_ID, RawVmexitCapture, State, VMCB,
            diagnostics::record as diagnostic_record,
            image_base,
            msr::read_msr,
            startup::{mailboxes, send_native_notification},
            svmvisor_resident_raw_vmexit,
        },
        terminal::{self, TerminalControl},
    },
};

impl RawVmexitCapture {
    pub(super) fn stop_record(
        self,
        expected_vmcb: u64,
        assigned_apic_id: u32,
    ) -> Option<(u8, [u64; 6])> {
        // Assembly captures GPR/VMCB provenance on every exit. Physical APIC
        // identity and the optional cache sample are SYS_CFG-specific; other
        // owned registers must not depend on that sample.
        let index = self.guest_rcx as u32;
        if self.code != 0x7c || index != SYS_CFG || self.physical_cache_valid != 1 {
            return None;
        }
        if self.entry_sequence == 0
            || self.entry_sequence != self.exit_sequence
            || self.entry_vmcb_pa != expected_vmcb
            || self.exit_vmcb_pa != expected_vmcb
            || self.context_vmcb_pa != expected_vmcb
            || self.physical_apic_id != u64::from(assigned_apic_id)
        {
            return Some((
                11,
                [
                    self.exit_vmcb_pa,
                    expected_vmcb,
                    (self.physical_apic_id << 32) | u64::from(assigned_apic_id),
                    self.exit_rip,
                    self.nrip,
                    self.entry_rip,
                ],
            ));
        }
        Some((
            10,
            [
                self.exit_rip,
                self.nrip,
                self.entry_rip,
                self.guest_cr0,
                self.mtrr_def_type,
                self.host_cr0,
            ],
        ))
    }
}

pub(super) unsafe fn terminal_requested(state: &State) -> bool {
    state.armed
        && terminal_enabled(state)
        && unsafe { terminal_control() }.ready(state.count)
        && unsafe { terminal_control() }.requested()
}

/// Terminal-only: no route guard is held, no resume follows. APM2 Table15-10
/// holds external SMI/NMI/INIT while GIF=0. All CPUs acknowledge only in that
/// state and never reopen GIF afterward, excluding their firmware/config writes.
/// Reset/machine-check or a nonparticipating CPU can lose retained evidence.
/// The barrier state and fault details stay in monitor-owned memory.
/// Iteration caps are not time bounds.
pub(super) unsafe fn terminal_finish(state: &mut State) {
    if !state.armed || !terminal_enabled(state) {
        return;
    }
    let shared = unsafe { terminal_control() };
    if !shared.ready(state.count) {
        return;
    }
    let winner = state.stopped_valid && shared.claim(state.slot, state.count);
    if !shared.requested() {
        return;
    }
    if !shared.acknowledge(state.slot, state.count) {
        return;
    }
    if !winner {
        return;
    }
    // The published ready gate follows every target's armed/guest ACK. The
    // dedicated terminal request is authoritative; no guest INIT is enqueued.
    let base = unsafe { read_msr(apic::APIC_BASE) };
    // x2APIC has no software-polled ICR delivery status to wait for.
    if base != state.host_apic_base
        || base & apic::APIC_BASE_X2APIC != apic::APIC_BASE_X2APIC
        || unsafe { read_msr(VM_CR) } & VM_CR_R_INIT == 0
        || unsafe { mailboxes(state.count) }.iter().any(|m| !m.is_ready())
    {
        shared.finish(2);
        return;
    }
    // Same already admitted INIT-to-#SX wire operation as startup notification,
    // with a separate irreversible terminal publication instead of a queue.
    unsafe { send_native_notification() };
    for _ in 0..20_000_000 {
        if shared.all_acknowledged(state.count) {
            shared.finish(1);
            // Only a closed reason category can reach the public journal.
            // Detailed stop/fault evidence remains private even on failure.
            let _ = unsafe { super::diagnostics::publish_stop(state) };
            return;
        }
        core::hint::spin_loop();
    }
    shared.finish(3);
}

/// All accesses use the existing pool-excluded shared alias, initialized before
/// any arm call. No guest reference or original DXE pointer survives here.
pub(super) unsafe fn terminal_control() -> &'static TerminalControl {
    unsafe {
        &*((image_base() + super::STARTUP_PAGE_OFFSET + terminal::CONTROL_OFFSET)
            as *const TerminalControl)
    }
}

pub(super) fn terminal_enabled(state: &State) -> bool {
    // Collective refusal is required even when no diagnostic endpoint exists.
    // The shared ready gate still waits for every CPU's actual bootstrap ACK.
    state.startup_owned
        && (2..=super::super::MAX_RESIDENT_CPUS).contains(&state.count)
        && state.slot < state.count
        && state.configuration.is_some()
}

pub(super) fn stop(state: &mut State, code: u64, rip: u64, info1: u64, info2: u64) -> bool {
    // Retain the exact terminal reason privately. The dedicated stopped owner
    // never resumes after this.
    unsafe {
        ptr::write_volatile(&mut state.stopped_rip, rip);
        ptr::write_volatile(&mut state.stopped_info1, info1);
        ptr::write_volatile(&mut state.stopped_info2, info2);
        ptr::write_volatile(&mut state.stopped, code);
        ptr::write_volatile(&mut state.stopped_valid, true);
        if code == 0x7c {
            let raw = ptr::read_volatile(ptr::addr_of!(svmvisor_resident_raw_vmexit));
            if let Some((event, context)) =
                raw.stop_record(ptr::addr_of!(VMCB) as u64, ASSIGNED_APIC_ID)
            {
                // Prefer the immutable boundary for the private first-fault
                // payload; the State fields above retain the final stop reason.
                diagnostic_record(event, true, context, info1 as u32);
            }
        }
        diagnostic_record(3, true, [rip, code, info1, info2, state.exits, 0], 0);
    }
    false
}

/// Terminal assembly has copied the normalized first host exception frame to
/// private retained storage and blocked recursive callback entry. No STATE
/// reference may be formed here: a host fault can interrupt a live mutable
/// runtime borrow. Capture is bounded, then this CPU stays stopped.
#[unsafe(no_mangle)]
unsafe extern "C" fn svmvisor_resident_host_fault(frame: *const u64, cr2: u64, cr3: u64) -> ! {
    let vector = unsafe { ptr::read(frame) } as u32;
    let error = unsafe { ptr::read(frame.add(1)) };
    let rip = unsafe { ptr::read(frame.add(2)) };
    let flags = unsafe { ptr::read(frame.add(4)) };
    let rsp = unsafe { ptr::read(frame.add(5)) };
    unsafe {
        diagnostic_record(4, true, [rip, error, cr2, cr3, rsp, flags], vector);
    }
    unsafe {
        asm!("cli", "2: hlt", "jmp 2b", options(noreturn, nostack));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arch::x86_64::msr::{TARGET_PHYSICAL_BITS, TARGET_SIGNATURE},
        host::resident::runtime::INITIAL_STATE,
        svm::configuration::ConfigurationRoute,
    };

    #[test]
    fn collective_refusal_does_not_require_a_terminal_endpoint() {
        let mut state = INITIAL_STATE;
        state.startup_owned = true;
        state.count = 24;
        state.slot = 23;
        assert!(state.terminal_endpoint.is_none());
        assert!(!terminal_enabled(&state), "no admitted configuration owner");
        state.configuration = Some(
            ConfigurationRoute::admit_target(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, 0xe000_0021)
                .unwrap(),
        );
        assert!(terminal_enabled(&state));
        state.startup_owned = false;
        assert!(!terminal_enabled(&state));
    }

    #[test]
    fn collective_refusal_rejects_invalid_participation() {
        let mut state = INITIAL_STATE;
        state.startup_owned = true;
        state.configuration = Some(
            ConfigurationRoute::admit_target(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, 0xe000_0021)
                .unwrap(),
        );
        for (count, slot) in [(0, 0), (1, 0), (2, 2), (32, 32), (33, 0), (usize::MAX, 0)] {
            state.count = count;
            state.slot = slot;
            assert!(!terminal_enabled(&state), "count {count}, slot {slot}");
        }
        state.count = 32;
        state.slot = 31;
        assert!(terminal_enabled(&state));
    }
}
