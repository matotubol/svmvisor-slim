//! Temporary ECAM write windows for the minimal reader's endpoint lifetime.
//!
//! PPR57896 physical pp40-41 requires UC ECAM and orders configuration before
//! subsequent posted writes. APM2 physical p273 defines CPUID serialization,
//! including draining write buffers. These are first-boot CPU ordering guarantees;
//! firmware/SMM, physical removal and asynchronous device reset remain excluded.

use core::{arch::x86_64::__cpuid_count, ptr};

use crate::{
    host::resident::runtime::{
        NPT, State, diagnostics,
        exit::retry_routing,
        stop::{stop, terminal_control},
    },
    memory::npt::set_identity_write_range,
    svm::vmcb::Vmcb,
};

/// # Safety
/// Valid stopped CPU/context, before any startup reset, root switch or MMIO publication.
pub(super) unsafe fn close(state: &mut State, vmcb: &mut Vmcb) -> bool {
    if !state.armed || !diagnostics::available() {
        return true;
    }
    // SAFETY: published shared control, private stopped CPU and VMCB.
    let control = unsafe { terminal_control() };
    if !control.configuration_open(state.slot) {
        return true;
    }
    // Native host CPUID does not change guest CPUID interception or register state.
    // Serialize before releasing the cross-CPU mask, even if this exit is an INIT or fault.
    let _ = __cpuid_count(0, 0);
    let aperture =
        unsafe { diagnostics::endpoint() }.and_then(|endpoint| endpoint.config_aperture());
    if let Some((base, bytes)) = aperture
        // SAFETY: no guest currently consumes this CPU's tables.
        && unsafe { set_permissions(vmcb, base, bytes, false) }
    {
        vmcb.request_full_tlb_flush();
        control.finish_configuration(state.slot);
        return true;
    }
    let exit = vmcb.exit_snapshot();
    stop(state, exit.code, exit.rip, 0xf205, exit.info2)
}

/// # Safety
/// Actual admitted ECAM write NPF, stopped private root and guest context.
pub(super) unsafe fn open(
    state: &mut State,
    vmcb: &mut Vmcb,
    base: u64,
    bytes: u64,
) -> Option<bool> {
    // SAFETY: initialized shared control on the admitted runtime.
    let control = unsafe { terminal_control() };
    let Some(guard) = control.diagnostic_lock() else {
        return Some(retry_routing(state, vmcb));
    };
    let exit = vmcb.exit_snapshot();
    // SAFETY: shared gate excludes publication; native store has not yet executed.
    unsafe { diagnostics::note_config_write(exit.info2, 0, 0, 1) };
    if !guard.begin_configuration(state.slot)
        // SAFETY: only the currently installed private root can consume this retry.
        || !unsafe { set_permissions(vmcb, base, bytes, true) }
    {
        return Some(stop(state, exit.code, exit.rip, 0xf203, exit.info2));
    }
    vmcb.request_full_tlb_flush();
    state.routing_retries = 0;
    // The window remains published after the gate drops, through guest execution.
    Some(true)
}

pub(super) unsafe fn publication_blocked() -> bool {
    // SAFETY: caller holds the published control page's diagnostic gate.
    unsafe { terminal_control() }.configuration_pending()
}

/// Whether this CPU must retain the existing opportunistic PAUSE exit until
/// its next exit closes an ECAM write window. This is not a timer guarantee.
pub(super) unsafe fn pending(state: &State) -> bool {
    state.armed
        && diagnostics::available()
        && unsafe { terminal_control() }.configuration_open(state.slot)
}

/// Only this CPU's active identity root may have an open configuration window.
unsafe fn set_permissions(vmcb: &Vmcb, base: u64, bytes: u64, writable: bool) -> bool {
    let root = vmcb.nested_root();
    if root == ptr::addr_of!(NPT) as u64 {
        // SAFETY: private current CPU tables, guest stopped throughout the mutation.
        let storage = unsafe { &mut (*ptr::addr_of_mut!(NPT)).0 };
        set_identity_write_range(storage, root, base, bytes, writable).is_ok()
    } else {
        false
    }
}
