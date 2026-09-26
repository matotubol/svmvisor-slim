//! Resident entry point linked from the hypervisor crate into its payload artifact.

use crate::host::resident::{self, ResidentDirectory};

/// # Safety
/// DXE owns the complete raw pool, immutable package, identity mappings and
/// exclusive preparation of this CPU slot, as required by `resident::prepare`.
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn entry_uefi(
    base: u64,
    directory: *mut ResidentDirectory,
    pool_base: u64,
    pool_bytes: u64,
    cpu_slot: u64,
    apic_id: u64,
) -> u64 {
    // SAFETY: the shared DXE contract is forwarded without changing ownership.
    unsafe { svmvisor_minimal_prepare(base, directory, pool_base, pool_bytes, cpu_slot, apic_id) }
}

/// Actual minimal producer entry retained for the linked-artifact audit.
/// # Safety
/// Same complete DXE ownership contract as `entry_uefi`.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "win64" fn svmvisor_minimal_prepare(
    base: u64,
    directory: *mut ResidentDirectory,
    pool_base: u64,
    pool_bytes: u64,
    cpu_slot: u64,
    apic_id: u64,
) -> u64 {
    // SAFETY: this producer selects resident-runtime at compile time;
    // the shared preparation only constructs state and never executes VMRUN.
    unsafe { resident::prepare(base, directory, pool_base, pool_bytes, cpu_slot, apic_id) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        // SAFETY: this payload is entered only at CPL0 under the shared DXE contract.
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}
