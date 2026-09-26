//! Native publication and consumption of the CPU control exclusion manifest.
use core::ptr;
use svmvisor_hypervisor::{
    arch::x86_64::msr::{MMIO_CFG_BASE_ADDR, TARGET_SIGNATURE},
    firmware::native::resident::iommu::{
        control::manifest_from_report,
        retained::{CaptureMetadata, RetainedObservation},
    },
    host::resident::{
        STARTUP_PAGE_OFFSET,
        configuration::RouteExpectation,
        control::{CONTROL_MANIFEST_OFFSET, ControlManifest},
    },
    memory::{address::AddressPolicy, npt::ControlPageDenials},
};
use uefi_raw::Status;

/// # Safety
/// Serialized installer after capture, before any CPU/guest can run. The
/// initialized observation is valid typed exclusive firmware storage; the pool
/// including the startup page has already passed native RW/WB admission.
pub(super) unsafe fn publish(
    retained: u64,
    pool_base: u64,
    policy: AddressPolicy,
    expected: RouteExpectation,
    cpu_count: usize,
) -> Result<(), Status> {
    let route = unsafe { super::capture::rdmsr(MMIO_CFG_BASE_ADDR) };
    expected
        .admit(TARGET_SIGNATURE, policy.physical_bits(), route, cpu_count)
        .ok_or(Status::UNSUPPORTED)?;
    let metadata = CaptureMetadata {
        configuration_route: route,
        signature: TARGET_SIGNATURE,
        physical_bits: policy.physical_bits(),
        cpu_count: cpu_count as u8,
    };
    let observation = unsafe { &*(retained as *const RetainedObservation) };
    let report = observation.report(metadata).map_err(|_| Status::UNSUPPORTED)?;
    let manifest = manifest_from_report(report, policy, TARGET_SIGNATURE, route, cpu_count)
        .map_err(|_| Status::UNSUPPORTED)?;
    let destination = pool_base + STARTUP_PAGE_OFFSET + CONTROL_MANIFEST_OFFSET;
    unsafe { (destination as *mut ControlManifest).write(manifest) };
    Ok(())
}

/// # Safety
/// Entire shared startup page is currently readable retained RAM; caller owns
/// the serialized pre-entry phase. Only integer fields are copied from backing.
pub(super) unsafe fn read(
    pool_base: u64,
    pool_bytes: u64,
    policy: AddressPolicy,
    count: usize,
) -> Result<ControlPageDenials, u64> {
    let pool = policy.validate(pool_base, pool_bytes, 4096).map_err(|_| 24u64)?;
    let manifest = unsafe {
        ptr::read(
            (pool_base + STARTUP_PAGE_OFFSET + CONTROL_MANIFEST_OFFSET) as *const ControlManifest,
        )
    };
    manifest
        .denials(
            policy,
            TARGET_SIGNATURE,
            unsafe { super::capture::rdmsr(MMIO_CFG_BASE_ADDR) },
            count,
            pool,
        )
        .map_err(|_| 24u64)
}
