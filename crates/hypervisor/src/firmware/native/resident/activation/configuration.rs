//! Reapply the common configuration guard at every firmware NPT construction.
use core::arch::x86_64::__cpuid_count;

use svmvisor_hypervisor::{
    arch::x86_64::msr::{MMIO_CFG_BASE_ADDR, TARGET_PHYSICAL_BITS, TARGET_SIGNATURE},
    host::resident::configuration::RouteExpectation,
    memory::npt::{IdentityNpt, IdentityNptError},
};

/// # Safety
/// The owning native CPU constructs inactive tables before its first guest
/// entry. `expected` was copied from the installer's retained common record
/// through validated native mappings. No terminal endpoint is required.
pub(super) unsafe fn protect(
    npt: &mut IdentityNpt<'_>,
    expected: RouteExpectation,
    physical_bits: u8,
    count: usize,
) -> Result<(), IdentityNptError> {
    let signature = __cpuid_count(1, 0).eax;
    // PPR57896 p210 is target-specific. Refuse before any target MSR read.
    if signature != TARGET_SIGNATURE || physical_bits != TARGET_PHYSICAL_BITS {
        return Err(IdentityNptError::InvalidExclusion);
    }
    let route = expected
        .admit(
            signature,
            physical_bits,
            unsafe { super::capture::rdmsr(MMIO_CFG_BASE_ADDR) },
            count,
        )
        .ok_or(IdentityNptError::InvalidExclusion)?;
    let (base, bytes) = route.aperture();
    npt.protect_write_range(base, bytes)
}
