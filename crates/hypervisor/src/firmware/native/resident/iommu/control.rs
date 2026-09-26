//! Derive actual CPU control exclusions from one complete aperture observation.
//! Requester/alias policy ambiguity does not authorize DMA, but does not prevent
//! withholding the independently corroborated control pages from guest CPUs.
#![forbid(unsafe_code)]

use super::Report;
use crate::{
    host::resident::control::{ControlManifest, ControlManifestError},
    memory::{address::AddressPolicy, npt::MAX_CONTROL_PAGE_RANGES},
};
use svmvisor_card_abi::endpoint::TerminalEndpoint;

pub fn manifest_from_report(
    report: &Report,
    policy: AddressPolicy,
    signature: u32,
    route: u64,
    cpu_count: usize,
) -> Result<ControlManifest, ControlManifestError> {
    let units = report.tables.ivrs.units();
    let unavailable = || ControlManifest::unavailable(policy, signature, route, cpu_count);
    if !report.tables.is_complete()
        || report.failure.is_some()
        || units.is_empty()
        || units.len() * 2 + 1 > MAX_CONTROL_PAGE_RANGES
    {
        return unavailable();
    }
    let inert = policy.validate(0, 4096, 4096).map_err(|_| ControlManifestError::Ranges)?;
    let mut ranges = [inert; MAX_CONTROL_PAGE_RANGES];
    // Whole F7 control page contains the +310 reset register, +360/+362/+368
    // PM routing and +3d2 control. Denying observed routes is not a claim of
    // complete chipset control coverage; SMM remains trusted.
    ranges[0] = policy
        .validate(crate::host::resident::platform::FCH_CONTROL_PAGE, 4096, 4096)
        .map_err(|_| ControlManifestError::Ranges)?;
    let mut length = 1;
    for (unit, observed) in units.iter().zip(&report.hardware) {
        let (Some(pci), Some(bytes), Some(registers), None) =
            (observed.pci, observed.mmio_bytes, observed.registers, observed.error)
        else {
            return unavailable();
        };
        let base = u64::from(pci.base_low & 0xffff_c000) | (u64::from(pci.base_high) << 32);
        let expected_bytes = if registers.extended_features.is_some_and(|efr| efr & (1 << 9) != 0) {
            0x80000
        } else {
            0x4000
        };
        if unit.segment != 0
            || pci.base_low & 1 == 0
            || base != unit.mmio_base
            || bytes != expected_bytes
            || !crate::host::resident::platform::outside_control_page(base, bytes)
            || !crate::host::resident::platform::outside_control_page(pci.config_page, 4096)
            || TerminalEndpoint::config_page_from_msr(route, u32::from(unit.device_id))
                != Some(pci.config_page)
        {
            return unavailable();
        }
        ranges[length] =
            policy.validate(base, bytes, bytes).map_err(|_| ControlManifestError::Ranges)?;
        ranges[length + 1] = policy
            .validate(pci.config_page, 4096, 4096)
            .map_err(|_| ControlManifestError::Ranges)?;
        length += 2;
    }
    ranges[..length].sort_unstable_by_key(|range| range.base());
    // More than one capability can share a config page. Union whole pages;
    // this never removes a denial or selects among requester declarations.
    let mut used = 0;
    for index in 0..length {
        let range = ranges[index];
        if used != 0 && range.base() <= ranges[used - 1].last_byte() + 1 {
            let previous = ranges[used - 1];
            let end = previous.last_byte().max(range.last_byte()) + 1;
            ranges[used - 1] = policy
                .validate(previous.base(), end - previous.base(), 4096)
                .map_err(|_| ControlManifestError::Ranges)?;
        } else {
            ranges[used] = range;
            used += 1;
        }
    }
    ControlManifest::new(policy, signature, route, cpu_count, &ranges[..used])
}
