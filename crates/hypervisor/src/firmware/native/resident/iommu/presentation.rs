//! Fresh firmware-report to scalar guest-presentation preparation. Success
//! retains private candidate bytes; PublicationOwner separately establishes
//! source identity, runtime behavior and guest-visible firmware publication.

use super::{ObservationState, Report};
pub mod roots;
use crate::{
    memory::iommu::virtualized::presentation::{PreparationError, Storage, UnitDescriptor},
    svm::configuration::ConfigurationRoute,
};

/// No hardware access or guest publication occurs here. Incomplete acquisition
/// and every unresolved source conflict are recorded, without inventing an
/// ordinary PCI inventory or converting unknown functions into absent devices.
pub fn prepare(
    storage: &mut Storage,
    report: &Report,
    route: ConfigurationRoute,
) -> Result<(), PreparationError> {
    if report.failure.is_some() || !report.tables.is_complete() {
        return storage.refuse(PreparationError::IncompleteReport);
    }
    if report.state != ObservationState::Observed || report.tables.ivrs.has_unresolved_diagnostics()
    {
        return storage.refuse(PreparationError::UnresolvedInventory);
    }
    let units = report.tables.ivrs.units();
    if units.is_empty() || units.len() > 4 {
        return storage.refuse(PreparationError::UnitCount);
    }
    let (base, bytes) = route.aperture();
    if !crate::host::resident::platform::outside_control_page(base, bytes)
        || report.tables.mcfg.allocations().len() != 1
        || report
            .tables
            .mcfg
            .allocations()
            .iter()
            .any(|a| a.segment != 0 || a.start != base || a.last != base + bytes - 1)
    {
        return storage.refuse(PreparationError::Resource);
    }
    let mut descriptors = [UnitDescriptor::EMPTY; 4];
    for (index, unit) in units.iter().enumerate() {
        let observed = report.hardware[index];
        let (Some(pci), Some(registers), Some(physical_mmio_bytes)) =
            (observed.pci, observed.registers, observed.mmio_bytes)
        else {
            return storage.refuse(PreparationError::IncompleteReport);
        };
        let observed_base = (u64::from(pci.base_high) << 32) | u64::from(pci.base_low & !0x3fff);
        if observed.error.is_some() || observed_base != unit.mmio_base || pci.base_low & 1 == 0
            || !crate::host::resident::platform::outside_control_page(unit.mmio_base, physical_mmio_bytes)
            || pci.capability_header & 0x00ff_00ff != 0x000b_000f
            // This profile cannot advertise an already disabled physical owner
            // as preboot DMA protection. Takeover still needs its real audit.
            || (report.tables.ivrs.iv_info & 2 != 0 && registers.control & 1 == 0)
        {
            return storage.refuse(PreparationError::Profile);
        }
        descriptors[index] = UnitDescriptor {
            segment: unit.segment,
            device_id: unit.device_id,
            physical_capability_offset: unit.capability_offset,
            reserved: 0,
            vendor_device: pci.vendor_device,
            class_revision: pci.class_revision,
            mmio_base: unit.mmio_base,
            physical_mmio_bytes,
            configuration_page: pci.config_page,
        };
    }
    if report.hardware[units.len()..].iter().any(|u| *u != super::UnitObservation::EMPTY) {
        return storage.refuse(PreparationError::IncompleteReport);
    }
    storage.prepare(&report.tables.ivrs, route, &descriptors[..units.len()])
}
