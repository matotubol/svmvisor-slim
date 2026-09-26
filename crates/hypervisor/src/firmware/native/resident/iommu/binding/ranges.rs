use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedBuffer {
    DeviceTable,
    Command,
    Event,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Region {
    ProtectedPool,
    Bank { assignment: usize },
    Ecam { allocation: usize },
    ConfigurationPage { unit: usize },
    ControlAperture { unit: usize },
    FirmwareReservation { index: usize },
    ObservedBuffer { unit: usize, buffer: ObservedBuffer },
    PlatformControl,
}

pub(super) fn checked(
    policy: AddressPolicy,
    base: u64,
    bytes: u64,
    alignment: u64,
    region: Region,
) -> Result<PhysicalRange, BindingError> {
    policy.validate(base, bytes, alignment).map_err(|error| BindingError::Address { region, error })
}

fn disjoint(
    first: PhysicalRange,
    first_region: Region,
    second: PhysicalRange,
    second_region: Region,
) -> Result<(), BindingError> {
    if first.base() <= second.last_byte() && second.base() <= first.last_byte() {
        return Err(BindingError::Overlap { first: first_region, second: second_region });
    }
    Ok(())
}

fn platform_disjoint(extent: PhysicalRange, region: Region) -> Result<(), BindingError> {
    if !crate::host::resident::platform::outside_control_page(extent.base(), extent.len()) {
        return Err(BindingError::Overlap { first: region, second: Region::PlatformControl });
    }
    Ok(())
}

pub(super) fn pool_and_assignments(
    policy: AddressPolicy,
    report: &Report,
    pool: PhysicalRange,
    assignments: &[UnitAssignment<'_>],
) -> Result<(), BindingError> {
    checked(policy, pool.base(), pool.len(), 4096, Region::ProtectedPool)?;
    if pool.len() & 4095 != 0 {
        return Err(BindingError::PartialPoolPage);
    }
    platform_disjoint(pool, Region::ProtectedPool)?;
    for (index, allocation) in report.tables.mcfg.allocations().iter().enumerate() {
        let region = Region::Ecam { allocation: index };
        let bytes = allocation.last - allocation.start + 1;
        let ecam = checked(policy, allocation.start, bytes, 4096, region)?;
        platform_disjoint(ecam, region)?;
        disjoint(pool, Region::ProtectedPool, ecam, region)?;
    }
    // Numeric overlap is sufficient to refuse. Disjointness does not resolve
    // the reservation's requester scope, bypass semantics or lifecycle policy.
    for (index, reservation) in report.tables.ivrs.memory_regions().iter().enumerate() {
        let region = Region::FirmwareReservation { index };
        let extent = checked(policy, reservation.start, reservation.length, 1, region)?;
        disjoint(pool, Region::ProtectedPool, extent, region)?;
    }
    for (index, assignment) in assignments.iter().enumerate() {
        if !report
            .tables
            .ivrs
            .units()
            .iter()
            .any(|unit| UnitIdentity::from_unit(*unit) == assignment.identity)
        {
            return Err(BindingError::UnknownUnit { assignment: index });
        }
        let region = Region::Bank { assignment: index };
        checked(policy, assignment.extent.base(), assignment.extent.len(), 4096, region)?;
        if assignment.extent.len() != IOMMU_RESOURCE_BYTES {
            return Err(BindingError::BankSize { assignment: index });
        }
        if assignment.extent.base() < pool.base()
            || assignment.extent.last_byte() > pool.last_byte()
        {
            return Err(BindingError::BankOutsidePool { assignment: index });
        }
        for (other_index, other) in assignments[..index].iter().enumerate() {
            if assignment.identity.same_capability(other.identity) {
                return Err(BindingError::DuplicateAssignment {
                    first: other_index,
                    second: index,
                });
            }
            if core::ptr::eq(assignment.storage, other.storage) {
                return Err(BindingError::ReusedStorage { first: other_index, second: index });
            }
            disjoint(
                assignment.extent,
                region,
                other.extent,
                Region::Bank { assignment: other_index },
            )?;
        }
    }
    Ok(())
}

pub(super) fn configuration_page(
    policy: AddressPolicy,
    report: &Report,
    identity: UnitIdentity,
    unit: usize,
) -> Result<PhysicalRange, BindingError> {
    let mut candidates = report.tables.mcfg.allocations().iter().filter_map(|allocation| {
        (allocation.segment == identity.segment)
            .then(|| allocation.address(identity.device_id, 0))
            .flatten()
    });
    let base = candidates.next().ok_or(BindingError::EcamIdentity { unit })?;
    if candidates.next().is_some() {
        return Err(BindingError::EcamIdentity { unit });
    }
    checked(policy, base, 4096, 4096, Region::ConfigurationPage { unit })
}

pub(super) fn control_disjoint(
    report: &Report,
    pool: PhysicalRange,
    plan: &UninstalledBindingPlan,
    aperture: PhysicalRange,
    unit: usize,
) -> Result<(), BindingError> {
    let region = Region::ControlAperture { unit };
    platform_disjoint(aperture, region)?;
    disjoint(aperture, region, pool, Region::ProtectedPool)?;
    for (index, allocation) in report.tables.mcfg.allocations().iter().enumerate() {
        if aperture.base() <= allocation.last && allocation.start <= aperture.last_byte() {
            return Err(BindingError::Overlap {
                first: region,
                second: Region::Ecam { allocation: index },
            });
        }
    }
    for other in plan.units() {
        disjoint(
            aperture,
            region,
            other.control_aperture,
            Region::ControlAperture { unit: usize::from(other.unit_index) },
        )?;
    }
    Ok(())
}

pub(super) fn iommu_width(
    physical_bits: u8,
    extent: PhysicalRange,
    unit: usize,
    region: Region,
) -> Result<(), BindingError> {
    if extent.last_byte() >> physical_bits != 0 {
        return Err(BindingError::IommuAddressWidth { unit, region });
    }
    Ok(())
}

pub(super) fn observed_buffers(
    policy: AddressPolicy,
    report: &Report,
    pool: PhysicalRange,
    plan: &UninstalledBindingPlan,
) -> Result<(), BindingError> {
    // Register field layouts: 48882-3.11 physical pp214-216,252-256.
    // Reserved read bits are masked, not interpreted as an encoded address.
    const BASE: u64 = 0x000f_ffff_ffff_f000;
    for unit_plan in plan.units() {
        let unit = usize::from(unit_plan.unit_index);
        let r = unit_plan.observed_registers;
        for (buffer, raw, required, head, tail) in [
            (ObservedBuffer::DeviceTable, r.device_table, r.control & 1 != 0, 0, 0),
            (
                ObservedBuffer::Command,
                r.command_buffer,
                r.control & (1 << 12) != 0 || r.status & (1 << 4) != 0,
                r.command_head,
                r.command_tail,
            ),
            (
                ObservedBuffer::Event,
                r.event_log,
                r.control & (1 << 2) != 0 || r.status & (1 << 3) != 0,
                r.event_head,
                r.event_tail,
            ),
        ] {
            let base = raw & BASE;
            if base == 0 && !required {
                continue;
            }
            let invalid = BindingError::ObservedBuffer { unit, buffer };
            if base == 0 {
                return Err(invalid);
            }
            let bytes = if buffer == ObservedBuffer::DeviceTable {
                ((raw & 511) + 1) * 4096
            } else {
                let length = raw >> 56 & 15;
                if length < 8 {
                    return Err(invalid);
                }
                let bytes = 16u64 << length;
                if head & 0x7fff0 >= bytes || tail & 0x7fff0 >= bytes {
                    return Err(invalid);
                }
                bytes
            };
            let region = Region::ObservedBuffer { unit, buffer };
            let extent = checked(policy, base, bytes, 4096, region)?;
            platform_disjoint(extent, region)?;
            iommu_width(unit_plan.iommu_physical_bits, extent, unit, region)?;
            disjoint(extent, region, pool, Region::ProtectedPool)?;
            for other in plan.units() {
                disjoint(
                    extent,
                    region,
                    other.control_aperture,
                    Region::ControlAperture { unit: usize::from(other.unit_index) },
                )?;
            }
            for (index, allocation) in report.tables.mcfg.allocations().iter().enumerate() {
                if extent.base() <= allocation.last && allocation.start <= extent.last_byte() {
                    return Err(BindingError::Overlap {
                        first: region,
                        second: Region::Ecam { allocation: index },
                    });
                }
            }
        }
    }
    Ok(())
}
