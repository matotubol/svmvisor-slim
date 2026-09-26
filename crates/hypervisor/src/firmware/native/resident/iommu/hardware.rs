//! AMD 48882-3.11 pp205-208/214-225/250-256: capability identity and
//! documented RO/RW/RW1C register reads only. RW1C status is never written.
//! PCI/MMIO observations are sequential, not an atomic or stable ownership claim.
use super::{MAX_OBSERVED_UNITS, ObservationState, ReadError, ReadOnlyAccess, Report};
use crate::memory::{
    address::AddressPolicy,
    iommu::{IommuUnit, Mcfg},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareError {
    Read { offset: u16, error: ReadError },
    PhysicalAddress,
    MissingEcam,
    AmbiguousEcam,
    MissingFunction,
    WrongClass,
    UnsupportedHeader,
    MalformedCapabilities,
    CapabilityMissing,
    CapabilityIdentity,
    CapabilityRevision,
    MmioDisabled,
    MmioBaseMismatch,
    MmioOverlapsEcam,
    MmioOverlapsIommu { unit_index: u16 },
    ApertureScanStopped,
    FirmwareFeatureMismatch,
    PerformanceBaseAlignment,
    ChangingConfiguration,
    ExtendedStateNotInventoried,
    InvalidActiveBuffer,
    MmioOverlapsPlatform,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciObservation {
    pub config_page: u64,
    pub vendor_device: u32,
    pub command_status: u32,
    pub class_revision: u32,
    pub capability_header: u32,
    pub base_low: u32,
    pub base_high: u32,
    pub range: u32,
    pub miscellaneous0: u32,
    pub miscellaneous1: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterObservation {
    pub device_table: u64,
    pub command_buffer: u64,
    pub event_log: u64,
    pub control: u64,
    pub exclusion_base: u64,
    pub exclusion_limit: u64,
    pub extended_features: Option<u64>,
    pub extended_features2: Option<u64>,
    pub command_head: u64,
    pub command_tail: u64,
    pub event_head: u64,
    pub event_tail: u64,
    pub status: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitObservation {
    pub pci: Option<PciObservation>,
    /// Feature-derived aperture size, after physical-width/alignment checks.
    /// A known extent can still overlap another declaration and be refused.
    pub mmio_bytes: Option<u64>,
    pub registers: Option<RegisterObservation>,
    pub error: Option<HardwareError>,
}
impl UnitObservation {
    pub const EMPTY: Self = Self { pci: None, mmio_bytes: None, registers: None, error: None };
}

pub(super) fn observe(access: &mut impl ReadOnlyAccess, policy: AddressPolicy, out: &mut Report) {
    let units = out.tables.ivrs.units();
    if units.is_empty() || units.len() > MAX_OBSERVED_UNITS {
        out.state = ObservationState::Unsupported;
        return;
    }
    // Addresses described by tables are metadata, but malformed widths must
    // not reach an adapter as purportedly admitted resources.
    if out
        .tables
        .ivrs
        .memory_regions()
        .iter()
        .any(|r| policy.validate(r.start, r.length, 1).is_err())
        || out.tables.mcfg.allocations().iter().any(|a| {
            a.last.checked_sub(a.start).and_then(|n| n.checked_add(1)).is_none_or(|bytes| {
                policy.validate(a.start, bytes, 1).is_err()
                    || !crate::host::resident::platform::outside_control_page(a.start, bytes)
            })
        })
    {
        out.state = ObservationState::Malformed;
        return;
    }
    // A low-address PCSup unit can cover a later declared unit. Visit physical
    // bases in ascending order, not IVHD order, so no covered neighbor is read
    // before the larger aperture is known. No sort buffer or allocation needed;
    // this bounded selection performs at most MAX_UNITS squared comparisons.
    let mut previous_base = None;
    let mut stopped = false;
    for _ in 0..units.len() {
        let next = units
            .iter()
            .enumerate()
            .filter(|(_, unit)| previous_base.is_none_or(|previous| unit.mmio_base > previous))
            .min_by_key(|(_, unit)| unit.mmio_base);
        let Some((index, unit)) = next else {
            out.state = ObservationState::Ambiguous;
            return;
        };
        previous_base = Some(unit.mmio_base);
        let Some(slot) = out.hardware.get_mut(index) else {
            out.state = ObservationState::Unsupported;
            return;
        };
        if stopped {
            slot.error = Some(HardwareError::ApertureScanStopped);
            continue;
        }
        if let Err(error) =
            observe_unit(access, policy, &out.tables.mcfg, units, index, *unit, slot)
        {
            slot.error = Some(error);
        }
        // Unknown or changing decode cannot admit another unit's MMIO. An
        // overlap stops the scan immediately, even for later disjoint units.
        stopped = slot.mmio_bytes.is_none()
            || slot.error.is_some_and(|error| {
                aperture_conflict(error) || error == HardwareError::ChangingConfiguration
            });
        // Type11/40 EFR/EFR2 images are exact register copies, not suggestions
        // (48882-3.11 pp298-301). Do not choose one disagreeing form silently.
        if let Some(registers) = slot.registers {
            if out.tables.ivrs.forms().iter().filter(|form| form.unit_index as usize == index).any(
                |form| {
                    (form.efr.is_some() && form.efr != registers.extended_features)
                        || (form.efr2.is_some() && form.efr2 != registers.extended_features2)
                },
            ) {
                slot.error = Some(HardwareError::FirmwareFeatureMismatch);
            }
        }
    }
    // Unresolved diagnostics need review before a future ownership transaction.
    // Even all-successful register reads do not erase that ambiguity.
    out.state = if out.tables.ivrs.has_unresolved_diagnostics()
        || out
            .hardware
            .iter()
            .take(units.len())
            .any(|unit| unit.error.is_some_and(aperture_conflict))
    {
        ObservationState::Ambiguous
    } else if out.hardware.iter().take(units.len()).any(|unit| unit.error.is_some()) {
        ObservationState::Partial
    } else {
        ObservationState::Observed
    };
}

fn observe_unit(
    access: &mut impl ReadOnlyAccess,
    policy: AddressPolicy,
    mcfg: &Mcfg,
    units: &[IommuUnit],
    unit_index: usize,
    unit: IommuUnit,
    out: &mut UnitObservation,
) -> Result<(), HardwareError> {
    policy.validate(unit.mmio_base, 0x4000, 0x4000).map_err(|_| HardwareError::PhysicalAddress)?;
    check_aperture(mcfg, units, unit_index, unit.mmio_base, 0x4000)?;
    let mut candidates = mcfg.allocations().iter().filter(|allocation| {
        allocation.segment == unit.segment && allocation.address(unit.device_id, 0).is_some()
    });
    let allocation = candidates.next().ok_or(HardwareError::MissingEcam)?;
    if candidates.next().is_some() {
        return Err(HardwareError::AmbiguousEcam);
    }
    let page = allocation.address(unit.device_id, 0).ok_or(HardwareError::MissingEcam)?;
    policy.validate(page, 4096, 4096).map_err(|_| HardwareError::PhysicalAddress)?;
    let pci = capability(access, unit, page)?;
    out.pci = Some(pci);
    if pci.base_low & 1 == 0 {
        return Err(HardwareError::MmioDisabled);
    }
    let base = (u64::from(pci.base_high) << 32) | u64::from(pci.base_low & 0xffff_c000);
    if base == 0 || base != unit.mmio_base {
        return Err(HardwareError::MmioBaseMismatch);
    }
    let mut read = |offset| -> Result<u64, HardwareError> {
        let address = base.checked_add(u64::from(offset)).ok_or(HardwareError::PhysicalAddress)?;
        policy.validate(address, 8, 8).map_err(|_| HardwareError::PhysicalAddress)?;
        access.read_mmio_u64(address).map_err(|error| HardwareError::Read { offset, error })
    };
    // Both Extended Feature registers are reserved unless EFRSup is advertised
    // (48882-3.11 pp225/250). Firmware images do not authorize optional reads.
    let features = if pci.capability_header & (1 << 27) != 0 { Some(read(0x30)?) } else { None };
    let mmio_bytes = if features.is_some_and(|value| value & (1 << 9) != 0) {
        policy
            .validate(base, 0x80000, 0x80000)
            .map_err(|_| HardwareError::PerformanceBaseAlignment)?;
        0x80000
    } else {
        0x4000
    };
    out.mmio_bytes = Some(mmio_bytes);
    // PCSup expands the entire register aperture, not merely the offsets we
    // read. Check it before EFR2/control/queue reads and before another unit.
    check_aperture(mcfg, units, unit_index, base, mmio_bytes)?;
    let registers = RegisterObservation {
        extended_features: features,
        extended_features2: if features.is_some() { Some(read(0x1a0)?) } else { None },
        control: read(0x18)?,
        device_table: read(0)?,
        command_buffer: read(8)?,
        event_log: read(0x10)?,
        exclusion_base: read(0x20)?,
        exclusion_limit: read(0x28)?,
        command_head: read(0x2000)?,
        command_tail: read(0x2008)?,
        event_head: read(0x2010)?,
        event_tail: read(0x2018)?,
        status: read(0x2020)?,
    };
    out.registers = Some(registers);
    if read(0x18)? != registers.control
        || read(0)? != registers.device_table
        || read(8)? != registers.command_buffer
        || read(0x10)? != registers.event_log
        || read(0x20)? != registers.exclusion_base
        || read(0x28)? != registers.exclusion_limit
    {
        return Err(HardwareError::ChangingConfiguration);
    }
    if capability(access, unit, page)? != pci {
        return Err(HardwareError::ChangingConfiguration);
    }
    // These modes involve additional table/queue sets outside this deliberately
    // bounded observation profile. Preserve the base registers and refuse a
    // complete acquisition status instead of following any DMA pointer.
    if unobserved_control_state(registers.control) {
        return Err(HardwareError::ExtendedStateNotInventoried);
    }
    validate_active_buffers(policy, registers)?;
    Ok(())
}

fn aperture_conflict(error: HardwareError) -> bool {
    matches!(
        error,
        HardwareError::MmioOverlapsEcam
            | HardwareError::MmioOverlapsIommu { .. }
            | HardwareError::MmioOverlapsPlatform
    )
}

fn check_aperture(
    mcfg: &Mcfg,
    units: &[IommuUnit],
    unit_index: usize,
    base: u64,
    bytes: u64,
) -> Result<(), HardwareError> {
    if !crate::host::resident::platform::outside_control_page(base, bytes) {
        return Err(HardwareError::MmioOverlapsPlatform);
    }
    if mcfg
        .allocations()
        .iter()
        .any(|allocation| aperture_overlaps(base, bytes, allocation.start, allocation.last))
    {
        return Err(HardwareError::MmioOverlapsEcam);
    }
    for (other_index, other) in units.iter().enumerate() {
        if other_index == unit_index {
            continue;
        }
        let last = other.mmio_base.checked_add(0x3fff).ok_or(HardwareError::PhysicalAddress)?;
        if aperture_overlaps(base, bytes, other.mmio_base, last) {
            return Err(HardwareError::MmioOverlapsIommu { unit_index: other_index as u16 });
        }
    }
    Ok(())
}

/// Full inclusive-range comparison. Overflow/empty windows fail closed. MCFG
/// alignment is separately established by the parser, never inferred here.
pub(super) fn aperture_overlaps(base: u64, bytes: u64, other_base: u64, other_last: u64) -> bool {
    other_base > other_last
        || bytes
            .checked_sub(1)
            .and_then(|last| base.checked_add(last))
            .is_none_or(|last| base <= other_last && other_base <= last)
}

fn validate_active_buffers(
    policy: AddressPolicy,
    r: RegisterObservation,
) -> Result<(), HardwareError> {
    const BASE: u64 = 0x000f_ffff_ffff_f000;
    let valid = |base, bytes| base != 0 && policy.validate(base, bytes, 4096).is_ok();
    if r.control & 1 != 0 && !valid(r.device_table & BASE, ((r.device_table & 511) + 1) * 4096) {
        return Err(HardwareError::InvalidActiveBuffer);
    }
    for (enabled, raw, head, tail) in [
        (r.control & (1 << 12) != 0, r.command_buffer, r.command_head, r.command_tail),
        (r.control & 4 != 0, r.event_log, r.event_head, r.event_tail),
    ] {
        if !enabled {
            continue;
        }
        let length_code = (raw >> 56) & 15;
        let bytes = 16u64 << length_code;
        if length_code < 8
            || !valid(raw & BASE, bytes)
            || head & 0x7fff0 >= bytes
            || tail & 0x7fff0 >= bytes
        {
            return Err(HardwareError::InvalidActiveBuffer);
        }
    }
    if r.exclusion_base & 1 != 0 {
        let base = r.exclusion_base & BASE;
        let last = (r.exclusion_limit & BASE) | 4095;
        if last
            .checked_sub(base)
            .and_then(|n| n.checked_add(1))
            .is_none_or(|bytes| policy.validate(base, bytes, 4096).is_err())
        {
            return Err(HardwareError::InvalidActiveBuffer);
        }
    }
    Ok(())
}

pub(super) fn unobserved_control_state(control: u64) -> bool {
    // p217 PNG + pp218-220 descriptions: each field below enables state whose
    // additional registers/tables are outside this acquisition profile.
    const PPR: u64 = 7 << 13;
    const GUEST_TRANSLATION_AND_APIC: u64 = 3 << 16;
    const SMI_FILTER: u64 = (1 << 22) | (1 << 24);
    const GA_MODE_AND_LOG: u64 = 0x1f << 25;
    const DUAL_LOGS_AND_TABLE_SEGMENTS: u64 = 0x7f << 30;
    const MEMORY_ROUTING: u64 = 1 << 40;
    const X2APIC: u64 = 3 << 50;
    const VIRTUAL_IOMMU: u64 = 3 << 52;
    const TIERED_MEMORY: u64 = 1 << 56;
    const BUFFER_TRANSLATION_AND_SNP: u64 = 0xf << 60;
    control
        & (PPR
            | GUEST_TRANSLATION_AND_APIC
            | SMI_FILTER
            | GA_MODE_AND_LOG
            | DUAL_LOGS_AND_TABLE_SEGMENTS
            | MEMORY_ROUTING
            | X2APIC
            | VIRTUAL_IOMMU
            | TIERED_MEMORY
            | BUFFER_TRANSLATION_AND_SNP)
        != 0
}

fn capability(
    access: &mut impl ReadOnlyAccess,
    unit: IommuUnit,
    page: u64,
) -> Result<PciObservation, HardwareError> {
    let mut read = |offset: u16| {
        let address = page.checked_add(u64::from(offset)).ok_or(HardwareError::PhysicalAddress)?;
        access
            .read_pci_u32(unit.segment, unit.device_id, address)
            .map_err(|error| HardwareError::Read { offset, error })
    };
    let vendor_device = read(0)?;
    if matches!(vendor_device & 0xffff, 0 | 0xffff) {
        return Err(HardwareError::MissingFunction);
    }
    let command_status = read(4)?;
    let class_revision = read(8)?;
    if class_revision >> 8 != 0x080600 {
        return Err(HardwareError::WrongClass);
    }
    if (read(0x0c)? >> 16) & 0x7f != 0 {
        return Err(HardwareError::UnsupportedHeader);
    }
    if command_status & (1 << 20) == 0 {
        return Err(HardwareError::CapabilityMissing);
    }
    let offset = unit.capability_offset;
    if !(0x40..=0xec).contains(&offset) || offset & 3 != 0 {
        return Err(HardwareError::MalformedCapabilities);
    }
    let mut next = (read(0x34)? & 0xff) as u16;
    let mut visited = 0u64;
    let mut found = None;
    for _ in 0..48 {
        if next == 0 {
            break;
        }
        if !(0x40..=0xfc).contains(&next) || next & 3 != 0 || visited & (1 << (next / 4)) != 0 {
            return Err(HardwareError::MalformedCapabilities);
        }
        visited |= 1 << (next / 4);
        let header = read(next)?;
        if next == offset {
            found = Some(header);
        }
        next = ((header >> 8) & 0xff) as u16;
    }
    if next != 0 {
        return Err(HardwareError::MalformedCapabilities);
    }
    let header = found.ok_or(HardwareError::CapabilityMissing)?;
    if header & 0xff != 0x0f || (header >> 16) & 7 != 3 {
        return Err(HardwareError::CapabilityIdentity);
    }
    if (header >> 19) & 0x1f != 1 {
        return Err(HardwareError::CapabilityRevision);
    }
    let extended = header & (1 << 28) != 0;
    let length = if extended { 24 } else { 20 };
    if offset + length > 256 {
        return Err(HardwareError::MalformedCapabilities);
    }
    for inner in ((offset + 4)..(offset + length)).step_by(4) {
        if visited & (1 << (inner / 4)) != 0 {
            return Err(HardwareError::MalformedCapabilities);
        }
    }
    Ok(PciObservation {
        config_page: page,
        vendor_device,
        command_status,
        class_revision,
        capability_header: header,
        base_low: read(offset + 4)?,
        base_high: read(offset + 8)?,
        range: read(offset + 12)?,
        miscellaneous0: read(offset + 16)?,
        miscellaneous1: if extended { Some(read(offset + 20)?) } else { None },
    })
}
