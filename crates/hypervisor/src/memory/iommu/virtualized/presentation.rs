//! Coherent bounded guest firmware profile. This renderer neither installs an
//! ACPI table nor infers physical topology from a scan. Its caller must establish
//! every actual requester/ACPI identity and implement the retained reservations.
//! Source layouts: 48882-3.11 physical pp290-292,300-309 (text and PNG checked).

use crate::memory::iommu::{Ivrs, MemoryScope, RequesterKind, SpecialVariety, UidFormat};
use crate::svm::pci::iommu::{APERTURE_BYTES, CAPABILITY_OFFSET};

/// Table 88 (physical p292), independently encoded from PCI Miscellaneous 0:
/// VA[21:15]=48, PA[14:8]=48, GVA[7:5]=2 and EFRSup[0]=1. Bit1 is a separately
/// retained preboot-DMA requirement; PCI MsiNum[4:0] must not be copied here.
pub const IVINFO_PROFILE: u32 = (48 << 15) | (48 << 8) | (2 << 5) | 1;

mod retained;
pub use retained::{
    PreparationError, PublicationOwner, PublishError, STORAGE_BYTES, Storage, UnitAccess,
    UnitDescriptor, View,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unit {
    pub segment: u16,
    pub device_id: u16,
    pub mmio_base: u64,
}

impl Unit {
    pub const EMPTY: Self = Self { segment: 0, device_id: 0, mmio_base: 0 };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnresolvedInventory,
    UnitIdentity,
    ResourceWidth,
    UnsupportedAts,
    UnsupportedExtendedSettings,
    AcpiStringIdentityRequired,
    MissingDeviceEntries,
    Capacity,
}

/// One revision-2/type-40 representation per identified unit, with the exact
/// same VA/PA/GVA/EFR profile as the PCI bank and virtual MMIO core. No physical
/// feature bits are copied. DMA-remap support is retained as a requirement for
/// publication; rendering alone does not establish preboot DMA protection.
/// Output is cleared on error so a partial table cannot escape as a candidate.
pub fn render(source: &Ivrs, units: &[Unit], out: &mut [u8]) -> Result<usize, Error> {
    out.fill(0);
    let result = render_inner(source, units, out);
    if result.is_err() {
        out.fill(0);
    }
    result
}

fn render_inner(source: &Ivrs, units: &[Unit], out: &mut [u8]) -> Result<usize, Error> {
    if source.has_unresolved_diagnostics() {
        return Err(Error::UnresolvedInventory);
    }
    if units.is_empty() || units.len() > 4 || units.len() != source.units().len() {
        return Err(Error::UnitIdentity);
    }
    for (index, unit) in units.iter().enumerate() {
        let physical = source.units()[index];
        if unit.segment != physical.segment
            || unit.device_id != physical.device_id
            || unit.segment != 0
            || unit.mmio_base == 0
            || unit.mmio_base & 0x3fff != 0
            || unit.mmio_base.checked_add(APERTURE_BYTES).is_none_or(|end| end > super::GUEST_LIMIT)
        {
            return Err(Error::UnitIdentity);
        }
        for other in &units[..index] {
            if other.device_id == unit.device_id
                || (other.mmio_base < unit.mmio_base + APERTURE_BYTES
                    && unit.mmio_base < other.mmio_base + APERTURE_BYTES)
            {
                return Err(Error::UnitIdentity);
            }
        }
    }
    for region in source.memory_regions() {
        if region.length == 0
            || region.start.checked_add(region.length).is_none_or(|end| end > super::GUEST_LIMIT)
        {
            return Err(Error::ResourceWidth);
        }
    }
    let dma_remap = source.iv_info & 2;
    let mut writer = Writer { out, position: 0 };
    let header = writer.zero(48)?;
    header[..4].copy_from_slice(b"IVRS");
    header[8] = 2;
    header[10..16].copy_from_slice(&source.header.oem_id);
    header[16..24].copy_from_slice(&source.header.oem_table_id);
    header[24..28].copy_from_slice(&source.header.oem_revision.to_le_bytes());
    header[28..32].copy_from_slice(b"SVMV");
    header[32..36].copy_from_slice(&1u32.to_le_bytes());
    header[36..40].copy_from_slice(&(IVINFO_PROFILE | dma_remap).to_le_bytes());

    for (index, unit) in units.iter().enumerate() {
        // Alternative forms are equivalent only after the parser's complete
        // diagnostics have been resolved. Prefer the form capable of ACPI IDs.
        let (selected, _) = source
            .forms()
            .iter()
            .enumerate()
            .filter(|(_, form)| usize::from(form.unit_index) == index)
            .max_by_key(|(_, form)| form.kind)
            .ok_or(Error::UnitIdentity)?;
        let start = writer.position;
        let header = writer.zero(40)?;
        header[0] = 0x40;
        header[1] = 1 << 5; // Coherent recommended; ATS/HT/optional flags clear.
        header[4..6].copy_from_slice(&unit.device_id.to_le_bytes());
        header[6..8].copy_from_slice(&CAPABILITY_OFFSET.to_le_bytes());
        header[8..16].copy_from_slice(&unit.mmio_base.to_le_bytes());
        header[16..18].copy_from_slice(&unit.segment.to_le_bytes());
        // MsiNum/UnitID, HATDis, EFR and EFR2 are all zero.
        for scope in
            source.requester_scopes().iter().filter(|s| usize::from(s.form_index) == selected)
        {
            settings(scope.dte_settings)?;
            let kind = match scope.kind {
                RequesterKind::All => 1,
                RequesterKind::Select => 2,
                RequesterKind::Range => 3,
                RequesterKind::AliasSelect => 0x42,
                RequesterKind::AliasRange => 0x43,
                RequesterKind::ExtendedSelect => 0x46,
                RequesterKind::ExtendedRange => 0x47,
            };
            let entry = writer.zero(if kind < 0x40 { 4 } else { 8 })?;
            entry[0] = kind;
            entry[1..3].copy_from_slice(&scope.range.first.to_le_bytes());
            entry[3] = scope.dte_settings;
            if let Some(source) = scope.alias_source {
                entry[5..7].copy_from_slice(&source.to_le_bytes());
            }
            if let Some(extended) = scope.extended_settings {
                if extended & !(1 << 31) != 0 {
                    return Err(Error::UnsupportedExtendedSettings);
                }
                entry[4..8].copy_from_slice(&extended.to_le_bytes());
            }
            if matches!(
                scope.kind,
                RequesterKind::Range | RequesterKind::AliasRange | RequesterKind::ExtendedRange
            ) {
                let end = writer.zero(4)?;
                end[0] = 4;
                end[1..3].copy_from_slice(&scope.range.last.to_le_bytes());
            }
        }
        for special in
            source.special_devices().iter().filter(|s| usize::from(s.form_index) == selected)
        {
            settings(special.dte_settings)?;
            let entry = writer.zero(8)?;
            entry[0] = 0x48;
            entry[3] = special.dte_settings;
            entry[4] = special.handle;
            entry[5..7].copy_from_slice(&special.source_id.to_le_bytes());
            entry[7] = match special.variety {
                SpecialVariety::IoApic => 1,
                SpecialVariety::Hpet => 2,
            };
        }
        for acpi in source.acpi_devices().iter().filter(|s| usize::from(s.form_index) == selected) {
            settings(acpi.dte_settings)?;
            if dma_remap != 0 && acpi.uid_format != UidFormat::String {
                return Err(Error::AcpiStringIdentityRequired);
            }
            let entry = writer.zero(22 + acpi.uid().len())?;
            entry[0] = 0xf0;
            entry[1..3].copy_from_slice(&acpi.source_id.to_le_bytes());
            entry[3] = acpi.dte_settings;
            entry[4..12].copy_from_slice(&acpi.hardware_id);
            entry[12..20].copy_from_slice(&acpi.compatible_id);
            entry[20] = match acpi.uid_format {
                UidFormat::Absent => 0,
                UidFormat::Integer => 1,
                UidFormat::String => 2,
            };
            entry[21] = acpi.uid().len() as u8;
            entry[22..].copy_from_slice(acpi.uid());
        }
        let length = writer.position - start;
        if length == 40 {
            return Err(Error::MissingDeviceEntries);
        }
        let length = u16::try_from(length).map_err(|_| Error::Capacity)?;
        writer.out[start + 2..start + 4].copy_from_slice(&length.to_le_bytes());
        // Preserve every reservation, including ones following another
        // equivalent physical form. Never erase an exclusion/unity requirement.
        for region in source.memory_regions().iter().filter(|region| {
            source
                .forms()
                .get(usize::from(region.preceding_form_index))
                .is_some_and(|form| usize::from(form.unit_index) == index)
        }) {
            let entry = writer.zero(32)?;
            entry[1] = region.raw_flags;
            entry[2..4].copy_from_slice(&32u16.to_le_bytes());
            match region.scope {
                MemoryScope::AllDevices => entry[0] = 0x20,
                MemoryScope::Devices { segment, range } => {
                    entry[0] = if range.first == range.last { 0x21 } else { 0x22 };
                    entry[4..6].copy_from_slice(&range.first.to_le_bytes());
                    if range.first != range.last {
                        entry[6..8].copy_from_slice(&range.last.to_le_bytes());
                    }
                    entry[8..10].copy_from_slice(&segment.to_le_bytes());
                }
            }
            entry[16..24].copy_from_slice(&region.start.to_le_bytes());
            entry[24..32].copy_from_slice(&region.length.to_le_bytes());
        }
    }
    let length = writer.position;
    writer.out[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    writer.out[9] =
        0u8.wrapping_sub(writer.out[..length].iter().fold(0u8, |sum, b| sum.wrapping_add(*b)));
    Ok(length)
}

fn settings(value: u8) -> Result<(), Error> {
    if value & 8 != 0 { Err(Error::UnsupportedAts) } else { Ok(()) }
}

struct Writer<'a> {
    out: &'a mut [u8],
    position: usize,
}
impl Writer<'_> {
    fn zero(&mut self, bytes: usize) -> Result<&mut [u8], Error> {
        let end = self.position.checked_add(bytes).ok_or(Error::Capacity)?;
        let part = self.out.get_mut(self.position..end).ok_or(Error::Capacity)?;
        part.fill(0);
        self.position = end;
        Ok(part)
    }
}
