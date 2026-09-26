//! IVRS/IVHD/IVMD, 48882-3.11 pp290-309 (physical pages).
//! IVMD p308 and the explicit segment row on p309 define +8..9 as segment;
//! the leftover generic reserved +8..15 row on p309 conflicts with those.
//! We retain segment and require only +10..15 zero for types 21h/22h.

use super::acpi::Bytes;
use super::*;

pub fn parse_ivrs(bytes: &[u8]) -> Result<Ivrs, ParseError> {
    let mut out = Ivrs::EMPTY;
    parse_ivrs_into(bytes, &mut out)?;
    Ok(out)
}

/// No input references survive parsing. Output is empty on any failure.
pub fn parse_ivrs_into(bytes: &[u8], out: &mut Ivrs) -> Result<(), ParseError> {
    out.clear();
    let result = parse(bytes, out);
    if result.is_err() {
        out.clear();
    }
    result
}

fn parse(bytes: &[u8], out: &mut Ivrs) -> Result<(), ParseError> {
    out.header = validate_sdt(bytes, *b"IVRS")?;
    let r = Bytes::new(bytes, *b"IVRS", 0);
    if !matches!(out.header.revision, 1 | 2) {
        return Err(r.fail(8, ParseErrorKind::UnsupportedRevision));
    }
    out.iv_info = r.u32(36)?;
    if out.iv_info & 0xff80_001c != 0 {
        return Err(r.fail(36, ParseErrorKind::ReservedField));
    }
    r.zero(40, 8)?;
    let mut offset = 48;
    let mut preceding_form = None;
    while offset < bytes.len() {
        r.part(offset, 4)?;
        let kind = r.u8(offset)?;
        let length = r.u16(offset + 2)? as usize;
        if length < 4 {
            return Err(r.fail(offset + 2, ParseErrorKind::InvalidLength));
        }
        let block = Bytes::new(r.part(offset, length)?, *b"IVRS", offset);
        match kind {
            0x10 | 0x11 | 0x40 => {
                preceding_form = Some(parse_ivhd(&block, offset, out)?);
            }
            0x20..=0x22 => {
                let form =
                    preceding_form.ok_or_else(|| block.fail(0, ParseErrorKind::OrphanIvmd))?;
                parse_ivmd(&block, offset, form, out)?;
            }
            _ => return Err(block.fail(0, ParseErrorKind::UnsupportedBlock(kind))),
        }
        // length was checked against the enclosing slice and is at least 4.
        offset += length;
    }
    if out.units().is_empty() {
        return Err(r.fail(48, ParseErrorKind::MissingIommu));
    }
    check_alias_sources(out)?;
    check_auxiliary_sources(out)?;
    compare_forms(out)?;
    Ok(())
}

fn parse_ivhd(r: &Bytes<'_>, offset: usize, out: &mut Ivrs) -> Result<u16, ParseError> {
    let kind = r.u8(0)?;
    let header_len = if kind == 0x10 { 24 } else { 40 };
    r.part(0, header_len)?;
    if kind == 0x40 && out.header.revision != 2 {
        return Err(r.fail(0, ParseErrorKind::UnsupportedBlock(kind)));
    }
    if kind != 0x10 && out.iv_info & 1 == 0 {
        return Err(r.fail(0, ParseErrorKind::UnsupportedBlock(kind)));
    }
    let flags = r.u8(1)?;
    let device_id = r.u16(4)?;
    let capability_offset = r.u16(6)?;
    let mmio_base = r.u64(8)?;
    let segment = r.u16(16)?;
    let iommu_info = r.u16(18)?;
    let feature_info = r.u32(20)?;
    // Conventional PCI capability, including its 20-byte minimum block.
    if !(0x40..=0xec).contains(&capability_offset) || capability_offset & 3 != 0 {
        return Err(r.fail(6, ParseErrorKind::InvalidCapabilityOffset));
    }
    // Minimum aperture is 16 KiB; actual optional PCSup aperture needs hardware
    // corroboration (48882-3.11 p207). Neither this check nor IVRS owns the MMIO.
    if mmio_base & 0x3fff != 0 {
        return Err(r.fail(8, ParseErrorKind::MisalignedAddress));
    }
    mmio_base.checked_add(0x3fff).ok_or_else(|| r.fail(8, ParseErrorKind::AddressOverflow))?;
    let mask = match kind {
        0x10 => 1,
        0x11 => 2,
        _ => 4,
    };
    let mut unit_index = None;
    for index in 0..out.units.len {
        let unit = out.units.data[index];
        if unit.segment == segment
            && unit.device_id == device_id
            && unit.capability_offset == capability_offset
        {
            if unit.mmio_base != mmio_base {
                return Err(r.fail(8, ParseErrorKind::ConflictingUnitIdentity));
            }
            if unit.form_mask & mask != 0 {
                return Err(r.fail(0, ParseErrorKind::DuplicateForm));
            }
            unit_index = Some(index);
        } else if unit.mmio_base == mmio_base {
            return Err(r.fail(8, ParseErrorKind::ConflictingMmioAddress));
        }
    }
    let unit_index = match unit_index {
        Some(index) => {
            out.units.data[index].form_mask |= mask;
            index
        }
        None => {
            let index = out.units.len;
            out.units.push(
                IommuUnit {
                    segment,
                    device_id,
                    capability_offset,
                    mmio_base,
                    first_form_offset: offset as u32,
                    form_mask: mask,
                },
                *b"IVRS",
                offset,
                Limit::Units,
            )?;
            index
        }
    };
    let form_index = out.forms.len as u16;
    let form = IvhdForm {
        unit_index: unit_index as u16,
        offset: offset as u32,
        kind,
        flags,
        iommu_info,
        feature_info,
        efr: if kind == 0x10 { None } else { Some(r.u64(24)?) },
        efr2: if kind == 0x10 { None } else { Some(r.u64(32)?) },
    };
    out.forms.push(form, *b"IVRS", offset, Limit::Forms)?;
    if iommu_info & 0xe0e0 != 0
        || (kind != 0x10 && (flags & 0xc0 != 0 || feature_info & 0xf000_1ffe != 0))
        || (kind == 0x10 && out.iv_info & 1 == 0 && feature_info != 0)
    {
        // These form fields are labelled reserved, unlike explicit MBZ fields.
        // Preserve the raw fields and surface the limitation instead of guessing.
        out.diagnose(DiagnosticKind::ReservedIvhdBits, offset as u32, None)?;
    }
    let before = out.scopes.len + out.special.len + out.acpi.len;
    parse_entries(r, offset, header_len, form_index, out)?;
    if before == out.scopes.len + out.special.len + out.acpi.len {
        return Err(r.fail(header_len, ParseErrorKind::MissingDeviceEntries));
    }
    Ok(form_index)
}

fn parse_entries(
    r: &Bytes<'_>,
    block_offset: usize,
    mut cursor: usize,
    form_index: u16,
    out: &mut Ivrs,
) -> Result<(), ParseError> {
    let mut saw_acpi = false;
    while cursor < r.data.len() {
        let kind = r.u8(cursor)?;
        let absolute = block_offset + cursor;
        if kind == 0xf0 {
            if out.forms.data[form_index as usize].kind != 0x40 {
                return Err(r.fail(cursor, ParseErrorKind::UnsupportedDeviceEntry(kind)));
            }
            saw_acpi = true;
            let length = parse_acpi(r, cursor, absolute, form_index, out)?;
            cursor += length;
            continue;
        }
        if saw_acpi {
            return Err(r.fail(cursor, ParseErrorKind::FixedEntryAfterAcpi));
        }
        let length = match kind {
            1..=4 => 4,
            0x42 | 0x43 | 0x46 | 0x47 | 0x48 => 8,
            _ => return Err(r.fail(cursor, ParseErrorKind::UnsupportedDeviceEntry(kind))),
        };
        r.part(cursor, length)?;
        if kind == 4 {
            return Err(r.fail(cursor, ParseErrorKind::UnexpectedRangeEnd));
        }
        if kind == 0x48 {
            parse_special(r, cursor, absolute, form_index, out)?;
            cursor += length;
            continue;
        }
        let first = if kind == 1 { 0 } else { r.u16(cursor + 1)? };
        let dte_settings = r.u8(cursor + 3)?;
        let alias_source = if kind == 0x42 || kind == 0x43 {
            r.zero(cursor + 4, 1)?;
            r.zero(cursor + 7, 1)?;
            Some(r.u16(cursor + 5)?)
        } else {
            None
        };
        let extended_settings = if kind == 0x46 || kind == 0x47 {
            let bits = r.u32(cursor + 4)?;
            if bits & 0x7fff_fff8 != 0 {
                return Err(r.fail(cursor + 4, ParseErrorKind::ReservedField));
            }
            Some(bits)
        } else {
            None
        };
        let is_range = matches!(kind, 3 | 0x43 | 0x47);
        let last = if is_range {
            let end = cursor + length;
            if r.data.len().saturating_sub(end) < 4 || r.u8(end)? != 4 {
                return Err(r.fail(end, ParseErrorKind::MissingRangeEnd));
            }
            r.zero(end + 3, 1)?;
            let last = r.u16(end + 1)?;
            if last < first {
                return Err(r.fail(end + 1, ParseErrorKind::InvalidRange));
            }
            last
        } else if kind == 1 {
            u16::MAX
        } else {
            first
        };
        let scope = RequesterScope {
            form_index,
            offset: absolute as u32,
            range: RequesterRange { first, last },
            dte_settings,
            alias_source,
            extended_settings,
            kind: match kind {
                1 => RequesterKind::All,
                2 => RequesterKind::Select,
                3 => RequesterKind::Range,
                0x42 => RequesterKind::AliasSelect,
                0x43 => RequesterKind::AliasRange,
                0x46 => RequesterKind::ExtendedSelect,
                _ => RequesterKind::ExtendedRange,
            },
        };
        add_scope(scope, out)?;
        cursor += length + if is_range { 4 } else { 0 };
    }
    Ok(())
}

fn add_scope(scope: RequesterScope, out: &mut Ivrs) -> Result<(), ParseError> {
    let unit_index = out.forms.data[scope.form_index as usize].unit_index;
    let unit = out.units.data[unit_index as usize];
    for index in 0..out.scopes.len {
        let prior = out.scopes.data[index];
        let prior_unit_index = out.forms.data[prior.form_index as usize].unit_index;
        if prior.form_index == scope.form_index {
            if scope.range.overlaps(prior.range) {
                out.diagnose(DiagnosticKind::RequesterOverlap, scope.offset, Some(prior.offset))?;
            }
            // Aliases with disjoint actual DeviceIDs still use the same DTE
            // when their transaction sources coincide (48882-3.11 p305).
            // Compare only fields present in both declarations; absence of an
            // extended setting is not an implicit contradictory setting.
            let settings_conflict = scope.dte_settings != prior.dte_settings
                || matches!((scope.extended_settings, prior.extended_settings),
                    (Some(current), Some(previous)) if current != previous);
            if settings_conflict && scope.source_range().overlaps(prior.source_range()) {
                out.diagnose(
                    DiagnosticKind::SourceSettingsConflict,
                    scope.offset,
                    Some(prior.offset),
                )?;
            }
        } else if unit_index != prior_unit_index
            && unit.segment == out.units.data[prior_unit_index as usize].segment
            && (scope.range.overlaps(prior.range)
                || scope.source_range().overlaps(prior.source_range()))
        {
            out.diagnose(DiagnosticKind::RequesterAcrossUnits, scope.offset, Some(prior.offset))?;
        }
    }
    out.scopes.push(scope, *b"IVRS", scope.offset as usize, Limit::RequesterScopes)
}

fn parse_special(
    r: &Bytes<'_>,
    cursor: usize,
    absolute: usize,
    form_index: u16,
    out: &mut Ivrs,
) -> Result<(), ParseError> {
    r.zero(cursor + 1, 2)?;
    let device = SpecialDevice {
        form_index,
        offset: absolute as u32,
        source_id: r.u16(cursor + 5)?,
        dte_settings: r.u8(cursor + 3)?,
        handle: r.u8(cursor + 4)?,
        variety: match r.u8(cursor + 7)? {
            1 => SpecialVariety::IoApic,
            2 => SpecialVariety::Hpet,
            _ => return Err(r.fail(cursor + 7, ParseErrorKind::ReservedField)),
        },
    };
    for index in 0..out.special.len {
        let prior = out.special.data[index];
        if prior.form_index == form_index
            && prior.handle == device.handle
            && prior.variety == device.variety
        {
            out.diagnose(
                DiagnosticKind::DuplicateSpecialIdentity,
                device.offset,
                Some(prior.offset),
            )?;
        }
    }
    out.special.push(device, *b"IVRS", absolute, Limit::SpecialDevices)
}

fn parse_acpi(
    r: &Bytes<'_>,
    cursor: usize,
    absolute: usize,
    form_index: u16,
    out: &mut Ivrs,
) -> Result<usize, ParseError> {
    r.part(cursor, 22)?;
    let length = r.u8(cursor + 21)? as usize;
    let uid = r.part(cursor + 22, length)?;
    if length > MAX_UID_BYTES {
        return Err(r.fail(cursor + 21, ParseErrorKind::LimitExceeded(Limit::UidBytes)));
    }
    let uid_format = match r.u8(cursor + 20)? {
        0 if length == 0 => UidFormat::Absent,
        // Preserve integer encoding, without silently truncating to u32/u64.
        1 if (1..=8).contains(&length) => UidFormat::Integer,
        2 if length != 0 && uid.iter().all(|byte| (0x20..=0x7e).contains(byte)) => {
            UidFormat::String
        }
        0..=2 => return Err(r.fail(cursor + 20, ParseErrorKind::InvalidUid)),
        kind => return Err(r.fail(cursor + 20, ParseErrorKind::UnsupportedUidFormat(kind))),
    };
    if out.iv_info & 2 != 0 && uid_format != UidFormat::String {
        return Err(r.fail(cursor + 20, ParseErrorKind::InvalidUid));
    }
    let hardware_id = r.array(cursor + 4)?;
    let compatible_id = r.array(cursor + 12)?;
    if !valid_hardware_id(hardware_id, false) || !valid_hardware_id(compatible_id, true) {
        return Err(r.fail(cursor + 4, ParseErrorKind::InvalidHardwareId));
    }
    let mut device = AcpiDevice {
        form_index,
        offset: absolute as u32,
        source_id: r.u16(cursor + 1)?,
        dte_settings: r.u8(cursor + 3)?,
        hardware_id,
        compatible_id,
        uid_format,
        uid_length: length as u8,
        ..AcpiDevice::EMPTY
    };
    device.uid_bytes[..length].copy_from_slice(uid);
    let unit_index = out.forms.data[form_index as usize].unit_index;
    let segment = out.units.data[unit_index as usize].segment;
    for index in 0..out.acpi.len {
        let prior = out.acpi.data[index];
        if same_acpi_identity(&prior, &device) {
            out.diagnose(DiagnosticKind::DuplicateAcpiIdentity, device.offset, Some(prior.offset))?;
        }
        let prior_unit = out.forms.data[prior.form_index as usize].unit_index;
        if prior.source_id == device.source_id
            && segment == out.units.data[prior_unit as usize].segment
        {
            out.diagnose(
                if unit_index == prior_unit {
                    DiagnosticKind::SharedAcpiSource
                } else {
                    DiagnosticKind::RequesterAcrossUnits
                },
                device.offset,
                Some(prior.offset),
            )?;
            // p307 Table110/note5 permits multiple ACPI instances on one
            // source, but their Table106 DTE settings still describe the same
            // hardware entry. Preserve disagreements for explicit resolution.
            if unit_index == prior_unit && device.dte_settings != prior.dte_settings {
                out.diagnose(
                    DiagnosticKind::SourceSettingsConflict,
                    device.offset,
                    Some(prior.offset),
                )?;
            }
        }
    }
    for index in 0..out.scopes.len {
        let scope = out.scopes.data[index];
        if scope.form_index == form_index
            && (scope.range.contains(device.source_id)
                || scope.alias_source == Some(device.source_id))
        {
            out.diagnose(DiagnosticKind::AcpiSourceAlsoNumeric, device.offset, Some(scope.offset))?;
        }
    }
    out.acpi.push(device, *b"IVRS", absolute, Limit::AcpiDevices)?;
    Ok(22 + length)
}

fn valid_hardware_id(id: [u8; 8], optional: bool) -> bool {
    if id == [0; 8] {
        return optional;
    }
    if id[4..] == [0; 4] {
        return true;
    } // Encoded integer HID/CID.
    let length = if id[7] == 0 { 7 } else { 8 };
    let vendor_length = length - 4;
    // ACPI_Spec_6.6 p435: NNNN#### allows digits in the four-character
    // ACPI vendor ID (e.g. 80860003), while PNP AAA#### requires letters.
    id[..vendor_length]
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || (vendor_length == 4 && byte.is_ascii_digit()))
        && id[vendor_length..length].iter().all(u8::is_ascii_hexdigit)
}

fn same_acpi_identity(a: &AcpiDevice, b: &AcpiDevice) -> bool {
    let common_id = a.hardware_id == b.hardware_id
        || (a.compatible_id != [0; 8]
            && (a.compatible_id == b.hardware_id || a.compatible_id == b.compatible_id))
        || (b.compatible_id != [0; 8] && b.compatible_id == a.hardware_id);
    let same_uid = a.uid_format == b.uid_format
        && match a.uid_format {
            UidFormat::Integer => {
                // Compare the little-endian numeric identity while retaining the
                // original length/bytes in each record. No truncation is permitted.
                let mut left = [0; 8];
                let mut right = [0; 8];
                left[..a.uid().len()].copy_from_slice(a.uid());
                right[..b.uid().len()].copy_from_slice(b.uid());
                left == right
            }
            _ => a.uid() == b.uid(),
        };
    common_id && same_uid
}

fn parse_ivmd(
    r: &Bytes<'_>,
    offset: usize,
    preceding_form_index: u16,
    out: &mut Ivrs,
) -> Result<(), ParseError> {
    if r.data.len() != 32 {
        return Err(r.fail(2, ParseErrorKind::InvalidLength));
    }
    let kind = r.u8(0)?;
    let flags = r.u8(1)?;
    if flags & 0xf0 != 0 {
        return Err(r.fail(1, ParseErrorKind::ReservedField));
    }
    let semantics = if flags & 8 != 0 {
        MemorySemantics::Exclusion
    } else {
        let read = flags & 2 != 0;
        let write = flags & 4 != 0;
        let unity = flags & 1 != 0;
        if !read && !write && unity {
            return Err(r.fail(1, ParseErrorKind::InvalidIvmdFlags));
        }
        MemorySemantics::Permissions { read, write, unity }
    };
    let segment = r.u16(8)?;
    r.zero(10, 6)?;
    let scope = if kind == 0x20 {
        r.zero(4, 6)?;
        MemoryScope::AllDevices
    } else {
        let first = r.u16(4)?;
        let last = if kind == 0x21 {
            r.zero(6, 2)?;
            first
        } else {
            r.u16(6)?
        };
        if first > last {
            return Err(r.fail(4, ParseErrorKind::InvalidRange));
        }
        let unit = out.forms.data[preceding_form_index as usize].unit_index;
        if segment != out.units.data[unit as usize].segment {
            return Err(r.fail(8, ParseErrorKind::IvmdSegmentMismatch));
        }
        MemoryScope::Devices { segment, range: RequesterRange { first, last } }
    };
    let start = r.u64(16)?;
    let length = r.u64(24)?;
    if length == 0 {
        return Err(r.fail(24, ParseErrorKind::InvalidLength));
    }
    let last =
        start.checked_add(length - 1).ok_or_else(|| r.fail(24, ParseErrorKind::AddressOverflow))?;
    for index in 0..out.regions.len {
        let prior = out.regions.data[index];
        if prior.start <= last && start <= prior.last && memory_scopes_overlap(scope, prior.scope) {
            out.diagnose(
                DiagnosticKind::OverlappingMemoryRegions,
                offset as u32,
                Some(prior.offset),
            )?;
        }
    }
    out.regions.push(
        MemoryRegion {
            offset: offset as u32,
            preceding_form_index,
            scope,
            raw_flags: flags,
            semantics,
            start,
            last,
            length,
        },
        *b"IVRS",
        offset,
        Limit::MemoryRegions,
    )
}

fn memory_scopes_overlap(a: MemoryScope, b: MemoryScope) -> bool {
    match (a, b) {
        (MemoryScope::AllDevices, _) | (_, MemoryScope::AllDevices) => true,
        (
            MemoryScope::Devices { segment: a, range: ar },
            MemoryScope::Devices { segment: b, range: br },
        ) => a == b && ar.overlaps(br),
    }
}

fn check_alias_sources(out: &mut Ivrs) -> Result<(), ParseError> {
    for index in 0..out.scopes.len {
        let scope = out.scopes.data[index];
        if let Some(source) = scope.alias_source {
            if !out.scopes.as_slice().iter().any(|other| {
                other.form_index == scope.form_index
                    && other.alias_source.is_none()
                    && other.range.contains(source)
            }) {
                out.diagnose(DiagnosticKind::AliasSourceUndeclared, scope.offset, None)?;
            }
        }
    }
    Ok(())
}

fn different_unit_same_segment(out: &Ivrs, a: u16, b: u16) -> bool {
    let a = out.forms.data[a as usize].unit_index;
    let b = out.forms.data[b as usize].unit_index;
    a != b && out.units.data[a as usize].segment == out.units.data[b as usize].segment
}

fn same_unit(out: &Ivrs, a: u16, b: u16) -> bool {
    out.forms.data[a as usize].unit_index == out.forms.data[b as usize].unit_index
}

/// Sources in later IVHDs must be checked as well as declarations already seen.
/// ACPI and special devices can share one source within a unit; assigning that
/// source to two units in the same segment needs resolution. A special device's
/// Table 106 settings must also agree with other declarations of its source;
/// absent extended settings supply no additional constraint (pp304-305).
fn check_auxiliary_sources(out: &mut Ivrs) -> Result<(), ParseError> {
    for index in 0..out.acpi.len {
        let device = out.acpi.data[index];
        for scope_index in 0..out.scopes.len {
            let scope = out.scopes.data[scope_index];
            if different_unit_same_segment(out, device.form_index, scope.form_index)
                && scope.source_range().contains(device.source_id)
            {
                out.diagnose(
                    DiagnosticKind::RequesterAcrossUnits,
                    device.offset,
                    Some(scope.offset),
                )?;
            }
        }
    }
    for index in 0..out.special.len {
        let device = out.special.data[index];
        for scope_index in 0..out.scopes.len {
            let scope = out.scopes.data[scope_index];
            if !scope.source_range().contains(device.source_id) {
                continue;
            }
            if same_unit(out, device.form_index, scope.form_index)
                && device.dte_settings != scope.dte_settings
            {
                out.diagnose(
                    DiagnosticKind::SourceSettingsConflict,
                    device.offset,
                    Some(scope.offset),
                )?;
            } else if different_unit_same_segment(out, device.form_index, scope.form_index) {
                out.diagnose(
                    DiagnosticKind::RequesterAcrossUnits,
                    device.offset,
                    Some(scope.offset),
                )?;
            }
        }
        for acpi_index in 0..out.acpi.len {
            let acpi = out.acpi.data[acpi_index];
            if device.source_id != acpi.source_id {
                continue;
            }
            if same_unit(out, device.form_index, acpi.form_index)
                && device.dte_settings != acpi.dte_settings
            {
                out.diagnose(
                    DiagnosticKind::SourceSettingsConflict,
                    device.offset,
                    Some(acpi.offset),
                )?;
            } else if different_unit_same_segment(out, device.form_index, acpi.form_index) {
                out.diagnose(
                    DiagnosticKind::RequesterAcrossUnits,
                    device.offset,
                    Some(acpi.offset),
                )?;
            }
        }
        for prior_index in 0..index {
            let prior = out.special.data[prior_index];
            if same_unit(out, device.form_index, prior.form_index) {
                if device.source_id == prior.source_id && device.dte_settings != prior.dte_settings
                {
                    out.diagnose(
                        DiagnosticKind::SourceSettingsConflict,
                        device.offset,
                        Some(prior.offset),
                    )?;
                }
                continue;
            }
            if device.variety == prior.variety && device.handle == prior.handle {
                out.diagnose(
                    DiagnosticKind::DuplicateSpecialIdentity,
                    device.offset,
                    Some(prior.offset),
                )?;
            }
            if different_unit_same_segment(out, device.form_index, prior.form_index)
                && device.source_id == prior.source_id
            {
                out.diagnose(
                    DiagnosticKind::RequesterAcrossUnits,
                    device.offset,
                    Some(prior.offset),
                )?;
            }
        }
    }
    Ok(())
}

fn compare_forms(out: &mut Ivrs) -> Result<(), ParseError> {
    for index in 0..out.forms.len {
        let current = out.forms.data[index];
        for prior_index in 0..index {
            let prior = out.forms.data[prior_index];
            if current.unit_index != prior.unit_index {
                continue;
            }
            // Legacy feature_info has a different encoding and no EFR image.
            // Compare common fields across versions; retain all raw fields.
            let both_extended = current.kind != 0x10 && prior.kind != 0x10;
            if current.flags & 0x3f != prior.flags & 0x3f
                || current.iommu_info != prior.iommu_info
                || (both_extended
                    && (current.feature_info != prior.feature_info
                        || current.efr != prior.efr
                        || current.efr2 != prior.efr2))
            {
                out.diagnose(
                    DiagnosticKind::FormPropertiesDiffer,
                    current.offset,
                    Some(prior.offset),
                )?;
            }
            let current_scopes =
                out.scopes.as_slice().iter().filter(|s| s.form_index as usize == index);
            let prior_scopes =
                out.scopes.as_slice().iter().filter(|s| s.form_index as usize == prior_index);
            if current_scopes.clone().count() != prior_scopes.clone().count()
                || current_scopes
                    .into_iter()
                    .any(|s| !prior_scopes.clone().any(|p| s.same_declaration(*p)))
            {
                out.diagnose(
                    DiagnosticKind::FormRequesterScopesDiffer,
                    current.offset,
                    Some(prior.offset),
                )?;
            }
            let current_special =
                out.special.as_slice().iter().filter(|s| s.form_index as usize == index);
            let prior_special =
                out.special.as_slice().iter().filter(|s| s.form_index as usize == prior_index);
            if current_special.clone().count() != prior_special.clone().count()
                || current_special
                    .into_iter()
                    .any(|s| !prior_special.clone().any(|p| s.same_declaration(*p)))
            {
                out.diagnose(
                    DiagnosticKind::FormSpecialDevicesDiffer,
                    current.offset,
                    Some(prior.offset),
                )?;
            }
        }
    }
    Ok(())
}
