use super::*;

#[test]
fn sdt_table_byte_limit_is_exact() {
    let accepted = sdt(*b"TEST", 1, &vec![0; MAX_TABLE_BYTES - SDT_HEADER_LEN]);
    assert_eq!(validate_sdt(&accepted, *b"TEST").unwrap().length as usize, MAX_TABLE_BYTES);
    let too_large = sdt(*b"TEST", 1, &vec![0; MAX_TABLE_BYTES - SDT_HEADER_LEN + 1]);
    assert_eq!(
        validate_sdt(&too_large, *b"TEST").unwrap_err().kind,
        ParseErrorKind::LimitExceeded(Limit::TableBytes)
    );
    let mut advertised = sdt(*b"TEST", 1, &[]);
    put32(&mut advertised, 4, u32::MAX);
    assert_eq!(
        validate_sdt(&advertised, *b"TEST").unwrap_err().kind,
        ParseErrorKind::LimitExceeded(Limit::TableBytes)
    );
}

#[test]
fn every_unit_can_have_all_three_forms_at_capacity() {
    let mut blocks = Vec::new();
    for segment in 0..MAX_UNITS as u16 {
        for kind in [0x10, 0x11, 0x40] {
            blocks.push(ivhd(kind, segment, &entry(2, 1, 0)));
        }
    }
    let out = parse_ivrs(&ivrs(&blocks)).unwrap();
    assert_eq!(out.units().len(), MAX_UNITS);
    assert_eq!(out.forms().len(), MAX_FORMS);
    assert!(!out.has_unresolved_diagnostics());
    // A fourth known form is a duplicate before it could overrun form storage.
    blocks.push(ivhd(0x10, 0, &entry(2, 1, 0)));
    reject_ivrs(&ivrs(&blocks), ParseErrorKind::DuplicateForm);
    blocks.pop();
    blocks.push(ivhd(0x10, MAX_UNITS as u16, &entry(2, 1, 0)));
    reject_ivrs(&ivrs(&blocks), ParseErrorKind::LimitExceeded(Limit::Units));
}

#[test]
fn requester_scope_capacity_has_no_silent_truncation() {
    let mut entries = Vec::new();
    for device in 0..MAX_REQUESTER_SCOPES as u16 {
        entries.extend(entry(2, device, 0));
    }
    let out = parse_ivrs(&ivrs(&[ivhd(0x10, 0, &entries)])).unwrap();
    assert_eq!(out.requester_scopes().len(), MAX_REQUESTER_SCOPES);
    entries.extend(entry(2, MAX_REQUESTER_SCOPES as u16, 0));
    reject_ivrs(
        &ivrs(&[ivhd(0x10, 0, &entries)]),
        ParseErrorKind::LimitExceeded(Limit::RequesterScopes),
    );
}

#[test]
fn special_device_capacity_has_no_silent_truncation() {
    let mut entries = Vec::new();
    for handle in 0..MAX_SPECIAL_DEVICES as u8 {
        entries.extend([0x48, 0, 0, 0, handle, handle, 0, 1]);
    }
    let out = parse_ivrs(&ivrs(&[ivhd(0x10, 0, &entries)])).unwrap();
    assert_eq!(out.special_devices().len(), MAX_SPECIAL_DEVICES);
    entries.extend([0x48, 0, 0, 0, MAX_SPECIAL_DEVICES as u8, 0, 0, 1]);
    reject_ivrs(
        &ivrs(&[ivhd(0x10, 0, &entries)]),
        ParseErrorKind::LimitExceeded(Limit::SpecialDevices),
    );
}

#[test]
fn acpi_device_and_uid_capacities_are_independently_enforced() {
    let mut entries = Vec::new();
    for index in 0..MAX_ACPI_DEVICES as u16 {
        let uid = [b'A' + (index / 26) as u8, b'A' + (index % 26) as u8];
        entries.extend(acpi_entry(index, 2, &uid));
    }
    let out = parse_ivrs(&ivrs(&[ivhd(0x40, 0, &entries)])).unwrap();
    assert_eq!(out.acpi_devices().len(), MAX_ACPI_DEVICES);
    entries.extend(acpi_entry(500, 2, b"ZZ"));
    reject_ivrs(
        &ivrs(&[ivhd(0x40, 0, &entries)]),
        ParseErrorKind::LimitExceeded(Limit::AcpiDevices),
    );
    let accepted = acpi_entry(1, 2, &[b'A'; MAX_UID_BYTES]);
    assert_eq!(
        parse_ivrs(&ivrs(&[ivhd(0x40, 0, &accepted)])).unwrap().acpi_devices()[0].uid().len(),
        MAX_UID_BYTES
    );
    let rejected = acpi_entry(1, 2, &[b'A'; MAX_UID_BYTES + 1]);
    reject_ivrs(&ivrs(&[ivhd(0x40, 0, &rejected)]), ParseErrorKind::LimitExceeded(Limit::UidBytes));
}

#[test]
fn ivmd_capacity_has_no_silent_truncation() {
    let mut blocks = vec![ivhd(0x10, 0, &entry(1, 0, 0))];
    for index in 0..MAX_MEMORY_REGIONS {
        blocks.push(ivmd(0x20, 8, 0, 0, 0, index as u64 * 4096, 4096));
    }
    assert_eq!(parse_ivrs(&ivrs(&blocks)).unwrap().memory_regions().len(), MAX_MEMORY_REGIONS);
    blocks.push(ivmd(0x20, 8, 0, 0, 0, MAX_MEMORY_REGIONS as u64 * 4096, 4096));
    reject_ivrs(&ivrs(&blocks), ParseErrorKind::LimitExceeded(Limit::MemoryRegions));
}

#[test]
fn ecam_allocation_capacity_has_no_silent_truncation() {
    let mut allocations = Vec::new();
    for segment in 0..MAX_MCFG_ALLOCATIONS as u16 {
        allocations.push((0x8000_0000 + segment as u64 * 0x100_0000, segment, 0, 0));
    }
    assert_eq!(parse_mcfg(&mcfg(&allocations)).unwrap().allocations().len(), MAX_MCFG_ALLOCATIONS);
    allocations.push((0xc000_0000, MAX_MCFG_ALLOCATIONS as u16, 0, 0));
    assert_eq!(
        parse_mcfg(&mcfg(&allocations)).unwrap_err().kind,
        ParseErrorKind::LimitExceeded(Limit::McfgAllocations)
    );
}

#[test]
fn diagnostic_capacity_rejects_rather_than_hiding_additional_ambiguity() {
    let mut entries = Vec::new();
    for _ in 0..16 {
        entries.extend(entry(2, 0, 0));
    } // 120 pairwise overlaps.
    for id in 1..=8 {
        for _ in 0..2 {
            entries.extend(entry(2, id, 0));
        }
    }
    let out = parse_ivrs(&ivrs(&[ivhd(0x10, 0, &entries)])).unwrap();
    assert_eq!(out.diagnostics().len(), MAX_DIAGNOSTICS);
    entries.extend(entry(2, 8, 0));
    reject_ivrs(
        &ivrs(&[ivhd(0x10, 0, &entries)]),
        ParseErrorKind::LimitExceeded(Limit::Diagnostics),
    );
}
