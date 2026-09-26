use super::*;

#[test]
fn every_fixture_prefix_is_rejected_without_out_of_bounds_reads() {
    for end in 0..IVRS.len() {
        assert!(parse_ivrs(&IVRS[..end]).is_err(), "IVRS prefix {end}");
    }
    for end in 0..MCFG.len() {
        assert!(parse_mcfg(&MCFG[..end]).is_err(), "MCFG prefix {end}");
    }
}

#[test]
fn table_length_signature_checksum_and_revision_are_checked() {
    let mut bytes = IVRS.to_vec();
    bytes[0] = b'X';
    reject_ivrs(&bytes, ParseErrorKind::BadSignature);
    let mut bytes = IVRS.to_vec();
    bytes[9] ^= 1;
    reject_ivrs(&bytes, ParseErrorKind::BadChecksum);
    let mut bytes = IVRS.to_vec();
    bytes[8] = 3;
    checksum(&mut bytes);
    reject_ivrs(&bytes, ParseErrorKind::UnsupportedRevision);
    let mut bytes = IVRS.to_vec();
    put32(&mut bytes, 4, 35);
    reject_ivrs(&bytes, ParseErrorKind::InvalidLength);
    let mut bytes = IVRS.to_vec();
    bytes.push(0);
    reject_ivrs(&bytes, ParseErrorKind::TrailingBytes);
    let mut bytes = MCFG.to_vec();
    bytes[8] = 2;
    checksum(&mut bytes);
    assert_eq!(parse_mcfg(&bytes).unwrap_err().kind, ParseErrorKind::UnsupportedRevision);
}

#[test]
fn ivrs_reserved_header_bits_and_required_iommu_are_checked() {
    let block = ivhd(0x10, 0, &entry(2, 1, 0));
    for offset in [36, 40, 47] {
        let mut bytes = ivrs(&[block.clone()]);
        bytes[offset] |= if offset == 36 { 4 } else { 1 };
        checksum(&mut bytes);
        reject_ivrs(&bytes, ParseErrorKind::ReservedField);
    }
    reject_ivrs(&ivrs(&[]), ParseErrorKind::MissingIommu);
}

#[test]
fn invalid_block_lengths_and_unknown_blocks_never_skip_silently() {
    for length in [0, 1, 2, 3] {
        let mut block = ivhd(0x10, 0, &entry(2, 1, 0));
        put16(&mut block, 2, length);
        reject_ivrs(&ivrs(&[block]), ParseErrorKind::InvalidLength);
    }
    for length in [4, 20, 23] {
        let mut block = vec![0; length];
        block[0] = 0x10;
        put16(&mut block, 2, length as u16);
        reject_ivrs(&ivrs(&[block]), ParseErrorKind::Truncated);
    }
    let mut block = ivhd(0x11, 0, &entry(2, 1, 0));
    put16(&mut block, 2, 200);
    reject_ivrs(&ivrs(&[block]), ParseErrorKind::Truncated);
    reject_ivrs(&ivrs(&[vec![0x99, 0, 4, 0]]), ParseErrorKind::UnsupportedBlock(0x99));
    reject_ivrs(&ivrs(&[vec![0x10]]), ParseErrorKind::Truncated);
    reject_ivrs(&ivrs(&[ivhd(0x10, 0, &[])]), ParseErrorKind::MissingDeviceEntries);
}

#[test]
fn version_and_efr_support_constrain_ivhd_forms() {
    let mut bytes = ivrs(&[ivhd(0x40, 0, &entry(2, 1, 0))]);
    bytes[8] = 1;
    checksum(&mut bytes);
    reject_ivrs(&bytes, ParseErrorKind::UnsupportedBlock(0x40));
    for kind in [0x11, 0x40] {
        let mut bytes = ivrs(&[ivhd(kind, 0, &entry(2, 1, 0))]);
        bytes[36] &= !1;
        checksum(&mut bytes);
        reject_ivrs(&bytes, ParseErrorKind::UnsupportedBlock(kind));
    }
    let mut bytes = ivrs(&[ivhd(0x10, 0, &entry(2, 1, 0))]);
    bytes[8] = 1;
    bytes[36] = 0;
    checksum(&mut bytes);
    assert!(parse_ivrs(&bytes).is_ok());
}

#[test]
fn duplicate_form_and_conflicting_unit_address_are_rejected_in_either_order() {
    let a = ivhd(0x10, 0, &entry(2, 1, 0));
    reject_ivrs(&ivrs(&[a.clone(), a.clone()]), ParseErrorKind::DuplicateForm);
    let mut b = ivhd(0x11, 0, &entry(2, 1, 0));
    put64(&mut b, 8, 0xf080_0000);
    reject_ivrs(&ivrs(&[a.clone(), b.clone()]), ParseErrorKind::ConflictingUnitIdentity);
    reject_ivrs(&ivrs(&[b, a.clone()]), ParseErrorKind::ConflictingUnitIdentity);
    let mut b = a.clone();
    put16(&mut b, 4, 3);
    reject_ivrs(&ivrs(&[a, b]), ParseErrorKind::ConflictingMmioAddress);
}

#[test]
fn unit_capability_and_minimum_mmio_alignment_are_bounded() {
    for capability in [0, 0x3c, 0x41, 0xf0, 0x100, 0xffff] {
        let mut block = ivhd(0x10, 0, &entry(2, 1, 0));
        put16(&mut block, 6, capability);
        reject_ivrs(&ivrs(&[block]), ParseErrorKind::InvalidCapabilityOffset);
    }
    let mut block = ivhd(0x10, 0, &entry(2, 1, 0));
    put64(&mut block, 8, 0xf000_1000);
    reject_ivrs(&ivrs(&[block]), ParseErrorKind::MisalignedAddress);
}

#[test]
fn range_end_is_immediate_inclusive_and_never_inferred() {
    reject_ivrs(&ivrs(&[ivhd(0x10, 0, &entry(4, 7, 0))]), ParseErrorKind::UnexpectedRangeEnd);
    for start_kind in [3, 0x43, 0x47] {
        let mut start = entry(start_kind, 9, 0);
        if start_kind != 3 {
            start.extend_from_slice(&[0; 4]);
        }
        reject_ivrs(&ivrs(&[ivhd(0x10, 0, &start)]), ParseErrorKind::MissingRangeEnd);
        let mut nonadjacent = start.clone();
        nonadjacent.extend(entry(2, 20, 0));
        nonadjacent.extend(entry(4, 30, 0));
        reject_ivrs(&ivrs(&[ivhd(0x10, 0, &nonadjacent)]), ParseErrorKind::MissingRangeEnd);
        let mut reversed = start.clone();
        reversed.extend(entry(4, 8, 0));
        reject_ivrs(&ivrs(&[ivhd(0x10, 0, &reversed)]), ParseErrorKind::InvalidRange);
        let mut bad_end = start;
        bad_end.extend(entry(4, 9, 1));
        reject_ivrs(&ivrs(&[ivhd(0x10, 0, &bad_end)]), ParseErrorKind::ReservedField);
    }
}

#[test]
fn unknown_and_truncated_device_entries_are_rejected() {
    for kind in [0, 5, 0x40, 0x41, 0x44, 0x49, 0x80, 0xff] {
        reject_ivrs(
            &ivrs(&[ivhd(0x10, 0, &entry(kind, 0, 0))]),
            ParseErrorKind::UnsupportedDeviceEntry(kind),
        );
    }
    for bytes in [vec![2], vec![2, 1, 0], vec![0x42, 1, 0, 0], vec![0xf0, 1, 0, 0]] {
        reject_ivrs(&ivrs(&[ivhd(0x40, 0, &bytes)]), ParseErrorKind::Truncated);
    }
    let mut bytes = alias(0x42, 1, 2);
    bytes[7] = 1;
    reject_ivrs(&ivrs(&[ivhd(0x10, 0, &bytes)]), ParseErrorKind::ReservedField);
    let mut bytes = entry(0x46, 1, 0);
    bytes.extend_from_slice(&8u32.to_le_bytes());
    reject_ivrs(&ivrs(&[ivhd(0x10, 0, &bytes)]), ParseErrorKind::ReservedField);
}

#[test]
fn acpi_entry_format_lengths_order_and_required_string_uid_are_checked() {
    for uid in [
        acpi_entry(1, 0, b"bad"),
        acpi_entry(1, 1, &[]),
        acpi_entry(1, 2, &[]),
        acpi_entry(1, 2, b"abc\0"),
    ] {
        reject_ivrs(&ivrs(&[ivhd(0x40, 0, &uid)]), ParseErrorKind::InvalidUid);
    }
    reject_ivrs(
        &ivrs(&[ivhd(0x40, 0, &acpi_entry(1, 3, b"a"))]),
        ParseErrorKind::UnsupportedUidFormat(3),
    );
    let mut bytes = acpi_entry(1, 2, b"ID00");
    bytes[21] = 6;
    reject_ivrs(&ivrs(&[ivhd(0x40, 0, &bytes)]), ParseErrorKind::Truncated);
    let mut bytes = acpi_entry(1, 2, b"ID00");
    bytes.extend(entry(2, 5, 0));
    reject_ivrs(&ivrs(&[ivhd(0x40, 0, &bytes)]), ParseErrorKind::FixedEntryAfterAcpi);
    reject_ivrs(
        &ivrs(&[ivhd(0x11, 0, &acpi_entry(1, 2, b"ID00"))]),
        ParseErrorKind::UnsupportedDeviceEntry(0xf0),
    );
    for uid in [acpi_entry(1, 0, &[]), acpi_entry(1, 1, &[1, 0, 0, 0])] {
        let mut bytes = ivrs(&[ivhd(0x40, 0, &uid)]);
        bytes[36] |= 2;
        checksum(&mut bytes);
        reject_ivrs(&bytes, ParseErrorKind::InvalidUid);
    }
}

#[test]
fn acpi_numeric_vendor_id_and_integer_uid_are_preserved() {
    let mut bytes = acpi_entry(1, 1, &[0x78, 0x56, 0x34, 0x12]);
    bytes[4..12].copy_from_slice(b"80860003");
    let out = parse_ivrs(&ivrs(&[ivhd(0x40, 0, &bytes)])).unwrap();
    assert_eq!(out.acpi_devices()[0].hardware_id, *b"80860003");
    assert_eq!(out.acpi_devices()[0].uid(), [0x78, 0x56, 0x34, 0x12]);
    bytes[4..12].copy_from_slice(b"PNP0C0C\0");
    assert!(parse_ivrs(&ivrs(&[ivhd(0x40, 0, &bytes)])).is_ok());
    bytes[4..12].copy_from_slice(b"1NP0C0C\0");
    reject_ivrs(&ivrs(&[ivhd(0x40, 0, &bytes)]), ParseErrorKind::InvalidHardwareId);
    let mut bytes = acpi_entry(1, 0, &[]);
    bytes[4..12].fill(0);
    reject_ivrs(&ivrs(&[ivhd(0x40, 0, &bytes)]), ParseErrorKind::InvalidHardwareId);
}

#[test]
fn valid_acpi_source_sharing_is_informational() {
    let a = acpi_entry(0xa5, 2, b"ID00");
    let b = acpi_entry(0xa5, 2, b"ID01");
    for entries in [[a.clone(), b.clone()].concat(), [b, a].concat()] {
        let out = parse_ivrs(&ivrs(&[ivhd(0x40, 0, &entries)])).unwrap();
        assert_eq!(out.acpi_devices().len(), 2);
        assert!(has_diag(&out, DiagnosticKind::SharedAcpiSource));
        assert!(!has_diag(&out, DiagnosticKind::SourceSettingsConflict));
        assert!(!out.has_unresolved_diagnostics());
    }
}

#[test]
fn conflicting_acpi_source_settings_require_resolution_in_either_order() {
    let mut a = acpi_entry(0xa5, 2, b"ID00");
    let mut b = acpi_entry(0xa5, 2, b"ID01");
    // Table 106 assigns one SysMgt field to the shared source's DTE. Do not
    // silently select or combine these two different declarations.
    a[3] = 0x10;
    b[3] = 0x20;
    for declarations in [[a.clone(), b.clone()], [b, a]] {
        let entries = declarations.concat();
        let out = parse_ivrs(&ivrs(&[ivhd(0x40, 0, &entries)])).unwrap();
        let devices = out.acpi_devices();
        assert_eq!(devices.len(), 2);
        for (device, declaration) in devices.iter().zip(&declarations) {
            assert_eq!(device.source_id, 0xa5);
            assert_eq!(device.dte_settings, declaration[3]);
            assert_eq!(device.uid(), &declaration[22..]);
        }
        assert!(has_diag(&out, DiagnosticKind::SharedAcpiSource));
        assert!(!has_diag(&out, DiagnosticKind::DuplicateAcpiIdentity));
        assert!(out.diagnostics().iter().any(|diagnostic| {
            diagnostic.kind == DiagnosticKind::SourceSettingsConflict
                && diagnostic.offset == devices[1].offset
                && diagnostic.related_offset == Some(devices[0].offset)
        }));
        assert!(out.has_unresolved_diagnostics());
    }
}

#[test]
fn equivalent_legacy_extended_forms_do_not_create_spurious_ambiguity() {
    let mut a = ivhd(0x10, 0, &entry(2, 1, 0));
    let mut b = ivhd(0x11, 0, &entry(2, 1, 0));
    a[1] = 0xc0; // Legacy feature flags, not the reserved high bits in 11h.
    put32(&mut a, 20, 0x1234_5678);
    put32(&mut b, 20, 0x2000);
    put64(&mut b, 24, 0xff);
    let out = parse_ivrs(&ivrs(&[a, b])).unwrap();
    assert!(!out.has_unresolved_diagnostics());
}

#[test]
fn ivmd_orphans_bad_flags_reserved_fields_segment_mismatch_and_overflow_reject() {
    let unit = ivhd(0x10, 0, &entry(1, 0, 0));
    reject_ivrs(&ivrs(&[ivmd(0x20, 8, 0, 0, 0, 0x1000, 4096)]), ParseErrorKind::OrphanIvmd);
    let cases = [
        (ivmd(0x20, 1, 0, 0, 0, 0x1000, 1), ParseErrorKind::InvalidIvmdFlags),
        (ivmd(0x20, 0x80, 0, 0, 0, 0x1000, 1), ParseErrorKind::ReservedField),
        (ivmd(0x20, 8, 1, 0, 0, 0x1000, 1), ParseErrorKind::ReservedField),
        (ivmd(0x21, 8, 1, 1, 0, 0x1000, 1), ParseErrorKind::ReservedField),
        (ivmd(0x22, 8, 2, 1, 0, 0x1000, 1), ParseErrorKind::InvalidRange),
        (ivmd(0x21, 8, 1, 0, 1, 0x1000, 1), ParseErrorKind::IvmdSegmentMismatch),
        (ivmd(0x20, 8, 0, 0, 0, 0x1000, 0), ParseErrorKind::InvalidLength),
        (ivmd(0x20, 8, 0, 0, 0, u64::MAX, 2), ParseErrorKind::AddressOverflow),
    ];
    for (region, expected) in cases {
        reject_ivrs(&ivrs(&[unit.clone(), region]), expected);
    }
    let mut region = ivmd(0x20, 8, 0, 0, 0, 0x1000, 1);
    region[10] = 1;
    reject_ivrs(&ivrs(&[unit, region]), ParseErrorKind::ReservedField);
}

#[test]
fn overlapping_memory_semantics_are_both_retained() {
    let out = parse_ivrs(&ivrs(&[
        ivhd(0x10, 0, &entry(1, 0, 0)),
        ivmd(0x20, 0, 0, 0, 0, 0x1000, 4096),
        ivmd(0x21, 8, 1, 0, 0, 0x1000, 4096),
    ]))
    .unwrap();
    assert_eq!(out.memory_regions().len(), 2);
    assert!(has_diag(&out, DiagnosticKind::OverlappingMemoryRegions));
}

#[test]
fn mcfg_rejects_bus_conflicts_physical_aliases_overflow_and_partial_records() {
    let cases = [
        (
            mcfg(&[(0x8000_0000, 0, 0, 31), (0xa000_0000, 0, 31, 63)]),
            ParseErrorKind::ConflictingEcamBuses,
        ),
        (
            mcfg(&[(0x8000_0000, 0, 0, 31), (0x8000_0000, 1, 0, 31)]),
            ParseErrorKind::OverlappingEcam,
        ),
        (mcfg(&[(0x8000_0000, 0, 32, 31)]), ParseErrorKind::InvalidRange),
        (mcfg(&[(0x8000_1000, 0, 0, 0)]), ParseErrorKind::MisalignedAddress),
        (mcfg(&[(0xffff_ffff_fff0_0000, 0, 1, 1)]), ParseErrorKind::AddressOverflow),
        (mcfg(&[]), ParseErrorKind::MissingMcfgAllocation),
    ];
    for (bytes, expected) in cases {
        assert_eq!(parse_mcfg(&bytes).unwrap_err().kind, expected);
    }
    let mut bytes = MCFG.to_vec();
    bytes.push(0);
    seal(&mut bytes);
    assert_eq!(parse_mcfg(&bytes).unwrap_err().kind, ParseErrorKind::InvalidLength);
    for offset in [36, 43, 56, 59] {
        let mut bytes = MCFG.to_vec();
        bytes[offset] = 1;
        checksum(&mut bytes);
        assert_eq!(parse_mcfg(&bytes).unwrap_err().kind, ParseErrorKind::ReservedField);
    }
}

#[test]
fn every_single_byte_fixture_mutation_is_bounded_even_with_recomputed_checksum() {
    // Covers nested length/type/UID boundaries after bypassing the outer checksum
    // guard. Some mutations are valid alternate declarations; neither may panic.
    for index in 0..IVRS.len() {
        let mut bytes = IVRS.to_vec();
        bytes[index] ^= 0xff;
        checksum(&mut bytes);
        let _ = parse_ivrs(&bytes);
    }
    for index in 0..MCFG.len() {
        let mut bytes = MCFG.to_vec();
        bytes[index] ^= 0xff;
        checksum(&mut bytes);
        let _ = parse_mcfg(&bytes);
    }
}
