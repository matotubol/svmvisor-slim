use super::*;

fn special(source: u16, settings: u8, handle: u8) -> Vec<u8> {
    vec![0x48, 0, 0, settings, handle, source as u8, (source >> 8) as u8, 1]
}

fn conflict_count(out: &Ivrs) -> usize {
    out.diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.kind == DiagnosticKind::SourceSettingsConflict)
        .count()
}

fn assert_conflict_pair(out: &Ivrs, a: u32, b: u32) {
    assert_eq!(
        out.diagnostics()
            .iter()
            .filter(|diagnostic| {
                diagnostic.kind == DiagnosticKind::SourceSettingsConflict
                    && ((diagnostic.offset == a && diagnostic.related_offset == Some(b))
                        || (diagnostic.offset == b && diagnostic.related_offset == Some(a)))
            })
            .count(),
        1
    );
    assert!(out.has_unresolved_diagnostics());
}

#[test]
fn special_sources_with_different_settings_require_resolution_in_either_order() {
    let a = special(0xa5, 0x10, 1);
    let b = special(0xa5, 0x20, 2);
    for declarations in [[a.clone(), b.clone()], [b, a]] {
        let out = parse_ivrs(&ivrs(&[ivhd(0x10, 0, &declarations.concat())])).unwrap();
        let devices = out.special_devices();
        assert_eq!(devices.len(), 2);
        for (device, declaration) in devices.iter().zip(&declarations) {
            assert_eq!(device.source_id, 0xa5);
            assert_eq!(device.dte_settings, declaration[3]);
            assert_eq!(device.handle, declaration[4]);
        }
        assert_eq!(conflict_count(&out), 1);
        assert_conflict_pair(&out, devices[0].offset, devices[1].offset);
        assert!(!has_diag(&out, DiagnosticKind::DuplicateSpecialIdentity));
    }
}

#[test]
fn special_sources_conflict_with_numeric_sources_in_either_order() {
    let mut range = entry(3, 0xa0, 0x20);
    range.extend(entry(4, 0xaf, 0));
    let mut extended = entry(0x46, 0xa5, 0x20);
    extended.extend_from_slice(&0x8000_0000u32.to_le_bytes());
    for numeric in [entry(2, 0xa5, 0x20), range, extended] {
        let device = special(0xa5, 0x10, 1);
        for entries in
            [[numeric.clone(), device.clone()].concat(), [device, numeric.clone()].concat()]
        {
            let out = parse_ivrs(&ivrs(&[ivhd(0x10, 0, &entries)])).unwrap();
            assert_eq!(out.special_devices()[0].dte_settings, 0x10);
            assert_eq!(out.requester_scopes()[0].dte_settings, 0x20);
            assert_eq!(conflict_count(&out), 1);
            assert_conflict_pair(
                &out,
                out.special_devices()[0].offset,
                out.requester_scopes()[0].offset,
            );
        }
    }
}

#[test]
fn special_sources_conflict_with_acpi_and_other_forms_of_the_same_unit() {
    let device = special(0xa5, 0x10, 1);
    let acpi = acpi_entry(0xa5, 2, b"ID00");
    // Fixed entries must precede F0h within one form. Across forms both orders
    // are legal, and unit normalization must preserve the shared-source check.
    let cases = [
        ivrs(&[ivhd(0x40, 0, &[device.clone(), acpi.clone()].concat())]),
        ivrs(&[ivhd(0x10, 0, &device), ivhd(0x40, 0, &acpi)]),
        ivrs(&[ivhd(0x40, 0, &acpi), ivhd(0x10, 0, &device)]),
    ];
    for table in cases {
        let out = parse_ivrs(&table).unwrap();
        assert_eq!(out.units().len(), 1);
        assert_eq!(out.special_devices()[0].dte_settings, 0x10);
        assert_eq!(out.acpi_devices()[0].dte_settings, 0x40);
        assert_eq!(out.acpi_devices()[0].uid(), b"ID00");
        assert_eq!(conflict_count(&out), 1);
        assert_conflict_pair(&out, out.special_devices()[0].offset, out.acpi_devices()[0].offset);
    }
    for peer in [special(0xa5, 0x20, 2), entry(2, 0xa5, 0x20)] {
        let a = ivhd(0x10, 0, &device);
        let b = ivhd(0x11, 0, &peer);
        for blocks in [[a.clone(), b.clone()], [b, a]] {
            let out = parse_ivrs(&ivrs(&blocks)).unwrap();
            assert_eq!(out.units().len(), 1);
            assert_eq!(conflict_count(&out), 1);
        }
    }
}

#[test]
fn compatible_special_source_sharing_does_not_infer_absent_extended_settings() {
    let device = special(0xa5, 0x40, 1);
    let mut extended = entry(0x46, 0xa5, 0x40);
    extended.extend_from_slice(&0x8000_0000u32.to_le_bytes());
    for entries in [
        [device.clone(), special(0xa5, 0x40, 2)].concat(),
        [device.clone(), extended].concat(),
        [device, acpi_entry(0xa5, 2, b"ID00")].concat(),
    ] {
        let out = parse_ivrs(&ivrs(&[ivhd(0x40, 0, &entries)])).unwrap();
        assert!(out.diagnostics().is_empty());
        assert!(!out.has_unresolved_diagnostics());
    }
}

#[test]
fn special_source_checks_use_alias_sources_and_preserve_existing_conflict_pairs() {
    let mut aliased = alias(0x42, 0xa5, 0x300);
    aliased[3] = 0x20;
    let mut entries = entry(2, 0x300, 0x20);
    entries.extend(aliased);
    // This is the actual peripheral's ID, not its IOMMU transaction source.
    entries.extend(special(0xa5, 0x10, 1));
    let out = parse_ivrs(&ivrs(&[ivhd(0x10, 0, &entries)])).unwrap();
    assert!(out.diagnostics().is_empty());

    // The source itself shares the alias's DTE. A separate numeric declaration
    // of the source already conflicts with the alias; do not emit it twice.
    let mut entries = entry(2, 0x300, 0x10);
    let mut aliased = alias(0x42, 0xa5, 0x300);
    aliased[3] = 0x20;
    entries.extend(aliased);
    entries.extend(special(0x300, 0x10, 1));
    let out = parse_ivrs(&ivrs(&[ivhd(0x10, 0, &entries)])).unwrap();
    assert_eq!(conflict_count(&out), 2);
    assert_conflict_pair(&out, out.requester_scopes()[0].offset, out.requester_scopes()[1].offset);
    assert_conflict_pair(&out, out.special_devices()[0].offset, out.requester_scopes()[1].offset);
}

#[test]
fn special_source_settings_are_not_compared_across_units_or_segments() {
    for segment in [0, 1] {
        let a = ivhd(0x10, 0, &special(0xa5, 0x10, 1));
        let mut b = ivhd(0x10, segment, &special(0xa5, 0x20, 2));
        put16(&mut b, 4, 3);
        put64(&mut b, 8, 0xf008_0000);
        for blocks in [[a.clone(), b.clone()], [b, a]] {
            let out = parse_ivrs(&ivrs(&blocks)).unwrap();
            assert_eq!(conflict_count(&out), 0);
            assert_eq!(has_diag(&out, DiagnosticKind::RequesterAcrossUnits), segment == 0);
            assert_eq!(out.has_unresolved_diagnostics(), segment == 0);
        }
    }
}
