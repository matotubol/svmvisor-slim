use svmvisor_hypervisor::memory::iommu::requester::{
    EvidenceKind, InitError, Query, ResolveErrorKind as Error, Resolver, SourceDeclaration,
    SourceMapping, SourceSettings,
};
use svmvisor_hypervisor::memory::iommu::{
    DiagnosticKind, Discovery, Ivrs, RequesterRange, discover, parse_ivrs,
};

const WINDOWS_IVRS: &[u8] = include_bytes!("fixtures/iommu/windows-2026-09-26/IVRS.bin");
const WINDOWS_MCFG: &[u8] = include_bytes!("fixtures/iommu/windows-2026-09-26/MCFG.bin");

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn ivhd(kind: u8, segment: u16, unit: u16, entries: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; if kind == 0x10 { 24 } else { 40 }];
    bytes[0] = kind;
    bytes[1] = 0x20;
    put16(&mut bytes, 4, unit);
    put16(&mut bytes, 6, 0x40);
    put64(&mut bytes, 8, 0xf000_0000 + u64::from(segment) * 0x100_0000 + u64::from(unit) * 0x4000);
    put16(&mut bytes, 16, segment);
    bytes.extend_from_slice(entries);
    let length = bytes.len() as u16;
    put16(&mut bytes, 2, length);
    bytes
}

fn inventory(blocks: &[Vec<u8>]) -> Ivrs {
    let mut bytes = vec![0; 48];
    bytes[..4].copy_from_slice(b"IVRS");
    bytes[8] = 2;
    put32(&mut bytes, 36, 1);
    for block in blocks {
        bytes.extend_from_slice(block);
    }
    let length = bytes.len() as u32;
    put32(&mut bytes, 4, length);
    bytes[9] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
    parse_ivrs(&bytes).unwrap()
}

fn entry(kind: u8, id: u16, settings: u8) -> Vec<u8> {
    vec![kind, id as u8, (id >> 8) as u8, settings]
}

fn range(first: u16, last: u16, settings: u8) -> Vec<u8> {
    [entry(3, first, settings), entry(4, last, 0)].concat()
}

fn alias(first: u16, last: u16, source: u16, settings: u8) -> Vec<u8> {
    let mut bytes = entry(if first == last { 0x42 } else { 0x43 }, first, settings);
    bytes.extend_from_slice(&[0, source as u8, (source >> 8) as u8, 0]);
    if first != last {
        bytes.extend(entry(4, last, 0));
    }
    bytes
}

fn extended(id: u16, settings: u8, extended: u32) -> Vec<u8> {
    let mut bytes = entry(0x46, id, settings);
    bytes.extend_from_slice(&extended.to_le_bytes());
    bytes
}

fn special(source: u16, settings: u8, handle: u8) -> Vec<u8> {
    vec![0x48, 0, 0, settings, handle, source as u8, (source >> 8) as u8, 1]
}

fn acpi(source: u16, settings: u8, uid: &[u8]) -> Vec<u8> {
    let mut bytes = entry(0xf0, source, settings);
    bytes.extend_from_slice(b"AMDI0020");
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&[2, uid.len() as u8]);
    bytes.extend_from_slice(uid);
    bytes
}

fn q(requester: u16) -> Query {
    Query { segment: 0, requester }
}

#[test]
fn redundant_equal_declarations_preserve_all_provenance_and_parser_diagnostics() {
    let declaration = range(0x100, 0x1ff, 0x28);
    let out = inventory(&[
        ivhd(0x10, 0, 2, &[declaration.clone(), declaration.clone()].concat()),
        ivhd(0x11, 0, 2, &declaration),
        ivhd(0x40, 0, 2, &declaration),
    ]);
    let before = out.clone();
    let resolver = Resolver::new(&out);
    let resolved = resolver.resolve(q(0x180)).unwrap();
    assert_eq!(resolved.unit_index, 0);
    assert_eq!(resolved.unit().device_id, 2);
    assert_eq!(resolved.source_id, 0x180);
    assert_eq!(resolved.settings, SourceSettings { dte: 0x28, extended: None });
    assert_eq!(resolved.forms().map(|form| form.kind).collect::<Vec<_>>(), [0x10, 0x11, 0x40]);
    assert_eq!(resolved.requester_declarations().count(), 4);
    assert_eq!(resolved.source_declarations().count(), 4);
    assert!(resolved.diagnostics().iter().any(|d| d.kind == DiagnosticKind::RequesterOverlap));
    assert!(
        resolver.diagnostics().iter().any(|d| d.kind == DiagnosticKind::FormRequesterScopesDiffer)
    );
    assert!(out.has_unresolved_diagnostics());
    assert_eq!(out, before);
}

#[test]
fn alias_range_uses_one_direct_source_and_merges_present_extended_settings() {
    let entries = [
        alias(0x100, 0x10f, 0x300, 0x40),
        alias(0x200, 0x200, 0x300, 0x40),
        extended(0x300, 0x40, 0x8000_0007),
        special(0x300, 0x40, 1),
    ]
    .concat();
    let out = inventory(&[
        ivhd(0x10, 0, 2, &entries),
        ivhd(0x11, 0, 2, &entries),
        ivhd(0x40, 0, 2, &entries),
    ]);
    let resolver = Resolver::new(&out);
    for id in [0x100, 0x10f, 0x200] {
        let resolved = resolver.resolve(q(id)).unwrap();
        assert_eq!(resolved.source_id, 0x300);
        assert_eq!(resolved.source_mapping(), SourceMapping::Alias(0x300));
        assert_eq!(resolved.settings, SourceSettings { dte: 0x40, extended: Some(0x8000_0007) });
        assert_eq!(resolved.source_declarations().count(), 12);
        assert_eq!(
            resolved
                .source_declarations()
                .filter(|e| matches!(e.declaration, SourceDeclaration::Special(_)))
                .count(),
            3
        );
        for evidence in resolved.source_declarations() {
            assert_eq!(evidence.settings().dte, 0x40);
            assert!(evidence.location.offset >= 48);
        }
    }
    let interval = resolver.resolve_interval(q(0x100)).unwrap();
    assert_eq!(interval.range, RequesterRange { first: 0x100, last: 0x10f });
    assert_eq!(interval.source_id(0x10f), Some(0x300));
    assert_eq!(interval.source_id(0x110), None);
    assert_eq!(resolver.resolve(q(0x300)).unwrap().source_mapping(), SourceMapping::Identity);
}

#[test]
fn overlaps_have_no_specificity_alias_order_or_same_value_precedence() {
    let pairs = [
        (range(3, 0xfffe, 0), alias(0xff00, 0xffff, 0xa5, 0), 0xff00),
        (range(0x100, 0x1ff, 0), entry(2, 0x180, 0), 0x180),
        (entry(2, 0x100, 0), alias(0x100, 0x100, 0x100, 0), 0x100),
        (extended(0x100, 0, 0x8000_0000), entry(2, 0x100, 0), 0x100),
    ];
    for (a, b, requester) in pairs {
        for entries in [[a.clone(), b.clone()].concat(), [b, a].concat()] {
            let out = inventory(&[ivhd(0x10, 0, 2, &entries)]);
            let error = Resolver::new(&out).resolve(q(requester)).unwrap_err();
            assert_eq!(error.kind, Error::OverlappingDeclarations);
            assert_eq!(error.first.unwrap().kind, EvidenceKind::Requester);
            assert_ne!(error.first, error.second);
        }
    }
}

#[test]
fn form_kind_range_alias_and_explicit_extended_differences_remain_unresolved() {
    let pairs = [
        (entry(2, 0x100, 0), range(0x100, 0x100, 0)),
        (range(0x100, 0x1ff, 0), range(0x100, 0x2ff, 0)),
        (entry(2, 0x100, 0), entry(2, 0x100, 0x40)),
        (extended(0x100, 0, 0), extended(0x100, 0, 0x8000_0000)),
        (entry(2, 0x100, 0), extended(0x100, 0, 0)),
        (alias(0x100, 0x100, 0x300, 0), alias(0x100, 0x100, 0x400, 0)),
    ];
    for (a, b) in pairs {
        for blocks in [
            [ivhd(0x10, 0, 2, &a), ivhd(0x11, 0, 2, &b)],
            [ivhd(0x11, 0, 2, &b), ivhd(0x10, 0, 2, &a)],
        ] {
            let out = inventory(&blocks);
            assert_eq!(
                Resolver::new(&out).resolve(q(0x100)).unwrap_err().kind,
                Error::FormDeclarationsDiffer
            );
        }
    }
    let out =
        inventory(&[ivhd(0x10, 0, 2, &entry(2, 0x100, 0)), ivhd(0x11, 0, 2, &entry(2, 0x200, 0))]);
    assert_eq!(
        Resolver::new(&out).resolve(q(0x100)).unwrap_err().kind,
        Error::MissingFormDeclaration
    );
}

#[test]
fn aliases_require_same_unit_direct_source_without_chain_chasing() {
    let cases = [
        (alias(0x100, 0x100, 0x300, 0), Error::AliasSourceUndeclared),
        (
            [alias(0x100, 0x100, 0x300, 0), alias(0x300, 0x300, 0x400, 0), entry(2, 0x400, 0)]
                .concat(),
            Error::AliasSourceNotDirect,
        ),
        (
            [alias(0x100, 0x100, 0x300, 0), entry(2, 0x300, 0), alias(0x300, 0x300, 0x400, 0)]
                .concat(),
            Error::OverlappingDeclarations,
        ),
    ];
    for (entries, expected) in cases {
        let out = inventory(&[ivhd(0x10, 0, 2, &entries)]);
        let error = Resolver::new(&out).resolve(q(0x100)).unwrap_err();
        assert_eq!(error.kind, expected);
        assert_eq!(error.subject_requester, 0x300);
        assert_eq!(error.query, q(0x100));
    }
    let out = inventory(&[
        ivhd(0x10, 0, 2, &alias(0x100, 0x100, 0x300, 0)),
        ivhd(0x10, 0, 3, &entry(2, 0x300, 0)),
    ]);
    assert_eq!(Resolver::new(&out).resolve(q(0x100)).unwrap_err().kind, Error::SourceAcrossUnits);
}

#[test]
fn actual_and_shared_source_collisions_across_units_are_segment_scoped() {
    for same_segment in [true, false] {
        for shared_source in [true, false] {
            let a = if shared_source {
                [entry(2, 0x300, 0), alias(0x100, 0x100, 0x300, 0)].concat()
            } else {
                entry(2, 0x100, 0)
            };
            let b = if shared_source { alias(0x200, 0x200, 0x300, 0) } else { entry(2, 0x100, 0) };
            let a = ivhd(0x10, 0, 2, &a);
            let b = ivhd(0x10, u16::from(!same_segment), 3, &b);
            for blocks in [[a.clone(), b.clone()], [b, a]] {
                let out = inventory(&blocks);
                let result = Resolver::new(&out).resolve(q(0x100));
                if same_segment {
                    assert_eq!(
                        result.unwrap_err().kind,
                        if shared_source {
                            Error::SourceAcrossUnits
                        } else {
                            Error::RequesterAcrossUnits
                        }
                    );
                } else {
                    assert_eq!(result.unwrap().unit().device_id, 2);
                }
            }
        }
    }
}

#[test]
fn disjoint_alias_special_and_acpi_declarations_still_constrain_shared_source_settings() {
    let peers =
        [alias(0x200, 0x200, 0x300, 0x40), special(0x300, 0x40, 1), acpi(0x300, 0x40, b"ID00")];
    for peer in peers {
        let entries = [entry(2, 0x300, 0), alias(0x100, 0x100, 0x300, 0), peer].concat();
        let out = inventory(&[ivhd(0x40, 0, 2, &entries)]);
        let error = Resolver::new(&out).resolve(q(0x100)).unwrap_err();
        assert_eq!(error.kind, Error::SourceSettingsConflict);
        assert_eq!(error.subject_requester, 0x300);
        assert_eq!(error.first.unwrap().offset, out.requester_scopes()[1].offset);
        assert!(error.second.is_some());
    }
}

#[test]
fn special_identity_changes_missing_forms_and_equal_repetitions_are_distinct() {
    let numeric = entry(2, 0x300, 0x40);
    let one = special(0x300, 0x40, 1);
    let out = inventory(&[ivhd(0x10, 0, 2, &[numeric.clone(), one.clone(), one.clone()].concat())]);
    let resolution = Resolver::new(&out).resolve(q(0x300)).unwrap();
    assert_eq!(resolution.source_declarations().count(), 3);
    assert!(out.diagnostics().iter().any(|d| d.kind == DiagnosticKind::DuplicateSpecialIdentity));

    let out = inventory(&[ivhd(
        0x10,
        0,
        2,
        &[numeric.clone(), one.clone(), special(0x400, 0x40, 1)].concat(),
    )]);
    assert_eq!(
        Resolver::new(&out).resolve(q(0x300)).unwrap_err().kind,
        Error::SpecialIdentityConflict
    );
    let out = inventory(&[
        ivhd(0x10, 0, 2, &[numeric.clone(), one].concat()),
        ivhd(0x11, 0, 2, &numeric),
    ]);
    assert_eq!(Resolver::new(&out).resolve(q(0x300)).unwrap_err().kind, Error::SpecialFormsDiffer);
}

#[test]
fn source_only_auxiliary_entries_do_not_establish_numeric_peripheral_identity() {
    for entries in [special(0xa5, 0x40, 1), acpi(0xa5, 0x40, b"ID00")] {
        let out = inventory(&[ivhd(0x40, 0, 2, &entries)]);
        assert_eq!(
            Resolver::new(&out).resolve(q(0xa5)).unwrap_err().kind,
            Error::AuxiliaryIdentityRequired
        );
    }
    let out = inventory(&[ivhd(
        0x40,
        0,
        2,
        &[entry(2, 0xa5, 0x40), acpi(0xa5, 0x40, b"ID00"), acpi(0xa5, 0x40, b"ID01")].concat(),
    )]);
    assert_eq!(
        Resolver::new(&out).resolve(q(0xa5)).unwrap_err().kind,
        Error::AcpiSourceRequiresIdentity
    );
    assert!(out.diagnostics().iter().any(|d| d.kind == DiagnosticKind::SharedAcpiSource));
}

#[test]
fn unit_properties_refuse_locally_but_legacy_feature_encoding_is_not_compared_raw() {
    let entries = entry(2, 0x100, 0);
    let mut legacy = ivhd(0x10, 0, 2, &entries);
    put32(&mut legacy, 20, 0x1234);
    let mut modern = ivhd(0x11, 0, 2, &entries);
    put32(&mut modern, 20, 0x2000);
    let out = inventory(&[legacy.clone(), modern.clone()]);
    assert!(Resolver::new(&out).resolve(q(0x100)).is_ok());

    modern[1] ^= 1;
    let out = inventory(&[legacy.clone(), modern]);
    assert_eq!(
        Resolver::new(&out).resolve(q(0x100)).unwrap_err().kind,
        Error::UnitDiagnostic(DiagnosticKind::FormPropertiesDiffer)
    );
    let mut reserved = ivhd(0x11, 0, 2, &entries);
    reserved[1] |= 0x80;
    let out = inventory(&[reserved]);
    assert_eq!(
        Resolver::new(&out).resolve(q(0x100)).unwrap_err().kind,
        Error::UnitDiagnostic(DiagnosticKind::ReservedIvhdBits)
    );

    let mut unrelated = ivhd(0x11, 1, 3, &entries);
    unrelated[1] |= 0x80;
    let out = inventory(&[legacy, unrelated]);
    assert!(Resolver::new(&out).resolve(q(0x100)).is_ok());
    assert!(out.has_unresolved_diagnostics());
}

#[test]
fn source_endpoints_expose_interior_conflicts_and_late_failure_preserves_inventory() {
    let out = inventory(&[ivhd(
        0x10,
        0,
        2,
        &[range(0, 0x3ff, 0), alias(0x500, 0x500, 0x200, 0x40)].concat(),
    )]);
    let before = out.clone();
    let resolver = Resolver::new(&out);
    assert!(resolver.resolve(q(0)).is_ok());
    assert!(resolver.resolve(q(0x3ff)).is_ok());
    let interval = resolver.resolve_interval(q(0)).unwrap();
    assert_eq!(interval.range, RequesterRange { first: 0, last: 0x1ff });
    assert_eq!(interval.source_id(0x123), Some(0x123));
    let error = resolver.validate_range(0, RequesterRange { first: 0, last: 0x3ff }).unwrap_err();
    assert_eq!(error.query, q(0x200));
    assert_eq!(error.kind, Error::SourceSettingsConflict);
    assert_eq!(out, before);
}

#[test]
fn full_u16_ranges_bounds_gaps_and_maximum_scope_count_use_endpoint_queries() {
    let out = inventory(&[ivhd(0x10, 0, 2, &entry(1, 0, 0))]);
    let resolver = Resolver::new(&out);
    let all = RequesterRange { first: 0, last: 0xffff };
    assert_eq!(resolver.validate_range(0, all).unwrap().intervals, 1);
    assert_eq!(resolver.resolve_interval(q(0xffff)).unwrap().range.last, 0xffff);
    assert_eq!(resolver.resolve(q(0xffff)).unwrap().source_id, 0xffff);
    assert_eq!(
        resolver.validate_range(0, RequesterRange { first: 1, last: 0 }).unwrap_err().kind,
        Error::InvalidRange
    );

    let out =
        inventory(&[ivhd(0x10, 0, 2, &[range(0, 0xff, 0), range(0x200, 0xffff, 0)].concat())]);
    let error = Resolver::new(&out).validate_range(0, all).unwrap_err();
    assert_eq!(error.query, q(0x100));
    assert_eq!(error.kind, Error::NoNumericDeclaration);

    let entries = (0..256)
        .flat_map(|bus| range(bus << 8, (bus << 8) | 0xff, (bus & 7) as u8))
        .collect::<Vec<_>>();
    let out = inventory(&[ivhd(0x10, 0, 2, &entries)]);
    let resolver = Resolver::new(&out);
    assert_eq!(resolver.validate_range(0, all).unwrap().intervals, 256);
    for id in [0, 0xff, 0x100, 0x80ff, 0xff00, 0xffff] {
        let resolved = resolver.resolve(q(id)).unwrap();
        assert_eq!(resolved.source_id, id);
        assert_eq!(resolved.settings.dte, ((id >> 8) & 7) as u8);
    }
}

#[test]
fn real_windows_fixture_resolves_only_local_numeric_evidence_and_keeps_ambiguity() {
    let discovery = discover(WINDOWS_IVRS, WINDOWS_MCFG).unwrap();
    let before = discovery.clone();
    let resolver = Resolver::from_discovery(&discovery).unwrap();
    let resolved = resolver.resolve(q(0x1000)).unwrap();
    assert_eq!(resolved.unit().mmio_base, 0xf760_0000);
    assert_eq!(resolved.unit().device_id, 2);
    assert_eq!(resolved.source_id, 0x1000);
    assert_eq!(resolved.forms().count(), 3);
    assert_eq!(resolved.requester_declarations().count(), 3);
    assert!(resolver.validate_range(0, RequesterRange { first: 0x1000, last: 0xfeff }).is_ok());
    for id in [0xff00, 0xfffe] {
        assert_eq!(resolver.resolve(q(id)).unwrap_err().kind, Error::OverlappingDeclarations);
    }
    assert_eq!(
        resolver
            .validate_range(0, RequesterRange { first: 0x1000, last: 0xffff })
            .unwrap_err()
            .query,
        q(0xff00)
    );
    let last = resolver.resolve(q(0xffff)).unwrap_err();
    assert_eq!(last.kind, Error::SourceSettingsConflict);
    assert_eq!(last.subject_requester, 0xa5);
    assert_eq!(last.second.unwrap().kind, EvidenceKind::Acpi);
    assert_eq!(resolver.resolve(q(0xa0)).unwrap_err().kind, Error::SourceSettingsConflict);
    assert!(discovery.ivrs.has_unresolved_diagnostics());
    assert_eq!(resolved.diagnostics(), discovery.ivrs.diagnostics());
    assert_eq!(discovery, before);
}

#[test]
fn empty_and_incomplete_inputs_produce_no_resolution() {
    assert_eq!(Resolver::new(&Ivrs::EMPTY).resolve(q(0)).unwrap_err().kind, Error::EmptyInventory);
    assert_eq!(
        Resolver::from_discovery(&Discovery::EMPTY).unwrap_err(),
        InitError::IncompleteDiscovery
    );
}
