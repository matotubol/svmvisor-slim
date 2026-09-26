extern crate std;

use super::*;
use std::{vec, vec::Vec};

mod limits;
mod malformed;
mod special_sources;

const IVRS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/iommu/windows-2026-09-26/IVRS.bin"
));
const MCFG: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/iommu/windows-2026-09-26/MCFG.bin"
));

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn checksum(bytes: &mut [u8]) {
    bytes[9] = 0;
    bytes[9] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)));
}
fn seal(bytes: &mut [u8]) {
    put32(bytes, 4, bytes.len() as u32);
    checksum(bytes);
}
fn sdt(signature: [u8; 4], revision: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 36];
    out[..4].copy_from_slice(&signature);
    out[8] = revision;
    out.extend_from_slice(body);
    seal(&mut out);
    out
}
fn ivrs(blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![0; 12];
    body[0] = 1; // EFRSup, without inferring enabled remapping.
    for block in blocks {
        body.extend_from_slice(block);
    }
    sdt(*b"IVRS", 2, &body)
}
fn ivhd(kind: u8, segment: u16, entries: &[u8]) -> Vec<u8> {
    let mut out = vec![0; if kind == 0x10 { 24 } else { 40 }];
    out[0] = kind;
    put16(&mut out, 4, 2);
    put16(&mut out, 6, 0x40);
    put64(&mut out, 8, 0xf000_0000 + segment as u64 * 0x80000);
    put16(&mut out, 16, segment);
    out.extend_from_slice(entries);
    let length = out.len() as u16;
    put16(&mut out, 2, length);
    out
}
fn entry(kind: u8, device: u16, settings: u8) -> Vec<u8> {
    vec![kind, device as u8, (device >> 8) as u8, settings]
}
fn alias(kind: u8, device: u16, source: u16) -> Vec<u8> {
    let mut out = entry(kind, device, 0);
    out.extend_from_slice(&[0, source as u8, (source >> 8) as u8, 0]);
    out
}
fn acpi_entry(source: u16, uid_format: u8, uid: &[u8]) -> Vec<u8> {
    let mut out = entry(0xf0, source, 0x40);
    out.extend_from_slice(b"AMDI0020");
    out.extend_from_slice(&[0; 8]);
    out.push(uid_format);
    out.push(uid.len() as u8);
    out.extend_from_slice(uid);
    out
}
fn ivmd(
    kind: u8,
    flags: u8,
    first: u16,
    last: u16,
    segment: u16,
    start: u64,
    length: u64,
) -> Vec<u8> {
    let mut out = vec![0; 32];
    out[0] = kind;
    out[1] = flags;
    put16(&mut out, 2, 32);
    put16(&mut out, 4, first);
    put16(&mut out, 6, last);
    put16(&mut out, 8, segment);
    put64(&mut out, 16, start);
    put64(&mut out, 24, length);
    out
}
fn mcfg(allocations: &[(u64, u16, u8, u8)]) -> Vec<u8> {
    let mut body = vec![0; 8];
    for &(base, segment, first, last) in allocations {
        body.extend_from_slice(&base.to_le_bytes());
        body.extend_from_slice(&segment.to_le_bytes());
        body.extend_from_slice(&[first, last, 0, 0, 0, 0]);
    }
    sdt(*b"MCFG", 1, &body)
}
fn has_diag(report: &Ivrs, kind: DiagnosticKind) -> bool {
    report.diagnostics().iter().any(|d| d.kind == kind)
}
fn reject_ivrs(bytes: &[u8], kind: ParseErrorKind) {
    let error = parse_ivrs(bytes).unwrap_err();
    assert_eq!(error.table, *b"IVRS");
    assert_eq!(error.kind, kind, "{error:?}");
}

#[test]
fn captured_guest_inventory_preserves_forms_aliases_acpi_and_exclusions() {
    let out = discover(IVRS, MCFG).unwrap();
    assert!(out.is_complete());
    let inventory = &out.ivrs;
    assert_eq!(inventory.units().len(), 1);
    let unit = inventory.units()[0];
    assert_eq!(
        (unit.segment, unit.device_id, unit.capability_offset, unit.mmio_base),
        (0, 2, 0x40, 0xf760_0000)
    );
    assert_eq!(unit.form_mask, 7);
    assert_eq!(inventory.forms().iter().map(|f| f.kind).collect::<Vec<_>>(), [0x10, 0x11, 0x40]);
    assert_eq!(inventory.forms()[0].efr, None);
    assert_eq!(inventory.forms()[1].efr, Some(0x2465_77ef_a225_4afe));
    assert_eq!(inventory.forms()[2].efr2, Some(0));
    assert_eq!(inventory.requester_scopes().len(), 6);
    for scopes in inventory.requester_scopes().chunks_exact(2) {
        assert_eq!(scopes[0].range, RequesterRange { first: 3, last: 0xfffe });
        assert_eq!(scopes[1].range, RequesterRange { first: 0xff00, last: 0xffff });
        assert_eq!(scopes[1].alias_source, Some(0xa5));
    }
    assert!(has_diag(inventory, DiagnosticKind::RequesterOverlap));
    assert!(!has_diag(inventory, DiagnosticKind::AliasSourceUndeclared));
    assert!(!has_diag(inventory, DiagnosticKind::FormRequesterScopesDiffer));
    assert_eq!(inventory.special_devices().len(), 9);
    assert_eq!(inventory.acpi_devices().len(), 4);
    for (index, device) in inventory.acpi_devices().iter().enumerate() {
        assert_eq!(device.hardware_id, *b"AMDI0020");
        assert_eq!(device.source_id, 0xa5);
        assert_eq!(device.uid_format, UidFormat::String);
        assert_eq!(device.uid(), [b'I', b'D', b'0', b'0' + index as u8]);
    }
    assert!(has_diag(inventory, DiagnosticKind::SharedAcpiSource));
    assert!(has_diag(inventory, DiagnosticKind::AcpiSourceAlsoNumeric));
    assert!(!has_diag(inventory, DiagnosticKind::DuplicateAcpiIdentity));
    assert_eq!(inventory.memory_regions().len(), 3);
    let expected_starts = [0x947a_1000, 0x947a_0000, 0x8da7_f000];
    for (region, start) in inventory.memory_regions().iter().zip(expected_starts) {
        assert_eq!(region.preceding_form_index, 1);
        assert_eq!(
            region.scope,
            MemoryScope::Devices { segment: 0, range: RequesterRange { first: 0, last: 0xfff } }
        );
        assert_eq!(region.raw_flags, 8);
        assert_eq!(region.semantics, MemorySemantics::Exclusion);
        assert_eq!((region.start, region.last, region.length), (start, start + 0xfff, 4096));
    }
    let ecam = out.mcfg.allocations()[0];
    assert_eq!((ecam.base, ecam.segment, ecam.start_bus, ecam.end_bus), (0xe000_0000, 0, 0, 255));
    assert_eq!(ecam.address(2, 0x40), Some(0xe000_2040));
    assert!(!has_diag(inventory, DiagnosticKind::IommuOutsideMcfg));
}

#[test]
fn nonzero_start_bus_uses_bus_zero_base_and_disjoint_ranges_are_valid() {
    let bytes = mcfg(&[(0x8000_0000, 0, 0x40, 0x4f), (0x8000_0000, 0, 0x60, 0x6f)]);
    let out = parse_mcfg(&bytes).unwrap();
    assert_eq!(out.allocations().len(), 2);
    let a = out.allocations()[0];
    assert_eq!((a.start, a.last), (0x8400_0000, 0x84ff_ffff));
    assert_eq!(a.address(0x4108, 0xfff), Some(0x8410_8fff));
    assert_eq!(a.address(0x3fff, 0), None);
    assert_eq!(a.address(0x5000, 0), None);
    assert_eq!(a.address(0x4108, 4096), None);
}

#[test]
fn forms_remain_distinct_and_differences_are_diagnosed_without_precedence() {
    let a = ivhd(0x10, 0, &entry(2, 0x100, 0));
    let mut b = ivhd(0x11, 0, &entry(2, 0x200, 7));
    let mut c = ivhd(0x40, 0, &entry(2, 0x300, 9));
    put32(&mut b, 20, 0x2000);
    put64(&mut b, 24, 7);
    put64(&mut c, 24, 9);
    put64(&mut c, 32, 0x1234);
    let out = parse_ivrs(&ivrs(&[a, b, c])).unwrap();
    assert_eq!(out.units().len(), 1);
    assert_eq!(out.requester_scopes().len(), 3);
    assert_eq!(out.forms()[2].efr2, Some(0x1234));
    assert!(has_diag(&out, DiagnosticKind::FormPropertiesDiffer));
    assert!(has_diag(&out, DiagnosticKind::FormRequesterScopesDiffer));
}

#[test]
fn ivmd_retains_parent_form_global_scope_and_permission_semantics() {
    let unit = ivhd(0x11, 7, &entry(1, 0, 0));
    let declarations = [
        unit,
        ivmd(0x20, 0, 0, 0, 0, 0x1001, 17),
        ivmd(0x21, 7, 0x200, 0, 7, 0x3000, 3),
        ivmd(0x22, 15, 0x300, 0x3ff, 7, 0x4000, 7),
    ];
    let out = parse_ivrs(&ivrs(&declarations)).unwrap();
    let regions = out.memory_regions();
    assert_eq!(regions[0].scope, MemoryScope::AllDevices);
    assert_eq!(
        regions[0].semantics,
        MemorySemantics::Permissions { read: false, write: false, unity: false }
    );
    assert_eq!((regions[0].start, regions[0].last), (0x1001, 0x1011));
    assert_eq!(
        regions[1].semantics,
        MemorySemantics::Permissions { read: true, write: true, unity: true }
    );
    assert_eq!(regions[2].semantics, MemorySemantics::Exclusion);
    assert_eq!(regions[2].raw_flags, 15); // IR/IW/Unity ignored, not lost.
    assert!(regions.iter().all(|region| region.preceding_form_index == 0));
}

#[test]
fn undeclared_alias_and_cross_unit_assignment_are_explicit() {
    let a = ivhd(0x10, 0, &alias(0x42, 0x100, 0x200));
    let mut b = ivhd(0x10, 0, &entry(2, 0x100, 0));
    put16(&mut b, 4, 3);
    put64(&mut b, 8, 0xf008_0000);
    let out = parse_ivrs(&ivrs(&[a, b])).unwrap();
    assert!(has_diag(&out, DiagnosticKind::AliasSourceUndeclared));
    assert!(has_diag(&out, DiagnosticKind::RequesterAcrossUnits));
}

#[test]
fn duplicate_acpi_instance_is_preserved_and_diagnosed() {
    let mut entries = acpi_entry(0xa5, 2, b"ID00");
    entries.extend(acpi_entry(0xa6, 2, b"ID00"));
    let out = parse_ivrs(&ivrs(&[ivhd(0x40, 0, &entries)])).unwrap();
    assert_eq!(out.acpi_devices().len(), 2);
    assert!(has_diag(&out, DiagnosticKind::DuplicateAcpiIdentity));
}

#[test]
fn extended_dte_and_exact_requester_endpoints_are_preserved() {
    let mut entries = entry(0x46, 0xffff, 0xff);
    entries.extend_from_slice(&0x8000_0007u32.to_le_bytes());
    entries.extend(entry(0x47, 0, 0x55));
    entries.extend_from_slice(&0x8000_0000u32.to_le_bytes());
    entries.extend(entry(4, 0xfffe, 0));
    let out = parse_ivrs(&ivrs(&[ivhd(0x10, 0, &entries)])).unwrap();
    assert_eq!(out.requester_scopes()[0].extended_settings, Some(0x8000_0007));
    assert_eq!(out.requester_scopes()[1].range, RequesterRange { first: 0, last: 0xfffe });
    assert!(!has_diag(&out, DiagnosticKind::RequesterOverlap));
}

#[test]
fn failed_replacement_clears_visible_inventory_in_place() {
    let mut out = discover(IVRS, MCFG).unwrap();
    assert!(discover_into(IVRS, b"bad", &mut out).is_err());
    assert!(!out.is_complete());
    assert!(out.ivrs.units().is_empty());
    assert!(out.ivrs.forms().is_empty());
    assert!(out.ivrs.diagnostics().is_empty());
    assert!(out.mcfg.allocations().is_empty());
    discover_into(IVRS, MCFG, &mut out).unwrap();
    out.clear();
    assert!(!out.is_complete());
    assert!(out.ivrs.units().is_empty());
}

#[test]
fn cross_table_missing_coverage_and_mmio_alias_are_not_silent() {
    let table = ivrs(&[ivhd(0x10, 0, &entry(2, 0x100, 0))]);
    let ecam = mcfg(&[(0xf000_0000, 0, 0, 0)]);
    let out = discover(&table, &ecam).unwrap();
    assert!(has_diag(&out.ivrs, DiagnosticKind::IommuMmioOverlapsEcam));
    let out = discover(&table, &mcfg(&[(0x8000_0000, 4, 0, 255)])).unwrap();
    assert!(has_diag(&out.ivrs, DiagnosticKind::IommuOutsideMcfg));
}

#[test]
fn report_is_bounded_and_owns_no_input_lifetime() {
    let out = {
        let table = IVRS.to_vec();
        parse_ivrs(&table).unwrap()
    };
    assert_eq!(out.acpi_devices()[0].uid(), b"ID00");
    let bytes = core::mem::size_of::<Discovery>();
    std::println!("Discovery size: {bytes} bytes");
    assert!(bytes <= 32 * 1024);
}

#[test]
fn shared_alias_source_across_units_is_diagnosed_despite_disjoint_peripherals() {
    let a = ivhd(0x10, 0, &alias(0x42, 0x100, 0x300));
    let mut b = ivhd(0x10, 0, &alias(0x42, 0x200, 0x300));
    put16(&mut b, 4, 3);
    put64(&mut b, 8, 0xf008_0000);
    let out = parse_ivrs(&ivrs(&[a, b])).unwrap();
    assert!(has_diag(&out, DiagnosticKind::RequesterAcrossUnits));
}

#[test]
fn acpi_source_conflict_with_later_unit_is_not_order_dependent() {
    let a = ivhd(0x40, 0, &acpi_entry(0x300, 2, b"ID00"));
    let mut b = ivhd(0x10, 0, &entry(2, 0x300, 0));
    put16(&mut b, 4, 3);
    put64(&mut b, 8, 0xf008_0000);
    for blocks in [[a.clone(), b.clone()], [b, a]] {
        let out = parse_ivrs(&ivrs(&blocks)).unwrap();
        assert!(has_diag(&out, DiagnosticKind::RequesterAcrossUnits));
    }
}

#[test]
fn same_unit_alias_source_settings_conflict_is_retained_in_either_order() {
    let mut range = alias(0x43, 0x100, 0x300);
    range.extend(entry(4, 0x10f, 0));
    let mut singleton = alias(0x42, 0x200, 0x300);
    singleton[3] = 0x40;
    for declarations in [[range.clone(), singleton.clone()], [singleton, range]] {
        let mut entries = entry(2, 0x300, 0);
        for declaration in declarations {
            entries.extend(declaration);
        }
        let out = parse_ivrs(&ivrs(&[ivhd(0x10, 0, &entries)])).unwrap();
        let scopes = out.requester_scopes();
        assert_eq!(scopes.len(), 3);
        assert!(!scopes[1].range.overlaps(scopes[2].range));
        assert_eq!(scopes[1].alias_source, Some(0x300));
        assert_eq!(scopes[2].alias_source, Some(0x300));
        assert_ne!(scopes[1].dte_settings, scopes[2].dte_settings);
        assert!(out.diagnostics().iter().any(|diagnostic| {
            diagnostic.kind == DiagnosticKind::SourceSettingsConflict
                && diagnostic.offset == scopes[2].offset
                && diagnostic.related_offset == Some(scopes[1].offset)
        }));
        assert!(out.has_unresolved_diagnostics());
        assert!(!has_diag(&out, DiagnosticKind::RequesterOverlap));
        assert!(!has_diag(&out, DiagnosticKind::AliasSourceUndeclared));
    }
}

#[test]
fn compatible_disjoint_aliases_can_share_a_source_without_conflict() {
    let mut entries = entry(0x46, 0x300, 0x40);
    entries.extend_from_slice(&0x8000_0000u32.to_le_bytes());
    let mut range = alias(0x43, 0x100, 0x300);
    range[3] = 0x40;
    range.extend(entry(4, 0x10f, 0));
    let mut singleton = alias(0x42, 0x200, 0x300);
    singleton[3] = 0x40;
    entries.extend(range);
    entries.extend(singleton);
    let out = parse_ivrs(&ivrs(&[ivhd(0x10, 0, &entries)])).unwrap();
    assert_eq!(out.requester_scopes().len(), 3);
    assert_eq!(out.requester_scopes()[0].extended_settings, Some(0x8000_0000));
    assert_eq!(out.requester_scopes()[1].extended_settings, None);
    assert!(out.diagnostics().is_empty());
    assert!(!out.has_unresolved_diagnostics());
}
