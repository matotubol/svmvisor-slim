extern crate std;

use super::*;
use crate::{
    arch::x86_64::msr::TARGET_SIGNATURE,
    firmware::native::resident::iommu::{
        AcquisitionError, HardwareError, ObservationState, ReadError, UnitObservation,
    },
    memory::{
        address::EncryptionState,
        iommu::{DiagnosticKind, MemorySemantics, ParseErrorKind, discover},
    },
};
use std::{collections::BTreeMap, panic::AssertUnwindSafe, vec, vec::Vec};

const SYSTEM: u64 = 0x10_0000;
const CONFIG: u64 = 0x10_1000;
const RSDP: u64 = 0x20_0000;
const XSDT: u64 = 0x20_1000;
const IVRS: u64 = 0x20_2000;
const MCFG: u64 = 0x20_3000;
const ECAM: u64 = 0xe000_2000;
const MMIO: u64 = 0xf760_0000;
const EFR: u64 = 0x2465_77ef_a225_4afe;
const IVRS_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/iommu/windows-2026-09-26/IVRS.bin"
));
const MCFG_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/iommu/windows-2026-09-26/MCFG.bin"
));
const METADATA: CaptureMetadata = CaptureMetadata {
    configuration_route: 0xe000_0021,
    signature: TARGET_SIGNATURE,
    physical_bits: 48,
    cpu_count: 24,
};

fn policy() -> AddressPolicy {
    AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

fn empty() -> RetainedObservation {
    // Host-only tests may use stack initialization; firmware uses the static
    // template and captures at the final allocation address.
    RetainedObservation { header: RetainedHeader::EMPTY, report: Report::EMPTY }
}

struct Fixture {
    firmware: BTreeMap<u64, Vec<u8>>,
    acpi: BTreeMap<u64, Vec<u8>>,
    pci: BTreeMap<u64, u32>,
    mmio: BTreeMap<u64, u64>,
    reads: usize,
    control_reads: usize,
    change_control: bool,
    deny_mmio: Option<u64>,
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn checksum(bytes: &mut [u8], offset: usize) {
    bytes[offset] = 0;
    bytes[offset] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
}
fn sdt(signature: &[u8; 4], length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(signature);
    put32(&mut bytes, 4, length as u32);
    bytes[8] = 1;
    bytes
}

impl Fixture {
    fn new() -> Self {
        let mut system = vec![0; core::mem::size_of::<uefi_raw::table::system::SystemTable>()];
        let bytes = system.len() as u32;
        put64(&mut system, 0, uefi_raw::table::system::SystemTable::SIGNATURE);
        put32(&mut system, 8, 0x20000);
        put32(&mut system, 12, bytes);
        put64(&mut system, 104, 1);
        put64(&mut system, 112, CONFIG);
        let crc = super::super::acpi::crc32_header(&system);
        put32(&mut system, 16, crc);
        let mut config = vec![
            0x71, 0xe8, 0x68, 0x88, 0xf1, 0xe4, 0xd3, 0x11, 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c,
            0x88, 0x81,
        ];
        config.extend_from_slice(&RSDP.to_le_bytes());
        let mut rsdp = vec![0; 36];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[15] = 2;
        put32(&mut rsdp, 20, 36);
        put64(&mut rsdp, 24, XSDT);
        checksum(&mut rsdp[..20], 8);
        checksum(&mut rsdp, 32);
        let mut xsdt = sdt(b"XSDT", 52);
        put64(&mut xsdt, 36, IVRS);
        put64(&mut xsdt, 44, MCFG);
        checksum(&mut xsdt, 9);
        Self {
            firmware: [(SYSTEM, system), (CONFIG, config)].into_iter().collect(),
            acpi: [
                (RSDP, rsdp),
                (XSDT, xsdt),
                (IVRS, IVRS_BYTES.to_vec()),
                (MCFG, MCFG_BYTES.to_vec()),
            ]
            .into_iter()
            .collect(),
            pci: [
                (0, 0x1649_1022),
                (4, 1 << 20),
                (8, 0x0806_0000),
                (12, 0),
                (0x34, 0x40),
                (0x40, 0x080b_000f),
                (0x44, MMIO as u32 | 1),
                (0x48, 0),
                (0x4c, 0),
                (0x50, 0),
            ]
            .into_iter()
            .map(|(offset, value)| (ECAM + offset, value))
            .collect(),
            mmio: [
                (0, 0x900000),
                (8, 0x0800_0000_00a0_0000),
                (0x10, 0x0800_0000_00b0_0000),
                (0x18, 0x1005),
                (0x20, 0x947a_0001),
                (0x28, 0x947a_1000),
                (0x30, EFR),
                (0x1a0, 0),
                (0x2000, 0),
                (0x2008, 16),
                (0x2010, 0),
                (0x2018, 32),
                (0x2020, 0x18),
            ]
            .into_iter()
            .map(|(offset, value)| (MMIO + offset, value))
            .collect(),
            reads: 0,
            control_reads: 0,
            change_control: false,
            deny_mmio: None,
        }
    }

    fn without_conflicting_declarations() -> Self {
        let mut fixture = Self::new();
        let mut table = sdt(b"IVRS", 76);
        table[48] = 0x10;
        put16(&mut table, 50, 28);
        put16(&mut table, 52, 2);
        put16(&mut table, 54, 0x40);
        put64(&mut table, 56, MMIO);
        table[72] = 2;
        put16(&mut table, 73, 0x2008);
        checksum(&mut table, 9);
        fixture.acpi.insert(IVRS, table);
        fixture.pci.insert(ECAM + 0x40, 0x000b_000f);
        fixture
    }

    fn copy(map: &BTreeMap<u64, Vec<u8>>, address: u64, out: &mut [u8]) -> Result<(), ReadError> {
        let (&base, bytes) = map.range(..=address).next_back().ok_or(ReadError::Unavailable)?;
        let offset = (address - base) as usize;
        out.copy_from_slice(bytes.get(offset..offset + out.len()).ok_or(ReadError::Unavailable)?);
        Ok(())
    }
}

impl ReadOnlyAccess for Fixture {
    fn read_firmware(&mut self, address: u64, out: &mut [u8]) -> Result<(), ReadError> {
        self.reads += 1;
        Self::copy(&self.firmware, address, out)
    }
    fn read_acpi(&mut self, address: u64, out: &mut [u8]) -> Result<(), ReadError> {
        self.reads += 1;
        Self::copy(&self.acpi, address, out)
    }
    fn read_pci_u32(
        &mut self,
        segment: u16,
        requester: u16,
        address: u64,
    ) -> Result<u32, ReadError> {
        assert_eq!((segment, requester), (0, 2));
        self.reads += 1;
        self.pci.get(&address).copied().ok_or(ReadError::Unavailable)
    }
    fn read_mmio_u64(&mut self, address: u64) -> Result<u64, ReadError> {
        self.reads += 1;
        if self.deny_mmio == Some(address) {
            return Err(ReadError::Mapping);
        }
        let value = self.mmio.get(&address).copied().ok_or(ReadError::Unavailable)?;
        if address == MMIO + 0x18 {
            self.control_reads += 1;
            if self.change_control && self.control_reads > 1 {
                return Ok(value ^ 1);
            }
        }
        Ok(value)
    }
}

#[test]
fn full_inventory_hardware_and_conflicts_outlive_all_capture_inputs() {
    let mut retained = empty();
    let expected = discover(IVRS_BYTES, MCFG_BYTES).unwrap();
    {
        let mut fixture = Fixture::new();
        let mut scratch = Scratch::EMPTY;
        retained.capture_once(METADATA, &mut fixture, policy(), SYSTEM, &mut scratch).unwrap();
        for bytes in fixture.firmware.values_mut().chain(fixture.acpi.values_mut()) {
            bytes.fill(0xff);
        }
        fixture.mmio.clear();
        // A different successful acquisition overwrites every scratch table
        // buffer before both its source and scratch are dropped.
        let mut discarded = Report::EMPTY;
        let mut replacement = Fixture::without_conflicting_declarations();
        super::super::acquire(&mut replacement, policy(), SYSTEM, &mut scratch, &mut discarded);
        assert_eq!(discarded.state, ObservationState::Observed);
        assert_eq!(discarded.tables.ivrs.forms().len(), 1);
    }
    let report = retained.report(METADATA).unwrap();
    assert_eq!(report.tables, expected);
    assert_eq!(report.state, ObservationState::Ambiguous);
    assert_eq!(report.failure, None);
    assert_eq!(report.tables.ivrs.forms().len(), 3);
    assert_eq!(report.tables.ivrs.requester_scopes().len(), 6);
    assert_eq!(report.tables.ivrs.special_devices().len(), 9);
    assert_eq!(report.tables.ivrs.acpi_devices()[3].uid(), b"ID03");
    assert!(report.tables.ivrs.requester_scopes().iter().any(|s| s.alias_source == Some(0xa5)));
    assert!(
        report.tables.ivrs.diagnostics().iter().any(|d| d.kind == DiagnosticKind::RequesterOverlap)
    );
    assert!(
        report
            .tables
            .ivrs
            .memory_regions()
            .iter()
            .all(|r| r.semantics == MemorySemantics::Exclusion)
    );
    let observed = report.hardware[0];
    assert_eq!(observed.error, None);
    assert_eq!(observed.mmio_bytes, Some(0x80000));
    assert_eq!(observed.pci.unwrap().config_page, ECAM);
    let registers = observed.registers.unwrap();
    assert_eq!(registers.extended_features, Some(EFR));
    assert_eq!(registers.extended_features2, Some(0));
    assert_eq!(registers.device_table, 0x900000);
    assert_eq!(registers.command_buffer, 0x0800_0000_00a0_0000);
    assert_eq!(registers.exclusion_base, 0x947a_0001);
    assert_eq!(registers.event_tail, 32);
    assert!(report.hardware[1..].iter().all(|unit| *unit == UnitObservation::EMPTY));
    assert_eq!(retained.header().system_table_address(), SYSTEM);
    assert_eq!(retained.header().validate(METADATA), Ok(report.diagnostic_word()));
}

#[test]
fn late_hardware_failure_keeps_both_registers_and_partial_status() {
    let mut retained = empty();
    let mut fixture = Fixture::without_conflicting_declarations();
    let mut scratch = Scratch::EMPTY;
    fixture.change_control = true;
    retained.capture_once(METADATA, &mut fixture, policy(), SYSTEM, &mut scratch).unwrap();
    let report = retained.report(METADATA).unwrap();
    assert_eq!(report.state, ObservationState::Partial);
    assert!(report.tables.is_complete());
    assert_eq!(report.hardware[0].error, Some(HardwareError::ChangingConfiguration));
    assert_eq!(report.hardware[0].registers.unwrap().control, 0x1005);
    assert!(report.hardware[0].pci.is_some());
    assert_eq!(retained.header().validate(METADATA), Ok(0x0200_0160));
}

#[test]
fn acquisition_failure_and_incomplete_unit_are_published_as_evidence() {
    let mut retained = empty();
    let mut fixture = Fixture::new();
    let mut scratch = Scratch::EMPTY;
    fixture.acpi.get_mut(&IVRS).unwrap()[10] ^= 1;
    retained.capture_once(METADATA, &mut fixture, policy(), SYSTEM, &mut scratch).unwrap();
    let report = retained.report(METADATA).unwrap();
    let Some(AcquisitionError::Table(error)) = report.failure else {
        panic!("missing parse failure")
    };
    assert_eq!(error.table, *b"IVRS");
    assert_eq!(error.kind, ParseErrorKind::BadChecksum);
    assert!(!report.tables.is_complete());
    assert_eq!(report.state, ObservationState::Malformed);
    assert_eq!(retained.header().validate(METADATA), Ok(0x0200_0040));

    let mut retained = empty();
    let mut fixture = Fixture::new();
    fixture.deny_mmio = Some(MMIO + 0x18);
    retained.capture_once(METADATA, &mut fixture, policy(), SYSTEM, &mut scratch).unwrap();
    let report = retained.report(METADATA).unwrap();
    assert_eq!(report.state, ObservationState::Ambiguous);
    assert!(report.tables.is_complete());
    assert!(report.tables.ivrs.has_unresolved_diagnostics());
    assert!(report.hardware[0].pci.is_some());
    assert!(report.hardware[0].registers.is_none());
    assert_eq!(report.hardware[0].mmio_bytes, Some(0x80000));
    assert_eq!(
        report.hardware[0].error,
        Some(HardwareError::Read { offset: 0x18, error: ReadError::Mapping })
    );
}

#[test]
fn unpublished_and_repeated_captures_never_expose_or_replace_an_observation() {
    let mut retained = empty();
    assert!(matches!(retained.report(METADATA), Err(RetentionError::NotPublished)));
    let mut fixture = Fixture::new();
    let mut scratch = Scratch::EMPTY;
    retained.capture_once(METADATA, &mut fixture, policy(), SYSTEM, &mut scratch).unwrap();
    let before = retained.header().validate(METADATA).unwrap();
    let reads = fixture.reads;
    fixture.acpi.clear();
    assert_eq!(
        retained.capture_once(METADATA, &mut fixture, policy(), 0, &mut scratch),
        Err(RetentionError::AlreadyAttempted)
    );
    assert_eq!(fixture.reads, reads);
    assert_eq!(retained.header().validate(METADATA), Ok(before));
    assert_eq!(retained.report(METADATA).unwrap().tables.ivrs.forms().len(), 3);
}

#[test]
fn scalar_header_rejects_wrong_context_layout_counts_and_reserved_values() {
    let mut retained = empty();
    let mut scratch = Scratch::EMPTY;
    retained.capture_once(METADATA, &mut Fixture::new(), policy(), SYSTEM, &mut scratch).unwrap();
    let original = *retained.header();
    for corrupt in [
        |h: &mut RetainedHeader| h.layout_version ^= 1,
        |h: &mut RetainedHeader| h.bytes -= 1,
        |h: &mut RetainedHeader| h.phase = u32::MAX,
        |h: &mut RetainedHeader| h.diagnostic_word |= 1,
        |h: &mut RetainedHeader| h.diagnostic_word = 0x0200_1150,
        |h: &mut RetainedHeader| h.diagnostic_word = 0x0202_0150,
        |h: &mut RetainedHeader| h.diagnostic_word = 0x0200_0100,
        |h: &mut RetainedHeader| h.reserved[1] = 1,
        |h: &mut RetainedHeader| h.reserved_tail[2] = 1,
    ] {
        let mut header = original;
        corrupt(&mut header);
        assert_eq!(header.validate(METADATA), Err(RetentionError::InvalidHeader));
    }
    for phase in [EMPTY, CAPTURING] {
        let mut header = original;
        header.phase = phase;
        assert_eq!(header.validate(METADATA), Err(RetentionError::NotPublished));
    }
    for changed in [
        CaptureMetadata { configuration_route: METADATA.configuration_route ^ 4, ..METADATA },
        CaptureMetadata { signature: METADATA.signature ^ 1, ..METADATA },
        CaptureMetadata { physical_bits: 47, ..METADATA },
        CaptureMetadata { cpu_count: 23, ..METADATA },
    ] {
        assert_eq!(original.validate(changed), Err(RetentionError::MetadataMismatch));
    }
    // All scalar bit patterns can be handled without reading a typed payload.
    let all_ones = RetainedHeader {
        layout_version: u32::MAX,
        bytes: u32::MAX,
        phase: u32::MAX,
        diagnostic_word: u32::MAX,
        configuration_route: u64::MAX,
        system_table_address: u64::MAX,
        signature: u32::MAX,
        physical_bits: u8::MAX,
        cpu_count: u8::MAX,
        reserved: [u8::MAX; 2],
        reserved_tail: [u64::MAX; 3],
    };
    assert_eq!(all_ones.validate(METADATA), Err(RetentionError::InvalidHeader));
    retained.report.state = ObservationState::Partial;
    assert_eq!(retained.header().validate(METADATA), original.validate(METADATA));
    assert!(matches!(retained.report(METADATA), Err(RetentionError::ReportMismatch)));
}

#[test]
fn invalid_metadata_is_rejected_before_any_capture_read() {
    for metadata in [
        CaptureMetadata { physical_bits: 47, ..METADATA },
        CaptureMetadata { cpu_count: 0, ..METADATA },
        CaptureMetadata { cpu_count: u8::MAX, ..METADATA },
    ] {
        let mut retained = empty();
        let mut fixture = Fixture::new();
        let mut scratch = Scratch::EMPTY;
        assert_eq!(
            retained.capture_once(metadata, &mut fixture, policy(), SYSTEM, &mut scratch),
            Err(RetentionError::InvalidMetadata)
        );
        assert_eq!(fixture.reads, 0);
        assert_eq!(retained.header, RetainedHeader::EMPTY);
    }
}

#[test]
fn interrupted_capture_stays_unpublished_and_cannot_retry() {
    struct Panics;
    impl ReadOnlyAccess for Panics {
        fn read_firmware(&mut self, _: u64, _: &mut [u8]) -> Result<(), ReadError> {
            panic!("interrupted")
        }
        fn read_acpi(&mut self, _: u64, _: &mut [u8]) -> Result<(), ReadError> {
            unreachable!()
        }
        fn read_pci_u32(&mut self, _: u16, _: u16, _: u64) -> Result<u32, ReadError> {
            unreachable!()
        }
        fn read_mmio_u64(&mut self, _: u64) -> Result<u64, ReadError> {
            unreachable!()
        }
    }
    let mut retained = empty();
    let mut scratch = Scratch::EMPTY;
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        retained.capture_once(METADATA, &mut Panics, policy(), SYSTEM, &mut scratch)
    }));
    assert!(result.is_err());
    assert!(matches!(retained.report(METADATA), Err(RetentionError::NotPublished)));
    assert_eq!(
        retained.capture_once(METADATA, &mut Fixture::new(), policy(), SYSTEM, &mut scratch),
        Err(RetentionError::AlreadyAttempted)
    );
}

#[test]
fn static_template_and_actual_layout_fit_the_assigned_extent() {
    assert_eq!(RetainedObservation::empty_template().header, RetainedHeader::EMPTY);
    assert!(core::ptr::eq(
        RetainedObservation::empty_template(),
        RetainedObservation::empty_template()
    ));
    assert_eq!(size_of::<Report>(), 24_880);
    assert_eq!(RETAINED_BYTES, 24_944);
    assert_eq!(RETAINED_ALIGN, 8);
    assert_eq!(REPORT_OFFSET, 64);
    assert!(!core::mem::needs_drop::<RetainedObservation>());
}
