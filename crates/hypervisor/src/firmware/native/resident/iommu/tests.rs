extern crate std;
use super::*;
use crate::{boot::memory::MemoryDescriptor, memory::address::EncryptionState};
use std::{collections::BTreeMap, vec, vec::Vec};

const SYSTEM: u64 = 0x100000;
const CONFIG: u64 = 0x101000;
const RSDP: u64 = 0x200000;
const XSDT: u64 = 0x201000;
const IVRS: u64 = 0x202000;
const MCFG: u64 = 0x203000;
const ECAM: u64 = 0xe2002000; // MCFG bus-zero base + requester 20:00.2.
const MMIO: u64 = 0xfd000000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Firmware,
    Acpi,
    Pci,
    Mmio,
}
struct Fake {
    ram: BTreeMap<u64, (Kind, Vec<u8>)>,
    pci: BTreeMap<u64, u32>,
    mmio: BTreeMap<u64, u64>,
    reads: Vec<(Kind, u64, usize)>,
    deny: Option<(Kind, u64)>,
    changing_control: bool,
}
impl Fake {
    fn ram_read(&mut self, kind: Kind, address: u64, out: &mut [u8]) -> Result<(), ReadError> {
        self.reads.push((kind, address, out.len()));
        if self.deny == Some((kind, address)) {
            return Err(ReadError::Mapping);
        }
        let (&base, (stored_kind, bytes)) =
            self.ram.range(..=address).next_back().ok_or(ReadError::Unavailable)?;
        if kind != *stored_kind {
            return Err(ReadError::MemoryType);
        }
        let offset = (address - base) as usize;
        let input = bytes.get(offset..offset + out.len()).ok_or(ReadError::Unavailable)?;
        out.copy_from_slice(input);
        Ok(())
    }
    fn bytes(&mut self, address: u64) -> &mut Vec<u8> {
        &mut self.ram.get_mut(&address).unwrap().1
    }
    fn checksum(&mut self, address: u64) {
        checksum(self.bytes(address), 9);
    }
    fn system_crc(&mut self) {
        let crc = acpi::crc32_header(self.bytes(SYSTEM));
        set32(self.bytes(SYSTEM), 16, crc);
    }
}
impl ReadOnlyAccess for Fake {
    fn read_firmware(&mut self, address: u64, out: &mut [u8]) -> Result<(), ReadError> {
        self.ram_read(Kind::Firmware, address, out)
    }
    fn read_acpi(&mut self, address: u64, out: &mut [u8]) -> Result<(), ReadError> {
        self.ram_read(Kind::Acpi, address, out)
    }
    fn read_pci_u32(
        &mut self,
        segment: u16,
        requester: u16,
        address: u64,
    ) -> Result<u32, ReadError> {
        assert_eq!(segment, 0);
        assert_eq!(address & !4095, 0xe0000000 + (u64::from(requester) << 12));
        assert_eq!(address & 3, 0);
        self.reads.push((Kind::Pci, address, 4));
        self.pci.get(&address).copied().ok_or(ReadError::Unavailable)
    }
    fn read_mmio_u64(&mut self, address: u64) -> Result<u64, ReadError> {
        assert_eq!(address & 7, 0);
        self.reads.push((Kind::Mmio, address, 8));
        if self.changing_control
            && address == MMIO + 0x18
            && self.reads.iter().filter(|read| read.0 == Kind::Mmio && read.1 == address).count()
                > 1
        {
            return self
                .mmio
                .get(&address)
                .copied()
                .map(|value| value ^ 1)
                .ok_or(ReadError::Unavailable);
        }
        if self.deny == Some((Kind::Mmio, address)) {
            return Err(ReadError::Mapping);
        }
        self.mmio.get(&address).copied().ok_or(ReadError::Unavailable)
    }
}
fn set16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn set32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn set64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn checksum(bytes: &mut [u8], offset: usize) {
    bytes[offset] = 0;
    bytes[offset] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b)));
}
fn sdt(signature: &[u8; 4], length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    bytes[..4].copy_from_slice(signature);
    set32(&mut bytes, 4, length as u32);
    bytes[8] = 1;
    bytes
}
fn fixture() -> Fake {
    let mut fake = Fake {
        ram: BTreeMap::new(),
        pci: BTreeMap::new(),
        mmio: BTreeMap::new(),
        reads: Vec::new(),
        deny: None,
        changing_control: false,
    };
    let mut system = vec![0u8; core::mem::size_of::<uefi_raw::table::system::SystemTable>()];
    let length = system.len();
    set64(&mut system, 0, uefi_raw::table::system::SystemTable::SIGNATURE);
    set32(&mut system, 8, 0x20000);
    set32(&mut system, 12, length as u32);
    set64(&mut system, 104, 1);
    set64(&mut system, 112, CONFIG);
    fake.ram.insert(SYSTEM, (Kind::Firmware, system));
    fake.system_crc();
    let mut config = vec![
        0x71, 0xe8, 0x68, 0x88, 0xf1, 0xe4, 0xd3, 0x11, 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88,
        0x81,
    ];
    config.extend_from_slice(&RSDP.to_le_bytes());
    fake.ram.insert(CONFIG, (Kind::Firmware, config));
    let mut rsdp = vec![0; 36];
    rsdp[..8].copy_from_slice(b"RSD PTR ");
    rsdp[15] = 2;
    set32(&mut rsdp, 20, 36);
    set64(&mut rsdp, 24, XSDT);
    checksum(&mut rsdp[..20], 8);
    checksum(&mut rsdp, 32);
    fake.ram.insert(RSDP, (Kind::Acpi, rsdp));
    let mut xsdt = sdt(b"XSDT", 52);
    set64(&mut xsdt, 36, IVRS);
    set64(&mut xsdt, 44, MCFG);
    checksum(&mut xsdt, 9);
    fake.ram.insert(XSDT, (Kind::Acpi, xsdt));
    let mut ivrs = sdt(b"IVRS", 76);
    ivrs[48] = 0x10;
    set16(&mut ivrs, 50, 28);
    set16(&mut ivrs, 52, 0x2002);
    set16(&mut ivrs, 54, 0x40);
    set64(&mut ivrs, 56, MMIO);
    ivrs[72] = 2;
    set16(&mut ivrs, 73, 0x2008);
    checksum(&mut ivrs, 9);
    fake.ram.insert(IVRS, (Kind::Acpi, ivrs));
    let mut mcfg = sdt(b"MCFG", 60);
    set64(&mut mcfg, 44, 0xe0000000);
    mcfg[54] = 0x20;
    mcfg[55] = 0x2f;
    checksum(&mut mcfg, 9);
    fake.ram.insert(MCFG, (Kind::Acpi, mcfg));
    for (offset, value) in [
        (0, 0x16491022),
        (4, 1 << 20),
        (8, 0x08060000),
        (12, 0),
        (0x34, 0x40),
        (0x40, 0x000b000f),
        (0x44, MMIO as u32 | 1),
        (0x48, 0),
        (0x4c, 0),
        (0x50, 0),
    ] {
        fake.pci.insert(ECAM + offset, value);
    }
    for (offset, value) in [
        (0, 0x900000),
        (8, 0x0800000000a00000),
        (0x10, 0x0800000000b00000),
        (0x18, 0x1005),
        (0x20, 0),
        (0x28, 0),
        (0x2000, 0),
        (0x2008, 16),
        (0x2010, 0),
        (0x2018, 16),
        (0x2020, 0x18),
    ] {
        fake.mmio.insert(MMIO + offset, value);
    }
    fake
}
fn policy() -> AddressPolicy {
    AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

fn paging_config(cr3: u64, pcid: bool) -> crate::host::paging::PagingConfig {
    crate::host::paging::PagingConfig {
        cr3,
        physical_bits: 48,
        la57: false,
        nxe: true,
        pcid,
        page1gb: true,
    }
}

#[test]
fn root_cache_preflight_preserves_pcid_tags_without_accepting_pwt_or_pcd() {
    for tag in [0x18, 0xfff] {
        assert_eq!(
            root_cache_preflight(policy(), paging_config(0x100000 | tag, true), 48, 6),
            Ok(())
        );
        assert_eq!(
            root_cache_preflight(policy(), paging_config(0x100000 | tag, false), 48, 6),
            Err(ReadError::CacheType)
        );
    }
    for pcid in [false, true] {
        assert_eq!(root_cache_preflight(policy(), paging_config(0x100000, pcid), 48, 6), Ok(()));
    }
}

#[test]
fn root_cache_preflight_retains_width_and_pat_refusals_with_pcids() {
    for pcid in [false, true] {
        let config = paging_config(0x100000 | if pcid { 0xfff } else { 0 }, pcid);
        assert_eq!(
            root_cache_preflight(
                policy(),
                crate::host::paging::PagingConfig { physical_bits: 47, ..config },
                48,
                6
            ),
            Err(ReadError::CacheType)
        );
        assert_eq!(root_cache_preflight(policy(), config, 47, 6), Err(ReadError::CacheType));
        for pat in [0, 1, 4, 5, 7, 0x600] {
            // Only PAT[0] is interpreted here; another entry does not repair it.
            assert_eq!(root_cache_preflight(policy(), config, 48, pat), Err(ReadError::CacheType));
        }
    }
}

fn run(fake: &mut Fake) -> Report {
    let mut scratch = Scratch::EMPTY;
    let mut report = Report::EMPTY;
    acquire(fake, policy(), SYSTEM, &mut scratch, &mut report);
    report
}

#[test]
fn bounded_acquisition_uses_bus_zero_relative_ecam_and_owned_observations() {
    let mut fake = fixture();
    let report = run(&mut fake);
    assert_eq!(report.state, ObservationState::Observed);
    assert_eq!(report.diagnostic_word(), 0x0201_0110);
    assert!(report.tables.is_complete());
    let raw = report.hardware[0].registers.unwrap();
    assert_eq!(raw.device_table, 0x900000);
    assert_eq!(raw.command_buffer, 0x0800000000a00000);
    assert_eq!(raw.extended_features, None);
    assert_eq!(raw.extended_features2, None);
    assert!(fake.reads.iter().any(|r| *r == (Kind::Pci, ECAM, 4)));
    assert!(!fake.reads.iter().any(|r| r.1 == MMIO + 0x30));
    assert!(!fake.reads.iter().any(|r| r.1 == MMIO + 0x1a0));
    assert!(!fake.reads.iter().any(|r| [0x900000, 0xa00000, 0xb00000].contains(&r.1)));
    fake.bytes(IVRS).fill(0);
    assert_eq!(report.tables.ivrs.units().len(), 1);
    std::println!(
        "Discovery={} Report={} Scratch={}",
        core::mem::size_of::<crate::memory::iommu::Discovery>(),
        core::mem::size_of::<Report>(),
        core::mem::size_of::<Scratch>()
    );
    assert!(core::mem::size_of::<Report>() <= 32 * 1024);
}

#[test]
fn checksums_and_root_lengths_fail_before_device_reads() {
    for address in [SYSTEM, RSDP, XSDT, IVRS, MCFG] {
        let mut fake = fixture();
        let offset = if matches!(address, IVRS | MCFG) { 10 } else { 0 };
        fake.bytes(address)[offset] ^= 1;
        let report = run(&mut fake);
        assert_eq!(report.state, ObservationState::Malformed, "address={address:x}");
        assert!(!report.tables.is_complete());
        assert!(!fake.reads.iter().any(|r| matches!(r.0, Kind::Pci | Kind::Mmio)));
    }
    let mut fake = fixture();
    set64(fake.bytes(SYSTEM), 104, u64::MAX);
    fake.system_crc();
    assert_eq!(run(&mut fake).state, ObservationState::Unsupported);
    assert!(!fake.reads.iter().any(|r| r.1 == CONFIG));
}

#[test]
fn duplicate_config_roots_and_xsdt_targets_are_ambiguous() {
    let mut fake = fixture();
    let entry = fake.bytes(CONFIG).clone();
    fake.bytes(CONFIG).extend(entry);
    set64(fake.bytes(SYSTEM), 104, 2);
    fake.system_crc();
    assert_eq!(run(&mut fake).failure, Some(AcquisitionError::DuplicateRoot));
    let mut fake = fixture();
    set64(fake.bytes(XSDT), 44, IVRS);
    fake.checksum(XSDT);
    assert_eq!(run(&mut fake).failure, Some(AcquisitionError::DuplicateTable));
}

#[test]
fn unavailable_or_oversized_data_is_not_replaced_with_a_partial_table_report() {
    let mut fake = fixture();
    fake.deny = Some((Kind::Acpi, MCFG));
    let report = run(&mut fake);
    assert_eq!(report.state, ObservationState::Unavailable);
    assert!(!report.tables.is_complete());
    assert!(report.tables.ivrs.units().is_empty());
    let mut fake = fixture();
    set32(fake.bytes(IVRS), 4, 65537);
    assert_eq!(run(&mut fake).state, ObservationState::Unsupported);
    assert!(!fake.reads.iter().any(|r| r.2 > 65536));
}

#[test]
fn physical_width_is_checked_before_requesting_a_read() {
    let mut fake = fixture();
    set64(fake.bytes(RSDP), 24, 1 << 48);
    checksum(fake.bytes(RSDP), 32);
    assert_eq!(run(&mut fake).failure, Some(AcquisitionError::Read(ReadError::Address)));
    assert!(!fake.reads.iter().any(|r| r.1 >= 1 << 48));
}

#[test]
fn malformed_or_disabled_capability_never_reads_mmio() {
    for (offset, value, expected) in [
        (0x40, 0x000b400f, HardwareError::MalformedCapabilities),
        (0x40, 0x0013000f, HardwareError::CapabilityRevision),
        (0x40, 0x000b0005, HardwareError::CapabilityIdentity),
        (0x44, MMIO as u32, HardwareError::MmioDisabled),
        (0x44, 0xfedc0001, HardwareError::MmioBaseMismatch),
    ] {
        let mut fake = fixture();
        fake.pci.insert(ECAM + offset, value);
        let report = run(&mut fake);
        assert_eq!(report.hardware[0].error, Some(expected));
        assert!(!fake.reads.iter().any(|r| r.0 == Kind::Mmio));
        assert_ne!(report.state, ObservationState::Observed);
    }
}

#[test]
fn inaccessible_mmio_preserves_pci_with_an_explicit_partial_reason() {
    let mut fake = fixture();
    fake.deny = Some((Kind::Mmio, MMIO + 0x2010));
    let report = run(&mut fake);
    assert_eq!(report.state, ObservationState::Partial);
    assert_eq!(
        report.hardware[0].error,
        Some(HardwareError::Read { offset: 0x2010, error: ReadError::Mapping })
    );
    assert!(report.hardware[0].pci.is_some());
    assert!(report.hardware[0].registers.is_none());
    assert_eq!(report.diagnostic_word(), 0x0200_0160);
}

#[test]
fn every_uninventoried_mode_bit_prevents_complete_mmio_status() {
    for bit in [
        13, 14, 15, 16, 17, 22, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 40, 50, 51, 52,
        53, 56, 60, 61, 62, 63,
    ] {
        let mut fake = fixture();
        fake.mmio.insert(MMIO + 0x18, 0x1005 | (1u64 << bit));
        let report = run(&mut fake);
        assert_eq!(
            report.hardware[0].error,
            Some(HardwareError::ExtendedStateNotInventoried),
            "bit={bit}"
        );
        assert_eq!(report.state, ObservationState::Partial);
        assert_eq!(report.diagnostic_word() & 0x00ff0000, 0);
    }
}

#[test]
fn active_queue_pointers_are_checked_as_numbers_and_never_followed() {
    let mut fake = fixture();
    fake.mmio.insert(MMIO + 0x2008, 0x1000);
    let report = run(&mut fake);
    assert_eq!(report.hardware[0].error, Some(HardwareError::InvalidActiveBuffer));
    assert!(report.hardware[0].registers.is_some());
    assert!(!fake.reads.iter().any(|r| r.1 == 0xa00000));
}

#[test]
fn exact_feature_copy_mismatch_cannot_be_observed() {
    let mut fake = extended_fixture(0x11, 1, 0);
    fake.mmio.insert(MMIO + 0x30, 2);
    let report = run(&mut fake);
    assert_eq!(report.hardware[0].error, Some(HardwareError::FirmwareFeatureMismatch));
    assert_ne!(report.state, ObservationState::Observed);
}

fn extended_fixture(kind: u8, efr: u64, efr2: u64) -> Fake {
    let mut fake = fixture();
    let ivrs = fake.bytes(IVRS);
    ivrs.resize(92, 0);
    set32(ivrs, 4, 92);
    set32(ivrs, 36, 1);
    ivrs[8] = 2;
    ivrs[48] = kind;
    set16(ivrs, 50, 44);
    ivrs[72..].fill(0);
    set64(ivrs, 72, efr);
    set64(ivrs, 80, efr2);
    ivrs[88] = 2;
    set16(ivrs, 89, 0x2008);
    fake.checksum(IVRS);
    fake.pci.insert(ECAM + 0x40, 0x080b000f);
    fake.mmio.insert(MMIO + 0x30, efr);
    fake.mmio.insert(MMIO + 0x1a0, efr2);
    fake
}

#[test]
fn both_extended_feature_images_are_corroborated_for_each_extended_form() {
    for kind in [0x11, 0x40] {
        let mut fake = extended_fixture(kind, 1, 0x100);
        let report = run(&mut fake);
        assert_eq!(report.state, ObservationState::Observed);
        assert_eq!(report.diagnostic_word(), 0x0201_0110);
        let raw = report.hardware[0].registers.unwrap();
        assert_eq!(raw.extended_features, Some(1));
        assert_eq!(raw.extended_features2, Some(0x100));
        assert_eq!(fake.reads.iter().filter(|r| **r == (Kind::Mmio, MMIO + 0x1a0, 8)).count(), 1);
    }
}

#[test]
fn mismatched_second_feature_image_prevents_complete_observation() {
    for kind in [0x11, 0x40] {
        let mut fake = extended_fixture(kind, 1, 0x100);
        fake.mmio.insert(MMIO + 0x1a0, 0x108);
        let report = run(&mut fake);
        assert_eq!(report.hardware[0].error, Some(HardwareError::FirmwareFeatureMismatch));
        assert_eq!(report.hardware[0].registers.unwrap().extended_features2, Some(0x108));
        assert_eq!(report.tables.ivrs.forms()[0].efr2, Some(0x100));
        assert_eq!(report.state, ObservationState::Partial);
        assert_eq!(report.diagnostic_word(), 0x0200_0160);
    }
}

#[test]
fn firmware_feature_images_do_not_override_the_optional_register_gate() {
    let mut fake = extended_fixture(0x11, 1, 0x100);
    fake.pci.insert(ECAM + 0x40, 0x000b000f);
    let report = run(&mut fake);
    assert_eq!(report.hardware[0].error, Some(HardwareError::FirmwareFeatureMismatch));
    let raw = report.hardware[0].registers.unwrap();
    assert_eq!(raw.extended_features, None);
    assert_eq!(raw.extended_features2, None);
    assert!(!fake.reads.iter().any(|r| [MMIO + 0x30, MMIO + 0x1a0].contains(&r.1)));
    assert_eq!(report.state, ObservationState::Partial);
}

#[test]
fn inaccessible_second_feature_register_preserves_its_read_error() {
    let mut fake = extended_fixture(0x11, 1, 0x100);
    fake.deny = Some((Kind::Mmio, MMIO + 0x1a0));
    let report = run(&mut fake);
    assert_eq!(
        report.hardware[0].error,
        Some(HardwareError::Read { offset: 0x1a0, error: ReadError::Mapping })
    );
    assert!(report.hardware[0].pci.is_some());
    assert!(report.hardware[0].registers.is_none());
    assert_eq!(report.state, ObservationState::Partial);
    assert_eq!(report.diagnostic_word(), 0x0200_0160);
}

#[test]
fn changing_control_is_retained_as_a_partial_observation() {
    let mut fake = fixture();
    fake.changing_control = true;
    let report = run(&mut fake);
    assert_eq!(report.hardware[0].error, Some(HardwareError::ChangingConfiguration));
    assert!(report.hardware[0].registers.is_some());
    assert_eq!(report.state, ObservationState::Partial);
    assert_eq!(report.diagnostic_word() & 0x00ff0000, 0);
}

#[test]
fn acpi2_has_priority_and_legacy_only_never_falls_back_to_scanning() {
    let legacy_guid = [
        0x30, 0x2d, 0x9d, 0xeb, 0x88, 0x2d, 0xd3, 0x11, 0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1,
        0x4d,
    ];
    let mut fake = fixture();
    let current = fake.bytes(CONFIG).clone();
    let legacy = fake.bytes(CONFIG);
    legacy[..16].copy_from_slice(&legacy_guid);
    set64(legacy, 16, 0xdead0000);
    legacy.extend(current);
    set64(fake.bytes(SYSTEM), 104, 2);
    fake.system_crc();
    assert_eq!(run(&mut fake).state, ObservationState::Observed);
    assert!(!fake.reads.iter().any(|read| read.1 == 0xdead0000));
    let mut fake = fixture();
    fake.bytes(CONFIG)[..16].copy_from_slice(&legacy_guid);
    assert_eq!(run(&mut fake).failure, Some(AcquisitionError::LegacyAcpiOnly));
    assert!(!fake.reads.iter().any(|read| read.0 == Kind::Acpi));
}

#[test]
fn hardware_mmio_cannot_overlap_the_ecam_configuration_aperture() {
    let mut fake = fixture();
    set64(fake.bytes(IVRS), 56, 0xe2000000);
    fake.checksum(IVRS);
    let report = run(&mut fake);
    assert_eq!(report.hardware[0].error, Some(HardwareError::MmioOverlapsEcam));
    assert_eq!(report.state, ObservationState::Ambiguous);
    assert!(!fake.reads.iter().any(|read| matches!(read.0, Kind::Pci | Kind::Mmio)));
}

#[test]
fn chipset_aliases_never_reach_a_pci_or_iommu_probe() {
    for performance in [false, true] {
        let mut fake = multi_unit_fixture(&[(0xfed80000, performance)], false);
        let report = run(&mut fake);
        assert_eq!(report.hardware[0].error, Some(HardwareError::MmioOverlapsPlatform));
        assert_eq!(report.state, ObservationState::Ambiguous);
        assert!(!fake.reads.iter().any(|read| matches!(read.0, Kind::Pci | Kind::Mmio)));
    }
    let mut fake = fixture();
    set64(fake.bytes(MCFG), 44, 0xf0000000);
    fake.bytes(MCFG)[54] = 0;
    fake.bytes(MCFG)[55] = 255;
    fake.checksum(MCFG);
    let report = run(&mut fake);
    assert_eq!(report.state, ObservationState::Malformed);
    assert!(!fake.reads.iter().any(|read| matches!(read.0, Kind::Pci | Kind::Mmio)));
}

fn multi_unit_fixture(units: &[(u64, bool)], reverse_declarations: bool) -> Fake {
    let mut fake = fixture();
    let pci_template: Vec<_> =
        fake.pci.iter().map(|(&address, &value)| (address - ECAM, value)).collect();
    let mmio_template: Vec<_> =
        fake.mmio.iter().map(|(&address, &value)| (address - MMIO, value)).collect();
    fake.pci.clear();
    fake.mmio.clear();
    let mut blocks = Vec::new();
    for (index, &(base, performance_counters)) in units.iter().enumerate() {
        let requester = 0x2002 + index as u16;
        let mut block = [0u8; 28];
        block[0] = 0x10;
        set16(&mut block, 2, 28);
        set16(&mut block, 4, requester);
        set16(&mut block, 6, 0x40);
        set64(&mut block, 8, base);
        block[24] = 2;
        set16(&mut block, 25, 0x2100 + index as u16);
        blocks.push(block);
        let config = 0xe0000000 + (u64::from(requester) << 12);
        for &(offset, value) in &pci_template {
            fake.pci.insert(config + offset, value);
        }
        fake.pci.insert(config + 0x44, base as u32 | 1);
        fake.pci.insert(config + 0x48, (base >> 32) as u32);
        for &(offset, value) in &mmio_template {
            fake.mmio.insert(base + offset, value);
        }
        if performance_counters {
            fake.pci.insert(config + 0x40, 0x080b000f);
            fake.mmio.insert(base + 0x30, 1 << 9);
            fake.mmio.insert(base + 0x1a0, 0);
        }
    }
    if reverse_declarations {
        blocks.reverse();
    }
    let mut ivrs = sdt(b"IVRS", 48);
    for block in blocks {
        ivrs.extend_from_slice(&block);
    }
    let length = ivrs.len();
    set32(&mut ivrs, 4, length as u32);
    checksum(&mut ivrs, 9);
    fake.ram.insert(IVRS, (Kind::Acpi, ivrs));
    fake
}

#[test]
fn expanded_iommu_aperture_stops_mmio_in_either_declaration_order() {
    for reversed in [false, true] {
        // The third, disjoint unit verifies that collision stops the entire
        // scan, not only the immediately covered neighbor.
        let mut fake = multi_unit_fixture(
            &[(MMIO, true), (MMIO + 0x4000, false), (MMIO + 0x100000, false)],
            reversed,
        );
        let report = run(&mut fake);
        let units = report.tables.ivrs.units();
        let expanded = units.iter().position(|unit| unit.mmio_base == MMIO).unwrap();
        let covered = units.iter().position(|unit| unit.mmio_base == MMIO + 0x4000).unwrap();
        assert_eq!(report.hardware[expanded].mmio_bytes, Some(0x80000));
        assert_eq!(
            report.hardware[expanded].error,
            Some(HardwareError::MmioOverlapsIommu { unit_index: covered as u16 })
        );
        for (index, slot) in report.hardware.iter().enumerate().take(units.len()) {
            if index != expanded {
                assert_eq!(slot.error, Some(HardwareError::ApertureScanStopped));
                assert!(slot.pci.is_none());
            }
            assert!(slot.registers.is_none());
        }
        assert_eq!(report.state, ObservationState::Ambiguous);
        assert_eq!(report.diagnostic_word(), 0x0200_0350);
        let mmio_reads: Vec<_> =
            fake.reads.iter().copied().filter(|read| read.0 == Kind::Mmio).collect();
        assert_eq!(mmio_reads, [(Kind::Mmio, MMIO + 0x30, 8)]);
    }
}

#[test]
fn adjacent_minimum_apertures_remain_independent_in_either_declaration_order() {
    for reversed in [false, true] {
        let mut fake = multi_unit_fixture(&[(MMIO, false), (MMIO + 0x4000, false)], reversed);
        let report = run(&mut fake);
        assert_eq!(report.state, ObservationState::Observed);
        assert_eq!(report.diagnostic_word(), 0x0202_0210);
        for slot in report.hardware.iter().take(2) {
            assert_eq!(slot.mmio_bytes, Some(0x4000));
            assert!(slot.registers.is_some());
            assert_eq!(slot.error, None);
        }
        let first = fake.reads.iter().find(|read| read.0 == Kind::Mmio).unwrap();
        assert_eq!(*first, (Kind::Mmio, MMIO + 0x18, 8));
    }
}

#[test]
fn unknown_lower_aperture_stops_higher_unit_probes_in_either_declaration_order() {
    for reversed in [false, true] {
        let mut fake = multi_unit_fixture(&[(MMIO, true), (MMIO + 0x4000, false)], reversed);
        fake.deny = Some((Kind::Mmio, MMIO + 0x30));
        let report = run(&mut fake);
        let lower =
            report.tables.ivrs.units().iter().position(|unit| unit.mmio_base == MMIO).unwrap();
        assert_eq!(report.hardware[lower].mmio_bytes, None);
        assert_eq!(
            report.hardware[lower].error,
            Some(HardwareError::Read { offset: 0x30, error: ReadError::Mapping })
        );
        assert_eq!(report.hardware[1 - lower].error, Some(HardwareError::ApertureScanStopped));
        assert_eq!(report.state, ObservationState::Partial);
        let mmio_reads: Vec<_> =
            fake.reads.iter().copied().filter(|read| read.0 == Kind::Mmio).collect();
        assert_eq!(mmio_reads, [(Kind::Mmio, MMIO + 0x30, 8)]);
    }
}

#[test]
fn aperture_comparison_covers_the_tail_and_admitted_ecam_alignment() {
    use super::hardware::aperture_overlaps;
    // Pure interval inputs exercise the full extent without pretending that
    // 0x140000 is a parser-admitted, 1-MiB-aligned MCFG boundary.
    assert!(!aperture_overlaps(0x100000, 0x4000, 0x140000, 0x1fffff));
    assert!(aperture_overlaps(0x100000, 0x80000, 0x140000, 0x1fffff));
    assert!(!aperture_overlaps(0x100000, 0x80000, 0x180000, 0x1fffff));
    assert!(aperture_overlaps(u64::MAX - 7, 16, 0, 4095));
    assert!(aperture_overlaps(0x100000, 0, 0, 4095));
    assert!(aperture_overlaps(0x100000, 0x4000, 0x300000, 0x200000));
    // A 512-KiB-aligned aperture cannot straddle a 1-MiB-aligned MCFG
    // boundary: it divides that alignment. Genuine parser-admitted windows
    // therefore have the same overlap result for the minimum and full spans.
    for base in (0x100000..0x400000).step_by(0x80000) {
        assert_eq!(
            aperture_overlaps(base, 0x4000, 0x200000, 0x2fffff),
            aperture_overlaps(base, 0x80000, 0x200000, 0x2fffff)
        );
    }
}

#[test]
fn descriptor_policy_keeps_acpi_and_mmio_out_of_generic_ram() {
    let descriptor = |memory_type, attributes| MemoryDescriptor {
        memory_type,
        physical_start: 0x200000,
        page_count: 1,
        attributes,
    };
    for memory_type in [9, 10] {
        let map = [descriptor(memory_type, 8)];
        assert_eq!(descriptor_span(&map, policy(), MemoryKind::Acpi, 0x200000, 4096), Ok(()));
        assert_eq!(
            descriptor_span(&map, policy(), MemoryKind::PageTable, 0x200000, 8),
            Err(ReadError::MemoryType)
        );
        assert_eq!(
            descriptor_span(&map, policy(), MemoryKind::Firmware, 0x200000, 8),
            Err(ReadError::MemoryType)
        );
    }
    assert_eq!(
        descriptor_span(&[descriptor(11, 1)], policy(), MemoryKind::Mmio, 0x200000, 8),
        Ok(())
    );
    assert_eq!(
        descriptor_span(&[descriptor(11, 8)], policy(), MemoryKind::Mmio, 0x200000, 8),
        Err(ReadError::CacheType)
    );
    assert_eq!(
        descriptor_span(&[descriptor(9, 0x2008)], policy(), MemoryKind::Acpi, 0x200000, 8),
        Err(ReadError::ReadProtected)
    );
    assert_eq!(
        descriptor_span(&[descriptor(9, 8)], policy(), MemoryKind::Acpi, 0x200fff, 2),
        Err(ReadError::MemoryMap)
    );
    assert_eq!(
        descriptor_span(
            &[descriptor(9, 8), descriptor(9, 8)],
            policy(),
            MemoryKind::Acpi,
            0x200000,
            8
        ),
        Err(ReadError::MemoryMap)
    );
}
