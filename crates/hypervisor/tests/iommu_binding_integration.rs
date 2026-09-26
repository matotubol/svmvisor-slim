//! Compose offline inventory, per-unit banks and exact CPU control-page holes.
//! Synthetic observations and asserted physical assignments are not live owners.

use std::alloc::{Layout, alloc_zeroed, handle_alloc_error};
use svmvisor_hypervisor::{
    arch::x86_64::capabilities::EvidenceFlag,
    firmware::native::resident::iommu::{
        ObservationState, PciObservation, RegisterObservation, Report, UnitObservation,
        binding::{self, UnitAssignment, UnitIdentity},
        resources::ResourceStorage,
    },
    host::resident::{IOMMU_RESOURCE_BYTES, pool_bytes_for_processors},
    memory::{
        address::{ADDRESS_MASK, AddressPolicy, EncryptionState, PhysicalRange},
        iommu::{
            RequesterRange, discover,
            requester::{Query, Resolver, SourceMapping},
        },
        npt::{
            CACHE_TABLE_COUNT, CacheMapping, ControlPageDenials, IdentityNpt, NptEvidence,
            identity_is_quarantined, retype_identity_policy,
        },
    },
};

const POOL: u64 = 0x200000;
const BANK: u64 = 0x310000;
const ECAM: u64 = 0xe0000000;
const MMIO: u64 = 0xfd400000;
const IOMMU_ID: u16 = 2;

fn policy() -> AddressPolicy {
    AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

fn extent(base: u64, bytes: u64) -> PhysicalRange {
    policy().validate(base, bytes, 4096).unwrap()
}

fn bank() -> Box<ResourceStorage> {
    let layout = Layout::new::<ResourceStorage>();
    // Integer-only storage; allocate directly to avoid a multi-MiB stack value.
    let raw = unsafe { alloc_zeroed(layout) };
    if raw.is_null() {
        handle_alloc_error(layout);
    }
    let mut bank: Box<ResourceStorage> = unsafe { Box::from_raw(raw.cast()) };
    bank.prepare(policy(), BANK).unwrap();
    bank
}

fn set16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn set64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn table(signature: &[u8; 4], length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(signature);
    bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    bytes[8] = 1;
    bytes
}

fn checksum(bytes: &mut [u8]) {
    bytes[9] = 0;
    bytes[9] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
}

fn report(performance_counters: bool) -> Report {
    let mut ivrs = table(b"IVRS", 80);
    ivrs[48] = 0x10;
    set16(&mut ivrs, 50, 32);
    set16(&mut ivrs, 52, IOMMU_ID);
    set16(&mut ivrs, 54, 0x40);
    set64(&mut ivrs, 56, MMIO);
    ivrs[72] = 3;
    set16(&mut ivrs, 73, 0x100);
    ivrs[76] = 4;
    set16(&mut ivrs, 77, 0x1ff);
    checksum(&mut ivrs);
    let mut mcfg = table(b"MCFG", 60);
    set64(&mut mcfg, 44, ECAM);
    mcfg[55] = 0xff;
    checksum(&mut mcfg);
    let mut report = Report::EMPTY;
    report.tables = discover(&ivrs, &mcfg).unwrap();
    assert!(report.tables.ivrs.diagnostics().is_empty());
    report.state = ObservationState::Observed;
    report.hardware[0] = UnitObservation {
        pci: Some(PciObservation {
            config_page: ECAM + (u64::from(IOMMU_ID) << 12),
            vendor_device: 0x16491022,
            command_status: 1 << 20,
            class_revision: 0x08060000,
            capability_header: 0x080b000f,
            base_low: MMIO as u32 | 1,
            base_high: 0,
            range: 0,
            miscellaneous0: (48 << 15) | (48 << 8),
            miscellaneous1: None,
        }),
        mmio_bytes: Some(if performance_counters { 0x80000 } else { 0x4000 }),
        registers: Some(RegisterObservation {
            device_table: 0,
            command_buffer: 0,
            event_log: 0,
            control: 0,
            exclusion_base: 0,
            exclusion_limit: 0,
            extended_features: Some(if performance_counters { 1 << 9 } else { 0 }),
            extended_features2: Some(0),
            command_head: 0,
            command_tail: 0,
            event_head: 0,
            event_tail: 0,
            status: 0,
        }),
        error: None,
    };
    report
}

/// Walk raw NPT bytes without using the production translation helper.
fn translate(tables: &[[u8; 4096]], address: u64) -> Option<u64> {
    let mut table = 0;
    for level in (1..=4).rev() {
        let length = 1u64 << (12 + 9 * (level - 1));
        let offset = (((address / length) & 511) * 8) as usize;
        let word = u64::from_le_bytes(tables[table][offset..offset + 8].try_into().unwrap());
        if word & 1 == 0 {
            return None;
        }
        if level == 1 || level < 4 && word & 128 != 0 {
            let pat = if level == 1 { 0 } else { 1 << 12 };
            return Some((word & ADDRESS_MASK & !pat) | (address & (length - 1)));
        }
        table = usize::try_from(((word & ADDRESS_MASK) - POOL) / 4096).unwrap();
        assert!(table > 0 && table < tables.len());
    }
    unreachable!()
}

fn assert_permanent_holes(tables: &[[u8; 4096]], holes: &[PhysicalRange]) {
    for hole in holes {
        for page in (hole.base()..=hole.last_byte()).step_by(4096) {
            for address in [page, page + 4095] {
                assert_eq!(translate(tables, address), None, "hole at {address:#x}");
                assert_eq!(identity_is_quarantined(tables, POOL, address), Ok(false));
            }
        }
    }
}

#[test]
fn bound_controls_and_whole_retained_pool_stay_denied_across_cache_rebuilds() {
    let bank = bank();
    let pool = extent(POOL, pool_bytes_for_processors(1).unwrap());
    assert!(pool.last_byte() + 1 >= BANK + IOMMU_RESOURCE_BYTES);
    for performance_counters in [false, true] {
        let report = report(performance_counters);
        let plan = binding::bind(
            policy(),
            &report,
            pool,
            &[UnitAssignment {
                identity: UnitIdentity::from_unit(report.tables.ivrs.units()[0]),
                extent: extent(BANK, IOMMU_RESOURCE_BYTES),
                storage: &bank,
            }],
        )
        .unwrap();
        let resolver = Resolver::from_discovery(&report.tables).unwrap();
        let declared = RequesterRange { first: 0x100, last: 0x1ff };
        assert_eq!(resolver.validate_range(0, declared).unwrap().intervals, 1);
        let resolved = resolver.resolve(Query { segment: 0, requester: 0x180 }).unwrap();
        assert_eq!(resolved.source_id, 0x180);
        assert_eq!(resolved.source_mapping(), SourceMapping::Identity);
        let unit = plan.unit(usize::from(resolved.unit_index)).unwrap();
        assert_eq!(unit.identity, UnitIdentity::from_unit(*resolved.unit()));
        assert_eq!(unit.configuration_page.base(), ECAM + 0x2000);
        assert_eq!(unit.configuration_page.len(), 4096);
        assert_eq!(unit.control_aperture.base(), MMIO);
        assert_eq!(
            unit.control_aperture.len(),
            if performance_counters { 0x80000 } else { 0x4000 }
        );
        assert_eq!(unit.bank.last_byte(), BANK + IOMMU_RESOURCE_BYTES - 1);
        assert!(unit.bank.last_byte() < pool.last_byte());
        assert_eq!(plan.unresolved_diagnostics(), 0);
        // Deliberate offline composition, never automatic activation from Report.
        let denied =
            ControlPageDenials::new(policy(), &[unit.configuration_page, unit.control_aperture])
                .unwrap();
        let holes = [pool, unit.configuration_page, unit.control_aperture];
        let mut original = vec![[0; 4096]; CACHE_TABLE_COUNT];
        IdentityNpt::new_with_denied_ranges(
            &mut original,
            POOL,
            policy(),
            pool,
            NptEvidence {
                nx_supported: EvidenceFlag::Set,
                host_nxe: EvidenceFlag::Set,
                host_four_level: EvidenceFlag::Set,
            },
            EvidenceFlag::Set,
            6,
            &denied,
        )
        .unwrap();
        assert_permanent_holes(&original, &holes);
        let mut quarantine = vec![[0; 4096]; CACHE_TABLE_COUNT];
        retype_identity_policy(&original, &mut quarantine, POOL, |_, _| {
            Ok(Some(CacheMapping::Quarantine))
        })
        .unwrap();
        assert_permanent_holes(&quarantine, &holes);
        let mut restored = vec![[0; 4096]; CACHE_TABLE_COUNT];
        retype_identity_policy(&quarantine, &mut restored, POOL, |_, _| {
            Ok(Some(CacheMapping::Pat(0)))
        })
        .unwrap();
        assert_permanent_holes(&restored, &holes);
        for hole in holes {
            for address in [hole.base() - 1, hole.last_byte() + 1] {
                assert_eq!(translate(&original, address), Some(address));
                assert_eq!(translate(&restored, address), Some(address));
                assert_eq!(identity_is_quarantined(&quarantine, POOL, address), Ok(true));
            }
        }
    }
}
