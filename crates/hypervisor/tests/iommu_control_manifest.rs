//! Exercise the native producer, scalar handoff and firmware NPT/cache consumers
//! together. Disconnected memory only; no firmware or hardware effects.
mod ownership_support;

use ownership_support::{policy, report, report_with_mmio_stride};
use svmvisor_hypervisor::{
    arch::x86_64::{capabilities::EvidenceFlag as F, msr::TARGET_SIGNATURE},
    boot::memory::MemoryDescriptor,
    firmware::native::resident::{
        iommu::{HardwareError, UnitObservation, control::manifest_from_report},
        memory::prepare_identity_npt_with_denials,
    },
    host::resident::{
        SHARED_RETAINED_BYTES,
        control::{ControlManifest, ControlManifestError},
    },
    memory::{
        address::{AddressPolicy, EncryptionState},
        npt::{
            CACHE_TABLE_COUNT, CacheMapping, ControlPageDenials, NptEvidence,
            identity_is_quarantined, retype_identity_policy_with_denials,
        },
    },
};

const ROUTE: u64 = 0xe000_0021;
const POOL: u64 = 0x1000_0000;
const ROOT: u64 = POOL + 0x80000;
const POOL_BYTES: u64 = 2 * 0x100000 + SHARED_RETAINED_BYTES;

#[test]
fn known_fch_controls_are_denied_even_when_outside_every_iommu_aperture() {
    let report = ownership_support::report_with_mmio_base(1, 0xfd00_0000, 0x4000);
    let manifest = manifest_from_report(&report, policy(), TARGET_SIGNATURE, ROUTE, 2).unwrap();
    assert_eq!(
        denials(&manifest).ranges(),
        &[(0xe0100000, 0xe0101000), (0xfd000000, 0xfd004000), (0xfed80000, 0xfed81000)]
    );
}

fn denials(manifest: &ControlManifest) -> ControlPageDenials {
    manifest
        .denials(
            policy(),
            TARGET_SIGNATURE,
            ROUTE,
            2,
            policy().validate(POOL, POOL_BYTES, 4096).unwrap(),
        )
        .unwrap()
}

/// Independent hardware-format walker, including accumulated write permission.
fn translation(storage: &[[u8; 4096]], address: u64) -> Option<(u64, bool)> {
    let mut table = 0;
    let mut writable = true;
    for level in (1..=4).rev() {
        let bytes = 1u64 << (12 + 9 * (level - 1));
        let index = ((address / bytes) & 511) as usize;
        let entry =
            u64::from_le_bytes(storage[table][index * 8..index * 8 + 8].try_into().unwrap());
        if entry & 1 == 0 {
            return None;
        }
        writable &= entry & 2 != 0;
        let base = entry & 0x000f_ffff_ffff_f000;
        if level == 1 || level < 4 && entry & 128 != 0 {
            let pat = if level == 1 { 0 } else { 1 << 12 };
            return Some(((base & !pat) | (address & (bytes - 1)), writable));
        }
        table = usize::try_from((base - ROOT) / 4096).unwrap();
        assert!(table < storage.len());
    }
    unreachable!()
}

#[test]
fn native_producer_to_boot_and_cache_rebuild_excludes_every_control_and_pool_page() {
    let report = report_with_mmio_stride(2, 0x200000);
    let manifest = manifest_from_report(&report, policy(), TARGET_SIGNATURE, ROUTE, 2).unwrap();
    assert!(manifest.is_complete());
    let denied = denials(&manifest);
    assert_eq!(
        denied.ranges(),
        &[
            (0xe0100000, 0xe0102000),
            (0xfd000000, 0xfd004000),
            (0xfd200000, 0xfd204000),
            (0xfed80000, 0xfed81000)
        ]
    );
    let pool = policy().validate(POOL, POOL_BYTES, 4096).unwrap();
    let map = [MemoryDescriptor {
        memory_type: 6,
        physical_start: POOL,
        page_count: POOL_BYTES / 4096,
        attributes: (1 << 63) | 8,
    }];
    let evidence = NptEvidence { nx_supported: F::Set, host_nxe: F::Set, host_four_level: F::Set };
    let mut initial = vec![[0xa5; 4096]; CACHE_TABLE_COUNT];
    let mut npt = prepare_identity_npt_with_denials(
        &mut initial,
        ROOT,
        policy(),
        pool,
        &map,
        evidence,
        F::Set,
        6,
        &denied,
    )
    .unwrap();
    // The real resident owns64 pages. The historical eight-page prefix cannot
    // describe this full resource pool and both independent control extents.
    assert!(npt.used_tables() > 8);
    npt.protect_write_range(0xe0000000, 0x10000000).unwrap();
    drop(npt);
    let mut quarantined = vec![[0; 4096]; CACHE_TABLE_COUNT];
    retype_identity_policy_with_denials(
        &initial,
        &mut quarantined,
        ROOT,
        policy(),
        &denied,
        |_, _| Ok(Some(CacheMapping::Quarantine)),
    )
    .unwrap();
    let mut restored = vec![[0; 4096]; CACHE_TABLE_COUNT];
    retype_identity_policy_with_denials(
        &quarantined,
        &mut restored,
        ROOT,
        policy(),
        &denied,
        |_, _| Ok(Some(CacheMapping::Pat(0))),
    )
    .unwrap();
    for storage in [&initial, &quarantined, &restored] {
        for &(base, end) in
            denied.ranges().iter().chain(core::iter::once(&(POOL, POOL + POOL_BYTES)))
        {
            for page in (base..end).step_by(4096) {
                for address in [page, page + 4095] {
                    assert_eq!(translation(storage, address), None, "{address:#x}");
                    assert_eq!(identity_is_quarantined(storage, ROOT, address), Ok(false));
                }
            }
        }
    }
    for address in [POOL - 1, POOL + POOL_BYTES, 0xfcffffff, 0xfd008000, 0xfed7ffff, 0xfed81000] {
        assert_eq!(translation(&restored, address), Some((address, true)));
    }
    for address in [0xe00fffff, 0xe0102000] {
        assert_eq!(translation(&restored, address), Some((address, false)));
    }
}

#[test]
fn incomplete_or_inconsistent_apertures_never_yield_a_partial_complete_manifest() {
    for change in 0..7 {
        let mut report = report(2);
        match change {
            0 => report.hardware[1] = UnitObservation::EMPTY,
            1 => report.hardware[1].error = Some(HardwareError::ChangingConfiguration),
            2 => report.hardware[1].pci.as_mut().unwrap().base_low ^= 0x4000,
            3 => report.hardware[1].pci.as_mut().unwrap().base_low &= !1,
            4 => report.hardware[1].pci.as_mut().unwrap().config_page += 4096,
            5 => report.hardware[1].mmio_bytes = Some(0x80000),
            6 => report.hardware[1].registers = None,
            _ => unreachable!(),
        }
        let manifest = manifest_from_report(&report, policy(), TARGET_SIGNATURE, ROUTE, 2).unwrap();
        assert!(!manifest.is_complete(), "mutation {change}");
        assert!(denials(&manifest).is_empty());
    }
    let report = ownership_support::report_with_mmio_base(1, 0xfed80000, 0x4000);
    assert!(
        !manifest_from_report(&report, policy(), TARGET_SIGNATURE, ROUTE, 2).unwrap().is_complete()
    );
}

#[test]
fn performance_counters_exclude_the_complete_larger_aperture() {
    let mut report = report(1);
    report.hardware[0].mmio_bytes = Some(0x80000);
    report.hardware[0].registers.as_mut().unwrap().extended_features = Some((1 << 6) | (1 << 9));
    let manifest = manifest_from_report(&report, policy(), TARGET_SIGNATURE, ROUTE, 2).unwrap();
    assert!(manifest.is_complete());
    let denied = denials(&manifest);
    assert!(denied.contains(0xfd000000));
    assert!(denied.contains(0xfd07ffff));
    assert!(!denied.contains(0xfd080000));
    assert!(denied.contains(0xfed80000));
}

#[test]
fn handoff_rejects_route_cpu_profile_participant_and_pool_changes() {
    let manifest = manifest_from_report(&report(1), policy(), TARGET_SIGNATURE, ROUTE, 2).unwrap();
    let pool = policy().validate(POOL, POOL_BYTES, 4096).unwrap();
    for (signature, bits, route, count) in [
        (TARGET_SIGNATURE ^ 1, 48, ROUTE, 2),
        (TARGET_SIGNATURE, 47, ROUTE, 2),
        (TARGET_SIGNATURE, 48, ROUTE ^ (1 << 28), 2),
        (TARGET_SIGNATURE, 48, ROUTE, 3),
    ] {
        let policy =
            AddressPolicy::new(bits, EncryptionState::Unencrypted { encryption_bit: None })
                .unwrap();
        assert_eq!(
            manifest.denials(policy, signature, route, count, pool),
            Err(ControlManifestError::Context)
        );
    }
    assert_eq!(
        manifest.denials(
            policy(),
            TARGET_SIGNATURE,
            ROUTE,
            2,
            policy().validate(0xfed80000, 4096, 4096).unwrap()
        ),
        Err(ControlManifestError::PoolOverlap)
    );
    assert!(ControlManifest::new(policy(), TARGET_SIGNATURE, ROUTE, 2, &[]).is_err());
}
