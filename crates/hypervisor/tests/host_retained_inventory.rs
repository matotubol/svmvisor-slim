//! Independent page walks of retained observation/resource mappings, without hardware.
use svmvisor_hypervisor::{
    arch::x86_64::capabilities::EvidenceFlag,
    host::{
        paging::{self, PagingConfig},
        resident::{
            IOMMU_COMPOSITION_BYTES, IOMMU_RESOURCE_BYTES, IOMMU_RETAINED_BYTES, IOMMU_UNIT_STRIDE,
            MAX_NATIVE_IOMMU_UNITS, SHARED_RETAINED_BYTES,
            inventory::{HOST_TABLE_PAGES, map_retained_backing},
            is_valid_pool_slot, native_iommu_resources, pool_bytes_for_processors,
            pool_processor_count, retained_iommu_base,
        },
    },
    memory::{
        address::{ADDRESS_MASK, AddressPolicy, EncryptionState},
        npt::{CacheMapping, IdentityNpt, NptEvidence, TableStorage, retype_identity_policy},
    },
};

fn prepared(root: u64, base: u64) -> [[u64; 512]; HOST_TABLE_PAGES] {
    let mut tables = [[0; 512]; HOST_TABLE_PAGES];
    tables[0][0] = (root + 4096) | 3;
    tables[1][0] = (root + 8192) | 3;
    tables[2][((base >> 21) & 511) as usize] = (root + 12288) | 3;
    // One code page, one RW/NX page and the otherwise absent guard/alias pages.
    tables[3][((base >> 12) & 511) as usize] = base | 1;
    tables[3][(((base + 4096) >> 12) & 511) as usize] = (base + 4096) | 3 | (1 << 63);
    tables
}

#[test]
fn all_private_roots_map_observation_read_only_and_unit_resources_writable() {
    for count in 1..=32 {
        let pool = 0x200000;
        let bytes = pool_bytes_for_processors(count).unwrap();
        let tail = retained_iommu_base(pool, bytes).unwrap();
        for slot in 0..count {
            let base = pool + slot as u64 * 0x100000;
            let root = base + 0x10000;
            let mut tables = prepared(root, base);
            let original = tables;
            assert!(map_retained_backing(&mut tables, root, base, pool, bytes));
            let cfg = PagingConfig {
                cr3: root,
                physical_bits: 48,
                la57: false,
                nxe: true,
                pcid: false,
                page1gb: true,
            };
            let walk = |address| {
                paging::translate(cfg, address, |entry| {
                    let offset = entry.checked_sub(root)? as usize;
                    tables
                        .get(offset / 4096)
                        .and_then(|page| page.get((offset % 4096) / 8))
                        .copied()
                })
            };
            for page in (tail..tail + SHARED_RETAINED_BYTES).step_by(4096) {
                for edge in [0, 4095] {
                    let actual = walk(page + edge).unwrap();
                    assert_eq!(actual.physical_address, page + edge);
                    assert!(!actual.user && !actual.executable);
                    assert_eq!(actual.writable, page >= tail + IOMMU_RETAINED_BYTES);
                    assert_eq!(actual.pat_index, 0);
                }
            }
            assert!(walk(base).unwrap().executable);
            assert!(walk(base + 4096).unwrap().writable);
            assert!(walk(base + 8192).is_err());
            assert!(walk(tail - 1).is_err());
            assert!(walk(tail + SHARED_RETAINED_BYTES).is_err());
            let shared_directory = base >> 21 == tail >> 21;
            if shared_directory {
                assert_eq!(tables[5], [0; 512]);
            }
            // All original local PTEs, including guard holes, remain exact.
            for page in (base..base + 0x100000).step_by(4096) {
                let index = ((page >> 12) & 511) as usize;
                assert_eq!(tables[3][index], original[3][index]);
            }
        }
    }
}

#[test]
fn invalid_pool_or_conflicting_root_is_rejected_before_any_mapping_write() {
    let root = 0x210000;
    let base = 0x200000;
    let bytes = pool_bytes_for_processors(2).unwrap();
    let tail = retained_iommu_base(base, bytes).unwrap();
    for case in 0..9 {
        let mut tables = prepared(root, base);
        let (mut chosen_root, mut chosen_base, mut chosen_bytes) = (root, base, bytes);
        match case {
            0 => chosen_bytes -= SHARED_RETAINED_BYTES,
            1 => chosen_root += 1,
            2 => chosen_base = tail,
            3 => tables[0][0] |= 4,
            4 => tables[2][((tail >> 21) & 511) as usize] = 0x123003,
            5 => tables[4][511] = 1,
            6 => tables[5][0] = 1,
            7 => tables[2][((tail >> 21) & 511) as usize + 1] = 0x123003,
            _ => tables[2][((base >> 21) & 511) as usize] = 0,
        }
        let before = tables;
        assert!(!map_retained_backing(&mut tables, chosen_root, chosen_base, base, chosen_bytes));
        assert_eq!(tables, before);
    }
    let mut tables = prepared(root, base);
    let one = pool_bytes_for_processors(1).unwrap();
    tables[3][256] = 1; // Tail shares the local PT in a one-CPU pool.
    let before = tables;
    assert!(!map_retained_backing(&mut tables, root, base, base, one));
    assert_eq!(tables, before);
}

#[test]
fn pool_extent_includes_tail_and_cannot_be_decoded_as_another_cpu() {
    for count in 1..=32 {
        let bytes = pool_bytes_for_processors(count).unwrap();
        assert_eq!(bytes, count as u64 * 0x100000 + 0x3262000);
        assert_eq!(pool_processor_count(bytes), Some(count));
        assert_eq!(pool_processor_count(bytes - 0x3262000), None);
        assert_eq!(pool_processor_count(bytes + 4096), None);
        let highest = (0x40000000 - bytes) & !0x1fffff;
        assert!(retained_iommu_base(highest, bytes).is_some());
        assert!(retained_iommu_base(highest + 0x200000, bytes).is_none());
        assert!(!is_valid_pool_slot(
            highest + count as u64 * 0x100000,
            highest,
            bytes,
            count as u64,
            0
        ));
    }
    for count in [0, 33, usize::MAX] {
        assert_eq!(pool_bytes_for_processors(count), None);
    }
    for base in [0, 0x100000, 0x280000, u64::MAX & !0x1fffff] {
        assert_eq!(retained_iommu_base(base, 0x110000), None);
    }
}

fn nested_present(tables: &[[u8; 4096]], root: u64, address: u64) -> bool {
    let mut table = 0;
    for level in (1..=4).rev() {
        let index = ((address >> (12 + 9 * (level - 1))) & 511) as usize;
        let word = u64::from_le_bytes(tables[table][index * 8..index * 8 + 8].try_into().unwrap());
        if word & 1 == 0 {
            return false;
        }
        if level == 1 || level < 4 && word & 128 != 0 {
            return true;
        }
        table = ((word & ADDRESS_MASK) - root) as usize / 4096;
    }
    unreachable!()
}

#[test]
fn maximum_pool_tail_remains_absent_after_quarantine_and_cache_restoration() {
    let base = 0x200000;
    let bytes = pool_bytes_for_processors(32).unwrap();
    let tail = retained_iommu_base(base, bytes).unwrap();
    let policy =
        AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: None }).unwrap();
    let mut source = TableStorage([[0; 4096]; 8]);
    IdentityNpt::new(
        &mut source,
        base,
        policy,
        policy.validate(base, bytes, 4096).unwrap(),
        NptEvidence {
            nx_supported: EvidenceFlag::Set,
            host_nxe: EvidenceFlag::Set,
            host_four_level: EvidenceFlag::Set,
        },
        EvidenceFlag::Set,
        6,
    )
    .unwrap();
    let mut quarantined = vec![[0; 4096]; 64];
    retype_identity_policy(&source.0, &mut quarantined, base, |_, _| {
        Ok(Some(CacheMapping::Quarantine))
    })
    .unwrap();
    let mut restored = vec![[0; 4096]; 64];
    retype_identity_policy(&quarantined, &mut restored, base, |_, _| {
        Ok(Some(CacheMapping::Pat(0)))
    })
    .unwrap();
    for tables in [&source.0[..], &quarantined[..], &restored[..]] {
        for page in (base..base + bytes).step_by(4096) {
            assert!(!nested_present(tables, base, page));
            assert!(!nested_present(tables, base, page + 4095));
        }
        assert!(!nested_present(tables, base, tail - 1));
        assert!(!nested_present(tables, base, base));
    }
    for tables in [&source.0[..], &restored[..]] {
        assert!(nested_present(tables, base, base - 1));
        assert!(nested_present(tables, base, base + bytes));
    }
}

#[test]
fn every_unit_has_disjoint_bank_and_two_complete_retained_generations() {
    assert_eq!(MAX_NATIVE_IOMMU_UNITS, 4);
    assert_eq!(IOMMU_UNIT_STRIDE, 0x810000);
    assert_eq!(IOMMU_RESOURCE_BYTES, 0x210000);
    assert_eq!(IOMMU_COMPOSITION_BYTES, 0x300000);
    for count in [1, 2, 3, 24, 32] {
        let pool = 0x200000;
        let bytes = pool_bytes_for_processors(count).unwrap();
        let tail = retained_iommu_base(pool, bytes).unwrap();
        let mut next = tail + 0x10000;
        for unit in 0..4 {
            let actual = native_iommu_resources(pool, bytes, unit).unwrap();
            assert_eq!(actual.bank, next);
            assert_eq!(actual.generations, [next + 0x210000, next + 0x510000]);
            assert_eq!(actual.generations[1] + 0x300000, next + 0x810000);
            next += 0x810000;
        }
        let shared = svmvisor_hypervisor::host::resident::native_iommu_shared(pool, bytes).unwrap();
        assert_eq!(shared.presentation, next);
        assert_eq!(shared.workspace, next + 0x12000);
        assert_eq!(shared.workspace + 0x1200000, pool + bytes);
        assert_eq!(shared.presentation & 4095, 0);
        assert_eq!(shared.workspace & 4095, 0);
        assert_eq!(native_iommu_resources(pool, bytes, 4), None);
        assert_eq!(native_iommu_resources(pool, bytes, usize::MAX), None);
        assert_eq!(native_iommu_resources(pool, bytes - 4096, 0), None);
        assert_eq!(native_iommu_resources(pool + 4096, bytes, 0), None);
    }
}
