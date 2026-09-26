use svmvisor_hypervisor::memory::{
    address::{ADDRESS_MASK, NX},
    npt::{
        CacheMapping, CacheNptError, identity_is_quarantined, retype_identity,
        retype_identity_policy, set_identity_write_range,
    },
};

fn put(tables: &mut [[u8; 4096]], table: usize, index: usize, value: u64) {
    tables[table][index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
}

fn get(tables: &[[u8; 4096]], table: usize, index: usize) -> u64 {
    u64::from_le_bytes(tables[table][index * 8..index * 8 + 8].try_into().unwrap())
}

fn lookup(tables: &[[u8; 4096]], address: u64) -> Option<(u64, u8, bool, bool)> {
    let mut table = 0;
    let mut writable = true;
    let mut executable = true;
    for level in (1..=4).rev() {
        let shift = 12 + 9 * (level - 1);
        let e = get(tables, table, ((address >> shift) & 511) as usize);
        if e & 1 == 0 {
            return None;
        }
        writable &= e & 2 != 0;
        executable &= e & NX == 0;
        if level == 1 || (level < 4 && e & 128 != 0) {
            let pat_bit = if level == 1 { 7 } else { 12 };
            let selector = ((e >> 3) & 3) as u8 | (((e >> pat_bit) & 1) as u8) << 2;
            return Some((1 << shift, selector, writable, executable));
        }
        table = ((e & ADDRESS_MASK) - 0x100000) as usize / 4096;
    }
    unreachable!()
}

fn source() -> Vec<[u8; 4096]> {
    let mut source = vec![[0; 4096]; 4];
    put(&mut source, 0, 0, 0x101007);
    put(&mut source, 1, 0, 0x87);
    put(&mut source, 1, 1, 0x40000087 | NX);
    source
}

#[test]
fn quarantine_round_trip_preserves_holes_and_permissions() {
    let mut original = source();
    // Read-only original mapping must remain read-only after splitting/restoring.
    put(&mut original, 1, 0, 0x85);
    let mut blocked = vec![[0; 4096]; 8];
    retype_identity_policy(&original, &mut blocked, 0x100000, |start, end| {
        if start < 0x100000 && end > 0x100000 {
            Ok(None)
        } else if start < 0x100000 {
            Ok(Some(CacheMapping::Quarantine))
        } else {
            Ok(Some(CacheMapping::Pat(0)))
        }
    })
    .unwrap();
    assert_eq!(lookup(&blocked, 0), None);
    assert_eq!(lookup(&blocked, 0xff000), None);
    assert_eq!(lookup(&blocked, 0x100000), Some((4096, 0, false, true)));
    assert_eq!(lookup(&blocked, 0x80000000), None);
    let mut restored = vec![[0; 4096]; 8];
    retype_identity_policy(&blocked, &mut restored, 0x100000, |_, _| {
        Ok(Some(CacheMapping::Pat(0)))
    })
    .unwrap();
    assert_eq!(lookup(&restored, 0), Some((4096, 0, false, true)));
    assert_eq!(lookup(&restored, 0xff000), Some((4096, 0, false, true)));
    assert_eq!(lookup(&restored, 0x80000000), None);
    assert_eq!(lookup(&restored, 0x40000000), Some((1 << 30, 0, true, false)));
}

#[test]
fn quarantined_large_leaf_can_split_on_later_policy_and_errors_leave_source_unchanged() {
    let original = source();
    let mut blocked = vec![[0; 4096]; 8];
    retype_identity_policy(&original, &mut blocked, 0x100000, |_, _| {
        Ok(Some(CacheMapping::Quarantine))
    })
    .unwrap();
    let saved = blocked.clone();
    let mut restored = vec![[0; 4096]; 8];
    retype_identity_policy(&blocked, &mut restored, 0x100000, |start, end| {
        if start == 0 && end > 4096 {
            Ok(None)
        } else if start == 0 {
            Ok(Some(CacheMapping::Quarantine))
        } else {
            Ok(Some(CacheMapping::Pat(4)))
        }
    })
    .unwrap();
    assert_eq!(lookup(&restored, 0), None);
    assert_eq!(lookup(&restored, 4096), Some((4096, 4, true, true)));
    assert_eq!(blocked, saved);
    assert_eq!(
        retype_identity_policy(&blocked, &mut restored, 0x100000, |_, _| {
            Err(CacheNptError::MemoryType)
        }),
        Err(CacheNptError::MemoryType)
    );
    assert_eq!(blocked, saved);
}

#[test]
fn quarantine_query_distinguishes_low_holes_and_never_restores_them() {
    let mut original = source();
    put(&mut original, 1, 0, 0x102007);
    put(&mut original, 2, 0, 0x103005);
    put(&mut original, 3, 0, 0x7);
    put(&mut original, 3, 2, 0x2007 | NX);
    let mut blocked = vec![[0; 4096]; 8];
    retype_identity_policy(&original, &mut blocked, 0x100000, |_, _| {
        Ok(Some(CacheMapping::Quarantine))
    })
    .unwrap();
    assert_eq!(identity_is_quarantined(&blocked, 0x100000, 0x123), Ok(true));
    assert_eq!(identity_is_quarantined(&blocked, 0x100000, 0x1000), Ok(false));
    assert_eq!(identity_is_quarantined(&blocked, 0x100000, 0x2000), Ok(true));
    assert_eq!(identity_is_quarantined(&blocked, 0x100000, 0x80000000), Ok(false));
    let mut restored = vec![[0; 4096]; 8];
    retype_identity_policy(&blocked, &mut restored, 0x100000, |_, _| {
        Ok(Some(CacheMapping::Pat(0)))
    })
    .unwrap();
    assert_eq!(lookup(&restored, 0), Some((4096, 0, false, true)));
    assert_eq!(lookup(&restored, 0x1000), None);
    assert_eq!(lookup(&restored, 0x2000), Some((4096, 0, false, false)));
    assert_eq!(identity_is_quarantined(&restored, 0x100000, 0x123), Ok(false));
    // An inaccessible table link is not a cache-owned leaf and cannot be restored.
    put(&mut blocked, 0, 0, 0x101406);
    assert_eq!(identity_is_quarantined(&blocked, 0x100000, 0), Err(CacheNptError::Entry));
    assert_eq!(
        retype_identity_policy(&blocked, &mut restored, 0x100000, |_, _| {
            Ok(Some(CacheMapping::Pat(0)))
        }),
        Err(CacheNptError::Entry)
    );
    put(&mut blocked, 0, 0, 0x101087);
    assert_eq!(identity_is_quarantined(&blocked, 0x100000, 0), Err(CacheNptError::Entry));
}

#[test]
fn pat_selectors_use_bit12_for_large_leaves_and_bit7_for_small_leaves() {
    for selector in 0..8 {
        let source = source();
        let mut target = vec![[0; 4096]; 8];
        let used = retype_identity(&source, &mut target, 0x100000, |start, end| {
            if start < 0x2000 && end > 0x1000 && end - start > 4096 {
                Ok(None)
            } else {
                Ok(Some(selector))
            }
        })
        .unwrap();
        assert_eq!(used, 4);
        assert_eq!(lookup(&target, 0x1000), Some((4096, selector, true, true)));
        assert_eq!(lookup(&target, 0x200000), Some((1 << 21, selector, true, true)));
        assert_eq!(lookup(&target, 0x40000000), Some((1 << 30, selector, true, false)));
        assert_eq!(lookup(&target, 0x80000000), None);
    }
}

#[test]
fn exclusions_and_configuration_permissions_survive_retyping_and_later_revocation() {
    let mut source = source();
    put(&mut source, 1, 0, 0x102007);
    put(&mut source, 2, 0, 0);
    put(&mut source, 2, 1, 0x200085);
    let original = source.clone();
    let mut target = vec![[0; 4096]; 8];
    retype_identity(&source, &mut target, 0x100000, |start, end| {
        if start == 0x200000 && end - start > 4096 { Ok(None) } else { Ok(Some(4)) }
    })
    .unwrap();
    assert_eq!(source, original);
    assert_eq!(lookup(&target, 0), None);
    assert_eq!(lookup(&target, 0x200000), Some((4096, 4, false, true)));
    set_identity_write_range(&mut target, 0x100000, 0x200000, 0x200000, true).unwrap();
    assert_eq!(lookup(&target, 0x200000), Some((4096, 4, true, true)));
    assert_eq!(lookup(&target, 0), None);
}

#[test]
fn capacity_and_bad_type_failures_never_change_the_source() {
    let source = source();
    let before = source.clone();
    let mut target = vec![[0; 4096]; 2];
    assert_eq!(
        retype_identity(&source, &mut target, 0x100000, |_, _| Ok(None)),
        Err(CacheNptError::Storage)
    );
    assert_eq!(source, before);
    assert_eq!(
        retype_identity(&source, &mut target, 0x100000, |_, _| Ok(Some(8))),
        Err(CacheNptError::MemoryType)
    );
    assert_eq!(source, before);
}

#[test]
fn configuration_revocation_preserves_large_leaf_pat_selectors() {
    for selector in 0..8 {
        let mut source = source();
        put(&mut source, 1, 0, 0x102007);
        put(&mut source, 2, 1, 0x200085);
        let mut target = vec![[0; 4096]; 8];
        retype_identity(&source, &mut target, 0x100000, |_, _| Ok(Some(selector))).unwrap();
        assert_eq!(lookup(&target, 0x200000), Some((1 << 21, selector, false, true)));
        set_identity_write_range(&mut target, 0x100000, 0x200000, 0x200000, true).unwrap();
        assert_eq!(lookup(&target, 0x200000), Some((1 << 21, selector, true, true)));
    }
}
