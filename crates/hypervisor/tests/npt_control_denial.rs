//! Independent walks of emitted NPT bytes; no physical or device access.

use std::collections::BTreeSet;
use svmvisor_hypervisor::{
    arch::x86_64::capabilities::EvidenceFlag,
    memory::{
        address::{ADDRESS_MASK, AddressPolicy, EncryptionState, NX, PhysicalRange},
        npt::{
            CACHE_TABLE_COUNT, CacheMapping, CacheNptError, ControlPageDenialError,
            ControlPageDenials, IdentityNpt, IdentityNptError, MAX_CONTROL_PAGE_RANGES,
            NptEvidence, identity_is_quarantined, retype_identity_policy,
            retype_identity_policy_with_denials, set_identity_write_range,
        },
    },
};

const ROOT: u64 = 0x200000;
const MONITOR_BYTES: u64 = 0x100000;
const DOMAIN: u64 = 1 << 40;

fn policy(bits: u8) -> AddressPolicy {
    AddressPolicy::new(bits, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

fn evidence() -> NptEvidence {
    NptEvidence {
        nx_supported: EvidenceFlag::Set,
        host_nxe: EvidenceFlag::Set,
        host_four_level: EvidenceFlag::Set,
    }
}

fn ranges(values: &[(u64, u64)]) -> Vec<PhysicalRange> {
    values.iter().map(|&(base, bytes)| policy(52).validate(base, bytes, 1).unwrap()).collect()
}

fn denial(values: &[(u64, u64)]) -> ControlPageDenials {
    ControlPageDenials::new(policy(48), &ranges(values)).unwrap()
}

fn build<'a>(
    storage: &'a mut [[u8; 4096]],
    denied: &ControlPageDenials,
) -> Result<IdentityNpt<'a>, IdentityNptError> {
    IdentityNpt::new_with_denied_ranges(
        storage,
        ROOT,
        policy(48),
        policy(48).validate(ROOT, MONITOR_BYTES, 4096).unwrap(),
        evidence(),
        EvidenceFlag::Set,
        6,
        denied,
    )
}

fn word(storage: &[[u8; 4096]], table: usize, index: usize) -> u64 {
    u64::from_le_bytes(storage[table][index * 8..index * 8 + 8].try_into().unwrap())
}

fn put(storage: &mut [[u8; 4096]], table: usize, index: usize, value: u64) {
    storage[table][index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
}

/// Return terminal entry location and accumulated architectural permissions.
fn walk(storage: &[[u8; 4096]], gpa: u64) -> (usize, usize, u64, u64, bool, bool) {
    let mut table = 0;
    let mut writable = true;
    let mut executable = true;
    for level in (1..=4).rev() {
        let length = 1 << (12 + 9 * (level - 1));
        let index = ((gpa / length) & 511) as usize;
        let entry = word(storage, table, index);
        writable &= entry & 2 != 0;
        executable &= entry & NX == 0;
        if entry & 1 == 0 || level == 1 || level < 4 && entry & 128 != 0 {
            return (table, index, entry, length, writable, executable);
        }
        table = usize::try_from(((entry & ADDRESS_MASK) - ROOT) / 4096).unwrap();
        assert!(table > 0 && table < storage.len());
    }
    unreachable!()
}

fn present(storage: &[[u8; 4096]], gpa: u64) -> Option<(u64, bool, bool)> {
    let (_, _, entry, bytes, writable, executable) = walk(storage, gpa);
    if entry & 1 == 0 {
        None
    } else {
        let pat = if bytes == 4096 { 0 } else { 1 << 12 };
        let host = (entry & ADDRESS_MASK & !pat) | (gpa & (bytes - 1));
        Some((host, writable, executable))
    }
}

fn assert_absent(storage: &[[u8; 4096]], address: u64) {
    assert_eq!(present(storage, address), None, "{address:#x}");
    assert_eq!(walk(storage, address).2, 0, "permanent hole at {address:#x}");
    assert_eq!(identity_is_quarantined(storage, ROOT, address), Ok(false));
}

fn audit_tree(storage: &[[u8; 4096]], denied: &ControlPageDenials) -> usize {
    fn visit(
        storage: &[[u8; 4096]],
        table: usize,
        level: u32,
        start: u64,
        denied: &ControlPageDenials,
        seen: &mut BTreeSet<usize>,
    ) {
        assert!(seen.insert(table), "no table aliases");
        let length = 1u64 << (12 + 9 * (level - 1));
        for index in 0..512 {
            let e = word(storage, table, index);
            if e == 0 {
                continue;
            }
            assert_eq!(e & 1, 1, "no restorable marker in initial tree");
            let base = start + index as u64 * length;
            if level == 1 || level < 4 && e & 128 != 0 {
                assert_eq!(e & ADDRESS_MASK, base, "every present leaf is identity");
                assert!(base + length <= ROOT || base >= ROOT + MONITOR_BYTES);
                for &(first, limit) in denied.ranges() {
                    assert!(base + length <= first || base >= limit);
                }
            } else {
                let child = usize::try_from(((e & ADDRESS_MASK) - ROOT) / 4096).unwrap();
                assert!(child < storage.len());
                visit(storage, child, level - 1, base, denied, seen);
            }
        }
    }
    let mut seen = BTreeSet::new();
    visit(storage, 0, 4, 0, denied, &mut seen);
    for (index, page) in storage.iter().enumerate() {
        if !seen.contains(&index) {
            assert!(page.iter().all(|&byte| byte == 0), "unused table {index}");
        }
    }
    seen.len()
}

#[test]
fn exact_control_pages_cross_all_directory_boundaries_and_never_alias() {
    let controls = [
        (0, 4096),
        (ROOT + 0x80000, 4096), // Already in the monitor exclusion.
        ((1 << 21) * 3 - 4096, 8192),
        ((1 << 30) - 4096, 3 * 4096),
        ((1 << 39) - 4096, 8192),
        (DOMAIN - 4096, 4096),
    ];
    let denied = denial(&controls);
    let mut storage = vec![[0xa5; 4096]; CACHE_TABLE_COUNT];
    let used;
    {
        let npt = build(&mut storage, &denied).unwrap();
        assert_eq!(npt.denied_ranges(), &denied);
        used = npt.used_tables();
        for &(base, bytes) in &controls {
            for page in (base..base + bytes).step_by(4096) {
                for address in [page, page + 4095] {
                    assert_eq!(npt.translate(address), Ok(None));
                }
            }
        }
    }
    assert_eq!(audit_tree(&storage, &denied), used);
    for &(base, bytes) in &controls {
        for page in (base..base + bytes).step_by(4096) {
            assert_absent(&storage, page);
            assert_absent(&storage, page + 4095);
        }
        for neighbor in [base.checked_sub(1), base.checked_add(bytes)] {
            if let Some(address) =
                neighbor.filter(|&a| a < DOMAIN && !(ROOT..ROOT + MONITOR_BYTES).contains(&a))
            {
                assert_eq!(present(&storage, address), Some((address, true, true)));
            }
        }
    }
    // Assigned backing remains denied, including every unused page.
    for page in 0..CACHE_TABLE_COUNT {
        assert_absent(&storage, ROOT + (page * 4096) as u64);
        assert_absent(&storage, ROOT + (page * 4096 + 4095) as u64);
    }
}

#[test]
fn overlapping_monitor_and_adjacent_denials_form_holes_without_neighbor_loss() {
    let denied = denial(&[
        (ROOT - 4096, 8192),
        (ROOT + MONITOR_BYTES - 4096, 8192),
        (0x40000000, 0x200000),
        (0x40200000, 0x3fe00000),
    ]);
    let mut storage = vec![[0; 4096]; CACHE_TABLE_COUNT];
    let used = build(&mut storage, &denied).unwrap().used_tables();
    assert_eq!(audit_tree(&storage, &denied), used);
    for address in [ROOT - 4096, ROOT, ROOT + MONITOR_BYTES, 0x40000000, 0x7fffffff] {
        assert_absent(&storage, address);
    }
    assert_eq!(walk(&storage, 0x60000000).3, 1 << 30);
    for address in [ROOT - 4097, ROOT + MONITOR_BYTES + 4096, 0x3fffffff, 0x80000000] {
        assert_eq!(present(&storage, address), Some((address, true, true)));
    }
}

#[test]
fn complete_page_policy_rejects_partial_unsorted_overlapping_and_excess_ranges() {
    let p = policy(48);
    assert_eq!(ControlPageDenials::new(p, &[]), Ok(ControlPageDenials::EMPTY));
    for input in [&[(1, 4096)][..], &[(4096, 1)][..], &[(4096, 4097)][..]] {
        assert!(ControlPageDenials::new(p, &ranges(input)).is_err());
    }
    for input in [&[(8192, 4096), (4096, 4096)][..], &[(4096, 8192), (8192, 4096)][..]] {
        assert_eq!(
            ControlPageDenials::new(p, &ranges(input)),
            Err(ControlPageDenialError::UnsortedOrOverlapping)
        );
    }
    let input: Vec<_> = (0..MAX_CONTROL_PAGE_RANGES + 1)
        .map(|index| p.validate(index as u64 * 4096, 4096, 4096).unwrap())
        .collect();
    assert!(ControlPageDenials::new(p, &input[..MAX_CONTROL_PAGE_RANGES]).is_ok());
    assert_eq!(ControlPageDenials::new(p, &input), Err(ControlPageDenialError::Capacity));
}

#[test]
fn range_physical_width_encryption_and_identity_domain_are_separate_checks() {
    assert!(matches!(
        ControlPageDenials::new(policy(32), &ranges(&[(1 << 32, 4096)])),
        Err(ControlPageDenialError::Address(_))
    ));
    assert_eq!(
        ControlPageDenials::new(policy(52), &ranges(&[(DOMAIN, 4096)])),
        Err(ControlPageDenialError::OutsideIdentityDomain)
    );
    assert!(ControlPageDenials::new(policy(52), &ranges(&[(DOMAIN - 4096, 4096)])).is_ok());
    let encrypted_bit =
        AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: Some(32) }).unwrap();
    assert!(matches!(
        ControlPageDenials::new(encrypted_bit, &ranges(&[((1 << 32) - 4096, 8192)])),
        Err(ControlPageDenialError::Address(_))
    ));
}

#[test]
fn constructor_capacity_and_full_backing_checks_are_transactional() {
    let denied = denial(&[(0x40001000, 4096), (0x80001000, 4096)]);
    for capacity in [0, 1, 6, CACHE_TABLE_COUNT + 1] {
        let mut storage = vec![[0xa5; 4096]; capacity];
        let saved = storage.clone();
        assert!(matches!(build(&mut storage, &denied), Err(IdentityNptError::StorageBounds)));
        assert_eq!(storage, saved);
    }
    let mut storage = vec![[0xa5; 4096]; 9];
    assert_eq!(build(&mut storage, &denied).unwrap().used_tables(), 9);
    let mut exact = vec![[0xa5; 4096]; 8];
    let saved = exact.clone();
    assert!(matches!(build(&mut exact, &denied), Err(IdentityNptError::StorageBounds)));
    assert_eq!(exact, saved);

    // The used tree would fit; the complete assigned arena does not fit.
    let mut storage = vec![[0xa5; 4096]; CACHE_TABLE_COUNT];
    let saved = storage.clone();
    assert!(matches!(
        IdentityNpt::new_with_denied_ranges(
            &mut storage,
            ROOT,
            policy(48),
            policy(48).validate(ROOT, 0x20000, 4096).unwrap(),
            evidence(),
            EvidenceFlag::Set,
            6,
            &ControlPageDenials::EMPTY,
        ),
        Err(IdentityNptError::TableArenaOutsideExclusion)
    ));
    assert_eq!(storage, saved);
}

#[test]
fn construction_revalidates_a_policy_created_for_a_wider_physical_domain() {
    let denied = denial(&[(1 << 35, 4096)]);
    let mut storage = vec![[0xa5; 4096]; CACHE_TABLE_COUNT];
    let saved = storage.clone();
    assert!(matches!(
        IdentityNpt::new_with_denied_ranges(
            &mut storage,
            ROOT,
            policy(32),
            policy(32).validate(ROOT, MONITOR_BYTES, 4096).unwrap(),
            evidence(),
            EvidenceFlag::Set,
            6,
            &denied,
        ),
        Err(IdentityNptError::ControlDenial(ControlPageDenialError::Address(_)))
    ));
    assert_eq!(storage, saved);
}

#[test]
fn range_capacity_does_not_promise_unavailable_table_capacity() {
    let input: Vec<_> =
        (1..=MAX_CONTROL_PAGE_RANGES).map(|index| ((index as u64) << 30 | 4096, 4096)).collect();
    let denied = denial(&input);
    let mut storage = vec![[0xa5; 4096]; CACHE_TABLE_COUNT];
    let saved = storage.clone();
    assert!(matches!(build(&mut storage, &denied), Err(IdentityNptError::StorageBounds)));
    assert_eq!(storage, saved);
    // Five initial pages plus two for each of 29 scattered control pages.
    let denied = denial(&input[..29]);
    assert_eq!(build(&mut storage, &denied).unwrap().used_tables(), 63);
    assert_eq!(audit_tree(&storage, &denied), 63);
    let denied = denial(&input[..30]);
    let saved = storage.clone();
    assert!(matches!(build(&mut storage, &denied), Err(IdentityNptError::StorageBounds)));
    assert_eq!(storage, saved);
}

#[test]
fn diagnostic_write_changes_never_reopen_partial_or_complete_control_holes() {
    let denied = denial(&[(0xe0010000, 4096), (0xe0400000, 0x200000)]);
    let mut storage = vec![[0; 4096]; CACHE_TABLE_COUNT];
    {
        let mut npt = build(&mut storage, &denied).unwrap();
        npt.protect_write_range(0xe0000000, 0x1000000).unwrap();
        assert!(!npt.translate(0xe0000000).unwrap().unwrap().writable);
        assert_eq!(npt.translate(0xe0010000), Ok(None));
        assert_eq!(npt.translate(0xe0400000), Ok(None));
    }
    for writable in [true, false, true, false] {
        set_identity_write_range(&mut storage, ROOT, 0xe0000000, 0x1000000, writable).unwrap();
        for address in [0xe0010000, 0xe0010fff, 0xe0400000, 0xe05fffff] {
            assert_absent(&storage, address);
        }
        for address in [0xe000ffff, 0xe0011000, 0xe0600000] {
            assert_eq!(present(&storage, address), Some((address, writable, true)));
        }
    }
}

#[test]
fn write_helper_rejects_a_stale_present_pte_alias_before_any_permission_edit() {
    let denied = denial(&[(0xe0010000, 4096)]);
    let mut storage = vec![[0; 4096]; CACHE_TABLE_COUNT];
    build(&mut storage, &denied).unwrap().protect_write_range(0xe0000000, 0x1000000).unwrap();
    let (pt, index, _, _, _, _) = walk(&storage, 0xe0011000);
    put(&mut storage, pt, index, 0xe0010007);
    let saved = storage.clone();
    assert_eq!(
        set_identity_write_range(&mut storage, ROOT, 0xe0000000, 0x1000000, true),
        Err(IdentityNptError::StorageBounds)
    );
    assert_eq!(storage, saved);
}

#[test]
fn denial_overlay_on_a_legacy_tree_survives_quarantine_and_plain_rebuilds() {
    let denied = denial(&[(0xe0010000, 4096), (0xe0400000, 0x200000)]);
    let mut original = vec![[0; 4096]; CACHE_TABLE_COUNT];
    build(&mut original, &ControlPageDenials::EMPTY)
        .unwrap()
        .protect_write_range(0xe0000000, 0x1000000)
        .unwrap();
    let saved = original.clone();
    let mut blocked = vec![[0; 4096]; CACHE_TABLE_COUNT];
    retype_identity_policy_with_denials(
        &original,
        &mut blocked,
        ROOT,
        policy(48),
        &denied,
        |s, e| {
            assert!(!denied.ranges().iter().any(|&(base, limit)| base < e && s < limit));
            Ok(Some(CacheMapping::Quarantine))
        },
    )
    .unwrap();
    assert_eq!(original, saved);
    for address in [0xe0010000, 0xe0400000, ROOT] {
        assert_absent(&blocked, address);
    }
    assert_eq!(identity_is_quarantined(&blocked, ROOT, 0xe0011000), Ok(true));
    let mut restored = vec![[0; 4096]; CACHE_TABLE_COUNT];
    for selector in 0..8 {
        retype_identity_policy(&blocked, &mut restored, ROOT, |_, _| {
            Ok(Some(CacheMapping::Pat(selector)))
        })
        .unwrap();
        for address in [0xe0010000, 0xe0010fff, 0xe0400000, 0xe05fffff, ROOT] {
            assert_absent(&restored, address);
        }
        assert_eq!(present(&restored, 0xe0011000), Some((0xe0011000, false, true)));
        set_identity_write_range(&mut restored, ROOT, 0xe0000000, 0x1000000, true).unwrap();
        assert_absent(&restored, 0xe0010000);
        assert_absent(&restored, 0xe0400000);
        assert_eq!(present(&restored, 0xe0011000), Some((0xe0011000, true, true)));
    }
}

#[test]
fn applying_a_denial_to_a_recoverable_quarantine_makes_it_permanent() {
    let denied = denial(&[(0x80001000, 4096)]);
    let mut original = vec![[0; 4096]; CACHE_TABLE_COUNT];
    build(&mut original, &ControlPageDenials::EMPTY).unwrap();
    let mut quarantined = vec![[0; 4096]; CACHE_TABLE_COUNT];
    retype_identity_policy(&original, &mut quarantined, ROOT, |_, _| {
        Ok(Some(CacheMapping::Quarantine))
    })
    .unwrap();
    assert_eq!(identity_is_quarantined(&quarantined, ROOT, 0x80001000), Ok(true));
    let mut denied_tree = vec![[0; 4096]; CACHE_TABLE_COUNT];
    retype_identity_policy_with_denials(
        &quarantined,
        &mut denied_tree,
        ROOT,
        policy(48),
        &denied,
        |_, _| Ok(Some(CacheMapping::Pat(0))),
    )
    .unwrap();
    assert_absent(&denied_tree, 0x80001000);
    assert_eq!(present(&denied_tree, 0x80002000), Some((0x80002000, true, true)));
    retype_identity_policy(&denied_tree, &mut original, ROOT, |_, _| {
        Ok(Some(CacheMapping::Pat(0)))
    })
    .unwrap();
    assert_absent(&original, 0x80001000);
}

#[test]
fn malformed_aliases_are_rejected_even_inside_denied_spans_and_failures_clear_output() {
    let denied = denial(&[(0x40000000, 1 << 30)]);
    let mut source = vec![[0; 4096]; CACHE_TABLE_COUNT];
    build(&mut source, &ControlPageDenials::EMPTY).unwrap();
    // Alias GPA 1GiB to physical zero; denial must not hide malformed source.
    put(&mut source, 1, 1, 0x87);
    let saved = source.clone();
    let mut target = vec![[0xa5; 4096]; CACHE_TABLE_COUNT];
    assert_eq!(
        retype_identity_policy_with_denials(
            &source,
            &mut target,
            ROOT,
            policy(48),
            &denied,
            |_, _| Ok(Some(CacheMapping::Pat(0)))
        ),
        Err(CacheNptError::NonIdentity)
    );
    assert_eq!(source, saved);
    assert!(target.iter().flatten().all(|&byte| byte == 0));
}

#[test]
fn late_callback_and_capacity_failures_never_leave_present_output() {
    let denied = denial(&[(0x80001000, 4096)]);
    let mut source = vec![[0; 4096]; CACHE_TABLE_COUNT];
    build(&mut source, &ControlPageDenials::EMPTY).unwrap();
    let saved = source.clone();
    for capacity in [3, CACHE_TABLE_COUNT] {
        let mut target = vec![[0xa5; 4096]; capacity];
        let error = retype_identity_policy_with_denials(
            &source,
            &mut target,
            ROOT,
            policy(48),
            &denied,
            |start, _| {
                if start >= 1 << 39 {
                    Err(CacheNptError::MemoryType)
                } else {
                    Ok(Some(CacheMapping::Pat(0)))
                }
            },
        );
        assert_eq!(
            error,
            Err(if capacity == 3 { CacheNptError::Storage } else { CacheNptError::MemoryType })
        );
        assert_eq!(source, saved);
        assert!(target.iter().flatten().all(|&byte| byte == 0));
    }
}

#[test]
fn cache_denial_rebuild_revalidates_policy_and_both_complete_backing_spans() {
    let denied = denial(&[(1 << 35, 4096)]);
    let mut source = vec![[0; 4096]; CACHE_TABLE_COUNT];
    build(&mut source, &ControlPageDenials::EMPTY).unwrap();
    let mut destination = vec![[0xa5; 4096]; CACHE_TABLE_COUNT];
    let saved = destination.clone();
    assert!(matches!(
        retype_identity_policy_with_denials(
            &source,
            &mut destination,
            ROOT,
            policy(32),
            &denied,
            |_, _| Ok(Some(CacheMapping::Pat(0)))
        ),
        Err(CacheNptError::ControlDenial(ControlPageDenialError::Address(_)))
    ));
    assert_eq!(destination, saved);
    for (source_pages, destination_pages) in [(1, 2), (2, 1)] {
        let input = vec![[0; 4096]; source_pages];
        let mut output = vec![[0xa5; 4096]; destination_pages];
        let saved = output.clone();
        assert!(matches!(
            retype_identity_policy_with_denials(
                &input,
                &mut output,
                (1 << 32) - 4096,
                policy(32),
                &ControlPageDenials::EMPTY,
                |_, _| Ok(Some(CacheMapping::Pat(0)))
            ),
            Err(CacheNptError::Address(_))
        ));
        assert_eq!(output, saved);
    }
}
