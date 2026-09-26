//! The resident identity NPT with a monitor pool and immutable control-page holes.

use crate::{
    arch::x86_64::capabilities::EvidenceFlag,
    memory::{
        address::{
            ADDRESS_MASK, AddressError, AddressPolicy, PAGE_BYTES, PRESENT, PhysicalRange, WRITE,
        },
        npt::{
            cache::CACHE_TABLE_COUNT,
            denial::{ControlPageDenialError, ControlPageDenials},
            table::{NptEvidence, TableStorage, TableView, indices},
        },
    },
};

/// Bounded low-memory monitor extent: up to 32 private MiB images and the
/// shared observation, four hardware banks and two composed generations per
/// unit. Independent of CPU count; the complete unused capacity is excluded.
pub const MAX_IDENTITY_EXCLUSION_BYTES: u64 = (32 << 20) + 0x3262000;

/// Separate native-boot profile, retaining identity access outside explicit
/// holes. CPU access denial alone is not DMA or device-control ownership.
pub struct IdentityNpt<'a> {
    storage: &'a mut [[u8; PAGE_BYTES]],
    arena: PhysicalRange,
    excluded: PhysicalRange,
    denied: ControlPageDenials,
    guest_bits: u8,
    used: usize,
    levels: [u8; CACHE_TABLE_COUNT],
    protected_range: Option<(u64, u64)>,
}

impl<'a> IdentityNpt<'a> {
    /// Legacy native identity profile with only the monitor pool excluded.
    /// All table storage, including unused pages, must lie in that pool.
    pub fn new(
        storage: &'a mut TableStorage,
        table_base: u64,
        policy: AddressPolicy,
        excluded: PhysicalRange,
        evidence: NptEvidence,
        one_gib_pages: EvidenceFlag,
        source_pat: u64,
    ) -> Result<Self, IdentityNptError> {
        Self::new_with_denied_ranges(
            &mut storage.0,
            table_base,
            policy,
            excluded,
            evidence,
            one_gib_pages,
            source_pat,
            &ControlPageDenials::EMPTY,
        )
    }

    /// Build while every consumer is stopped. APM2 physical pp206-207,211,
    /// 215-216,612-614: absent entries deny reads, writes and instruction fetches.
    /// Control holes are permanent zero entries, never restorable cache guards.
    ///
    /// Map 0..2^min(physical_bits,40), splitting only where a 4KiB-aligned hole
    /// needs it. The monitor is at most MAX_IDENTITY_EXCLUSION_BYTES below 1GiB, or a legacy <=1MiB
    /// interval contained in one 2MiB page elsewhere in-domain. The complete
    /// assigned backing must lie in the monitor, even if some pages are unused.
    /// At most CACHE_TABLE_COUNT pages may be assigned. Plan sizing and all
    /// address checks precede mutation; every returned error preserves storage.
    ///
    /// The caller supplies host four-level/NXE evidence, host PAT0=WB and an
    /// admitted platform policy. This builder performs no hardware operation and
    /// cannot establish physical backing, Windows coexistence or DMA ownership.
    pub fn new_with_denied_ranges(
        storage: &'a mut [[u8; PAGE_BYTES]],
        table_base: u64,
        policy: AddressPolicy,
        excluded: PhysicalRange,
        evidence: NptEvidence,
        one_gib_pages: EvidenceFlag,
        source_pat: u64,
        denied: &ControlPageDenials,
    ) -> Result<Self, IdentityNptError> {
        use IdentityNptError as E;
        if evidence.nx_supported != EvidenceFlag::Set
            || evidence.host_nxe != EvidenceFlag::Set
            || evidence.host_four_level != EvidenceFlag::Set
        {
            return Err(E::RequiredModeNotEstablished);
        }
        if one_gib_pages != EvidenceFlag::Set {
            return Err(E::OneGiBPagesNotEstablished);
        }
        if source_pat & 0xff != 6 {
            return Err(E::PatZeroNotWriteBack);
        }
        let guest_bits = policy.physical_bits().min(40);
        let domain = policy.validate(0, 1u64 << guest_bits, 4096).map_err(E::Address)?;
        let excluded =
            policy.validate(excluded.base(), excluded.len(), 4096).map_err(E::Address)?;
        let legacy_exclusion =
            excluded.len() <= 1 << 20 && excluded.base() >> 21 == excluded.last_byte() >> 21;
        if excluded.len() & 4095 != 0
            || excluded.len() > MAX_IDENTITY_EXCLUSION_BYTES
            || (!legacy_exclusion && excluded.last_byte() >= 1 << 30)
            || excluded.last_byte() > domain.last_byte()
        {
            return Err(E::InvalidExclusion);
        }
        denied.validate(policy).map_err(E::ControlDenial)?;
        if storage.is_empty() || storage.len() > CACHE_TABLE_COUNT {
            return Err(E::StorageBounds);
        }
        let arena = policy
            .validate(table_base, (storage.len() * PAGE_BYTES) as u64, 4096)
            .map_err(E::Address)?;
        if arena.base() < excluded.base() || arena.last_byte() > excluded.last_byte() {
            return Err(E::TableArenaOutsideExclusion);
        }
        let holes = Holes { excluded, denied };
        let pdpt_count = if guest_bits == 40 { 2 } else { 1 };
        let mut planned = 1 + pdpt_count;
        for gib in 0..(1u64 << (guest_bits - 30)) {
            holes.count_tables(3, gib << 30, &mut planned, storage.len())?;
        }
        if planned > storage.len() {
            return Err(E::StorageBounds);
        }
        // The infallible emission pass follows exactly the admitted plan.
        for page in storage.iter_mut() {
            page.fill(0);
        }
        let mut result = Self {
            storage,
            arena,
            excluded,
            denied: *denied,
            guest_bits,
            used: 1 + pdpt_count,
            levels: [0; CACHE_TABLE_COUNT],
            protected_range: None,
        };
        result.levels[0] = 4;
        for index in 0..pdpt_count {
            result.levels[1 + index] = 3;
            identity_put(
                result.storage,
                0,
                index,
                (table_base + ((1 + index) * PAGE_BYTES) as u64) | 7,
            );
        }
        for gib in 0..(1u64 << (guest_bits - 30)) {
            let value = result.emit(3, gib << 30);
            identity_put(result.storage, 1 + (gib / 512) as usize, (gib % 512) as usize, value);
        }
        Ok(result)
    }

    fn emit(&mut self, level: u32, start: u64) -> u64 {
        let length = 1u64 << (12 + 9 * (level - 1));
        let holes = Holes { excluded: self.excluded, denied: &self.denied };
        if holes.covers(start, start + length) {
            return 0;
        }
        if !holes.intersects(start, start + length) {
            return start | if level == 1 { 7 } else { 0x87 };
        }
        let table = self.used;
        self.used += 1;
        self.levels[table] = (level - 1) as u8;
        for index in 0..512 {
            let value = self.emit(level - 1, start + (index as u64) * (length >> 9));
            identity_put(self.storage, table, index, value);
        }
        (self.arena.base() + (table * PAGE_BYTES) as u64) | 7
    }

    pub const fn root_address(&self) -> u64 {
        self.arena.base()
    }
    pub const fn guest_bits(&self) -> u8 {
        self.guest_bits
    }
    pub const fn used_tables(&self) -> usize {
        self.used
    }
    pub const fn excluded(&self) -> PhysicalRange {
        self.excluded
    }
    pub const fn denied_ranges(&self) -> &ControlPageDenials {
        &self.denied
    }

    /// Add the legacy 2MiB-rounded ECAM write guard in stopped tables. Existing
    /// control-page holes survive even when they already split this GiB. The
    /// aperture remains distinct from the monitor's GiB for the legacy profile.
    pub fn protect_write_range(&mut self, base: u64, bytes: u64) -> Result<(), IdentityNptError> {
        use IdentityNptError as E;
        let (start, end) = identity_protection_range(base, bytes)?;
        if self.protected_range.is_some() || start >> 30 == self.excluded.base() >> 30 {
            return Err(E::InvalidExclusion);
        }
        if end > 1u64 << self.guest_bits {
            return Err(E::GuestAddressOutsideWidth);
        }
        // Audit every prospective leaf before any permission or link change.
        let mut address = start;
        while address < end {
            let (_, span) = self.translation(address)?;
            address = (address & !(span - 1)) + span;
        }
        let pdpt = 1 + (start >> 39) as usize;
        let pi = ((start >> 30) & 511) as usize;
        let entry = u64::from_le_bytes(self.storage[pdpt][pi * 8..pi * 8 + 8].try_into().unwrap());
        if entry == 0 {
            // A wholly denied GiB needs no write guard.
            self.protected_range = Some((start, end));
            return Ok(());
        }
        if entry & 0x80 == 0 {
            set_identity_write_range(self.storage, self.arena.base(), base, bytes, false)?;
        } else {
            let pd = self.used;
            if pd >= self.storage.len() {
                return Err(E::StorageBounds);
            }
            let gib = start & !((1u64 << 30) - 1);
            for i in 0..512 {
                let address = gib + ((i as u64) << 21);
                let flags = if (start..end).contains(&address) { 0x85 } else { 0x87 };
                identity_put(self.storage, pd, i, address | flags);
            }
            identity_put(
                self.storage,
                pdpt,
                pi,
                (self.arena.base() + (pd * PAGE_BYTES) as u64) | 7,
            );
            self.levels[pd] = 2;
            self.used += 1;
        }
        self.protected_range = Some((start, end));
        Ok(())
    }

    /// Unused storage pages remain zero and are never exported as reachable.
    pub fn table(&self, index: usize) -> Option<TableView<'_>> {
        if index >= self.used {
            return None;
        }
        Some(TableView {
            physical_address: self.arena.base() + (index * PAGE_BYTES) as u64,
            bytes: self.storage.get(index)?,
        })
    }

    /// Audit emitted bytes without physical dereferences or a TLB. Missing
    /// parent tables cannot masquerade as individual denied pages, and every
    /// present leaf is checked against the complete immutable hole policy.
    pub fn translate(&self, gpa: u64) -> Result<Option<IdentityTranslation>, IdentityNptError> {
        self.translation(gpa).map(|(translation, _)| translation)
    }

    fn translation(
        &self,
        gpa: u64,
    ) -> Result<(Option<IdentityTranslation>, u64), IdentityNptError> {
        use IdentityNptError as E;
        if gpa >> self.guest_bits != 0 {
            return Err(E::GuestAddressOutsideWidth);
        }
        let holes = Holes { excluded: self.excluded, denied: &self.denied };
        let mut table = 0;
        let mut writable = true;
        for (depth, index) in indices(gpa).into_iter().enumerate() {
            let level = 4 - depth;
            let bytes = self.storage.get(table).ok_or(E::StorageBounds)?;
            let offset = index * 8;
            let entry = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            let page_bytes = 1u64 << (12 + 9 * (level - 1));
            let start = gpa & !(page_bytes - 1);
            if entry & PRESENT == 0 {
                if entry == 0 && level <= 3 && holes.covers(start, start + page_bytes) {
                    return Ok((None, page_bytes));
                }
                return Err(E::StorageBounds);
            }
            let protected =
                level == 2 && self.protected_range.is_some_and(|(s, e)| s <= gpa && gpa < e);
            if entry & 7 != if protected { 5 } else { 7 } || entry & !(ADDRESS_MASK | 0xe7) != 0 {
                return Err(E::StorageBounds);
            }
            writable &= entry & WRITE != 0;
            let large = entry & 0x80 != 0;
            if level == 4 && large || level == 1 && large {
                return Err(E::StorageBounds);
            }
            if large || level == 1 {
                let base = entry & ADDRESS_MASK;
                if base & (page_bytes - 1) != 0
                    || base != start
                    || holes.intersects(base, base + page_bytes)
                {
                    return Err(E::StorageBounds);
                }
                return Ok((
                    Some(IdentityTranslation {
                        host_address: gpa,
                        page_bytes,
                        writable,
                        executable: true,
                        pat_index: 0,
                    }),
                    page_bytes,
                ));
            }
            let offset =
                (entry & ADDRESS_MASK).checked_sub(self.arena.base()).ok_or(E::StorageBounds)?;
            let next = usize::try_from(offset / PAGE_BYTES as u64).map_err(|_| E::StorageBounds)?;
            if next >= self.used || self.levels[next] as usize != level - 1 {
                return Err(E::StorageBounds);
            }
            table = next;
        }
        Err(E::StorageBounds)
    }
}

struct Holes<'a> {
    excluded: PhysicalRange,
    denied: &'a ControlPageDenials,
}

impl Holes<'_> {
    fn intersects(&self, start: u64, end: u64) -> bool {
        self.excluded.base() < end && start <= self.excluded.last_byte()
            || self.denied.intersects(start, end)
    }

    fn covers(&self, start: u64, end: u64) -> bool {
        // Insert the monitor into the sorted denial traversal without copying
        // or requiring the caller to split ranges that overlap the monitor.
        let mut cursor = start;
        for &(base, limit) in self.denied.ranges() {
            if self.excluded.base() <= cursor && cursor <= self.excluded.last_byte() {
                cursor = self.excluded.last_byte() + 1;
            }
            if base > cursor {
                break;
            }
            cursor = cursor.max(limit);
            if cursor >= end {
                return true;
            }
        }
        if self.excluded.base() <= cursor && cursor <= self.excluded.last_byte() {
            cursor = self.excluded.last_byte() + 1;
        }
        cursor >= end
    }

    fn count_tables(
        &self,
        level: u32,
        start: u64,
        count: &mut usize,
        capacity: usize,
    ) -> Result<(), IdentityNptError> {
        let length = 1u64 << (12 + 9 * (level - 1));
        if !self.intersects(start, start + length) || self.covers(start, start + length) {
            return Ok(());
        }
        // Page alignment ensures a 4KiB leaf is wholly present or wholly absent.
        if level == 1 || *count >= capacity {
            return Err(IdentityNptError::StorageBounds);
        }
        *count += 1;
        for index in 0..512 {
            self.count_tables(level - 1, start + index * (length >> 9), count, capacity)?;
        }
        Ok(())
    }
}

/// Intended nested translation only; guest paging and actual MTRR/PAT cache
/// composition remain separate. The installed ECAM guard can restrict writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityTranslation {
    pub host_address: u64,
    pub page_bytes: u64,
    pub writable: bool,
    pub executable: bool,
    pub pat_index: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityNptError {
    RequiredModeNotEstablished,
    OneGiBPagesNotEstablished,
    PatZeroNotWriteBack,
    Address(AddressError),
    ControlDenial(ControlPageDenialError),
    InvalidExclusion,
    TableArenaOutsideExclusion,
    GuestAddressOutsideWidth,
    StorageBounds,
}

/// Restore only the installed ECAM PD write restrictions after diagnostic
/// revocation. Caller exclusively owns this stopped CPU's installed tables;
/// no other CPU may use or edit them, and the caller must request a nested-TLB
/// flush before resuming the SAME faulting instruction. Every link/entry is
/// checked before the first mutation. Existing leaf holes are never changed.
pub fn restore_identity_write_range(
    storage: &mut TableStorage,
    table_base: u64,
    base: u64,
    bytes: u64,
) -> Result<(), IdentityNptError> {
    set_identity_write_range(&mut storage.0, table_base, base, bytes, true)
}

/// Change only PD write permissions in an already split configuration aperture.
/// Validate the complete range before editing it, preserving leaf holes, A/D and cache bits.
/// Caller owns these stopped-CPU tables and the full TLB flush before reentry.
pub fn set_identity_write_range(
    storage: &mut [[u8; PAGE_BYTES]],
    table_base: u64,
    base: u64,
    bytes: u64,
    writable: bool,
) -> Result<(), IdentityNptError> {
    use IdentityNptError as E;
    let (start, end) = identity_protection_range(base, bytes)?;
    if table_base & 4095 != 0
        || table_base & !ADDRESS_MASK != 0
        || storage.is_empty()
        || storage.len() > CACHE_TABLE_COUNT
        || table_base
            .checked_add((storage.len() * PAGE_BYTES) as u64)
            .is_none_or(|end| end > ADDRESS_MASK + PAGE_BYTES as u64)
    {
        return Err(E::StorageBounds);
    }
    let child = |e: u64| -> Result<usize, E> {
        if e & 7 != 7 || e & !(ADDRESS_MASK | 0x67) != 0 {
            return Err(E::StorageBounds);
        }
        let d = (e & ADDRESS_MASK).checked_sub(table_base).ok_or(E::StorageBounds)?;
        let i = usize::try_from(d / PAGE_BYTES as u64).map_err(|_| E::StorageBounds)?;
        if i == 0 || i >= storage.len() {
            return Err(E::StorageBounds);
        }
        Ok(i)
    };
    let entry = |table: usize, index: usize| -> Result<u64, E> {
        let page = storage.get(table).filter(|_| index < 512).ok_or(E::StorageBounds)?;
        // The fixed eight-byte slice is inside the checked page.
        Ok(u64::from_le_bytes(page[index * 8..index * 8 + 8].try_into().unwrap()))
    };
    let pdpt = child(entry(0, (start >> 39) as usize)?)?;
    let pd = child(entry(pdpt, ((start >> 30) & 511) as usize)?)?;
    for a in (start..end).step_by(1 << 21) {
        let e = entry(pd, ((a >> 21) & 511) as usize)?;
        if e == 0 {
            continue;
        }
        if !matches!(e & 7, 5 | 7) || e & !(ADDRESS_MASK | 0xff) != 0 {
            return Err(E::StorageBounds);
        }
        if e & 0x80 != 0 {
            if e & ADDRESS_MASK & !(1 << 12) != a {
                return Err(E::StorageBounds);
            }
        } else {
            let pt = child(e | WRITE)?;
            if pt == pd || pt == pdpt {
                return Err(E::StorageBounds);
            }
            for index in 0..512 {
                let leaf = entry(pt, index)?;
                if leaf == 0 {
                    continue;
                }
                // A cache quarantine remains inaccessible and is never made
                // present here. Every other reachable PTE must be identity;
                // opening a PD cannot grant a stale alias to a control page.
                let quarantined = leaf & PRESENT == 0 && leaf & (1 << 10) != 0;
                if leaf & !(ADDRESS_MASK | crate::memory::address::NX | 0xfff) != 0
                    || leaf & ADDRESS_MASK != a + (index * PAGE_BYTES) as u64
                    || !matches!(leaf & 7, 5 | 7) && !quarantined
                    || leaf & (1 << 10) != 0 && !quarantined
                {
                    return Err(E::StorageBounds);
                }
            }
        }
    }
    for a in (start..end).step_by(1 << 21) {
        let i = ((a >> 21) & 511) as usize;
        // The complete PD and all indices were validated before this mutation pass.
        let entry = &mut storage[pd][i * 8..i * 8 + 8];
        let value = u64::from_le_bytes(entry.try_into().unwrap());
        if value == 0 {
            continue;
        }
        let value = if writable { value | WRITE } else { value & !WRITE };
        entry.copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

/// Bound and outward-round an ECAM aperture. No physical address is accessed.
pub fn identity_protection_range(base: u64, bytes: u64) -> Result<(u64, u64), IdentityNptError> {
    let end =
        base.checked_add(bytes).filter(|_| bytes != 0).ok_or(IdentityNptError::InvalidExclusion)?;
    let start = base & !((1u64 << 21) - 1);
    let end = end.checked_add((1 << 21) - 1).ok_or(IdentityNptError::InvalidExclusion)?
        & !((1u64 << 21) - 1);
    if base & ((1 << 20) - 1) != 0
        || bytes & ((1 << 20) - 1) != 0
        || start >> 30 != (end - 1) >> 30
        || end > 1u64 << 40
    {
        return Err(IdentityNptError::InvalidExclusion);
    }
    Ok((start, end))
}

fn identity_put(storage: &mut [[u8; PAGE_BYTES]], table: usize, index: usize, value: u64) {
    storage[table][index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{address::EncryptionState, npt::TABLE_COUNT};

    fn policy() -> AddressPolicy {
        AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
    }
    fn evidence() -> NptEvidence {
        NptEvidence {
            nx_supported: EvidenceFlag::Set,
            host_nxe: EvidenceFlag::Set,
            host_four_level: EvidenceFlag::Set,
        }
    }

    fn identity_translation(
        storage: &[[u8; PAGE_BYTES]],
        base: u64,
        gpa: u64,
    ) -> Option<(u64, bool)> {
        let mut table = 0;
        for (depth, index) in indices(gpa).into_iter().enumerate() {
            let entry =
                u64::from_le_bytes(storage[table][index * 8..index * 8 + 8].try_into().unwrap());
            if entry & 1 == 0 {
                return None;
            }
            if depth == 3 || entry & 0x80 != 0 {
                let size = 1u64 << (12 + 9 * (3 - depth));
                return Some(((entry & ADDRESS_MASK) + (gpa & (size - 1)), entry & 2 != 0));
            }
            table = ((entry & ADDRESS_MASK) - base) as usize / 4096;
        }
        unreachable!()
    }

    #[test]
    fn configuration_windows_restore_native_root_permissions() {
        let policy = policy();
        let root = 0x400000;
        let mut original = TableStorage([[0; PAGE_BYTES]; TABLE_COUNT]);
        let mut npt = IdentityNpt::new(
            &mut original,
            root,
            policy,
            policy.validate(root, 0x100000, 4096).unwrap(),
            evidence(),
            EvidenceFlag::Set,
            6,
        )
        .unwrap();
        npt.protect_write_range(0xe0000000, 0x1000000).unwrap();
        let baseline = npt.storage.to_vec();
        for _ in 0..3 {
            set_identity_write_range(npt.storage, root, 0xe0000000, 0x1000000, true).unwrap();
            assert_eq!(
                identity_translation(npt.storage, root, 0xe0001000),
                Some((0xe0001000, true))
            );
            assert!(npt.translate(root).unwrap().is_none());
            set_identity_write_range(npt.storage, root, 0xe0000000, 0x1000000, false).unwrap();
            assert_eq!(npt.storage, baseline);
        }
    }

    #[test]
    fn configuration_permission_change_refuses_corruption_without_partial_edits() {
        let policy = policy();
        let root = 0x400000;
        let mut storage = TableStorage([[0; PAGE_BYTES]; TABLE_COUNT]);
        let mut npt = IdentityNpt::new(
            &mut storage,
            root,
            policy,
            policy.validate(root, 0x100000, 4096).unwrap(),
            evidence(),
            EvidenceFlag::Set,
            6,
        )
        .unwrap();
        npt.protect_write_range(0xe0000000, 0x1000000).unwrap();
        let pdpt = ((u64::from_le_bytes(npt.storage[0][0..8].try_into().unwrap()) & ADDRESS_MASK)
            - root) as usize
            / PAGE_BYTES;
        let offset = 3 * 8;
        let pd = ((u64::from_le_bytes(npt.storage[pdpt][offset..offset + 8].try_into().unwrap())
            & ADDRESS_MASK)
            - root) as usize
            / PAGE_BYTES;
        // Corrupt the last PD entry, after seven otherwise valid entries.
        let offset = (((0xe0e00000u64 >> 21) & 511) as usize) * 8;
        npt.storage[pd][offset..offset + 8].copy_from_slice(&0x12345005u64.to_le_bytes());
        let before = npt.storage.to_vec();
        for writable in [true, false] {
            assert_eq!(
                set_identity_write_range(npt.storage, root, 0xe0000000, 0x1000000, writable),
                Err(IdentityNptError::StorageBounds)
            );
            assert_eq!(npt.storage, before);
        }
    }

    #[test]
    fn identity_pool_audit_distinguishes_full_holes_from_missing_endpoint_tables() {
        let policy = policy();
        let excluded = policy.validate(0x201000, 0x600000, 4096).unwrap();
        for (index, value, address) in [
            // First/last partial PD entries cannot become wholesale holes,
            // even when this particular GPA lies inside the monitor.
            (1, 0, 0x201000),
            (4, 0, 0x800000),
            // A wholly excluded PD leaf cannot regain a present identity map.
            (2, 0x400087, 0x400000),
            // Nor can an endpoint become a large leaf that exposes the monitor
            // while an audit queries one of its ordinary adjacent addresses.
            (1, 0x200087, 0x200000),
            // Linking the endpoint to an unused page is not an admitted hole.
            (1, 0x207007, 0x201000),
        ] {
            let mut storage = TableStorage([[0; PAGE_BYTES]; TABLE_COUNT]);
            let npt = IdentityNpt::new(
                &mut storage,
                0x201000,
                policy,
                excluded,
                evidence(),
                EvidenceFlag::Set,
                6,
            )
            .unwrap();
            assert_eq!(npt.translate(0x400000), Ok(None));
            identity_put(npt.storage, 3, index, value);
            let before = npt.storage.to_vec();
            assert_eq!(npt.translate(address), Err(IdentityNptError::StorageBounds));
            assert_eq!(npt.storage, before);
        }
    }
}
