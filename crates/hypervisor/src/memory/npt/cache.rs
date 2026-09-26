//! Build replacement identity NPT memory types without editing the active tree.
//! APM2 physical pp207/211/215: PAT is bit7 in a PTE, bit12 in a large leaf.
//! APM2 pp615-616: nested selectors index the host PAT, not the guest PAT.

use crate::memory::{
    address::{ADDRESS_MASK, AddressError, AddressPolicy, NX, PAGE_BYTES, PRESENT, WRITE},
    npt::denial::{ControlPageDenialError, ControlPageDenials},
    npt::table_guard::TableWriteDenials,
};

const PS: u64 = 1 << 7;
const LARGE_PAT: u64 = 1 << 12;
const CACHE_BITS: u64 = (1 << 3) | (1 << 4);
const LEAF_FLAGS: u64 = NX | 0x0fff;
// Software-owned bit, stored only on an inaccessible leaf. Retains its original
// address/permissions so a later policy update cannot resurrect an ordinary hole.
const QUARANTINED: u64 = 1 << 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheMapping {
    Pat(u8),
    Quarantine,
}

/// Inspect only monitor-owned table storage, never guest physical memory.
/// A marked inaccessible leaf identifies the cache owner's routing guard.
pub fn identity_is_quarantined(
    tables: &[[u8; PAGE_BYTES]],
    table_base: u64,
    address: u64,
) -> Result<bool, CacheNptError> {
    if table_base & 4095 != 0 || table_base & !ADDRESS_MASK != 0 || address >= 1 << 48 {
        return Err(CacheNptError::Storage);
    }
    let mut table = 0;
    for level in (1..=4).rev() {
        let shift = 12 + 9 * (level - 1);
        let index = ((address >> shift) & 511) as usize;
        let page = tables.get(table).ok_or(CacheNptError::Storage)?;
        let entry = u64::from_le_bytes(page[index * 8..index * 8 + 8].try_into().unwrap());
        let marked = entry & QUARANTINED != 0;
        let leaf = level == 1 || (level < 4 && entry & PS != 0);
        if entry & PRESENT == 0 {
            if entry == 0 {
                return Ok(false);
            }
            if !marked || !leaf {
                return Err(CacheNptError::Entry);
            }
            let pat_bit = if level == 1 { PS } else { LARGE_PAT };
            let base = entry & ADDRESS_MASK & !pat_bit;
            if entry & !(ADDRESS_MASK | LEAF_FLAGS) != 0 || base != address & !((1u64 << shift) - 1)
            {
                return Err(CacheNptError::Entry);
            }
            return Ok(true);
        }
        if marked {
            return Err(CacheNptError::Entry);
        }
        if leaf {
            return Ok(false);
        }
        if entry & !(ADDRESS_MASK | NX | 0x67) != 0 {
            return Err(CacheNptError::Entry);
        }
        let offset =
            (entry & ADDRESS_MASK).checked_sub(table_base).ok_or(CacheNptError::Storage)?;
        table = (offset / PAGE_BYTES as u64) as usize;
        if table == 0 {
            return Err(CacheNptError::Storage);
        }
    }
    Err(CacheNptError::Entry)
}

/// Runtime capacity for splits at guest MTRR boundaries. Initial admission
/// constructs the ordinary eight-page tree in this storage's prefix.
pub const CACHE_TABLE_COUNT: usize = 64;

#[repr(C, align(4096))]
pub struct CacheTableStorage(pub [[u8; PAGE_BYTES]; CACHE_TABLE_COUNT]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheNptError {
    Storage,
    Entry,
    NonIdentity,
    Address(AddressError),
    ControlDenial(ControlPageDenialError),
    GuestAddressOutsideDomain,
    MemoryType,
    NonUniformPage,
}

/// Stage a complete replacement in disjoint, inactive storage. Links are encoded
/// for `table_base`, the address at which the caller will install the result.
/// The source is never changed, including on error. A failed destination is not
/// installable. Successful output retains every absent mapping and permission.
///
/// `select(start, end)` must return one admitted host-PAT index for the whole
/// half-open span, or `None` when its type changes inside it. It must be stable
/// through the call. The caller proves physical/guest PAT composition, ownership,
/// physical width, and the cache/TLB rendezvous before installing any output.
/// At most four recursive frames are used; no table-sized stack object exists.
pub fn retype_identity(
    source: &[[u8; PAGE_BYTES]],
    destination: &mut [[u8; PAGE_BYTES]],
    table_base: u64,
    mut select: impl FnMut(u64, u64) -> Result<Option<u8>, CacheNptError>,
) -> Result<usize, CacheNptError> {
    retype_identity_policy(source, destination, table_base, |start, end| {
        select(start, end).map(|value| value.map(CacheMapping::Pat))
    })
}

/// As `retype_identity`, with inaccessible leaves for unrepresentable routing.
/// Only this builder's marked leaves can subsequently be restored. A guest
/// access to a quarantined range must stop or use a real routing emulator.
pub fn retype_identity_policy(
    source: &[[u8; PAGE_BYTES]],
    destination: &mut [[u8; PAGE_BYTES]],
    table_base: u64,
    select: impl FnMut(u64, u64) -> Result<Option<CacheMapping>, CacheNptError>,
) -> Result<usize, CacheNptError> {
    rebuild(
        source,
        destination,
        table_base,
        None,
        &ControlPageDenials::EMPTY,
        TableWriteDenials::EMPTY,
        select,
    )
}

/// Reapply the retained CPU denial policy while constructing inactive tables.
/// This also removes ranges from a legacy identity tree or a recoverable cache
/// quarantine. All present/recoverable source leaves must be identity mappings;
/// physical aliases are rejected even if their GPA lies in a denied range.
///
/// A denial becomes an ordinary zero hole before the memory-type callback can
/// restore it. Subsequent legacy retypes also preserve that zero permanently.
/// The physical policy validates both entire assigned backing spans, every leaf
/// and the denial plan. The caller still owns allocation/protection, installation
/// and all-CPU TLB invalidation. A returned error never changes the source; after
/// a failed emission the destination is cleared and must not be installed.
pub fn retype_identity_policy_with_denials(
    source: &[[u8; PAGE_BYTES]],
    destination: &mut [[u8; PAGE_BYTES]],
    table_base: u64,
    policy: AddressPolicy,
    denied: &ControlPageDenials,
    select: impl FnMut(u64, u64) -> Result<Option<CacheMapping>, CacheNptError>,
) -> Result<usize, CacheNptError> {
    denied.validate(policy).map_err(CacheNptError::ControlDenial)?;
    rebuild(source, destination, table_base, Some(policy), denied, TableWriteDenials::EMPTY, select)
}

/// Preserve separate readable table-source guards through cache reconstruction.
pub fn retype_identity_policy_with_guards(
    source: &[[u8; PAGE_BYTES]],
    destination: &mut [[u8; PAGE_BYTES]],
    table_base: u64,
    policy: AddressPolicy,
    denied: &ControlPageDenials,
    write_denied: TableWriteDenials<'_>,
    select: impl FnMut(u64, u64) -> Result<Option<CacheMapping>, CacheNptError>,
) -> Result<usize, CacheNptError> {
    denied.validate(policy).map_err(CacheNptError::ControlDenial)?;
    TableWriteDenials::new(policy, write_denied.pages())?;
    rebuild(source, destination, table_base, Some(policy), denied, write_denied, select)
}

fn rebuild(
    source: &[[u8; PAGE_BYTES]],
    destination: &mut [[u8; PAGE_BYTES]],
    table_base: u64,
    policy: Option<AddressPolicy>,
    denied: &ControlPageDenials,
    write_denied: TableWriteDenials<'_>,
    mut select: impl FnMut(u64, u64) -> Result<Option<CacheMapping>, CacheNptError>,
) -> Result<usize, CacheNptError> {
    if source.is_empty()
        || destination.is_empty()
        || source.len() > CACHE_TABLE_COUNT
        || destination.len() > CACHE_TABLE_COUNT
        || table_base & 4095 != 0
        || table_base & !ADDRESS_MASK != 0
        || table_base
            .checked_add((source.len().max(destination.len()) * PAGE_BYTES) as u64)
            .is_none_or(|end| end > ADDRESS_MASK + PAGE_BYTES as u64)
    {
        return Err(CacheNptError::Storage);
    }
    if let Some(policy) = policy {
        policy
            .validate(table_base, (source.len() * PAGE_BYTES) as u64, PAGE_BYTES as u64)
            .map_err(CacheNptError::Address)?;
        policy
            .validate(table_base, (destination.len() * PAGE_BYTES) as u64, PAGE_BYTES as u64)
            .map_err(CacheNptError::Address)?;
    }
    for page in destination.iter_mut() {
        page.fill(0);
    }
    let mut builder = Builder {
        source,
        destination,
        table_base,
        policy,
        denied,
        write_denied,
        used: 1,
        select: &mut select,
    };
    for index in 0..512 {
        let result =
            builder.entry(0, index).and_then(|entry| builder.node(entry, 4, (index as u64) << 39));
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                // No stale PRESENT link survives a partially emitted image.
                for page in builder.destination.iter_mut() {
                    page.fill(0);
                }
                return Err(error);
            }
        };
        builder.put(0, index, value);
    }
    Ok(builder.used)
}

struct Builder<'a, F> {
    source: &'a [[u8; PAGE_BYTES]],
    destination: &'a mut [[u8; PAGE_BYTES]],
    table_base: u64,
    policy: Option<AddressPolicy>,
    denied: &'a ControlPageDenials,
    write_denied: TableWriteDenials<'a>,
    used: usize,
    select: &'a mut F,
}

impl<F: FnMut(u64, u64) -> Result<Option<CacheMapping>, CacheNptError>> Builder<'_, F> {
    fn node(&mut self, entry: u64, level: u32, start: u64) -> Result<u64, CacheNptError> {
        let quarantined = entry & PRESENT == 0 && entry & QUARANTINED != 0;
        let entry = if quarantined { (entry & !QUARANTINED) | PRESENT } else { entry };
        if entry & PRESENT == 0 {
            return if entry == 0 { Ok(0) } else { Err(CacheNptError::Entry) };
        }
        let length = 1u64 << (12 + 9 * (level - 1));
        let leaf = level == 1 || (level < 4 && entry & PS != 0);
        if entry & QUARANTINED != 0 || quarantined && !leaf {
            return Err(CacheNptError::Entry);
        }
        if leaf {
            let pat_bit = if level == 1 { PS } else { LARGE_PAT };
            let address = entry & ADDRESS_MASK & !pat_bit;
            if entry & !(ADDRESS_MASK | LEAF_FLAGS) != 0 || address & (length - 1) != 0 {
                return Err(CacheNptError::Entry);
            }
            if address != start {
                return Err(CacheNptError::NonIdentity);
            }
            if let Some(policy) = self.policy {
                policy.validate(address, length, length).map_err(CacheNptError::Address)?;
                if start + length > 1u64 << policy.physical_bits().min(40) {
                    return Err(CacheNptError::GuestAddressOutsideDomain);
                }
            }
            if self.denied.covers(start, start + length) {
                return Ok(0);
            }
            let table_source = self.write_denied.intersects(start, start + length);
            let mapping =
                if self.denied.intersects(start, start + length) || (table_source && level > 1) {
                    None
                } else {
                    (self.select)(start, start + length)?
                };
            if let Some(mapping) = mapping {
                let index = match mapping {
                    CacheMapping::Quarantine => {
                        return Ok((entry & !(PRESENT | if table_source { WRITE } else { 0 }))
                            | QUARANTINED);
                    }
                    CacheMapping::Pat(index) => index,
                };
                if index > 7 {
                    return Err(CacheNptError::MemoryType);
                }
                return Ok((entry
                    & !(CACHE_BITS | pat_bit | if table_source { WRITE } else { 0 }))
                    | (u64::from(index & 3) << 3)
                    | if index & 4 != 0 { pat_bit } else { 0 });
            }
            if level == 1 {
                return Err(CacheNptError::NonUniformPage);
            }
            let table = self.allocate()?;
            let child_length = length >> 9;
            // Permissions of the original leaf become parent permissions. In
            // particular ECAM revocation can later restore the PD write bit
            // without leaving a second hidden write restriction in each PTE.
            let flags = (entry & LEAF_FLAGS & !(PS | CACHE_BITS)) | WRITE;
            for index in 0..512 {
                let base = start + (index as u64) * child_length;
                let child = base | flags | if level > 2 { PS } else { 0 };
                let value = self.node(child, level - 1, base)?;
                self.put(table, index, value);
            }
            return Ok(self.link(table, entry & (NX | 0x67)));
        }
        if level == 1 || entry & !(ADDRESS_MASK | NX | 0x67) != 0 {
            return Err(CacheNptError::Entry);
        }
        let offset =
            (entry & ADDRESS_MASK).checked_sub(self.table_base).ok_or(CacheNptError::Storage)?;
        let source_table = (offset / PAGE_BYTES as u64) as usize;
        if source_table == 0 || source_table >= self.source.len() {
            return Err(CacheNptError::Storage);
        }
        let table = self.allocate()?;
        let child_length = length >> 9;
        for index in 0..512 {
            let value = self.node(
                self.entry(source_table, index)?,
                level - 1,
                start + (index as u64) * child_length,
            )?;
            self.put(table, index, value);
        }
        Ok(self.link(table, entry & (NX | 0x67)))
    }

    fn allocate(&mut self) -> Result<usize, CacheNptError> {
        if self.used == self.destination.len() {
            return Err(CacheNptError::Storage);
        }
        let index = self.used;
        self.used += 1;
        Ok(index)
    }

    fn link(&self, table: usize, flags: u64) -> u64 {
        (self.table_base + (table * PAGE_BYTES) as u64) | flags
    }

    fn entry(&self, table: usize, index: usize) -> Result<u64, CacheNptError> {
        let page = self.source.get(table).ok_or(CacheNptError::Storage)?;
        Ok(u64::from_le_bytes(page[index * 8..index * 8 + 8].try_into().unwrap()))
    }

    fn put(&mut self, table: usize, index: usize, value: u64) {
        self.destination[table][index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
}
