//! Readable, nonwritable guest IOMMU source pages. This policy is separate from
//! absent monitor/control holes. It can be reapplied to every NPT reconstruction.
//! Native installation still requires all affected CPUs stopped and nested-TLB
//! invalidation on each CPU; NPT alone never closes device DMA writes.

use super::cache::{self, CacheMapping, CacheNptError};
use crate::memory::address::{AddressPolicy, PAGE_BYTES};

pub const MAX_TABLE_SOURCE_PAGES: usize = 4096;

#[derive(Clone, Copy, Debug)]
pub struct TableWriteDenials<'a> {
    pages: &'a [u64],
}

impl<'a> TableWriteDenials<'a> {
    pub const EMPTY: Self = Self { pages: &[] };

    pub fn new(policy: AddressPolicy, pages: &'a [u64]) -> Result<Self, CacheNptError> {
        if pages.len() > MAX_TABLE_SOURCE_PAGES {
            return Err(CacheNptError::Storage);
        }
        for (index, page) in pages.iter().copied().enumerate() {
            policy
                .validate(page, PAGE_BYTES as u64, PAGE_BYTES as u64)
                .map_err(CacheNptError::Address)?;
            if index != 0 && pages[index - 1] >= page {
                return Err(CacheNptError::Entry);
            }
        }
        Ok(Self { pages })
    }

    pub const fn pages(self) -> &'a [u64] {
        self.pages
    }

    pub fn intersects(self, start: u64, end: u64) -> bool {
        let index = self.pages.partition_point(|page| *page + PAGE_BYTES as u64 <= start);
        self.pages.get(index).is_some_and(|page| *page < end)
    }

    pub fn covers_page(self, start: u64) -> bool {
        self.pages.binary_search(&start).is_ok()
    }
}

/// Stage page-granular guards while preserving the complete source cache and
/// permission policy, including ordinary holes and recoverable quarantines.
/// Physical aliases are explicitly refused by the underlying identity verifier.
/// Capacity failure leaves the source unchanged and clears the staged output.
pub fn protect_identity_tables(
    source: &[[u8; PAGE_BYTES]],
    destination: &mut [[u8; PAGE_BYTES]],
    root: u64,
    policy: AddressPolicy,
    guards: TableWriteDenials<'_>,
) -> Result<usize, CacheNptError> {
    cache::retype_identity_policy_with_guards(
        source,
        destination,
        root,
        policy,
        &super::ControlPageDenials::EMPTY,
        guards,
        |start, end| {
            let (entry, level) = source_leaf(source, root, start)?;
            let length = 1u64 << (12 + 9 * (level - 1));
            if end > (start & !(length - 1)) + length {
                return Ok(None);
            }
            if entry & 1 == 0 && entry & (1 << 10) != 0 {
                return Ok(Some(CacheMapping::Quarantine));
            }
            let high = if level == 1 { (entry >> 7) & 1 } else { (entry >> 12) & 1 };
            Ok(Some(CacheMapping::Pat((((entry >> 3) & 3) | (high << 2)) as u8)))
        },
    )
}

/// Verify each requested page against the ACTUAL installed root. This is
/// numeric table validation, not a TLB or all-CPU acknowledgement.
pub fn verify_identity_tables(
    tables: &[[u8; PAGE_BYTES]],
    root: u64,
    guards: TableWriteDenials<'_>,
) -> Result<(), CacheNptError> {
    verify_identity_table_guards(tables, root, guards)?;
    for page in guards.pages() {
        let (entry, level) = source_leaf(tables, root, *page)?;
        if level != 1 || entry & 1 == 0 {
            return Err(CacheNptError::Entry);
        }
    }
    Ok(())
}

/// Final-entry verification needs write denial, even if cache policy currently
/// quarantines the source. A capture separately requires present readable RAM.
/// Quarantine is accepted only with its explicit retained software marker;
/// arbitrary absent/corrupt entries are never treated as valid source guards.
pub fn verify_identity_table_guards(
    tables: &[[u8; PAGE_BYTES]],
    root: u64,
    guards: TableWriteDenials<'_>,
) -> Result<(), CacheNptError> {
    use crate::memory::address::{ADDRESS_MASK, NX};
    for page in guards.pages() {
        let (entry, level) = source_leaf(tables, root, *page)?;
        let present = entry & 1 != 0;
        let quarantined = entry & (1 << 10) != 0;
        if level != 1
            || present == quarantined
            || entry & 2 != 0
            || entry & 4 == 0
            || entry & ADDRESS_MASK != *page
            || entry & !(ADDRESS_MASK | NX | 0xfff) != 0
        {
            return Err(CacheNptError::Entry);
        }
    }
    Ok(())
}

fn source_leaf(
    tables: &[[u8; PAGE_BYTES]],
    root: u64,
    address: u64,
) -> Result<(u64, u8), CacheNptError> {
    use crate::memory::address::ADDRESS_MASK;
    if root & 4095 != 0
        || root & !ADDRESS_MASK != 0
        || address >= 1 << 48
        || tables.is_empty()
        || tables.len() > super::CACHE_TABLE_COUNT
    {
        return Err(CacheNptError::Storage);
    }
    let mut table = 0;
    let mut seen = [usize::MAX; 4];
    for level in (1..=4).rev() {
        if seen.contains(&table) {
            return Err(CacheNptError::Storage);
        }
        seen[(4 - level) as usize] = table;
        let page = tables.get(table).ok_or(CacheNptError::Storage)?;
        let index = ((address >> (12 + 9 * (level - 1))) & 511) as usize;
        let entry = u64::from_le_bytes(page[index * 8..index * 8 + 8].try_into().unwrap());
        if level == 1 || (level < 4 && entry & (1 << 7) != 0) {
            return Ok((entry, level));
        }
        if entry & 1 == 0 || entry & !(ADDRESS_MASK | crate::memory::address::NX | 0x67) != 0 {
            return Err(CacheNptError::Entry);
        }
        let offset = (entry & ADDRESS_MASK).checked_sub(root).ok_or(CacheNptError::Storage)?;
        table = (offset / PAGE_BYTES as u64) as usize;
    }
    Err(CacheNptError::Entry)
}
