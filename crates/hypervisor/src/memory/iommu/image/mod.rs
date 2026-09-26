//! Bounded offline images for the restricted four-level AMD host page format.
//!
//! The caller lends owned storage and assigns its numeric physical span. This
//! module does not establish physical allocation, retention, cache attributes,
//! hardware ownership or DMA isolation. No numeric address is dereferenced.
//! No DTE, requester assignment, interrupt policy or activation is produced.
//!
//! Every input and capacity check precedes the first write. Output mappings may
//! alias each other, but cannot intersect protected memory or any assigned table
//! backing, even unused capacity or a leaf with Permissions::None. Directories
//! preserve leaf permissions with IR=IW=1; every leaf keeps its explicit IR/IW/FC.
//!
//! Sources: 48882-3.11 physical pp79-85, text and PNG checked, particularly
//! Table 15 and Figures 8-10. See README.md for bounds and the ownership boundary.
#![forbid(unsafe_code)]

use super::tables::{EncodingError, HostPageEntry, PageCoherency, PageLevel, Permissions};
use crate::memory::address::{
    ADDRESS_MASK, AddressError, AddressPolicy, PAGE_BYTES, PhysicalRange,
};

/// Limits apply before traversing input slices or touching storage.
pub const MAX_MAPPING_RANGES: usize = 4096;
pub const MAX_PROTECTED_RANGES: usize = 4096;
/// At most 128 MiB of caller-owned table storage; this module allocates none.
pub const MAX_TABLE_PAGES: usize = 32_768;
pub const WORDS_PER_PAGE: usize = PAGE_BYTES / core::mem::size_of::<u64>();

/// One real 4 KiB table page. The numeric backing assignment is separate from
/// this Rust object's address and does not establish a physical allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C, align(4096))]
pub struct TablePage {
    words: [u64; WORDS_PER_PAGE],
}

const _: () = {
    assert!(core::mem::size_of::<TablePage>() == PAGE_BYTES);
    assert!(core::mem::align_of::<TablePage>() == PAGE_BYTES);
    assert!(core::mem::offset_of!(TablePage, words) == 0);
};

impl TablePage {
    pub const ZERO: Self = Self { words: [0; WORDS_PER_PAGE] };

    pub const fn words(&self) -> &[u64; WORDS_PER_PAGE] {
        &self.words
    }
}

/// A page-aligned affine mapping: each input byte at io_base + offset maps to
/// system_base + offset. Ranges must be nonempty and ordered without DVA overlap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingRange {
    pub io_base: u64,
    pub system_base: u64,
    pub len: u64,
    pub permissions: Permissions,
    pub coherency: PageCoherency,
}

/// A nonempty, page-aligned physical output exclusion. The slice must be sorted
/// by base without overlap. Assignment of the full protected set is external.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtectedRange {
    pub base: u64,
    pub len: u64,
}

/// Immutable offline words borrowing the caller's storage. Success describes
/// only this image, not active hardware or an isolation-ready/authorized domain.
#[derive(Debug)]
pub struct HostPageTableImage<'a> {
    backing: PhysicalRange,
    pages: &'a [TablePage],
}

impl HostPageTableImage<'_> {
    pub const fn root_address(&self) -> u64 {
        self.backing.base()
    }

    /// All assigned storage, including capacity not used by the emitted image.
    pub const fn backing_range(&self) -> PhysicalRange {
        self.backing
    }

    /// Used pages in physical order; all other supplied pages are unchanged.
    pub const fn pages(&self) -> &[TablePage] {
        self.pages
    }

    /// Snapshot lookup suitable for host_walk::walk. Addresses are numeric keys,
    /// never physical reads. Unaligned/out-of-image words return None, including
    /// addresses in unused assigned backing.
    pub fn read_word(&self, address: u64) -> Option<u64> {
        let offset = address.checked_sub(self.backing.base())?;
        if offset & 7 != 0 {
            return None;
        }
        let page = usize::try_from(offset / PAGE_BYTES as u64).ok()?;
        let word = (offset % PAGE_BYTES as u64) as usize / core::mem::size_of::<u64>();
        self.pages.get(page).map(|page| page.words[word])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputRange {
    MappingIo(usize),
    MappingSystem(usize),
    Protected(usize),
    Backing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    MappingRanges,
    ProtectedRanges,
    TablePages,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    LimitExceeded(Limit),
    Address { range: InputRange, error: AddressError },
    LengthNotPageAligned(InputRange),
    IoAddressOutsideWidth { mapping: usize },
    UnsortedOrOverlapping(InputRange),
    ProtectedOutput { mapping: usize, protected: usize },
    TableBackingOutput { mapping: usize },
    InsufficientCapacity { required: u64, available: usize },
    Encoding(EncodingError),
}

struct Prepared {
    backing: PhysicalRange,
    pages: usize,
    directories: [u64; 3],
    leaves: [[u64; 2]; 4],
}

/// Build an immutable offline host-table image in caller-owned bounded storage.
/// On every Err, all storage is unchanged. On success only the used prefix is
/// initialized; the entire assigned span is excluded from output mappings.
///
/// The sorted input contract permits arithmetic sizing before any per-page
/// work. Preflight is O(P + M log(P + 1)); emission visits at most 512 times the
/// number of available table pages. Empty mappings emit one all-absent root.
/// This function must never be used to modify tables visible to active hardware.
pub fn build<'a>(
    policy: AddressPolicy,
    backing_base: u64,
    storage: &'a mut [TablePage],
    mappings: &[MappingRange],
    protected: &[ProtectedRange],
) -> Result<HostPageTableImage<'a>, BuildError> {
    let prepared = prepare(policy, backing_base, storage.len(), mappings, protected)?;
    let pages = &mut storage[..prepared.pages];
    for page in pages.iter_mut() {
        page.words.fill(HostPageEntry::ABSENT.word());
    }
    emit(&prepared, pages, mappings);
    Ok(HostPageTableImage { backing: prepared.backing, pages })
}

fn prepare(
    policy: AddressPolicy,
    backing_base: u64,
    capacity: usize,
    mappings: &[MappingRange],
    protected: &[ProtectedRange],
) -> Result<Prepared, BuildError> {
    if mappings.len() > MAX_MAPPING_RANGES {
        return Err(BuildError::LimitExceeded(Limit::MappingRanges));
    }
    if protected.len() > MAX_PROTECTED_RANGES {
        return Err(BuildError::LimitExceeded(Limit::ProtectedRanges));
    }
    if capacity > MAX_TABLE_PAGES {
        return Err(BuildError::LimitExceeded(Limit::TablePages));
    }
    let backing = if capacity == 0 {
        None
    } else {
        Some(validate_physical(
            policy,
            backing_base,
            capacity as u64 * PAGE_BYTES as u64,
            InputRange::Backing,
        )?)
    };
    let mut previous_last = None;
    for (index, range) in protected.iter().enumerate() {
        let input = InputRange::Protected(index);
        let checked = validate_physical(policy, range.base, range.len, input)?;
        if previous_last.is_some_and(|last| range.base <= last) {
            return Err(BuildError::UnsortedOrOverlapping(input));
        }
        previous_last = Some(checked.last_byte());
    }
    let mut required = 1u64;
    previous_last = None;
    for (index, mapping) in mappings.iter().enumerate() {
        let input = InputRange::MappingIo(index);
        let last = validate_io(mapping.io_base, mapping.len, index)?;
        if previous_last.is_some_and(|last| mapping.io_base <= last) {
            return Err(BuildError::UnsortedOrOverlapping(input));
        }
        let output = validate_physical(
            policy,
            mapping.system_base,
            mapping.len,
            InputRange::MappingSystem(index),
        )?;
        if let Some(backing) = backing
            && output.base() <= backing.last_byte()
            && backing.base() <= output.last_byte()
        {
            return Err(BuildError::TableBackingOutput { mapping: index });
        }
        // Every protected range was validated before this binary search. The
        // first range ending at/after output.base is the only possible first hit.
        let candidate =
            protected.partition_point(|range| range.base + range.len - 1 < output.base());
        if let Some(range) = protected.get(candidate)
            && range.base <= output.last_byte()
        {
            return Err(BuildError::ProtectedOutput { mapping: index, protected: candidate });
        }
        // Each distinct prefix needs one L1, L2 or L3 table. Sorted, disjoint
        // ranges can share only the prior range's final prefix at each level.
        // Unsigned 48-bit DVA bounds make the sum at most 134,480,385 pages.
        for shift in [21, 30, 39] {
            let first_prefix = mapping.io_base >> shift;
            let last_prefix = last >> shift;
            let shared = previous_last.is_some_and(|last| last >> shift == first_prefix);
            required += last_prefix - first_prefix + 1 - u64::from(shared);
        }
        previous_last = Some(last);
    }
    if required > capacity as u64 {
        return Err(BuildError::InsufficientCapacity { required, available: capacity });
    }
    // required >= 1, so the capacity check excludes the no-backing case. Keep
    // this explicit error before writes if this preparation code ever changes.
    let backing =
        backing.ok_or(BuildError::InsufficientCapacity { required, available: capacity })?;
    let mut directories = [0; 3];
    for (index, level) in
        [PageLevel::Four, PageLevel::Three, PageLevel::Two].into_iter().enumerate()
    {
        directories[index] =
            HostPageEntry::directory(policy, level, backing_base, Permissions::ReadWrite)
                .map_err(BuildError::Encoding)?
                .word()
                & !ADDRESS_MASK;
    }
    let mut leaves = [[0; 2]; 4];
    for (permission, permissions) in
        [Permissions::None, Permissions::Read, Permissions::Write, Permissions::ReadWrite]
            .into_iter()
            .enumerate()
    {
        for (coherent, coherency) in
            [PageCoherency::Inherit, PageCoherency::ForceCoherent].into_iter().enumerate()
        {
            leaves[permission][coherent] =
                HostPageEntry::leaf_4k(policy, backing_base, permissions, coherency)
                    .map_err(BuildError::Encoding)?
                    .word()
                    & !ADDRESS_MASK;
        }
    }
    Ok(Prepared { backing, pages: required as usize, directories, leaves })
}

fn validate_io(base: u64, len: u64, mapping: usize) -> Result<u64, BuildError> {
    let input = InputRange::MappingIo(mapping);
    let error = |error| BuildError::Address { range: input, error };
    if len == 0 {
        return Err(error(AddressError::EmptyRange));
    }
    if base & (PAGE_BYTES as u64 - 1) != 0 {
        return Err(error(AddressError::Misaligned));
    }
    if len & (PAGE_BYTES as u64 - 1) != 0 {
        return Err(BuildError::LengthNotPageAligned(input));
    }
    let last = base.checked_add(len - 1).ok_or_else(|| error(AddressError::Overflow))?;
    if last >> 48 != 0 {
        return Err(BuildError::IoAddressOutsideWidth { mapping });
    }
    Ok(last)
}

fn validate_physical(
    policy: AddressPolicy,
    base: u64,
    len: u64,
    input: InputRange,
) -> Result<PhysicalRange, BuildError> {
    if len & (PAGE_BYTES as u64 - 1) != 0 {
        return Err(BuildError::LengthNotPageAligned(input));
    }
    policy
        .validate(base, len, PAGE_BYTES as u64)
        .map_err(|error| BuildError::Address { range: input, error })
}

fn emit(prepared: &Prepared, pages: &mut [TablePage], mappings: &[MappingRange]) {
    let mut path = [0usize; 4];
    let mut next_page = 1;
    let mut previous_io = None;
    for mapping in mappings {
        let permission = match mapping.permissions {
            Permissions::None => 0,
            Permissions::Read => 1,
            Permissions::Write => 2,
            Permissions::ReadWrite => 3,
        };
        let coherent = match mapping.coherency {
            PageCoherency::Inherit => 0,
            PageCoherency::ForceCoherent => 1,
        };
        let mut offset = 0;
        while offset < mapping.len {
            let io = mapping.io_base + offset;
            for (depth, shift) in [39, 30, 21].into_iter().enumerate() {
                if previous_io.is_none_or(|previous| previous >> shift != io >> shift) {
                    let address = prepared.backing.base() + next_page as u64 * PAGE_BYTES as u64;
                    let index = ((io >> shift) & 511) as usize;
                    pages[path[depth]].words[index] = address | prepared.directories[depth];
                    path[depth + 1] = next_page;
                    next_page += 1;
                }
            }
            let index = ((io >> 12) & 511) as usize;
            pages[path[3]].words[index] =
                (mapping.system_base + offset) | prepared.leaves[permission][coherent];
            previous_io = Some(io);
            offset += PAGE_BYTES as u64;
        }
    }
}

#[cfg(test)]
mod tests;
