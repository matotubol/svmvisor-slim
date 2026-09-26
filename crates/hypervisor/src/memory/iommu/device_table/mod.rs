//! Bounded, uninstalled AMD device-table images for all 16-bit DeviceIDs.
//!
//! A complete image has 65,536 32-byte entries in 512 contiguous 4 KiB pages.
//! The explicit default must deny I/O reads/writes and abort DTE-controlled
//! interrupts. Overrides use the existing complete restricted entry codec.
//! This describes the unsegmented format; actual DevTblSegEn=0 is external.
//!
//! Numeric backing and entry validation establish neither physical ownership
//! nor DMA protection. Referenced page/interrupt tables, aliases, global modes,
//! exclusions, SMI filtering, ATS caches, quiescence and installation remain
//! external. In particular, EX=0 cannot override the global exclusion Allow bit,
//! I=0 does not drain cached device translations, and DTEs do not control SMI.
//! No hardware is accessed and no Windows coexistence policy is selected.
//!
//! Sources: 48882-3.11 physical pp60-61,63,70-75,78-79,214,223; table/layout
//! PNGs checked. See README.md for the storage contract and remaining duties.
#![forbid(unsafe_code)]

use super::tables::{CompleteHostDeviceEntry, DteInterruptPolicy, EncodingError, Permissions};
use crate::memory::address::{AddressError, AddressPolicy, PAGE_BYTES, PhysicalRange};

pub const ENTRY_COUNT: usize = 1 << 16;
pub const ENTRY_BYTES: usize = 32;
pub const ENTRIES_PER_PAGE: usize = PAGE_BYTES / ENTRY_BYTES;
pub const TABLE_PAGES: usize = ENTRY_COUNT / ENTRIES_PER_PAGE;
pub const TABLE_BYTES: usize = TABLE_PAGES * PAGE_BYTES;
pub const WORDS_PER_PAGE: usize = PAGE_BYTES / core::mem::size_of::<u64>();
/// Local bounds, checked before traversing inputs or mutating storage.
pub const MAX_ASSIGNMENTS: usize = 4096;
/// At most 4 MiB is assigned; only the first 2 MiB contains the device table.
pub const MAX_BACKING_PAGES: usize = 1024;

/// Raw little-endian u64 words on the supported x86-64 target. This page has a
/// hardware memory layout; CompleteHostDeviceEntry itself deliberately does not.
/// The Rust address and the caller's numeric physical assignment are separate.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C, align(4096))]
pub struct DeviceTablePage {
    words: [u64; WORDS_PER_PAGE],
}

const _: () = {
    assert!(core::mem::size_of::<DeviceTablePage>() == PAGE_BYTES);
    assert!(core::mem::align_of::<DeviceTablePage>() == PAGE_BYTES);
    assert!(core::mem::offset_of!(DeviceTablePage, words) == 0);
    assert!(TABLE_PAGES == 512);
    assert!(TABLE_BYTES == 0x20_0000);
};

impl DeviceTablePage {
    /// Storage initializer only: zero DTEs permit passthrough, so this is never
    /// an accepted default or a constructed device-table image.
    pub const ZERO: Self = Self { words: [0; WORDS_PER_PAGE] };

    pub const fn words(&self) -> &[u64; WORDS_PER_PAGE] {
        &self.words
    }
}

/// An explicit inclusive DeviceID range. Inputs must be sorted by `first`
/// without overlap; adjacent ranges are allowed. No alias or topology inference
/// is performed. The same complete entry is emitted for every ID in the range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub first: u16,
    pub last: u16,
    pub entry: CompleteHostDeviceEntry,
}

/// Immutable offline words borrowing caller-owned storage. This is not an
/// installation, an allocation owner, or a protection/reader readiness token.
#[derive(Debug)]
pub struct DeviceTableImage<'a> {
    table: PhysicalRange,
    backing: PhysicalRange,
    pages: &'a [DeviceTablePage],
}

impl DeviceTableImage<'_> {
    /// Exactly the emitted 2 MiB table, without unused assigned capacity.
    pub const fn table_range(&self) -> PhysicalRange {
        self.table
    }

    /// Every assigned byte, including unused capacity requiring protection.
    pub const fn backing_range(&self) -> PhysicalRange {
        self.backing
    }

    /// Exactly 512 pages in DeviceID/physical order; extra supplied pages are
    /// validated but not changed and are not exposed as part of the table.
    pub const fn pages(&self) -> &[DeviceTablePage] {
        self.pages
    }

    pub fn entry_words(&self, device_id: u16) -> [u64; 4] {
        let index = usize::from(device_id);
        let page = &self.pages[index / ENTRIES_PER_PAGE];
        let word = (index % ENTRIES_PER_PAGE) * 4;
        [page.words[word], page.words[word + 1], page.words[word + 2], page.words[word + 3]]
    }

    /// Inert MMIO Offset 0000h encoding: Size[8:0] is page count minus one,
    /// so full coverage uses 1FFh. DevTabBase occupies bits 51:12 (p214).
    /// Actual unsegmented mode and safe installation are not established here.
    pub const fn base_register_value(&self) -> u64 {
        self.table.base() | (TABLE_PAGES as u64 - 1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputEntry {
    Default,
    Assignment(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    TooManyAssignments,
    TooManyBackingPages,
    InsufficientCapacity {
        available: usize,
    },
    BackingAddress(AddressError),
    Encoding {
        input: InputEntry,
        error: EncodingError,
    },
    DefaultAllowsDma,
    DefaultRemapsInterrupts,
    ReversedAssignment {
        assignment: usize,
    },
    UnsortedOrOverlapping {
        assignment: usize,
    },
    /// Same DomainID with different host roots has undefined hardware behavior
    /// (p70). Mode is already fixed to four by the complete entry codec.
    InconsistentDomain {
        first: InputEntry,
        second: InputEntry,
        domain_id: u16,
    },
}

/// Construct one complete, unsegmented offline image. Every error leaves every
/// supplied byte unchanged. All numeric backing, entry, range and domain checks
/// finish before the first store. Storage visible to hardware must not be used.
///
/// The explicit default must have Permissions::None and AbortControlled, even
/// if overrides cover every DeviceID. Entries are re-decoded under this policy.
/// Emitted entries sharing a DomainID must share their host root; cross-IOMMU
/// domain assignments and the referenced tables' contents/ownership are external.
/// Preflight uses O(A^2) time for at most 4,096 ranges and constant scratch space;
/// emission visits exactly 65,536 entries. This function allocates nothing.
pub fn build<'a>(
    policy: AddressPolicy,
    backing_base: u64,
    storage: &'a mut [DeviceTablePage],
    default: CompleteHostDeviceEntry,
    assignments: &[Assignment],
) -> Result<DeviceTableImage<'a>, BuildError> {
    let (table, backing) = prepare(policy, backing_base, storage.len(), default, assignments)?;
    let pages = &mut storage[..TABLE_PAGES];
    let mut assignment = 0;
    for (device_id, words) in
        pages.iter_mut().flat_map(|page| page.words.chunks_exact_mut(4)).enumerate()
    {
        while assignments.get(assignment).is_some_and(|range| device_id > usize::from(range.last)) {
            assignment += 1;
        }
        let entry = match assignments.get(assignment) {
            Some(range) if device_id >= usize::from(range.first) => range.entry,
            _ => default,
        };
        words.copy_from_slice(&entry.words());
    }
    Ok(DeviceTableImage { table, backing, pages })
}

fn prepare(
    policy: AddressPolicy,
    backing_base: u64,
    capacity: usize,
    default: CompleteHostDeviceEntry,
    assignments: &[Assignment],
) -> Result<(PhysicalRange, PhysicalRange), BuildError> {
    if assignments.len() > MAX_ASSIGNMENTS {
        return Err(BuildError::TooManyAssignments);
    }
    if capacity > MAX_BACKING_PAGES {
        return Err(BuildError::TooManyBackingPages);
    }
    if capacity < TABLE_PAGES {
        return Err(BuildError::InsufficientCapacity { available: capacity });
    }
    let backing = policy
        .validate(backing_base, capacity as u64 * PAGE_BYTES as u64, PAGE_BYTES as u64)
        .map_err(BuildError::BackingAddress)?;
    let table = policy
        .validate(backing_base, TABLE_BYTES as u64, PAGE_BYTES as u64)
        .map_err(BuildError::BackingAddress)?;
    revalidate(policy, default, InputEntry::Default)?;
    if default.translation().permissions() != Permissions::None {
        return Err(BuildError::DefaultAllowsDma);
    }
    if default.interrupt_policy() != DteInterruptPolicy::AbortControlled {
        return Err(BuildError::DefaultRemapsInterrupts);
    }
    let mut assigned = 0usize;
    let mut previous_last = None;
    for (index, range) in assignments.iter().enumerate() {
        if range.first > range.last {
            return Err(BuildError::ReversedAssignment { assignment: index });
        }
        if previous_last.is_some_and(|last| range.first <= last) {
            return Err(BuildError::UnsortedOrOverlapping { assignment: index });
        }
        revalidate(policy, range.entry, InputEntry::Assignment(index))?;
        previous_last = Some(range.last);
        assigned += usize::from(range.last) - usize::from(range.first) + 1;
    }
    for (index, range) in assignments.iter().enumerate() {
        let current = InputEntry::Assignment(index);
        if assigned < ENTRY_COUNT {
            consistent_domain(default, InputEntry::Default, range.entry, current)?;
        }
        for (previous, earlier) in assignments[..index].iter().enumerate() {
            consistent_domain(
                earlier.entry,
                InputEntry::Assignment(previous),
                range.entry,
                current,
            )?;
        }
    }
    Ok((table, backing))
}

fn revalidate(
    policy: AddressPolicy,
    entry: CompleteHostDeviceEntry,
    input: InputEntry,
) -> Result<(), BuildError> {
    CompleteHostDeviceEntry::decode(policy, entry.words())
        .map(|_| ())
        .map_err(|error| BuildError::Encoding { input, error })
}

fn consistent_domain(
    first: CompleteHostDeviceEntry,
    first_input: InputEntry,
    second: CompleteHostDeviceEntry,
    second_input: InputEntry,
) -> Result<(), BuildError> {
    let first = first.translation();
    let second = second.translation();
    if first.domain_id() == second.domain_id() && first.root_address() != second.root_address() {
        return Err(BuildError::InconsistentDomain {
            first: first_input,
            second: second_input,
            domain_id: first.domain_id(),
        });
    }
    Ok(())
}
