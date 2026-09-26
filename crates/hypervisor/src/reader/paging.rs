//! Passive four-level AMD64 translation of caller-supplied, unencrypted memory images.
//! No access permissions are evaluated and no accessed or dirty bits are changed.

use crate::memory::address::{
    ADDRESS_MASK, NX, PAGE_BYTES, PAT_LARGE, PML4_RESERVED_MASK, PRESENT, PS, is_canonical_48,
};

// Four-level indexing: 24593_3.44_APM_Vol2 p207, p211. Entry formats: p206, p207,
// p211, p215. These are physical PDF pages, not the printed page numbers.
const TABLE_INDEX_BITS: u32 = 9;
const TABLE_INDEX_MASK: u64 = 0x01ff;
const PAGE_OFFSET_BITS: u32 = PAGE_BYTES.trailing_zeros();
const ENTRY_BYTES: usize = size_of::<u64>();
const WALK_LEVELS: u32 = 4;

/// Explicit image profile: four-level paging, no encryption or upper-address-ignore,
/// and PAT support. The caller supplies the physical width and captured EFER.NXE state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagingConfig {
    physical_bits: u8,
    nxe: bool,
    page_1g: bool,
}

impl PagingConfig {
    /// Accept the same 32..=52 physical-width profile as memory::address::AddressPolicy.
    /// `page_1g` states whether the image's processor supported 1-Gbyte pages.
    pub fn new(physical_bits: u8, nxe: bool, page_1g: bool) -> Result<Self, PagingError> {
        if !(32..=52).contains(&physical_bits) {
            return Err(PagingError::UnsupportedPhysicalWidth);
        }
        Ok(Self { physical_bits, nxe, page_1g })
    }

    /// Physical address width declared for the supplied image.
    pub const fn physical_bits(self) -> u8 {
        self.physical_bits
    }

    pub const fn nxe(self) -> bool {
        self.nxe
    }

    pub const fn page_1g(self) -> bool {
        self.page_1g
    }
}

/// A numerical translation, not a grant of read, write, execute, or user access.
/// It retains no reference to the image and does not pin the mapping or backing bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Translation {
    pa: u64,
    page_bytes: u64,
    contiguous_bytes: u64,
}

impl Translation {
    pub const fn pa(self) -> u64 {
        self.pa
    }

    pub const fn page_bytes(self) -> u64 {
        self.page_bytes
    }

    /// Bytes remaining in this mapping, including the translated byte.
    pub const fn contiguous_bytes(self) -> u64 {
        self.contiguous_bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagingError {
    UnsupportedPhysicalWidth,
    NoncanonicalAddress,
    MisalignedRoot,
    RootOutsidePhysicalWidth,
    PhysicalRead,
    NotPresent,
    ReservedBitsSet,
    UnsupportedPageSize,
}

/// Translate one VA with at most four eight-byte reads from an immutable memory image.
/// `root_pa` is the PML4's aligned physical address, not an encoded CR3 register value.
/// The callback must fill the complete slice before returning `Ok(())`; it may modify
/// its scratch slice on error. Callback errors propagate without further reads.
///
/// The caller is responsible for image consistency and the accuracy of the profile.
/// Table entries are sampled separately, without revalidation or retries. A changing
/// callback source can therefore yield a translation assembled from different image states,
/// even when every callback succeeds. The result does not certify a coherent mapping.
/// Software and protection-key bits are accepted; permissions and cache types are not
/// evaluated. In particular this does not establish that a CPU could access the VA.
pub fn translate(
    config: PagingConfig,
    root_pa: u64,
    va: u64,
    read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), PagingError>,
) -> Result<Translation, PagingError> {
    // Canonicality: 24593_3.44_APM_Vol2 p202. Validate before any callback.
    if !is_canonical_48(va) {
        return Err(PagingError::NoncanonicalAddress);
    }
    if root_pa & (PAGE_BYTES as u64 - 1) != 0 {
        return Err(PagingError::MisalignedRoot);
    }
    if root_pa >> config.physical_bits != 0 {
        return Err(PagingError::RootOutsidePhysicalWidth);
    }

    let physical_mask = (1u64 << config.physical_bits) - 1;
    let mut table_pa = root_pa;
    for level in (0..WALK_LEVELS).rev() {
        let shift = PAGE_OFFSET_BITS + TABLE_INDEX_BITS * level;
        let index = (va >> shift) & TABLE_INDEX_MASK;
        let mut bytes = [0; ENTRY_BYTES];
        // Table bases are aligned and width-checked, so this addition cannot overflow
        // or leave the physical width, even for the final entry of the highest table.
        read(table_pa + index * ENTRY_BYTES as u64, &mut bytes)?;
        let entry = u64::from_le_bytes(bytes);
        // All remaining bits are software-owned for P=0: 24593_3.44_APM_Vol2 p216.
        if entry & PRESENT == 0 {
            return Err(PagingError::NotPresent);
        }
        // Only unimplemented ADDRESS bits are reserved, not available bits 62:52.
        // Width, NX, and reserved behavior: 24593_3.44_APM_Vol2 p216, p218, p219.
        if entry & ADDRESS_MASK & !physical_mask != 0 || (!config.nxe && entry & NX != 0) {
            return Err(PagingError::ReservedBitsSet);
        }
        if level == WALK_LEVELS - 1 && entry & PML4_RESERVED_MASK != 0 {
            return Err(PagingError::ReservedBitsSet);
        }
        let large = level != 0 && entry & PS != 0;
        if large && level == 2 && !config.page_1g {
            return Err(PagingError::UnsupportedPageSize);
        }
        if level == 0 || large {
            let page_bytes = 1u64 << shift;
            let offset_mask = page_bytes - 1;
            // PAT is bit 12 in large leaves, bit 7 in PTEs. The intervening low
            // address bits are MBZ: 24593_3.44_APM_Vol2 p207, p211, p215, p218.
            if large && entry & ADDRESS_MASK & offset_mask & !PAT_LARGE != 0 {
                return Err(PagingError::ReservedBitsSet);
            }
            let offset = va & offset_mask;
            return Ok(Translation {
                pa: (entry & ADDRESS_MASK & !offset_mask) | offset,
                page_bytes,
                contiguous_bytes: page_bytes - offset,
            });
        }
        table_pa = entry & ADDRESS_MASK;
    }
    // The final level always returns a leaf or an error.
    Err(PagingError::NotPresent)
}
