use super::{COMMAND_BYTES, MAX_COMMAND_PAGES, QueueError};
use crate::memory::address::{AddressPolicy, PAGE_BYTES, PhysicalRange};

// MMIO 2000h/2008h contain a byte offset in bits 18:4, not an entry index.
// 48882-3.11 pp252-253, text and PNG checked.
const POINTER_MASK: u64 = 0x0007_fff0;

/// Validated numeric geometry only. No register is read or written and no
/// backing, stopped-state, cache attribute or ownership evidence is established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandRingGeometry {
    backing: PhysicalRange,
    length_encoding: u8,
}

impl CommandRingGeometry {
    /// The entire physical span must fit policy. ComLen is log2(entries):
    /// 8..15, covering 1, 2, 4, ... 128 pages (48882-3.11 p215).
    pub fn new(
        policy: AddressPolicy,
        physical_base: u64,
        page_count: usize,
    ) -> Result<Self, QueueError> {
        if !page_count.is_power_of_two() || page_count > MAX_COMMAND_PAGES {
            return Err(QueueError::InvalidCommandPageCount(page_count));
        }
        let backing = policy
            .validate(physical_base, (page_count * PAGE_BYTES) as u64, PAGE_BYTES as u64)
            .map_err(|error| QueueError::Address { backing: super::Backing::Commands, error })?;
        Ok(Self { backing, length_encoding: 8 + page_count.trailing_zeros() as u8 })
    }

    pub const fn backing(self) -> PhysicalRange {
        self.backing
    }

    pub const fn entry_count(self) -> usize {
        self.backing.len() as usize / COMMAND_BYTES
    }

    /// One slot must stay empty: advancing tail to or beyond head is undefined
    /// (p253). A minimum 256-entry ring therefore holds at most 255 commands.
    pub const fn usable_entries(self) -> usize {
        self.entry_count() - 1
    }

    pub const fn byte_len(self) -> u32 {
        self.backing.len() as u32
    }

    /// Inert MMIO 0008h value: ComBase[51:12], ComLen[59:56], reserved bits zero.
    /// This is not permission to program a live command-buffer base register.
    pub const fn base_register_value(self) -> u64 {
        self.backing.base() | ((self.length_encoding as u64) << 56)
    }

    /// Validate a whole raw head/tail register value without masking bad bits.
    /// The returned value remains a 16-byte-aligned byte offset.
    pub fn validate_offset(self, raw: u64) -> Result<u32, QueueError> {
        if raw & !POINTER_MASK != 0 {
            return Err(QueueError::InvalidPointerBits(raw));
        }
        if raw >= self.backing.len() {
            return Err(QueueError::PointerOutsideRing(raw));
        }
        Ok(raw as u32)
    }

    pub(super) const fn distance(self, from: u32, to: u32) -> u32 {
        (to + self.byte_len() - from) % self.byte_len()
    }

    pub(super) const fn next(self, offset: u32) -> u32 {
        (offset + COMMAND_BYTES as u32) % self.byte_len()
    }
}
