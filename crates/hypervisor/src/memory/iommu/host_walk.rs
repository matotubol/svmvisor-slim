//! Offline check of one untranslated memory address through the restricted
//! four-level host format. This is not an IOMMU emulator or an access grant.
//!
//! The callback supplies words from one immutable, caller-owned table snapshot;
//! its numeric addresses are lookup keys, not permission to read physical memory.
//! At most four words are requested. No physical address is dereferenced here.
//! A live, changing table walk cannot provide the snapshot this checker requires.
//!
//! Only the lower half of a DTE is modeled. Device identity, interrupt and special
//! transactions, exclusions, ATS, hardware feature/control state, caches/TLBs,
//! requester coverage and ownership are outside the result. Checking one address
//! does not establish that an entire protected region is inaccessible to DMA.
//!
//! Sources: 48882-3.11 physical pp79-85, including table/index layout PNGs p82/p85.
//! DVA bits above 47 must be zero; x86 canonical sign extension does not apply.
#![forbid(unsafe_code)]

use super::tables::{
    EncodingError, HostDeviceEntry, HostPageEntry, PageCoherency, PageLevel, Permissions,
};
use crate::memory::address::AddressPolicy;

pub const MAX_WORD_READS: usize = 4;

/// Numeric result for a present leaf, even when its effective permissions deny
/// both reads and writes. An absent entry instead returns `Ok(None)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostTranslation {
    pub system_address: u64,
    pub permissions: Permissions,
    pub coherency: PageCoherency,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalkError<E> {
    IoAddressOutsideWidth,
    DeviceEncoding(EncodingError),
    Read {
        level: PageLevel,
        entry_address: u64,
        error: E,
    },
    PageEncoding {
        level: PageLevel,
        entry_address: u64,
        error: EncodingError,
    },
    /// A checked entry must supply all fields required by its containing level.
    IncompleteEntry,
}

/// Check a single address against immutable offline words. The supplied policy
/// revalidates the DTE too: the entry may have been built with a different width
/// or encryption-bit policy. This function neither observes nor configures an
/// IOMMU and must not be used to mint runtime authorization.
pub fn walk<E>(
    policy: AddressPolicy,
    device: HostDeviceEntry,
    io_address: u64,
    mut read_word: impl FnMut(u64) -> Result<u64, E>,
) -> Result<Option<HostTranslation>, WalkError<E>> {
    if io_address >> 48 != 0 {
        return Err(WalkError::IoAddressOutsideWidth);
    }
    let device =
        HostDeviceEntry::decode(policy, device.words()).map_err(WalkError::DeviceEncoding)?;
    let mut table = device.root_address();
    let mut readable = device.permissions().allows_read();
    let mut writable = device.permissions().allows_write();
    for level in [PageLevel::Four, PageLevel::Three, PageLevel::Two, PageLevel::One] {
        let shift = 12 + 9 * (level.number() - 1);
        let index = (io_address >> shift) & 511;
        // The decoder validates the complete 4 KiB table page against a maximum
        // 52-bit physical range. Its final aligned word cannot overflow u64.
        let entry_address = table + index * 8;
        let raw = read_word(entry_address).map_err(|error| WalkError::Read {
            level,
            entry_address,
            error,
        })?;
        let entry = HostPageEntry::decode(policy, level, raw)
            .map_err(|error| WalkError::PageEncoding { level, entry_address, error })?;
        if !entry.is_present() {
            return Ok(None);
        }
        let address = entry.address().ok_or(WalkError::IncompleteEntry)?;
        let permissions = entry.permissions().ok_or(WalkError::IncompleteEntry)?;
        readable &= permissions.allows_read();
        writable &= permissions.allows_write();
        if level == PageLevel::One {
            return Ok(Some(HostTranslation {
                system_address: address | (io_address & 4095),
                permissions: match (readable, writable) {
                    (false, false) => Permissions::None,
                    (true, false) => Permissions::Read,
                    (false, true) => Permissions::Write,
                    (true, true) => Permissions::ReadWrite,
                },
                coherency: entry.coherency().ok_or(WalkError::IncompleteEntry)?,
            }));
        }
        table = address;
    }
    Err(WalkError::IncompleteEntry)
}

#[cfg(test)]
mod tests;
