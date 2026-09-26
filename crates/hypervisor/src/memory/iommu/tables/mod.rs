//! Offline AMD IOMMU host-entry formats, not an installed DMA policy.
//!
//! The restricted profile uses four host levels, contiguous directory links and
//! 4 KiB leaves. All optional guest, ATS/PPR, access/dirty-update, CXL, exclusion
//! and page-migration fields are zero. Decoders reject noncanonical ignored bits
//! as well as reserved and unsupported fields; they are not general AMD decoders.
//!
//! `HostDeviceEntry` preserves the DTE bits 127:0 API. `CompleteHostDeviceEntry`
//! emits all 256 bits with mandatory explicit DTE interrupt policy and IV=1.
//! Basic remapping uses 32-bit IRTEs and requires GAEn=0 externally. Five special
//! pass bits are always zero. SMI is outside DTE control and needs a separate
//! filter; even AbortControlled is not a policy that blocks every interrupt.
//!
//! Success proves only numeric field/range validity. There is no hardware access,
//! allocation, table walk, DomainID assignment, requester coverage, alias audit,
//! invalidation, device quiescence, interrupt/DMA enforcement or ownership here.
//! Caller-supplied AddressPolicy is not fresh platform evidence. Hardware HATS,
//! physical width, feature state, coherency and retained table ownership still
//! require independent verification before any future installation.
//!
//! Layout sources, physical pages with text and PNG checked: 48882-3.11 p63,
//! pp64-75, pp82-85, pp90-93. Walk constraints: pp79-81. SMI: pp47,55,75.
//! Basic APIC limits: 24593_3.44_APM_Vol2 pp707,709. See adjacent README.md.

#![forbid(unsafe_code)]

mod complete;
mod device;
mod interrupt;
mod page;

pub use complete::CompleteHostDeviceEntry;
pub use device::HostDeviceEntry;
pub use interrupt::{BasicInterruptEntry, BasicInterruptTable, DteInterruptPolicy};
pub use page::{HostPageEntry, PageCoherency, PageLevel};

use crate::memory::address::{ADDRESS_MASK, AddressError, AddressPolicy, PAGE_BYTES};

const IR: u64 = 1 << 61;
const IW: u64 = 1 << 62;
const PERMISSIONS: u64 = IR | IW;
const LEVEL_MASK: u64 = 7 << 9;

/// Entry-local I/O permissions. Effective access is the AND of the DTE and
/// every traversed entry (48882-3.11 pp70-71, p81, p83 and p85).
/// These values neither grant authority nor account for bypass paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permissions {
    None,
    Read,
    Write,
    ReadWrite,
}

impl Permissions {
    pub const fn allows_read(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    pub const fn allows_write(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }

    const fn bits(self) -> u64 {
        match self {
            Self::None => 0,
            Self::Read => IR,
            Self::Write => IW,
            Self::ReadWrite => IR | IW,
        }
    }

    const fn from_word(word: u64) -> Self {
        match word & PERMISSIONS {
            0 => Self::None,
            IR => Self::Read,
            IW => Self::Write,
            _ => Self::ReadWrite,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodingError {
    Address(AddressError),
    /// A reserved, unsupported or deliberately canonicalized field is nonzero.
    /// `word` is the zero-based 64-bit word within this encoded portion.
    UnsupportedBits {
        word: u8,
        bits: u64,
    },
    /// V=0 is passthrough, not a deny entry; TV=0 is outside this profile.
    DeviceTranslationDisabled,
    /// IV=0 forwards interrupts without remapping; this profile requires IV=1.
    DeviceInterruptMappingDisabled,
    /// IntCtl=1 is passthrough; IntCtl=3 is reserved.
    UnsupportedInterruptControl(u8),
    /// The abort policy requires its ignored root and length fields to be zero.
    NonCanonicalInterruptTable,
    /// Encoded IntTabLen outside the restricted 0..=9 basic-table profile.
    UnsupportedInterruptTableLength(u8),
    /// Basic-table counts must be powers of two in 1..=512.
    UnsupportedInterruptEntryCount(u16),
    NonCanonicalAbortedInterrupt,
    UnsupportedInterruptDestination(u8),
    UnsupportedInterruptVector(u8),
    UnsupportedHostMode(u8),
    UnsupportedPageLevel(u8),
    NonCanonicalAbsent,
    LeafAtWrongLevel(PageLevel),
    DirectoryAtLeafLevel,
    UnsupportedNextLevel {
        current: PageLevel,
        next: u8,
    },
}

fn validate_page(policy: AddressPolicy, address: u64) -> Result<(), EncodingError> {
    policy
        .validate(address, PAGE_BYTES as u64, PAGE_BYTES as u64)
        .map(|_| ())
        .map_err(EncodingError::Address)
}

#[cfg(test)]
mod tests;
