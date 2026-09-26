//! Executable, disconnected software AMD IOMMU core.
//!
//! Guest input has its own architectural decoders. Private output uses the
//! existing restricted host codecs. No guest address is a hardware pointer.
//! This module does not publish PCI/IVRS, admit a platform, capture live guest
//! memory, or install a native owner. See README.md for the remaining boundary.
#![forbid(unsafe_code)]

pub mod compose;
pub mod device;
pub mod guest;
pub mod presentation;
pub mod registers;
pub mod snapshot;

pub const GUEST_ADDRESS_BITS: u8 = 48;
pub const GUEST_LIMIT: u64 = 1 << GUEST_ADDRESS_BITS;

pub(crate) const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
pub(crate) const PAGE: u64 = 4096;

pub(crate) fn guest_span(base: u64, len: u64, alignment: u64) -> bool {
    len != 0
        && base & (alignment - 1) == 0
        && base.checked_add(len).is_some_and(|end| end <= GUEST_LIMIT)
}

pub(crate) fn permissions(read: bool, write: bool) -> super::tables::Permissions {
    use super::tables::Permissions;
    match (read, write) {
        (false, false) => Permissions::None,
        (true, false) => Permissions::Read,
        (false, true) => Permissions::Write,
        (true, true) => Permissions::ReadWrite,
    }
}

pub(crate) fn intersect(
    a: super::tables::Permissions,
    b: super::tables::Permissions,
) -> super::tables::Permissions {
    permissions(a.allows_read() && b.allows_read(), a.allows_write() && b.allows_write())
}
