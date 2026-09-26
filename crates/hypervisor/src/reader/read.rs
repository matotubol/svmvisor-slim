//! Bounded contiguous reads from caller-supplied memory images.
//!
//! Translations and data reads happen separately. The result is not an atomic snapshot if the
//! caller changes the supplied image between callbacks. This module does not map live memory.

use crate::memory::address::{PAGE_BYTES, is_canonical_48};

use super::paging::{self, PagingConfig, PagingError};

/// Maximum output length for one read.
pub const MAX_READ_BYTES: usize = 16 * PAGE_BYTES;
/// Maximum page walks, including an unaligned first page.
pub const MAX_PAGE_WALKS: usize = MAX_READ_BYTES / PAGE_BYTES + 1;

/// Completed prefix and the reason reading stopped, if any.
/// Completion means callbacks supplied those bytes, not that they share one image state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadReport {
    pub bytes_read: usize,
    pub error: Option<ReadError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    LengthLimit,
    AddressOverflow,
    NoncanonicalRange,
    WalkLimit,
    Paging(PagingError),
}

impl From<PagingError> for ReadError {
    fn from(error: PagingError) -> Self {
        Self::Paging(error)
    }
}

/// Read one virtual range using a caller-provided PML4 address and physical-image callback.
///
/// The callback must initialize its entire slice before returning `Ok(())`. A short or unavailable
/// read must return `Err(PagingError::PhysicalRead)`; it may modify its slice before failing. The
/// callback receives only local scratch, so failure never changes the unread output tail. Bytes
/// from a failed callback are discarded and are not counted in `bytes_read`.
/// The callback's own writes to its source or other state cannot be rolled back by this function.
///
/// A successful translation is used for its data callback without revalidation. If the source
/// changes, that address may already refer to different data; even a successful read may combine
/// bytes from different image states. Consistency across table and data callbacks, and across
/// separate operations, requires the caller to keep the supplied image stable throughout.
///
/// Each iteration reads at most one 4 KiB page fragment, even with huge-page mappings. There are
/// at most `MAX_PAGE_WALKS` translations, four table callbacks per translation, and one data
/// callback per translation. The caller controls callback execution time. No retries occur.
///
/// Oversized, overflowing, or noncanonical ranges fail before any callback or output mutation.
/// Empty output succeeds without inspecting the root or invoking the callback. Other failures
/// preserve the completed prefix and leave every byte after it untouched.
pub fn read_virtual(
    config: PagingConfig,
    root_pa: u64,
    va: u64,
    output: &mut [u8],
    read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), PagingError>,
) -> ReadReport {
    if let Err(error) = validate_range(va, output.len()) {
        return ReadReport { bytes_read: 0, error: Some(error) };
    }

    let mut bytes_read = 0;
    let mut scratch = [0u8; PAGE_BYTES];
    for _ in 0..MAX_PAGE_WALKS {
        if bytes_read == output.len() {
            return ReadReport { bytes_read, error: None };
        }
        // The complete inclusive range was checked before any callback.
        let current_va = va + bytes_read as u64;
        let translation = match paging::translate(config, root_pa, current_va, read) {
            Ok(translation) => translation,
            Err(error) => return ReadReport { bytes_read, error: Some(error.into()) },
        };
        let page_remaining = PAGE_BYTES - (current_va as usize & (PAGE_BYTES - 1));
        let length = page_remaining.min(output.len() - bytes_read);
        if let Err(error) = read(translation.pa(), &mut scratch[..length]) {
            return ReadReport { bytes_read, error: Some(error.into()) };
        }
        output[bytes_read..bytes_read + length].copy_from_slice(&scratch[..length]);
        bytes_read += length;
    }
    let error = (bytes_read != output.len()).then_some(ReadError::WalkLimit);
    ReadReport { bytes_read, error }
}

fn validate_range(va: u64, length: usize) -> Result<(), ReadError> {
    if length > MAX_READ_BYTES {
        return Err(ReadError::LengthLimit);
    }
    if length == 0 {
        return Ok(());
    }
    let last = va.checked_add(length as u64 - 1).ok_or(ReadError::AddressOverflow)?;
    // The fixed length limit prevents jumping across the entire canonical hole.
    if !is_canonical_48(va) || !is_canonical_48(last) {
        return Err(ReadError::NoncanonicalRange);
    }
    Ok(())
}
