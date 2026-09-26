//! Bounded bitmap-kernel dump indexing; format evidence is recorded in ../FORMAT.md.

use std::{io::Read, path::Path};

use svmvisor_hypervisor::memory::address::PAGE_BYTES;

use crate::capture::image::{CaptureImage, ImageError, PhysicalRun, dump};

const SECONDARY_BYTES: usize = 0x038;
const PAYLOAD_OFFSET: usize = 0x020;
const PRESENT_PAGES_OFFSET: usize = 0x028;
const BITMAP_PAGES_OFFSET: usize = 0x030;
const MAX_BITMAP_BYTES: u64 = 16 * 1024 * 1024;
const RANK_BYTES: usize = 512;

pub(super) struct BitmapIndex {
    bytes: Vec<u8>,
    ranks: Vec<u64>,
    page_count: u64,
    payload_offset: u64,
}

impl BitmapIndex {
    fn new(
        bytes: Vec<u8>,
        page_count: u64,
        present_pages: u64,
        payload_offset: u64,
    ) -> Result<Self, ImageError> {
        let tail_bits = page_count % 8;
        if tail_bits != 0 && bytes.last().is_some_and(|byte| byte >> tail_bits != 0) {
            return Err(ImageError::InvalidDump("bits outside declared bitmap page count"));
        }
        let mut ranks = Vec::with_capacity(bytes.len().div_ceil(RANK_BYTES));
        let mut count = 0u64;
        for chunk in bytes.chunks(RANK_BYTES) {
            ranks.push(count);
            count += chunk.iter().map(|byte| u64::from(byte.count_ones())).sum::<u64>();
        }
        if count != present_pages {
            return Err(ImageError::InvalidDump(
                "bitmap population differs from present page count",
            ));
        }
        Ok(Self { bytes, ranks, page_count, payload_offset })
    }

    pub(super) fn max_physical_address(&self) -> u64 {
        // Admission bounded the entire represented physical span, including missing tail pages.
        self.page_count * PAGE_BYTES as u64 - 1
    }

    pub(super) fn run(&self, address: u64) -> Option<PhysicalRun> {
        let page = address / PAGE_BYTES as u64;
        if page >= self.page_count {
            return None;
        }
        let byte_index = (page / 8) as usize;
        let bit = (page % 8) as u32;
        let byte = self.bytes[byte_index];
        if byte & (1 << bit) == 0 {
            return None;
        }
        let block = byte_index / RANK_BYTES;
        let preceding = self.ranks[block]
            + self.bytes[block * RANK_BYTES..byte_index]
                .iter()
                .map(|value| u64::from(value.count_ones()))
                .sum::<u64>()
            + u64::from((byte & ((1 << bit) - 1)).count_ones());
        Some(PhysicalRun {
            start: page * PAGE_BYTES as u64,
            length: PAGE_BYTES as u64,
            file_offset: self.payload_offset + preceding * PAGE_BYTES as u64,
        })
    }
}

impl CaptureImage {
    pub(crate) fn open_bitmap_kernel_dump(path: &Path) -> Result<Self, ImageError> {
        let (mut file, length, header) = dump::open_header(path, 6)?;
        let mut secondary = [0; SECONDARY_BYTES];
        file.read_exact(&mut secondary).map_err(ImageError::Read)?;
        if &secondary[..8] != b"SDMPDUMP" {
            return Err(ImageError::InvalidDump("expected SDMP/DUMP bitmap-kernel header"));
        }
        let payload_offset = dump::read_u64(&secondary, PAYLOAD_OFFSET);
        let present_pages = dump::read_u64(&secondary, PRESENT_PAGES_OFFSET);
        let page_count = dump::read_u64(&secondary, BITMAP_PAGES_OFFSET);
        let bitmap_bytes = page_count.div_ceil(8);
        if bitmap_bytes == 0 || bitmap_bytes > MAX_BITMAP_BYTES {
            return Err(ImageError::InvalidDump("bitmap must contain 1..16 MiB of metadata"));
        }
        page_count.checked_mul(PAGE_BYTES as u64).ok_or(ImageError::AddressOverflow)?;
        if present_pages == 0 || present_pages > page_count {
            return Err(ImageError::InvalidDump("invalid present page count"));
        }
        let bitmap_end = dump::HEADER_BYTES as u64 + SECONDARY_BYTES as u64 + bitmap_bytes;
        let aligned_end =
            bitmap_end.checked_add(PAGE_BYTES as u64 - 1).ok_or(ImageError::AddressOverflow)?
                & !(PAGE_BYTES as u64 - 1);
        if payload_offset != aligned_end {
            return Err(ImageError::InvalidDump(
                "payload must follow page-aligned bitmap metadata",
            ));
        }
        let payload_bytes =
            present_pages.checked_mul(PAGE_BYTES as u64).ok_or(ImageError::AddressOverflow)?;
        let expected_length =
            payload_offset.checked_add(payload_bytes).ok_or(ImageError::AddressOverflow)?;
        if expected_length != length {
            return Err(ImageError::InvalidDump("bitmap payload length mismatch"));
        }
        let mut bytes = vec![0; bitmap_bytes as usize];
        file.read_exact(&mut bytes).map_err(ImageError::Read)?;
        let bitmap = BitmapIndex::new(bytes, page_count, present_pages, payload_offset)?;
        let mut metadata = dump::metadata(&header, present_pages);
        metadata.bitmap_pages = Some(page_count);
        Ok(Self { file, runs: Vec::new(), bitmap: Some(bitmap), dump_metadata: Some(metadata) })
    }
}

#[cfg(test)]
pub(crate) fn bitmap_dump_fixture(
    pages: &[(u64, &[u8])],
    bitmap_pages: u64,
    root: u64,
    list: u64,
) -> Vec<u8> {
    let mut bytes = dump::full_dump_fixture(&[], root, list);
    bytes[0xf98..0xf9c].copy_from_slice(&6u32.to_le_bytes());
    let bitmap_bytes = bitmap_pages.div_ceil(8) as usize;
    let metadata_end = dump::HEADER_BYTES + SECONDARY_BYTES + bitmap_bytes;
    let payload_offset = metadata_end.div_ceil(PAGE_BYTES) * PAGE_BYTES;
    bytes.resize(payload_offset, 0);
    let secondary = &mut bytes[dump::HEADER_BYTES..];
    secondary[..8].copy_from_slice(b"SDMPDUMP");
    secondary[PAYLOAD_OFFSET..PAYLOAD_OFFSET + 8]
        .copy_from_slice(&(payload_offset as u64).to_le_bytes());
    secondary[PRESENT_PAGES_OFFSET..PRESENT_PAGES_OFFSET + 8]
        .copy_from_slice(&(pages.len() as u64).to_le_bytes());
    secondary[BITMAP_PAGES_OFFSET..BITMAP_PAGES_OFFSET + 8]
        .copy_from_slice(&bitmap_pages.to_le_bytes());
    let mut previous = None;
    for &(address, page) in pages {
        assert_eq!(page.len(), PAGE_BYTES);
        assert_eq!(address % PAGE_BYTES as u64, 0);
        assert!(previous.is_none_or(|previous| previous < address));
        previous = Some(address);
        let pfn = address / PAGE_BYTES as u64;
        assert!(pfn < bitmap_pages);
        bytes[dump::HEADER_BYTES + SECONDARY_BYTES + (pfn / 8) as usize] |= 1 << (pfn % 8);
        bytes.extend_from_slice(page);
    }
    let length = bytes.len() as u64;
    bytes[0xfa0..0xfa8].copy_from_slice(&length.to_le_bytes());
    bytes
}

#[cfg(test)]
mod tests;
