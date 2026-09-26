//! Shared AMD64 dump headers and traditional full-dump run parsing (DumpType 1).
//!
//! Layout source: Windows SDK 10.0.28000.0 um/mindumpdef.h, DUMP_HEADER64 and
//! PHYSICAL_MEMORY_DESCRIPTOR64. Payload order is corroborated by QEMU's write_runs:
//! https://github.com/qemu/qemu/blob/master/dump/win_dump-x86.c
//! See the capture format evidence document for the supported subset and offsets.

use std::{fs::File, io::Read, path::Path};

use svmvisor_hypervisor::memory::address::PAGE_BYTES;

use crate::capture::image::{CaptureImage, ImageError, PhysicalRun};

pub(super) const HEADER_BYTES: usize = 0x2000;
const RUN_COUNT_OFFSET: usize = 0x088;
const PAGE_COUNT_OFFSET: usize = 0x090;
const RUN_OFFSET: usize = 0x098;
const RUN_BYTES: usize = 16;
const MAX_RUNS: usize = 43;
const DUMP_TYPE_OFFSET: usize = 0xf98;
const REQUIRED_SPACE_OFFSET: usize = 0xfa0;
const ATTRIBUTES_OFFSET: usize = 0x1050;
// Refuse incomplete, filtered, encrypted, and unknown attribute meanings.
const ALLOWED_ATTRIBUTES: u32 = (1 << 0) | (1 << 1) | (1 << 4) | (1 << 5) | (1 << 7) | (1 << 9);

/// Untrusted header observations; these do not establish captured kernel identity or context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DumpMetadata {
    pub dump_type: u32,
    pub directory_table_base: u64,
    pub ps_active_process_head: u64,
    pub ps_loaded_module_list: u64,
    pub major_version: u32,
    pub minor_version: u32,
    pub run_count: Option<u32>,
    pub page_count: u64,
    pub bitmap_pages: Option<u64>,
}

impl CaptureImage {
    pub(crate) fn open_full_dump(path: &Path) -> Result<Self, ImageError> {
        let (file, length, header) = open_header(path, 1)?;
        let (runs, dump_metadata) = parse(&header, length)?;
        Ok(Self { file, runs, bitmap: None, dump_metadata: Some(dump_metadata) })
    }
}

#[cfg(test)]
pub(crate) fn full_dump_fixture(runs: &[(u64, &[u8])], root: u64, list: u64) -> Vec<u8> {
    let mut bytes = vec![0; HEADER_BYTES];
    bytes[..8].copy_from_slice(b"PAGEDU64");
    bytes[0x030..0x034].copy_from_slice(&0x8664u32.to_le_bytes());
    bytes[DUMP_TYPE_OFFSET..DUMP_TYPE_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[RUN_COUNT_OFFSET..RUN_COUNT_OFFSET + 4]
        .copy_from_slice(&(runs.len() as u32).to_le_bytes());
    bytes[0x010..0x018].copy_from_slice(&root.to_le_bytes());
    bytes[0x028..0x030].copy_from_slice(&list.to_le_bytes());
    let mut pages = 0u64;
    for (index, (start, data)) in runs.iter().enumerate() {
        assert_eq!(start % PAGE_BYTES as u64, 0);
        assert_eq!(data.len() % PAGE_BYTES, 0);
        assert!(index < MAX_RUNS);
        let offset = RUN_OFFSET + index * RUN_BYTES;
        let count = (data.len() / PAGE_BYTES) as u64;
        bytes[offset..offset + 8].copy_from_slice(&(start / PAGE_BYTES as u64).to_le_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&count.to_le_bytes());
        pages += count;
        bytes.extend_from_slice(data);
    }
    bytes[PAGE_COUNT_OFFSET..PAGE_COUNT_OFFSET + 8].copy_from_slice(&pages.to_le_bytes());
    let length = bytes.len() as u64;
    bytes[REQUIRED_SPACE_OFFSET..REQUIRED_SPACE_OFFSET + 8].copy_from_slice(&length.to_le_bytes());
    bytes
}

pub(super) fn open_header(
    path: &Path,
    dump_type: u32,
) -> Result<(File, u64, [u8; HEADER_BYTES]), ImageError> {
    let mut file = File::open(path).map_err(ImageError::Open)?;
    let metadata = file.metadata().map_err(ImageError::Metadata)?;
    if !metadata.is_file() {
        return Err(ImageError::NotRegularFile);
    }
    let mut header = [0; HEADER_BYTES];
    file.read_exact(&mut header).map_err(ImageError::Read)?;
    if &header[..8] != b"PAGEDU64" {
        return Err(ImageError::InvalidDump("expected PAGE/DU64 signature"));
    }
    if read_u32(&header, 0x030) != 0x8664 {
        return Err(ImageError::InvalidDump("machine must be AMD64"));
    }
    if read_u32(&header, DUMP_TYPE_OFFSET) != dump_type {
        return Err(ImageError::InvalidDump("DumpType does not match explicitly selected format"));
    }
    if read_u32(&header, ATTRIBUTES_OFFSET) & !ALLOWED_ATTRIBUTES != 0 {
        return Err(ImageError::InvalidDump(
            "incomplete, filtered, encrypted or unknown attributes",
        ));
    }
    if read_u64(&header, REQUIRED_SPACE_OFFSET) != metadata.len() {
        return Err(ImageError::InvalidDump("RequiredDumpSpace differs from file length"));
    }
    Ok((file, metadata.len(), header))
}

pub(super) fn metadata(header: &[u8; HEADER_BYTES], page_count: u64) -> DumpMetadata {
    DumpMetadata {
        dump_type: read_u32(header, DUMP_TYPE_OFFSET),
        directory_table_base: read_u64(header, 0x010),
        ps_active_process_head: read_u64(header, 0x028),
        ps_loaded_module_list: read_u64(header, 0x020),
        major_version: read_u32(header, 0x008),
        minor_version: read_u32(header, 0x00c),
        run_count: None,
        page_count,
        bitmap_pages: None,
    }
}

pub(super) fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

fn parse(
    header: &[u8; HEADER_BYTES],
    file_length: u64,
) -> Result<(Vec<PhysicalRun>, DumpMetadata), ImageError> {
    let count = read_u32(header, RUN_COUNT_OFFSET) as usize;
    if count == 0 || count > MAX_RUNS {
        return Err(ImageError::InvalidDump("run count must be 1..43"));
    }
    let mut runs: Vec<PhysicalRun> = Vec::with_capacity(count);
    let mut offset = HEADER_BYTES as u64;
    let mut total_pages = 0u64;
    for index in 0..count {
        let entry = RUN_OFFSET + index * RUN_BYTES;
        let base_page = read_u64(header, entry);
        let pages = read_u64(header, entry + 8);
        if pages == 0 {
            return Err(ImageError::InvalidDump("empty physical run"));
        }
        let start = base_page.checked_mul(PAGE_BYTES as u64).ok_or(ImageError::AddressOverflow)?;
        let length = pages.checked_mul(PAGE_BYTES as u64).ok_or(ImageError::AddressOverflow)?;
        let last = start.checked_add(length - 1).ok_or(ImageError::AddressOverflow)?;
        if runs.iter().any(|run| start <= run.start + (run.length - 1) && run.start <= last) {
            return Err(ImageError::InvalidDump("overlapping physical runs"));
        }
        runs.push(PhysicalRun { start, length, file_offset: offset });
        offset = offset.checked_add(length).ok_or(ImageError::AddressOverflow)?;
        total_pages = total_pages.checked_add(pages).ok_or(ImageError::AddressOverflow)?;
    }
    if total_pages != read_u64(header, PAGE_COUNT_OFFSET) {
        return Err(ImageError::InvalidDump("page count differs from physical runs"));
    }
    if offset != read_u64(header, REQUIRED_SPACE_OFFSET) || offset != file_length {
        return Err(ImageError::InvalidDump("payload length or RequiredDumpSpace mismatch"));
    }
    let mut dump_metadata = metadata(header, total_pages);
    dump_metadata.run_count = Some(count as u32);
    Ok((runs, dump_metadata))
}

fn read_u32(bytes: &[u8; HEADER_BYTES], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}
