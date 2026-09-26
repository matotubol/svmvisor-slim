use super::*;

use std::{
    env,
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
    process,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct BitmapFixture {
    path: PathBuf,
}

impl BitmapFixture {
    fn new(bytes: &[u8]) -> Self {
        let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path =
            env::temp_dir().join(format!("svmvisor-bitmap-{}-{sequence}.dmp", process::id()));
        let mut file = File::options().write(true).create_new(true).open(&path).unwrap();
        file.write_all(bytes).unwrap();
        Self { path }
    }
}

impl Drop for BitmapFixture {
    fn drop(&mut self) {
        fs::remove_file(&self.path).unwrap();
    }
}

#[test]
fn bitmap_bit_order_rank_boundaries_and_missing_pages() {
    let first = [0x11; PAGE_BYTES];
    let second = [0x22; PAGE_BYTES];
    let third = [0x33; PAGE_BYTES];
    let fourth = [0x44; PAGE_BYTES];
    let fifth = [0x55; PAGE_BYTES];
    let sixth = [0x66; PAGE_BYTES];
    let pfns = [0, 7, 8, 4095, 4096, 4098];
    let payloads = [&first[..], &second[..], &third[..], &fourth[..], &fifth[..], &sixth[..]];
    let pages = pfns.iter().zip(payloads).map(|(pfn, data)| (pfn * 4096, data)).collect::<Vec<_>>();
    let fixture = BitmapFixture::new(&bitmap_dump_fixture(&pages, 4101, 0x1234, 0x5678));
    let mut image = CaptureImage::open_bitmap_kernel_dump(&fixture.path).unwrap();
    let metadata = image.dump_metadata().unwrap();
    assert_eq!(metadata.dump_type, 6);
    assert_eq!(metadata.run_count, None);
    assert_eq!(metadata.bitmap_pages, Some(4101));
    assert_eq!(metadata.page_count, 6);
    assert_eq!(metadata.directory_table_base, 0x1234);
    assert_eq!(metadata.ps_active_process_head, 0x5678);
    assert_eq!(image.max_physical_address(), 4101 * 4096 - 1);
    for (index, pfn) in pfns.iter().enumerate() {
        let mut output = [0; 3];
        image.read(pfn * 4096 + 23, &mut output).unwrap();
        assert_eq!(output, [((index + 1) * 0x11) as u8; 3]);
    }
    for pfn in [1, 6, 4094, 4097, 4100, 4101] {
        let mut output = [0xa5; 2];
        assert!(matches!(image.read(pfn * 4096, &mut output), Err(ImageError::OutsideImage)));
        assert_eq!(output, [0xa5; 2]);
    }
    let mut output = [0; 4];
    image.read(8 * 4096 - 2, &mut output).unwrap();
    assert_eq!(output, [0x22, 0x22, 0x33, 0x33]);
    image.read(4096 * 4096 - 2, &mut output).unwrap();
    assert_eq!(output, [0x44, 0x44, 0x55, 0x55]);
    output.fill(0xa5);
    assert!(matches!(image.read(4097 * 4096 - 2, &mut output), Err(ImageError::OutsideImage)));
    assert_eq!(output, [0xa5; 4]);
    image.read(u64::MAX, &mut []).unwrap();
    assert!(matches!(image.read(u64::MAX, &mut output), Err(ImageError::AddressOverflow)));
}

#[test]
fn bitmap_rejects_wrong_format_metadata_counts_and_tail_bits() {
    let original = bitmap_dump_fixture(&[(0, &[1; PAGE_BYTES])], 9, 0, 0);
    for (offset, value) in [
        (0xf98, 1),
        (0xf98, 5),
        (0xf98, 8),
        (0x2000, 0),
        (0x2000, u64::from_le_bytes(*b"FDMPDUMP")),
        (0x2020, 0x2000),
        (0x2020, 0x3001),
        (0x2020, u64::MAX),
        (0x2028, 0),
        (0x2028, 2),
        (0x2028, 10),
        (0x2028, u64::MAX),
        (0x2030, 0),
        (0x2030, u64::MAX),
        (0x2030, MAX_BITMAP_BYTES * 8 + 1),
    ] {
        let mut bytes = original.clone();
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        let fixture = BitmapFixture::new(&bytes);
        assert!(
            CaptureImage::open_bitmap_kernel_dump(&fixture.path).is_err(),
            "offset={offset:#x}"
        );
    }
    for (index, value) in [(0x2038, 0), (0x2038, 3), (0x2039, 0x80)] {
        let mut bytes = original.clone();
        bytes[index] = value;
        let fixture = BitmapFixture::new(&bytes);
        assert!(CaptureImage::open_bitmap_kernel_dump(&fixture.path).is_err());
    }
}

#[test]
fn bitmap_refuses_truncation_and_trailing_data_and_reports_late_io_failure() {
    let bytes = bitmap_dump_fixture(&[(0, &[1; PAGE_BYTES])], 8, 0, 0);
    for length in [0x2000, 0x2037, 0x2038, 0x3000, bytes.len() - 1] {
        let mut shorter = bytes[..length].to_vec();
        shorter[0xfa0..0xfa8].copy_from_slice(&(length as u64).to_le_bytes());
        let fixture = BitmapFixture::new(&shorter);
        assert!(CaptureImage::open_bitmap_kernel_dump(&fixture.path).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    let length = extra.len() as u64;
    extra[0xfa0..0xfa8].copy_from_slice(&length.to_le_bytes());
    let fixture = BitmapFixture::new(&extra);
    assert!(CaptureImage::open_bitmap_kernel_dump(&fixture.path).is_err());

    let fixture = BitmapFixture::new(&bytes);
    let mut image = CaptureImage::open_bitmap_kernel_dump(&fixture.path).unwrap();
    File::options().write(true).open(&fixture.path).unwrap().set_len(0x3001).unwrap();
    assert!(matches!(image.read(0, &mut [0; 4]), Err(ImageError::Read(error))
        if error.kind() == io::ErrorKind::UnexpectedEof));
}
