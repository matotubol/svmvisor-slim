use super::*;

use std::{
    env, fs,
    path::PathBuf,
    process,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct ImageFixture {
    path: PathBuf,
}

impl ImageFixture {
    fn new(bytes: &[u8]) -> Self {
        let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!("svmvisor-image-{}-{sequence}.raw", process::id()));
        let mut file = File::options().write(true).create_new(true).open(&path).unwrap();
        io::Write::write_all(&mut file, bytes).unwrap();
        Self { path }
    }
}

impl Drop for ImageFixture {
    fn drop(&mut self) {
        fs::remove_file(&self.path).unwrap();
    }
}

#[test]
fn reads_nonzero_base_and_repeated_seeks_without_modifying_file() {
    let fixture = ImageFixture::new(&[10, 20, 30, 40]);
    let mut image = CaptureImage::open_raw(&fixture.path, 0x2000).unwrap();
    assert_eq!(image.max_physical_address(), 0x2003);
    let mut bytes = [0; 2];
    image.read(0x2002, &mut bytes).unwrap();
    assert_eq!(bytes, [30, 40]);
    image.read(0x2000, &mut bytes).unwrap();
    assert_eq!(bytes, [10, 20]);
    assert_eq!(fs::read(&fixture.path).unwrap(), [10, 20, 30, 40]);
}

#[test]
fn outside_and_overflowing_ranges_preserve_output() {
    let fixture = ImageFixture::new(&[1, 2, 3, 4]);
    let mut image = CaptureImage::open_raw(&fixture.path, 0x1000).unwrap();
    let mut bytes = [0xa5; 2];
    for pa in [0x0fff, 0x1003, 0x1004] {
        assert!(matches!(image.read(pa, &mut bytes), Err(ImageError::OutsideImage)));
        assert_eq!(bytes, [0xa5; 2]);
    }
    assert!(matches!(image.read(u64::MAX, &mut bytes), Err(ImageError::AddressOverflow)));
    assert_eq!(bytes, [0xa5; 2]);
    image.read(u64::MAX, &mut []).unwrap();
}

#[test]
fn final_physical_byte_is_addressable_but_larger_image_overflows() {
    let fixture = ImageFixture::new(&[1, 2]);
    assert!(matches!(
        CaptureImage::open_raw(&fixture.path, u64::MAX),
        Err(ImageError::AddressOverflow)
    ));
    let mut image = CaptureImage::open_raw(&fixture.path, u64::MAX - 1).unwrap();
    let mut bytes = [0];
    image.read(u64::MAX, &mut bytes).unwrap();
    assert_eq!(bytes, [2]);
}

#[test]
fn empty_image_is_rejected() {
    let fixture = ImageFixture::new(&[]);
    assert!(matches!(CaptureImage::open_raw(&fixture.path, 0), Err(ImageError::EmptyImage)));
}

#[test]
fn truncation_after_open_retains_io_error() {
    let fixture = ImageFixture::new(&[1, 2, 3, 4]);
    let mut image = CaptureImage::open_raw(&fixture.path, 0).unwrap();
    File::options().write(true).open(&fixture.path).unwrap().set_len(1).unwrap();
    let error = image.read(0, &mut [0; 4]).unwrap_err();
    assert!(
        matches!(&error, ImageError::Read(source) if source.kind() == io::ErrorKind::UnexpectedEof)
    );
    assert!(error.source().is_some());
}

#[test]
fn missing_file_retains_open_error() {
    let fixture = ImageFixture::new(&[1]);
    let path = fixture.path.clone();
    drop(fixture);
    let error = match CaptureImage::open_raw(&path, 0) {
        Ok(_) => panic!("removed fixture unexpectedly opened"),
        Err(error) => error,
    };
    assert!(matches!(&error, ImageError::Open(source) if source.kind() == io::ErrorKind::NotFound));
    assert!(error.source().is_some());
}

#[test]
fn file_growth_does_not_extend_declared_physical_range() {
    let fixture = ImageFixture::new(&[1]);
    let mut image = CaptureImage::open_raw(&fixture.path, 0).unwrap();
    File::options().write(true).open(&fixture.path).unwrap().set_len(2).unwrap();
    let mut bytes = [0xa5];
    assert!(matches!(image.read(1, &mut bytes), Err(ImageError::OutsideImage)));
    assert_eq!(bytes, [0xa5]);
    assert_eq!(image.max_physical_address(), 0);
}

#[test]
fn dump_reads_follow_descriptor_order_not_physical_order() {
    let low = [0x11; 0x1000];
    let high = [0x22; 0x1000];
    let fixture = ImageFixture::new(&full_dump_fixture(
        &[(0x3000, &high), (0x1000, &low)],
        0x1234,
        0xffff_8000_0000_0020,
    ));
    let mut image = CaptureImage::open_full_dump(&fixture.path).unwrap();
    assert_eq!(image.max_physical_address(), 0x3fff);
    let metadata = image.dump_metadata().unwrap();
    assert_eq!(metadata.directory_table_base, 0x1234);
    assert_eq!(metadata.ps_active_process_head, 0xffff_8000_0000_0020);
    assert_eq!(metadata.run_count, Some(2));
    let mut bytes = [0; 3];
    image.read(0x3001, &mut bytes).unwrap();
    assert_eq!(bytes, [0x22; 3]);
    image.read(0x1ffd, &mut bytes).unwrap();
    assert_eq!(bytes, [0x11; 3]);
    for address in [0, 0x1ffe, 0x2000, 0x4000] {
        assert!(matches!(image.read(address, &mut bytes), Err(ImageError::OutsideImage)));
        assert_eq!(bytes, [0x11; 3]);
    }
}

#[test]
fn dump_crosses_adjacent_runs_with_nonadjacent_file_offsets() {
    let first = [0x11; 0x1000];
    let second = [0x22; 0x1000];
    let third = [0x33; 0x1000];
    let fixture = ImageFixture::new(&full_dump_fixture(
        &[(0x2000, &second), (0x9000, &third), (0x1000, &first)],
        0,
        0,
    ));
    let mut image = CaptureImage::open_full_dump(&fixture.path).unwrap();
    let mut bytes = [0; 4];
    image.read(0x1ffe, &mut bytes).unwrap();
    assert_eq!(bytes, [0x11, 0x11, 0x22, 0x22]);
    image.read(u64::MAX, &mut []).unwrap();
}

#[test]
fn dump_rejects_wrong_signatures_architecture_types_and_attributes() {
    let original = full_dump_fixture(&[(0, &[0; 0x1000])], 0, 0);
    for (offset, value) in [
        (0, 0),
        (4, u32::from_le_bytes(*b"DUMP")),
        (0x030, 0x014c),
        (0xf98, 0),
        (0xf98, 2),
        (0xf98, 3),
        (0xf98, 4),
        (0xf98, 5),
        (0xf98, 6),
        (0xf98, 7),
        (0xf98, 8),
        (0xf98, 10),
        (0x1050, 1 << 2),
        (0x1050, 1 << 3),
        (0x1050, 1 << 6),
        (0x1050, 1 << 8),
        (0x1050, 1 << 31),
    ] {
        let mut bytes = original.clone();
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        let fixture = ImageFixture::new(&bytes);
        assert!(
            matches!(CaptureImage::open_full_dump(&fixture.path), Err(ImageError::InvalidDump(_))),
            "offset={offset:#x} value={value:#x}"
        );
    }
}

#[test]
fn dump_rejects_malformed_run_metadata_without_allocating_payload() {
    let original = full_dump_fixture(&[(0x1000, &[0; 0x1000]), (0x3000, &[0; 0x1000])], 0, 0);
    for (offset, value) in [
        (0x088, 0),
        (0x088, 44),
        (0x088, u32::MAX as u64),
        (0x090, 1),
        (0x098, u64::MAX),
        (0x0a0, 0),
        (0x0a0, u64::MAX),
        (0x0a8, 1),
        (0xfa0, 0),
        (0xfa0, u64::MAX),
    ] {
        let mut bytes = original.clone();
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        let fixture = ImageFixture::new(&bytes);
        assert!(CaptureImage::open_full_dump(&fixture.path).is_err(), "offset={offset:#x}");
    }
    let mut bytes = original.clone();
    bytes[0x098..0x0a0].copy_from_slice(&(u64::MAX / 0x1000).to_le_bytes());
    bytes[0x0a0..0x0a8].copy_from_slice(&2u64.to_le_bytes());
    let fixture = ImageFixture::new(&bytes);
    assert!(matches!(
        CaptureImage::open_full_dump(&fixture.path),
        Err(ImageError::AddressOverflow)
    ));
}

#[test]
fn dump_rejects_short_headers_truncated_payload_and_trailers() {
    let bytes = full_dump_fixture(&[(0, &[0; 0x1000])], 0, 0);
    for length in [0, 7, 0x1fff, 0x2000, bytes.len() - 1] {
        let fixture = ImageFixture::new(&bytes[..length]);
        assert!(CaptureImage::open_full_dump(&fixture.path).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    let fixture = ImageFixture::new(&extra);
    assert!(matches!(CaptureImage::open_full_dump(&fixture.path), Err(ImageError::InvalidDump(_))));
}

#[test]
fn dump_read_preserves_post_open_truncation_error() {
    let fixture = ImageFixture::new(&full_dump_fixture(&[(0x1000, &[1; 0x1000])], 0, 0));
    let mut image = CaptureImage::open_full_dump(&fixture.path).unwrap();
    File::options().write(true).open(&fixture.path).unwrap().set_len(0x2001).unwrap();
    let error = image.read(0x1000, &mut [0; 4]).unwrap_err();
    assert!(
        matches!(&error, ImageError::Read(source) if source.kind() == io::ErrorKind::UnexpectedEof)
    );
}

#[test]
fn dump_accepts_maximum_run_table_without_reading_context_as_runs() {
    let page = [0; 0x1000];
    let runs = (0..43).map(|index| (index * 0x2000, page.as_slice())).collect::<Vec<_>>();
    let fixture = ImageFixture::new(&full_dump_fixture(&runs, 0, 0));
    let image = CaptureImage::open_full_dump(&fixture.path).unwrap();
    assert_eq!(image.dump_metadata().unwrap().run_count, Some(43));
    assert_eq!(image.max_physical_address(), 42 * 0x2000 + 0xfff);
}
