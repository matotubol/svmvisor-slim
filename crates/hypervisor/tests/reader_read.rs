use svmvisor_hypervisor::reader::{
    paging::{PagingConfig, PagingError},
    read::{self, MAX_PAGE_WALKS, MAX_READ_BYTES, ReadError, ReadReport},
};

struct Image {
    bytes: Vec<u8>,
    calls: usize,
    failure_pa: Option<u64>,
}

impl Image {
    fn new() -> Self {
        let mut result = Self { bytes: vec![0; 22 * 4096], calls: 0, failure_pa: None };
        for (pa, entry) in [(0x1000, 0x2003u64), (0x2000, 0x3003), (0x3000, 0x4003)] {
            result.bytes[pa..pa + 8].copy_from_slice(&entry.to_le_bytes());
        }
        for index in 0..17 {
            let pa = (5 + index) * 4096;
            let entry = pa as u64 | 3;
            let offset = 0x4000 + index * 8;
            result.bytes[offset..offset + 8].copy_from_slice(&entry.to_le_bytes());
            result.bytes[pa..pa + 4096].fill(0xa0 + index as u8);
        }
        result
    }

    fn read(&mut self, pa: u64, bytes: &mut [u8]) -> Result<(), PagingError> {
        self.calls += 1;
        if self.failure_pa == Some(pa) {
            bytes.fill(0xee);
            return Err(PagingError::PhysicalRead);
        }
        let start = usize::try_from(pa).map_err(|_| PagingError::PhysicalRead)?;
        let end = start.checked_add(bytes.len()).ok_or(PagingError::PhysicalRead)?;
        let source = self.bytes.get(start..end).ok_or(PagingError::PhysicalRead)?;
        bytes.copy_from_slice(source);
        Ok(())
    }
}

fn config() -> PagingConfig {
    PagingConfig::new(48, true, true).unwrap()
}

#[test]
fn cross_page_read_preserves_order() {
    let mut image = Image::new();
    let mut output = [0xcd; 12];
    let report = read::read_virtual(config(), 0x1000, 4090, &mut output, &mut |pa, bytes| {
        image.read(pa, bytes)
    });
    assert_eq!(report, ReadReport { bytes_read: 12, error: None });
    assert_eq!(output, [0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1]);
    assert_eq!(image.calls, 10);
}

#[test]
fn data_callback_failure_discards_partial_scratch_and_preserves_tail() {
    let mut image = Image::new();
    image.failure_pa = Some(0x6000);
    let mut output = [0xcd; 12];
    let report = read::read_virtual(config(), 0x1000, 4090, &mut output, &mut |pa, bytes| {
        image.read(pa, bytes)
    });
    assert_eq!(report.bytes_read, 6);
    assert_eq!(report.error, Some(ReadError::Paging(PagingError::PhysicalRead)));
    assert_eq!(&output[..6], &[0xa0; 6]);
    assert_eq!(&output[6..], &[0xcd; 6]);
    assert_eq!(image.calls, 10);
}

#[test]
fn table_callback_failure_preserves_completed_prefix_and_tail() {
    let mut image = Image::new();
    image.failure_pa = Some(0x4008);
    let mut output = [0xcd; 12];
    let report = read::read_virtual(config(), 0x1000, 4090, &mut output, &mut |pa, bytes| {
        image.read(pa, bytes)
    });
    assert_eq!(report.bytes_read, 6);
    assert_eq!(report.error, Some(ReadError::Paging(PagingError::PhysicalRead)));
    assert_eq!(&output[..6], &[0xa0; 6]);
    assert_eq!(&output[6..], &[0xcd; 6]);
    assert_eq!(image.calls, 9);
}

#[test]
fn missing_mapping_preserves_completed_prefix_and_tail() {
    let mut image = Image::new();
    image.bytes[0x4008..0x4010].fill(0);
    let mut output = [0xcd; 12];
    let report = read::read_virtual(config(), 0x1000, 4090, &mut output, &mut |pa, bytes| {
        image.read(pa, bytes)
    });
    assert_eq!(report.bytes_read, 6);
    assert!(matches!(report.error, Some(ReadError::Paging(_))));
    assert_eq!(&output[..6], &[0xa0; 6]);
    assert_eq!(&output[6..], &[0xcd; 6]);
}

#[test]
fn invalid_ranges_never_read_or_mutate_output() {
    for (va, length, expected) in [
        (0, MAX_READ_BYTES + 1, ReadError::LengthLimit),
        (u64::MAX, 2, ReadError::AddressOverflow),
        (0x0000_8000_0000_0000, 1, ReadError::NoncanonicalRange),
        (0x0000_7fff_ffff_ffff, 2, ReadError::NoncanonicalRange),
        (0xffff_7fff_ffff_ffff, 2, ReadError::NoncanonicalRange),
    ] {
        let mut output = vec![0xcd; length];
        let report = read::read_virtual(config(), 0x1000, va, &mut output, &mut |_, _| {
            panic!("invalid range must not invoke the callback")
        });
        assert_eq!(report, ReadReport { bytes_read: 0, error: Some(expected) });
        assert!(output.iter().all(|byte| *byte == 0xcd));
    }
}

#[test]
fn empty_read_does_not_inspect_root_or_address() {
    let report = read::read_virtual(config(), 3, u64::MAX, &mut [], &mut |_, _| {
        panic!("empty read must not invoke the callback")
    });
    assert_eq!(report, ReadReport { bytes_read: 0, error: None });
}

#[test]
fn unaligned_maximum_read_stays_within_fixed_callback_budget() {
    let mut image = Image::new();
    let mut output = vec![0xcd; MAX_READ_BYTES];
    let report = read::read_virtual(config(), 0x1000, 1, &mut output, &mut |pa, bytes| {
        image.read(pa, bytes)
    });
    assert_eq!(report, ReadReport { bytes_read: MAX_READ_BYTES, error: None });
    assert_eq!(MAX_PAGE_WALKS, 17);
    assert_eq!(image.calls, MAX_PAGE_WALKS * 5);
    for (offset, byte) in output.iter().enumerate() {
        assert_eq!(*byte, 0xa0 + ((offset + 1) / 4096) as u8);
    }
}

#[test]
fn first_data_failure_never_changes_output() {
    let mut image = Image::new();
    image.failure_pa = Some(0x5000);
    let mut output = [0xcd; 13];
    let report = read::read_virtual(config(), 0x1000, 0, &mut output, &mut |pa, bytes| {
        image.read(pa, bytes)
    });
    assert_eq!(report.bytes_read, 0);
    assert_eq!(report.error, Some(ReadError::Paging(PagingError::PhysicalRead)));
    assert_eq!(output, [0xcd; 13]);
    assert_eq!(image.calls, 5);
}

#[test]
fn mapping_change_before_data_read_uses_sampled_address_without_retry() {
    let mut image = Image::new();
    let mut output = [0xcd; 8];
    let report = read::read_virtual(config(), 0x1000, 0, &mut output, &mut |pa, bytes| {
        if pa == 0x5000 {
            // The callback changes the mapping after translation selected the old backing page.
            image.bytes[0x4000..0x4008].copy_from_slice(&0x6003u64.to_le_bytes());
            image.bytes[0x5000..0x5008].fill(0xee);
        }
        image.read(pa, bytes)
    });
    assert_eq!(report, ReadReport { bytes_read: 8, error: None });
    assert_eq!(output, [0xee; 8]);
    assert_eq!(&image.bytes[0x6000..0x6008], &[0xa1; 8]);
    assert_eq!(image.calls, 5);
}

#[test]
fn mapping_removed_after_first_fragment_preserves_prefix_without_retry() {
    let mut image = Image::new();
    let mut output = [0xcd; 12];
    let report = read::read_virtual(config(), 0x1000, 4090, &mut output, &mut |pa, bytes| {
        image.read(pa, bytes)?;
        if pa == 0x5ffa {
            image.bytes[0x4008..0x4010].fill(0);
        }
        Ok(())
    });
    assert_eq!(
        report,
        ReadReport { bytes_read: 6, error: Some(ReadError::Paging(PagingError::NotPresent)) }
    );
    assert_eq!(&output[..6], &[0xa0; 6]);
    assert_eq!(&output[6..], &[0xcd; 6]);
    assert_eq!(image.calls, 9);
}
