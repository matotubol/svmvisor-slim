//! Synthetic memory images exercise only the public passive translator.

use svmvisor_hypervisor::reader::paging::{self, PagingConfig, PagingError, Translation};

struct Image {
    bytes: Vec<u8>,
    reads: Vec<u64>,
}

impl Image {
    fn new() -> Self {
        let mut image = Self { bytes: vec![0; 0x5000], reads: Vec::new() };
        image.entry(0x1000, 0x2001);
        image.entry(0x2000, 0x3001);
        image.entry(0x3000, 0x4001);
        image.entry(0x4000, 0x8001);
        image
    }

    fn entry(&mut self, pa: usize, entry: u64) {
        self.bytes[pa..pa + 8].copy_from_slice(&entry.to_le_bytes());
    }

    fn translate(&mut self, va: u64) -> Result<Translation, PagingError> {
        let config = PagingConfig::new(48, true, true).unwrap();
        self.with_config(config, 0x1000, va)
    }

    fn with_config(
        &mut self,
        config: PagingConfig,
        root_pa: u64,
        va: u64,
    ) -> Result<Translation, PagingError> {
        paging::translate(config, root_pa, va, &mut |pa, bytes| {
            self.reads.push(pa);
            let start = usize::try_from(pa).map_err(|_| PagingError::PhysicalRead)?;
            let end = start.checked_add(bytes.len()).ok_or(PagingError::PhysicalRead)?;
            let source = self.bytes.get(start..end).ok_or(PagingError::PhysicalRead)?;
            bytes.copy_from_slice(source);
            Ok(())
        })
    }
}

#[test]
fn four_kbyte_leaf_uses_four_little_endian_reads() {
    let mut image = Image::new();
    let translation = image.translate(0x123).unwrap();
    assert_eq!(translation.pa(), 0x8123);
    assert_eq!(translation.page_bytes(), 0x1000);
    assert_eq!(translation.contiguous_bytes(), 0xedd);
    assert_eq!(image.reads, [0x1000, 0x2000, 0x3000, 0x4000]);
}

#[test]
fn large_leaves_include_offsets_and_exclude_pat() {
    for (entry_pa, entry, va, expected, page_bytes, reads) in [
        (0x3000, 0x20_1081, 0x1f_ffff, 0x3f_ffff, 0x20_0000, 3),
        (0x2000, 0x4000_1081, 0x3fff_ffff, 0x7fff_ffff, 0x4000_0000, 2),
    ] {
        let mut image = Image::new();
        image.entry(entry_pa, entry);
        let translation = image.translate(va).unwrap();
        assert_eq!(translation.pa(), expected);
        assert_eq!(translation.page_bytes(), page_bytes);
        assert_eq!(translation.contiguous_bytes(), 1);
        assert_eq!(image.reads.len(), reads);
    }
}

#[test]
fn canonical_upper_address_selects_last_slot_at_every_level() {
    let mut image = Image::new();
    image.entry(0x1ff8, 0x2001);
    image.entry(0x2ff8, 0x3001);
    image.entry(0x3ff8, 0x4001);
    image.entry(0x4ff8, 0x9001);
    let translation = image.translate(u64::MAX).unwrap();
    assert_eq!(translation.pa(), 0x9fff);
    assert_eq!(translation.contiguous_bytes(), 1);
    assert_eq!(image.reads, [0x1ff8, 0x2ff8, 0x3ff8, 0x4ff8]);
}

#[test]
fn malformed_input_is_rejected_before_reading() {
    assert_eq!(PagingConfig::new(31, true, true), Err(PagingError::UnsupportedPhysicalWidth));
    assert_eq!(PagingConfig::new(53, true, true), Err(PagingError::UnsupportedPhysicalWidth));
    let config = PagingConfig::new(32, true, true).unwrap();
    for (root_pa, va, error) in [
        (0x1000, 0x0000_8000_0000_0000, PagingError::NoncanonicalAddress),
        (0x1000, 0xffff_7fff_ffff_ffff, PagingError::NoncanonicalAddress),
        (0x1001, 0, PagingError::MisalignedRoot),
        (1 << 32, 0, PagingError::RootOutsidePhysicalWidth),
    ] {
        let mut image = Image::new();
        assert_eq!(image.with_config(config, root_pa, va), Err(error));
        assert!(image.reads.is_empty());
    }
}

#[test]
fn absent_entries_ignore_every_other_bit_and_stop_immediately() {
    for (index, pa) in [0x1000, 0x2000, 0x3000, 0x4000].into_iter().enumerate() {
        let mut image = Image::new();
        image.entry(pa, u64::MAX - 1);
        assert_eq!(image.translate(0), Err(PagingError::NotPresent));
        assert_eq!(image.reads.len(), index + 1);
    }
}

#[test]
fn high_software_and_protection_key_bits_do_not_extend_addresses() {
    let mut image = Image::new();
    for (pa, entry) in [(0x1000, 0x2001), (0x2000, 0x3101), (0x3000, 0x4101), (0x4000, 0x8181)] {
        image.entry(pa, entry | 0x7ff0_0000_0000_0000);
    }
    assert_eq!(image.translate(0).unwrap().pa(), 0x8000);
}

#[test]
fn pml4_reserved_bits_and_large_leaf_alignment_are_rejected() {
    for (pa, entry) in [
        (0x1000, 0x2081),
        (0x1000, 0x2101),
        (0x2000, 0x4000_2081),
        (0x2000, 0x6000_0081),
        (0x3000, 0x20_2081),
        (0x3000, 0x30_0081),
    ] {
        let mut image = Image::new();
        image.entry(pa, entry);
        assert_eq!(image.translate(0), Err(PagingError::ReservedBitsSet));
    }
}

#[test]
fn unimplemented_physical_address_bits_are_rejected_at_every_level() {
    for (pa, entry) in [(0x1000, 0x2001), (0x2000, 0x3001), (0x3000, 0x4001), (0x4000, 0x8001)] {
        let mut image = Image::new();
        image.entry(pa, entry | (1 << 48));
        assert_eq!(image.translate(0), Err(PagingError::ReservedBitsSet));
    }
}

#[test]
fn nx_requires_nxe_but_does_not_prevent_numerical_translation() {
    for (pa, entry) in [(0x1000, 0x2001), (0x2000, 0x3001), (0x3000, 0x4001), (0x4000, 0x8001)] {
        let mut image = Image::new();
        image.entry(pa, entry | (1 << 63));
        let config = PagingConfig::new(48, false, true).unwrap();
        assert_eq!(image.with_config(config, 0x1000, 0), Err(PagingError::ReservedBitsSet));
        assert_eq!(image.translate(0).unwrap().pa(), 0x8000);
    }
}

#[test]
fn one_gbyte_support_is_explicit() {
    let mut image = Image::new();
    image.entry(0x2000, 0x4000_0081);
    let config = PagingConfig::new(48, true, false).unwrap();
    assert_eq!(image.with_config(config, 0x1000, 0), Err(PagingError::UnsupportedPageSize));
    assert_eq!(image.reads.len(), 2);
}

#[test]
fn missing_image_bytes_and_callback_errors_stop_the_walk() {
    let mut image = Image::new();
    image.entry(0x2000, 0x9001);
    assert_eq!(image.translate(0), Err(PagingError::PhysicalRead));
    assert_eq!(image.reads, [0x1000, 0x2000, 0x9000]);
    let mut count = 0;
    let config = PagingConfig::new(48, true, true).unwrap();
    let result = paging::translate(config, 0x1000, 0, &mut |_, bytes| {
        count += 1;
        bytes.fill(0xff);
        Err(PagingError::PhysicalRead)
    });
    assert_eq!(result, Err(PagingError::PhysicalRead));
    assert_eq!(count, 1);
}

#[test]
fn self_referencing_tables_still_read_at_most_four_entries() {
    let mut image = Image::new();
    image.entry(0x1000, 0x1001);
    assert_eq!(image.translate(0x123).unwrap().pa(), 0x1123);
    assert_eq!(image.reads, [0x1000; 4]);
}

#[test]
fn maximum_width_accepts_highest_table_slot_without_overflow() {
    let config = PagingConfig::new(52, true, true).unwrap();
    let root_pa = 0x000f_ffff_ffff_f000;
    let mut count = 0;
    let result = paging::translate(config, root_pa, u64::MAX, &mut |pa, bytes| {
        count += 1;
        assert_eq!(pa, 0x000f_ffff_ffff_fff8);
        bytes.copy_from_slice(&(root_pa | 1).to_le_bytes());
        Ok(())
    })
    .unwrap();
    assert_eq!(result.pa(), 0x000f_ffff_ffff_ffff);
    assert_eq!(count, 4);
}
