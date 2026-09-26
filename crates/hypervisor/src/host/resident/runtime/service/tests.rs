use super::*;

extern crate std;

use std::vec::Vec;

use crate::{
    host::resident::runtime::guest_reader::nested_fragment,
    memory::npt::{TABLE_COUNT, TableStorage},
};

#[derive(Debug, PartialEq, Eq)]
enum OutputCall {
    Translate(u64),
    Admit(u64, usize),
    Write(u64, Vec<u8>),
}

struct OutputFixture {
    translations: [Result<u64, ()>; 6],
    translated: usize,
    refused: Option<u64>,
    write_failure: Option<u64>,
    calls: Vec<OutputCall>,
    copied: Vec<u8>,
}

impl OutputFixture {
    fn new() -> Self {
        Self {
            translations: [Ok(0x8fff), Ok(0xa000), Ok(0xc000), Ok(0x8fff), Ok(0xa000), Ok(0xc000)],
            translated: 0,
            refused: None,
            write_failure: None,
            calls: Vec::new(),
            copied: Vec::new(),
        }
    }

    fn write(&mut self, va: u64, source: &[u8]) -> Result<(), ()> {
        write_output(
            self,
            va,
            source,
            |memory, address| {
                memory.calls.push(OutputCall::Translate(address));
                let result = memory.translations[memory.translated];
                memory.translated += 1;
                result
            },
            |memory, physical, length| {
                memory.calls.push(OutputCall::Admit(physical, length));
                memory.refused != Some(physical)
            },
            |memory, physical, bytes| {
                memory.calls.push(OutputCall::Write(physical, bytes.to_vec()));
                if memory.write_failure == Some(physical) {
                    return Err(());
                }
                memory.copied.extend_from_slice(bytes);
                Ok(())
            },
        )
    }
}

fn fixture() -> (PagingConfig, TableStorage) {
    let mut tables = TableStorage([[0; PAGE_BYTES]; TABLE_COUNT]);
    tables.0[0][..8].copy_from_slice(&0x20_1007u64.to_le_bytes());
    tables.0[1][..8].copy_from_slice(&0x87u64.to_le_bytes());
    let config = PagingConfig {
        cr3: 0x20_0000,
        physical_bits: 48,
        la57: false,
        nxe: true,
        pcid: false,
        page1gb: true,
    };
    (config, tables)
}

#[test]
fn caller_walk_requires_user_write_and_wb_at_every_level() {
    let config = PagingConfig {
        cr3: 0x1000,
        physical_bits: 48,
        la57: false,
        nxe: true,
        pcid: false,
        page1gb: true,
    };
    let entries = [0x2007, 0x3007, 0x4007, 0x8007];
    let walk = |entries: [u64; 4], writable| {
        user_translation(config, 6, 0x123, writable, &mut |pa| {
            entries.get((pa / 4096 - 1) as usize).copied()
        })
    };
    assert_eq!(walk(entries, true), Ok(0x8123));
    for level in 0..4 {
        let mut changed = entries;
        changed[level] &= !4;
        assert!(walk(changed, false).is_err());
        changed = entries;
        changed[level] &= !2;
        assert!(walk(changed, true).is_err());
        assert_eq!(walk(changed, false), Ok(0x8123));
        changed = entries;
        changed[level] |= 1 << 3;
        assert!(walk(changed, true).is_err());
        changed = entries;
        changed[level] |= 0x7ff0_0000_0000_0000;
        assert_eq!(walk(changed, true), Ok(0x8123));
    }
}

#[test]
fn caller_ranges_refuse_kernel_overflow_and_oversized_buffers_before_walk() {
    for (address, length) in [
        (0, 1),
        (0x1000, 0),
        (0x1000, MAX_RESPONSE_BYTES + 1),
        ((1 << 47) - 1, 2),
        (0xffff_8000_0000_0000, 1),
        (u64::MAX, 2),
    ] {
        assert!(!user_range(address, length));
    }
    assert!(user_range(0x1fff, MAX_RESPONSE_BYTES));
    assert!(user_range((1 << 47) - 1, 1));
}

#[test]
fn nested_admission_refuses_nonidentity_and_unowned_table_links() {
    let (config, mut tables) = fixture();
    assert!(nested_fragment(config, &tables.0, 0x30_0000, 32, false));
    tables.0[1][..8].copy_from_slice(&0x4000_0087u64.to_le_bytes());
    assert!(!nested_fragment(config, &tables.0, 0x30_0000, 32, false));
    tables.0[0][..8].copy_from_slice(&0x9000_0007u64.to_le_bytes());
    assert!(!nested_fragment(config, &tables.0, 0x30_0000, 32, false));
}

#[test]
fn nested_admission_walks_owned_runtime_splits_beyond_the_bootstrap_prefix() {
    let (config, _) = fixture();
    let mut tables = std::vec![[0u8; PAGE_BYTES]; crate::memory::npt::CACHE_TABLE_COUNT];
    tables[0][..8].copy_from_slice(&(config.cr3 + 9 * 4096 | 7).to_le_bytes());
    tables[9][..8].copy_from_slice(&(config.cr3 + 12 * 4096 | 7).to_le_bytes());
    tables[12][8..16].copy_from_slice(&0x20_0087u64.to_le_bytes());
    assert!(nested_fragment(config, &tables, 0x30_0000, 32, false));
    assert!(nested_fragment(config, &tables, 0x30_0000, 32, true));
    tables[12][8] &= !2;
    assert!(nested_fragment(config, &tables, 0x30_0000, 32, false));
    assert!(!nested_fragment(config, &tables, 0x30_0000, 32, true));
}

#[test]
fn nested_admission_refuses_absent_and_non_wb_leaf() {
    let (config, mut tables) = fixture();
    tables.0[1][..8].copy_from_slice(&0u64.to_le_bytes());
    assert!(!nested_fragment(config, &tables.0, 0x30_0000, 32, false));
    tables.0[1][..8].copy_from_slice(&0x8fu64.to_le_bytes());
    assert!(!nested_fragment(config, &tables.0, 0x30_0000, 32, false));
}

#[test]
fn output_admission_requires_writable_nested_parents_and_leaf() {
    for level in [0, 1] {
        let (config, mut tables) = fixture();
        assert!(nested_fragment(config, &tables.0, 0x30_0000, 32, true));
        tables.0[level][0] &= !2;
        assert!(nested_fragment(config, &tables.0, 0x30_0000, 32, false));
        assert!(!nested_fragment(config, &tables.0, 0x30_0000, 32, true));
    }
}

#[test]
fn output_invalid_ranges_stop_before_any_callback() {
    let source = [0u8; MAX_RESPONSE_BYTES + 1];
    for (address, length) in [
        (0, 1),
        (0x1000, 0),
        (0x1000, MAX_RESPONSE_BYTES + 1),
        ((1 << 47) - 1, 2),
        (0xffff_8000_0000_0000, 1),
        (u64::MAX, 2),
    ] {
        let mut memory = OutputFixture::new();
        assert_eq!(memory.write(address, &source[..length]), Err(()));
        assert!(memory.calls.is_empty());
    }
}

#[test]
fn output_preflight_translation_or_admission_failure_never_writes() {
    let source = [0x5a; MAX_RESPONSE_BYTES];
    for page in 0..3 {
        for refuse_translation in [false, true] {
            let mut memory = OutputFixture::new();
            if refuse_translation {
                memory.translations[page] = Err(());
            } else {
                memory.refused = memory.translations[page].ok();
            }
            assert_eq!(memory.write(0x1fff, &source), Err(()));
            assert_eq!(memory.translated, page + 1);
            assert!(memory.copied.is_empty());
            assert!(memory.calls.iter().all(|call| !matches!(call, OutputCall::Write(..))));
        }
    }
}

#[test]
fn output_late_unmap_or_remap_stops_at_the_written_prefix() {
    let source = [0x5a; MAX_RESPONSE_BYTES];
    for page in 0..3 {
        for changed in [Err(()), Ok(0xe000)] {
            let mut memory = OutputFixture::new();
            memory.translations[3 + page] = changed;
            assert_eq!(memory.write(0x1fff, &source), Err(()));
            assert_eq!(memory.translated, 4 + page);
            let prefix = [0, 1, 1 + PAGE_BYTES][page];
            assert_eq!(memory.copied, source[..prefix]);
            assert_eq!(
                memory.calls.iter().filter(|call| matches!(call, OutputCall::Write(..))).count(),
                page
            );
            assert_eq!(
                memory.calls.last(),
                Some(&OutputCall::Translate([0x1fff, 0x2000, 0x3000][page]))
            );
        }
    }
}

#[test]
fn output_aliases_are_rejected_before_writes_even_with_different_page_offsets() {
    let source = [0x5a; MAX_RESPONSE_BYTES];
    for (page, physical) in [(1, 0x8000), (2, 0x8000), (2, 0xa000)] {
        let mut memory = OutputFixture::new();
        memory.translations[page] = Ok(physical);
        assert_eq!(memory.write(0x1fff, &source), Err(()));
        assert_eq!(memory.translated, page + 1);
        assert!(memory.copied.is_empty());
        assert!(memory.calls.iter().all(|call| !matches!(call, OutputCall::Write(..))));
    }
}

#[test]
fn output_maximum_unaligned_response_preflights_three_pages_then_rewalks_each_write() {
    let source = core::array::from_fn::<_, MAX_RESPONSE_BYTES, _>(|index| index as u8);
    let mut memory = OutputFixture::new();
    assert_eq!(memory.write(0x1fff, &source), Ok(()));
    assert_eq!(memory.copied, source);
    assert_eq!(
        memory.calls,
        [
            OutputCall::Translate(0x1fff),
            OutputCall::Admit(0x8fff, 1),
            OutputCall::Translate(0x2000),
            OutputCall::Admit(0xa000, PAGE_BYTES),
            OutputCall::Translate(0x3000),
            OutputCall::Admit(0xc000, MAX_RESPONSE_BYTES - PAGE_BYTES - 1),
            OutputCall::Translate(0x1fff),
            OutputCall::Write(0x8fff, source[..1].to_vec()),
            OutputCall::Translate(0x2000),
            OutputCall::Write(0xa000, source[1..1 + PAGE_BYTES].to_vec()),
            OutputCall::Translate(0x3000),
            OutputCall::Write(0xc000, source[1 + PAGE_BYTES..].to_vec()),
        ]
    );
}

#[test]
fn output_write_callback_failure_propagates_without_visiting_later_pages() {
    let source = [0x5a; MAX_RESPONSE_BYTES];
    for page in 0..3 {
        let mut memory = OutputFixture::new();
        let physical = [0x8fff, 0xa000, 0xc000][page];
        memory.write_failure = Some(physical);
        assert_eq!(memory.write(0x1fff, &source), Err(()));
        assert_eq!(memory.translated, 4 + page);
        let prefix = [0, 1, 1 + PAGE_BYTES][page];
        assert_eq!(memory.copied, source[..prefix]);
        assert_eq!(
            memory.calls.iter().filter(|call| matches!(call, OutputCall::Write(..))).count(),
            page + 1
        );
        assert!(
            matches!(memory.calls.last(), Some(OutputCall::Write(address, _)) if *address == physical)
        );
    }
}
