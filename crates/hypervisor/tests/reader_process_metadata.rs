//! Exact adjacent-field reads use synthetic layouts and supplied byte arrays only.

use svmvisor_hypervisor::reader::{
    paging::{PagingConfig, PagingError},
    process::{
        self, ProcessError, ProcessLayoutEvidence, ProcessNode, ProcessObservation, ProcessProfile,
        ProcessRequest,
    },
    read::ReadError,
};

const HEAD: u64 = 0x6000;
const FIRST: u64 = 0x8000;
const SECOND: u64 = 0xa000;

struct Image {
    bytes: Vec<u8>,
    layout: ProcessLayoutEvidence,
    first: u64,
    calls: Vec<(u64, usize)>,
    fail_call: Option<usize>,
}

impl Image {
    fn new(layout: ProcessLayoutEvidence, first: u64) -> Self {
        let mut image =
            Self { bytes: vec![0; 0x10000], layout, first, calls: Vec::new(), fail_call: None };
        for (pa, word) in [
            (0x1000, 0x2001),
            (0x2000, 0x3001),
            (0x3000, 0x4001),
            (0x4030, 0x6001),
            (0x4040, 0xa001),
            (0x4048, 0xc001),
            (0x4050, 0xb001),
        ] {
            image.word(pa, word);
        }
        let links = u64::from(layout.active_links_offset);
        image.links(HEAD, first + links, SECOND + links);
        image.links(first + links, SECOND + links, HEAD);
        image.links(SECOND + links, HEAD, first + links);
        for (va, pid, root, time) in [(first, 42, 0xd000, 100), (SECOND, 84, 0xe000, 200)] {
            image.virtual_word(va + u64::from(layout.pid_offset), pid);
            image.virtual_word(va + u64::from(layout.directory_root_offset), root);
            image.virtual_word(va + u64::from(layout.create_time_offset.unwrap()), time);
        }
        image
    }

    fn word(&mut self, pa: usize, word: u64) {
        self.bytes[pa..pa + 8].copy_from_slice(&word.to_le_bytes());
    }

    fn virtual_word(&mut self, va: u64, word: u64) {
        let pa = match va & !0xfff {
            0x6000 => va,
            0x8000 => 0xa000 + (va & 0xfff),
            0x9000 => 0xc000 + (va & 0xfff),
            0xa000 => 0xb000 + (va & 0xfff),
            _ => panic!("unexpected fixture VA"),
        };
        self.word(pa as usize, word);
    }

    fn links(&mut self, va: u64, forward: u64, backward: u64) {
        self.virtual_word(va, forward);
        self.virtual_word(va + 8, backward);
    }

    fn find(
        &mut self,
        pid: u64,
        max_nodes: usize,
    ) -> Result<Option<ProcessObservation>, ProcessError> {
        process::find(
            config(),
            ProcessProfile::new(self.layout).unwrap(),
            request(pid, max_nodes),
            &mut |pa, bytes| self.read(pa, bytes),
        )
    }

    fn list(&mut self, nodes: &mut [ProcessNode]) -> Result<usize, ProcessError> {
        process::list(
            config(),
            ProcessProfile::new(self.layout).unwrap(),
            0x1000,
            HEAD,
            nodes,
            &mut |pa, bytes| self.read(pa, bytes),
        )
    }

    fn read(&mut self, pa: u64, bytes: &mut [u8]) -> Result<(), PagingError> {
        self.calls.push((pa, bytes.len()));
        if self.fail_call == Some(self.calls.len()) {
            bytes.fill(0xff);
            return Err(PagingError::PhysicalRead);
        }
        let start = usize::try_from(pa).map_err(|_| PagingError::PhysicalRead)?;
        let end = start.checked_add(bytes.len()).ok_or(PagingError::PhysicalRead)?;
        bytes.copy_from_slice(self.bytes.get(start..end).ok_or(PagingError::PhysicalRead)?);
        Ok(())
    }

    fn data_calls(&self) -> Vec<(u64, usize)> {
        self.calls.iter().copied().filter(|&(pa, _)| pa >= HEAD).collect()
    }

    fn expected(&self) -> ProcessObservation {
        ProcessObservation {
            pid: 42,
            eprocess_va: self.first,
            create_time: Some(100),
            kernel_root_pa: 0xd000,
        }
    }
}

fn config() -> PagingConfig {
    PagingConfig::new(48, true, true).unwrap()
}

fn layout(pid_offset: u32) -> ProcessLayoutEvidence {
    ProcessLayoutEvidence {
        eprocess_bytes: 0x100,
        active_links_offset: 0x020,
        pid_offset,
        create_time_offset: Some(0x060),
        directory_root_offset: 0x050,
        dtb_low_bits_mask: 0,
    }
}

fn request(pid: u64, max_nodes: usize) -> ProcessRequest {
    ProcessRequest { kernel_root_pa: 0x1000, list_head_va: HEAD, pid, max_nodes }
}

#[test]
fn both_adjacent_orders_halve_same_page_node_callbacks_for_find_and_list() {
    for (pid_offset, first_pa, second_pa) in [(0x018, 0xa018, 0xb018), (0x030, 0xa020, 0xb020)] {
        let mut image = Image::new(layout(pid_offset), FIRST);
        assert_eq!(image.find(99, 2), Ok(None));
        assert_eq!(image.calls.len(), 5 + 2 * 5);
        assert_eq!(image.data_calls(), [(HEAD, 16), (first_pa, 24), (second_pa, 24)]);
        image.calls.clear();
        let mut nodes = [ProcessNode::default(); 2];
        assert_eq!(image.list(&mut nodes), Ok(2));
        assert_eq!(image.calls.len(), 5 + 2 * 5);
        assert_eq!(
            nodes,
            [
                ProcessNode { eprocess_va: FIRST, pid: 42 },
                ProcessNode { eprocess_va: SECOND, pid: 84 }
            ]
        );
        image.calls.clear();
        assert_eq!(image.find(42, 2), Ok(Some(image.expected())));
        assert_eq!(image.calls.len(), 5 + 2 * 5 + 2 * 5);
    }
    let mut separate = Image::new(layout(0x040), FIRST);
    assert_eq!(separate.find(99, 2), Ok(None));
    assert_eq!(separate.calls.len(), 5 + 2 * 10);
}

#[test]
fn even_a_one_word_gap_preserves_separate_reads_and_does_not_read_padding() {
    for pid_offset in [0x010, 0x038, 0x040, 0x0f8] {
        let mut image = Image::new(layout(pid_offset), FIRST);
        assert_eq!(image.find(99, 2), Ok(None));
        assert_eq!(image.calls.len(), 25);
        assert_eq!(
            image.data_calls(),
            [
                (HEAD, 16),
                (0xa020, 16),
                (0xa000 + u64::from(pid_offset), 8),
                (0xb020, 16),
                (0xb000 + u64::from(pid_offset), 8),
            ]
        );
        image.calls.clear();
        image.links(FIRST + 0x020, FIRST + 0x020, HEAD);
        assert_eq!(image.find(42, 2), Err(ProcessError::CorruptLinks));
        assert_eq!(image.data_calls(), [(HEAD, 16), (0xa020, 16)]);
    }
}

#[test]
fn adjacent_ranges_translate_noncontiguous_pages_and_stop_at_exact_boundaries() {
    for (pid_offset, first, fragments) in [
        (0x018, 0x8fd8, vec![(0xaff0, 16), (0xc000, 8)]),
        (0x018, 0x8fe0, vec![(0xaff8, 8), (0xc000, 16)]),
        (0x030, 0x8fd8, vec![(0xaff8, 8), (0xc000, 16)]),
        (0x030, 0x8fd0, vec![(0xaff0, 16), (0xc000, 8)]),
        (0x018, 0x8fd0, vec![(0xafe8, 24)]),
        (0x030, 0x8fc8, vec![(0xafe8, 24)]),
    ] {
        let mut image = Image::new(layout(pid_offset), first);
        assert_eq!(image.find(99, 2), Ok(None));
        assert_eq!(image.calls.len(), 5 + 5 * fragments.len() + 5);
        let mut expected = vec![(HEAD, 16)];
        expected.extend(fragments);
        expected.push((if pid_offset == 0x018 { 0xb018 } else { 0xb020 }, 24));
        assert_eq!(image.data_calls(), expected);
        image.calls.clear();
        assert_eq!(image.find(42, 2), Ok(Some(image.expected())));
    }
}

#[test]
fn adjacent_fields_retain_link_pointer_backlink_self_loop_and_head_checks() {
    for pid_offset in [0x018, 0x030] {
        for (va, value, expected) in [
            (FIRST + 0x020, 0, ProcessError::InvalidPointer),
            (FIRST + 0x028, 3, ProcessError::InvalidPointer),
            (FIRST + 0x020, FIRST + 0x020, ProcessError::CorruptLinks),
            (FIRST + 0x028, SECOND + 0x020, ProcessError::CorruptLinks),
            (SECOND + 0x028, HEAD, ProcessError::CorruptLinks),
            (HEAD + 8, FIRST + 0x020, ProcessError::CorruptLinks),
        ] {
            let mut image = Image::new(layout(pid_offset), FIRST);
            image.virtual_word(va, value);
            assert_eq!(image.find(42, 2), Err(expected));
        }
        let mut image = Image::new(layout(pid_offset), FIRST);
        image.virtual_word(SECOND + u64::from(pid_offset), 42);
        assert_eq!(image.find(42, 2), Err(ProcessError::DuplicatePid));
        let mut image = Image::new(layout(pid_offset), FIRST);
        assert_eq!(image.find(42, 1), Err(ProcessError::NodeLimit));
    }
}

#[test]
fn invalid_object_extent_fails_before_any_node_fields_are_read() {
    for pid_offset in [0x018, 0x030] {
        for pointer in [8, 0x0000_7fff_ffff_ff80, u64::MAX - 0x77, u64::MAX - 7] {
            let mut image = Image::new(layout(pid_offset), FIRST);
            image.links(HEAD, pointer, SECOND + 0x020);
            assert_eq!(image.find(42, 2), Err(ProcessError::InvalidPointer));
            assert_eq!(image.data_calls(), [(HEAD, 16)]);
        }
    }
}

#[test]
fn every_callback_failure_discards_find_results_and_stops_immediately() {
    for pid_offset in [0x018, 0x030] {
        for first in [FIRST, 0x8fd8] {
            let mut baseline = Image::new(layout(pid_offset), first);
            assert_eq!(baseline.find(42, 2), Ok(Some(baseline.expected())));
            for failed in 1..=baseline.calls.len() {
                let mut image = Image::new(layout(pid_offset), first);
                image.fail_call = Some(failed);
                assert_eq!(
                    image.find(42, 2),
                    Err(ProcessError::Read(ReadError::Paging(PagingError::PhysicalRead)))
                );
                assert_eq!(image.calls.len(), failed);
            }
        }
    }
}

#[test]
fn partial_adjacent_fields_never_publish_a_list_node() {
    for pid_offset in [0x018, 0x030] {
        let mut baseline = Image::new(layout(pid_offset), 0x8fd8);
        assert_eq!(baseline.find(99, 2), Ok(None));
        for failed in 6..=15 {
            let mut image = Image::new(layout(pid_offset), 0x8fd8);
            image.fail_call = Some(failed);
            let mut nodes = [ProcessNode { eprocess_va: 1, pid: 2 }; 2];
            assert!(matches!(image.list(&mut nodes), Err(ProcessError::Read(_))));
            assert_eq!(nodes, [ProcessNode { eprocess_va: 1, pid: 2 }; 2]);
            assert_eq!(image.calls.len(), failed);
        }
    }
}

#[test]
fn cross_page_read_observes_a_removed_mapping_before_reading_the_second_fragment() {
    let evidence = layout(0x018);
    let mut image = Image::new(evidence, 0x8fd8);
    let result = process::find(
        config(),
        ProcessProfile::new(evidence).unwrap(),
        request(42, 2),
        &mut |pa, bytes| {
            image.read(pa, bytes)?;
            if pa == 0xaff0 {
                image.word(0x4048, 0);
            }
            Ok(())
        },
    );
    assert_eq!(result, Err(ProcessError::Read(ReadError::Paging(PagingError::NotPresent))));
    assert_eq!(image.data_calls(), [(HEAD, 16), (0xaff0, 16)]);
}

#[test]
fn grouped_node_read_does_not_claim_atomic_identity_or_cache_later_discoveries() {
    let evidence = layout(0x018);
    let mut image = Image::new(evidence, FIRST);
    let mut changed = false;
    let result = process::find(
        config(),
        ProcessProfile::new(evidence).unwrap(),
        request(42, 2),
        &mut |pa, bytes| {
            image.read(pa, bytes)?;
            if pa == 0xa018 && !changed {
                image.virtual_word(FIRST + 0x018, 43);
                image.virtual_word(FIRST + 0x050, 0xf000);
                image.virtual_word(FIRST + 0x060, 101);
                changed = true;
            }
            Ok(())
        },
    );
    assert!(changed);
    assert_eq!(
        result,
        Ok(Some(ProcessObservation {
            create_time: Some(101),
            kernel_root_pa: 0xf000,
            ..image.expected()
        }))
    );
    image.calls.clear();
    assert_eq!(image.find(42, 2), Ok(None));
    assert_eq!(image.calls.len(), 15);
    assert_eq!(
        image.find(43, 2),
        Ok(Some(ProcessObservation {
            pid: 43,
            create_time: Some(101),
            kernel_root_pa: 0xf000,
            ..image.expected()
        }))
    );
}
