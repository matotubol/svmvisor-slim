//! Synthetic layouts only: no offset here identifies a Windows release.

use svmvisor_hypervisor::reader::{
    paging::{PagingConfig, PagingError},
    process::{
        self, ProcessError, ProcessLayoutEvidence, ProcessNode, ProcessObservation, ProcessProfile,
        ProcessRequest,
    },
};

const HEAD: u64 = 0x6000;
const FIRST: u64 = 0x8fd8;
const SECOND: u64 = 0xa000;

struct Image {
    bytes: Vec<u8>,
    calls: usize,
    failed_pa: Option<u64>,
}

impl Image {
    fn new() -> Self {
        let mut image = Self { bytes: vec![0; 0x10000], calls: 0, failed_pa: None };
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
        image.links(HEAD, FIRST + 0x020, SECOND + 0x020);
        image.links(FIRST + 0x020, SECOND + 0x020, HEAD);
        image.links(SECOND + 0x020, HEAD, FIRST + 0x020);
        for (va, pid, root, time) in [(FIRST, 42, 0xd123, 100), (SECOND, 84, 0xe000, 200)] {
            image.virtual_word(va + 0x040, pid);
            image.virtual_word(va + 0x050, root);
            image.virtual_word(va + 0x060, time);
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
        self.with_layout(layout(), pid, max_nodes)
    }

    fn with_layout(
        &mut self,
        layout: ProcessLayoutEvidence,
        pid: u64,
        max_nodes: usize,
    ) -> Result<Option<ProcessObservation>, ProcessError> {
        let config = PagingConfig::new(48, true, true).unwrap();
        let profile = ProcessProfile::new(layout)?;
        let request = ProcessRequest { kernel_root_pa: 0x1000, list_head_va: HEAD, pid, max_nodes };
        process::find(config, profile, request, &mut |pa, bytes: &mut [u8]| self.read(pa, bytes))
    }

    fn list(&mut self, nodes: &mut [ProcessNode]) -> Result<usize, ProcessError> {
        let config = PagingConfig::new(48, true, true).unwrap();
        let profile = ProcessProfile::new(layout())?;
        process::list(config, profile, 0x1000, HEAD, nodes, &mut |pa, bytes: &mut [u8]| {
            self.read(pa, bytes)
        })
    }

    fn read(&mut self, pa: u64, bytes: &mut [u8]) -> Result<(), PagingError> {
        self.calls += 1;
        if self.failed_pa == Some(pa) {
            bytes.fill(0xff);
            return Err(PagingError::PhysicalRead);
        }
        let start = usize::try_from(pa).map_err(|_| PagingError::PhysicalRead)?;
        let end = start.checked_add(bytes.len()).ok_or(PagingError::PhysicalRead)?;
        let source = self.bytes.get(start..end).ok_or(PagingError::PhysicalRead)?;
        bytes.copy_from_slice(source);
        Ok(())
    }
}

fn layout() -> ProcessLayoutEvidence {
    ProcessLayoutEvidence {
        eprocess_bytes: 0x100,
        active_links_offset: 0x020,
        pid_offset: 0x040,
        create_time_offset: Some(0x060),
        directory_root_offset: 0x050,
        dtb_low_bits_mask: 0x0fff,
    }
}

#[test]
fn matching_process_crosses_noncontiguous_pages_and_normalizes_explicit_low_bits() {
    let mut image = Image::new();
    assert_eq!(
        image.find(42, 2).unwrap(),
        Some(ProcessObservation {
            pid: 42,
            eprocess_va: FIRST,
            create_time: Some(100),
            kernel_root_pa: 0xd000,
        })
    );
    assert_eq!(
        image.find(84, 2).unwrap(),
        Some(ProcessObservation {
            pid: 84,
            eprocess_va: SECOND,
            create_time: Some(200),
            kernel_root_pa: 0xe000,
        })
    );
}

#[test]
fn missing_pid_and_valid_empty_list_return_none() {
    let mut image = Image::new();
    assert_eq!(image.find(99, 2), Ok(None));
    image.links(HEAD, HEAD, HEAD);
    assert_eq!(image.find(42, 1), Ok(None));
}

#[test]
fn corruption_after_match_does_not_release_partial_observation() {
    let mut image = Image::new();
    image.links(SECOND + 0x020, HEAD, HEAD);
    assert_eq!(image.find(42, 2), Err(ProcessError::CorruptLinks));
    image.links(SECOND + 0x020, HEAD, FIRST + 0x020);
    image.links(HEAD, FIRST + 0x020, FIRST + 0x020);
    assert_eq!(image.find(42, 2), Err(ProcessError::CorruptLinks));
}

#[test]
fn cyclic_list_terminates_with_error() {
    let mut image = Image::new();
    image.links(SECOND + 0x020, FIRST + 0x020, FIRST + 0x020);
    assert_eq!(image.find(42, 10), Err(ProcessError::CorruptLinks));
    assert!(image.calls < 100);
    image.links(FIRST + 0x020, FIRST + 0x020, HEAD);
    assert_eq!(image.find(42, 10), Err(ProcessError::CorruptLinks));
}

#[test]
fn finite_node_limit_is_enforced_even_after_match() {
    let mut image = Image::new();
    assert_eq!(image.find(42, 1), Err(ProcessError::NodeLimit));
    let calls = image.calls;
    assert_eq!(image.find(42, 0), Err(ProcessError::InvalidNodeLimit));
    assert_eq!(image.find(42, process::MAX_PROCESS_NODES + 1), Err(ProcessError::InvalidNodeLimit));
    assert_eq!(image.calls, calls);
}

#[test]
fn duplicate_matching_pid_is_ambiguous() {
    let mut image = Image::new();
    image.virtual_word(SECOND + 0x040, 42);
    assert_eq!(image.find(42, 2), Err(ProcessError::DuplicatePid));
}

#[test]
fn partial_second_page_of_links_and_missing_tables_fail_without_observation() {
    let mut image = Image::new();
    image.failed_pa = Some(0xc000);
    assert!(matches!(image.find(42, 2), Err(ProcessError::Read(_))));
    image.failed_pa = None;
    image.word(0x4048, 0);
    assert!(matches!(image.find(42, 2), Err(ProcessError::Read(_))));
}

#[test]
fn invalid_pointers_are_rejected() {
    for pointer in [0, 3, 0x0000_8000_0000_0000, u64::MAX - 7, 8] {
        let mut image = Image::new();
        image.links(HEAD, pointer, SECOND + 0x020);
        assert_eq!(image.find(42, 2), Err(ProcessError::InvalidPointer));
    }
}

#[test]
fn layout_rejects_misalignment_extent_overflow_and_field_overlap() {
    for evidence in [
        ProcessLayoutEvidence { eprocess_bytes: 0, ..layout() },
        ProcessLayoutEvidence { eprocess_bytes: u32::MAX, ..layout() },
        ProcessLayoutEvidence { pid_offset: 0x041, ..layout() },
        ProcessLayoutEvidence { directory_root_offset: u32::MAX - 7, ..layout() },
        ProcessLayoutEvidence { active_links_offset: 0x0f8, ..layout() },
        ProcessLayoutEvidence { dtb_low_bits_mask: 0x1000, ..layout() },
    ] {
        assert_eq!(ProcessProfile::new(evidence), Err(ProcessError::InvalidProfile));
    }
    for evidence in [
        ProcessLayoutEvidence { pid_offset: 0x028, ..layout() },
        ProcessLayoutEvidence { directory_root_offset: 0x040, ..layout() },
        ProcessLayoutEvidence { create_time_offset: Some(0x020), ..layout() },
    ] {
        assert_eq!(ProcessProfile::new(evidence), Err(ProcessError::OverlappingFields));
    }
}

#[test]
fn creation_identity_is_explicitly_absent_when_profile_lacks_field() {
    let mut image = Image::new();
    let evidence = ProcessLayoutEvidence { create_time_offset: None, ..layout() };
    assert_eq!(image.with_layout(evidence, 42, 2).unwrap().unwrap().create_time, None);
}

#[test]
fn root_rejects_unpermitted_low_bits_and_high_metadata() {
    let mut image = Image::new();
    let evidence = ProcessLayoutEvidence { dtb_low_bits_mask: 0, ..layout() };
    assert_eq!(image.with_layout(evidence, 42, 2), Err(ProcessError::InvalidDirectoryRoot));
    for raw_root in [(1 << 48) | 0xd000, (1 << 63) | 0xd000] {
        image.virtual_word(FIRST + 0x050, raw_root);
        assert_eq!(image.find(42, 2), Err(ProcessError::InvalidDirectoryRoot));
    }
    image.virtual_word(FIRST + 0x050, 0);
    assert_eq!(image.find(42, 2).unwrap().unwrap().kernel_root_pa, 0);
}

#[test]
fn list_copies_every_node_in_order_within_the_slice_limit() {
    let mut image = Image::new();
    let mut nodes = [ProcessNode::default(); 3];
    assert_eq!(image.list(&mut nodes), Ok(2));
    assert_eq!(
        nodes[..2],
        [ProcessNode { eprocess_va: FIRST, pid: 42 }, ProcessNode { eprocess_va: SECOND, pid: 84 }]
    );
    assert_eq!(image.list(&mut nodes[..1]), Err(ProcessError::NodeLimit));
    assert_eq!(image.list(&mut []), Err(ProcessError::InvalidNodeLimit));
    image.links(SECOND + 0x020, HEAD, HEAD);
    assert_eq!(image.list(&mut nodes), Err(ProcessError::CorruptLinks));
}

#[test]
fn traversal_coalesces_pid_and_links_without_reading_creation_time_or_root() {
    let mut image = Image::new();
    // Head: five callbacks. FIRST's PID/link range crosses two noncontiguous pages:
    // ten callbacks. SECOND fits one page: five callbacks. Previously this took thirty.
    assert_eq!(image.find(99, 2), Ok(None));
    assert_eq!(image.calls, 20);
    image.calls = 0;
    let mut nodes = [ProcessNode::default(); 2];
    assert_eq!(image.list(&mut nodes), Ok(2));
    assert_eq!(image.calls, 20);

    // A distant PID remains a separate read rather than expanding a bounded field read.
    image.virtual_word(FIRST + 0x0c0, 42);
    image.virtual_word(SECOND + 0x0c0, 84);
    image.calls = 0;
    let evidence = ProcessLayoutEvidence { pid_offset: 0x0c0, ..layout() };
    assert_eq!(image.with_layout(evidence, 99, 2), Ok(None));
    assert_eq!(image.calls, 30);
}

#[test]
fn combined_traversal_preserves_cross_page_fields_and_validates_the_tail() {
    let config = PagingConfig::new(48, true, true).unwrap();
    let profile = ProcessProfile::new(layout()).unwrap();
    let request =
        process::ProcessListRequest { kernel_root_pa: 0x1000, list_head_va: HEAD, max_nodes: 2 };
    for corrupt in [false, true] {
        let mut image = Image::new();
        if corrupt {
            image.links(HEAD, FIRST + 0x020, FIRST + 0x020);
        }
        let mut bytes = [0; 0x048];
        let mut observed = Vec::new();
        let result = process::visit_fields(
            config,
            profile,
            request,
            &mut process::ProcessFields { offset: 0x020, bytes: &mut bytes },
            &mut |pa, bytes: &mut [u8]| image.read(pa, bytes),
            &mut |node, bytes| {
                let bytes = bytes.unwrap();
                let time = u64::from_le_bytes(bytes[0x040..0x048].try_into().unwrap());
                observed.push((node.pid, time));
                Ok(())
            },
        );
        assert_eq!(observed, [(42, 100), (84, 200)]);
        assert_eq!(image.calls, 20);
        assert_eq!(result, if corrupt { Err(ProcessError::CorruptLinks) } else { Ok(()) });
    }
}

#[test]
fn combined_traversal_skips_missing_metadata_but_requires_complete_pid_and_links() {
    let mut image = Image::new();
    // Place all required fields before a boundary; only optional metadata crosses it.
    let first = 0x8f80;
    image.links(HEAD, first + 0x020, SECOND + 0x020);
    image.links(first + 0x020, SECOND + 0x020, HEAD);
    image.virtual_word(first + 0x040, 42);
    image.links(SECOND + 0x020, HEAD, first + 0x020);
    image.word(0x4048, 0);
    let request =
        process::ProcessListRequest { kernel_root_pa: 0x1000, list_head_va: HEAD, max_nodes: 2 };
    let config = PagingConfig::new(48, true, true).unwrap();
    let profile = ProcessProfile::new(layout()).unwrap();
    let mut bytes = [0; 0x0e0];
    let mut observed = Vec::new();
    process::visit_fields(
        config,
        profile,
        request,
        &mut process::ProcessFields { offset: 0x020, bytes: &mut bytes },
        &mut |pa, bytes: &mut [u8]| image.read(pa, bytes),
        &mut |node, bytes| {
            observed.push((node.pid, bytes.is_some()));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(observed, [(42, false), (84, true)]);

    image.word(0x4040, 0);
    let result = process::visit_fields(
        config,
        profile,
        request,
        &mut process::ProcessFields { offset: 0x020, bytes: &mut bytes },
        &mut |pa, bytes: &mut [u8]| image.read(pa, bytes),
        &mut |_, _| panic!("unreadable node must not reach the visitor"),
    );
    assert!(matches!(result, Err(ProcessError::Read(_))));
}

#[test]
fn invalid_combined_field_ranges_fail_before_reading_memory() {
    let config = PagingConfig::new(48, true, true).unwrap();
    let profile = ProcessProfile::new(layout()).unwrap();
    let request =
        process::ProcessListRequest { kernel_root_pa: 0x1000, list_head_va: HEAD, max_nodes: 2 };
    for (offset, length) in [(0, 0), (0x028, 0x040), (0x020, 0x020), (0x020, 0x100), (u32::MAX, 8)]
    {
        let mut bytes = vec![0; length];
        assert_eq!(
            process::visit_fields(
                config,
                profile,
                request,
                &mut process::ProcessFields { offset, bytes: &mut bytes },
                &mut |_: u64, _: &mut [u8]| panic!("invalid range must not read memory"),
                &mut |_, _| panic!("invalid range must not visit nodes"),
            ),
            Err(ProcessError::InvalidProfile),
        );
    }
}
