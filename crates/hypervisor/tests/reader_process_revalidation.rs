//! Synthetic process identities and layouts; no Windows build offsets are assumed.

use svmvisor_hypervisor::reader::{
    paging::{PagingConfig, PagingError},
    process::{
        self, ProcessError, ProcessLayoutEvidence, ProcessObservation, ProcessProfile,
        ProcessRequest,
    },
    read::ReadError,
};

const ROOT: u64 = 0x1000;
const HEAD: u64 = 0x6000;
const UNRELATED: u64 = 0x7000;
const PREVIOUS: u64 = 0x8000;
const TARGET: u64 = 0x9fd8;
const NEXT: u64 = 0xb000;
const FINAL: u64 = 0xc000;

struct Image {
    bytes: Vec<u8>,
    calls: Vec<(u64, usize)>,
    fail_call: Option<usize>,
}

impl Image {
    fn new(layout: ProcessLayoutEvidence) -> Self {
        let mut image = Self { bytes: vec![0; 0x12000], calls: Vec::new(), fail_call: None };
        for (pa, value) in [(0x1000, 0x2001), (0x2000, 0x3001), (0x3000, 0x4001)] {
            image.word(pa, value);
        }
        for page in 6..=12 {
            let pa = match page {
                9 => 0xd000,
                10 => 0xe000,
                _ => page * 0x1000,
            };
            image.word(0x4000 + page * 8, pa | 1);
        }
        let nodes = [UNRELATED, PREVIOUS, TARGET, NEXT, FINAL];
        let links = u64::from(layout.active_links_offset);
        image.links(HEAD, UNRELATED + links, FINAL + links);
        for (index, node) in nodes.into_iter().enumerate() {
            let previous = if index == 0 { HEAD } else { nodes[index - 1] + links };
            let next = if index + 1 == nodes.len() { HEAD } else { nodes[index + 1] + links };
            image.links(node + links, next, previous);
            image.virtual_word(node + u64::from(layout.pid_offset), 40 + index as u64);
            image.virtual_word(node + u64::from(layout.directory_root_offset), 0xf123);
            if let Some(offset) = layout.create_time_offset {
                image.virtual_word(node + u64::from(offset), 100 + index as u64);
            }
        }
        image
    }

    fn word(&mut self, pa: u64, value: u64) {
        let start = pa as usize;
        self.bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn virtual_word(&mut self, va: u64, value: u64) {
        let pa = match va & !0xfff {
            0x9000 => 0xd000 + (va & 0xfff),
            0xa000 => 0xe000 + (va & 0xfff),
            _ => va,
        };
        self.word(pa, value);
    }

    fn links(&mut self, va: u64, forward: u64, backward: u64) {
        self.virtual_word(va, forward);
        self.virtual_word(va + 8, backward);
    }

    fn read(&mut self, pa: u64, output: &mut [u8]) -> Result<(), PagingError> {
        self.calls.push((pa, output.len()));
        if self.fail_call == Some(self.calls.len()) {
            output.fill(0xff);
            return Err(PagingError::PhysicalRead);
        }
        let start = usize::try_from(pa).map_err(|_| PagingError::PhysicalRead)?;
        let end = start.checked_add(output.len()).ok_or(PagingError::PhysicalRead)?;
        output.copy_from_slice(self.bytes.get(start..end).ok_or(PagingError::PhysicalRead)?);
        Ok(())
    }

    fn find(&mut self, layout: ProcessLayoutEvidence) -> ProcessObservation {
        process::find(
            config(),
            ProcessProfile::new(layout).unwrap(),
            ProcessRequest { kernel_root_pa: ROOT, list_head_va: HEAD, pid: 42, max_nodes: 5 },
            &mut |pa, output: &mut [u8]| self.read(pa, output),
        )
        .unwrap()
        .unwrap()
    }

    fn revalidate(
        &mut self,
        layout: ProcessLayoutEvidence,
        expected: ProcessObservation,
    ) -> Result<ProcessObservation, ProcessError> {
        process::revalidate(
            config(),
            ProcessProfile::new(layout).unwrap(),
            ROOT,
            expected,
            &mut |pa, output: &mut [u8]| self.read(pa, output),
        )
    }
}

fn config() -> PagingConfig {
    PagingConfig::new(48, true, true).unwrap()
}

fn layout() -> ProcessLayoutEvidence {
    ProcessLayoutEvidence {
        eprocess_bytes: 0x200,
        active_links_offset: 0x020,
        pid_offset: 0x040,
        create_time_offset: Some(0x060),
        directory_root_offset: 0x050,
        dtb_low_bits_mask: 0x0fff,
    }
}

#[test]
fn revalidation_reads_exactly_target_fields_and_local_reciprocals_with_fresh_walks() {
    let layout = layout();
    let mut image = Image::new(layout);
    let expected = image.find(layout);
    assert_eq!(expected.kernel_root_pa, 0xf000);
    let mut calls = Vec::new();
    for (pte, pa, length) in [
        (0x4048, 0xdff8, 8),
        (0x4050, 0xe000, 32),
        (0x4050, 0xe038, 8),
        (0x4050, 0xe028, 8),
        (0x4058, 0xb028, 8),
        (0x4040, 0x8020, 8),
    ] {
        calls.extend([(0x1000, 8), (0x2000, 8), (0x3000, 8), (pte, 8), (pa, length)]);
    }
    for _ in 0..2 {
        image.calls.clear();
        assert_eq!(image.revalidate(layout, expected), Ok(expected));
        assert_eq!(image.calls, calls);
    }
}

#[test]
fn pid_creation_time_and_target_root_mutations_are_distinct_failures() {
    for (offset, value, error) in [
        (0x040, 84, ProcessError::IdentityChanged),
        (0x060, 999, ProcessError::IdentityChanged),
        (0x050, 0x10000, ProcessError::DirectoryRootChanged),
        (0x050, 1 << 48, ProcessError::InvalidDirectoryRoot),
    ] {
        let mut image = Image::new(layout());
        let expected = image.find(layout());
        image.virtual_word(TARGET + offset, value);
        assert_eq!(image.revalidate(layout(), expected), Err(error));
    }
}

#[test]
fn changing_neighbors_is_valid_when_current_links_are_reciprocal() {
    let mut image = Image::new(layout());
    let expected = image.find(layout());
    image.links(TARGET + 0x020, NEXT + 0x020, UNRELATED + 0x020);
    image.links(UNRELATED + 0x020, TARGET + 0x020, HEAD);
    image.links(PREVIOUS + 0x020, 0, 0);
    assert_eq!(image.revalidate(layout(), expected), Ok(expected));
}

#[test]
fn self_links_invalid_pointers_and_unlinked_target_are_rejected() {
    for (va, value, error) in [
        (TARGET + 0x020, TARGET + 0x020, ProcessError::CorruptLinks),
        (TARGET + 0x028, TARGET + 0x020, ProcessError::CorruptLinks),
        (TARGET + 0x020, 0, ProcessError::InvalidPointer),
        (TARGET + 0x028, 3, ProcessError::InvalidPointer),
        (NEXT + 0x028, PREVIOUS + 0x020, ProcessError::CorruptLinks),
        (PREVIOUS + 0x020, NEXT + 0x020, ProcessError::CorruptLinks),
    ] {
        let mut image = Image::new(layout());
        let expected = image.find(layout());
        image.virtual_word(va, value);
        assert_eq!(image.revalidate(layout(), expected), Err(error));
    }
}

#[test]
fn disappearing_and_replaced_mappings_are_not_hidden_by_a_translation_cache() {
    let mut image = Image::new(layout());
    let expected = image.find(layout());
    assert_eq!(image.revalidate(layout(), expected), Ok(expected));
    image.word(0x4050, 0);
    assert_eq!(
        image.revalidate(layout(), expected),
        Err(ProcessError::Read(ReadError::Paging(PagingError::NotPresent)))
    );
    image.word(0x4050, 0x10001);
    let previous_page = image.bytes[0xe000..0xf000].to_vec();
    image.bytes[0x10000..0x11000].copy_from_slice(&previous_page);
    image.word(0x10018, 84);
    assert_eq!(image.revalidate(layout(), expected), Err(ProcessError::IdentityChanged));
}

#[test]
fn every_callback_failure_discards_the_observation_and_stops_reading() {
    let mut baseline = Image::new(layout());
    let expected = baseline.find(layout());
    baseline.calls.clear();
    assert_eq!(baseline.revalidate(layout(), expected), Ok(expected));
    for failed in 1..=baseline.calls.len() {
        let mut image = Image::new(layout());
        image.fail_call = Some(failed);
        assert_eq!(
            image.revalidate(layout(), expected),
            Err(ProcessError::Read(ReadError::Paging(PagingError::PhysicalRead)))
        );
        assert_eq!(image.calls.len(), failed);
    }
}

#[test]
fn nearby_time_coalesces_and_distant_identity_fields_remain_bounded() {
    for evidence in [
        ProcessLayoutEvidence { create_time_offset: Some(0x030), ..layout() },
        ProcessLayoutEvidence { create_time_offset: Some(0x058), ..layout() },
        ProcessLayoutEvidence { pid_offset: 0x080, ..layout() },
        ProcessLayoutEvidence { create_time_offset: None, ..layout() },
    ] {
        let mut image = Image::new(evidence);
        let expected = image.find(evidence);
        image.calls.clear();
        assert_eq!(image.revalidate(evidence, expected), Ok(expected));
        assert!(image.calls.iter().all(|&(_, length)| length <= 64));
        if evidence.create_time_offset == Some(0x030) {
            assert_eq!(image.calls.len(), 25);
            assert!(!image.calls.contains(&(0xe038, 8)));
        }
        if evidence.create_time_offset == Some(0x058) {
            assert_eq!(image.calls.len(), 25);
            assert!(image.calls.contains(&(0xdff8, 8)));
            assert!(image.calls.contains(&(0xe000, 56)));
        }
    }
}

#[test]
fn invalid_expected_address_or_creation_time_shape_fails_without_callbacks() {
    let mut image = Image::new(layout());
    let expected = image.find(layout());
    image.calls.clear();
    assert_eq!(
        image.revalidate(layout(), ProcessObservation { eprocess_va: u64::MAX - 7, ..expected }),
        Err(ProcessError::InvalidPointer)
    );
    assert_eq!(
        image.revalidate(layout(), ProcessObservation { create_time: None, ..expected }),
        Err(ProcessError::IdentityChanged)
    );
    assert!(image.calls.is_empty());
}
