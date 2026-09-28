//! Transport-independent process batches with bounded service opportunities.
//! Identity checks are observations, not page pins or atomic snapshots.

use svmvisor_card_abi::{
    batch::{
        self, BatchRequest, MAX_DATA_BYTES, MAX_RANGES, MAX_RESPONSE_BYTES, Operation, Status,
    },
    diagnostic::{DiagnosticEntry, DiagnosticObservation},
};

use crate::{
    memory::address::{PAGE_BYTES, is_canonical_48},
    reader::{
        paging::{self, PagingConfig, PagingError},
        process::{self, ProcessError, ProcessLayoutEvidence, ProcessObservation, ProcessProfile},
        read::ReadError,
    },
};

pub const SLICE_BYTES: usize = 256;
/// Six metadata ranges, at most two pages and five physical callbacks per page.
pub const MAX_SLICE_CALLS: usize = 60;
/// A local call may group four data fragments, but never mix them with metadata validation.
/// Four four-level translations plus their data reads need at most twenty callbacks.
pub const MAX_DATA_SLICES_PER_CALL: usize = 4;
/// Eight ranges add at most sixteen alignment fragments to sixteen full data slices.
pub const MAX_SERVICE_STEPS: usize = 34;

pub struct BatchEngine {
    session: u64,
    sequence: u64,
    boot: u64,
    next_token: u64,
    binding: Option<ProcessBinding>,
    request: Option<BatchRequest>,
    config: Option<PagingConfig>,
    phase: BatchPhase,
    range: usize,
    offset: usize,
    length: usize,
    data: [u8; MAX_DATA_BYTES],
    response: [u8; MAX_RESPONSE_BYTES],
    response_length: usize,
    steps: usize,
}

impl BatchEngine {
    pub const fn new() -> Self {
        Self {
            session: 0,
            sequence: 0,
            boot: 0,
            next_token: 0,
            binding: None,
            request: None,
            config: None,
            phase: BatchPhase::Idle,
            range: 0,
            offset: 0,
            length: 0,
            data: [0; MAX_DATA_BYTES],
            response: [0; MAX_RESPONSE_BYTES],
            response_length: 0,
            steps: 0,
        }
    }

    pub fn response(&self) -> Option<&[u8]> {
        (self.phase == BatchPhase::Complete).then_some(&self.response[..self.response_length])
    }

    /// Accept a shape-checked request. The round trip through the codec also validates callers
    /// constructing the public wire value directly. Completed replies must be consumed first.
    pub fn begin(
        &mut self,
        request: BatchRequest,
        boot: u64,
        config: PagingConfig,
    ) -> Result<(), Status> {
        if self.phase != BatchPhase::Idle {
            return Err(Status::Sequence);
        }
        if request.count > MAX_RANGES {
            return Err(Status::Shape);
        }
        let decoded = BatchRequest::decode(&request.encode()).map_err(|_| Status::Shape)?;
        if decoded != request {
            return Err(Status::Shape);
        }
        if self.boot != 0 && self.boot != boot {
            self.clear();
        }
        self.request = Some(request);
        self.config = Some(config);
        self.length = 0;
        self.range = 0;
        self.offset = 0;
        self.steps = 0;
        self.boot = boot;
        if boot == 0 {
            self.finish(Status::Identity);
            return Ok(());
        }
        if request.operation == Operation::Hello {
            // A new transport session invalidates every prior process token. Replayed Hello
            // within the same session cannot reset sequence enforcement.
            if request.session == self.session && request.sequence <= self.sequence {
                self.finish(Status::Sequence);
                return Ok(());
            }
            self.session = request.session;
            self.sequence = request.sequence;
            self.binding = None;
            self.finish(Status::Success);
            return Ok(());
        }
        if request.session != self.session || request.boot != boot {
            self.finish(Status::Identity);
            return Ok(());
        }
        if request.sequence <= self.sequence {
            self.finish(Status::Sequence);
            return Ok(());
        }
        self.sequence = request.sequence;
        self.phase = match request.operation {
            Operation::Hello => BatchPhase::Idle,
            Operation::Physical => BatchPhase::Data,
            Operation::Bind => {
                self.binding = None;
                let evidence = request.binding;
                if evidence.creation_offset == u32::MAX {
                    self.finish(Status::Binding);
                    return Ok(());
                }
                let profile = ProcessProfile::new(ProcessLayoutEvidence {
                    eprocess_bytes: evidence.object_bytes,
                    active_links_offset: evidence.links_offset,
                    pid_offset: evidence.pid_offset,
                    directory_root_offset: evidence.root_offset,
                    create_time_offset: (evidence.creation_offset != u32::MAX)
                        .then_some(evidence.creation_offset),
                    dtb_low_bits_mask: evidence.root_mask,
                });
                let Ok(profile) = profile else {
                    self.finish(Status::Binding);
                    return Ok(());
                };
                // Exhaustion never wraps a token back to a previously issued value.
                let Some(token) = self.next_token.checked_add(1) else {
                    self.finish(Status::Binding);
                    return Ok(());
                };
                self.next_token = token;
                self.binding = Some(ProcessBinding {
                    profile,
                    kernel_root: evidence.kernel_root,
                    token,
                    observation: ProcessObservation {
                        pid: evidence.pid,
                        eprocess_va: evidence.object,
                        kernel_root_pa: evidence.target_root,
                        create_time: (evidence.creation_offset != u32::MAX)
                            .then_some(evidence.creation),
                    },
                });
                BatchPhase::Before
            }
            Operation::Sample | Operation::Explain => {
                if self.binding.is_none_or(|binding| binding.token != request.token) {
                    if request.operation == Operation::Explain {
                        self.binding = None;
                    }
                    self.finish(Status::Binding);
                    return Ok(());
                }
                for range in &request.ranges[..request.count] {
                    let end = range.address + (u64::from(range.length) - 1);
                    if request.operation == Operation::Sample
                        && (!is_canonical_48(range.address) || !is_canonical_48(end))
                    {
                        self.finish(Status::Shape);
                        return Ok(());
                    }
                }
                BatchPhase::Before
            }
        };
        Ok(())
    }

    /// Each call performs one metadata validation, one diagnostic walk, or one <=256-byte fragment.
    /// The callback budget is enforced even if a future validator grows more expensive.
    pub fn advance(
        &mut self,
        read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), PagingError>,
    ) -> bool {
        self.advance_with_translation(read, &mut None)
    }

    fn advance_with_translation(
        &mut self,
        read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), PagingError>,
        translation: &mut Option<FragmentTranslation>,
    ) -> bool {
        let Some(request) = self.request else {
            return false;
        };
        let Some(config) = self.config else {
            return false;
        };
        if self.phase == BatchPhase::Complete {
            return true;
        }
        if self.steps == MAX_SERVICE_STEPS {
            self.binding = None;
            self.finish(Status::Read);
            return true;
        }
        self.steps += 1;
        // The ordinary data and diagnostic paths share the same physical callback type and
        // paging walker. Only the diagnostic data phase initializes and records wire evidence.
        let mut diagnostic =
            if request.operation == Operation::Explain && self.phase == BatchPhase::Data {
                self.binding.map(|binding| DiagnosticObservation {
                    root: binding.observation.kernel_root_pa,
                    address: request.ranges[0].address,
                    physical_bits: config.physical_bits(),
                    nxe: config.nxe(),
                    page_1g: config.page_1g(),
                    ..DiagnosticObservation::EMPTY
                })
            } else {
                None
            };
        let mut calls = 0;
        let mut bounded = |address, bytes: &mut [u8]| {
            if calls == MAX_SLICE_CALLS || bytes.len() > SLICE_BYTES {
                return Err(PagingError::PhysicalRead);
            }
            calls += 1;
            read(address, bytes).map_err(|_| PagingError::PhysicalRead)?;
            if let Some(observation) = diagnostic.as_mut() {
                let bytes: &mut [u8; 8] =
                    bytes.try_into().map_err(|_| PagingError::PhysicalRead)?;
                let entry = observation
                    .entries
                    .get_mut(observation.count)
                    .ok_or(PagingError::PhysicalRead)?;
                *entry = DiagnosticEntry { address, value: u64::from_le_bytes(*bytes) };
                observation.count += 1;
            }
            Ok(())
        };
        match self.phase {
            BatchPhase::Before | BatchPhase::After => {
                let Some(binding) = self.binding else {
                    self.finish(Status::Binding);
                    return true;
                };
                let validation = process::revalidate(
                    config,
                    binding.profile,
                    binding.kernel_root,
                    binding.observation,
                    &mut bounded,
                );
                if let Err(error) = validation {
                    self.binding = None;
                    let status = if request.operation == Operation::Explain
                        && error == ProcessError::Read(ReadError::Paging(PagingError::PhysicalRead))
                    {
                        Status::Read
                    } else {
                        Status::Binding
                    };
                    self.finish(status);
                } else if self.phase == BatchPhase::After || request.operation == Operation::Bind {
                    self.finish(Status::Success);
                } else {
                    self.phase = BatchPhase::Data;
                }
            }
            BatchPhase::Data if request.operation == Operation::Explain => {
                let Some(binding) = self.binding else {
                    self.finish(Status::Binding);
                    return true;
                };
                let result = paging::translate(
                    config,
                    binding.observation.kernel_root_pa,
                    request.ranges[0].address,
                    &mut bounded,
                );
                if result == Err(PagingError::PhysicalRead) {
                    self.finish(Status::Read);
                    return true;
                }
                let Some(observation) = diagnostic else {
                    self.finish(Status::Binding);
                    return true;
                };
                let Ok(bytes) = observation.encode() else {
                    self.finish(Status::Read);
                    return true;
                };
                self.data[..bytes.len()].copy_from_slice(&bytes);
                self.length = bytes.len();
                self.phase = BatchPhase::After;
            }
            BatchPhase::Data => {
                let range = request.ranges[self.range];
                let address = range.address + self.offset as u64;
                let page_remaining = PAGE_BYTES - (address as usize & (PAGE_BYTES - 1));
                let count =
                    SLICE_BYTES.min(range.length as usize - self.offset).min(page_remaining);
                let physical = if request.operation == Operation::Sample {
                    if let Some(previous) = translation.filter(|previous| {
                        previous.range == self.range && previous.address == address
                    }) {
                        previous.physical
                    } else {
                        let binding = self.binding.unwrap();
                        match paging::translate(
                            config,
                            binding.observation.kernel_root_pa,
                            address,
                            &mut bounded,
                        ) {
                            Ok(translation) => translation.pa(),
                            Err(_) => {
                                self.finish(Status::Read);
                                return true;
                            }
                        }
                    }
                } else {
                    address
                };
                if bounded(physical, &mut self.data[self.length..self.length + count]).is_err() {
                    self.finish(Status::Read);
                    return true;
                }
                self.length += count;
                self.offset += count;
                // Reuse only for the immediately following fragment of this range in this
                // 4 KiB page. Even a huge-page translation is forgotten at a 4 KiB boundary.
                // A successful translation and the page bound make both additions safe.
                *translation = if request.operation == Operation::Sample
                    && self.offset < range.length as usize
                    && count < page_remaining
                {
                    Some(FragmentTranslation {
                        range: self.range,
                        address: address + count as u64,
                        physical: physical + count as u64,
                    })
                } else {
                    None
                };
                if self.offset == range.length as usize {
                    self.range += 1;
                    self.offset = 0;
                }
                if self.range == request.count {
                    if request.operation == Operation::Sample {
                        self.phase = BatchPhase::After;
                    } else {
                        self.finish(Status::Success);
                    }
                }
            }
            BatchPhase::Idle | BatchPhase::Complete => {}
        }
        self.phase == BatchPhase::Complete
    }

    /// Service one metadata phase or at most four data fragments (at most 1024 data bytes).
    /// Metadata validation stays on each side of the data, in separate opportunities.
    /// Adjacent fragments in the same range and 4 KiB page share one sampled translation
    /// during this call only. This does not pin the mapping or provide an atomic snapshot.
    /// The whole call retains the single-phase callback ceiling; grouping never grants a
    /// fresh callback budget per fragment. This bounds work, not elapsed time: callers
    /// must separately validate their worst-case interrupt latency on the target machine.
    pub fn advance_bounded(
        &mut self,
        read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), PagingError>,
    ) -> bool {
        let limit = if self.phase == BatchPhase::Data { MAX_DATA_SLICES_PER_CALL } else { 1 };
        let mut translation = None;
        let mut calls = 0;
        let mut bounded = |address, bytes: &mut [u8]| {
            if calls == MAX_SLICE_CALLS || bytes.len() > SLICE_BYTES {
                return Err(PagingError::PhysicalRead);
            }
            calls += 1;
            read(address, bytes)
        };
        for _ in 0..limit {
            if self.advance_with_translation(&mut bounded, &mut translation) {
                return true;
            }
            if self.phase != BatchPhase::Data {
                break;
            }
        }
        false
    }

    pub fn reset_response(&mut self) {
        self.data.fill(0);
        self.response.fill(0);
        self.response_length = 0;
        self.request = None;
        self.phase = BatchPhase::Idle;
    }

    /// Cancel transport ownership, forgetting the session and process binding.
    pub fn clear(&mut self) {
        self.reset_response();
        self.session = 0;
        self.sequence = 0;
        self.binding = None;
        self.config = None;
    }

    fn finish(&mut self, status: Status) {
        if status != Status::Success {
            self.length = 0;
            self.data.fill(0);
        }
        let token = self.binding.map_or(0, |binding| binding.token);
        self.response_length = batch::encode_response(
            self.request.unwrap(),
            self.boot,
            token,
            status,
            &self.data[..self.length],
            &mut self.response,
        )
        .unwrap();
        self.phase = BatchPhase::Complete;
    }
}

impl Default for BatchEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
struct ProcessBinding {
    profile: ProcessProfile,
    kernel_root: u64,
    observation: ProcessObservation,
    token: u64,
}

#[derive(Clone, Copy)]
struct FragmentTranslation {
    range: usize,
    address: u64,
    physical: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BatchPhase {
    Idle,
    Before,
    Data,
    After,
    Complete,
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;
    use svmvisor_card_abi::{
        batch::{BatchRange, BindingEvidence},
        diagnostic,
    };

    fn request(operation: Operation, sequence: u64) -> BatchRequest {
        BatchRequest {
            operation,
            session: 1,
            boot: 7,
            sequence,
            token: 0,
            count: 0,
            ranges: [BatchRange::EMPTY; MAX_RANGES],
            binding: BindingEvidence::EMPTY,
        }
    }

    fn config() -> PagingConfig {
        PagingConfig::new(48, true, true).unwrap()
    }

    fn hello(engine: &mut BatchEngine) {
        let mut request = request(Operation::Hello, 1);
        request.boot = 0;
        engine.begin(request, 7, config()).unwrap();
        assert_eq!(status(engine), Status::Success as u32);
        engine.reset_response();
    }

    fn status(engine: &BatchEngine) -> u32 {
        u32::from_le_bytes(engine.response().unwrap()[40..44].try_into().unwrap())
    }

    fn put(image: &mut [u8], address: usize, value: u64) {
        image[address..address + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn image() -> [u8; 0x10000] {
        let mut image = [0; 0x10000];
        put(&mut image, 0x1000, 0x2003);
        put(&mut image, 0x2000, 0x3003);
        put(&mut image, 0x3000, 0x0083);
        put(&mut image, 0x6000, 0x6100);
        put(&mut image, 0x6008, 0x6200);
        put(&mut image, 0x6010, 42);
        put(&mut image, 0x6018, 0x1000);
        put(&mut image, 0x6020, 99);
        put(&mut image, 0x6108, 0x6000);
        put(&mut image, 0x6200, 0x6000);
        image[0x8000..0xb000].fill(0xa5);
        image
    }

    fn advance(engine: &mut BatchEngine, image: &[u8]) -> bool {
        let mut calls = 0;
        let complete = engine.advance(&mut |address, bytes| {
            calls += 1;
            assert!(bytes.len() <= SLICE_BYTES);
            let start = address as usize;
            let source = image.get(start..start + bytes.len()).ok_or(PagingError::PhysicalRead)?;
            bytes.copy_from_slice(source);
            Ok(())
        });
        assert!(calls <= MAX_SLICE_CALLS);
        complete
    }

    fn bind(engine: &mut BatchEngine, image: &[u8]) -> u64 {
        let mut request = request(Operation::Bind, 2);
        request.binding = BindingEvidence {
            kernel_root: 0x1000,
            target_root: 0x1000,
            pid: 42,
            object: 0x6000,
            creation: 99,
            object_bytes: 64,
            links_offset: 0,
            pid_offset: 16,
            root_offset: 24,
            creation_offset: 32,
            root_mask: 0,
        };
        engine.begin(request, 7, config()).unwrap();
        assert!(advance(engine, image));
        assert_eq!(status(engine), Status::Success as u32);
        let token = u64::from_le_bytes(engine.response().unwrap()[32..40].try_into().unwrap());
        engine.reset_response();
        token
    }

    fn sample(token: u64) -> BatchRequest {
        let mut request = request(Operation::Sample, 3);
        request.token = token;
        request.count = 2;
        request.ranges[0] = BatchRange { address: 0x8ff0, length: 1024 };
        request.ranges[1] = BatchRange { address: 0x9800, length: 3072 };
        request
    }

    fn four_level_image() -> [u8; 0x10000] {
        let mut image = image();
        put(&mut image, 0x3000, 0x4003);
        for page in 0..16 {
            put(&mut image, 0x4000 + page * 8, (page as u64 * 4096) | 3);
        }
        for (index, byte) in image[0x8000..0xb000].iter_mut().enumerate() {
            *byte = (index ^ (index >> 8)) as u8;
        }
        image
    }

    fn pending(operation: Operation, ranges: &[BatchRange], image: &[u8]) -> BatchEngine {
        let mut engine = BatchEngine::new();
        hello(&mut engine);
        let token = if matches!(operation, Operation::Sample | Operation::Explain) {
            bind(&mut engine, image)
        } else {
            0
        };
        let mut request = request(operation, 3);
        request.token = token;
        request.count = ranges.len();
        request.ranges[..ranges.len()].copy_from_slice(ranges);
        engine.begin(request, 7, config()).unwrap();
        engine
    }

    fn finish_traced(
        engine: &mut BatchEngine,
        image: &[u8],
        grouped: bool,
        fail_at: Option<u64>,
    ) -> Vec<Vec<(u64, usize)>> {
        let mut opportunities = Vec::new();
        loop {
            let phase = engine.phase;
            let mut trace = Vec::new();
            let mut read = |address, bytes: &mut [u8]| {
                trace.push((address, bytes.len()));
                assert!(bytes.len() <= SLICE_BYTES);
                if Some(address) == fail_at {
                    bytes.fill(0xee);
                    return Err(PagingError::PhysicalRead);
                }
                let start = address as usize;
                let source =
                    image.get(start..start + bytes.len()).ok_or(PagingError::PhysicalRead)?;
                bytes.copy_from_slice(source);
                Ok(())
            };
            let complete =
                if grouped { engine.advance_bounded(&mut read) } else { engine.advance(&mut read) };
            assert!(trace.len() <= MAX_SLICE_CALLS);
            if grouped && phase == BatchPhase::Data {
                assert!(trace.len() <= MAX_DATA_SLICES_PER_CALL * 5);
                assert!(
                    trace.iter().filter(|(address, _)| *address >= 0x8000).count()
                        <= MAX_DATA_SLICES_PER_CALL
                );
                assert!(
                    trace
                        .iter()
                        .filter(|(address, _)| *address >= 0x8000)
                        .map(|(_, length)| *length)
                        .sum::<usize>()
                        <= 1024
                );
            }
            opportunities.push(trace);
            assert!(opportunities.len() <= MAX_SERVICE_STEPS);
            if complete {
                return opportunities;
            }
        }
    }

    #[test]
    fn bounded_calls_preserve_bytes_and_data_reads_with_fewer_continuations() {
        let image = four_level_image();
        for (operation, ranges, old_calls, new_calls) in [
            (Operation::Physical, std::vec![BatchRange { address: 0x8000, length: 4096 }], 16, 4),
            (Operation::Sample, std::vec![BatchRange { address: 0x8000, length: 4096 }], 18, 6),
            (Operation::Physical, std::vec![BatchRange { address: 0x8001, length: 4096 }], 17, 5),
            (Operation::Sample, std::vec![BatchRange { address: 0x8001, length: 4096 }], 19, 7),
            (
                Operation::Physical,
                std::vec![BatchRange { address: 0x8fff, length: 512 }; MAX_RANGES],
                24,
                6,
            ),
            (
                Operation::Sample,
                std::vec![BatchRange { address: 0x8fff, length: 512 }; MAX_RANGES],
                26,
                8,
            ),
        ] {
            let mut single = pending(operation, &ranges, &image);
            let mut grouped = pending(operation, &ranges, &image);
            let old = finish_traced(&mut single, &image, false, None);
            let new = finish_traced(&mut grouped, &image, true, None);
            assert_eq!(old.len(), old_calls);
            assert_eq!(new.len(), new_calls);
            assert_eq!(
                old.iter().flatten().filter(|(address, _)| *address >= 0x8000).collect::<Vec<_>>(),
                new.iter().flatten().filter(|(address, _)| *address >= 0x8000).collect::<Vec<_>>()
            );
            assert_eq!(single.steps, grouped.steps);
            assert_eq!(single.response(), grouped.response());
            assert_eq!(status(&grouped), Status::Success as u32);
            let expected: Vec<_> = ranges
                .iter()
                .flat_map(|range| {
                    image[range.address as usize..range.address as usize + range.length as usize]
                        .iter()
                        .copied()
                })
                .collect();
            assert_eq!(&grouped.response().unwrap()[64..64 + expected.len()], expected);
            if operation == Operation::Sample {
                assert!(new.first().unwrap().iter().all(|(address, _)| *address < 0x8000));
                assert!(new.last().unwrap().iter().all(|(address, _)| *address < 0x8000));
                assert_eq!(old.first(), new.first());
                assert_eq!(old.last(), new.last());
                assert!(new[1].len() < 20);
            } else {
                assert_eq!(
                    old.iter().flatten().collect::<Vec<_>>(),
                    new.iter().flatten().collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn bounded_calls_stop_at_first_failure_and_discard_partial_data() {
        let image = four_level_image();
        let ranges = [BatchRange { address: 0x8000, length: 4096 }];
        for operation in [Operation::Physical, Operation::Sample] {
            for fail_at in [0x8000, 0x8100, 0x8300, 0x8400, 0x8f00] {
                let mut single = pending(operation, &ranges, &image);
                let mut grouped = pending(operation, &ranges, &image);
                let old = finish_traced(&mut single, &image, false, Some(fail_at));
                let new = finish_traced(&mut grouped, &image, true, Some(fail_at));
                assert_eq!(
                    old.iter()
                        .flatten()
                        .filter(|(address, _)| *address >= 0x8000)
                        .collect::<Vec<_>>(),
                    new.iter()
                        .flatten()
                        .filter(|(address, _)| *address >= 0x8000)
                        .collect::<Vec<_>>()
                );
                assert_eq!(single.steps, grouped.steps);
                assert_eq!(single.response(), grouped.response());
                assert_eq!(status(&grouped), Status::Read as u32);
                assert_eq!(grouped.response().unwrap().len(), 68);
                assert!(grouped.data.iter().all(|byte| *byte == 0));
            }
        }
    }

    #[test]
    fn bounded_calls_share_one_walk_for_four_fragments_of_each_page_size() {
        let mut gigabyte = image();
        put(&mut gigabyte, 0x2000, 0x0083);
        for (image, levels) in [(four_level_image(), 4), (image(), 3), (gigabyte, 2)] {
            let ranges = [BatchRange { address: 0x8000, length: 1024 }];
            let mut single = pending(Operation::Sample, &ranges, &image);
            let mut grouped = pending(Operation::Sample, &ranges, &image);
            let old = finish_traced(&mut single, &image, false, None);
            let new = finish_traced(&mut grouped, &image, true, None);
            assert_eq!(old[1..5].iter().map(Vec::len).sum::<usize>(), 4 * (levels + 1));
            assert_eq!(new[1].len(), levels + 4);
            assert_eq!(new.len(), 3);
            assert_eq!(single.steps, grouped.steps);
            assert_eq!(single.response(), grouped.response());
        }
    }

    #[test]
    fn bounded_calls_restart_walks_at_pages_and_each_range() {
        for (image, levels) in [(four_level_image(), 4), (image(), 3)] {
            for ranges in [
                std::vec![BatchRange { address: 0x8f00, length: 1024 }],
                std::vec![
                    BatchRange { address: 0x8000, length: 512 },
                    BatchRange { address: 0x8200, length: 512 },
                ],
                std::vec![
                    BatchRange { address: 0x8000, length: 512 },
                    BatchRange { address: 0x8100, length: 512 },
                ],
                std::vec![
                    BatchRange { address: 0x8000, length: 512 },
                    BatchRange { address: 0x8400, length: 512 },
                ],
            ] {
                let mut engine = pending(Operation::Sample, &ranges, &image);
                let trace = finish_traced(&mut engine, &image, true, None);
                assert_eq!(trace.len(), 3);
                assert_eq!(trace[1].len(), 2 * levels + 4);
                assert_eq!(trace[1].iter().filter(|(address, _)| *address == 0x1000).count(), 2);
                let expected: Vec<_> = ranges
                    .iter()
                    .flat_map(|range| {
                        image
                            [range.address as usize..range.address as usize + range.length as usize]
                            .iter()
                            .copied()
                    })
                    .collect();
                assert_eq!(&engine.response().unwrap()[64..64 + expected.len()], expected);
            }
        }
    }

    #[test]
    fn bounded_calls_discard_a_failed_walk_after_partial_data() {
        let image = four_level_image();
        let ranges = [BatchRange { address: 0x8f00, length: 512 }];
        let mut engine = pending(Operation::Sample, &ranges, &image);
        let trace = finish_traced(&mut engine, &image, true, Some(0x4048));
        assert_eq!(status(&engine), Status::Read as u32);
        assert_eq!(trace.len(), 2);
        assert_eq!(trace[1].len(), 9);
        assert_eq!(trace[1].last(), Some(&(0x4048, 8)));
        assert_eq!(trace[1].iter().filter(|(address, _)| *address >= 0x8000).count(), 1);
        assert_eq!(engine.response().unwrap().len(), 68);
        assert!(engine.data.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn bounded_calls_observe_new_mapping_in_the_next_opportunity() {
        let mut image = four_level_image();
        image[0xc000..0xd000].fill(0x3c);
        let mut engine =
            pending(Operation::Sample, &[BatchRange { address: 0x8000, length: 2048 }], &image);
        assert!(!advance(&mut engine, &image));
        let mut calls = 0;
        assert!(!engine.advance_bounded(&mut |address, bytes| {
            calls += 1;
            let start = address as usize;
            bytes.copy_from_slice(&image[start..start + bytes.len()]);
            Ok(())
        }));
        assert_eq!(calls, 8);
        assert_eq!(engine.length, 1024);
        put(&mut image, 0x4040, 0xc003);
        let trace = finish_traced(&mut engine, &image, true, None);
        assert_eq!(trace[0].len(), 8);
        assert_eq!(trace[0][4..], [(0xc400, 256), (0xc500, 256), (0xc600, 256), (0xc700, 256)]);
        assert_eq!(status(&engine), Status::Success as u32);
        assert_eq!(&engine.response().unwrap()[64..1088], &image[0x8000..0x8400]);
        assert_eq!(&engine.response().unwrap()[1088..2112], &[0x3c; 1024]);
    }

    #[test]
    fn reused_translation_does_not_extend_service_step_budget() {
        let image = four_level_image();
        let mut engine =
            pending(Operation::Sample, &[BatchRange { address: 0x8000, length: 4096 }], &image);
        assert!(!advance(&mut engine, &image));
        engine.steps = MAX_SERVICE_STEPS - 2;
        let trace = finish_traced(&mut engine, &image, true, None);
        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0].len(), 6);
        assert_eq!(engine.steps, MAX_SERVICE_STEPS);
        assert_eq!(status(&engine), Status::Read as u32);
        assert!(engine.data.iter().all(|byte| *byte == 0));
        assert!(engine.binding.is_none());
    }

    #[test]
    fn bounded_calls_keep_both_identity_checks_outside_the_data_group() {
        for before in [true, false] {
            let mut image = four_level_image();
            let mut engine =
                pending(Operation::Sample, &[BatchRange { address: 0x8000, length: 4096 }], &image);
            if !before {
                while engine.phase != BatchPhase::After {
                    assert!(!engine.advance_bounded(&mut |address, bytes| {
                        let start = address as usize;
                        bytes.copy_from_slice(&image[start..start + bytes.len()]);
                        Ok(())
                    }));
                }
                assert_eq!(engine.length, 4096);
            }
            put(&mut image, 0x6020, 100);
            assert!(engine.advance_bounded(&mut |address, bytes| {
                assert!(address < 0x8000);
                let start = address as usize;
                bytes.copy_from_slice(&image[start..start + bytes.len()]);
                Ok(())
            }));
            assert_eq!(status(&engine), Status::Binding as u32);
            assert_eq!(engine.response().unwrap().len(), 68);
            assert!(engine.binding.is_none());
            assert!(engine.data.iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn bounded_calls_do_not_reset_phase_or_request_limits() {
        let image = four_level_image();
        let mut engine =
            pending(Operation::Physical, &[BatchRange { address: 0x8000, length: 4096 }], &image);
        engine.steps = MAX_SERVICE_STEPS - 2;
        let mut calls = 0;
        assert!(engine.advance_bounded(&mut |_, bytes| {
            calls += 1;
            bytes.fill(0xaa);
            Ok(())
        }));
        assert_eq!(calls, 2);
        assert_eq!(status(&engine), Status::Read as u32);
        assert!(engine.data.iter().all(|byte| *byte == 0));
        for (count, length) in [(1, 4097), (MAX_RANGES + 1, 1)] {
            let mut engine = BatchEngine::new();
            hello(&mut engine);
            let mut request = request(Operation::Physical, 2);
            request.count = count;
            request.ranges.fill(BatchRange { address: 0x8000, length });
            assert_eq!(engine.begin(request, 7, config()), Err(Status::Shape));
            assert!(!engine.advance_bounded(&mut |_, _| panic!("refused request must not read")));
        }
    }

    #[test]
    fn batch_revalidates_and_reads_across_pages_in_bounded_slices() {
        let image = image();
        let mut engine = BatchEngine::new();
        hello(&mut engine);
        let token = bind(&mut engine, &image);
        engine.begin(sample(token), 7, config()).unwrap();
        let mut slices = 0;
        while !advance(&mut engine, &image) {
            slices += 1;
            assert!(slices < 32);
        }
        assert!(slices > 16);
        assert_eq!(status(&engine), Status::Success as u32);
        assert_eq!(&engine.response().unwrap()[64..4160], &[0xa5; 4096]);
    }

    #[test]
    fn post_validation_discards_data_and_invalidates_binding() {
        let mut image = image();
        let mut engine = BatchEngine::new();
        hello(&mut engine);
        let token = bind(&mut engine, &image);
        engine.begin(sample(token), 7, config()).unwrap();
        while engine.phase != BatchPhase::After {
            assert!(!advance(&mut engine, &image));
        }
        put(&mut image, 0x6020, 100);
        assert!(advance(&mut engine, &image));
        assert_eq!(status(&engine), Status::Binding as u32);
        assert_eq!(engine.response().unwrap().len(), 68);
        assert!(engine.data.iter().all(|byte| *byte == 0));
        assert!(engine.binding.is_none());
    }

    #[test]
    fn refuses_replays_wrong_sessions_and_partial_physical_failures() {
        let mut engine = BatchEngine::new();
        hello(&mut engine);
        let mut request = request(Operation::Physical, 2);
        request.count = 1;
        request.ranges[0] = BatchRange { address: 0x8000, length: 512 };
        engine.begin(request, 7, config()).unwrap();
        assert!(!engine.advance(&mut |_, bytes| {
            bytes.fill(0xee);
            Ok(())
        }));
        assert!(engine.advance(&mut |_, bytes| {
            bytes.fill(0xaa);
            Err(PagingError::PhysicalRead)
        }));
        assert_eq!(status(&engine), Status::Read as u32);
        assert_eq!(engine.response().unwrap().len(), 68);
        engine.reset_response();
        engine.begin(request, 7, config()).unwrap();
        assert_eq!(status(&engine), Status::Sequence as u32);
        engine.reset_response();
        request.sequence = 3;
        request.session = 2;
        engine.begin(request, 7, config()).unwrap();
        assert_eq!(status(&engine), Status::Identity as u32);
    }

    #[test]
    fn identity_change_before_sample_never_reads_target_data() {
        let mut image = image();
        let mut engine = BatchEngine::new();
        hello(&mut engine);
        let token = bind(&mut engine, &image);
        put(&mut image, 0x6018, 0x4000);
        engine.begin(sample(token), 7, config()).unwrap();
        assert!(engine.advance(&mut |address, bytes| {
            assert!(address < 0x8000);
            bytes.copy_from_slice(&image[address as usize..address as usize + bytes.len()]);
            Ok(())
        }));
        assert_eq!(status(&engine), Status::Binding as u32);
        assert!(engine.binding.is_none());
    }

    #[test]
    fn every_range_page_split_stays_within_total_service_bound() {
        let image = image();
        let mut engine = BatchEngine::new();
        hello(&mut engine);
        let token = bind(&mut engine, &image);
        let mut request = sample(token);
        request.count = MAX_RANGES;
        request.ranges.fill(BatchRange { address: 0x8fff, length: 512 });
        engine.begin(request, 7, config()).unwrap();
        let mut steps = 1;
        while !advance(&mut engine, &image) {
            steps += 1;
            assert!(steps <= MAX_SERVICE_STEPS);
        }
        assert_eq!(status(&engine), Status::Success as u32);
        assert_eq!(steps, 26);
    }

    #[test]
    fn boot_change_and_clear_require_a_new_session_handshake() {
        let mut engine = BatchEngine::new();
        hello(&mut engine);
        let mut request = request(Operation::Physical, 2);
        request.count = 1;
        request.ranges[0] = BatchRange { address: 0x8000, length: 1 };
        request.boot = 8;
        engine.begin(request, 8, config()).unwrap();
        assert_eq!(status(&engine), Status::Identity as u32);
        engine.clear();
        assert!(engine.response().is_none());
        assert!(engine.binding.is_none());
        assert_eq!(engine.session, 0);
    }

    #[test]
    fn binding_requires_creation_time_offset_but_accepts_zero_timestamp() {
        let mut image = image();
        let mut engine = BatchEngine::new();
        hello(&mut engine);
        let mut request = request(Operation::Bind, 2);
        request.binding = BindingEvidence {
            kernel_root: 0x1000,
            target_root: 0x1000,
            pid: 42,
            object: 0x6000,
            creation: 0,
            object_bytes: 64,
            links_offset: 0,
            pid_offset: 16,
            root_offset: 24,
            creation_offset: u32::MAX,
            root_mask: 0,
        };
        engine.begin(request, 7, config()).unwrap();
        assert_eq!(status(&engine), Status::Binding as u32);
        assert!(engine.binding.is_none());
        engine.reset_response();
        request.sequence = 3;
        request.binding.creation_offset = 32;
        put(&mut image, 0x6020, 0);
        engine.begin(request, 7, config()).unwrap();
        assert!(advance(&mut engine, &image));
        assert_eq!(status(&engine), Status::Success as u32);
    }

    #[test]
    fn direct_request_with_excess_ranges_is_rejected_before_encoding() {
        let mut engine = BatchEngine::new();
        let mut request = request(Operation::Physical, 1);
        request.count = usize::MAX;
        assert_eq!(engine.begin(request, 7, config()), Err(Status::Shape));
        assert!(engine.response().is_none());
    }

    #[test]
    fn explain_returns_exact_walk_evidence_in_three_opportunities_without_target_reads() {
        for (kind, address, count) in [
            (0, 0x8123, 4),
            (1, 0x8123, 4),
            (2, 0x8123, 3),
            (3, 0x8123, 2),
            (4, 0x0000_8000_0000_0000, 0),
            (5, 0x8123, 4),
            (6, u64::MAX, 1),
        ] {
            let mut image = four_level_image();
            match kind {
                1 => put(&mut image, 0x4040, 0x1234_5000),
                2 => put(&mut image, 0x3000, 0x83),
                3 => put(&mut image, 0x2000, 0x83),
                5 => put(&mut image, 0x4040, (1 << 48) | 0x8003),
                _ => {}
            }
            let mut engine =
                pending(Operation::Explain, &[BatchRange { address, length: 1 }], &image);
            let token = engine.binding.unwrap().token;
            let calls = finish_traced(&mut engine, &image, true, None);
            assert_eq!(calls.len(), 3);
            assert_eq!(engine.steps, 3);
            assert_eq!(calls[1].len(), count);
            assert!(calls.iter().flatten().all(|(pa, _)| *pa < 0x8000));
            assert_eq!(status(&engine), Status::Success as u32);
            let response = engine.response().unwrap();
            assert_eq!(response.len(), 64 + diagnostic::BYTES + 4);
            assert_eq!(u64::from_le_bytes(response[32..40].try_into().unwrap()), token);
            let observation = DiagnosticObservation::decode(&response[64..160]).unwrap();
            assert_eq!(observation.root, 0x1000);
            assert_eq!(observation.address, address);
            assert_eq!(observation.physical_bits, 48);
            assert!(observation.nxe && observation.page_1g);
            assert_eq!(observation.count, count);
            for (entry, &(pa, length)) in observation.entries[..count].iter().zip(&calls[1]) {
                assert_eq!(length, 8);
                assert_eq!(entry.address, pa);
                assert_eq!(
                    entry.value,
                    u64::from_le_bytes(image[pa as usize..pa as usize + 8].try_into().unwrap())
                );
            }
            assert_eq!(observation.entries[count..], [DiagnosticEntry::EMPTY; 4][count..]);
        }
    }

    #[test]
    fn explain_pre_and_post_identity_changes_discard_evidence_and_token() {
        for before in [true, false] {
            for (offset, value) in [(0x6010, 43), (0x6018, 0x2000), (0x6020, 100), (0x6108, 0x6200)]
            {
                let mut image = four_level_image();
                let mut engine = pending(
                    Operation::Explain,
                    &[BatchRange { address: 0x8000, length: 1 }],
                    &image,
                );
                if !before {
                    assert!(!advance(&mut engine, &image));
                    assert!(!advance(&mut engine, &image));
                    assert_eq!(engine.length, diagnostic::BYTES);
                }
                put(&mut image, offset, value);
                assert!(advance(&mut engine, &image));
                assert_eq!(status(&engine), Status::Binding as u32);
                let response = engine.response().unwrap();
                assert_eq!(response.len(), 68);
                assert_eq!(&response[32..40], &[0; 8]);
                assert!(engine.binding.is_none());
                assert!(engine.data.iter().all(|byte| *byte == 0));
            }
        }
    }

    #[test]
    fn explain_physical_walk_failures_return_no_partial_evidence_or_extra_reads() {
        let image = four_level_image();
        for failed in 1..=4 {
            let mut engine =
                pending(Operation::Explain, &[BatchRange { address: 0x8000, length: 1 }], &image);
            let token = engine.binding.unwrap().token;
            assert!(!advance(&mut engine, &image));
            let mut calls = 0;
            assert!(engine.advance_bounded(&mut |pa, bytes| {
                calls += 1;
                if calls == failed {
                    bytes.fill(0xee);
                    return Err(PagingError::PhysicalRead);
                }
                bytes.copy_from_slice(&image[pa as usize..pa as usize + bytes.len()]);
                Ok(())
            }));
            assert_eq!(calls, failed);
            assert_eq!(status(&engine), Status::Read as u32);
            let response = engine.response().unwrap();
            assert_eq!(response.len(), 68);
            assert_eq!(u64::from_le_bytes(response[32..40].try_into().unwrap()), token);
            assert!(engine.data.iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn explain_metadata_physical_failures_are_transport_errors_and_discard_evidence() {
        let image = four_level_image();
        for phase in [BatchPhase::Before, BatchPhase::After] {
            let mut baseline =
                pending(Operation::Explain, &[BatchRange { address: 0x8000, length: 1 }], &image);
            let opportunities = finish_traced(&mut baseline, &image, true, None);
            let count = opportunities[if phase == BatchPhase::Before { 0 } else { 2 }].len();
            for failed in 1..=count {
                let mut engine = pending(
                    Operation::Explain,
                    &[BatchRange { address: 0x8000, length: 1 }],
                    &image,
                );
                while engine.phase != phase {
                    assert!(!advance(&mut engine, &image));
                }
                let mut calls = 0;
                assert!(engine.advance_bounded(&mut |pa, bytes| {
                    calls += 1;
                    if calls == failed {
                        bytes.fill(0xee);
                        return Err(PagingError::PhysicalRead);
                    }
                    bytes.copy_from_slice(&image[pa as usize..pa as usize + bytes.len()]);
                    Ok(())
                }));
                assert_eq!(calls, failed);
                assert_eq!(status(&engine), Status::Read as u32);
                assert_eq!(engine.response().unwrap().len(), 68);
                assert!(engine.binding.is_none());
                assert!(engine.data.iter().all(|byte| *byte == 0));
            }
        }
        let mut sample =
            pending(Operation::Sample, &[BatchRange { address: 0x8000, length: 1 }], &image);
        assert!(sample.advance(&mut |_, _| Err(PagingError::PhysicalRead)));
        assert_eq!(status(&sample), Status::Binding as u32);
    }

    #[test]
    fn explain_preserves_the_submitted_paging_width_and_feature_flags() {
        let image = four_level_image();
        for physical_bits in [32, 48, 52] {
            for (nxe, page_1g) in [(false, false), (true, false), (false, true), (true, true)] {
                let mut engine = BatchEngine::new();
                hello(&mut engine);
                let token = bind(&mut engine, &image);
                let mut request = request(Operation::Explain, 3);
                request.token = token;
                request.count = 1;
                request.ranges[0] = BatchRange { address: 0x8000, length: 1 };
                let config = PagingConfig::new(physical_bits, nxe, page_1g).unwrap();
                engine.begin(request, 7, config).unwrap();
                finish_traced(&mut engine, &image, true, None);
                assert_eq!(status(&engine), Status::Success as u32);
                let observation =
                    DiagnosticObservation::decode(&engine.response().unwrap()[64..160]).unwrap();
                assert_eq!(observation.physical_bits, physical_bits);
                assert_eq!(observation.nxe, nxe);
                assert_eq!(observation.page_1g, page_1g);
            }
        }
    }

    #[test]
    fn explain_preserves_sequence_binding_shape_and_service_limits() {
        let image = four_level_image();
        for (token, count, length) in [(0, 1, 1), (1, 0, 1), (1, 2, 1), (1, 1, 0), (1, 1, 2)] {
            let mut engine = BatchEngine::new();
            hello(&mut engine);
            bind(&mut engine, &image);
            let mut request = request(Operation::Explain, 3);
            request.token = token;
            request.count = count;
            request.ranges[0] = BatchRange { address: 0x8000, length };
            assert_eq!(engine.begin(request, 7, config()), Err(Status::Shape));
            assert!(!engine.advance(&mut |_, _| panic!("malformed request must not read")));
        }
        let mut engine = BatchEngine::new();
        hello(&mut engine);
        let token = bind(&mut engine, &image);
        let mut request = request(Operation::Explain, 3);
        request.token = token + 1;
        request.count = 1;
        request.ranges[0] = BatchRange { address: 0x8000, length: 1 };
        engine.begin(request, 7, config()).unwrap();
        assert_eq!(status(&engine), Status::Binding as u32);
        assert_eq!(&engine.response().unwrap()[32..40], &[0; 8]);
        assert!(engine.binding.is_none());
        for phase in [BatchPhase::Before, BatchPhase::Data, BatchPhase::After] {
            let mut engine = pending(Operation::Explain, &request.ranges[..1], &image);
            while engine.phase != phase {
                assert!(!advance(&mut engine, &image));
            }
            engine.steps = MAX_SERVICE_STEPS;
            assert!(engine.advance_bounded(&mut |_, _| panic!("exhausted service must not read")));
            assert_eq!(status(&engine), Status::Read as u32);
            assert_eq!(engine.response().unwrap().len(), 68);
            assert!(engine.data.iter().all(|byte| *byte == 0));
        }
        let mut engine = pending(Operation::Explain, &request.ranges[..1], &image);
        let request = engine.request.unwrap();
        finish_traced(&mut engine, &image, true, None);
        engine.reset_response();
        engine.begin(request, 7, config()).unwrap();
        assert_eq!(status(&engine), Status::Sequence as u32);
        let mut engine =
            pending(Operation::Sample, &[BatchRange { address: u64::MAX, length: 1 }], &image);
        finish_traced(&mut engine, &image, true, None);
        assert_eq!(status(&engine), Status::Read as u32);
    }
}
