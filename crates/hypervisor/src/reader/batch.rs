//! Transport-independent process batches, bounded to one phase per service opportunity.
//! Identity checks are observations, not page pins or atomic snapshots.

use svmvisor_card_abi::batch::{
    self, BatchRequest, MAX_DATA_BYTES, MAX_RANGES, MAX_RESPONSE_BYTES, Operation, Status,
};

use crate::{
    memory::address::is_canonical_48,
    reader::{
        paging::{self, PagingConfig, PagingError},
        process::{self, ProcessLayoutEvidence, ProcessObservation, ProcessProfile},
    },
};

pub const SLICE_BYTES: usize = 256;
/// Six metadata ranges, at most two pages and five physical callbacks per page.
pub const MAX_SLICE_CALLS: usize = 60;
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
            Operation::Sample => {
                if self.binding.is_none_or(|binding| binding.token != request.token) {
                    self.finish(Status::Binding);
                    return Ok(());
                }
                for range in &request.ranges[..request.count] {
                    let end = range.address + u64::from(range.length) - 1;
                    if !is_canonical_48(range.address) || !is_canonical_48(end) {
                        self.finish(Status::Shape);
                        return Ok(());
                    }
                }
                BatchPhase::Before
            }
        };
        Ok(())
    }

    /// Each call performs one metadata validation or one <=256-byte page fragment.
    /// The callback budget is enforced even if a future validator grows more expensive.
    pub fn advance(
        &mut self,
        read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), PagingError>,
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
        let mut calls = 0;
        let mut bounded = |address, bytes: &mut [u8]| {
            if calls == MAX_SLICE_CALLS || bytes.len() > SLICE_BYTES {
                return Err(PagingError::PhysicalRead);
            }
            calls += 1;
            read(address, bytes)
        };
        match self.phase {
            BatchPhase::Before | BatchPhase::After => {
                let Some(binding) = self.binding else {
                    self.finish(Status::Binding);
                    return true;
                };
                if process::revalidate(
                    config,
                    binding.profile,
                    binding.kernel_root,
                    binding.observation,
                    &mut bounded,
                )
                .is_err()
                {
                    self.binding = None;
                    self.finish(Status::Binding);
                } else if self.phase == BatchPhase::After || request.operation == Operation::Bind {
                    self.finish(Status::Success);
                } else {
                    self.phase = BatchPhase::Data;
                }
            }
            BatchPhase::Data => {
                let range = request.ranges[self.range];
                let address = range.address + self.offset as u64;
                let count = SLICE_BYTES
                    .min(range.length as usize - self.offset)
                    .min(4096 - (address as usize & 4095));
                let physical = if request.operation == Operation::Sample {
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
                } else {
                    address
                };
                if bounded(physical, &mut self.data[self.length..self.length + count]).is_err() {
                    self.finish(Status::Read);
                    return true;
                }
                self.length += count;
                self.offset += count;
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
    use super::*;
    use svmvisor_card_abi::batch::{BatchRange, BindingEvidence};

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
}
