use svmvisor_card_abi::batch::{
    BatchRange, BatchRequest, BindingEvidence, MAX_RANGES, Operation, Status,
};
use svmvisor_hypervisor::reader::{
    batch::{BatchEngine, MAX_SLICE_CALLS, SLICE_BYTES},
    paging::{PagingConfig, PagingError},
};

struct Fixture {
    engine: BatchEngine,
    image: Vec<u8>,
    sequence: u64,
    token: u64,
}

impl Fixture {
    fn new(object: u64, pid_offset: u32, creation_offset: u32) -> Self {
        let mut fixture =
            Self { engine: BatchEngine::new(), image: vec![0; 0x20000], sequence: 0, token: 0 };
        for (address, value) in [(0x1000, 0x2003), (0x2000, 0x3003), (0x3000, 0x4003)] {
            fixture.put(address, value);
        }
        for page in 0..32 {
            fixture.put(0x4000 + page * 8, page * 4096 | 3);
        }
        for (address, value) in [
            (object, 0x6800),
            (object + 8, 0x6900),
            (object + u64::from(pid_offset), 42),
            (object + 24, 0x1000),
            (object + u64::from(creation_offset), 99),
            (0x6808, object),
            (0x6900, object),
        ] {
            fixture.put(address, value);
        }
        fixture.image[0x8000..0xa000].fill(0xa5);
        let mut hello = fixture.request(Operation::Hello, &[]);
        hello.boot = 0;
        fixture.engine.begin(hello, 7, config()).unwrap();
        fixture.engine.reset_response();
        let mut bind = fixture.request(Operation::Bind, &[]);
        bind.binding = BindingEvidence {
            kernel_root: 0x1000,
            target_root: 0x1000,
            pid: 42,
            object,
            creation: 99,
            object_bytes: creation_offset.max(pid_offset).max(24) + 8,
            links_offset: 0,
            pid_offset,
            root_offset: 24,
            creation_offset,
            root_mask: 0,
        };
        fixture.engine.begin(bind, 7, config()).unwrap();
        fixture.finish();
        assert_eq!(fixture.status(), Status::Success as u32);
        fixture.token =
            u64::from_le_bytes(fixture.engine.response().unwrap()[32..40].try_into().unwrap());
        fixture.engine.reset_response();
        fixture
    }

    fn put(&mut self, address: u64, value: u64) {
        self.image[address as usize..][..8].copy_from_slice(&value.to_le_bytes());
    }

    fn request(&mut self, operation: Operation, ranges: &[(u64, u32)]) -> BatchRequest {
        self.sequence += 1;
        let mut request = BatchRequest {
            operation,
            session: 1,
            boot: 7,
            sequence: self.sequence,
            token: if operation == Operation::Sample { self.token } else { 0 },
            root_pa: if operation == Operation::Virtual { 0x1000 } else { 0 },
            paging: if operation == Operation::Virtual { 48 | (1 << 8) | (1 << 9) } else { 0 },
            count: ranges.len(),
            ranges: [BatchRange::EMPTY; MAX_RANGES],
            binding: BindingEvidence::EMPTY,
        };
        for (slot, &(address, length)) in request.ranges.iter_mut().zip(ranges) {
            *slot = BatchRange { address, length };
        }
        request
    }

    fn begin(&mut self, operation: Operation, ranges: &[(u64, u32)]) {
        self.engine.reset_response();
        let request = self.request(operation, ranges);
        self.engine.begin(request, 7, config()).unwrap();
    }

    fn finish(&mut self) -> Vec<usize> {
        let mut calls = Vec::new();
        loop {
            let mut count = 0;
            let complete = self.engine.advance_bounded(&mut |address, bytes| {
                count += 1;
                assert!(bytes.len() <= SLICE_BYTES);
                let source = self
                    .image
                    .get(address as usize..address as usize + bytes.len())
                    .ok_or(PagingError::PhysicalRead)?;
                bytes.copy_from_slice(source);
                Ok(())
            });
            assert!(count <= MAX_SLICE_CALLS);
            calls.push(count);
            assert!(calls.len() <= 34);
            if complete {
                return calls;
            }
        }
    }

    fn status(&self) -> u32 {
        u32::from_le_bytes(self.engine.response().unwrap()[40..44].try_into().unwrap())
    }
}

fn config() -> PagingConfig {
    PagingConfig::new(48, true, true).unwrap()
}

#[test]
fn small_samples_fit_both_validations_and_data_under_the_same_callback_ceiling() {
    for (ranges, callbacks, exits) in [
        (vec![(0x8000, 8)], 45, 1),
        (vec![(0x8000, 1024)], 60, 1),
        (vec![(0x8fff, 768)], 60, 1),
        (vec![(0x8000, 8); 4], 60, 1),
        (vec![(0x8000, 1025)], 65, 4),
        (vec![(0x8fff, 1024)], 65, 4),
        (vec![(0x8000, 8); 8], 80, 4),
        (vec![(0x8000, 4096)], 120, 6),
    ] {
        let mut fixture = Fixture::new(0x6000, 16, 32);
        fixture.begin(Operation::Sample, &ranges);
        let trace = fixture.finish();
        assert_eq!(trace.len(), exits, "{ranges:?}");
        assert_eq!(trace.iter().sum::<usize>(), callbacks);
        assert_eq!(fixture.status(), Status::Success as u32);
        let length = ranges.iter().map(|range| range.1 as usize).sum::<usize>();
        assert_eq!(&fixture.engine.response().unwrap()[64..64 + length], vec![0xa5; length]);
    }
}

#[test]
fn metadata_page_crossings_and_distant_fields_change_fast_path_admission() {
    for (object, pid, time, length, exits, callbacks) in [
        (0x6ff0, 16, 32, 512, 1, 60),
        (0x6ff0, 16, 32, 768, 3, 65),
        (0x6000, 16, 0x200, 512, 1, 60),
        (0x6000, 16, 0x200, 768, 3, 65),
        (0x6000, 0x100, 0x200, 8, 3, 65),
    ] {
        let mut fixture = Fixture::new(object, pid, time);
        fixture.begin(Operation::Sample, &[(0x8000, length)]);
        let trace = fixture.finish();
        assert_eq!(trace.len(), exits);
        assert_eq!(trace.iter().sum::<usize>(), callbacks);
        assert_eq!(fixture.status(), Status::Success as u32);
    }
}

#[test]
fn single_exit_samples_discard_data_when_identity_or_links_change_during_copy() {
    for changed in [0x6010, 0x6018, 0x6020, 0x6808, 0x6900] {
        let mut fixture = Fixture::new(0x6000, 16, 32);
        fixture.begin(Operation::Sample, &[(0x8000, 8)]);
        let mut copied = false;
        assert!(fixture.engine.advance_bounded(&mut |address, bytes| {
            bytes.copy_from_slice(&fixture.image[address as usize..][..bytes.len()]);
            if address == 0x8000 {
                copied = true;
                fixture.image[changed..][..8].fill(0);
            }
            Ok(())
        }));
        assert!(copied);
        assert_eq!(fixture.status(), Status::Binding as u32);
        assert_eq!(fixture.engine.response().unwrap().len(), 68);
        fixture.begin(Operation::Sample, &[(0x8000, 8)]);
        assert_eq!(fixture.status(), Status::Binding as u32);
    }
}

#[test]
fn virtual_reads_use_the_supplied_root_and_leave_the_process_binding_unchanged() {
    let mut fixture = Fixture::new(0x6000, 16, 32);
    for (address, value) in [(0x5000, 0xb003), (0xb000, 0xc003), (0xc000, 0xd003), (0xd040, 0xe003)]
    {
        fixture.put(address, value);
    }
    fixture.image[0xe000..0xe008].fill(0x5a);
    let mut request = fixture.request(Operation::Virtual, &[(0x8000, 8)]);
    request.root_pa = 0x5000;
    fixture.engine.begin(request, 7, config()).unwrap();
    assert_eq!(fixture.finish(), [5]);
    assert_eq!(&fixture.engine.response().unwrap()[64..72], &[0x5a; 8]);
    fixture.begin(Operation::Sample, &[(0x8000, 8)]);
    assert_eq!(fixture.finish(), [45]);
    assert_eq!(&fixture.engine.response().unwrap()[64..72], &[0xa5; 8]);
    // A second virtual read must walk the changed tables afresh.
    fixture.put(0x4040, 0xe003);
    fixture.begin(Operation::Virtual, &[(0x8000, 8)]);
    assert_eq!(fixture.finish(), [5]);
    assert_eq!(&fixture.engine.response().unwrap()[64..72], &[0x5a; 8]);
}

#[test]
fn virtual_translation_refusals_are_distinct_from_physical_failures_and_drop_partial_data() {
    for (entry, expected) in [(0, Status::Translation), (0x30003, Status::Read)] {
        let mut fixture = Fixture::new(0x6000, 16, 32);
        fixture.put(0x4048, entry);
        fixture.begin(Operation::Virtual, &[(0x8ff8, 16)]);
        fixture.finish();
        assert_eq!(fixture.status(), expected as u32);
        assert_eq!(fixture.engine.response().unwrap().len(), 68);
        fixture.begin(Operation::Sample, &[(0x8000, 8)]);
        fixture.finish();
        assert_eq!(fixture.status(), Status::Success as u32);
    }
}

#[test]
fn virtual_requests_reject_impossible_roots_modes_and_ranges_before_reading() {
    for (root, mode, address, host_config) in [
        (1 << 48, 48, 0x8000, config()),
        (0x1000, 49, 0x8000, config()),
        (0x1000, 48 | (1 << 8), 0x8000, PagingConfig::new(48, false, true).unwrap()),
        (0x1000, 48 | (1 << 9), 0x8000, PagingConfig::new(48, true, false).unwrap()),
        (0x1000, 48, 0x8000_0000_0000, config()),
        (0x1000, 48, 0x7fff_ffff_fffc, config()),
    ] {
        let mut fixture = Fixture::new(0x6000, 16, 32);
        let mut request = fixture.request(Operation::Virtual, &[(address, 8)]);
        request.root_pa = root;
        request.paging = mode;
        fixture.engine.begin(request, 7, host_config).unwrap();
        assert!(
            fixture.engine.advance_bounded(&mut |_, _| panic!("invalid request must not read"))
        );
        assert_eq!(fixture.status(), Status::Shape as u32);
    }
}
