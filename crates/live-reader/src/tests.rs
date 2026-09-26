//! The public API against the resident's own batch engine over an in-memory physical image.

use std::{cell::RefCell, rc::Rc, time::Instant};

use svmvisor_card_abi::batch::{BatchRequest, Operation, REQUEST_BYTES};
use svmvisor_hypervisor::reader::{batch::BatchEngine, paging::PagingConfig, paging::PagingError};

use crate::{
    Config, ErrorKind, Module, ProcessEntry, ProcessHandle, Svm, profile::KernelProfile,
    transport::Exchange,
};

const KERNEL_ROOT: u64 = 0x1000;
const LIST_HEAD: u64 = 0x3000;
const PROCESS_ROOT: u64 = 0x7000;
const EPROCESS: u64 = 0x10000;
const DATA: u64 = 0x20000;
const UNMAPPED: u64 = 0x4000_0000;
const PID: u32 = 42;
const CREATED: u64 = 123_456;

struct EngineTransport {
    engine: BatchEngine,
    memory: Rc<RefCell<Vec<u8>>>,
    operations: Rc<RefCell<Vec<Operation>>>,
    corrupt_sample: Rc<RefCell<bool>>,
    hypercalls: u64,
}

impl Exchange for EngineTransport {
    fn hypercalls(&self) -> Option<u64> {
        Some(self.hypercalls)
    }

    fn exchange(&mut self, bytes: &[u8; REQUEST_BYTES], _: Instant) -> Result<Vec<u8>, String> {
        let request = BatchRequest::decode(bytes).map_err(|error| format!("{error:?}"))?;
        self.operations.borrow_mut().push(request.operation);
        // Model the native SUBMIT, including immediate replies such as Hello. Each pending
        // bounded opportunity requires one more STEP. No actual VMMCALL runs in tests.
        self.hypercalls += 1;
        self.engine
            .begin(request, 7, PagingConfig::new(48, true, true).unwrap())
            .map_err(|error| format!("{error:?}"))?;
        while self.engine.response().is_none() {
            self.engine.advance_bounded(&mut |address, output| {
                let memory = self.memory.borrow();
                let source = memory
                    .get(address as usize..address as usize + output.len())
                    .ok_or(PagingError::PhysicalRead)?;
                output.copy_from_slice(source);
                Ok(())
            });
            if self.engine.response().is_none() {
                self.hypercalls += 1;
            }
        }
        let mut response = self.engine.response().unwrap().to_vec();
        self.engine.reset_response();
        if request.operation == Operation::Sample && *self.corrupt_sample.borrow() {
            response[16] ^= 1;
        }
        Ok(response)
    }
}

struct Fixture {
    svm: Svm,
    memory: Rc<RefCell<Vec<u8>>>,
    operations: Rc<RefCell<Vec<Operation>>>,
    corrupt_sample: Rc<RefCell<bool>>,
}

impl Fixture {
    /// Both roots map the first GiB of virtual memory onto physical memory one to one.
    fn new() -> Self {
        let profile = KernelProfile::fixture();
        let layout = profile.process().layout();
        let mut memory = vec![0; 0x40000];
        let links = EPROCESS + u64::from(layout.active_links_offset);
        for (address, word) in [
            (KERNEL_ROOT, 0x2001),
            (0x2000, 0x81),
            (PROCESS_ROOT, 0x8001),
            (0x8000, 0x81),
            (LIST_HEAD, links),
            (LIST_HEAD + 8, links),
            (links, LIST_HEAD),
            (links + 8, LIST_HEAD),
            (EPROCESS + u64::from(layout.pid_offset), u64::from(PID)),
            (EPROCESS + u64::from(layout.directory_root_offset), PROCESS_ROOT),
            (EPROCESS + u64::from(layout.create_time_offset.unwrap()), CREATED),
        ] {
            memory[address as usize..][..8].copy_from_slice(&word.to_le_bytes());
        }
        let name = EPROCESS as usize + profile.details().image_name as usize;
        memory[name..][..8].copy_from_slice(b"game.exe");
        for (index, byte) in memory[DATA as usize..].iter_mut().enumerate() {
            *byte = (index * 7 % 251) as u8;
        }
        let memory = Rc::new(RefCell::new(memory));
        let operations = Rc::new(RefCell::new(Vec::new()));
        let corrupt_sample = Rc::new(RefCell::new(false));
        let config = Config::new("kernel.exe", "kernel.pdb").max_nodes(4).manual_context(
            KERNEL_ROOT,
            LIST_HEAD,
            48,
            true,
            true,
        );
        let svm = Svm::with_transport(
            Box::new(EngineTransport {
                engine: BatchEngine::new(),
                memory: memory.clone(),
                operations: operations.clone(),
                corrupt_sample: corrupt_sample.clone(),
                hypercalls: 0,
            }),
            profile,
            config,
        )
        .unwrap();
        Self { svm, memory, operations, corrupt_sample }
    }

    fn expected(&self, address: u64, length: usize) -> Vec<u8> {
        self.memory.borrow()[address as usize..][..length].to_vec()
    }

    fn write(&self, address: u64, bytes: &[u8]) {
        self.memory.borrow_mut()[address as usize..][..bytes.len()].copy_from_slice(bytes);
    }

    fn samples_since(&self, start: usize) -> usize {
        self.operations.borrow()[start..].iter().filter(|&&op| op == Operation::Sample).count()
    }

    fn open(&mut self) -> ProcessHandle {
        self.svm.open_process(PID).unwrap()
    }

    /// Writes one eight-byte EPROCESS field; the next open reads it.
    fn set_field(&self, offset: u32, value: u64) {
        self.write(EPROCESS + u64::from(offset), &value.to_le_bytes());
    }
}

#[test]
fn bounded_sample_costs_cover_scalar_scattered_and_contiguous_reads() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.svm.calls(), 1);
    assert_eq!(fixture.svm.hypercalls(), Some(1)); // Hello; test transport has no probe.
    let handle = fixture.open();
    // Literal expected costs are independent of the engine's grouping constants:
    // each request pays before/after identity checks plus data service opportunities.
    for (count, spacing, length, expected_requests, expected_hypercalls) in [
        (1, 8, 8, 1, 3),
        (8, 256, 8, 1, 4),
        (8, 8, 8, 1, 3),
        (16, 256, 8, 2, 8),
        (16, 8, 8, 1, 3),
        (32, 256, 8, 4, 16),
        (32, 8, 8, 1, 3),
        (1, 4096, 4096, 1, 6),
        (1, 4096, 8192, 2, 12),
    ] {
        let mut buffers = vec![vec![0; length]; count];
        let mut reads: Vec<_> = buffers
            .iter_mut()
            .enumerate()
            .map(|(index, bytes)| (DATA + (index * spacing) as u64, bytes.as_mut_slice()))
            .collect();
        let calls = fixture.svm.calls();
        let hypercalls = fixture.svm.hypercalls().unwrap();
        fixture.svm.read_batch(handle, &mut reads).unwrap();
        assert_eq!(fixture.svm.calls() - calls, expected_requests);
        assert_eq!(fixture.svm.hypercalls().unwrap() - hypercalls, expected_hypercalls);
        for (index, buffer) in buffers.iter().enumerate() {
            assert_eq!(*buffer, fixture.expected(DATA + (index * spacing) as u64, length));
        }
    }
}

#[test]
fn later_request_failure_preserves_every_output_and_keeps_readable_binding() {
    let mut fixture = Fixture::new();
    let handle = fixture.open();
    let mut first = [0x55; 4096];
    let mut second = [0x66; 8];
    let calls = fixture.svm.calls();
    let error = fixture
        .svm
        .read_batch(handle, &mut [(DATA, &mut first), (UNMAPPED, &mut second)])
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unreadable);
    assert_eq!(fixture.svm.calls() - calls, 2);
    assert_eq!(first, [0x55; 4096]);
    assert_eq!(second, [0x66; 8]);
    fixture.svm.read_process_memory(handle, DATA, &mut second).unwrap();
    assert_eq!(second.as_slice(), fixture.expected(DATA, 8));
}

#[test]
fn subsequent_reads_revalidate_identity_and_never_reuse_previous_data() {
    let mut fixture = Fixture::new();
    let handle = fixture.open();
    let mut bytes = [0; 8];
    fixture.svm.read_process_memory(handle, DATA, &mut bytes).unwrap();
    fixture.write(DATA, &[0x91; 8]);
    fixture.svm.read_process_memory(handle, DATA, &mut bytes).unwrap();
    assert_eq!(bytes, [0x91; 8]);
    let creation = KernelProfile::fixture().process().layout().create_time_offset.unwrap();
    fixture.set_field(creation, CREATED + 1);
    let error = fixture.svm.read_process_memory(handle, DATA, &mut bytes).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ProcessGone);
    assert_eq!(bytes, [0x91; 8]);
    assert!(fixture.svm.is_connected());
    let calls = fixture.svm.calls();
    assert_eq!(
        fixture.svm.read_process_memory(handle, DATA, &mut bytes).unwrap_err().kind(),
        ErrorKind::InvalidHandle
    );
    assert_eq!(fixture.svm.calls(), calls);
}

#[test]
fn attach_refuses_a_pid_reused_since_the_listing() {
    let mut fixture = Fixture::new();
    let entry = ProcessEntry { pid: PID, name: "game.exe".into(), created: CREATED - 1 };
    assert_eq!(fixture.svm.attach(&entry).unwrap_err().kind(), ErrorKind::ProcessNotFound);
    assert!(fixture.svm.is_connected());
    let current = ProcessEntry { created: CREATED, ..entry };
    let handle = fixture.svm.attach(&current).unwrap();
    let mut bytes = [0; 8];
    fixture.svm.read_process_memory(handle, DATA, &mut bytes).unwrap();
    assert_eq!(bytes.as_slice(), fixture.expected(DATA, 8));
}

#[test]
fn corrupt_response_keeps_outputs_unchanged_and_ends_session_without_retry() {
    let mut fixture = Fixture::new();
    let handle = fixture.open();
    *fixture.corrupt_sample.borrow_mut() = true;
    let mut bytes = [0x55; 8];
    let start = fixture.operations.borrow().len();
    assert_eq!(
        fixture.svm.read_process_memory(handle, DATA, &mut bytes).unwrap_err().kind(),
        ErrorKind::SessionEnded
    );
    assert_eq!(bytes, [0x55; 8]);
    assert!(!fixture.svm.is_connected());
    assert_eq!(
        fixture.svm.read_process_memory(handle, DATA, &mut bytes).unwrap_err().kind(),
        ErrorKind::SessionEnded
    );
    assert_eq!(fixture.samples_since(start), 1);
}

#[test]
fn overflowing_module_offsets_send_nothing_and_preserve_output() {
    let mut fixture = Fixture::new();
    let handle = fixture.open();
    let module = Module { name: "bad.dll".into(), base: u64::MAX - 3, size: 0x1000 };
    let calls = fixture.svm.calls();
    let hypercalls = fixture.svm.hypercalls();
    let mut bytes = [0x55; 8];
    assert_eq!(
        fixture.svm.read_module(handle, &module, 8, &mut bytes).unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(bytes, [0x55; 8]);
    assert_eq!(fixture.svm.calls(), calls);
    assert_eq!(fixture.svm.hypercalls(), hypercalls);
    assert!(fixture.svm.is_connected());
}
