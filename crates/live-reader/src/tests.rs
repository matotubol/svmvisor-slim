//! The public API against the resident's own batch engine over an in-memory physical image.

use std::{
    cell::RefCell,
    rc::Rc,
    time::{Duration, Instant},
};

use svmvisor_card_abi::batch::{BatchRequest, Operation, REQUEST_BYTES};
use svmvisor_card_abi::local;
use svmvisor_hypervisor::reader::{
    batch::BatchEngine,
    paging::{PagingConfig, PagingError, PagingLevel},
};

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
    physical_mutation: Rc<RefCell<Option<PhysicalMutation>>>,
    hypercalls: u64,
    diagnostics: Rc<RefCell<bool>>,
}

#[derive(Clone, Copy)]
struct PhysicalMutation {
    trigger: u64,
    address: u64,
    value: u64,
}

impl Exchange for EngineTransport {
    fn hypercalls(&self) -> Option<u64> {
        Some(self.hypercalls)
    }

    fn capabilities(&mut self, _: u64, _: Instant) -> Result<u64, String> {
        self.hypercalls += 1;
        Ok(if *self.diagnostics.borrow() { local::CAP_DIAGNOSTIC } else { 0 })
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
                drop(memory);
                if request.operation == Operation::Explain {
                    let mutation = *self.physical_mutation.borrow();
                    if let Some(mutation) = mutation
                        && address == mutation.trigger
                    {
                        self.memory.borrow_mut()[mutation.address as usize..][..8]
                            .copy_from_slice(&mutation.value.to_le_bytes());
                        self.physical_mutation.borrow_mut().take();
                    }
                }
                Ok(())
            });
            if self.engine.response().is_none() {
                self.hypercalls += 1;
            }
        }
        let mut response = self.engine.response().unwrap().to_vec();
        self.engine.reset_response();
        if matches!(request.operation, Operation::Sample | Operation::Explain)
            && *self.corrupt_sample.borrow()
        {
            response[16] ^= 1;
        }
        if request.operation == Operation::Physical {
            let mutation = *self.physical_mutation.borrow();
            if let Some(mutation) = mutation
                && request.ranges[0].address == mutation.trigger
            {
                self.memory.borrow_mut()[mutation.address as usize..][..8]
                    .copy_from_slice(&mutation.value.to_le_bytes());
                self.physical_mutation.borrow_mut().take();
            }
        }
        Ok(response)
    }
}

struct Fixture {
    svm: Svm,
    memory: Rc<RefCell<Vec<u8>>>,
    operations: Rc<RefCell<Vec<Operation>>>,
    corrupt_sample: Rc<RefCell<bool>>,
    physical_mutation: Rc<RefCell<Option<PhysicalMutation>>>,
    diagnostics: Rc<RefCell<bool>>,
}

impl Fixture {
    /// Both roots map the first GiB of virtual memory onto physical memory one to one.
    fn new() -> Self {
        Self::with_read_timeout(Duration::from_secs(10))
    }

    fn with_read_timeout(timeout: Duration) -> Self {
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
        let physical_mutation = Rc::new(RefCell::new(None));
        let diagnostics = Rc::new(RefCell::new(false));
        let config = Config::new("kernel.exe", "kernel.pdb")
            .max_nodes(4)
            .read_timeout(timeout)
            .manual_context(KERNEL_ROOT, LIST_HEAD, 48, true, true);
        let svm = Svm::with_transport(
            Box::new(EngineTransport {
                engine: BatchEngine::new(),
                memory: memory.clone(),
                operations: operations.clone(),
                corrupt_sample: corrupt_sample.clone(),
                physical_mutation: physical_mutation.clone(),
                hypercalls: 0,
                diagnostics: diagnostics.clone(),
            }),
            profile,
            config,
        )
        .unwrap();
        Self { svm, memory, operations, corrupt_sample, physical_mutation, diagnostics }
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

#[test]
fn address_explanation_retains_root_raw_entries_and_large_page_result() {
    let mut fixture = Fixture::new();
    let handle = fixture.open();
    let before = fixture.memory.borrow().clone();
    let calls = fixture.svm.calls();
    let report = fixture.svm.explain_address(handle, DATA).unwrap();
    assert_eq!(report.pid, PID);
    assert_eq!(report.created, CREATED);
    assert_eq!(report.walk.root_pa, PROCESS_ROOT);
    assert_eq!(report.walk.va, DATA);
    assert_eq!(report.paging, PagingConfig::new(48, true, true).unwrap());
    let translation = report.walk.result.unwrap();
    assert_eq!(translation.pa(), DATA);
    assert_eq!(translation.page_bytes(), 1 << 30);
    let first = report.walk.entries[0].unwrap();
    assert_eq!(first.level, PagingLevel::Pml4);
    assert_eq!(first.table_pa, PROCESS_ROOT);
    assert_eq!(first.entry_pa, PROCESS_ROOT);
    assert_eq!(first.raw, Some(0x8001));
    let last = report.walk.entries[1].unwrap();
    assert_eq!(last.level, PagingLevel::Pdpt);
    assert_eq!(last.raw, Some(0x81));
    assert!(report.walk.entries[2..].iter().all(Option::is_none));
    assert!(fixture.svm.calls() - calls <= 124);
    assert_eq!(*fixture.memory.borrow(), before);
}

#[test]
fn resident_diagnostics_match_fallback_with_three_opportunities_and_one_lazy_query() {
    let mut legacy = Fixture::new();
    let mut resident = Fixture::new();
    *resident.diagnostics.borrow_mut() = true;
    let legacy_handle = legacy.open();
    let resident_handle = resident.open();
    let unchanged = resident.memory.borrow().clone();
    for (index, address) in [DATA, UNMAPPED, DATA + 17].into_iter().enumerate() {
        let calls = resident.svm.calls();
        let exits = resident.svm.hypercalls().unwrap();
        let operations = resident.operations.borrow().len();
        let expected = legacy.svm.explain_address(legacy_handle, address).unwrap();
        assert_eq!(resident.svm.explain_address(resident_handle, address).unwrap(), expected);
        assert_eq!(resident.svm.calls() - calls, if index == 0 { 2 } else { 1 });
        assert_eq!(resident.svm.hypercalls().unwrap() - exits, if index == 0 { 4 } else { 3 });
        assert_eq!(&resident.operations.borrow()[operations..], &[Operation::Explain]);
    }
    assert!(!legacy.operations.borrow().contains(&Operation::Explain));
    assert_eq!(*resident.memory.borrow(), unchanged);
    let calls = resident.svm.calls();
    let exits = resident.svm.hypercalls().unwrap();
    resident.svm.read_process_memory(resident_handle, DATA, &mut [0; 8]).unwrap();
    assert_eq!(resident.svm.calls() - calls, 1);
    assert_eq!(resident.svm.hypercalls().unwrap() - exits, 3);
}

#[test]
fn resident_diagnostics_discard_identity_changes_before_or_during_the_walk() {
    let creation = KernelProfile::fixture().process().layout().create_time_offset.unwrap();
    for during in [false, true] {
        let mut fixture = Fixture::new();
        *fixture.diagnostics.borrow_mut() = true;
        let handle = fixture.open();
        if during {
            *fixture.physical_mutation.borrow_mut() = Some(PhysicalMutation {
                trigger: 0x8000,
                address: EPROCESS + u64::from(creation),
                value: CREATED + 1,
            });
        } else {
            fixture.set_field(creation, CREATED + 1);
        }
        assert_eq!(
            fixture.svm.explain_address(handle, DATA).unwrap_err().kind(),
            ErrorKind::ProcessGone
        );
        assert!(fixture.svm.is_connected());
        let calls = fixture.svm.calls();
        assert_eq!(
            fixture.svm.explain_address(handle, DATA).unwrap_err().kind(),
            ErrorKind::InvalidHandle
        );
        assert_eq!(fixture.svm.calls(), calls);
    }
}

#[test]
fn resident_diagnostic_physical_or_framing_failures_end_the_session_without_fallback() {
    for framing in [false, true] {
        let mut fixture = Fixture::new();
        *fixture.diagnostics.borrow_mut() = true;
        let handle = fixture.open();
        if framing {
            *fixture.corrupt_sample.borrow_mut() = true;
        } else {
            fixture.write(PROCESS_ROOT, &0x90001u64.to_le_bytes());
        }
        let operations = fixture.operations.borrow().len();
        assert_eq!(
            fixture.svm.explain_address(handle, DATA).unwrap_err().kind(),
            ErrorKind::SessionEnded
        );
        assert_eq!(&fixture.operations.borrow()[operations..], &[Operation::Explain]);
        assert!(!fixture.svm.is_connected());
        let calls = fixture.svm.calls();
        assert_eq!(
            fixture.svm.explain_address(handle, DATA).unwrap_err().kind(),
            ErrorKind::SessionEnded
        );
        assert_eq!(fixture.svm.calls(), calls);
    }
}

#[test]
fn address_explanation_nonpresent_is_data_and_keeps_binding_usable() {
    let mut fixture = Fixture::new();
    let handle = fixture.open();
    fixture.write(0x8008, &(u64::MAX - 1).to_le_bytes());
    let report = fixture.svm.explain_address(handle, UNMAPPED).unwrap();
    assert_eq!(report.walk.result, Err(PagingError::NotPresent));
    let last = report.walk.entries[1].unwrap();
    assert_eq!(last.level, PagingLevel::Pdpt);
    assert_eq!(last.entry_pa, 0x8008);
    assert_eq!(last.raw, Some(u64::MAX - 1));
    let mut bytes = [0; 8];
    fixture.svm.read_process_memory(handle, DATA, &mut bytes).unwrap();
    assert_eq!(bytes.as_slice(), fixture.expected(DATA, 8));
    assert!(fixture.svm.is_connected());
}

#[test]
fn address_explanation_invalid_address_or_handle_sends_nothing() {
    let mut fixture = Fixture::new();
    let handle = fixture.open();
    let calls = fixture.svm.calls();
    assert_eq!(fixture.svm.process_created(handle).unwrap(), CREATED);
    assert_eq!(
        fixture.svm.explain_address(handle, 0x0000_8000_0000_0000).unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    fixture.svm.close_handle(handle);
    assert_eq!(
        fixture.svm.explain_address(handle, DATA).unwrap_err().kind(),
        ErrorKind::InvalidHandle
    );
    assert_eq!(fixture.svm.calls(), calls);
}

#[test]
fn address_explanation_rejects_identity_changes_before_and_after_the_walk() {
    let creation = KernelProfile::fixture().process().layout().create_time_offset.unwrap();
    for during in [false, true] {
        let mut fixture = Fixture::new();
        let handle = fixture.open();
        if during {
            *fixture.physical_mutation.borrow_mut() = Some(PhysicalMutation {
                trigger: 0x8000,
                address: EPROCESS + u64::from(creation),
                value: CREATED + 1,
            });
        } else {
            fixture.set_field(creation, CREATED + 1);
        }
        assert_eq!(
            fixture.svm.explain_address(handle, DATA).unwrap_err().kind(),
            ErrorKind::ProcessGone
        );
        assert!(fixture.svm.is_connected());
        let calls = fixture.svm.calls();
        assert_eq!(
            fixture.svm.explain_address(handle, DATA).unwrap_err().kind(),
            ErrorKind::InvalidHandle
        );
        assert_eq!(fixture.svm.calls(), calls);
    }
}

#[test]
fn address_explanation_physical_failure_ends_session_without_retry() {
    let mut fixture = Fixture::new();
    let handle = fixture.open();
    fixture.write(PROCESS_ROOT, &0x90001u64.to_le_bytes());
    assert_eq!(
        fixture.svm.explain_address(handle, DATA).unwrap_err().kind(),
        ErrorKind::SessionEnded
    );
    assert!(!fixture.svm.is_connected());
    let calls = fixture.svm.calls();
    assert_eq!(
        fixture.svm.explain_address(handle, DATA).unwrap_err().kind(),
        ErrorKind::SessionEnded
    );
    assert_eq!(fixture.svm.calls(), calls);
}

#[test]
fn address_explanation_obeys_the_read_deadline_before_reading_physical_memory() {
    let mut fixture = Fixture::with_read_timeout(Duration::ZERO);
    let handle = fixture.open();
    let calls = fixture.svm.calls();
    assert_eq!(
        fixture.svm.explain_address(handle, DATA).unwrap_err().kind(),
        ErrorKind::SessionEnded
    );
    assert_eq!(fixture.svm.calls(), calls);
    assert!(!fixture.svm.is_connected());
}

#[test]
fn bounded_read_deadline_sends_nothing_when_already_expired() {
    let mut fixture = Fixture::new();
    let handle = fixture.open();
    let calls = fixture.svm.calls();
    let mut bytes = [0x55; 8];
    assert_eq!(
        fixture
            .svm
            .read_process_memory_bounded(handle, DATA, &mut bytes, Duration::ZERO)
            .unwrap_err()
            .kind(),
        ErrorKind::SessionEnded
    );
    assert_eq!(fixture.svm.calls(), calls);
    assert_eq!(bytes, [0x55; 8]);
    assert!(!fixture.svm.is_connected());
}

#[test]
fn terminal_phase_errors_cannot_be_cleared_by_reopening_a_process() {
    let mut fixture = Fixture::with_read_timeout(Duration::MAX);
    let handle = fixture.open();
    let calls = fixture.svm.calls();
    let mut bytes = [0x55; 8];
    assert_eq!(
        fixture.svm.read_process_memory(handle, DATA, &mut bytes).unwrap_err().kind(),
        ErrorKind::SessionEnded
    );
    assert_eq!(bytes, [0x55; 8]);
    assert!(!fixture.svm.is_connected());
    assert_eq!(fixture.svm.open_process(PID).unwrap_err().kind(), ErrorKind::SessionEnded);
    assert_eq!(fixture.svm.calls(), calls);
}

#[test]
fn batching_reduces_modeled_exits_and_next_tick_reads_fresh_unchanged_target() {
    let mut fixture = Fixture::new();
    let handle = fixture.open();
    let before = fixture.memory.borrow().clone();
    let mut scalar = [[0; 8]; 8];
    let start = fixture.svm.hypercalls().unwrap();
    for (index, bytes) in scalar.iter_mut().enumerate() {
        fixture.svm.read_process_memory(handle, DATA + index as u64 * 256, bytes).unwrap();
    }
    assert_eq!(fixture.svm.hypercalls().unwrap() - start, 24);
    let mut batch = [[0; 8]; 8];
    let start = fixture.svm.hypercalls().unwrap();
    let mut ranges: Vec<_> = batch
        .iter_mut()
        .enumerate()
        .map(|(index, bytes)| (DATA + index as u64 * 256, bytes.as_mut_slice()))
        .collect();
    fixture.svm.read_batch(handle, &mut ranges).unwrap();
    assert_eq!(fixture.svm.hypercalls().unwrap() - start, 4);
    assert_eq!(batch, scalar);
    assert_eq!(*fixture.memory.borrow(), before);

    fixture.write(DATA, &[0x92; 8]);
    let changed = fixture.memory.borrow().clone();
    let mut ranges: Vec<_> = batch
        .iter_mut()
        .enumerate()
        .map(|(index, bytes)| (DATA + index as u64 * 256, bytes.as_mut_slice()))
        .collect();
    fixture.svm.read_batch(handle, &mut ranges).unwrap();
    assert_eq!(batch[0], [0x92; 8]);
    assert_eq!(*fixture.memory.borrow(), changed);
}
