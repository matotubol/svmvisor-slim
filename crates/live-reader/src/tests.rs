//! The public API against the resident's own batch engine over an in-memory physical image.

use std::{cell::RefCell, rc::Rc, time::Instant};

use svmvisor_card_abi::batch::{BatchRequest, Operation, REQUEST_BYTES};
use svmvisor_hypervisor::reader::{batch::BatchEngine, paging::PagingConfig, paging::PagingError};

use crate::{
    Config, ErrorKind, ProcessEntry, ProcessHandle, Svm,
    profile::KernelProfile,
    transport::{
        Exchange,
        testing::{Reply, Work, complete},
    },
};

const KERNEL_ROOT: u64 = 0x1000;
const LIST_HEAD: u64 = 0x3000;
const PROCESS_ROOT: u64 = 0x7000;
const EPROCESS: u64 = 0x10000;
const DATA: u64 = 0x20000;
const UNMAPPED: u64 = 0x4000_0000;
const PID: u32 = 42;
const CREATED: u64 = 123_456;

#[test]
fn live_connect_is_disabled_before_profile_validation_or_runtime_work() {
    for config in [
        Config::new("missing/ntoskrnl.exe", "missing/ntkrnlmp.pdb"),
        Config::new("", "").cpu(u16::MAX).max_nodes(0).max_calls(0),
        Config::new("", "").manual_context(0, 0, 0, false, false),
    ] {
        let error = Svm::connect(config).err().expect("live connection must remain disabled");
        assert_eq!(error.kind(), ErrorKind::ReaderDisabled);
        assert!(error.message().contains("legacy guest interface is retired"));
        assert!(error.message().contains("authenticated reader is not available"));
    }
}

struct EngineTransport {
    engine: BatchEngine,
    memory: Rc<RefCell<Vec<u8>>>,
    operations: Rc<RefCell<Vec<Operation>>>,
    exits: Rc<RefCell<Vec<Work>>>,
    corrupt_sample: Rc<RefCell<bool>>,
}

impl Exchange for EngineTransport {
    fn exchange(
        &mut self,
        bytes: &[u8; REQUEST_BYTES],
        deadline: Instant,
    ) -> Result<Vec<u8>, String> {
        let request = BatchRequest::decode(bytes).map_err(|error| format!("{error:?}"))?;
        self.operations.borrow_mut().push(request.operation);
        complete(deadline, |operation| {
            self.exits.borrow_mut().push(operation);
            if operation == Work::Submit {
                self.engine.begin(request, 7, PagingConfig::new(48, true, true).unwrap()).unwrap();
            } else {
                assert_eq!(operation, Work::Step);
            }
            self.engine.advance_bounded(&mut |address, output| {
                let memory = self.memory.borrow();
                let source = memory
                    .get(address as usize..address as usize + output.len())
                    .ok_or(PagingError::PhysicalRead)?;
                output.copy_from_slice(source);
                Ok(())
            });
            match self.engine.response() {
                Some(response) => Reply::Complete(response.len()),
                None => Reply::Pending,
            }
        })?;
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
    exits: Rc<RefCell<Vec<Work>>>,
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
        let exits = Rc::new(RefCell::new(Vec::new()));
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
                exits: exits.clone(),
                corrupt_sample: corrupt_sample.clone(),
            }),
            profile,
            config,
        )
        .unwrap();
        Self { svm, memory, operations, exits, corrupt_sample }
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

    fn four_level_kernel(&self) {
        self.write(0x2000, &0x4001u64.to_le_bytes());
        self.write(0x4000, &0x5001u64.to_le_bytes());
        for page in 0..64 {
            self.write(0x5000 + page * 8, &(page * 4096 | 1).to_le_bytes());
        }
    }

    fn chain(&self, entries: &[(u64, u32, &str)]) {
        let profile = KernelProfile::fixture();
        let layout = profile.process().layout();
        let template = self.expected(EPROCESS, layout.eprocess_bytes as usize);
        let links = |index: usize| entries[index].0 + u64::from(layout.active_links_offset);
        for (index, &(address, pid, name)) in entries.iter().enumerate() {
            let mut bytes = template.clone();
            let previous = if index == 0 { LIST_HEAD } else { links(index - 1) };
            let next = if index + 1 == entries.len() { LIST_HEAD } else { links(index + 1) };
            for (offset, value) in [
                (layout.active_links_offset, next),
                (layout.active_links_offset + 8, previous),
                (layout.pid_offset, u64::from(pid)),
                (profile.details().peb, DATA),
                (profile.details().create_time, CREATED + index as u64),
            ] {
                bytes[offset as usize..][..8].copy_from_slice(&value.to_le_bytes());
            }
            let short_name = &mut bytes[profile.details().image_name as usize..][..15];
            short_name.fill(0);
            short_name[..name.len()].copy_from_slice(name.as_bytes());
            self.write(address, &bytes);
        }
        let first = if entries.is_empty() { LIST_HEAD } else { links(0) };
        let last = if entries.is_empty() { LIST_HEAD } else { links(entries.len() - 1) };
        self.write(LIST_HEAD, &first.to_le_bytes());
        self.write(LIST_HEAD + 8, &last.to_le_bytes());
    }
}

#[test]
fn listing_reads_each_eprocess_once_with_fresh_translations_on_every_call() {
    let mut fixture = Fixture::new();
    fixture.four_level_kernel();
    fixture.chain(&[(EPROCESS, PID, "game.exe")]);
    for created in [CREATED, CREATED + 1] {
        fixture.set_field(KernelProfile::fixture().details().create_time, created);
        let start = fixture.svm.calls();
        let exits = fixture.exits.borrow().len();
        assert_eq!(
            fixture.svm.list_processes().unwrap(),
            [ProcessEntry { pid: PID, name: "game.exe".into(), created }],
        );
        // Each virtual request includes translation and data in one SUBMIT.
        assert_eq!(fixture.svm.calls() - start, 2);
        assert_eq!(&fixture.exits.borrow()[exits..], &[Work::Submit; 2]);
    }
}

#[test]
fn opening_coalesces_list_fields_and_samples_still_revalidate_identity() {
    let mut fixture = Fixture::new();
    fixture.four_level_kernel();
    let start = fixture.svm.calls();
    let exits = fixture.exits.borrow().len();
    let handle = fixture.open();
    assert_eq!(fixture.svm.calls() - start, 6);
    assert_eq!(&fixture.exits.borrow()[exits..], &[Work::Submit; 6]);
    let start = fixture.operations.borrow().len();
    let exits = fixture.exits.borrow().len();
    let mut output = [0; 8];
    fixture.svm.read_process_memory(handle, DATA, &mut output).unwrap();
    assert_eq!(output.as_slice(), fixture.expected(DATA, 8));
    assert_eq!(fixture.samples_since(start), 1);
    assert_eq!(&fixture.exits.borrow()[exits..], &[Work::Submit]);

    fixture.set_field(KernelProfile::fixture().details().create_time, CREATED + 1);
    let before = output;
    let error = fixture.svm.read_process_memory(handle, DATA, &mut output).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ProcessGone);
    assert_eq!(output, before);
    assert!(fixture.svm.is_connected());
}

#[test]
fn sample_submit_and_step_counts_match_the_bounded_resident_path() {
    let mut fixture = Fixture::new();
    fixture.four_level_kernel();
    let handle = fixture.open();
    for (length, steps) in [(8, 0), (1024, 0), (1025, 3), (4096, 5)] {
        let start = fixture.exits.borrow().len();
        let mut output = vec![0; length];
        fixture.svm.read_process_memory(handle, DATA, &mut output).unwrap();
        assert_eq!(output, fixture.expected(DATA, length));
        let mut expected = vec![Work::Submit];
        expected.extend(vec![Work::Step; steps]);
        assert_eq!(&fixture.exits.borrow()[start..], expected);
    }
}

#[test]
fn listing_combines_fields_across_noncontiguous_pages_and_skips_missing_metadata() {
    for mapping in [0x30001u64, 0, 0x50001] {
        let mut fixture = Fixture::new();
        fixture.four_level_kernel();
        // PID/links are on page 0x10000, while the image name is on page 0x11000.
        fixture.chain(&[(0x10cf0, PID, "game.exe"), (0x12000, 84, "other.exe")]);
        let page = fixture.expected(0x11000, 4096);
        fixture.write(0x30000, &page);
        fixture.write(0x5088, &mapping.to_le_bytes());
        let listed = fixture.svm.list_processes();
        if mapping == 0x50001 {
            // The required prefix succeeded, but the optional page's physical copy failed.
            // That transport refusal must not become a successful partial listing.
            assert_eq!(listed.unwrap_err().kind(), ErrorKind::SessionEnded);
            assert!(!fixture.svm.is_connected());
            continue;
        }
        let entries = listed.unwrap();
        let expected = ProcessEntry { pid: 84, name: "other.exe".into(), created: CREATED + 1 };
        if mapping != 0 {
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].name, "game.exe");
            assert_eq!(entries[1], expected);
        } else {
            assert_eq!(entries, [expected]);
        }
        assert!(fixture.svm.is_connected());
    }
}

#[test]
fn listing_rejects_corrupt_tail_and_missing_required_fields_without_partial_results() {
    for corrupt in [true, false] {
        let mut fixture = Fixture::new();
        fixture.four_level_kernel();
        fixture.chain(&[(EPROCESS, PID, "game.exe"), (0x12000, 84, "other.exe")]);
        // Resolving this name would poison the transport. Validate the complete list first.
        fixture.set_field(KernelProfile::fixture().details().audit_name, 0x50000);
        if corrupt {
            let first = EPROCESS
                + u64::from(KernelProfile::fixture().process().layout().active_links_offset);
            fixture.write(LIST_HEAD + 8, &first.to_le_bytes());
        } else {
            fixture.write(0x5090, &0u64.to_le_bytes());
        }
        assert_eq!(fixture.svm.list_processes().unwrap_err().kind(), ErrorKind::Discovery);
    }
}

#[test]
fn listing_keeps_full_names_and_case_insensitive_name_then_pid_order() {
    let mut fixture = Fixture::new();
    fixture.chain(&[(EPROCESS, 84, "short.exe"), (0x12000, PID, "ALPHA.exe")]);
    let path: Vec<u8> =
        "\\Device\\Volume\\alpha.exe".encode_utf16().flat_map(u16::to_le_bytes).collect();
    fixture.set_field(KernelProfile::fixture().details().audit_name, 0x14000);
    fixture.write(0x14000, &(path.len() as u16).to_le_bytes());
    fixture.write(0x14008, &0x15000u64.to_le_bytes());
    fixture.write(0x15000, &path);
    let entries = fixture.svm.list_processes().unwrap();
    assert_eq!(entries.iter().map(|entry| entry.pid).collect::<Vec<_>>(), [PID, 84]);
    assert_eq!(entries[1].name, "alpha.exe");
}

#[test]
fn listing_omits_kernel_processes_and_attach_refuses_reused_pids() {
    let mut fixture = Fixture::new();
    assert!(fixture.svm.list_processes().unwrap().is_empty());
    fixture.set_field(KernelProfile::fixture().details().peb, DATA);
    let entry = fixture.svm.list_processes().unwrap().remove(0);
    fixture.set_field(KernelProfile::fixture().details().create_time, CREATED + 1);
    assert_eq!(fixture.svm.attach(&entry).unwrap_err().kind(), ErrorKind::ProcessNotFound);
}

#[test]
fn listing_does_not_hide_fatal_backend_errors_in_optional_metadata() {
    let mut fixture = Fixture::new();
    fixture.chain(&[(EPROCESS, PID, "game.exe")]);
    // A mapped audit-name pointer beyond physical backing makes the resident refuse the copy.
    fixture.set_field(KernelProfile::fixture().details().audit_name, 0x50000);
    assert_eq!(fixture.svm.list_processes().unwrap_err().kind(), ErrorKind::SessionEnded);
    assert!(!fixture.svm.is_connected());
}

#[test]
fn unreadable_sample_keeps_the_binding_and_output_unchanged() {
    let mut fixture = Fixture::new();
    let handle = fixture.open();
    let mut output = [0xaa; 8];
    assert_eq!(
        fixture.svm.read_process_memory(handle, UNMAPPED, &mut output).unwrap_err().kind(),
        ErrorKind::Unreadable,
    );
    assert_eq!(output, [0xaa; 8]);
    fixture.svm.read_process_memory(handle, DATA, &mut output).unwrap();
    *fixture.corrupt_sample.borrow_mut() = true;
    let before = output;
    assert_eq!(
        fixture.svm.read_process_memory(handle, DATA, &mut output).unwrap_err().kind(),
        ErrorKind::SessionEnded,
    );
    assert_eq!(output, before);
}
