//! The public API against the resident's own batch engine over an in-memory physical image.

use std::{cell::RefCell, rc::Rc, time::Instant};

use svmvisor_card_abi::batch::{BatchRequest, Operation, REQUEST_BYTES};
use svmvisor_hypervisor::reader::{batch::BatchEngine, paging::PagingConfig, paging::PagingError};

use crate::{
    Config, ErrorKind, ProcessEntry, ProcessHandle, Svm, profile::KernelProfile,
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
}

impl Exchange for EngineTransport {
    fn exchange(&mut self, bytes: &[u8; REQUEST_BYTES], _: Instant) -> Result<Vec<u8>, String> {
        let request = BatchRequest::decode(bytes).map_err(|error| format!("{error:?}"))?;
        self.operations.borrow_mut().push(request.operation);
        self.engine
            .begin(request, 7, PagingConfig::new(48, true, true).unwrap())
            .map_err(|error| format!("{error:?}"))?;
        while !self.engine.advance(&mut |address, output| {
            let memory = self.memory.borrow();
            let source = memory
                .get(address as usize..address as usize + output.len())
                .ok_or(PagingError::PhysicalRead)?;
            output.copy_from_slice(source);
            Ok(())
        }) {}
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
