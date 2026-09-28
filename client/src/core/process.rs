//! One open process on its own runtime connection, read without passing handles around.

use svmvisor_live_reader::{
    AddressExplanation, Module, Plain, ProcessEntry, ProcessHandle, Result, Svm,
    capture::{self, CaptureLimits, CaptureObservation, CaptureRegion},
};

/// A process opened on a connection that it owns. Every read goes through the runtime, never
/// through Windows.
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let Some(mut process) = svmvisor_client::pick(svmvisor_client::config())? else {
///     return Ok(());
/// };
/// let client = process.module("client.dll")?.ok_or("client.dll is not loaded")?;
/// let health: u32 = process.read_module(&client, 0x40)?;
/// let position: [f32; 3] = process.read(client.base + 0x1000)?;
/// let header = process.read_module_bytes(&client, 0, 0x200)?;
/// # Ok(())
/// # }
/// ```
pub struct Process {
    svm: Svm,
    handle: ProcessHandle,
    entry: ProcessEntry,
}

impl Process {
    /// Opens `entry` on `svm`, refusing a PID reused since the listing; see [`Svm::attach`].
    pub fn new(mut svm: Svm, entry: ProcessEntry) -> Result<Self> {
        let handle = svm.attach(&entry)?;
        Ok(Self { svm, handle, entry })
    }

    pub fn pid(&self) -> u32 {
        self.entry.pid
    }

    /// The executable file name, such as `game.exe`.
    pub fn name(&self) -> &str {
        &self.entry.name
    }

    /// The handle for calls made on [`svm`](Self::svm) directly.
    pub fn handle(&self) -> ProcessHandle {
        self.handle
    }

    /// The connection, for library calls this type does not wrap.
    pub fn svm(&mut self) -> &mut Svm {
        &mut self.svm
    }

    /// False once the session has failed; every later read fails too.
    pub fn is_connected(&self) -> bool {
        self.svm.is_connected()
    }

    // Memory.

    /// Reads one little-endian value, such as `u32`, `f32`, a `u64` pointer or `[f32; 3]`.
    pub fn read<T: Plain>(&mut self, address: u64) -> Result<T> {
        self.svm.read(self.handle, address)
    }

    /// Reads `length` bytes from `address`.
    pub fn read_bytes(&mut self, address: u64, length: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0; length];
        self.read_into(address, &mut bytes)?;
        Ok(bytes)
    }

    /// Fills `bytes` from `address`. On error `bytes` is unchanged.
    pub fn read_into(&mut self, address: u64, bytes: &mut [u8]) -> Result<()> {
        self.svm.read_process_memory(self.handle, address, bytes)
    }

    /// Fills every `(address, bytes)` pair, eight ranges and 4096 bytes per runtime request.
    /// Batching unrelated reads is much faster than reading them one at a time.
    pub fn read_batch(&mut self, reads: &mut [(u64, &mut [u8])]) -> Result<()> {
        self.svm.read_batch(self.handle, reads)
    }

    /// Captures bounded page fragments, retaining unreadable spans as explicit evidence.
    pub fn capture(
        &mut self,
        regions: &[CaptureRegion],
        limits: CaptureLimits,
    ) -> Result<CaptureObservation> {
        capture::read(&mut self.svm, self.handle, regions, limits)
    }

    /// Returns the page-table entries and exact reason a translation stopped.
    pub fn explain_address(&mut self, address: u64) -> Result<AddressExplanation> {
        self.svm.explain_address(self.handle, address)
    }

    // Modules.

    /// Every loaded module in load order, the executable first. Each entry costs a runtime
    /// request or two, so keep the list rather than asking again before every read.
    pub fn modules(&mut self) -> Result<Vec<Module>> {
        self.svm.modules(self.handle)
    }

    /// The module named `name`, such as `client.dll`, ignoring ASCII case.
    pub fn module(&mut self, name: &str) -> Result<Option<Module>> {
        self.svm.module(self.handle, name)
    }

    /// The executable's own module.
    pub fn main_module(&mut self) -> Result<Option<Module>> {
        self.svm.main_module(self.handle)
    }

    /// Reads one value `offset` bytes into `module`, which must hold all of it.
    pub fn read_module<T: Plain>(&mut self, module: &Module, offset: u64) -> Result<T> {
        self.svm.read_module_value(self.handle, module, offset)
    }

    /// Reads `length` bytes from `offset` bytes into `module`, which must hold all of them.
    pub fn read_module_bytes(
        &mut self,
        module: &Module,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>> {
        let mut bytes = vec![0; length];
        self.svm.read_module(self.handle, module, offset, &mut bytes)?;
        Ok(bytes)
    }
}
