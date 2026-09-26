//! The connection to the resident runtime and the process handles it hands out.

use svmvisor_hypervisor::reader::{paging::PagingConfig, process::ProcessRequest};

#[cfg(test)]
use svmvisor_hypervisor::reader::process::MAX_PROCESS_NODES;

use crate::{
    binding::{self, Bound},
    bridge::{Failure, ReadBridge},
    config::Config,
    context,
    error::{Error, ErrorKind, Result},
    modules::{self, Module},
    pack,
    plain::Plain,
    process::{self, Details, ProcessEntry},
    profile::KernelProfile,
};

/// A local identifier for a resident process binding. Closing it or opening another process
/// invalidates it. Samples recheck the process identity; this does not hold a Windows object
/// reference or keep the process or its address space alive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcessHandle {
    pid: u32,
    serial: u64,
}

impl ProcessHandle {
    pub fn pid(self) -> u32 {
        self.pid
    }
}

/// The running kernel as found by the first `open_process`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelContext {
    /// Kernel image base, when it was discovered rather than supplied.
    pub kernel_base: Option<u64>,
    /// Physical address of the System process's top-level page table.
    pub kernel_root: u64,
    /// Virtual address of `PsActiveProcessHead`.
    pub process_list: u64,
}

#[derive(Clone, Copy)]
struct Resolved {
    paging: PagingConfig,
    kernel: KernelContext,
}

struct Open {
    handle: ProcessHandle,
    token: u64,
    created: u64,
    details: Details,
}

/// Retained reader API; live connections are currently disabled.
///
/// [`connect`](Self::connect) always returns [`ErrorKind::ReaderDisabled`]. The methods below
/// remain available for source compatibility and are exercised by in-memory tests.
///
/// The runtime keeps one bound process per connection, so opening a process closes the handle
/// opened before it. Reads are best-effort observations of a running process: each runtime
/// request checks the process identity before and after copying, but the values may change
/// while it copies.
pub struct Svm {
    bridge: ReadBridge,
    profile: KernelProfile,
    config: Config,
    context: Option<Resolved>,
    open: Option<Open>,
    serial: u64,
}

impl Svm {
    /// Returns [`ErrorKind::ReaderDisabled`] without opening files or contacting the runtime.
    ///
    /// The legacy guest interface has been retired. An authenticated replacement is not yet
    /// available, and no configuration value enables a fallback. This function is safe:
    /// it performs no native allocation, affinity change, or hypercall.
    pub fn connect(_config: Config) -> Result<Self> {
        Err(Error::new(
            ErrorKind::ReaderDisabled,
            "live reader is disabled: the legacy guest interface is retired and the authenticated reader is not available",
        ))
    }

    #[cfg(test)]
    fn with_bridge(
        bridge: ReadBridge,
        profile: KernelProfile,
        config: Config,
        paging: Option<PagingConfig>,
    ) -> Self {
        let context = config.context.zip(paging).map(|(manual, paging)| Resolved {
            paging,
            kernel: KernelContext {
                kernel_base: None,
                kernel_root: manual.kernel_root_pa,
                process_list: manual.list_head_va,
            },
        });
        Self { bridge, profile, config, context, open: None, serial: 0 }
    }

    /// Every user-mode process (every one with a PEB) in the kernel's process list, sorted by
    /// name then PID. The first call also discovers the kernel context. An open handle stays
    /// open.
    ///
    /// Names come from the full image path the kernel recorded when each process started, or
    /// from the short `ImageFileName` when there is none. PID, links and metadata share one
    /// field-range read per process; full names require two additional pointer-following reads.
    pub fn list_processes(&mut self) -> Result<Vec<ProcessEntry>> {
        self.alive()?;
        self.bridge.begin_phase("list", self.config.open_timeout).map_err(|m| self.ended(m))?;
        let context = self.resolved()?;
        let listed = process::list(
            context.paging,
            &self.profile,
            context.kernel.kernel_root,
            context.kernel.process_list,
            self.config.max_nodes,
            &mut self.bridge,
        )
        .map_err(|message| self.discovery(message))?;
        self.bridge.finish_phase().map_err(|m| self.ended(m))?;
        Ok(listed)
    }

    /// Opens a process picked from [`list_processes`](Self::list_processes), refusing it if its
    /// PID now belongs to a process created later. Otherwise like
    /// [`open_process`](Self::open_process).
    pub fn attach(&mut self, process: &ProcessEntry) -> Result<ProcessHandle> {
        let handle = self.open_process(process.pid)?;
        if !self.open.as_ref().is_some_and(|open| open.created == process.created) {
            self.open = None;
            return Err(Error::new(
                ErrorKind::ProcessNotFound,
                format!(
                    "PID {} is no longer {}; list the processes again",
                    process.pid, process.name
                ),
            ));
        }
        Ok(handle)
    }

    /// Like `OpenProcess`: finds `pid` in the kernel's process list and binds it. The first call
    /// also discovers the kernel context. Any handle opened earlier is closed.
    ///
    /// Windows is not asked for a handle. The PEB address and bitness the module calls need are
    /// read from the process's kernel object after discovery. The runtime compares PID,
    /// creation time, root and links before and after each sample to detect identity changes.
    /// These checks are best-effort observations; they do not pin the object or its pages.
    pub fn open_process(&mut self, pid: u32) -> Result<ProcessHandle> {
        self.alive()?;
        if pid == 0 {
            return Err(Error::new(ErrorKind::InvalidArgument, "PID 0 is not a process"));
        }
        self.open = None;
        self.bridge.begin_phase("open", self.config.open_timeout).map_err(|m| self.ended(m))?;
        let context = self.resolved()?;
        let request = ProcessRequest {
            kernel_root_pa: context.kernel.kernel_root,
            list_head_va: context.kernel.process_list,
            pid: u64::from(pid),
            max_nodes: self.config.max_nodes,
        };
        let found = binding::discover(context.paging, &self.profile, request, &mut self.bridge)
            .map_err(|message| self.discovery(message))?;
        self.bridge.finish_phase().map_err(|m| self.ended(m))?;
        let Bound { token, created, details } = found
            .ok_or_else(|| Error::new(ErrorKind::ProcessNotFound, format!("PID {pid} absent")))?;
        self.serial += 1;
        let handle = ProcessHandle { pid, serial: self.serial };
        self.open = Some(Open { handle, token, created, details });
        Ok(handle)
    }

    /// Like `CloseHandle`. Closing a handle that is no longer open does nothing.
    pub fn close_handle(&mut self, handle: ProcessHandle) {
        if self.open.as_ref().is_some_and(|open| open.handle == handle) {
            self.open = None;
        }
    }

    /// Like `ReadProcessMemory`: fills `buffer` from `address`. Any length is accepted; long
    /// reads take one runtime request per 4096 bytes. On error `buffer` is unchanged.
    pub fn read_process_memory(
        &mut self,
        handle: ProcessHandle,
        address: u64,
        buffer: &mut [u8],
    ) -> Result<()> {
        self.read_batch(handle, &mut [(address, buffer)])
    }

    /// Reads one little-endian value, such as `u32`, `f32`, `u64` pointers or `[f32; 3]`.
    pub fn read<T: Plain>(&mut self, handle: ProcessHandle, address: u64) -> Result<T> {
        let mut bytes = vec![0; T::SIZE];
        self.read_process_memory(handle, address, &mut bytes)?;
        Ok(T::from_le_bytes(&bytes))
    }

    /// Fills every `(address, buffer)` pair, packing up to eight ranges and 4096 bytes into each
    /// runtime request. Batching unrelated reads is much faster than reading them one at a time.
    /// On error no buffer is changed.
    pub fn read_batch(
        &mut self,
        handle: ProcessHandle,
        reads: &mut [(u64, &mut [u8])],
    ) -> Result<()> {
        let token = self.opened(handle)?.token;
        let shape: Vec<_> =
            reads.iter().map(|(address, buffer)| (*address, buffer.len())).collect();
        let requests = pack::plan(&shape)
            .map_err(|message| Error::new(ErrorKind::InvalidArgument, message))?;
        if requests.is_empty() {
            return Ok(());
        }
        self.bridge.begin_phase("read", self.config.read_timeout).map_err(|m| self.ended(m))?;
        let mut staged: Vec<Vec<u8>> = shape.iter().map(|&(_, length)| vec![0; length]).collect();
        for request in &requests {
            let ranges: Vec<_> = request.iter().map(|piece| piece.range).collect();
            let bytes = self.bridge.sample(token, &ranges).map_err(|failure| match failure {
                Failure::Unreadable => Error::new(
                    ErrorKind::Unreadable,
                    format!("PID {}: a requested address is not readable", handle.pid),
                ),
                Failure::Unbound => {
                    self.open = None;
                    Error::new(
                        ErrorKind::ProcessGone,
                        format!("PID {} exited or changed identity", handle.pid),
                    )
                }
                Failure::Fatal(message) => self.ended(message),
            })?;
            let mut bytes = bytes.as_slice();
            for piece in request {
                let (part, rest) = bytes.split_at(piece.range.length as usize);
                staged[piece.read][piece.offset..][..part.len()].copy_from_slice(part);
                bytes = rest;
            }
        }
        self.bridge.finish_phase().map_err(|m| self.ended(m))?;
        for ((_, buffer), bytes) in reads.iter_mut().zip(staged) {
            buffer.copy_from_slice(&bytes);
        }
        Ok(())
    }

    /// Every module the loader lists, in load order: the executable first, then its DLLs.
    ///
    /// Each entry costs a runtime request or two, so keep the list rather than calling this
    /// before every read. A module unlinked from the loader's list is not included.
    pub fn modules(&mut self, handle: ProcessHandle) -> Result<Vec<Module>> {
        let peb = self.peb(handle)?;
        modules::list(peb, &mut |address, buffer| self.read_process_memory(handle, address, buffer))
    }

    /// The module named `name`, such as `client.dll`, ignoring ASCII case. Only the entries
    /// whose names have the same length are read in full.
    pub fn module(&mut self, handle: ProcessHandle, name: &str) -> Result<Option<Module>> {
        let peb = self.peb(handle)?;
        modules::find(peb, name, &mut |address, buffer| {
            self.read_process_memory(handle, address, buffer)
        })
    }

    /// The executable's own module, the first the loader lists.
    pub fn main_module(&mut self, handle: ProcessHandle) -> Result<Option<Module>> {
        let peb = self.peb(handle)?;
        modules::first(peb, &mut |address, buffer| {
            self.read_process_memory(handle, address, buffer)
        })
    }

    /// Fills `buffer` from `offset` bytes into `module`. The whole range must lie inside the
    /// image; otherwise nothing is sent and the error is `InvalidArgument`.
    pub fn read_module(
        &mut self,
        handle: ProcessHandle,
        module: &Module,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<()> {
        if !module.contains(offset, buffer.len()) {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                format!(
                    "{}+0x{offset:X} ({} bytes) is outside its 0x{:X}-byte image",
                    module.name,
                    buffer.len(),
                    module.size
                ),
            ));
        }
        self.read_process_memory(handle, module.base + offset, buffer)
    }

    /// Reads one little-endian value `offset` bytes into `module`; see [`read`](Self::read).
    pub fn read_module_value<T: Plain>(
        &mut self,
        handle: ProcessHandle,
        module: &Module,
        offset: u64,
    ) -> Result<T> {
        let mut bytes = vec![0; T::SIZE];
        self.read_module(handle, module, offset, &mut bytes)?;
        Ok(T::from_le_bytes(&bytes))
    }

    /// The kernel context, once the first `open_process` has found it.
    pub fn kernel_context(&self) -> Option<KernelContext> {
        self.context.map(|context| context.kernel)
    }

    /// Logical runtime requests made so far, including discovery. Continuation VM exits
    /// are part of the same request and are not counted separately.
    pub fn calls(&self) -> u64 {
        self.bridge.calls()
    }

    /// False once the session has failed; every later call returns `SessionEnded`.
    pub fn is_connected(&self) -> bool {
        !self.bridge.failed()
    }

    /// The kernel context, discovered on first use.
    fn resolved(&mut self) -> Result<Resolved> {
        if let Some(context) = self.context {
            return Ok(context);
        }
        let context = self.discover_context()?;
        self.context = Some(context);
        Ok(context)
    }

    fn discover_context(&mut self) -> Result<Resolved> {
        let observation = self.bridge.context().map_err(|message| self.discovery(message))?;
        let candidate = context::candidate(observation)
            .map_err(|message| Error::new(ErrorKind::Discovery, message))?;
        let mut backend_error = None;
        let bridge = &mut self.bridge;
        let validated = context::discover(
            &self.profile,
            &[candidate],
            self.config.max_nodes,
            &mut process::memory(bridge, &mut backend_error),
        );
        let validated = validated.map_err(|error| {
            self.discovery(format!("automatic context failed: {error}; backend={backend_error:?}"))
        })?;
        Ok(Resolved {
            paging: validated.config(),
            kernel: KernelContext {
                kernel_base: Some(validated.kernel_base_va()),
                kernel_root: validated.kernel_root_pa(),
                process_list: validated.list_head_va(),
            },
        })
    }

    fn opened(&mut self, handle: ProcessHandle) -> Result<&mut Open> {
        self.alive()?;
        self.open.as_mut().filter(|open| open.handle == handle).ok_or_else(|| {
            Error::new(ErrorKind::InvalidHandle, "process handle is closed or was replaced")
        })
    }

    /// The PEB address, read from the process's kernel object when it was opened.
    fn peb(&mut self, handle: ProcessHandle) -> Result<u64> {
        let details = self.opened(handle)?.details;
        let refused = |reason: &str| {
            Err(Error::new(ErrorKind::Unreadable, format!("PID {}: {reason}", handle.pid)))
        };
        if details.wow64 {
            return refused(
                "32-bit processes keep a separate module list; only 64-bit is supported",
            );
        }
        if details.peb == 0 {
            return refused("the process has no PEB, so it has no module list");
        }
        Ok(details.peb)
    }

    fn alive(&self) -> Result<()> {
        if self.bridge.failed() {
            return Err(Error::new(
                ErrorKind::SessionEnded,
                "session already failed; connect again",
            ));
        }
        Ok(())
    }

    fn ended(&mut self, message: impl Into<String>) -> Error {
        self.open = None;
        Error::new(ErrorKind::SessionEnded, message)
    }

    /// Discovery errors leave the session usable unless the transport itself failed.
    fn discovery(&mut self, message: String) -> Error {
        if self.bridge.failed() {
            self.ended(message)
        } else {
            Error::new(ErrorKind::Discovery, message)
        }
    }
}

#[cfg(test)]
fn check(config: &Config) -> Result<Option<PagingConfig>> {
    let invalid = |message: &str| Error::new(ErrorKind::InvalidArgument, message);
    if config.cpu >= 32 {
        return Err(invalid("CPU must be 0..=31 in processor group 0"));
    }
    if config.max_nodes == 0 || config.max_nodes > MAX_PROCESS_NODES {
        return Err(invalid("max_nodes must be 1..=4096"));
    }
    if config.max_calls == Some(0) {
        return Err(invalid("max_calls must be nonzero"));
    }
    config
        .context
        .map(|manual| {
            PagingConfig::new(manual.physical_bits, manual.nxe, manual.page_1g)
                .map_err(|_| invalid("manual context physical width must be 32..=52"))
        })
        .transpose()
}

#[cfg(test)]
impl Svm {
    pub(crate) fn with_transport(
        transport: Box<dyn crate::transport::Exchange>,
        profile: KernelProfile,
        config: Config,
    ) -> Result<Self> {
        let paging = check(&config)?;
        let bridge = ReadBridge::with_transport(
            transport,
            11,
            config.max_calls.unwrap_or(u64::MAX),
            config.session_timeout,
            config.response_timeout,
        )
        .map_err(|message| Error::new(ErrorKind::Connect, message))?;
        Ok(Self::with_bridge(bridge, profile, config, paging))
    }
}
