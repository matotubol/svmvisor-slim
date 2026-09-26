//! Connection settings. The defaults suit an interactive program on a confirmed runtime boot.

use std::{path::PathBuf, time::Duration};

use svmvisor_hypervisor::reader::process::MAX_PROCESS_NODES;

#[derive(Clone, Debug)]
pub struct Config {
    pub(crate) kernel: PathBuf,
    pub(crate) pdb: PathBuf,
    pub(crate) cpu: u16,
    pub(crate) max_nodes: usize,
    pub(crate) max_calls: Option<u64>,
    pub(crate) session_timeout: Option<Duration>,
    pub(crate) response_timeout: Duration,
    pub(crate) open_timeout: Duration,
    pub(crate) read_timeout: Duration,
    pub(crate) context: Option<ManualContext>,
}

/// A caller-supplied kernel context, used instead of asking the runtime for one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ManualContext {
    pub kernel_root_pa: u64,
    pub list_head_va: u64,
    pub physical_bits: u8,
    pub nxe: bool,
    pub page_1g: bool,
}

impl Config {
    /// `kernel` and `pdb` must be the running Windows kernel's `ntoskrnl.exe` and its PDB.
    pub fn new(kernel: impl Into<PathBuf>, pdb: impl Into<PathBuf>) -> Self {
        Self {
            kernel: kernel.into(),
            pdb: pdb.into(),
            cpu: 0,
            max_nodes: MAX_PROCESS_NODES,
            max_calls: None,
            session_timeout: None,
            response_timeout: Duration::from_secs(5),
            open_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(10),
            context: None,
        }
    }

    /// Processor (group 0, 0..=31) the connecting thread is pinned to while connected.
    pub fn cpu(mut self, cpu: u16) -> Self {
        self.cpu = cpu;
        self
    }

    /// Most process-list entries one `open_process` or `list_processes` may walk.
    pub fn max_nodes(mut self, max_nodes: usize) -> Self {
        self.max_nodes = max_nodes;
        self
    }

    /// Most runtime requests one session may make; unlimited by default.
    pub fn max_calls(mut self, max_calls: u64) -> Self {
        self.max_calls = Some(max_calls);
        self
    }

    /// Ends the whole session after `timeout`; unlimited by default.
    pub fn session_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = Some(timeout);
        self
    }

    /// Longest wait for one runtime response.
    pub fn response_timeout(mut self, timeout: Duration) -> Self {
        self.response_timeout = timeout;
        self
    }

    /// Longest `open_process` or `list_processes`, including the first kernel context
    /// discovery.
    pub fn open_timeout(mut self, timeout: Duration) -> Self {
        self.open_timeout = timeout;
        self
    }

    /// Longest single read call, however many requests it is split into.
    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Use a known kernel root, `PsActiveProcessHead` address and paging mode instead of
    /// asking the runtime. Every value must match the running boot.
    #[doc(hidden)]
    pub fn manual_context(
        mut self,
        kernel_root_pa: u64,
        list_head_va: u64,
        physical_bits: u8,
        nxe: bool,
        page_1g: bool,
    ) -> Self {
        self.context =
            Some(ManualContext { kernel_root_pa, list_head_va, physical_bits, nxe, page_1g });
        self
    }
}
