//! Read another Windows process's memory through the resident svmvisor runtime, with calls
//! shaped like `OpenProcess` and `ReadProcessMemory`. No driver and no process handle with
//! read rights is involved; each read is one VMMCALL session served by the hypervisor.
//!
//! ```no_run
//! use svmvisor_live_reader::{Config, Svm};
//!
//! # fn main() -> Result<(), svmvisor_live_reader::Error> {
//! let config = Config::new("target/kernel-analysis/ntoskrnl.exe", "target/kernel-analysis/ntkrnlmp.pdb");
//! // SAFETY: this boot runs the redesigned svmvisor runtime.
//! let mut svm = unsafe { Svm::connect(config)? };
//! let entry = svm
//!     .list_processes()?
//!     .into_iter()
//!     .find(|process| process.name.eq_ignore_ascii_case("malware.exe"))
//!     .expect("malware.exe is running");
//! let malware = svm.attach(&entry)?;
//!
//! let client = svm.module(malware, "client.dll")?.expect("client.dll is loaded");
//! let something: u32 = svm.read_module_value(malware, &client, 0x2040)?;
//! let exe = svm.main_module(malware)?.expect("the loader lists the executable");
//! let something2: [f32; 3] = svm.read(malware, exe.base + 0x2100)?;
//!
//! let mut name = [0u8; 32];
//! let mut flags = [0u8; 4];
//! svm.read_batch(malware, &mut [(client.base + 0x3000, &mut name), (client.base + 0x3100, &mut flags)])?;
//! # Ok(())
//! # }
//! ```
//!
//! A connection belongs to the thread that made it: that thread is pinned to one CPU while the
//! connection lives, and `Svm` is neither `Send` nor `Sync`. Errors say what is still usable;
//! see [`ErrorKind`].
//!
//! Windows is never asked for anything: the process list is the kernel's own, walked through
//! the runtime, and no process is opened through Windows. The PEB address and bitness come
//! from the process's kernel object, and every byte of target memory, including the loader's
//! module list, comes from the runtime.

mod binding;
mod bridge;
mod config;
mod context;
mod error;
mod modules;
mod pack;
mod plain;
mod process;
pub mod profile;
mod svm;
mod transport;

pub use self::{
    config::Config,
    error::{Error, ErrorKind, Result},
    modules::Module,
    plain::Plain,
    process::ProcessEntry,
    svm::{KernelContext, ProcessHandle, Svm},
};

/// Most ranges one runtime request carries. `read_batch` splits larger batches; a batch within
/// this and [`MAX_REQUEST_BYTES`] is one identity-checked observation.
pub const MAX_REQUEST_RANGES: usize = svmvisor_card_abi::batch::MAX_RANGES;
/// Most bytes one runtime request returns.
pub const MAX_REQUEST_BYTES: usize = svmvisor_card_abi::batch::MAX_DATA_BYTES;

#[cfg(test)]
mod tests;
