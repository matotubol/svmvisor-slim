//! Retained reader API and offline batch-engine validation.
//!
//! Live access is disabled while the authenticated interface is being designed.
//! The legacy guest transport has been removed. [`Svm::connect`] is safe and always returns
//! [`ErrorKind::ReaderDisabled`] before checking profiles or making any native call.
//!
//! ```
//! use svmvisor_live_reader::{Config, ErrorKind, Svm};
//! let config = Config::new("ntoskrnl.exe", "ntkrnlmp.pdb");
//! let error = Svm::connect(config).err().expect("live reading is disabled");
//! assert_eq!(error.kind(), ErrorKind::ReaderDisabled);
//! ```
//!
//! Existing read types and methods remain for source compatibility and in-memory regression
//! tests. They do not provide an alternate connection or an authentication mechanism.

#![forbid(unsafe_code)]

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
