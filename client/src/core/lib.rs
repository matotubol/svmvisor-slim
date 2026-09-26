//! Windows client library core: process picker, process wrapper, and console helpers.
//!
//! Live access is currently disabled. [`connect`] returns [`ErrorKind::ReaderDisabled`],
//! and [`pick`] displays that error in its existing window. No executable frontend is included.
//! The same-PC authenticated replacement still requires an established isolation boundary;
//! this ordinary Windows library does not hold authorization keys or implement that boundary.

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("svmvisor-client needs 64-bit Windows: its picker is a Win32 window.");

pub use svmvisor_live_reader::{
    Config, Error, ErrorKind, Module, Plain, ProcessEntry, ProcessHandle, Result, Svm,
};

pub use self::{
    picker::pick,
    process::Process,
    runtime::{config, connect},
};

pub mod console;
mod picker;
mod process;
mod runtime;
