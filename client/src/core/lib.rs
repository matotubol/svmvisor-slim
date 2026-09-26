//! The svmvisor desktop client's core: connect to the runtime, pick a process in a window, and
//! read it through [`Process`] or at the [`console`] prompt. `main.rs` holds the reading; this
//! library does not change for it.

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
