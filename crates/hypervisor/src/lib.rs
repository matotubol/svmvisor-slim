//! Bare-metal AMD SVM hypervisor core.
//!
//! Architecture primitives, boot contracts, guest and host state, memory, and
//! SVM exit handling live in separate namespaces, for example `svm::dispatch`,
//! `guest::state`, `memory::address` or `boot::memory`. The `firmware` module
//! owns UEFI boot and is excluded from the freestanding resident target.
//! The `reader` module provides bounded memory reads and process discovery.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod arch;
pub mod boot;
pub mod guest;
pub mod host;
pub mod memory;
pub mod svm;
pub mod sync;

#[cfg(not(target_os = "none"))]
pub mod firmware;
pub mod reader;
