//! One error type for every public call, classified by what the caller can still do.

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

/// What failed, and so what remains usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Live reading is disabled. No profile was opened and no runtime call was made.
    ReaderDisabled,
    /// An argument or configuration value is out of range. Nothing was sent.
    InvalidArgument,
    /// The kernel/PDB files do not match the recorded profile. Nothing was sent.
    Profile,
    /// The runtime could not be reached or pinned. No session exists.
    Connect,
    /// Kernel context or process discovery failed. The session remains usable.
    Discovery,
    /// The process list holds no such PID. The session remains usable.
    ProcessNotFound,
    /// The handle was closed or replaced by a later `open_process`. Open the process again.
    InvalidHandle,
    /// The process exited or its identity changed. Its handle is closed; the session remains.
    ProcessGone,
    /// An address is not mapped in the process. The handle and session remain usable.
    Unreadable,
    /// The session failed and stays failed. Connect again.
    SessionEnded,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;
