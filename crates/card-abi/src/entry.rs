//! One-shot GMET entry experiment, version 1. Nonce is correlation, not authorization.
//! Inputs: RAX magic, RCX operation, RDX nonzero nonce, R8 version.
//! ARM: RAX zero when activated, otherwise one; RDX status.
//! QUERY: RAX zero for a matching nonce/root, RDX status, R8 exit code,
//! R9 RIP, R10 INFO1, R11 INFO2, R12 entry sequence. Preserve the caller's R12.
//! One attempt per CPU per boot, including refused activation. No mappings change.

pub const MAGIC: u64 = 0x3154_454d_4756_4d53;
pub const VERSION: u64 = 1;
pub const ARM: u64 = 1;
pub const QUERY: u64 = 2;
pub const REQUESTED: u64 = 1;
pub const ENTERED: u64 = 2;
pub const GATED: u64 = 3;
pub const REFLECTED: u64 = 4;
pub const INTERRUPTED: u64 = 5;
pub const REFUSED: u64 = 6;
pub const FAILED: u64 = 7;
