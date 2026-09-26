//! Same-guest VMMCALL transport for the bounded batch reader.
//! The installed reader is a CPL3 interface; CPL0-2 calls retain VMMCALL's native #UD.
//! RAX is the magic, RCX the operation, RDX the request VA, R8 the response VA,
//! and R9 the response capacity. R10 carries the session for submit, step, abort, and context
//! (zero for probe). RAX returns status and RDX length (version for probe); other registers survive.
//! Context requires the same disjoint request/result buffer shape as submit, reads no request
//! bytes, and writes the fresh caller observation defined in `context`.

pub const MAGIC: u64 = 0x5356_4d4c_4f43_414c;
pub const VERSION: u64 = 1;
pub const PROBE: u64 = 0;
pub const SUBMIT: u64 = 1;
pub const STEP: u64 = 2;
pub const ABORT: u64 = 3;
/// Optional fresh caller-context observation; older version-one runtimes return INVALID.
pub const CONTEXT: u64 = 4;
pub const COMPLETE: u64 = 0;
pub const PENDING: u64 = 1;
pub const UNAVAILABLE: u64 = 2;
pub const INVALID: u64 = 3;
pub const BUSY: u64 = 4;
pub const OWNER: u64 = 5;
pub const MEMORY: u64 = 6;
