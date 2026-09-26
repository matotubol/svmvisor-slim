//! Bounded virtual PCI configuration and device effects.
//!
//! This is an explicitly supplied synthetic fabric, never a view copied from
//! physical configuration space. It provides no native ownership constructor.
//! See README.md for its intentionally incomplete platform contract.
#![forbid(unsafe_code)]

mod bus;
mod function;
pub mod iommu;
pub mod transport;

pub use bus::{Bus, BusPolicy, ConfigOwner, RefuseOwner, Transition};
pub use function::{Bar, BarKind, Bridge, Function, FunctionSpec, Header, Msi};

use crate::svm::configuration::ScalarError;

/// One serialized configuration effect owner shared by both transports. A
/// narrow owner must reject unknown functions; only a complete fabric may
/// report an unlisted function as absent.
pub trait ConfigAccess {
    fn route(&self) -> crate::svm::configuration::ConfigurationRoute;
    fn io(&mut self, port: u16, width: u8, write: Option<u32>) -> Result<u32, Error>;
    fn ecam(&mut self, address: u64, width: u8, write: Option<u32>) -> Result<u32, Error>;
}

impl ConfigAccess for Bus<'_> {
    fn route(&self) -> crate::svm::configuration::ConfigurationRoute {
        self.route()
    }
    fn io(&mut self, port: u16, width: u8, write: Option<u32>) -> Result<u32, Error> {
        self.io(port, width, write)
    }
    fn ecam(&mut self, address: u64, width: u8, write: Option<u32>) -> Result<u32, Error> {
        self.ecam(address, width, write)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidPolicy,
    InvalidFunction,
    InvalidBar,
    InvalidTopology,
    DuplicateFunction,
    OutsidePolicy,
    InvalidAccess,
    SensitiveControl,
    UnsupportedControl,
    UnsupportedBusChange,
    DecodeEnabled,
    UnassignedBar,
    Overlap,
    MissingOwner,
    OwnerRejected,
    BusMasterDisabled,
    InterruptDisabled,
    NoInterrupt,
    NoDecode,
    Scalar(ScalarError),
    NonAccumulator,
    Commit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Space {
    Memory,
    Io,
}

/// Half-open guest address range. No member of this type is a host pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub base: u64,
    pub bytes: u64,
}

impl Region {
    pub const fn valid(self) -> bool {
        self.bytes != 0 && self.base.checked_add(self.bytes).is_some()
    }

    pub fn contains(self, base: u64, bytes: u64) -> bool {
        self.valid()
            && bytes != 0
            && base >= self.base
            && base.checked_add(bytes).is_some_and(|end| end <= self.base + self.bytes)
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.valid()
            && other.valid()
            && self.base < other.base + other.bytes
            && other.base < self.base + self.bytes
    }
}

/// Numeric dispatch key for an emulated BAR resource, never an authorization to
/// dereference guest or physical memory. Device implementations own its payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarAccess {
    pub bdf: u16,
    pub bar: u8,
    pub offset: u64,
    pub bytes: u64,
}

/// MSI address/data remain guest values. An interrupt owner must translate and
/// deliver this message; this type must never be used as a physical store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interrupt {
    Msi { bdf: u16, address: u64, data: u16 },
    Intx { bdf: u16, pin: u8, line: u8 },
}

pub(super) fn lane(register: u16, width: u8) -> Result<(u16, u32, u32), Error> {
    if !matches!(width, 1 | 2 | 4)
        || register >= 4096
        || u32::from(register & 3) + u32::from(width) > 4
    {
        return Err(Error::InvalidAccess);
    }
    // The observed B8/BC indirect route exists on host functions. Never hide it
    // behind generic unimplemented-register semantics, even in this model.
    if register & !3 == 0xb8 || register & !3 == 0xbc {
        return Err(Error::SensitiveControl);
    }
    let shift = u32::from(register & 3) * 8;
    let bits = if width == 4 { u32::MAX } else { (1 << (u32::from(width) * 8)) - 1 };
    Ok((register & !3, shift, bits))
}
