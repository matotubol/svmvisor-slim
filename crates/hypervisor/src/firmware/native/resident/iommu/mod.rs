//! Bounded, read-only pre-ExitBootServices IOMMU observations.
//!
//! The native adapter supplies current descriptor, mapping and cache checks.
//! This report owns its data and never borrows firmware tables. It is an
//! internal firmware observation, not protected storage or DMA ownership.
//! Existing table/queue addresses are recorded but never dereferenced.
#![forbid(unsafe_code)]

use crate::memory::{address::AddressPolicy, iommu::Discovery};

mod access;
mod acpi;
pub mod binding;
pub mod control;
mod hardware;
pub mod ownership;
pub mod presentation;
pub mod resources;
pub mod retained;

pub use access::{MemoryKind, descriptor_span, root_cache_preflight};
pub use acpi::{AcquisitionError, Scratch};
pub use hardware::{HardwareError, PciObservation, RegisterObservation, UnitObservation};

/// The adapter must refuse reads whose current descriptor, translation, cache
/// type or physical address is inadmissible. No method permits a write. RAM
/// copies and naturally aligned device reads deliberately use separate methods.
pub trait ReadOnlyAccess {
    fn read_firmware(&mut self, address: u64, out: &mut [u8]) -> Result<(), ReadError>;
    fn read_acpi(&mut self, address: u64, out: &mut [u8]) -> Result<(), ReadError>;
    fn read_pci_u32(
        &mut self,
        segment: u16,
        requester: u16,
        address: u64,
    ) -> Result<u32, ReadError>;
    fn read_mmio_u64(&mut self, address: u64) -> Result<u64, ReadError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    Address,
    MemoryMap,
    MemoryType,
    ReadProtected,
    CacheType,
    Mapping,
    Unsupported,
    Unavailable,
}

/// Stable diagnostic categories. None asserts that isolation exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ObservationState {
    Observed = 1,
    Unavailable = 2,
    Unsupported = 3,
    Malformed = 4,
    Ambiguous = 5,
    Partial = 6,
}

pub const MAX_OBSERVED_UNITS: usize = crate::memory::iommu::MAX_UNITS;
const _: () = assert!(MAX_OBSERVED_UNITS <= 16);

pub struct Report {
    pub state: ObservationState,
    pub failure: Option<AcquisitionError>,
    pub tables: Discovery,
    pub hardware: [UnitObservation; MAX_OBSERVED_UNITS],
}

impl Report {
    pub const EMPTY: Self = Self {
        state: ObservationState::Unavailable,
        failure: None,
        tables: Discovery::EMPTY,
        hardware: [UnitObservation::EMPTY; MAX_OBSERVED_UNITS],
    };

    /// Version 2 stage-5 detail, without its independently owned endpoint bit.
    /// Counts describe acquisition only. They cannot authorize a reader.
    pub fn diagnostic_word(&self) -> u32 {
        let units = self.tables.ivrs.units().len() as u32;
        let observed = self
            .hardware
            .iter()
            .take(units as usize)
            .filter(|unit| unit.registers.is_some() && unit.error.is_none())
            .count() as u32;
        0x0200_0000 | (observed << 16) | (units << 8) | ((self.state as u32) << 4)
    }
}

/// A single synchronous, allocation-free firmware snapshot. Boot Services must
/// remain live in the native adapter; the result retains no pointer into them.
/// `system_table` is the numeric address provided at this image's entry.
pub fn acquire(
    access: &mut impl ReadOnlyAccess,
    policy: AddressPolicy,
    system_table: u64,
    scratch: &mut Scratch,
    out: &mut Report,
) {
    out.state = ObservationState::Unavailable;
    out.failure = None;
    out.tables.clear();
    out.hardware.fill(UnitObservation::EMPTY);
    if let Err(error) = acpi::acquire_tables(access, policy, system_table, scratch, &mut out.tables)
    {
        out.tables.clear();
        out.state = error.state();
        out.failure = Some(error);
        return;
    }
    hardware::observe(access, policy, out);
}

/// Refresh only hardware against a retained, trusted pre-guest table inventory.
/// Caller retains the typed inventory's integrity and lifetime, serializes all
/// producers and independently compares the complete admitted control manifest.
/// This performs fresh reads, never interprets an old observation as ownership.
pub fn refresh_hardware(access: &mut impl ReadOnlyAccess, policy: AddressPolicy, out: &mut Report) {
    out.hardware.fill(UnitObservation::EMPTY);
    hardware::observe(access, policy, out);
}

#[cfg(test)]
mod tests;
