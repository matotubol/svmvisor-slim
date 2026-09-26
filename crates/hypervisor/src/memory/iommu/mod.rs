//! Bounded ACPI inventory and offline AMD IOMMU format checks.
//! No PCI/MMIO access or IOMMU programming occurs in this module.
//!
//! Parsing establishes structural evidence only: neither authenticity, device
//! ownership, active DMA translation nor an authorization boundary follows from
//! success. Diagnostics retain ambiguity instead of selecting a winning entry.
//! Input buffers must contain exactly one immutable snapshot of each table.
//! The `requester`, `tables`, `image`, `device_table`, `commands`, `queue` and `host_walk`
//! modules are offline tools.
//! Images use caller-owned storage and explicit numeric backing assignments;
//! commands are never submitted. Complete restricted DTE/interrupt codecs require
//! explicit policy; constructed images and queues never admit hardware.
//!
//! Layout references (physical PDF pages, text and PNG checked): ACPI_Spec_6.6
//! p176; 48882-3.11 pp290-309. Detailed IVHD tables pp298-301 define EFR2 at
//! +32, superseding the generic table's obsolete reserved label on p293.

mod acpi;
pub mod commands;
pub mod device_table;
pub mod host_walk;
pub mod image;
mod ivrs;
mod mcfg;
mod model;
pub mod physical;
pub mod queue;
pub mod requester;
pub mod virtualized;

pub mod tables;

pub use acpi::{AcpiHeader, MAX_TABLE_BYTES, SDT_HEADER_LEN, validate_sdt};
pub use ivrs::{parse_ivrs, parse_ivrs_into};
pub use mcfg::{parse_mcfg, parse_mcfg_into};
pub use model::*;

/// Parse independent table snapshots, retaining every supported declaration.
/// Prefer `discover_into` with preallocated storage in firmware.
pub fn discover(ivrs: &[u8], mcfg: &[u8]) -> Result<Discovery, ParseError> {
    let mut out = Discovery::EMPTY;
    discover_into(ivrs, mcfg, &mut out)?;
    Ok(out)
}

/// Replace an existing inventory without constructing a report-sized temporary.
/// On error the output is empty, so no partially parsed inventory can be used.
pub fn discover_into(ivrs: &[u8], mcfg: &[u8], out: &mut Discovery) -> Result<(), ParseError> {
    out.clear();
    let result = (|| {
        parse_ivrs_into(ivrs, &mut out.ivrs)?;
        parse_mcfg_into(mcfg, &mut out.mcfg)?;
        for index in 0..out.ivrs.units.len {
            let unit = out.ivrs.units.data[index];
            let bus = (unit.device_id >> 8) as u8;
            if !out.mcfg.allocations().iter().any(|allocation| {
                allocation.segment == unit.segment
                    && (allocation.start_bus..=allocation.end_bus).contains(&bus)
            }) {
                out.ivrs.diagnose(
                    DiagnosticKind::IommuOutsideMcfg,
                    unit.first_form_offset,
                    None,
                )?;
            }
            for allocation in out.mcfg.allocations() {
                // The parser has already checked the minimum register window.
                if unit.mmio_base <= allocation.last && allocation.start <= unit.mmio_base + 0x3fff
                {
                    out.ivrs.diagnose(
                        DiagnosticKind::IommuMmioOverlapsEcam,
                        unit.first_form_offset,
                        None,
                    )?;
                }
            }
        }
        out.complete = true;
        Ok(())
    })();
    if result.is_err() {
        out.clear();
    }
    result
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub table: [u8; 4],
    /// Byte offset in the table, including its ACPI header.
    pub offset: usize,
    pub kind: ParseErrorKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseErrorKind {
    Truncated,
    InvalidLength,
    TrailingBytes,
    BadSignature,
    BadChecksum,
    UnsupportedRevision,
    ReservedField,
    UnsupportedBlock(u8),
    UnsupportedDeviceEntry(u8),
    UnsupportedUidFormat(u8),
    InvalidUid,
    InvalidHardwareId,
    FixedEntryAfterAcpi,
    InvalidRange,
    MissingRangeEnd,
    UnexpectedRangeEnd,
    InvalidCapabilityOffset,
    MisalignedAddress,
    AddressOverflow,
    DuplicateForm,
    ConflictingUnitIdentity,
    ConflictingMmioAddress,
    OverlappingEcam,
    ConflictingEcamBuses,
    OrphanIvmd,
    IvmdSegmentMismatch,
    InvalidIvmdFlags,
    MissingIommu,
    MissingDeviceEntries,
    MissingMcfgAllocation,
    LimitExceeded(Limit),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    TableBytes,
    Units,
    Forms,
    RequesterScopes,
    SpecialDevices,
    AcpiDevices,
    UidBytes,
    MemoryRegions,
    McfgAllocations,
    Diagnostics,
}

fn error(table: [u8; 4], offset: usize, kind: ParseErrorKind) -> ParseError {
    ParseError { table, offset, kind }
}

#[cfg(test)]
mod tests;
