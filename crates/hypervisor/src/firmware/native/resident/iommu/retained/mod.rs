//! One historical firmware observation, captured directly into retained backing.
//!
//! The complete bounded `Report` remains typed: no declaration, diagnostic,
//! hardware observation or acquisition failure is selected out for retention.
//! The source tables and `Scratch` are borrowed only for the synchronous call.
//! This module neither allocates backing nor establishes its CPU/DMA protection.
//!
//! Only the integer-only header has a fixed layout. The payload is a Rust value
//! for this firmware image, not a serialized format or a cross-image ABI. Do not
//! form a `Report`/`RetainedObservation` reference from arbitrary bytes, or while
//! an uncontrolled writer could alter enum/Option representations. Header checks
//! cannot make that safe and cannot authenticate DMA-writable memory. A later
//! resident consumer may copy and check the header alone while leaving the
//! payload opaque. Ownership decisions require a new hardware observation and
//! the separately established lifetime/integrity of every relevant resource.

use core::mem::{align_of, offset_of, size_of};

use super::{MAX_OBSERVED_UNITS, ReadOnlyAccess, Report, Scratch};
use crate::{host::resident::MAX_RESIDENT_CPUS, memory::address::AddressPolicy};

pub const HEADER_BYTES: usize = 64;
pub const REPORT_OFFSET: usize = HEADER_BYTES;
pub const RETAINED_BYTES: usize = size_of::<RetainedObservation>();
pub const RETAINED_ALIGN: usize = align_of::<RetainedObservation>();

const LAYOUT_VERSION: u32 = 1;
const EMPTY: u32 = 0;
const CAPTURING: u32 = 1;
const PUBLISHED: u32 = 2;

/// Caller-supplied context recorded with the capture, not authority or proof
/// that hardware matched it. The native adapter must independently compare the
/// actual route before/during/after acquisition. Retention never reads hardware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureMetadata {
    pub configuration_route: u64,
    pub signature: u32,
    pub physical_bits: u8,
    pub cpu_count: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionError {
    InvalidHeader,
    InvalidMetadata,
    MetadataMismatch,
    NotPublished,
    AlreadyAttempted,
    ReportMismatch,
}

/// Scalar publication description at byte zero of the retained extent. Every
/// bit pattern is a valid Rust value; validation can therefore precede any
/// payload access. Copy only this type from raw backing, never the whole typed
/// container, if the payload's Rust validity/lifetime has not been established.
/// The publication word is not an atomic synchronization primitive: the caller
/// must serialize capture and handoff, with no concurrent readers or writers.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedHeader {
    layout_version: u32,
    bytes: u32,
    phase: u32,
    diagnostic_word: u32,
    configuration_route: u64,
    system_table_address: u64,
    signature: u32,
    physical_bits: u8,
    cpu_count: u8,
    reserved: [u8; 2],
    reserved_tail: [u64; 3],
}

impl RetainedHeader {
    const EMPTY: Self = Self {
        layout_version: LAYOUT_VERSION,
        bytes: RETAINED_BYTES as u32,
        phase: EMPTY,
        diagnostic_word: 0,
        configuration_route: 0,
        system_table_address: 0,
        signature: 0,
        physical_bits: 0,
        cpu_count: 0,
        reserved: [0; 2],
        reserved_tail: [0; 3],
    };

    /// Check layout, completed publication, bounded diagnostic counts and exact
    /// caller-supplied context. The returned stage-5 word has no endpoint bit.
    /// This checks only these scalar fields; it does not inspect or validate the
    /// report payload, establish freshness, or assert successful acquisition.
    pub fn validate(&self, expected: CaptureMetadata) -> Result<u32, RetentionError> {
        self.validate_layout()?;
        match self.phase {
            EMPTY | CAPTURING => return Err(RetentionError::NotPublished),
            PUBLISHED => {}
            _ => return Err(RetentionError::InvalidHeader),
        }
        if self.metadata() != expected {
            return Err(RetentionError::MetadataMismatch);
        }
        if !(32..=52).contains(&self.physical_bits)
            || !(1..=MAX_RESIDENT_CPUS).contains(&usize::from(self.cpu_count))
        {
            return Err(RetentionError::InvalidMetadata);
        }
        let state = (self.diagnostic_word >> 4) & 15;
        let units = (self.diagnostic_word >> 8) & 255;
        let observed = (self.diagnostic_word >> 16) & 255;
        if !(1..=6).contains(&state)
            || units as usize > MAX_OBSERVED_UNITS
            || observed > units
            || self.diagnostic_word != 0x0200_0000 | (observed << 16) | (units << 8) | (state << 4)
        {
            return Err(RetentionError::InvalidHeader);
        }
        Ok(self.diagnostic_word)
    }

    pub const fn metadata(&self) -> CaptureMetadata {
        CaptureMetadata {
            configuration_route: self.configuration_route,
            signature: self.signature,
            physical_bits: self.physical_bits,
            cpu_count: self.cpu_count,
        }
    }

    /// A historical numeric source address, never permission to dereference it.
    pub const fn system_table_address(&self) -> u64 {
        self.system_table_address
    }

    fn validate_layout(&self) -> Result<(), RetentionError> {
        if self.layout_version != LAYOUT_VERSION
            || self.bytes as usize != RETAINED_BYTES
            || self.reserved != [0; 2]
            || self.reserved_tail != [0; 3]
        {
            return Err(RetentionError::InvalidHeader);
        }
        Ok(())
    }
}

/// Initialize in caller-owned backing before capture and retain that backing
/// for every borrow. It contains values only, no firmware or scratch pointers.
/// The private payload is exposed immutably only after synchronous acquisition
/// returns, including when that return records unsupported/partial/failed work.
#[repr(C, align(8))]
pub struct RetainedObservation {
    header: RetainedHeader,
    report: Report,
}

static EMPTY_TEMPLATE: RetainedObservation =
    RetainedObservation { header: RetainedHeader::EMPTY, report: Report::EMPTY };

impl RetainedObservation {
    /// Static, fully typed initializer. An allocator with exclusive, aligned,
    /// writable backing can copy one value directly from this address to its
    /// destination (e.g. `ptr::copy_nonoverlapping`) before forming a reference.
    /// This avoids constructing a report-sized stack temporary. Do not replace
    /// the initializer with zeroed bytes; zero is not every enum's empty value.
    pub const fn empty_template() -> &'static Self {
        &EMPTY_TEMPLATE
    }

    /// Acquire once directly into the caller's already initialized backing.
    /// `Ok(())` means publication finished, not that discovery succeeded. All
    /// ordinary acquisition failures and unresolved/partial evidence are kept.
    /// An interrupted attempt remains unpublished and cannot be retried in this
    /// container. Nothing is copied out of boot scratch into a borrowed field.
    pub fn capture_once(
        &mut self,
        metadata: CaptureMetadata,
        access: &mut impl ReadOnlyAccess,
        policy: AddressPolicy,
        system_table: u64,
        scratch: &mut Scratch,
    ) -> Result<(), RetentionError> {
        self.header.validate_layout()?;
        if self.header.phase != EMPTY {
            return Err(RetentionError::AlreadyAttempted);
        }
        if self.header != RetainedHeader::EMPTY {
            return Err(RetentionError::InvalidHeader);
        }
        if metadata.physical_bits != policy.physical_bits()
            || !(1..=MAX_RESIDENT_CPUS).contains(&usize::from(metadata.cpu_count))
        {
            return Err(RetentionError::InvalidMetadata);
        }
        self.header.phase = CAPTURING;
        self.header.configuration_route = metadata.configuration_route;
        self.header.system_table_address = system_table;
        self.header.signature = metadata.signature;
        self.header.physical_bits = metadata.physical_bits;
        self.header.cpu_count = metadata.cpu_count;
        super::acquire(access, policy, system_table, scratch, &mut self.report);
        self.header.diagnostic_word = self.report.diagnostic_word();
        self.header.phase = PUBLISHED;
        Ok(())
    }

    pub const fn header(&self) -> &RetainedHeader {
        &self.header
    }

    /// Borrow this firmware image's live typed value. The header/summary check
    /// detects inconsistent metadata; it is not a raw-memory corruption check
    /// and cannot establish enum validity, DMA integrity or hardware freshness.
    /// The report cannot outlive its backing:
    ///
    /// ```compile_fail
    /// use svmvisor_hypervisor::firmware::native::resident::iommu::{
    ///     Report, retained::{CaptureMetadata, RetainedObservation},
    /// };
    /// fn detach(storage: &RetainedObservation, metadata: CaptureMetadata) -> &'static Report {
    ///     storage.report(metadata).unwrap()
    /// }
    /// ```
    pub fn report(&self, expected: CaptureMetadata) -> Result<&Report, RetentionError> {
        if self.header.validate(expected)? != self.report.diagnostic_word() {
            return Err(RetentionError::ReportMismatch);
        }
        Ok(&self.report)
    }
}

const _: () = {
    assert!(size_of::<RetainedHeader>() == HEADER_BYTES);
    assert!(align_of::<RetainedHeader>() == 8);
    assert!(offset_of!(RetainedObservation, header) == 0);
    assert!(offset_of!(RetainedObservation, report) == REPORT_OFFSET);
    assert!(offset_of!(RetainedHeader, phase) == 8);
    assert!(offset_of!(RetainedHeader, diagnostic_word) == 12);
    assert!(offset_of!(RetainedHeader, configuration_route) == 16);
    assert!(offset_of!(RetainedHeader, system_table_address) == 24);
    assert!(offset_of!(RetainedHeader, signature) == 32);
    assert!(offset_of!(RetainedHeader, physical_bits) == 36);
    assert!(offset_of!(RetainedHeader, cpu_count) == 37);
    assert!(offset_of!(RetainedHeader, reserved_tail) == 40);
    assert!(align_of::<Report>() == 8);
    assert!(RETAINED_ALIGN == 8);
    assert!(RETAINED_BYTES <= 64 * 1024);
};

#[cfg(test)]
mod tests;
