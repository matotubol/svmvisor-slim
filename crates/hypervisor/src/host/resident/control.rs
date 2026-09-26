//! Integer-only handoff of the native CPU control-page exclusion policy.
//!
//! The installer derives this from corroborated unit apertures before any CPU
//! enters its guest. Every NPT construction and runtime cache rebuild consumes
//! the same policy. This record grants no DMA or IOMMU ownership; takeover must
//! freshly corroborate its complete unit set before publishing hardware state.
#![forbid(unsafe_code)]

use crate::{
    memory::{
        address::{AddressPolicy, PhysicalRange},
        npt::{ControlPageDenials, MAX_CONTROL_PAGE_RANGES},
    },
    svm::configuration::ConfigurationRoute,
};

pub const CONTROL_MANIFEST_OFFSET: u64 = 0xa00;
const MAGIC: u64 = u64::from_le_bytes(*b"IOCTRL01");

/// All bit patterns are valid Rust values. Validate before interpreting fields;
/// copying this scalar record does not confer integrity or fresh provenance.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlManifest {
    magic: u64,
    route: u64,
    signature: u32,
    physical_bits: u8,
    cpu_count: u8,
    complete: u8,
    length: u8,
    reserved: [u64; 3],
    ranges: [[u64; 2]; MAX_CONTROL_PAGE_RANGES],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlManifestError {
    Header,
    Context,
    Ranges,
    PoolOverlap,
}

impl ControlManifest {
    /// No complete unit aperture set was acquired. The existing strict-refusal
    /// CPU profile can retain this record, but a native IOMMU takeover cannot.
    pub fn unavailable(
        policy: AddressPolicy,
        signature: u32,
        route: u64,
        cpu_count: usize,
    ) -> Result<Self, ControlManifestError> {
        Self::build(policy, signature, route, cpu_count, false, &[])
    }

    /// Complete, sorted, non-overlapping whole pages. The producer is responsible
    /// for including every observed unit's entire MMIO aperture and config page.
    pub fn new(
        policy: AddressPolicy,
        signature: u32,
        route: u64,
        cpu_count: usize,
        ranges: &[PhysicalRange],
    ) -> Result<Self, ControlManifestError> {
        Self::build(policy, signature, route, cpu_count, true, ranges)
    }

    fn build(
        policy: AddressPolicy,
        signature: u32,
        route: u64,
        cpu_count: usize,
        complete: bool,
        ranges: &[PhysicalRange],
    ) -> Result<Self, ControlManifestError> {
        if !(2..=super::MAX_RESIDENT_CPUS).contains(&cpu_count)
            || ConfigurationRoute::admit_target(signature, policy.physical_bits(), route).is_err()
            || complete && ranges.is_empty()
        {
            return Err(ControlManifestError::Context);
        }
        let denied =
            ControlPageDenials::new(policy, ranges).map_err(|_| ControlManifestError::Ranges)?;
        let mut result = Self {
            magic: MAGIC,
            route,
            signature,
            physical_bits: policy.physical_bits(),
            cpu_count: cpu_count as u8,
            complete: u8::from(complete),
            length: ranges.len() as u8,
            reserved: [0; 3],
            ranges: [[0; 2]; MAX_CONTROL_PAGE_RANGES],
        };
        for (output, &(base, end)) in result.ranges.iter_mut().zip(denied.ranges()) {
            *output = [base, end - base];
        }
        Ok(result)
    }

    pub const fn is_complete(&self) -> bool {
        self.complete == 1
    }

    pub fn denials(
        &self,
        policy: AddressPolicy,
        signature: u32,
        route: u64,
        cpu_count: usize,
        pool: PhysicalRange,
    ) -> Result<ControlPageDenials, ControlManifestError> {
        if self.magic != MAGIC
            || self.reserved != [0; 3]
            || self.complete > 1
            || usize::from(self.length) > MAX_CONTROL_PAGE_RANGES
            || (self.complete == 0) != (self.length == 0)
            || self.ranges[usize::from(self.length)..].iter().any(|range| *range != [0; 2])
        {
            return Err(ControlManifestError::Header);
        }
        if self.signature != signature
            || self.physical_bits != policy.physical_bits()
            || self.route != route
            || usize::from(self.cpu_count) != cpu_count
            || !(2..=super::MAX_RESIDENT_CPUS).contains(&cpu_count)
            || ConfigurationRoute::admit_target(signature, policy.physical_bits(), route).is_err()
        {
            return Err(ControlManifestError::Context);
        }
        policy.validate(pool.base(), pool.len(), 4096).map_err(|_| ControlManifestError::Ranges)?;
        // PhysicalRange has no unchecked constructor. Populate a fixed array
        // with a valid inert page, then expose only the validated used prefix.
        let inert = policy.validate(0, 4096, 4096).map_err(|_| ControlManifestError::Ranges)?;
        let mut ranges = [inert; MAX_CONTROL_PAGE_RANGES];
        for (index, &[base, length]) in self.ranges[..usize::from(self.length)].iter().enumerate() {
            let range =
                policy.validate(base, length, 4096).map_err(|_| ControlManifestError::Ranges)?;
            if base <= pool.last_byte() && pool.base() <= range.last_byte() {
                return Err(ControlManifestError::PoolOverlap);
            }
            ranges[index] = range;
        }
        ControlPageDenials::new(policy, &ranges[..usize::from(self.length)])
            .map_err(|_| ControlManifestError::Ranges)
    }
}

const _: () = {
    assert!(
        super::configuration::ROUTE_EXPECTATION_OFFSET
            + core::mem::size_of::<super::configuration::RouteExpectation>() as u64
            <= CONTROL_MANIFEST_OFFSET
    );
    assert!(CONTROL_MANIFEST_OFFSET + core::mem::size_of::<ControlManifest>() as u64 <= 4096);
    assert!(core::mem::align_of::<ControlManifest>() == 8);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{arch::x86_64::msr::TARGET_SIGNATURE, memory::address::EncryptionState};

    const ROUTE: u64 = 0xe000_0021;

    #[test]
    fn malformed_scalar_handoffs_cannot_reconstruct_a_denial_policy() {
        let policy =
            AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: None }).unwrap();
        let pool = policy.validate(0x10000000, 0x4000000, 4096).unwrap();
        let range = policy.validate(0xfed80000, 0x4000, 4096).unwrap();
        let valid = ControlManifest::new(policy, TARGET_SIGNATURE, ROUTE, 24, &[range]).unwrap();
        let consume =
            |manifest: ControlManifest| manifest.denials(policy, TARGET_SIGNATURE, ROUTE, 24, pool);
        assert!(consume(valid).is_ok());
        for change in 0..9 {
            let mut bad = valid;
            match change {
                0 => bad.magic ^= 1,
                1 => bad.reserved[1] = 1,
                2 => bad.complete = 2,
                3 => bad.complete = 0,
                4 => bad.length = 33,
                5 => bad.ranges[31] = [4096, 4096],
                6 => bad.ranges[0][0] += 1,
                7 => bad.ranges[0][1] -= 1,
                8 => bad.ranges[0][1] = u64::MAX,
                _ => unreachable!(),
            }
            assert!(consume(bad).is_err(), "mutation {change}");
        }
        let mut overlapping = valid;
        overlapping.ranges[0] = [pool.base(), 4096];
        assert_eq!(consume(overlapping), Err(ControlManifestError::PoolOverlap));
    }
}
