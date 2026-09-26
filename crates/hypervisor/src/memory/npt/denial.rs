//! Immutable numeric CPU-access exclusions, not proof of control ownership.

use crate::memory::address::{AddressError, AddressPolicy, PAGE_BYTES, PhysicalRange};

/// Two control ranges for each of the inventory's at most sixteen units.
/// Actual table capacity is checked independently before construction.
pub const MAX_CONTROL_PAGE_RANGES: usize = 32;

/// Sorted, disjoint, complete 4KiB physical pages to omit from an identity NPT.
/// The caller must retain this policy in protected storage, supply it on every
/// reconstruction and coordinate all consumers and TLB invalidation. Numeric
/// ranges establish neither ownership nor a coherent guest hardware profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlPageDenials {
    ranges: [(u64, u64); MAX_CONTROL_PAGE_RANGES],
    len: usize,
}

impl ControlPageDenials {
    pub const EMPTY: Self = Self { ranges: [(0, 0); MAX_CONTROL_PAGE_RANGES], len: 0 };

    /// Require explicit page boundaries; partial pages are never silently
    /// rounded over neighboring registers. Addresses are bounded by the native
    /// identity domain as well as the supplied physical/encryption policy.
    pub fn new(
        policy: AddressPolicy,
        ranges: &[PhysicalRange],
    ) -> Result<Self, ControlPageDenialError> {
        if ranges.len() > MAX_CONTROL_PAGE_RANGES {
            return Err(ControlPageDenialError::Capacity);
        }
        let mut result = Self::EMPTY;
        let mut previous_end = 0;
        for range in ranges {
            policy
                .validate(range.base(), range.len(), PAGE_BYTES as u64)
                .map_err(ControlPageDenialError::Address)?;
            if range.len() & (PAGE_BYTES as u64 - 1) != 0 {
                return Err(ControlPageDenialError::PartialPage);
            }
            let end = range.last_byte() + 1;
            if end > 1u64 << policy.physical_bits().min(40) {
                return Err(ControlPageDenialError::OutsideIdentityDomain);
            }
            if range.base() < previous_end {
                return Err(ControlPageDenialError::UnsortedOrOverlapping);
            }
            result.ranges[result.len] = (range.base(), end);
            result.len += 1;
            previous_end = end;
        }
        Ok(result)
    }

    /// Half-open physical intervals. There is no mutable range accessor.
    pub fn ranges(&self) -> &[(u64, u64)] {
        &self.ranges[..self.len]
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn contains(&self, address: u64) -> bool {
        self.ranges().iter().any(|&(start, end)| start <= address && address < end)
    }

    pub(super) fn validate(&self, policy: AddressPolicy) -> Result<(), ControlPageDenialError> {
        for &(start, end) in self.ranges() {
            policy
                .validate(start, end - start, PAGE_BYTES as u64)
                .map_err(ControlPageDenialError::Address)?;
            if end > 1u64 << policy.physical_bits().min(40) {
                return Err(ControlPageDenialError::OutsideIdentityDomain);
            }
        }
        Ok(())
    }

    pub(super) fn intersects(&self, start: u64, end: u64) -> bool {
        self.ranges().iter().any(|&(base, limit)| base < end && start < limit)
    }

    pub(super) fn covers(&self, start: u64, end: u64) -> bool {
        let mut cursor = start;
        for &(base, limit) in self.ranges() {
            if base > cursor {
                break;
            }
            cursor = cursor.max(limit);
            if cursor >= end {
                return true;
            }
        }
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlPageDenialError {
    Address(AddressError),
    Capacity,
    PartialPage,
    OutsideIdentityDomain,
    UnsortedOrOverlapping,
}
