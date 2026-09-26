//! Common configuration-route expectation retained in the monitor pool.
//!
//! The serialized firmware installer initializes this before any CPU arms. Each
//! CPU compares its actual route with this value before installing interception.
//! It contains no guest pointer, admission flag, credential or DMA ownership
//! grant. Its lifetime protection is CPU NPT exclusion; DMA protection remains
//! a separate unfinished prerequisite.
#![forbid(unsafe_code)]

use crate::svm::configuration::ConfigurationRoute;

/// Byte offset within the already shared startup page, after all mailboxes and
/// the fixed terminal-control block. This is independent of terminal presence.
pub const ROUTE_EXPECTATION_OFFSET: u64 = 0x900;

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteExpectation {
    raw: u64,
    signature: u32,
    physical_bits: u8,
    cpu_count: u8,
    reserved: [u8; 2],
}

impl RouteExpectation {
    /// Validate a firmware BSP observation. The caller owns its provenance;
    /// constructing this value alone establishes no protected execution.
    pub fn new(signature: u32, physical_bits: u8, raw: u64, count: usize) -> Option<Self> {
        if !(2..=super::MAX_RESIDENT_CPUS).contains(&count) {
            return None;
        }
        let route = ConfigurationRoute::admit_target(signature, physical_bits, raw).ok()?;
        let (base, bytes) = route.aperture();
        if !super::platform::outside_control_page(base, bytes) {
            return None;
        }
        Some(Self { raw, signature, physical_bits, cpu_count: count as u8, reserved: [0; 2] })
    }

    /// Revalidate the retained expectation and the actual current CPU route.
    /// All participating CPUs must match the same installed observation.
    pub fn admit(
        &self,
        signature: u32,
        physical_bits: u8,
        observed: u64,
        count: usize,
    ) -> Option<ConfigurationRoute> {
        if self.reserved != [0; 2]
            || signature != self.signature
            || physical_bits != self.physical_bits
            || count != usize::from(self.cpu_count)
            || !(2..=super::MAX_RESIDENT_CPUS).contains(&count)
        {
            return None;
        }
        let route = ConfigurationRoute::admit_target(signature, physical_bits, self.raw).ok()?;
        let (base, bytes) = route.aperture();
        if !super::platform::outside_control_page(base, bytes) {
            return None;
        }
        route.verify(observed).ok()?;
        Some(route)
    }
}

const _: () = {
    use core::mem::{align_of, size_of};
    assert!(size_of::<RouteExpectation>() == 16);
    assert!(align_of::<RouteExpectation>() == 8);
    assert!(
        super::terminal::CONTROL_OFFSET + size_of::<super::terminal::TerminalControl>() as u64
            <= ROUTE_EXPECTATION_OFFSET
    );
    assert!(ROUTE_EXPECTATION_OFFSET + size_of::<RouteExpectation>() as u64 <= 4096);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::msr::{TARGET_PHYSICAL_BITS, TARGET_SIGNATURE};

    const ROUTE: u64 = 0xe000_0021;

    #[test]
    fn every_cpu_must_match_retained_route_and_participant_count() {
        let expected =
            RouteExpectation::new(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, ROUTE, 24).unwrap();
        assert!(expected.admit(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, ROUTE, 24).is_some());
        for count in [0, 1, 23, 25, 33, usize::MAX] {
            assert!(expected.admit(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, ROUTE, count).is_none());
        }
        for raw in [0, ROUTE & !1, ROUTE ^ (1 << 28), ROUTE ^ 4, ROUTE | (1 << 63)] {
            assert!(expected.admit(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, raw, 24).is_none());
        }
        assert!(expected.admit(TARGET_SIGNATURE ^ 1, TARGET_PHYSICAL_BITS, ROUTE, 24).is_none());
        assert!(expected.admit(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS - 1, ROUTE, 24).is_none());
    }

    #[test]
    fn invalid_or_uninitialized_expectations_never_admit() {
        for count in [0, 1, 33, usize::MAX] {
            assert!(
                RouteExpectation::new(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, ROUTE, count)
                    .is_none()
            );
        }
        for raw in [0, ROUTE & !1, ROUTE | 2, u64::MAX, 0xfed0_0001, 0xf000_0021] {
            assert!(
                RouteExpectation::new(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, raw, 2).is_none()
            );
        }
        let mut expected =
            RouteExpectation::new(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, ROUTE, 2).unwrap();
        expected.reserved[1] = 1;
        assert!(expected.admit(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, ROUTE, 2).is_none());
        expected.reserved = [0; 2];
        expected.raw = 0;
        assert!(expected.admit(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, 0, 2).is_none());
        for raw in [0xfed0_0001, 0xf000_0021] {
            expected.raw = raw;
            assert!(expected.admit(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, raw, 2).is_none());
        }
    }
}
