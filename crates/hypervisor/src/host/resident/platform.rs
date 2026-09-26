//! Denial of the concrete F7 reset/power routes identified in
//! FIRMWARE-F7-EVIDENCE.md. This is deliberately not a complete chipset map.
//! Unsupported platform transitions terminate before their native effect.
#![forbid(unsafe_code)]

use crate::svm::{
    configuration::ConfigurationRoute,
    permission_maps::{Iopm, Permission},
};

pub const FCH_CONTROL_PAGE: u64 = 0xfed8_0000;
pub const PLATFORM_IO_OFFSET: u64 = 0xe00;
const MAGIC: u64 = u64::from_le_bytes(*b"F7IO0001");

/// Configuration/IOMMU windows must not reinterpret known chipset registers.
/// Empty or overflowing candidate windows cannot establish disjointness.
pub fn outside_control_page(base: u64, bytes: u64) -> bool {
    bytes != 0
        && base
            .checked_add(bytes)
            .is_some_and(|end| end <= FCH_CONTROL_PAGE || base >= FCH_CONTROL_PAGE + 4096)
}

/// Raw scalar handoff. Zero backing is valid Rust storage, but is not a valid
/// observation. Capture the three exact routing words before constructing this.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformIo {
    magic: u64,
    route: u64,
    raw360: u64,
    raw368: u64,
    count: u64,
    reserved: [u64; 3],
}

impl PlatformIo {
    pub fn from_observed(
        route: ConfigurationRoute,
        count: usize,
        raw360: u64,
        raw368: u64,
    ) -> Option<Self> {
        let result = Self {
            magic: MAGIC,
            route: route.raw(),
            raw360,
            raw368,
            count: count as u64,
            reserved: [0; 3],
        };
        result.validate(route, count).then_some(result)
    }

    /// F7 raw instructions read words at +360,+362,+368, then access widths
    /// 2,2,4; the final port is +4 from the +368 register's value. Reject a
    /// disabled/overflowed route rather than accidentally authorizing port 0.
    pub fn ranges(self) -> Option<[(u16, u32); 3]> {
        let first = self.raw360 as u16;
        let second = (self.raw360 >> 16) as u16;
        let third_base = self.raw368 as u16;
        let third = third_base.checked_add(4)?;
        if first == 0
            || second == 0
            || third_base == 0
            || u32::from(first) + 2 > 65536
            || u32::from(second) + 2 > 65536
            || u32::from(third) + 4 > 65536
        {
            return None;
        }
        let ranges = [(first, 2), (second, 2), (third, 4)];
        // The configuration handler can execute selector DWORD cycles at CF8.
        // A platform route must never alias those independently owned ports.
        if ranges
            .iter()
            .any(|&(base, bytes)| u32::from(base) < 0xd00 && 0xcf8 < u32::from(base) + bytes)
        {
            return None;
        }
        Some(ranges)
    }

    pub fn validate(self, route: ConfigurationRoute, count: usize) -> bool {
        self.magic == MAGIC
            && self.route == route.raw()
            && self.count == count as u64
            && (2..=super::MAX_RESIDENT_CPUS).contains(&count)
            && self.reserved == [0; 3]
            && self.ranges().is_some()
    }

    pub fn matches_observation(self, raw360: u64, raw368: u64) -> bool {
        // Only captured routing words matter; adjacent status/reserved fields
        // need not remain identical and are not assigned invented semantics.
        self.raw360 as u32 == raw360 as u32 && self.raw368 as u16 == raw368 as u16
    }

    pub fn install(self, iopm: &mut Iopm) -> bool {
        let Some(ranges) = self.ranges() else {
            return false;
        };
        ranges
            .into_iter()
            .all(|(base, bytes)| iopm.set_range(base, bytes, Permission::Intercept).is_ok())
    }

    pub fn installed(self, iopm: &Iopm) -> bool {
        self.ranges().is_some_and(|ranges| {
            ranges.into_iter().all(|(base, bytes)| {
                (u32::from(base)..u32::from(base) + bytes)
                    .all(|port| iopm.bytes()[port as usize / 8] & (1 << (port & 7)) != 0)
            })
        })
    }
}

const _: () = {
    assert!(
        super::control::CONTROL_MANIFEST_OFFSET
            + core::mem::size_of::<super::control::ControlManifest>() as u64
            <= PLATFORM_IO_OFFSET
    );
    assert!(PLATFORM_IO_OFFSET + core::mem::size_of::<PlatformIo>() as u64 <= 4096);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::msr::{TARGET_PHYSICAL_BITS, TARGET_SIGNATURE};

    #[test]
    fn observed_power_routes_are_intercepted_byte_for_byte_and_drift_refuses() {
        let route =
            ConfigurationRoute::admit_target(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, 0xe0000021)
                .unwrap();
        let state = PlatformIo::from_observed(route, 24, 0x0404_0400, 0x0420).unwrap();
        assert_eq!(state.ranges(), Some([(0x400, 2), (0x404, 2), (0x424, 4)]));
        let mut io = Iopm::new();
        io.set_range(0, 65536, Permission::Allow).unwrap();
        assert!(!state.installed(&io));
        assert!(state.install(&mut io));
        assert!(state.installed(&io));
        assert!(state.matches_observation(0xffff_ffff_0404_0400, 0xabcd_0000_0000_0420));
        assert!(!state.matches_observation(0x0404_0401, 0x0420));
        assert!(!state.validate(route, 2));
        io.set_range(0x426, 1, Permission::Allow).unwrap();
        assert!(!state.installed(&io));
        for (raw360, raw368) in [
            (0, 0x420),
            (0x0404_0400, 0),
            (0x0404_ffff, 0x420),
            (0x0404_0400, 0xfff9),
            (0x0404_0cf7, 0x420),
            (0x0cf8_0400, 0x420),
            (0x0404_0cff, 0x420),
            (0x0404_0400, 0xcf1),
            (0x0404_0400, 0xcf4),
            (0x0404_0400, 0xcfb),
        ] {
            assert!(PlatformIo::from_observed(route, 24, raw360, raw368).is_none());
        }
        assert!(PlatformIo::from_observed(route, 24, 0x0d00_0cf6, 0xcf0).is_some());
        assert!(PlatformIo::from_observed(route, 24, 0x0404_0400, 0xcfc).is_some());
    }

    #[test]
    fn unrelated_windows_cannot_claim_chipset_mmio() {
        for (base, bytes) in [
            (FCH_CONTROL_PAGE, 4096),
            (FCH_CONTROL_PAGE - 4096, 4097),
            (FCH_CONTROL_PAGE + 4095, 1),
            (FCH_CONTROL_PAGE, 0x4000),
            (FCH_CONTROL_PAGE, 0x80000),
            (0xfed0_0000, 0x100000),
            (0, 0),
            (u64::MAX - 7, 8),
        ] {
            assert!(!outside_control_page(base, bytes));
        }
        assert!(outside_control_page(FCH_CONTROL_PAGE - 4096, 4096));
        assert!(outside_control_page(FCH_CONTROL_PAGE + 4096, 4096));
    }
}
