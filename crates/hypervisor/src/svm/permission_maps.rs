//! SVM permission-map contents, from AMD APM vol. 2 rev. 3.44, chapter 15
//! (I/O intercepts and MSR permissions, table 15-8). A set bit intercepts access.
//!
//! These values supply aligned storage, not physical allocation, WB mappings,
//! or a live VMCB. IOIO_PROT/MSR_PROT must also be enabled by the caller.

use crate::{
    arch::x86_64::msr::{EFER, TSC_RATIO},
    svm::control_msrs::{SMM_ADDR, SMM_BASE, SMM_MASK},
};

pub const IOPM_BYTES: usize = 12 * 1024;
pub const MSRPM_BYTES: usize = 8 * 1024;

/// One bit per byte-wide port. The three architectural overrun bits and all
/// remaining padding stay intercepted, including for I/O crossing port 65535.
#[repr(C, align(4096))]
pub struct Iopm {
    bytes: [u8; IOPM_BYTES],
}

impl Iopm {
    pub const fn new() -> Self {
        Self { bytes: [0xff; IOPM_BYTES] }
    }

    pub const fn bytes(&self) -> &[u8; IOPM_BYTES] {
        &self.bytes
    }

    /// Set a contiguous number of byte-wide ports. This count describes a port
    /// range, not an instruction operand width. Invalid ranges change no bits.
    pub fn set_range(
        &mut self,
        first_port: u16,
        port_count: u32,
        permission: Permission,
    ) -> Result<(), PermissionMapError> {
        if port_count == 0 {
            return Err(PermissionMapError::EmptyIoRange);
        }
        let first = u32::from(first_port);
        if port_count > 65536 - first {
            return Err(PermissionMapError::IoRangeOutsidePorts);
        }
        for port in first..first + port_count {
            set_bit(&mut self.bytes, port as usize, permission);
        }
        Ok(())
    }
}

impl Default for Iopm {
    fn default() -> Self {
        Self::new()
    }
}

/// Two bits per covered MSR, read then write. The final 2 KiB are reserved and
/// always remain set. Unsupported MSRs intercept when MSR_PROT is enabled.
#[repr(C, align(4096))]
pub struct Msrpm {
    bytes: [u8; MSRPM_BYTES],
}

impl Msrpm {
    pub const fn new() -> Self {
        Self { bytes: [0xff; MSRPM_BYTES] }
    }

    /// Trusted native first boot: execute covered native MSRs directly except
    /// EFER and monitor/SVM controls. APM2 rev3.44 15.11/Table15-8 and 15.30.
    /// Protect C00101xx by default, including VM_CR, VM_HSAVE_PA, lock keys
    /// and encrypted-guest controls. OSVW accesses and SMRAM configuration reads
    /// stay native. Activation requires the exact target CPU and locked SMRAM
    /// admitted by HsaveAddressPolicy; this map does not establish that evidence.
    /// TSC_RATIO accesses use guest-owned register state; physical scaling stays
    /// at unity. Nested scaling remains unsupported. Other intercepted indices
    /// need their own emulation owners; out-of-map indices intercept in hardware.
    /// Requires the native VMCB intercept profile; not a sandbox MSR policy.
    pub fn native_boot() -> Self {
        let mut map = Self::new();
        map.bytes[..0x1800].fill(0);
        // Express the policy in MSR indices; `set` owns the byte/bit layout.
        // C0010100..C00101ff occupies bytes 0x1040..0x1080 (end exclusive).
        for index in [EFER, TSC_RATIO].into_iter().chain(0xc001_0100..=0xc001_01ff) {
            for access in [MsrAccess::Read, MsrAccess::Write] {
                map.set(index, access, Permission::Intercept).expect("covered monitor MSR");
            }
        }
        // PPR57896 rev3.00 pp.87/217: advertised OSVW length/status are RW
        // hardware state, not monitor controls. Preserve firmware values and
        // native write/fault semantics; do not synthesize workaround metadata.
        for index in [0xc001_0140, 0xc001_0141] {
            for access in [MsrAccess::Read, MsrAccess::Write] {
                map.set(index, access, Permission::Allow).expect("covered OSVW MSR");
            }
        }
        // 57896-3.00_PPR physical pp213-215: these firmware-owned registers
        // remain readable with SmmLock set. The monitor does not modify them;
        // let hardware return its native values without an unowned MSR exit.
        // Writes and every other protected SMM/SVM control remain intercepted.
        for index in [SMM_BASE, SMM_ADDR, SMM_MASK] {
            map.set(index, MsrAccess::Read, Permission::Allow).expect("covered SMRAM MSR");
        }
        // Physical cache/routing controls remain permanently host-owned;
        // both reads and writes use the core-shared logical cache bank.
        for index in (0x200..=0x20f)
            .chain(crate::svm::cache_policy::FIXED_MSRS)
            .chain([0xfe, 0x2ff, 0xc0010010, 0xc001001a, 0xc001001d])
            .chain(0xc0010016..=0xc0010019)
        {
            for access in [MsrAccess::Read, MsrAccess::Write] {
                map.set(index, access, Permission::Intercept).expect("covered cache MSR");
            }
        }
        map
    }

    pub const fn bytes(&self) -> &[u8; MSRPM_BYTES] {
        &self.bytes
    }

    /// Change only the selected read or write bit. Unsupported MSRs leave the
    /// complete map unchanged.
    pub fn set(
        &mut self,
        msr: u32,
        access: MsrAccess,
        permission: Permission,
    ) -> Result<(), PermissionMapError> {
        let (byte_base, index) = match msr {
            0x0000_0000..=0x0000_1fff => (0x0000, msr),
            0xc000_0000..=0xc000_1fff => (0x0800, msr - 0xc000_0000),
            0xc001_0000..=0xc001_1fff => (0x1000, msr - 0xc001_0000),
            _ => return Err(PermissionMapError::UnsupportedMsr),
        };
        let access_bit = match access {
            MsrAccess::Read => 0,
            MsrAccess::Write => 1,
        };
        // APM2 rev3.44 section 15.11/Table 15-8 (24593_3.44_APM_Vol2 p580):
        // four MSRs per byte, with read then write in each pair. `set_bit`
        // divides this absolute bit offset by 8, giving byte_base + index / 4
        // and bit 2 * (index % 4) + access_bit for every covered index.
        let bit = byte_base * 8 + index as usize * 2 + access_bit;
        set_bit(&mut self.bytes, bit, permission);
        Ok(())
    }
}

impl Default for Msrpm {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    Allow,
    Intercept,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsrAccess {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionMapError {
    EmptyIoRange,
    IoRangeOutsidePorts,
    UnsupportedMsr,
}

fn set_bit(bytes: &mut [u8], bit: usize, permission: Permission) {
    let mask = 1 << (bit % 8);
    let byte = &mut bytes[bit / 8];
    match permission {
        Permission::Allow => *byte &= !mask,
        Permission::Intercept => *byte |= mask,
    }
}
