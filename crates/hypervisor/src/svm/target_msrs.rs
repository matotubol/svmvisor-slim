//! Bounded MSR access contracts for the admitted native AMD target.
//!
//! This policy classifies only accesses whose outcome is documented. An MSRPM
//! intercept or a missing PPR entry is not evidence that an MSR is unimplemented.
//! `None` therefore preserves the caller's unsupported-access handling.
//!
//! Callers must validate the stopped instruction boundary and the classic,
//! non-SEV VMCB profile before applying a plan. In particular, VIRTUAL_TOM and
//! Secure AVIC may be accessible in encrypted guest modes that this policy does
//! not admit. No plan reads or writes a physical MSR.

use crate::arch::x86_64::msr::TARGET_SIGNATURE;

use super::control_msrs::{SMM_ADDR, SMM_BASE, SMM_MASK};

pub const SMM_CTL: u32 = 0xc001_0116;
pub const SMM_KEY: u32 = 0xc001_0119;
pub const AVIC_DOORBELL: u32 = 0xc001_011b;
pub const VIRTUAL_TOM: u32 = 0xc001_0135;
pub const SECURE_AVIC: u32 = 0xc001_0138;

const NO_SMM_CTL_MSR: u32 = 1 << 9;
const SMM_BASE_DEFINED: u64 = 0x0000_0000_ffff_ffff;
const SMM_ADDR_DEFINED: u64 = 0x0000_ffff_fffe_0000;
const SMM_MASK_DEFINED: u64 = SMM_ADDR_DEFINED | 0x773f;

/// A documented architectural outcome, without any instruction-state mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    GeneralProtection,
    ReadZero,
    IgnoreWrite,
}

/// Same-CPU firmware observations taken before activating the native profile.
///
/// SmmLock must remain set. The profile intercepts all SMM_KEY and SMRAM writes
/// and admits no operation that unlocks SMM; a processor RESET requires fresh
/// admission. Firmware must retain these reserved fields. This evidence does not
/// authorize encrypted guests, migration, or arbitrary native MSR forwarding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetMsrPolicy {
    no_smm_ctl: bool,
    smm_base_reserved: u64,
    smm_addr_reserved: u64,
    smm_mask_reserved: u64,
}

impl TargetMsrPolicy {
    /// Admit only the reviewed CPU and already-locked firmware SMM configuration.
    /// Capture MSRs only after independently establishing the exact target CPU.
    pub fn admit(
        signature: u32,
        extended21_eax: Option<u32>,
        hwcr: u64,
        smm_base: u64,
        smm_addr: u64,
        smm_mask: u64,
    ) -> Option<Self> {
        if signature != TARGET_SIGNATURE || hwcr & 1 == 0 {
            return None;
        }
        Some(Self {
            // 57896-3.00_PPR p117: Fn80000021.EAX[9] explicitly says that
            // SMM_CTL is not present. Missing evidence does not establish this.
            no_smm_ctl: extended21_eax.is_some_and(|eax| eax & NO_SMM_CTL_MSR != 0),
            smm_base_reserved: smm_base & !SMM_BASE_DEFINED,
            smm_addr_reserved: smm_addr & !SMM_ADDR_DEFINED,
            smm_mask_reserved: smm_mask & !SMM_MASK_DEFINED,
        })
    }

    /// Classify an RDMSR (`write == None`) or WRMSR (`Some(EDX:EAX)`).
    ///
    /// The caller must first prove a classic, non-SEV VMCB and a valid MSR
    /// instruction boundary. CPL faults take precedence over a successful plan.
    pub fn plan(&self, index: u32, write: Option<u64>) -> Option<Access> {
        match (index, write) {
            // 24593_3.44_APM_Vol2 p646 and 57896-3.00_PPR p117 establish
            // absence, not merely a read/write permission on an existing MSR.
            (SMM_CTL, _) if self.no_smm_ctl => Some(Access::GeneralProtection),
            // 57896-3.00_PPR p216: Write-only, Error-on-read. A legitimate
            // doorbell write has side effects and needs its own owner.
            (AVIC_DOORBELL, None) => Some(Access::GeneralProtection),
            // 24593_3.44_APM_Vol2 p669: inactive vTOM accesses raise #GP(0).
            // p682: accesses outside Secure AVIC mode raise #GP(0).
            (VIRTUAL_TOM | SECURE_AVIC, _) => Some(Access::GeneralProtection),
            // 24593_3.44_APM_Vol2 p649: reads are zero. With SmmLock set,
            // only a matching NONZERO key unlocks; zero is always ignored.
            // Nonzero writes cannot be decided from the unreadable firmware key.
            (SMM_KEY, None) => Some(Access::ReadZero),
            (SMM_KEY, Some(0)) => Some(Access::IgnoreWrite),
            // 57896-3.00_PPR pp213-215: defined fields are Read-only while
            // SmmLock is set. p27 defines this as writes ignored; p26 requires
            // reserved fields to be written as read, rather than presumed MBZ.
            (SMM_BASE, Some(value)) if value & !SMM_BASE_DEFINED == self.smm_base_reserved => {
                Some(Access::IgnoreWrite)
            }
            (SMM_ADDR, Some(value)) if value & !SMM_ADDR_DEFINED == self.smm_addr_reserved => {
                Some(Access::IgnoreWrite)
            }
            (SMM_MASK, Some(value)) if value & !SMM_MASK_DEFINED == self.smm_mask_reserved => {
                Some(Access::IgnoreWrite)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locked() -> TargetMsrPolicy {
        TargetMsrPolicy::admit(TARGET_SIGNATURE, Some(NO_SMM_CTL_MSR), 1, 0, 0, 0).unwrap()
    }

    #[test]
    fn admission_requires_the_reviewed_cpu_and_locked_smram() {
        for signature in [0, TARGET_SIGNATURE ^ 1, u32::MAX] {
            assert!(TargetMsrPolicy::admit(signature, Some(u32::MAX), 1, 0, 0, 0).is_none());
        }
        for hwcr in [0, u64::MAX & !1] {
            assert!(
                TargetMsrPolicy::admit(TARGET_SIGNATURE, Some(u32::MAX), hwcr, 0, 0, 0).is_none()
            );
        }
        assert!(TargetMsrPolicy::admit(TARGET_SIGNATURE, None, 1, 0, 0, 0).is_some());
    }

    #[test]
    fn smm_ctl_faults_only_when_absence_is_explicitly_enumerated() {
        for write in [None, Some(0), Some(u64::MAX)] {
            assert_eq!(locked().plan(SMM_CTL, write), Some(Access::GeneralProtection));
            for eax in [None, Some(0), Some(u32::MAX & !NO_SMM_CTL_MSR)] {
                let policy = TargetMsrPolicy::admit(TARGET_SIGNATURE, eax, 1, 0, 0, 0).unwrap();
                assert_eq!(policy.plan(SMM_CTL, write), None);
            }
        }
    }

    #[test]
    fn fault_plans_are_direction_and_guest_mode_specific() {
        let policy = locked();
        assert_eq!(policy.plan(AVIC_DOORBELL, None), Some(Access::GeneralProtection));
        for value in [0, 1, u64::MAX] {
            assert_eq!(policy.plan(AVIC_DOORBELL, Some(value)), None);
        }
        // These two contracts require the caller's classic-guest validation.
        for index in [VIRTUAL_TOM, SECURE_AVIC] {
            for write in [None, Some(0), Some(u64::MAX)] {
                assert_eq!(policy.plan(index, write), Some(Access::GeneralProtection));
            }
        }
    }

    #[test]
    fn unreadable_smm_key_never_authorizes_a_possible_unlock() {
        let policy = locked();
        assert_eq!(policy.plan(SMM_KEY, None), Some(Access::ReadZero));
        assert_eq!(policy.plan(SMM_KEY, Some(0)), Some(Access::IgnoreWrite));
        for bit in 0..64 {
            assert_eq!(policy.plan(SMM_KEY, Some(1 << bit)), None);
        }
        assert_eq!(policy.plan(SMM_KEY, Some(u64::MAX)), None);
    }

    #[test]
    fn locked_smram_defined_fields_are_ignored_but_reserved_fields_must_match() {
        // Deliberately nonzero reserved snapshots ensure this is a write-as-read
        // contract, not an invented zero mask. The normal runtime can admit a
        // stricter firmware profile before building this independent policy.
        let initial = [0xabcd_1234_5678_9abc, 0x9123_4567_89ab_cdef, 0xf123_4567_89ab_cdef];
        let policy = TargetMsrPolicy::admit(
            TARGET_SIGNATURE,
            Some(NO_SMM_CTL_MSR),
            1,
            initial[0],
            initial[1],
            initial[2],
        )
        .unwrap();
        for (index, defined, value) in [
            (SMM_BASE, SMM_BASE_DEFINED, initial[0]),
            (SMM_ADDR, SMM_ADDR_DEFINED, initial[1]),
            (SMM_MASK, SMM_MASK_DEFINED, initial[2]),
        ] {
            assert_eq!(policy.plan(index, None), None);
            assert_eq!(policy.plan(index, Some(value)), Some(Access::IgnoreWrite));
            assert_eq!(policy.plan(index, Some(value ^ defined)), Some(Access::IgnoreWrite));
            for bit in 0..64 {
                if (1 << bit) & defined == 0 {
                    assert_eq!(policy.plan(index, Some(value ^ (1 << bit))), None);
                }
            }
        }
    }

    #[test]
    fn undocumented_neighbors_and_separately_owned_registers_remain_unsupported() {
        let policy = locked();
        for index in [
            0,
            0xffff_ffff,
            0xc001_0100,
            0xc001_0110,
            0xc001_0114,
            0xc001_0115,
            0xc001_0117,
            0xc001_0118,
            0xc001_011a,
            0xc001_011c,
            0xc001_0134,
            0xc001_0136,
            0xc001_0137,
            0xc001_0139,
            0xc001_0140,
            0xc001_0141,
            0xc001_01ff,
        ] {
            for write in [None, Some(0), Some(u64::MAX)] {
                assert_eq!(policy.plan(index, write), None, "MSR {index:#x}");
            }
        }
    }
}
