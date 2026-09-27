//! Guest-owned MCAX machine-check MSRs on the admitted native target.
//!
//! APM2 rev3.44 15.11 p518/Table 15-8: the MSRPM covers 0000_0000h-1FFFh,
//! C000_0000h-1FFFh and C001_0000h-1FFFh, and "any attempt to read or write
//! an MSR not covered by the MSRPM will automatically cause an intercept".
//! PPR57896 rev3.00 3.1.2.2.4 p300-301/Table 23 places the MCAX banks at
//! MSRC000_2[3FF:000] (64 banks of 16 registers), outside every covered
//! range, so each access exits although the legacy aliases (0400h-047Fh) run
//! natively (`Msrpm::native_boot`). The guest owns machine-check state (no
//! #MC intercept), so the runtime repeats the access on the same CPU.
//!
//! The host must not fault. PPR p300: unimplemented and unused registers in
//! this space are RAZ/WRIG, and bank 4 is always RAZ/WRIG. PPR 3.1.2.3 p301
//! and HWCR p203 give the one #GP:
//! a non-zero write to an implemented MCA_STATUS while McStatusWrEn is 0.
//! PPR p307 bounds visible banks with MCG_CAP.Count and identifies an
//! unpopulated bank by MCA_IPID.HardwareID == 0. The runtime supplies that
//! same-CPU bank identity; the 64-bank address window alone does not imply
//! implementation. Table 23 labels register offset 7 "Reserved", without an
//! access contract. That offset in a populated bank remains unsupported and
//! never reaches hardware. The full unused-bank RAZ/WRIG rule still takes
//! precedence. MSRC000_2[FFF:400] is reserved and stays stopped.

pub(crate) const FIRST: u32 = 0xc000_2000;
pub(crate) const LAST: u32 = 0xc000_23ff;
/// PPR57896 rev3.00 p123: MCG_CAP.Count occupies bits 7:0 and is per core.
pub const MCG_CAP: u32 = 0x179;
/// PPR57896 rev3.00 p301, Table 23: each bank's identification register.
pub const IPID_OFFSET: u32 = 5;
/// Register offsets within a bank (Table 23 p301).
const STATUS: u32 = 1;
const RESERVED: u32 = 7;
const UNUSED_BANK: u32 = 4;

/// Whether this same-CPU bank identity permits the MCA_STATUS write rule.
///
/// PPR57896 rev3.00 p307: visible banks are 0..MCG_CAP.Count, with
/// MCA_IPID.HardwareID == 0 identifying an unpopulated RAZ/WRIG bank.
/// HardwareID is bits 43:32 (p321); writable instance identifiers and the
/// MCA type do not indicate presence. Bank 4 is unconditionally RAZ/WRIG
/// (p300), including when inconsistent identification data is supplied.
///
/// This is exact-target evidence, not a generic legacy-MCA discovery rule.
/// Every populated block in PPR57896 rev3.00 Tables 35-36 (pp311-312) has
/// CONFIG.McaX bit 0 read-only, reset 1: LS/IF/L2/DE/EX/FP/L3 at
/// pp320/331/339/348/356/364/374; CS/PIE/UMC/MP5/NBIO/KPX_SERDES/KPX_GMI/
/// PCS_GMI at pp386/395/403/413/421/429/438/450. Hence the p307 IPID
/// prerequisite holds on the admitted target; an arbitrary legacy bank
/// cannot be declared unused solely because its IPID read returned zero.
pub fn bank_implemented(index: u32, mcg_cap: u64, ipid: u64) -> bool {
    if !(FIRST..=LAST).contains(&index) {
        return false;
    }
    let bank = (index - FIRST) >> 4;
    bank != UNUSED_BANK && bank < (mcg_cap & 0xff) as u32 && (ipid >> 32) & 0xfff != 0
}

/// What the runtime does for one intercepted access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// RDMSR on this CPU; the value completes the instruction.
    Read,
    /// Complete the RDMSR with zero, or drop the WRMSR; no hardware access.
    ReadZeroIgnoreWrite,
    /// WRMSR of this value on this CPU.
    Write(u64),
    /// Queue #GP(0) at the unchanged RIP; no hardware access.
    GeneralProtection,
}

/// `None`: outside the MCAX window or a populated bank's reserved offset.
/// `write` is the WRMSR EDX:EAX, `status_writable` this CPU's HWCR.McStatusWrEn,
/// and `implemented` is the result of [`bank_implemented`] using
/// identification from that same CPU.
pub fn plan(
    index: u32,
    write: Option<u64>,
    status_writable: bool,
    implemented: bool,
) -> Option<Access> {
    if !(FIRST..=LAST).contains(&index) {
        return None;
    }
    if !implemented || (index - FIRST) >> 4 == UNUSED_BANK {
        return Some(Access::ReadZeroIgnoreWrite);
    }
    if index & 0xf == RESERVED {
        return None;
    }
    Some(match write {
        None => Access::Read,
        Some(value) if index & 0xf == STATUS && value != 0 && !status_writable => {
            Access::GeneralProtection
        }
        Some(value) => Access::Write(value),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_64_bank_window_is_owned_and_only_status_can_fault() {
        for index in [0xc000_1fff, 0xc000_2400, 0xc000_2fff, 0x401] {
            assert_eq!(plan(index, None, false, true), None);
            assert_eq!(plan(index, Some(0), true, false), None);
        }
        assert_eq!(plan(FIRST, None, false, true), Some(Access::Read));
        assert_eq!(plan(LAST, Some(u64::MAX), false, true), Some(Access::Write(u64::MAX)));
        // Windows enables bank 0 with all ones and clears STATUS with zero.
        assert_eq!(plan(0xc000_2000, Some(u64::MAX), false, true), Some(Access::Write(u64::MAX)));
        assert_eq!(plan(0xc000_2001, Some(0), false, true), Some(Access::Write(0)));
        assert_eq!(plan(0xc000_23f1, Some(1 << 63), false, true), Some(Access::GeneralProtection));
        assert_eq!(plan(0xc000_23f1, Some(1 << 63), true, true), Some(Access::Write(1 << 63)));
        for write in [None, Some(u64::MAX)] {
            assert_eq!(plan(0xc000_2007, write, true, true), None);
        }
        // DESTAT (offset 8) is plain read-write (PPR p323).
        assert_eq!(plan(0xc000_2008, Some(1), false, true), Some(Access::Write(1)));
    }

    #[test]
    fn bank_identity_uses_count_and_hardware_id_not_the_full_ipid() {
        let ls = 0xb0_u64 << 32;
        let writable_instance_and_type = (0xffff_u64 << 48) | (0xf_u64 << 44) | 0xffff_ffff;
        assert!(bank_implemented(FIRST, 1, ls));
        assert!(!bank_implemented(FIRST, 0, ls));
        assert!(!bank_implemented(FIRST + 0x10, 1, ls));
        assert!(bank_implemented(FIRST + 0x10, 2, ls));
        assert!(!bank_implemented(FIRST, 64, writable_instance_and_type));
        assert!(bank_implemented(FIRST, 64, ls | writable_instance_and_type));
        // MCG_CAP feature bits above Count must not create additional banks.
        assert!(!bank_implemented(FIRST, 1 << 8, ls));
        assert!(!bank_implemented(FIRST + 0x40, 64, ls));
        assert!(bank_implemented(LAST, 64, ls));
        assert!(!bank_implemented(LAST, 63, ls));
        for index in [FIRST - 1, LAST + 1, u32::MAX] {
            assert!(!bank_implemented(index, u64::MAX, u64::MAX));
        }
    }

    #[test]
    fn unused_banks_ignore_nonzero_status_before_applying_write_enable() {
        for (index, count, ipid) in [
            (FIRST + 0x40, 64, 0xb0_u64 << 32), // Bank 4 is always unused.
            (FIRST + 0x70, 7, 0xb0_u64 << 32),  // Outside this CPU's Count.
            (FIRST + 0x70, 8, 0),               // Unpopulated within Count.
        ] {
            let implemented = bank_implemented(index, count, ipid);
            assert!(!implemented);
            for offset in 0..16 {
                for write in [None, Some(0), Some(1), Some(u64::MAX)] {
                    for writable in [false, true] {
                        assert_eq!(
                            plan(index + offset, write, writable, implemented),
                            Some(Access::ReadZeroIgnoreWrite)
                        );
                    }
                }
            }
        }
        // Even a caller passing an inconsistent identity cannot make bank 4 fault.
        assert_eq!(plan(FIRST + 0x41, Some(1), false, true), Some(Access::ReadZeroIgnoreWrite));
    }
}
