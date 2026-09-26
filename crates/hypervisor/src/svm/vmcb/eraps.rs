//! Native ERAPS configuration and one-entry return-predictor clearing.
//!
//! APM2 rev3.44 sections 3.2.9 and 15.37.2, physical pages 132, 686-687;
//! Table B-1, physical page 802. The bits share the 058h control word with
//! ASID and TLB_CONTROL, but occupy a separate byte at 05Dh.

use super::Vmcb;

const ERAP_CONTROL: usize = 0x05d;
const ALLOW_LARGER_RAP: u8 = 1;
const CLEAR_RAP: u8 = 2;
const ERAPS_LEAF: u32 = 0x8000_0021;
const ERAPS_FEATURE: u32 = 1 << 24;

impl Vmcb {
    /// Configure a new native-CPUID guest before its first entry on this CPU.
    /// Both arguments must come from this same CPU's CPUID: extended maximum
    /// leaf and Fn80000021.EAX (zero when the leaf is unavailable). Hardware
    /// selects the native RAP size; it is not hard-coded to one Zen revision.
    /// Unsupported CPUs retain their reserved bits and original state.
    ///
    /// The initial clear separates this guest from any previous guest RAP
    /// contents on the CPU. Later native MOV CR3/INVPCID and other implicit
    /// invalidations execute their hardware RAP effects directly. Software
    /// emulation of such effects must call `request_guest_rap_clear` instead.
    pub fn configure_native_eraps(&mut self, max_extended_leaf: u32, features: u32) -> bool {
        if max_extended_leaf < ERAPS_LEAF || features & ERAPS_FEATURE == 0 {
            return false;
        }
        self.bytes[ERAP_CONTROL] |= ALLOW_LARGER_RAP | CLEAR_RAP;
        // ERAP_CONTROL has no group assigned in the documented clean-bit
        // layout. These rare control changes conservatively invalidate all.
        self.invalidate_all();
        true
    }

    /// Preserve an emulated architectural guest RAP-clear effect until entry.
    /// This includes target-owned INIT, emulated paging-mode transitions and
    /// intercepted MTRR writes (APM2 3.2.9 and 5.5.3, physical pp132,221-222).
    /// Call only when the operation commits; a rejected instruction has no
    /// predictor effect. Monitor-only NPT changes are not guest context changes.
    ///
    /// The ALLOW_LARGER_RAP bit is installed only after same-CPU admission, so
    /// inert/unsupported VMCBs never acquire a reserved CLEAR_RAP bit. This
    /// owner has no nested guests: a future L1/L2 transition must explicitly
    /// request clearing because guest RAP entries are not separated by ASID.
    pub(crate) fn request_guest_rap_clear(&mut self) {
        if self.bytes[ERAP_CONTROL] & ALLOW_LARGER_RAP != 0
            && self.bytes[ERAP_CONTROL] & CLEAR_RAP == 0
        {
            self.bytes[ERAP_CONTROL] |= CLEAR_RAP;
            self.invalidate_all();
        }
    }

    /// Apply the implicit invalidation effect of a committed cache-MSR write.
    /// MTRRs and IORRs implicitly invalidate translations (APM2 physical pages
    /// 222 and 591), so emulating their writes also owes a guest RAP clear.
    /// The instruction owner must call only after a successful WRMSR, including
    /// same-value writes. Reads and rejected writes never reach this method.
    ///
    /// SYS_CFG visibility changes and monitor NPT maintenance are separate
    /// operations; the manuals do not assign them this architectural effect.
    /// PAT executes directly in the native guest and is not emulated here.
    #[cfg_attr(not(feature = "resident-runtime"), allow(dead_code))]
    pub(crate) fn request_rap_clear_after_cache_msr_write(&mut self, index: u32) {
        if matches!(
            index,
            0x200..=0x20f | 0x250 | 0x258..=0x259 | 0x268..=0x26f | 0x2ff
                | 0xc001_0016..=0xc001_0019
        ) {
            self.request_guest_rap_clear();
        }
    }

    /// Consume the RAP-clear request submitted to the preceding valid entry.
    /// Hardware does not make this a one-shot control; leaving it set would
    /// clear the guest RAP on every VMRUN. Invalid entry retains the request.
    ///
    /// # Safety
    /// The caller must establish an actual VMRUN/VMEXIT on this exclusively
    /// owned VMCB on its owning CPU. Call before INIT, emulation, trial-state
    /// restoration or any other post-exit operation can request a new clear.
    /// Inert exit fields alone do not establish that an entry happened.
    pub unsafe fn consume_rap_clear_after_exit(&mut self) {
        if matches!(self.exit_snapshot().code, u64::MAX | 0xffff_ffff) {
            return;
        }
        if self.bytes[ERAP_CONTROL] & (ALLOW_LARGER_RAP | CLEAR_RAP) == ALLOW_LARGER_RAP | CLEAR_RAP
        {
            self.bytes[ERAP_CONTROL] &= !CLEAR_RAP;
            self.invalidate_all();
        }
    }
}

#[cfg(test)]
mod tests;
