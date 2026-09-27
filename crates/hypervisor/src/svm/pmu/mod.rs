//! Core performance-counter selector ownership for the reviewed native AMD CPU.
//!
//! The logical selectors belong to the guest; hardware selectors qualify counting
//! against the guest's logical EFER rather than the mandatory physical SVME bit.
//! This execution owner never enters an L2 guest, so an SVME-enabled guest is a
//! virtual host. A nested execution owner would need a different mode policy.
//!
//! Counters, RDPMC, global control/status and overflow delivery remain hardware
//! owned by this same guest on this same CPU. No counter values are synthesized.
//! The resident host must not use these counters or change the physical selectors.

use crate::arch::x86_64::msr::{
    EFER_SVME, PERF_CTL_DEFINED, PERF_CTL_EN, PERF_CTL_EVENT_SELECT, PERF_CTL_GUEST_ONLY,
    PERF_CTL_HOST_GUEST_ONLY, PERF_CTL_PRECISE_RETIRE, PERF_CTL0, PERF_LEGACY_CTL0,
    TARGET_SIGNATURE,
};

#[cfg(test)]
mod tests;

/// PPR 57896 physical page 118: NumPerfCtrCore is six on this processor.
pub const CONTROL_COUNT: usize = 6;

const LEGACY_CONTROL_COUNT: usize = 4;
const PERF_CTR_EXT_CORE: u32 = 1 << 23;
const PMC2_PRECISE_RETIRE: u32 = 1 << 12;
const PERF_MON_V2: u32 = 1;
const CORE_COUNTER_COUNT_MASK: u32 = 0xf;
const PRECISE_COUNTER: usize = 2;
const MERGE_CONTROL: u64 = PERF_CTL_EVENT_SELECT | PERF_CTL_EN;

/// Guest-visible controls captured after capability admission on the owning CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PmuState {
    controls: [u64; CONTROL_COUNT],
}

impl PmuState {
    /// Preserve native readback, including reserved fields, without touching HW.
    ///
    /// The capture must occur on the CPU admitted by `profile` immediately before
    /// exclusive selector ownership begins. Returning to firmware between capture
    /// and ownership would permit the native values to change underneath it.
    pub const fn new(_profile: PmuProfile, controls: [u64; CONTROL_COUNT]) -> Self {
        Self { controls }
    }

    /// Read either architectural alias from its single logical control value.
    pub fn read(&self, msr: u32) -> Option<u64> {
        Some(self.controls[control_index(msr)?])
    }

    /// Prepare a selector write without changing the logical or physical state.
    ///
    /// PPR 57896 physical page 26 requires reserved fields to be written as read.
    /// An unreviewed reserved-field change returns `None`; that is an unsupported
    /// access, not architectural evidence for injecting #GP. Event selection and
    /// unit-mask combinations otherwise retain the CPU's own counting behavior.
    pub fn prepare_write(&self, msr: u32, value: u64, logical_efer: u64) -> Option<PmuWritePlan> {
        let index = control_index(msr)?;
        let previous = self.controls[index];
        if (value ^ previous) & !defined_control(index) != 0 {
            return None;
        }
        Some(PmuWritePlan {
            index,
            previous,
            logical: value,
            effective: effective_control(index, value, logical_efer),
        })
    }

    /// Commit only a plan that still refers to this selector's current value.
    ///
    /// The runtime validates instruction continuation before this operation, then
    /// programs the physical selector. It must not resume between the two commits.
    pub fn commit_write(&mut self, plan: PmuWritePlan) -> Result<(), PmuError> {
        if self.controls[plan.index] != plan.previous {
            return Err(PmuError::StaleWritePlan);
        }
        self.controls[plan.index] = plan.logical;
        Ok(())
    }

    /// Recompute backing after every logical EFER change, including INIT.
    pub fn effective_control(&self, index: usize, logical_efer: u64) -> Option<u64> {
        Some(effective_control(index, *self.controls.get(index)?, logical_efer))
    }
}

/// Same-CPU CPUID observations, obtained only from enumerated CPUID leaves.
///
/// The caller independently establishes AMD vendor identity. A missing leaf must
/// not be replaced with the CPU's response to an out-of-range CPUID request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PmuEvidence {
    pub signature: u32,
    pub extended01_ecx: u32,
    pub extended21_eax: u32,
    pub extended22_eax: u32,
    pub extended22_ebx: u32,
}

/// Capability admission token, required before capturing selector MSRs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PmuProfile {
    _admitted: (),
}

impl PmuProfile {
    /// Admit the exact CPU and core-PMU layout reviewed in PPR 57896 rev. 3.00.
    pub fn admit(evidence: PmuEvidence) -> Option<Self> {
        // 57896-3.00_PPR pp87,117,118: six extended counters, precise-retire
        // support on counter 2 and the native PerfMonV2 global controls.
        if evidence.signature != TARGET_SIGNATURE
            || evidence.extended01_ecx & PERF_CTR_EXT_CORE == 0
            || evidence.extended21_eax & PMC2_PRECISE_RETIRE == 0
            || evidence.extended22_eax & PERF_MON_V2 == 0
            || evidence.extended22_ebx & CORE_COUNTER_COUNT_MASK != CONTROL_COUNT as u32
        {
            return None;
        }
        Some(Self { _admitted: () })
    }
}

/// A validated write, including the old value that must still own the selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PmuWritePlan {
    index: usize,
    previous: u64,
    logical: u64,
    effective: u64,
}

impl PmuWritePlan {
    pub const fn index(self) -> usize {
        self.index
    }

    /// The extended selector alias used for the single physical write.
    pub const fn msr(self) -> u32 {
        PERF_CTL0 + self.index as u32 * 2
    }

    pub const fn logical(self) -> u64 {
        self.logical
    }

    pub const fn effective(self) -> u64 {
        self.effective
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PmuError {
    StaleWritePlan,
}

/// Decode all six extended selectors and the first four legacy aliases.
pub const fn control_index(msr: u32) -> Option<usize> {
    if msr >= PERF_LEGACY_CTL0 && msr < PERF_LEGACY_CTL0 + LEGACY_CONTROL_COUNT as u32 {
        return Some((msr - PERF_LEGACY_CTL0) as usize);
    }
    if msr >= PERF_CTL0 && msr < PERF_CTL0 + CONTROL_COUNT as u32 * 2 {
        let offset = msr - PERF_CTL0;
        if offset & 1 == 0 {
            return Some((offset / 2) as usize);
        }
    }
    None
}

/// Return only implemented selector indices, never a counter or an adjacent MSR.
pub const fn control_msr(index: usize) -> Option<u32> {
    if index < CONTROL_COUNT { Some(PERF_CTL0 + index as u32 * 2) } else { None }
}

fn defined_control(index: usize) -> u64 {
    // 57896-3.00_PPR pp218,222: CntMask[7] is reserved on this target;
    // PreciseRetire is defined only on PERF_CTL2, including its legacy alias.
    PERF_CTL_DEFINED | if index == PRECISE_COUNTER { PERF_CTL_PRECISE_RETIRE } else { 0 }
}

fn effective_control(index: usize, logical: u64, logical_efer: u64) -> u64 {
    // 57896-3.00_PPR p256: the odd merge helper must be event FFF + EN,
    // with every other bit zero. The paired even selector filters its events.
    if index & 1 != 0 && logical == MERGE_CONTROL {
        return logical;
    }
    let filter = logical & PERF_CTL_HOST_GUEST_ONLY;
    // 24593_3.44_APM_Vol2 p477, Table 13-4: any HG bit requires SVME=1.
    // With SVME=1 this execution owner is a virtual host, never an L2 guest.
    let suppressed =
        if logical_efer & EFER_SVME == 0 { filter != 0 } else { filter == PERF_CTL_GUEST_ONLY };
    let effective = (logical & !PERF_CTL_HOST_GUEST_ONLY) | PERF_CTL_GUEST_ONLY;
    if suppressed { effective & !PERF_CTL_EN } else { effective }
}
