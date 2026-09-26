//! Native branch-record ownership, APM2 rev3.44 physical pages 602, 807-808.
//!
//! The nonreturning assembly entry freezes and captures the native controls and
//! records into the VMCB before its first VMRUN. Hardware then exchanges legacy
//! records and controls, and saves/restores the guest's sixteen-entry stack.
//! The host leaves recording disabled. INIT retains these MSRs (APM2 p544).

use crate::{arch::x86_64::capabilities::EXTENDED_PERFORMANCE_LEAF, svm::vmcb::Vmcb};

const LBR_CONTROL_OFFSET: usize = 0x0b8;
const LBR_VIRTUALIZATION_ENABLE: u64 = 1;
const LBR_VIRT: u32 = 1 << 1;
const LBR_STACK: u32 = 1 << 1;
const LBR_STACK_COUNT: u32 = 16;

impl Vmcb {
    /// Admit the complete target-sized legacy and stack hardware switch before
    /// first entry. Inputs are same-CPU CPUID evidence: maximum extended leaf,
    /// Fn8000_000A.EDX, Fn8000_0022.EAX and Fn8000_0022.EBX. PPR57896 rev3.00
    /// physical pages 101, 118 calls the last two fields LbrExtV2/LbrV2StackSz.
    /// No native records are synthesized or cleared here; the audited entry
    /// captures them after this final control configuration and before VMRUN.
    ///
    /// The fixed 16-entry admission matches the architectural VMCB stack extent
    /// and prevents a future CPU with more records from silently losing state.
    /// Call after `enable_native_nested_paging`, which admits the cold controls.
    pub fn configure_native_lbr(
        &mut self,
        maximum_extended_leaf: u32,
        svm_features: u32,
        performance_features: u32,
        performance_sizes: u32,
    ) -> bool {
        if maximum_extended_leaf < EXTENDED_PERFORMANCE_LEAF
            || svm_features & LBR_VIRT == 0
            || performance_features & LBR_STACK == 0
            || (performance_sizes >> 4) & 0x3f != LBR_STACK_COUNT
            || self.read_u64::<LBR_CONTROL_OFFSET>() != 0
        {
            return false;
        }
        self.write_u64::<LBR_CONTROL_OFFSET>(LBR_VIRTUALIZATION_ENABLE);
        true
    }

    /// Runtime profile invariant. No VMLOAD/VMSAVE, IBS, or unknown control may
    /// accidentally replace the required automatic branch-record switch.
    pub fn native_lbr_enabled(&self) -> bool {
        self.read_u64::<LBR_CONTROL_OFFSET>() == LBR_VIRTUALIZATION_ENABLE
    }
}

#[cfg(test)]
mod tests;
