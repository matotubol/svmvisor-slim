//! CPU-local ownership of VMCB state caching (APM2 rev3.44 physical pp588-590).
//!
//! Only the ten baseline groups reviewed here are reused. LBR, AVIC, CET and
//! future groups remain dirty; caching them needs their own feature/state audit.

use super::{CLEAN_BITS, Vmcb};

pub(super) const REVIEWED_CLEAN_MASK: u32 = 0x03ff;
const INTERCEPTS: u32 = 1 << 0;
const PERMISSION_MAPS: u32 = 1 << 1;
const ASID: u32 = 1 << 2;
const TPR: u32 = 1 << 3;
const NESTED_PAGING: u32 = 1 << 4;
const CONTROL_REGISTERS: u32 = 1 << 5;
const DEBUG_REGISTERS: u32 = 1 << 6;
const DESCRIPTOR_TABLES: u32 = 1 << 7;
const SEGMENTS: u32 = 1 << 8;
const CR2: u32 = 1 << 9;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    cpu: u32,
    physical: u64,
    storage: usize,
}

/// Separate from the hardware's exact 4-KiB VMCB. No reference survives entry.
/// The owner is not transferable across CPUs without `prepare_entry`, and must
/// be invalidated before reusing a VMCB page for another logical guest.
pub struct VmcbCacheOwner {
    mask: u32,
    completed: Option<Identity>,
    pending: Option<Identity>,
}

impl VmcbCacheOwner {
    pub const fn new() -> Self {
        Self { mask: 0, completed: None, pending: None }
    }

    /// Same-CPU CPUID Fn8000_000A.EDX evidence. Call before `prepare_entry`;
    /// reconfiguration forgets all previous reuse evidence.
    pub fn configure(&mut self, svm_features: u32) {
        self.mask = if svm_features & (1 << 5) != 0 { REVIEWED_CLEAN_MASK } else { 0 };
        self.completed = None;
        self.pending = None;
    }

    /// Final entry boundary, after every host VMCB mutation. A first entry,
    /// changed CPU/address, unsupported CPU or unconsumed prior entry is dirty.
    /// `cpu` and `physical` must come from the caller's established placement;
    /// this byte-only helper does not discover physical addresses or migration.
    pub fn prepare_entry(&mut self, vmcb: &mut Vmcb, cpu: u32, physical: u64) {
        let identity = Identity { cpu, physical, storage: vmcb as *mut Vmcb as usize };
        if physical == 0 || physical & 4095 != 0 {
            self.invalidate(vmcb);
            return;
        }
        if self.mask == 0 || self.completed != Some(identity) || self.pending.is_some() {
            vmcb.invalidate_all();
        }
        self.pending = Some(identity);
    }

    /// Consume the immediately preceding entry before any software state edit.
    /// Invalid entry, shutdown, missing entry or mismatched identity cannot
    /// establish a reusable state cache. Guest execution itself updates cached
    /// state and does not need software dirtying (APM2 p588).
    ///
    /// # Safety
    /// Exactly one actual VMRUN return occurred on this VMCB since the matching
    /// `prepare_entry`. Call once, before trial restoration, event completion,
    /// or any other host mutation. The runtime must prove the physical CPU and
    /// VMCB identity; retained exit bytes alone cannot prove entry execution.
    /// Guest VMSAVE/host VMLOAD may precede this: they transfer FS/GS, TR/LDTR
    /// and syscall state, none of this mask's cached groups (APM2 pp568,589).
    pub unsafe fn after_exit(&mut self, vmcb: &mut Vmcb, cpu: u32, physical: u64) {
        let identity = Identity { cpu, physical, storage: vmcb as *mut Vmcb as usize };
        let pending = self.pending.take();
        if pending != Some(identity)
            || matches!(vmcb.exit_snapshot().code, u64::MAX | 0xffff_ffff | 0x7f)
        {
            self.invalidate(vmcb);
            return;
        }
        self.completed = Some(identity);
        vmcb.set_clean_bits(self.mask);
    }

    /// Page reuse, changed logical guest, or lost entry/placement provenance.
    pub fn invalidate(&mut self, vmcb: &mut Vmcb) {
        self.completed = None;
        self.pending = None;
        vmcb.invalidate_all();
    }
}

impl Default for VmcbCacheOwner {
    fn default() -> Self {
        Self::new()
    }
}

impl Vmcb {
    pub(super) fn set_clean_bits(&mut self, value: u32) {
        self.bytes[CLEAN_BITS..CLEAN_BITS + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Call after changing the contents of a live IOPM/MSRPM, even when its
    /// physical base is unchanged. No flush of guest translations is implied.
    pub fn permission_maps_changed(&mut self) {
        self.dirty_cached_groups(PERMISSION_MAPS);
    }

    fn dirty_cached_groups(&mut self, mask: u32) {
        if mask != 0 {
            self.set_clean_bits(self.read_u32::<CLEAN_BITS>() & REVIEWED_CLEAN_MASK & !mask);
        }
    }

    /// Shared by every typed field writer, so a new setter cannot accidentally
    /// retain a stale group. Unknown fields conservatively invalidate everything.
    /// Direct bulk initialization/trial restoration explicitly invalidate all.
    #[inline(always)]
    pub(super) fn dirty_for_write(&mut self, offset: usize, bytes: usize) {
        self.dirty_cached_groups(write_group(offset, bytes));
    }
}

const fn within(offset: usize, bytes: usize, start: usize, end: usize) -> bool {
    offset >= start && offset < end && bytes <= end - offset
}

#[inline(always)]
const fn write_group(offset: usize, bytes: usize) -> u32 {
    if within(offset, bytes, 0x000, 0x018)
        || within(offset, bytes, 0x03c, 0x040)
        || within(offset, bytes, 0x050, 0x058)
    {
        INTERCEPTS
    } else if within(offset, bytes, 0x040, 0x050) {
        PERMISSION_MAPS
    } else if within(offset, bytes, 0x058, 0x05c) {
        ASID
    } else if within(offset, bytes, 0x060, 0x068) {
        TPR
    } else if within(offset, bytes, 0x0b0, 0x0b8) || within(offset, bytes, 0x668, 0x670) {
        NESTED_PAGING
    } else if within(offset, bytes, 0x4d0, 0x4d8) || within(offset, bytes, 0x548, 0x560) {
        CONTROL_REGISTERS
    } else if within(offset, bytes, 0x560, 0x570) {
        DEBUG_REGISTERS
    } else if within(offset, bytes, 0x460, 0x470) || within(offset, bytes, 0x480, 0x490) {
        DESCRIPTOR_TABLES
    } else if within(offset, bytes, 0x400, 0x440) || within(offset, bytes, 0x4cb, 0x4cc) {
        SEGMENTS
    } else if within(offset, bytes, 0x640, 0x648) {
        CR2
    } else if within(offset, bytes, 0x05c, 0x05d) // TLB_CONTROL; not adjacent ERAPS.
        || within(offset, bytes, 0x068, 0x090) // Shadow and exit status.
        || within(offset, bytes, 0x0a8, 0x0b0) // EVENTINJ.
        || within(offset, bytes, CLEAN_BITS, CLEAN_BITS + 4)
        || within(offset, bytes, 0x570, 0x580) // RFLAGS/RIP.
        || within(offset, bytes, 0x5d8, 0x5e0) // RSP.
        || within(offset, bytes, 0x5f8, 0x600) // RAX.
        // VMLOAD/VMSAVE auxiliary state is not VMRUN-cached state.
        || within(offset, bytes, 0x440, 0x460)
        || within(offset, bytes, 0x470, 0x480)
        || within(offset, bytes, 0x490, 0x4a0)
        || within(offset, bytes, 0x600, 0x640)
    {
        0
    } else {
        REVIEWED_CLEAN_MASK
    }
}

#[cfg(test)]
mod tests;
