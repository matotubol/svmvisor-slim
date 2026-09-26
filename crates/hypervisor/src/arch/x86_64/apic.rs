//! Native x2APIC registers used by startup and platform capture.

pub const APIC_BASE: u32 = 0x1b;
pub const APIC_BASE_BSP: u64 = 1 << 8;
pub(crate) const APIC_BASE_EXTD: u64 = 1 << 10;
pub(crate) const APIC_BASE_AE: u64 = 1 << 11;
pub const APIC_BASE_X2APIC: u64 = APIC_BASE_AE | APIC_BASE_EXTD;
pub const APIC_BASE_ADDRESS: u64 = 0x000f_ffff_ffff_f000;
pub const APIC_BASE_DEFAULT_ADDRESS: u64 = 0xfee0_0000;
pub const ID: u16 = 0x20;
pub const TPR: u16 = 0x80;
pub const SVR: u16 = 0xf0;
pub const ISR: u16 = 0x100;
pub const IRR: u16 = 0x200;
pub const ICR: u16 = 0x300;
pub const LVT_TIMER: u16 = 0x320;
pub const LVT_THERMAL: u16 = 0x330;
pub const LVT_PERFORMANCE: u16 = 0x340;
pub(crate) const LVT_LINT0: u16 = 0x350;
pub(crate) const LVT_LINT1: u16 = 0x360;
pub const LVT_ERROR: u16 = 0x370;
pub const TIMER_INITIAL_COUNT: u16 = 0x380;
pub const TIMER_DIVIDE: u16 = 0x3e0;
pub const LVT_MASKED: u32 = 1 << 16;
#[cfg(feature = "resident-runtime")]
pub(crate) const ICR_RESERVED: u64 = 0xfff0_0000 | (3 << 16) | (3 << 12);
#[cfg(feature = "resident-runtime")]
pub(crate) const ID_MSR: u32 = msr(ID);
pub const ICR_MSR: u32 = msr(ICR);
pub const LVTS: [u16; 6] =
    [LVT_TIMER, LVT_THERMAL, LVT_PERFORMANCE, LVT_LINT0, LVT_LINT1, LVT_ERROR];
pub const fn msr(offset: u16) -> u32 {
    0x800 + (offset as u32 >> 4)
}
