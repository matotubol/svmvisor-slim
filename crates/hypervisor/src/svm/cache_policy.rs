//! Target-native shadow MTRRs. No method writes physical cache controls.
//!
//! AMD APM2 rev3.44 physical pp279-294,615-616 and Family1Ah Model44h
//! PPR57896 rev3.00 pp126-173,202,205-206. The bank belongs to a physical
//! core; SYS_CFG19 belongs to its calling thread and is passed separately.
//! A candidate is inert until its owner synchronizes every affected vCPU's
//! nested translations and cache state. INIT must not reset this bank.

use crate::sync::TryLock;
use crate::{
    arch::x86_64::msr::{
        MTRR_CAP, MTRR_DEF_TYPE, SYS_CFG, SYS_CFG_DEFINED, SYS_CFG_ENCRYPTION,
        SYS_CFG_MTRR_FIX_DRAM_EN, SYS_CFG_MTRR_FIX_DRAM_MOD_EN, SYS_CFG_MTRR_TOM2_EN,
        SYS_CFG_TOM2_FORCE_MEM_TYPE_WB, TARGET_PHYSICAL_BITS, TARGET_SIGNATURE, TOM2,
    },
    memory::mtrrs::{DEF_TYPE_E, DEF_TYPE_FE, is_valid_default, is_valid_type},
};
use core::sync::atomic::{AtomicU32, AtomicU64};

pub const VARIABLE_COUNT: usize = 8;
pub const FIXED_MSRS: [u32; 11] =
    [0x250, 0x258, 0x259, 0x268, 0x269, 0x26a, 0x26b, 0x26c, 0x26d, 0x26e, 0x26f];
pub const TOP_MEM: u32 = 0xc001_001a;
const IORR_FIRST: u32 = 0xc001_0016;
const ADDRESS: u64 = 0x0000_ffff_ffff_f000;
const VALID: u64 = 1 << 11;
const FIXED_DRAM: u64 = 0x1818_1818_1818_1818;

/// Shared-core state only: bit19 is never stored in `sys_cfg`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheBank {
    pub capability: u64,
    pub default: u64,
    pub sys_cfg: u64,
    pub top_mem: u64,
    pub tom2: u64,
    pub iorr: [u64; 4],
    pub variable: [(u64, u64); VARIABLE_COUNT],
    pub fixed: [u64; 11],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheError {
    UnsupportedProfile,
    PhysicalCapture,
    GeneralProtection,
    UnsupportedRegister,
    UnsupportedControl,
    MalformedRange,
    UndefinedOverlap,
    Address,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheEffect {
    /// Register/visibility state alone changes; effective access policy does not.
    Registers,
    /// Publish only through the cache and translation rendezvous.
    MemoryTypes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheChange {
    pub bank: CacheBank,
    pub visibility: bool,
    pub effect: CacheEffect,
}

/// Retained storage initialized once by the firmware owner, then accessed
/// through every CPU's private shared alias. No CPU waits with `state` held.
#[repr(C, align(4096))]
pub struct SharedCache {
    pub(crate) state: TryLock<SharedCacheState>,
    pub(crate) ready: AtomicU32,
    pub(crate) phase: AtomicU32,
    pub(crate) parked: AtomicU32,
    pub(crate) prepared: AtomicU32,
    pub(crate) retired: AtomicU32,
    pub(crate) flushed: AtomicU32,
    pub(crate) applied: AtomicU32,
    pub(crate) departed: AtomicU32,
    pub(crate) generation: AtomicU64,
}

#[cfg_attr(not(feature = "resident-runtime"), allow(dead_code))]
pub(crate) struct SharedCacheState {
    pub captured: u32,
    pub physical: [CacheBank; 32],
    pub logical: [CacheBank; 32],
    pub core_keys: [u64; 32],
    pub core: [usize; 32],
    pub threads: [u32; 32],
    pub requested: CacheBank,
    pub owner_slot: usize,
    pub changed_core: usize,
}

#[cfg_attr(not(feature = "resident-runtime"), allow(dead_code))]
impl SharedCache {
    pub const fn new() -> Self {
        Self {
            state: TryLock::new(SharedCacheState {
                captured: 0,
                physical: [CacheBank::EMPTY; 32],
                logical: [CacheBank::EMPTY; 32],
                core_keys: [0; 32],
                core: [0; 32],
                threads: [0; 32],
                requested: CacheBank::EMPTY,
                owner_slot: 0,
                changed_core: 0,
            }),
            ready: AtomicU32::new(0),
            phase: AtomicU32::new(0),
            parked: AtomicU32::new(0),
            prepared: AtomicU32::new(0),
            retired: AtomicU32::new(0),
            flushed: AtomicU32::new(0),
            applied: AtomicU32::new(0),
            departed: AtomicU32::new(0),
            generation: AtomicU64::new(0),
        }
    }

    /// None means lock contention; Some(None) means no outstanding work.
    /// A joined generation and its parked bit are published under the same
    /// lock used to begin/finish a transaction, never from mixed generations.
    pub(crate) fn try_join(&self, slot: usize) -> Option<Option<u64>> {
        use core::sync::atomic::Ordering;
        let _owner = self.state.try_lock()?;
        if self.phase.load(Ordering::Acquire) == 0 {
            return Some(None);
        }
        let generation = self.generation.load(Ordering::Acquire);
        self.parked.fetch_or(1 << slot, Ordering::AcqRel);
        Some(Some(generation))
    }
}

impl Default for SharedCache {
    fn default() -> Self {
        Self::new()
    }
}
const _: () = assert!(core::mem::size_of::<SharedCache>() <= 0x8000);

impl CacheBank {
    pub const EMPTY: Self = Self {
        capability: 0,
        default: 0,
        sys_cfg: 0,
        top_mem: 0,
        tom2: 0,
        iorr: [0; 4],
        variable: [(0, 0); VARIABLE_COUNT],
        fixed: [0; 11],
    };

    /// Owning-CPU admission before any guest runs. The caller serializes the
    /// capture with firmware/SMT changes. Only thread-local visibility changes;
    /// it is restored before any return following the temporary write.
    pub fn capture(
        signature: u32,
        physical_bits: u8,
        mut read: impl FnMut(u32) -> u64,
        mut write: impl FnMut(u32, u64),
    ) -> Result<(Self, bool), CacheError> {
        if signature != TARGET_SIGNATURE || physical_bits != TARGET_PHYSICAL_BITS {
            return Err(CacheError::UnsupportedProfile);
        }
        let capability = read(MTRR_CAP);
        let original = read(SYS_CFG);
        if capability != 0x508
            || original & !SYS_CFG_DEFINED != 0
            || original & SYS_CFG_ENCRYPTION != 0
        {
            return Err(CacheError::PhysicalCapture);
        }
        let mut bank = Self {
            capability,
            default: read(MTRR_DEF_TYPE),
            sys_cfg: original & !SYS_CFG_MTRR_FIX_DRAM_MOD_EN,
            top_mem: read(TOP_MEM),
            tom2: read(TOM2),
            ..Self::EMPTY
        };
        for (n, pair) in bank.variable.iter_mut().enumerate() {
            *pair = (read(0x200 + 2 * n as u32), read(0x201 + 2 * n as u32));
        }
        for (n, value) in bank.iorr.iter_mut().enumerate() {
            *value = read(IORR_FIRST + n as u32);
        }
        let exposed = original | SYS_CFG_MTRR_FIX_DRAM_MOD_EN;
        if exposed != original {
            write(SYS_CFG, exposed);
        }
        let visible = read(SYS_CFG) == exposed;
        if visible {
            for (value, index) in bank.fixed.iter_mut().zip(FIXED_MSRS) {
                *value = read(index);
            }
        }
        if exposed != original {
            write(SYS_CFG, original);
        }
        if read(SYS_CFG) != original || !visible || read(MTRR_DEF_TYPE) != bank.default {
            return Err(CacheError::PhysicalCapture);
        }
        bank.validate()?;
        Ok((bank, original & SYS_CFG_MTRR_FIX_DRAM_MOD_EN != 0))
    }

    /// Validate encodings and active variable ranges. Dormant masks may hold
    /// firmware leftovers and intermediate guest values while E=0.
    pub fn validate(&self) -> Result<(), CacheError> {
        if self.capability != 0x508
            || !is_valid_default(self.default)
            || self.sys_cfg & (!SYS_CFG_DEFINED | SYS_CFG_ENCRYPTION | SYS_CFG_MTRR_FIX_DRAM_MOD_EN)
                != 0
        {
            return Err(CacheError::UnsupportedControl);
        }
        for &(base, mask) in &self.variable {
            if base & !(ADDRESS | 7) != 0 || mask & !(ADDRESS | VALID) != 0 {
                return Err(CacheError::UnsupportedControl);
            }
            if self.default & DEF_TYPE_E != 0 && mask & VALID != 0 {
                variable_range(base, mask)?;
            }
        }
        if self.default & (DEF_TYPE_E | DEF_TYPE_FE) == DEF_TYPE_E | DEF_TYPE_FE {
            for value in self.fixed {
                if value.to_le_bytes().iter().any(|b| b & !0x1f != 0 || !is_valid_type(b & 7)) {
                    return Err(CacheError::UnsupportedControl);
                }
                // Effective routing/type tuples are checked when admitting a
                // mapping. A programming window may hold an unrepresentable
                // tuple only while that page is inaccessible to the guest.
            }
        }
        Ok(())
    }

    pub fn read(&self, index: u32, visibility: bool) -> Option<u64> {
        Some(match index {
            MTRR_CAP => self.capability,
            MTRR_DEF_TYPE => self.default,
            SYS_CFG => self.sys_cfg | if visibility { SYS_CFG_MTRR_FIX_DRAM_MOD_EN } else { 0 },
            TOP_MEM => self.top_mem,
            TOM2 => self.tom2,
            0xc001_0016..=0xc001_0019 => self.iorr[(index - IORR_FIRST) as usize],
            0x200..=0x20f => {
                let pair = self.variable[((index - 0x200) / 2) as usize];
                if index & 1 == 0 { pair.0 } else { pair.1 }
            }
            _ => {
                self.fixed[FIXED_MSRS.iter().position(|&msr| msr == index)?]
                    & if visibility { u64::MAX } else { !FIXED_DRAM }
            }
        })
    }

    /// No state is mutated on failure. Architectural invalid type encodings
    /// produce #GP. Fixed routing changes require the owner to install guarded
    /// mappings; other unsupported routing/encryption changes are explicit
    /// monitor refusals, never invented guest faults. No CD/replay shortcut.
    pub fn prepare_write(
        &self,
        index: u32,
        value: u64,
        visibility: bool,
    ) -> Result<CacheChange, CacheError> {
        use CacheError::{GeneralProtection as Gp, UnsupportedControl as Unsupported};
        let mut next = CacheChange { bank: *self, visibility, effect: CacheEffect::Registers };
        let old = self.read(index, visibility).ok_or(CacheError::UnsupportedRegister)?;
        if index == MTRR_CAP {
            return Err(Gp);
        }
        if index == MTRR_DEF_TYPE {
            if !is_valid_default(value) {
                return Err(Gp);
            }
            // SYS_CFG18 owns fixed routing. The target's FE interaction with
            // that path is not established; preserve FE rather than fabricate
            // a new physical destination. E changes remain fully modeled.
            if (self.default ^ value) & DEF_TYPE_FE != 0 {
                return Err(Unsupported);
            }
            next.bank.default = value;
        } else if index == SYS_CFG {
            if value & !SYS_CFG_DEFINED != 0 {
                return Err(Unsupported);
            }
            // E=0 does not disable the DRAM routing attributes (APM2 p286).
            // PAT cannot implement a changed physical bus destination.
            let allowed = SYS_CFG_MTRR_FIX_DRAM_MOD_EN | SYS_CFG_MTRR_FIX_DRAM_EN;
            if (old ^ value) & !allowed != 0 {
                return Err(Unsupported);
            }
            next.visibility = value & SYS_CFG_MTRR_FIX_DRAM_MOD_EN != 0;
            next.bank.sys_cfg = value & !SYS_CFG_MTRR_FIX_DRAM_MOD_EN;
        } else if (0x200..=0x20f).contains(&index) {
            if index & 1 == 0 {
                if value & !(ADDRESS | 7) != 0 || !is_valid_type(value as u8) {
                    return Err(Gp);
                }
                next.bank.variable[((index - 0x200) / 2) as usize].0 = value;
            } else {
                if value & !(ADDRESS | VALID) != 0 {
                    return Err(Unsupported);
                }
                next.bank.variable[((index - 0x200) / 2) as usize].1 = value;
            }
        } else if let Some(slot) = FIXED_MSRS.iter().position(|&msr| msr == index) {
            // PPR p127's field-level Read,Error-on-write-1 semantics control
            // masked routing bits; p202's general visibility prose does not
            // grant permission to write ones into these hidden fields.
            if value.to_le_bytes().iter().any(|b| b & !0x1f != 0 || !is_valid_type(b & 7))
                || !visibility && value & FIXED_DRAM != 0
            {
                return Err(Gp);
            }
            next.bank.fixed[slot] =
                if visibility { value } else { value | self.fixed[slot] & FIXED_DRAM };
        } else if old != value {
            return Err(Unsupported);
        }
        next.bank.validate()?;
        // Routing is live independently of E (APM2 physical p286). In
        // particular, Windows' 0x780000 SYS_CFG write clears bit18 as it
        // exposes bit19; it must install inaccessible mappings before return.
        let routing_changed = (self.sys_cfg ^ next.bank.sys_cfg) & SYS_CFG_MTRR_FIX_DRAM_EN != 0
            || self
                .fixed
                .iter()
                .zip(next.bank.fixed)
                .any(|(old, new)| (old ^ new) & FIXED_DRAM != 0);
        let active = self.default & DEF_TYPE_E != 0 || next.bank.default & DEF_TYPE_E != 0;
        if routing_changed
            || active
                && (self.default != next.bank.default
                    || self.variable != next.bank.variable
                    || self.fixed != next.bank.fixed
                    || self.sys_cfg != next.bank.sys_cfg)
        {
            next.effect = CacheEffect::MemoryTypes;
        }
        Ok(next)
    }

    /// Logical MTRR type before PAT composition. Routing is checked separately.
    pub fn memory_type(&self, address: u64) -> Result<u8, CacheError> {
        if address >= 1 << 48 {
            return Err(CacheError::Address);
        }
        if self.default & DEF_TYPE_E == 0 {
            return Ok(0);
        }
        if let Some((slot, byte, _)) = self.fixed_slot(address) {
            return Ok(((self.fixed[slot] >> (byte * 8)) & 7) as u8);
        }
        let mut types = 0u8;
        for &(base, mask) in &self.variable {
            if mask & VALID == 0 {
                continue;
            }
            let (start, end) = variable_range(base, mask)?;
            if (start..end).contains(&address) {
                types |= 1 << (base & 7);
            }
        }
        if types & 1 != 0 {
            return Ok(0);
        }
        if types.count_ones() == 1 {
            return Ok(types.trailing_zeros() as u8);
        }
        if types == (1 << 4) | (1 << 6) {
            return Ok(4);
        }
        if types != 0 {
            return Err(CacheError::UndefinedOverlap);
        }
        if self.sys_cfg & (SYS_CFG_MTRR_TOM2_EN | SYS_CFG_TOM2_FORCE_MEM_TYPE_WB)
            == SYS_CFG_MTRR_TOM2_EN | SYS_CFG_TOM2_FORCE_MEM_TYPE_WB
            && (0x1_0000_0000..self.tom2).contains(&address)
        {
            return Ok(6);
        }
        Ok(self.default as u8)
    }

    /// First possible type/routing boundary after address, clipped to limit.
    /// This visits at most eight variable ranges, never iterates physical pages.
    pub fn next_boundary(&self, address: u64, limit: u64) -> Result<u64, CacheError> {
        if address >= limit || limit > 1 << 48 {
            return Err(CacheError::Address);
        }
        let mut next = limit;
        let mut admit = |value: u64| {
            if value > address {
                next = next.min(value);
            }
        };
        for point in [0x100000, self.top_mem, 0x1_0000_0000, self.tom2] {
            admit(point);
        }
        if let Some((_, _, end)) = self.fixed_slot(address) {
            admit(end);
        }
        if address < 0x100000 && self.sys_cfg & SYS_CFG_MTRR_FIX_DRAM_EN != 0 {
            admit(fixed_address_slot(address).2);
        }
        if self.sys_cfg & (1 << 20) != 0 {
            for pair in self.iorr.chunks_exact(2) {
                if pair[1] & VALID != 0 {
                    let (start, end) = variable_range(pair[0] & ADDRESS, pair[1])?;
                    admit(start);
                    admit(end);
                }
            }
        }
        if self.default & DEF_TYPE_E != 0 {
            for &(base, mask) in &self.variable {
                if mask & VALID != 0 {
                    let (start, end) = variable_range(base, mask)?;
                    admit(start);
                    admit(end);
                }
            }
        }
        Ok(next)
    }

    /// APM2 physical p616, Tables15-19/20. Select a host PAT entry whose
    /// composition matches logical MTRRs for EVERY possible guest PAT type.
    /// CD and WC+ are the documented coherent SVM forms of UC and WC. No
    /// other difference is accepted; physical UC cannot silently supply WB.
    pub fn nested_pat_index(
        &self,
        physical: &Self,
        address: u64,
        host_pat: u64,
    ) -> Result<u8, CacheError> {
        let logical_type = self.memory_type(address)?;
        let physical_type = physical.memory_type(address)?;
        let route = self.routing_bits(address)?;
        if route != physical.routing_bits(address)?
            || !valid_tuple(route | logical_type)
            || !valid_tuple(route | physical_type)
        {
            return Err(CacheError::UnsupportedControl);
        }
        for index in 0..8u8 {
            let nested = ((host_pat >> (index * 8)) & 255) as u8;
            if !matches!(nested, 0 | 1 | 4 | 5 | 6 | 7) {
                continue;
            }
            if [0, 7, 1, 5, 4, 6].into_iter().all(|guest| {
                normalize(combine_mtrr(combine_pat(guest, nested), physical_type))
                    == normalize(combine_mtrr(guest, logical_type))
            }) {
                return Ok(index);
            }
        }
        Err(CacheError::UnsupportedControl)
    }

    /// Whether a guest access reaches the same destination under the frozen
    /// physical controls. A mismatch requires an inaccessible NPT mapping and
    /// refusal of software guest-memory accesses, never a PAT substitution.
    pub fn routing_matches(&self, physical: &Self, address: u64) -> Result<bool, CacheError> {
        if address >= 1 << 48 {
            return Err(CacheError::Address);
        }
        Ok(self.routing_bits(address)? == physical.routing_bits(address)?)
    }

    fn fixed_slot(&self, address: u64) -> Option<(usize, usize, u64)> {
        if address >= 0x100000
            || self.default & (DEF_TYPE_E | DEF_TYPE_FE) != DEF_TYPE_E | DEF_TYPE_FE
        {
            return None;
        }
        Some(fixed_address_slot(address))
    }

    /// The fixed routing path is independent of E. FE is preserved by this
    /// owner until its routing interaction is established for the target.
    fn routing_bits(&self, address: u64) -> Result<u8, CacheError> {
        if address < 0x100000 {
            if self.sys_cfg & SYS_CFG_MTRR_FIX_DRAM_EN == 0 {
                return Ok(0);
            }
            let (slot, byte, _) = fixed_address_slot(address);
            return Ok(((self.fixed[slot] >> (byte * 8)) & 0x18) as u8);
        }
        let mut found = None;
        if self.sys_cfg & (1 << 20) != 0 {
            for pair in self.iorr.chunks_exact(2) {
                if pair[1] & VALID == 0 {
                    continue;
                }
                let (start, end) = variable_range(pair[0] & ADDRESS, pair[1])?;
                if (start..end).contains(&address) {
                    if found.is_some() {
                        return Err(CacheError::UnsupportedControl);
                    }
                    found = Some((pair[0] & 0x18) as u8);
                }
            }
        }
        if let Some(route) = found {
            return Ok(route);
        }
        let dram = if address < 0x1_0000_0000 {
            self.sys_cfg & (1 << 20) != 0 && address < self.top_mem
        } else {
            self.sys_cfg & SYS_CFG_MTRR_TOM2_EN != 0 && address < self.tom2
        };
        Ok(if dram { 0x18 } else { 0 })
    }
}

fn fixed_address_slot(address: u64) -> (usize, usize, u64) {
    debug_assert!(address < 0x100000);
    if address < 0x80000 {
        (0, (address / 0x10000) as usize, (address & !0xffff) + 0x10000)
    } else if address < 0xc0000 {
        (
            1 + ((address - 0x80000) / 0x20000) as usize,
            ((address & 0x1ffff) / 0x4000) as usize,
            (address & !0x3fff) + 0x4000,
        )
    } else {
        (
            3 + ((address - 0xc0000) / 0x8000) as usize,
            ((address & 0x7fff) / 0x1000) as usize,
            (address & !0xfff) + 0x1000,
        )
    }
}

fn valid_tuple(value: u8) -> bool {
    matches!(
        value,
        0x00 | 0x01 | 0x04 | 0x05 | 0x08 | 0x09 | 0x10 | 0x15 | 0x18 | 0x19 | 0x1c | 0x1e
    )
}

pub fn owned_msr(index: u32) -> bool {
    matches!(index, MTRR_CAP | MTRR_DEF_TYPE | SYS_CFG | TOP_MEM | TOM2
        | 0x200..=0x20f | 0xc001_0016..=0xc001_0019)
        || FIXED_MSRS.contains(&index)
}

fn variable_range(base: u64, mask: u64) -> Result<(u64, u64), CacheError> {
    let bits = mask & ADDRESS;
    let length = ((!bits & ADDRESS) | 4095) + 1;
    let start = base & ADDRESS;
    if !length.is_power_of_two() || start & (length - 1) != 0 || !is_valid_type(base as u8) {
        return Err(CacheError::MalformedRange);
    }
    Ok((start, start + length))
}

// Internal encodings never written to PAT: coherent WC+ and CD.
const WC_PLUS: u8 = 8;
const CD: u8 = 9;
fn normalize(value: u8) -> u8 {
    match value {
        WC_PLUS => 1,
        CD => 0,
        _ => value,
    }
}
fn pat_position(value: u8) -> usize {
    match value {
        0 => 0,
        7 => 1,
        1 => 2,
        5 => 3,
        4 => 4,
        6 => 5,
        _ => unreachable!(),
    }
}
fn combine_pat(guest: u8, nested: u8) -> u8 {
    // Rows are GUEST, columns HOST; the table is deliberately asymmetric.
    const TABLE: [[u8; 6]; 6] = [
        [0, 0, 0, 0, 0, 0],
        [0, 7, 1, 0, 0, 0],
        [1, 1, 1, WC_PLUS, WC_PLUS, WC_PLUS],
        [0, 0, 0, 5, 0, 5],
        [0, 0, 0, 0, 4, 4],
        [0, 0, 1, 5, 4, 6],
    ];
    TABLE[pat_position(guest)][pat_position(nested)]
}
fn combine_mtrr(pat: u8, mtrr: u8) -> u8 {
    let column = match mtrr {
        0 => 0,
        1 => 1,
        5 => 2,
        4 => 3,
        6 => 4,
        _ => unreachable!(),
    };
    let row = match pat {
        0 => 0,
        7 => 1,
        1 => 2,
        WC_PLUS => 3,
        5 => 4,
        4 => 5,
        6 => 6,
        _ => unreachable!(),
    };
    const TABLE: [[u8; 5]; 7] = [
        [0, CD, CD, CD, CD],
        [0, 1, CD, CD, CD],
        [1, 1, 1, 1, 1],
        [1, 1, WC_PLUS, WC_PLUS, WC_PLUS],
        [0, CD, 5, CD, 5],
        [0, CD, CD, 4, 4],
        [0, 1, 5, 4, 6],
    ];
    TABLE[row][column]
}

#[cfg(test)]
mod tests;
