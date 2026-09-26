//! Lane-accurate baseline register state. Read-only/absent features stay zero.
//! Sources: 48882-3.11 physical pp214-224,252-256,122,140; PNGs checked.

use super::guest::Exclusion;
use super::{ADDRESS, PAGE, guest_span};

pub const APERTURE_BYTES: u16 = 0x4000;
pub const IOMMU_EN: u64 = 1;
pub const EVENT_EN: u64 = 1 << 2;
pub const EVENT_INT_EN: u64 = 1 << 3;
pub const COMPLETION_INT_EN: u64 = 1 << 4;
pub const COMMAND_EN: u64 = 1 << 12;
pub const EVENT_OVERFLOW: u64 = 1;
pub const EVENT_INT: u64 = 1 << 1;
pub const COMPLETION_INT: u64 = 1 << 2;
pub const EVENT_RUN: u64 = 1 << 3;
pub const COMMAND_RUN: u64 = 1 << 4;
const CONTROL_MASK: u64 = 0x1ffd; // Baseline fields except unsupported HtTunEn.
const POINTER_MASK: u64 = 0x7fff0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError {
    Access,
    Running,
    Pointer,
    RingLength,
    Address,
    InvalidTimeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ring {
    pub base: u64,
    pub bytes: u64,
}

impl Ring {
    pub const fn next(self, offset: u64) -> u64 {
        (offset + 16) & (self.bytes - 1)
    }
    pub const fn distance(self, from: u64, to: u64) -> u64 {
        to.wrapping_sub(from) & (self.bytes - 1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registers {
    pub(crate) device: u64,
    pub(crate) command: u64,
    pub(crate) event: u64,
    pub(crate) control: u64,
    pub(crate) exclusion_base: u64,
    pub(crate) exclusion_limit: u64,
    pub(crate) command_head: u64,
    pub(crate) command_tail: u64,
    pub(crate) event_head: u64,
    pub(crate) event_tail: u64,
    pub(crate) status: u64,
}

impl Default for Registers {
    fn default() -> Self {
        Self::RESET
    }
}

impl Registers {
    pub const RESET: Self = Self {
        device: 0,
        command: 8 << 56,
        event: 8 << 56,
        control: 1 << 10,
        exclusion_base: 0,
        exclusion_limit: 0,
        command_head: 0,
        command_tail: 0,
        event_head: 0,
        event_tail: 0,
        status: 0,
    };

    pub fn read(&self, offset: u16, width: u8) -> Result<u64, RegisterError> {
        let (base, shift, mask) = lane(offset, width)?;
        Ok((self.word(base) >> shift) & mask)
    }

    fn word(&self, base: u16) -> u64 {
        match base {
            0x0000 => self.device,
            0x0008 => self.command,
            0x0010 => self.event,
            0x0018 => self.control,
            0x0020 => self.exclusion_base,
            0x0028 => self.exclusion_limit,
            0x2000 => self.command_head,
            0x2008 => self.command_tail,
            0x2010 => self.event_head,
            0x2018 => self.event_tail,
            0x2020 => self.status,
            // EFR/EFR2 and unsupported optional registers are RAZ/WI. This is
            // deliberately independent of any physical IOMMU feature report.
            _ => 0,
        }
    }

    pub const fn enabled(&self) -> bool {
        self.control & IOMMU_EN != 0
    }
    pub const fn command_running(&self) -> bool {
        self.status & COMMAND_RUN != 0
    }
    pub const fn event_running(&self) -> bool {
        self.status & EVENT_RUN != 0
    }
    pub const fn device_table(&self) -> (u64, u64) {
        (self.device & ADDRESS, ((self.device & 511) + 1) * PAGE)
    }
    pub fn command_ring(&self) -> Result<Ring, RegisterError> {
        ring(self.command)
    }
    pub fn event_ring(&self) -> Result<Ring, RegisterError> {
        ring(self.event)
    }
    pub const fn status(&self) -> u64 {
        self.status
    }
    pub const fn control(&self) -> u64 {
        self.control
    }

    pub fn exclusion(&self) -> Option<Exclusion> {
        (self.exclusion_base & 1 != 0).then_some(Exclusion {
            base: self.exclusion_base & ADDRESS,
            limit: (self.exclusion_limit & ADDRESS) | (PAGE - 1),
            allow_all: self.exclusion_base & 2 != 0,
        })
    }

    /// Prepare a full next bank before committing any lane. Device invokes this
    /// privately so policy-changing writes cannot bypass physical publication.
    pub(crate) fn prepare_write(
        &self,
        offset: u16,
        width: u8,
        value: u64,
    ) -> Result<(Self, bool), RegisterError> {
        let (base, shift, lane_mask) = lane(offset, width)?;
        let mask = lane_mask << shift;
        let lane_value = (value & lane_mask) << shift;
        let merged = (self.word(base) & !mask) | lane_value;
        let mut next = *self;
        let mut policy_change = false;
        match base {
            0x0000 => {
                next.device = merged & (ADDRESS | 511);
                let (base, len) = next.device_table();
                if !guest_span(base, len, PAGE) {
                    return Err(RegisterError::Address);
                }
                policy_change = self.enabled() && next.device != self.device;
            }
            0x0008 => {
                if self.command_running() {
                    return Err(RegisterError::Running);
                }
                next.command = merged & (ADDRESS | (15 << 56));
                ring(next.command)?;
                next.command_head = 0;
                next.command_tail = 0;
            }
            0x0010 => {
                if self.event_running() {
                    return Err(RegisterError::Running);
                }
                next.event = merged & (ADDRESS | (15 << 56));
                ring(next.event)?;
                next.event_head = 0;
                next.event_tail = 0;
            }
            0x0018 => {
                next.control = merged & CONTROL_MASK;
                if (next.control >> 5) & 7 == 7 {
                    return Err(RegisterError::InvalidTimeout);
                }
                policy_change = (next.control ^ self.control) & IOMMU_EN != 0;
                if next.enabled() {
                    let (base, len) = next.device_table();
                    if !guest_span(base, len, PAGE) {
                        return Err(RegisterError::Address);
                    }
                    if next.control & COMMAND_EN != 0 {
                        next.command_ring()?;
                        // CmdBufEn is level-sensitive: an actual write to this
                        // bit with 1 restarts an error-stopped command engine.
                        if mask & COMMAND_EN != 0 || !self.enabled() {
                            next.status |= COMMAND_RUN;
                        }
                    } else {
                        next.status &= !COMMAND_RUN;
                    }
                    if next.control & EVENT_EN != 0 {
                        next.event_ring()?;
                        if self.control & EVENT_EN == 0 || !self.enabled() {
                            next.status &= !EVENT_OVERFLOW;
                            next.status |= EVENT_RUN;
                        }
                    } else {
                        next.status &= !EVENT_RUN;
                    }
                } else {
                    next.status &= !(COMMAND_RUN | EVENT_RUN);
                }
            }
            0x0020 => {
                next.exclusion_base = merged & (ADDRESS | 3);
                if !guest_span(next.exclusion_base & ADDRESS, PAGE, PAGE) {
                    return Err(RegisterError::Address);
                }
                policy_change = self.enabled() && next.exclusion_base != self.exclusion_base;
            }
            0x0028 => {
                next.exclusion_limit = merged & ADDRESS;
                if !guest_span(next.exclusion_limit, PAGE, PAGE) {
                    return Err(RegisterError::Address);
                }
                policy_change = self.enabled() && next.exclusion_limit != self.exclusion_limit;
            }
            0x2000 => {
                if self.command_running() {
                    return Err(RegisterError::Running);
                }
                next.command_head = checked_pointer(merged, next.command_ring()?)?;
            }
            0x2008 => {
                let ring = next.command_ring()?;
                let pointer = checked_pointer(merged, ring)?;
                if self.command_running() {
                    let added = ring.distance(self.command_tail, pointer);
                    let used = ring.distance(self.command_head, self.command_tail);
                    if added > ring.bytes - 16 - used {
                        return Err(RegisterError::Pointer);
                    }
                }
                next.command_tail = pointer;
            }
            0x2010 => {
                let ring = next.event_ring()?;
                let pointer = checked_pointer(merged, ring)?;
                if self.event_running()
                    && ring.distance(self.event_head, pointer)
                        > ring.distance(self.event_head, self.event_tail)
                {
                    return Err(RegisterError::Pointer);
                }
                next.event_head = pointer;
            }
            0x2018 => {
                if self.event_running() {
                    return Err(RegisterError::Running);
                }
                next.event_tail = checked_pointer(merged, next.event_ring()?)?;
            }
            0x2020 => next.status &= !(lane_value & (EVENT_OVERFLOW | EVENT_INT | COMPLETION_INT)),
            _ => (),
        }
        Ok((next, policy_change))
    }
}

fn lane(offset: u16, width: u8) -> Result<(u16, u32, u64), RegisterError> {
    if !matches!(width, 1 | 2 | 4 | 8)
        || offset & (u16::from(width) - 1) != 0
        || u32::from(offset) + u32::from(width) > u32::from(APERTURE_BYTES)
        || offset & !7 == 0x1ff8
    {
        return Err(RegisterError::Access);
    }
    let mask = if width == 8 { u64::MAX } else { (1u64 << (u32::from(width) * 8)) - 1 };
    Ok((offset & !7, u32::from(offset & 7) * 8, mask))
}

fn ring(raw: u64) -> Result<Ring, RegisterError> {
    let order = ((raw >> 56) & 15) as u8;
    if order < 8 {
        return Err(RegisterError::RingLength);
    }
    let base = raw & ADDRESS;
    let bytes = (1 << order) * 16;
    if !guest_span(base, bytes, PAGE) {
        return Err(RegisterError::Address);
    }
    Ok(Ring { base, bytes })
}

fn checked_pointer(raw: u64, ring: Ring) -> Result<u64, RegisterError> {
    let pointer = raw & POINTER_MASK;
    if pointer >= ring.bytes { Err(RegisterError::Pointer) } else { Ok(pointer) }
}
