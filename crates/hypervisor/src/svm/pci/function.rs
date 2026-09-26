//! Register layouts: PG054 physical pp42,45,109-111,214-215; MSI control and
//! address/data layout: 48882-3.11 physical pp240-242. See README restrictions.

use super::{Error, Region, Space};

pub(super) const COMMAND: u16 = 0x0407;
const STATUS_W1C: u16 = 0xf900;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarKind {
    Memory32 { prefetchable: bool },
    Memory64 { prefetchable: bool },
    Io,
}

impl BarKind {
    pub const fn space(self) -> Space {
        match self {
            Self::Io => Space::Io,
            _ => Space::Memory,
        }
    }

    const fn attributes(self) -> u32 {
        match self {
            Self::Io => 1,
            Self::Memory32 { prefetchable } => (prefetchable as u32) << 3,
            Self::Memory64 { prefetchable } => 4 | ((prefetchable as u32) << 3),
        }
    }
}

/// One BAR's immutable virtual resource shape and admitted relocation range.
/// A 64-bit BAR consumes its immediately following slot, which must be None.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bar {
    pub kind: BarKind,
    pub bytes: u64,
    pub initial_base: u64,
    pub allowed: Region,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bridge {
    /// Fixed secondary bus: re-numbering needs requester/alias ownership that
    /// this profile does not have. Subordinate can close/narrow this interval.
    pub secondary: u8,
    pub subordinate: u8,
    /// Only a 32-bit non-prefetchable window and 16-bit I/O window are modeled.
    /// Both windows start closed, and are writable within these immutable bounds.
    pub memory: Option<Region>,
    pub io: Option<Region>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Header {
    Endpoint { subsystem_vendor: u16, subsystem_device: u16 },
    Bridge(Bridge),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FunctionSpec {
    pub bdf: u16,
    pub parent: Option<u16>,
    pub vendor: u16,
    pub device: u16,
    /// Class:subclass:programming-interface (24 bits).
    pub class_code: u32,
    pub revision: u8,
    pub multifunction: bool,
    pub header: Header,
    pub bars: [Option<Bar>; 6],
    /// One unmasked, 64-bit-address-capable MSI vector at 40h, or no capability.
    pub msi: bool,
    pub interrupt_pin: u8,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Msi {
    pub enabled: bool,
    pub address: u64,
    pub data: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Function {
    pub(super) spec: FunctionSpec,
    pub(super) command: u16,
    pub(super) status: u16,
    pub(super) addresses: [u64; 6],
    pub(super) probes: u8,
    pub(super) interrupt_line: u8,
    pub(super) intx_asserted: bool,
    pub(super) msi: Msi,
    pub(super) subordinate: u8,
    pub(super) memory_window: u32,
    pub(super) io_window: u16,
}

impl Function {
    pub fn new(spec: FunctionSpec) -> Result<Self, Error> {
        if matches!(spec.vendor, 0 | 0xffff)
            || spec.class_code > 0xff_ffff
            || spec.class_code >> 8 == 0x0600
            || spec.interrupt_pin > 4
            || (spec.bdf >> 8 == 0 && spec.bdf & 0xf8 >= 0xc0)
        {
            return Err(Error::InvalidFunction);
        }
        let mut addresses = [0; 6];
        let limit = if matches!(spec.header, Header::Bridge(_)) { 2 } else { 6 };
        for (index, bar) in spec.bars.iter().enumerate() {
            let Some(bar) = bar else { continue };
            let min = if bar.kind == BarKind::Io { 4 } else { 16 };
            let max = match bar.kind {
                BarKind::Io => 0x1_0000,
                BarKind::Memory32 { .. } => 1u64 << 32,
                BarKind::Memory64 { .. } => 1u64 << 48,
            };
            if index >= limit
                || bar.bytes < min
                || !bar.bytes.is_power_of_two()
                || !bar.allowed.valid()
                || bar.allowed.bytes < bar.bytes
                || bar.allowed.base + bar.allowed.bytes > max
                || bar.initial_base & (bar.bytes - 1) != 0
                || (bar.initial_base != 0 && !bar.allowed.contains(bar.initial_base, bar.bytes))
                || (matches!(bar.kind, BarKind::Memory64 { .. })
                    && (index + 1 >= limit || spec.bars[index + 1].is_some()))
            {
                return Err(Error::InvalidBar);
            }
            addresses[index] = bar.initial_base;
        }
        let subordinate = match spec.header {
            Header::Endpoint { .. } => 0,
            Header::Bridge(bridge) => {
                if spec.class_code != 0x060400
                    || bridge.secondary == 0
                    || bridge.secondary <= (spec.bdf >> 8) as u8
                    || bridge.secondary > bridge.subordinate
                    || !valid_bridge_region(bridge.memory, 1 << 20, 1u64 << 32)
                    || !valid_bridge_region(bridge.io, 1 << 12, 1 << 16)
                {
                    return Err(Error::InvalidTopology);
                }
                bridge.subordinate
            }
        };
        Ok(Self {
            spec,
            command: 0,
            status: 0,
            addresses,
            probes: 0,
            interrupt_line: 0,
            intx_asserted: false,
            msi: Msi::default(),
            subordinate,
            memory_window: 0x0000_fff0,
            io_window: 0x00f0,
        })
    }

    pub const fn spec(&self) -> &FunctionSpec {
        &self.spec
    }

    pub const fn command(&self) -> u16 {
        self.command
    }

    pub const fn msi(&self) -> Msi {
        self.msi
    }

    pub const fn intx_asserted(&self) -> bool {
        self.intx_asserted
    }
    pub const fn interrupt_line(&self) -> u8 {
        self.interrupt_line
    }
    pub fn bar_probing(&self, slot: usize) -> bool {
        slot < 6 && self.probes & (1 << slot) != 0
    }
    pub fn subordinate_bus(&self) -> Option<u8> {
        matches!(self.spec.header, Header::Bridge(_)).then_some(self.subordinate)
    }
    pub fn bridge_region(&self, space: Space) -> Option<Region> {
        if matches!(self.spec.header, Header::Bridge(_)) { self.bridge_window(space) } else { None }
    }

    pub fn bar_region(&self, slot: usize) -> Option<(Space, Region)> {
        let bar = self.spec.bars.get(slot).copied().flatten()?;
        Some((bar.kind.space(), Region { base: self.addresses[slot], bytes: bar.bytes }))
    }

    pub(super) fn enabled(&self, space: Space) -> bool {
        self.command
            & match space {
                Space::Memory => 2,
                Space::Io => 1,
            }
            != 0
    }

    pub(super) fn read_word(&self, register: u16) -> u32 {
        match register {
            0 => u32::from(self.spec.vendor) | (u32::from(self.spec.device) << 16),
            4 => {
                let status = self.status
                    | if self.spec.msi { 0x10 } else { 0 }
                    | if self.intx_asserted && !self.msi.enabled { 8 } else { 0 };
                u32::from(self.command) | (u32::from(status) << 16)
            }
            8 => self.spec.class_code << 8 | u32::from(self.spec.revision),
            0x0c => {
                let header = u32::from(matches!(self.spec.header, Header::Bridge(_)))
                    | if self.spec.multifunction { 0x80 } else { 0 };
                header << 16
            }
            0x10 | 0x14 => self.read_bar(usize::from((register - 0x10) / 4)),
            0x18..=0x30 => match self.spec.header {
                Header::Endpoint { subsystem_vendor, subsystem_device } => match register {
                    0x18..=0x24 => self.read_bar(usize::from((register - 0x10) / 4)),
                    0x2c => u32::from(subsystem_vendor) | (u32::from(subsystem_device) << 16),
                    _ => 0,
                },
                Header::Bridge(bridge) => match register {
                    0x18 => {
                        (u32::from(self.spec.bdf) >> 8)
                            | u32::from(bridge.secondary) << 8
                            | u32::from(self.subordinate) << 16
                    }
                    0x1c => u32::from(self.io_window),
                    0x20 => self.memory_window,
                    0x24 => 0x0000_fff0, // Prefetchable window permanently closed.
                    _ => 0,
                },
            },
            0x34 => {
                if self.spec.msi {
                    0x40
                } else {
                    0
                }
            }
            0x3c => u32::from(self.interrupt_line) | u32::from(self.spec.interrupt_pin) << 8,
            0x40 if self.spec.msi => 0x0080_0005 | u32::from(self.msi.enabled) << 16,
            0x44 if self.spec.msi => self.msi.address as u32,
            0x48 if self.spec.msi => (self.msi.address >> 32) as u32,
            0x4c if self.spec.msi => u32::from(self.msi.data),
            _ => 0,
        }
    }

    fn read_bar(&self, slot: usize) -> u32 {
        let (index, upper) = self.bar_slot(slot);
        let Some(bar) = self.spec.bars[index] else { return 0 };
        let raw =
            if self.probes & (1 << slot) != 0 { !(bar.bytes - 1) } else { self.addresses[index] };
        if upper { (raw >> 32) as u32 } else { raw as u32 | bar.kind.attributes() }
    }

    fn bar_slot(&self, slot: usize) -> (usize, bool) {
        if slot > 0
            && self.spec.bars[slot - 1].is_some_and(|b| matches!(b.kind, BarKind::Memory64 { .. }))
        {
            (slot - 1, true)
        } else {
            (slot, false)
        }
    }

    pub(super) fn write_word(&mut self, register: u16, value: u32, mask: u32) -> Result<(), Error> {
        let old = self.read_word(register);
        let merged = (old & !mask) | (value & mask);
        match register {
            4 => {
                // Error reporting, VGA, fast-back-to-back and every optional
                // command effect are unimplemented, even if the old bit is 0.
                if value & mask & 0xffff & !u32::from(COMMAND) != 0 {
                    return Err(Error::UnsupportedControl);
                }
                self.command = merged as u16 & COMMAND;
                self.status &= !((value >> 16) as u16 & (mask >> 16) as u16 & STATUS_W1C);
            }
            0x10 | 0x14 => self.write_bar(usize::from((register - 0x10) / 4), merged, mask)?,
            0x18..=0x30 => match self.spec.header {
                Header::Endpoint { .. } if register <= 0x24 => {
                    self.write_bar(usize::from((register - 0x10) / 4), merged, mask)?;
                }
                Header::Endpoint { .. } if register == 0x30 && value & mask != 0 => {
                    return Err(Error::UnsupportedControl); // No expansion ROM owner.
                }
                Header::Bridge(bridge) => {
                    self.write_bridge(bridge, register, merged, value & mask)?
                }
                _ => {}
            },
            0x3c => {
                if matches!(self.spec.header, Header::Bridge(_)) && value & mask & 0xffff_0000 != 0
                {
                    return Err(Error::UnsupportedControl); // Includes secondary bus reset.
                }
                self.interrupt_line = merged as u8;
            }
            0x38 if matches!(self.spec.header, Header::Bridge(_)) && value & mask != 0 => {
                return Err(Error::UnsupportedControl);
            }
            0x40 if self.spec.msi => {
                if merged & 0x0070_0000 != 0 {
                    return Err(Error::UnsupportedControl); // Single vector only.
                }
                self.msi.enabled = merged & (1 << 16) != 0;
            }
            0x44 if self.spec.msi => {
                self.msi.address = (self.msi.address & !0xffff_ffff) | u64::from(merged & !3)
            }
            0x48 if self.spec.msi => {
                self.msi.address = (self.msi.address & 0xffff_ffff) | u64::from(merged) << 32
            }
            0x4c if self.spec.msi => self.msi.data = merged as u16,
            // BIST writes request an unimplemented lifecycle operation.
            0x0c if value & mask & 0x4000_0000 != 0 => return Err(Error::UnsupportedControl),
            _ => {} // Defined virtual absent/RO fields, never physical passthrough.
        }
        Ok(())
    }

    fn write_bar(&mut self, slot: usize, value: u32, mask: u32) -> Result<(), Error> {
        let (index, upper) = self.bar_slot(slot);
        let Some(bar) = self.spec.bars[index] else { return Ok(()) };
        if self.enabled(bar.kind.space()) || self.command & 4 != 0 {
            return Err(Error::DecodeEnabled);
        }
        if mask == u32::MAX && value == u32::MAX {
            self.probes |= 1 << slot;
            return Ok(());
        }
        self.probes &= !(1 << slot);
        let address = if upper {
            (self.addresses[index] & 0xffff_ffff) | u64::from(value) << 32
        } else {
            let low_mask = if bar.kind == BarKind::Io { !3 } else { !15 };
            (self.addresses[index] & !0xffff_ffff) | u64::from(value & low_mask)
        };
        // 64-bit BAR halves may be programmed in either order while decoding is
        // off. Validate the complete address only when decoding/BME is enabled.
        self.addresses[index] = address & !(bar.bytes - 1);
        Ok(())
    }

    fn write_bridge(
        &mut self,
        bridge: Bridge,
        register: u16,
        merged: u32,
        written: u32,
    ) -> Result<(), Error> {
        match register {
            0x18 => {
                if merged as u8 != (self.spec.bdf >> 8) as u8
                    || (merged >> 8) as u8 != bridge.secondary
                    || (merged >> 16) as u8 > bridge.subordinate
                    || merged >> 24 != 0
                {
                    return Err(Error::UnsupportedBusChange);
                }
                if self.command & 7 != 0 {
                    return Err(Error::DecodeEnabled);
                }
                self.subordinate = (merged >> 16) as u8;
            }
            0x1c => {
                if self.command & 5 != 0 {
                    return Err(Error::DecodeEnabled);
                }
                if merged & 0x0f0f != 0 {
                    return Err(Error::UnsupportedControl);
                }
                self.io_window = merged as u16 & 0xf0f0;
                validate_window(self.bridge_window(Space::Io), bridge.io)?;
            }
            0x20 => {
                if self.command & 6 != 0 {
                    return Err(Error::DecodeEnabled);
                }
                if merged & 0x000f_000f != 0 {
                    return Err(Error::UnsupportedControl);
                }
                self.memory_window = merged;
                validate_window(self.bridge_window(Space::Memory), bridge.memory)?;
            }
            0x24 if merged != 0x0000_fff0 => return Err(Error::UnsupportedControl),
            0x28 | 0x2c | 0x30 if written != 0 => return Err(Error::UnsupportedControl),
            _ => {}
        }
        Ok(())
    }

    pub(super) fn bridge_window(&self, space: Space) -> Option<Region> {
        let (base, end) = match space {
            Space::Memory => (
                u64::from(self.memory_window & 0xfff0) << 16,
                u64::from(self.memory_window >> 16 & 0xfff0) << 16 | 0xfffff,
            ),
            Space::Io => (
                u64::from(self.io_window & 0xf0) << 8,
                u64::from(self.io_window >> 8 & 0xf0) << 8 | 0xfff,
            ),
        };
        (base <= end).then(|| Region { base, bytes: end - base + 1 })
    }

    pub(super) fn validate_active(&self) -> Result<(), Error> {
        for (slot, bar) in self.spec.bars.iter().enumerate() {
            let Some(bar) = bar else { continue };
            if self.enabled(bar.kind.space()) || self.command & 4 != 0 {
                let probe_mask =
                    if matches!(bar.kind, BarKind::Memory64 { .. }) { 3 } else { 1 } << slot;
                if self.addresses[slot] == 0 || self.probes & probe_mask != 0 {
                    return Err(Error::UnassignedBar);
                }
                if !bar.allowed.contains(self.addresses[slot], bar.bytes) {
                    return Err(Error::OutsidePolicy);
                }
            }
        }
        Ok(())
    }
}

fn valid_bridge_region(region: Option<Region>, alignment: u64, ceiling: u64) -> bool {
    region.is_none_or(|r| {
        r.valid()
            && r.base % alignment == 0
            && r.bytes % alignment == 0
            && r.base + r.bytes <= ceiling
    })
}

fn validate_window(window: Option<Region>, allowed: Option<Region>) -> Result<(), Error> {
    if window.is_some_and(|window| {
        allowed.is_none_or(|allowed| !allowed.contains(window.base, window.bytes))
    }) {
        Err(Error::OutsidePolicy)
    } else {
        Ok(())
    }
}
