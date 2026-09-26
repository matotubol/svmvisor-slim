//! Owned AMD IOMMU functions, independent of the synthetic ordinary PCI bus.
//! Only explicitly listed functions are handled. An unlisted BDF is unowned,
//! not absent. Layouts: 48882-3.11 physical pp205-210,240-242 (text/PNG checked).

use super::{ConfigAccess, Error, Msi, Region, lane};
use crate::svm::configuration::{ConfigurationRoute, LegacySelector, ScalarTarget};

pub const CAPABILITY_OFFSET: u16 = 0x40;
pub const MSI_OFFSET: u16 = 0x60;
pub const APERTURE_BYTES: u64 = 0x4000;
pub const CAPABILITY_HEADER: u32 = (1 << 27) | (1 << 26) | (1 << 19) | (3 << 16) | 0x0f;
pub const MISCELLANEOUS: u32 = (48 << 15) | (48 << 8) | (2 << 5);
const COMMAND: u32 = 0x0406; // No I/O BARs, error controls or INTx source.

/// Integer-only, stable resident storage. Every raw bit pattern can be copied
/// before validation. This does not confer backing integrity or synchronization.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IommuFunction {
    bdf: u16,
    reserved: u16,
    vendor_device: u32,
    revision: u32,
    command: u32,
    base: u64,
    allowed_base: u64,
    allowed_bytes: u64,
    enabled: u32,
    msi_enabled: u32,
    msi_address: u64,
    msi_data: u32,
    reserved_tail: u32,
}

impl IommuFunction {
    pub const EMPTY: Self = Self {
        bdf: 0,
        reserved: 0,
        vendor_device: 0,
        revision: 0,
        command: 0,
        base: 0,
        allowed_base: 0,
        allowed_bytes: 0,
        enabled: 0,
        msi_enabled: 0,
        msi_address: 0,
        msi_data: 0,
        reserved_tail: 0,
    };

    /// Resource assignment is explicit and virtual. Native preparation uses the
    /// identified unit's existing aperture, enabled/locked before publication.
    /// Enabling an unlocked bank later requires the effect owner's NPT update.
    pub fn new(
        bdf: u16,
        vendor_device: u32,
        revision: u8,
        allowed: Region,
        enabled: bool,
    ) -> Result<Self, Error> {
        let out = Self {
            bdf,
            vendor_device,
            revision: u32::from(revision),
            command: if enabled { 6 } else { 0 },
            base: allowed.base,
            allowed_base: allowed.base,
            allowed_bytes: allowed.bytes,
            enabled: u32::from(enabled),
            ..Self::EMPTY
        };
        out.validate()?;
        Ok(out)
    }

    pub fn validate(&self) -> Result<(), Error> {
        let allowed = self.allowed();
        if matches!(self.vendor_device as u16, 0 | 0xffff)
            || self.revision > 255
            || self.command & !COMMAND != 0
            || self.enabled > 1
            || self.msi_enabled > 1
            || self.msi_data > 0xffff
            || self.msi_address & 3 != 0
            || self.reserved != 0
            || self.reserved_tail != 0
            || !allowed.valid()
            || allowed.base == 0
            || allowed.base & (APERTURE_BYTES - 1) != 0
            || allowed.bytes & (APERTURE_BYTES - 1) != 0
            || allowed.base + allowed.bytes > 1 << 48
            || self.base & (APERTURE_BYTES - 1) != 0
            || (self.enabled != 0 && !allowed.contains(self.base, APERTURE_BYTES))
        {
            return Err(Error::InvalidFunction);
        }
        Ok(())
    }

    pub const fn bdf(&self) -> u16 {
        self.bdf
    }
    pub const fn base(&self) -> u64 {
        self.base
    }
    pub const fn enabled(&self) -> bool {
        self.enabled != 0
    }
    pub const fn command(&self) -> u16 {
        self.command as u16
    }
    pub const fn allowed(&self) -> Region {
        Region { base: self.allowed_base, bytes: self.allowed_bytes }
    }
    pub const fn msi(&self) -> Msi {
        Msi {
            enabled: self.msi_enabled != 0,
            address: self.msi_address,
            data: self.msi_data as u16,
        }
    }

    fn word(&self, register: u16) -> u32 {
        match register {
            0 => self.vendor_device,
            4 => self.command | (1 << 20), // Capability list, no fabricated errors.
            8 => 0x0806_0000 | self.revision,
            // Conservatively enumerate other functions on this device. This
            // does not claim that any other function is owned or absent.
            0x0c => 0x0080_0000,
            0x34 => u32::from(CAPABILITY_OFFSET),
            0x40 => CAPABILITY_HEADER | u32::from(MSI_OFFSET) << 8,
            0x44 => self.base as u32 | self.enabled,
            0x48 => (self.base >> 32) as u32,
            // RngValid=0: IVRS is authoritative. Range/UnitID are RO (p209).
            0x4c => 0,
            0x50 => MISCELLANEOUS,
            0x60 => 0x0080_0005 | self.msi_enabled << 16,
            0x64 => self.msi_address as u32,
            0x68 => (self.msi_address >> 32) as u32,
            0x6c => self.msi_data,
            _ => 0,
        }
    }

    fn changed(&self, register: u16, value: u32, mask: u32) -> Result<Self, Error> {
        let mut next = *self;
        let merged = (self.word(register) & !mask) | (value & mask);
        match register {
            4 => {
                if value & mask & 0xffff & !COMMAND != 0 {
                    return Err(Error::UnsupportedControl);
                }
                next.command = merged & COMMAND;
            }
            0x44 if self.enabled == 0 => {
                next.base = (self.base & !0xffff_ffff) | u64::from(merged & !0x3fff);
                next.enabled = merged & 1;
            }
            0x48 if self.enabled == 0 => {
                next.base = (self.base & 0xffff_ffff) | u64::from(merged) << 32
            }
            0x60 => {
                if value & mask & 0x0070_0000 != 0 {
                    return Err(Error::UnsupportedControl);
                }
                next.msi_enabled = (merged >> 16) & 1;
            }
            0x64 => next.msi_address = (self.msi_address & !0xffff_ffff) | u64::from(merged & !3),
            0x68 => next.msi_address = (self.msi_address & 0xffff_ffff) | u64::from(merged) << 32,
            0x6c => next.msi_data = merged & 0xffff,
            0x0c if value & mask & 0x4000_0000 != 0 => return Err(Error::UnsupportedControl),
            0x30 if value & mask != 0 => return Err(Error::UnsupportedControl),
            // Reserved/RO fields belong to this virtual function. In particular
            // p206 requires writes to locked capability registers be ignored.
            _ => {}
        }
        next.validate()?;
        Ok(next)
    }

    pub fn decode(&self, address: u64, width: u8) -> Result<u16, Error> {
        if !matches!(width, 1 | 2 | 4 | 8) || address & (u64::from(width) - 1) != 0 {
            return Err(Error::InvalidAccess);
        }
        if self.enabled == 0
            || self.command & 2 == 0
            || !(Region { base: self.base, bytes: APERTURE_BYTES })
                .contains(address, u64::from(width))
        {
            return Err(Error::NoDecode);
        }
        Ok((address - self.base) as u16)
    }
}

/// Bind all function identities, full-aperture traps, resource lifetime and MSI
/// routing to the real owner. `apply` completes every external effect before
/// software state or guest RIP changes. Guest addresses never become host stores.
pub trait Effects {
    fn revalidate(
        &mut self,
        route: ConfigurationRoute,
        functions: &[IommuFunction],
    ) -> Result<(), Error>;
    fn apply(&mut self, before: &IommuFunction, after: &IommuFunction) -> Result<(), Error>;
    fn interrupt(&mut self, bdf: u16, message: Msi) -> Result<(), Error>;
}

/// A borrow of one common retained bank under the caller's all-CPU route gate.
/// Reconstructing this view retains the shared selector and permanent poison.
pub struct Bank<'a> {
    route: ConfigurationRoute,
    functions: &'a mut [IommuFunction],
    selector: &'a mut u32,
    poisoned: &'a mut u32,
    effects: &'a mut dyn Effects,
}

impl<'a> Bank<'a> {
    pub fn new(
        route: ConfigurationRoute,
        functions: &'a mut [IommuFunction],
        selector: &'a mut u32,
        poisoned: &'a mut u32,
        effects: &'a mut dyn Effects,
    ) -> Result<Self, Error> {
        let mut bank = Self { route, functions, selector, poisoned, effects };
        bank.revalidate()?;
        Ok(bank)
    }

    fn revalidate(&mut self) -> Result<(), Error> {
        if *self.poisoned != 0 {
            return Err(Error::MissingOwner);
        }
        let result = (|| {
            LegacySelector::admit(*self.selector).map_err(Error::Scalar)?;
            if self.functions.is_empty() || self.functions.len() > 4 {
                return Err(Error::InvalidPolicy);
            }
            for (index, function) in self.functions.iter().enumerate() {
                function.validate()?;
                if u64::from(function.bdf) >= self.route.aperture().1 >> 12 {
                    return Err(Error::OutsidePolicy);
                }
                for other in &self.functions[..index] {
                    if other.bdf == function.bdf || other.allowed().overlaps(function.allowed()) {
                        return Err(Error::Overlap);
                    }
                }
            }
            self.effects.revalidate(self.route, self.functions)
        })();
        if result.is_err() {
            *self.poisoned = 1;
        }
        result
    }

    pub fn access(&mut self, target: ScalarTarget, write: Option<u32>) -> Result<u32, Error> {
        let (register, shift, bits) = lane(target.register, target.width)?;
        self.revalidate()?;
        let index =
            self.functions.iter().position(|f| f.bdf == target.bdf).ok_or(Error::MissingOwner)?;
        if let Some(value) = write {
            let before = self.functions[index];
            let after = before.changed(register, (value & bits) << shift, bits << shift)?;
            if before != after {
                let result = self.effects.apply(&before, &after);
                if result.is_err() {
                    *self.poisoned = 1;
                }
                result?;
                self.functions[index] = after;
            }
            Ok(0)
        } else {
            Ok(self.functions[index].word(register) >> shift & bits)
        }
    }

    pub fn interrupt(&mut self, bdf: u16) -> Result<(), Error> {
        self.revalidate()?;
        let function = self.functions.iter().find(|f| f.bdf == bdf).ok_or(Error::MissingOwner)?;
        if function.command & 4 == 0 {
            return Err(Error::BusMasterDisabled);
        }
        if !function.msi().enabled {
            return Err(Error::InterruptDisabled);
        }
        let result = self.effects.interrupt(bdf, function.msi());
        if result.is_err() {
            *self.poisoned = 1;
        }
        result
    }
}

impl ConfigAccess for Bank<'_> {
    fn route(&self) -> ConfigurationRoute {
        self.route
    }
    fn io(&mut self, port: u16, width: u8, write: Option<u32>) -> Result<u32, Error> {
        if port == 0xcf8 && width == 4 {
            let next = write.map(LegacySelector::admit).transpose().map_err(Error::Scalar)?;
            self.revalidate()?;
            if let Some(next) = next {
                *self.selector = next.raw();
            }
            return Ok(*self.selector);
        }
        let target = LegacySelector::admit(*self.selector)
            .and_then(|s| s.data(port, width))
            .map_err(Error::Scalar)?;
        self.access(target, write)
    }
    fn ecam(&mut self, address: u64, width: u8, write: Option<u32>) -> Result<u32, Error> {
        self.access(self.route.ecam_scalar(address, width).map_err(Error::Scalar)?, write)
    }
}
