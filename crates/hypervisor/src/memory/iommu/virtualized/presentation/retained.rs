//! Scalar shared storage for the DXE/resident boundary. Native initialization
//! uses the complete owned extent in place; zero is a valid empty bit pattern.
//! A checksum is structural validation, never DMA integrity or authorization.

use super::{Error, Unit, render};
use crate::{
    memory::iommu::{Ivrs, MAX_TABLE_BYTES},
    svm::{
        configuration::ConfigurationRoute,
        pci::{
            self, Region,
            iommu::{self, Bank, Effects, IommuFunction},
        },
    },
};

const MAGIC: u64 = 0x5052_4553_564d_4d55;
const VERSION: u32 = 1;
const PREPARING: u32 = 1;
const PREPARED: u32 = 2;
const ACTIVE: u32 = 3;
const FAILED: u32 = 4;
pub const STORAGE_BYTES: usize = core::mem::size_of::<Storage>();

/// Immutable physical identity and full trap extent, separate from the smaller
/// guest feature profile. No field is a pointer or permission to access hardware.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitDescriptor {
    pub segment: u16,
    pub device_id: u16,
    pub physical_capability_offset: u16,
    pub reserved: u16,
    pub vendor_device: u32,
    pub class_revision: u32,
    pub mmio_base: u64,
    pub physical_mmio_bytes: u64,
    pub configuration_page: u64,
}

impl UnitDescriptor {
    pub const EMPTY: Self = Self {
        segment: 0,
        device_id: 0,
        physical_capability_offset: 0,
        reserved: 0,
        vendor_device: 0,
        class_revision: 0,
        mmio_base: 0,
        physical_mmio_bytes: 0,
        configuration_page: 0,
    };
    fn validate(self, route: ConfigurationRoute) -> Result<(), PreparationError> {
        let (base, bytes) = route.aperture();
        let aperture = Region { base: self.mmio_base, bytes: self.physical_mmio_bytes };
        if self.segment != 0
            || self.reserved != 0
            || !(0x40..=0xec).contains(&self.physical_capability_offset)
            || self.physical_capability_offset & 3 != 0
            || matches!(self.vendor_device as u16, 0 | 0xffff)
            || self.class_revision >> 8 != 0x080600
            || u64::from(self.device_id) >= bytes >> 12
            || self.configuration_page != base + (u64::from(self.device_id) << 12)
        {
            return Err(PreparationError::UnitIdentity);
        }
        if !aperture.valid()
            || aperture.base == 0
            || aperture.bytes < iommu::APERTURE_BYTES
            || !aperture.bytes.is_power_of_two()
            || aperture.base & (aperture.bytes - 1) != 0
            || aperture.base + aperture.bytes > super::super::GUEST_LIMIT
            || aperture.overlaps(Region { base, bytes })
        {
            return Err(PreparationError::Resource);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationError {
    AlreadyAttempted,
    IncompleteReport,
    UnresolvedInventory,
    UnitCount,
    UnitIdentity,
    Resource,
    Profile,
    Firmware(Error),
}
impl PreparationError {
    pub const fn code(self) -> u32 {
        match self {
            Self::AlreadyAttempted => 1,
            Self::IncompleteReport => 2,
            Self::UnresolvedInventory => 3,
            Self::UnitCount => 4,
            Self::UnitIdentity => 5,
            Self::Resource => 6,
            Self::Profile => 7,
            Self::Firmware(Error::UnresolvedInventory) => 8,
            Self::Firmware(Error::UnitIdentity) => 9,
            Self::Firmware(Error::ResourceWidth) => 10,
            Self::Firmware(Error::UnsupportedAts) => 11,
            Self::Firmware(Error::UnsupportedExtendedSettings) => 12,
            Self::Firmware(Error::AcpiStringIdentityRequired) => 13,
            Self::Firmware(Error::MissingDeviceEntries) => 14,
            Self::Firmware(Error::Capacity) => 15,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishError {
    InvalidStorage,
    NotPrepared,
    Owner,
    Firmware,
    Verification,
}

/// A concrete candidate, not an attestation. The owner compares these exact
/// bytes/identities with its live topology and all-CPU runtime contracts.
#[derive(Clone, Copy)]
pub struct View<'a> {
    pub route: ConfigurationRoute,
    pub units: &'a [UnitDescriptor],
    pub functions: &'a [IommuFunction],
    pub ivrs: &'a [u8],
}

/// Publication is only possible through a backing owner. `admit` must establish
/// complete PCI/ACPI source identity, all IVMD semantics, resource reservation,
/// initial composed DMA/interrupt state, protected retained lifetime and all-CPU
/// trapping/dispatch before any firmware change. A partial scan is insufficient.
/// `replace_ivrs` must replace the sole IVRS in every guest-visible ACPI root,
/// preserving other tables/checksums, before Windows can enumerate. `verify`
/// reads back those guest-visible roots and checks this exact table/contract.
/// Any failure is terminal for this storage; an external partial effect cannot
/// be rolled back by restoring a register shadow.
pub trait PublicationOwner {
    fn admit(&mut self, view: View<'_>) -> Result<(), PublishError>;
    fn replace_ivrs(&mut self, view: View<'_>) -> Result<(), PublishError>;
    fn verify(&mut self, view: View<'_>) -> Result<(), PublishError>;
}

/// All fields have all-bit-pattern-valid representations and a fixed layout.
/// Every vCPU borrows the same instance under the shared route/effect gate.
/// Neither a numeric address nor validate() supplies that lifetime or lock.
#[repr(C, align(4096))]
pub struct Storage {
    magic: u64,
    version: u32,
    phase: u32,
    route: u64,
    unit_count: u32,
    ivrs_len: u32,
    preparation_error: u32,
    poisoned: u32,
    selector: u32,
    reserved: u32,
    units: [UnitDescriptor; 4],
    functions: [IommuFunction; 4],
    ivrs: [u8; MAX_TABLE_BYTES],
}

impl Storage {
    pub const EMPTY: Self = Self {
        magic: 0,
        version: 0,
        phase: 0,
        route: 0,
        unit_count: 0,
        ivrs_len: 0,
        preparation_error: 0,
        poisoned: 0,
        selector: 0,
        reserved: 0,
        units: [UnitDescriptor::EMPTY; 4],
        functions: [IommuFunction::EMPTY; 4],
        ivrs: [0; MAX_TABLE_BYTES],
    };
    pub fn empty_template() -> &'static Self {
        static EMPTY: Storage = Storage::EMPTY;
        &EMPTY
    }
    pub const fn is_active(&self) -> bool {
        self.phase == ACTIVE && self.poisoned == 0
    }
    pub const fn preparation_error(&self) -> u32 {
        self.preparation_error
    }

    /// Firmware's report adapter calls this on any acquisition/admission error.
    /// Failure is retained and can never be mistaken for an empty PCI fabric.
    pub fn refuse(&mut self, error: PreparationError) -> Result<(), PreparationError> {
        if self.phase != 0 {
            return Err(PreparationError::AlreadyAttempted);
        }
        self.magic = MAGIC;
        self.version = VERSION;
        self.phase = FAILED;
        self.preparation_error = error.code();
        self.poisoned = 1;
        Err(error)
    }

    /// Construct private candidate bytes only. No firmware or guest-visible
    /// state is published here. Even a successful preparation remains stopped
    /// until a real PublicationOwner establishes the complete native contract.
    pub fn prepare(
        &mut self,
        source: &Ivrs,
        route: ConfigurationRoute,
        units: &[UnitDescriptor],
    ) -> Result<(), PreparationError> {
        if self.phase != 0 {
            return Err(PreparationError::AlreadyAttempted);
        }
        self.magic = MAGIC;
        self.version = VERSION;
        self.phase = PREPARING;
        self.route = route.raw();
        self.unit_count = 0;
        self.ivrs_len = 0;
        self.preparation_error = 0;
        self.poisoned = 0;
        self.selector = 0;
        self.reserved = 0;
        self.units.fill(UnitDescriptor::EMPTY);
        self.functions.fill(IommuFunction::EMPTY);
        self.ivrs.fill(0);
        let result = self.prepare_inner(source, route, units);
        match result {
            Ok(()) => {
                self.phase = PREPARED;
                Ok(())
            }
            Err(error) => {
                self.phase = FAILED;
                self.preparation_error = error.code();
                self.poisoned = 1;
                self.unit_count = 0;
                self.ivrs_len = 0;
                self.units.fill(UnitDescriptor::EMPTY);
                self.functions.fill(IommuFunction::EMPTY);
                self.ivrs.fill(0);
                Err(error)
            }
        }
    }

    fn prepare_inner(
        &mut self,
        source: &Ivrs,
        route: ConfigurationRoute,
        units: &[UnitDescriptor],
    ) -> Result<(), PreparationError> {
        if units.is_empty() || units.len() > 4 || source.units().len() != units.len() {
            return Err(PreparationError::UnitCount);
        }
        let mut virtual_units = [Unit::EMPTY; 4];
        for (index, unit) in units.iter().copied().enumerate() {
            unit.validate(route)?;
            let expected = source.units()[index];
            if unit.segment != expected.segment
                || unit.device_id != expected.device_id
                || unit.physical_capability_offset != expected.capability_offset
                || unit.mmio_base != expected.mmio_base
            {
                return Err(PreparationError::UnitIdentity);
            }
            for other in &units[..index] {
                if unit.device_id == other.device_id
                    || (Region { base: unit.mmio_base, bytes: unit.physical_mmio_bytes }).overlaps(
                        Region { base: other.mmio_base, bytes: other.physical_mmio_bytes },
                    )
                {
                    return Err(PreparationError::Resource);
                }
            }
            self.units[index] = unit;
            self.functions[index] = IommuFunction::new(
                unit.device_id,
                unit.vendor_device,
                unit.class_revision as u8,
                Region { base: unit.mmio_base, bytes: iommu::APERTURE_BYTES },
                true,
            )
            .map_err(|_| PreparationError::Profile)?;
            virtual_units[index] = Unit {
                segment: unit.segment,
                device_id: unit.device_id,
                mmio_base: unit.mmio_base,
            };
        }
        self.ivrs_len = render(source, &virtual_units[..units.len()], &mut self.ivrs)
            .map_err(PreparationError::Firmware)? as u32;
        self.unit_count = units.len() as u32;
        Ok(())
    }

    pub fn validate(&self, route: ConfigurationRoute) -> Result<(), PublishError> {
        if self.magic != MAGIC
            || self.version != VERSION
            || self.reserved != 0
            || self.route != route.raw()
            || !matches!(self.phase, PREPARED | ACTIVE)
            || self.poisoned != 0
            || self.preparation_error != 0
            || !(1..=4).contains(&self.unit_count)
            || !(48..=MAX_TABLE_BYTES as u32).contains(&self.ivrs_len)
        {
            return Err(PublishError::InvalidStorage);
        }
        let count = self.unit_count as usize;
        for (unit, function) in self.units[..count].iter().zip(&self.functions[..count]) {
            unit.validate(route).map_err(|_| PublishError::InvalidStorage)?;
            function.validate().map_err(|_| PublishError::InvalidStorage)?;
            if function.bdf() != unit.device_id
                || function.base() != unit.mmio_base
                || !function.enabled()
                || function.allowed()
                    != (Region { base: unit.mmio_base, bytes: iommu::APERTURE_BYTES })
            {
                return Err(PublishError::InvalidStorage);
            }
        }
        if self.units[count..].iter().any(|u| *u != UnitDescriptor::EMPTY)
            || self.functions[count..].iter().any(|f| *f != IommuFunction::EMPTY)
        {
            return Err(PublishError::InvalidStorage);
        }
        crate::memory::iommu::validate_sdt(&self.ivrs[..self.ivrs_len as usize], *b"IVRS")
            .map_err(|_| PublishError::InvalidStorage)?;
        Ok(())
    }

    pub fn view(&self, route: ConfigurationRoute) -> Result<View<'_>, PublishError> {
        self.validate(route)?;
        Ok(View {
            route,
            units: &self.units[..self.unit_count as usize],
            functions: &self.functions[..self.unit_count as usize],
            ivrs: &self.ivrs[..self.ivrs_len as usize],
        })
    }

    pub fn publish(
        &mut self,
        route: ConfigurationRoute,
        owner: &mut impl PublicationOwner,
    ) -> Result<(), PublishError> {
        self.validate(route)?;
        if self.phase != PREPARED {
            return Err(PublishError::NotPrepared);
        }
        let result = (|| {
            owner.admit(self.view(route)?)?;
            owner.replace_ivrs(self.view(route)?)?;
            owner.verify(self.view(route)?)
        })();
        match result {
            Ok(()) => {
                self.phase = ACTIVE;
                Ok(())
            }
            Err(error) => {
                self.poisoned = 1;
                self.phase = FAILED;
                Err(error)
            }
        }
    }

    pub fn bank<'a>(
        &'a mut self,
        route: ConfigurationRoute,
        effects: &'a mut dyn Effects,
    ) -> Result<Bank<'a>, pci::Error> {
        self.validate(route).map_err(|_| pci::Error::MissingOwner)?;
        if !self.is_active() {
            return Err(pci::Error::MissingOwner);
        }
        Bank::new(
            route,
            &mut self.functions[..self.unit_count as usize],
            &mut self.selector,
            &mut self.poisoned,
            effects,
        )
    }

    /// Resolve only the emulated 16KiB sub-aperture. The retained descriptor
    /// still requires trapping the complete physical aperture; its optional
    /// tail is explicitly unsupported, never a physical passthrough.
    pub fn mmio_route(&self, address: u64, width: u8) -> Result<UnitAccess, pci::Error> {
        if !self.is_active() || !(1..=4).contains(&self.unit_count) {
            return Err(pci::Error::MissingOwner);
        }
        for (index, unit) in self.units[..self.unit_count as usize].iter().enumerate() {
            if (Region { base: unit.mmio_base, bytes: unit.physical_mmio_bytes })
                .contains(address, u64::from(width))
            {
                let offset = self.functions[index].decode(address, width).map_err(|error| {
                    if error == pci::Error::NoDecode {
                        pci::Error::UnsupportedControl
                    } else {
                        error
                    }
                })?;
                return Ok(UnitAccess { unit_index: index as u16, offset, width });
            }
        }
        Err(pci::Error::NoDecode)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitAccess {
    pub unit_index: u16,
    pub offset: u16,
    pub width: u8,
}

const _: () = assert!(STORAGE_BYTES <= 0x12000);
const _: () = assert!(core::mem::align_of::<Storage>() == 4096);
