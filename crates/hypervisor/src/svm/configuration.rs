//! Permanent configuration-route admission and bounded scalar operand decoding.
//!
//! PPR 57896-3.00 physical pp40-42,203,210 defines the target's ECAM route,
//! legacy selector and scalar-access restrictions. APM2 physical pp578-580
//! defines IOIO/MSR interception. These values establish neither PCI effects
//! policy nor IOMMU ownership. Configuration data and reset effects remain
//! unsupported; no hardware access occurs in this module.

use crate::{
    arch::x86_64::{
        capabilities::ValidatedCapabilities,
        msr::{MMIO_CFG_BASE_ADDR, TARGET_PHYSICAL_BITS, TARGET_SIGNATURE},
        registers::GuestRegisters,
    },
    svm::{
        dispatch::{NativeEferError, hardware_msr_instruction, validate_native_msr_boundary},
        permission_maps::{Iopm, MsrAccess, Msrpm, Permission, PermissionMapError},
        vmcb::{InstructionIntercept, Vmcb},
    },
};

const ROUTE_BASE: u64 = 0x0000_ffff_fff0_0000;
const ROUTE_DEFINED: u64 = ROUTE_BASE | 0x3d;
const LEGACY_DEFINED: u32 = 0x80ff_fffc;

/// An immutable route observed on the owning CPU, retained through guest INIT.
/// Runtime admission must additionally match the common protected expectation,
/// exclude owned RAM and install the aperture's NPT write protection. Firmware
/// and SMM remain trusted; sampling drift is not physical route locking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigurationRoute {
    raw: u64,
    base: u64,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteError {
    UnsupportedCpu,
    ReservedBits,
    Disabled,
    UnsupportedSegments,
    ApertureAlignment,
    PhysicalAddress,
    Drift,
}

impl ConfigurationRoute {
    /// Numeric admission for the exact target, with enabled segment-zero ECAM.
    /// PPR BusRange 9..15 describes multiple segments; the present owner refuses
    /// those defined encodings explicitly instead of truncating them to bus bits.
    pub fn admit_target(signature: u32, physical_bits: u8, raw: u64) -> Result<Self, RouteError> {
        if signature != TARGET_SIGNATURE || physical_bits != TARGET_PHYSICAL_BITS {
            return Err(RouteError::UnsupportedCpu);
        }
        if raw & !ROUTE_DEFINED != 0 {
            return Err(RouteError::ReservedBits);
        }
        if raw & 1 == 0 {
            return Err(RouteError::Disabled);
        }
        let range = (raw >> 2) & 15;
        if range > 8 {
            return Err(RouteError::UnsupportedSegments);
        }
        let base = raw & ROUTE_BASE;
        let bytes = 1u64 << (20 + range);
        if base & (bytes - 1) != 0 {
            return Err(RouteError::ApertureAlignment);
        }
        if base == 0 || base.checked_add(bytes).is_none_or(|end| end > (1u64 << physical_bits)) {
            return Err(RouteError::PhysicalAddress);
        }
        Ok(Self { raw, base, bytes })
    }

    pub const fn raw(self) -> u64 {
        self.raw
    }

    pub const fn aperture(self) -> (u64, u64) {
        (self.base, self.bytes)
    }

    pub const fn contains(self, address: u64) -> bool {
        address >= self.base && address - self.base < self.bytes
    }

    pub fn verify(self, observed: u64) -> Result<(), RouteError> {
        if observed == self.raw { Ok(()) } else { Err(RouteError::Drift) }
    }

    /// Establish the native boot I/O baseline before entry: other I/O ports
    /// execute natively, every access touching CF8..CFF is intercepted, and
    /// both route-MSR directions are owned. This has no endpoint dependency.
    /// Call only while constructing an exclusively owned, never-entered VMCB.
    pub fn install_native_intercepts(
        self,
        io: &mut Iopm,
        msrs: &mut Msrpm,
        vmcb: &mut Vmcb,
    ) -> Result<(), PermissionMapError> {
        io.set_range(0, 65536, Permission::Allow)?;
        io.set_range(0xcf8, 8, Permission::Intercept)?;
        for access in [MsrAccess::Read, MsrAccess::Write] {
            msrs.set(MMIO_CFG_BASE_ADDR, access, Permission::Intercept)?;
        }
        vmcb.set_instruction_intercept(InstructionIntercept::Ioio, true);
        vmcb.set_instruction_intercept(InstructionIntercept::Msr, true);
        Ok(())
    }

    /// Validate the controls this owner requires without changing any state.
    pub fn intercepts_installed(self, io: &Iopm, msrs: &Msrpm, vmcb: &Vmcb) -> bool {
        // MSRPM pairs are read then write; C001_0058 is byte 1016h, bits1:0.
        // The IOPM byte at CF8h/8 covers every touched CF8..CFF lane.
        io.bytes()[0xcf8 / 8] == 0xff
            && msrs.bytes()[0x1016] & 3 == 3
            && vmcb.instruction_intercept(InstructionIntercept::Ioio)
            && vmcb.instruction_intercept(InstructionIntercept::Msr)
    }

    /// Numeric target only; this does not decode an instruction, authorize a
    /// hardware cycle or prove its cache type. All target effects need policy.
    pub fn ecam_scalar(self, address: u64, width: u8) -> Result<ScalarTarget, ScalarError> {
        validate_lane(address, width)?;
        if !self.contains(address)
            || address.checked_add(u64::from(width) - 1).is_none_or(|last| !self.contains(last))
        {
            return Err(ScalarError::OutsideAperture);
        }
        let offset = address - self.base;
        Ok(ScalarTarget { bdf: (offset >> 12) as u16, register: (offset & 0xfff) as u16, width })
    }
}

/// Standard legacy BCS selector only. ExtRegNo is deliberately refused; the
/// PPR requires BIOS to disable legacy ECS before the OS (physical p40).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacySelector(u32);

impl LegacySelector {
    pub fn admit(raw: u32) -> Result<Self, ScalarError> {
        if raw & 0x0f00_0000 != 0 {
            return Err(ScalarError::ExtendedLegacyUnsupported);
        }
        if raw & !LEGACY_DEFINED != 0 {
            return Err(ScalarError::ReservedSelector);
        }
        Ok(Self(raw))
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Numeric port/selector target only. Disabled selectors route to an I/O
    /// link, so they are not reinterpreted as safe all-ones configuration reads.
    pub fn data(self, port: u16, width: u8) -> Result<ScalarTarget, ScalarError> {
        if !(0xcfc..=0xcff).contains(&port) {
            return Err(ScalarError::PortOrWidth);
        }
        validate_lane(u64::from(port), width)?;
        if self.0 & (1 << 31) == 0 {
            return Err(ScalarError::DisabledLegacy);
        }
        Ok(ScalarTarget {
            bdf: (self.0 >> 8) as u16,
            register: (self.0 & 0xfc) as u16 + port - 0xcfc,
            width,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScalarTarget {
    pub bdf: u16,
    pub register: u16,
    pub width: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarError {
    PortOrWidth,
    DwordCrossing,
    OutsideAperture,
    ReservedSelector,
    ExtendedLegacyUnsupported,
    DisabledLegacy,
}

fn validate_lane(address: u64, width: u8) -> Result<(), ScalarError> {
    if !matches!(width, 1 | 2 | 4) {
        return Err(ScalarError::PortOrWidth);
    }
    if (address & 3) + u64::from(width) > 4 {
        return Err(ScalarError::DwordCrossing);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteAccessError {
    Route(RouteError),
    Instruction(NativeEferError),
    WrongMsr,
    RouteChangeUnsupported,
}

/// Complete a route read or an exact same-value write with hardware NRIP.
/// Every refusal leaves the VMCB/frame untouched. A changed route is an
/// unsupported transition, not a fabricated #GP or a falsely successful write.
/// The caller supplies a freshly sampled physical MSR from the owning CPU.
pub fn handle_route_msr(
    owner: &ConfigurationRoute,
    observed: u64,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    capabilities: &ValidatedCapabilities,
    startup_owned: bool,
) -> Result<(), RouteAccessError> {
    use RouteAccessError as E;
    owner.verify(observed).map_err(E::Route)?;
    let instruction = hardware_msr_instruction(vmcb, capabilities).map_err(E::Instruction)?;
    validate_native_msr_boundary(vmcb, instruction, startup_owned).map_err(E::Instruction)?;
    if frame.rcx as u32 != MMIO_CFG_BASE_ADDR {
        return Err(E::WrongMsr);
    }
    if vmcb.guest_cpl() != 0 || vmcb.guest_rflags() & (1 << 8) != 0 {
        return Err(E::Instruction(NativeEferError::UnsupportedMode));
    }
    let exit = vmcb.exit_snapshot();
    let next = instruction
        .continuation(exit)
        .map_err(|error| E::Instruction(NativeEferError::Instruction(error)))?;
    if exit.info1 == 1 {
        let value = u64::from(vmcb.guest_rax() as u32) | (u64::from(frame.rdx as u32) << 32);
        if value != observed {
            return Err(E::RouteChangeUnsupported);
        }
        // This ordinary read-write register has no command or W1C fields.
        // With the exact backing already present, the requested state holds.
        vmcb.commit_emulated_instruction(vmcb.guest_rax(), next);
    } else {
        vmcb.commit_emulated_instruction(u64::from(observed as u32), next);
        frame.rdx = observed >> 32;
    }
    vmcb.complete_native_instruction_state();
    Ok(())
}
