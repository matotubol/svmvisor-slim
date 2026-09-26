//! Pure binding of disconnected candidate banks to a historical report.
//!
//! Success describes numeric relationships in these inputs only. It establishes
//! neither requester/reservation closure, current hardware state, DMA integrity,
//! quiescence nor authority to install a table, deny CPU controls or enable a
//! reader. The immutable report retains every ambiguity. See README.md.
#![forbid(unsafe_code)]

mod profile;
mod ranges;

pub use profile::ProfileError;
pub use ranges::{ObservedBuffer, Region};

use super::{
    AcquisitionError, HardwareError, MAX_OBSERVED_UNITS, ObservationState, PciObservation,
    RegisterObservation, Report, UnitObservation,
    resources::{ResourceError, ResourceHeader, ResourceStorage},
};
use crate::{
    host::resident::IOMMU_RESOURCE_BYTES,
    memory::{
        address::{AddressError, AddressPolicy, PhysicalRange},
        iommu::IommuUnit,
    },
};

/// Every identity component is explicit; neither a PCI function alone nor an
/// IVHD form ordinal identifies a unit (48882-3.11 physical pp205-208).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitIdentity {
    pub segment: u16,
    pub device_id: u16,
    pub capability_offset: u16,
    pub mmio_base: u64,
}

impl UnitIdentity {
    pub const fn from_unit(unit: IommuUnit) -> Self {
        Self {
            segment: unit.segment,
            device_id: unit.device_id,
            capability_offset: unit.capability_offset,
            mmio_base: unit.mmio_base,
        }
    }

    fn same_capability(self, other: Self) -> bool {
        self.segment == other.segment
            && self.device_id == other.device_id
            && self.capability_offset == other.capability_offset
    }
}

/// The extent is an independently supplied physical assignment, not a physical
/// address derived from this Rust reference. Both must describe the same bank.
/// A full immutable payload check occurs before a plan can be returned.
pub struct UnitAssignment<'a> {
    pub identity: UnitIdentity,
    pub extent: PhysicalRange,
    pub storage: &'a ResourceStorage,
}

/// Exactly the existing retained image: 65,536 Mode=4/domain=0/no-read/no-write
/// DTEs with controlled interrupt aborts, one empty root and one empty page each
/// for commands, events and completion. No optional tables/logs or bypass policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceProfile {
    DenyEmptyUnsegmentedBasic,
}

/// A copied numeric description, deliberately carrying no storage borrow or
/// hardware adapter. The observed registers can be active and historical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UninstalledUnitPlan {
    pub unit_index: u16,
    pub identity: UnitIdentity,
    pub configuration_page: PhysicalRange,
    pub control_aperture: PhysicalRange,
    pub bank: PhysicalRange,
    pub resource_header: ResourceHeader,
    pub observed_pci: PciObservation,
    pub observed_registers: RegisterObservation,
    /// Meaningful observed control fields required to be zero for this profile.
    /// This is a validation mask, never a value to write to hardware.
    pub profile_zero_control_mask: u64,
    pub iommu_physical_bits: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UninstalledBindingPlan {
    units: [Option<UninstalledUnitPlan>; MAX_OBSERVED_UNITS],
    len: usize,
    observed_state: ObservationState,
    unresolved_diagnostics: usize,
}

impl UninstalledBindingPlan {
    pub const fn profile(&self) -> ResourceProfile {
        ResourceProfile::DenyEmptyUnsegmentedBasic
    }

    pub fn units(&self) -> impl Iterator<Item = &UninstalledUnitPlan> {
        self.units[..self.len].iter().flatten()
    }

    pub fn unit(&self, report_index: usize) -> Option<&UninstalledUnitPlan> {
        self.units.get(report_index).and_then(Option::as_ref)
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn observed_state(&self) -> ObservationState {
        self.observed_state
    }

    /// Count retained from the input, not evidence that any diagnostic was
    /// resolved. The complete diagnostic records remain in the borrowed report.
    pub const fn unresolved_diagnostics(&self) -> usize {
        self.unresolved_diagnostics
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingError {
    IncompleteTables,
    Acquisition(AcquisitionError),
    ObservationState(ObservationState),
    UnitCount,
    AssignmentCount { units: usize, assignments: usize },
    DuplicateUnitIdentity { first: usize, second: usize },
    DuplicateAssignment { first: usize, second: usize },
    UnknownUnit { assignment: usize },
    ReusedStorage { first: usize, second: usize },
    MissingObservation { unit: usize },
    UnexpectedObservation { unit: usize },
    Hardware { unit: usize, error: HardwareError },
    CapabilityOffset { unit: usize },
    EcamIdentity { unit: usize },
    MmioIdentity { unit: usize },
    ApertureMismatch { unit: usize, expected: u64, observed: u64 },
    Profile { unit: usize, error: ProfileError },
    HostTranslationDisabled { unit: usize, form: usize },
    FirmwareFeatures { unit: usize, form: usize },
    Address { region: Region, error: AddressError },
    PartialPoolPage,
    BankSize { assignment: usize },
    BankOutsidePool { assignment: usize },
    IommuAddressWidth { unit: usize, region: Region },
    Overlap { first: Region, second: Region },
    Resources { assignment: usize, error: ResourceError },
    ObservedBuffer { unit: usize, buffer: ObservedBuffer },
}

/// Validate the complete inventory-to-bank assignment without I/O or mutation.
/// Work is bounded by the parser's limits, at most 16 assignments and the fixed
/// bank payload sizes. All units require separate banks; no partial plan escapes.
/// `protected_pool` is an asserted numeric exclusion, not proof of protection.
pub fn bind(
    policy: AddressPolicy,
    report: &Report,
    protected_pool: PhysicalRange,
    assignments: &[UnitAssignment<'_>],
) -> Result<UninstalledBindingPlan, BindingError> {
    if !report.tables.is_complete() {
        return Err(BindingError::IncompleteTables);
    }
    if let Some(error) = report.failure {
        return Err(BindingError::Acquisition(error));
    }
    if !matches!(report.state, ObservationState::Observed | ObservationState::Ambiguous) {
        return Err(BindingError::ObservationState(report.state));
    }
    let units = report.tables.ivrs.units();
    if units.is_empty() || units.len() > MAX_OBSERVED_UNITS {
        return Err(BindingError::UnitCount);
    }
    if assignments.len() != units.len() {
        return Err(BindingError::AssignmentCount {
            units: units.len(),
            assignments: assignments.len(),
        });
    }
    for (index, observation) in report.hardware.iter().enumerate().skip(units.len()) {
        if *observation != UnitObservation::EMPTY {
            return Err(BindingError::UnexpectedObservation { unit: index });
        }
    }
    ranges::pool_and_assignments(policy, report, protected_pool, assignments)?;
    let mut plan = UninstalledBindingPlan {
        units: [None; MAX_OBSERVED_UNITS],
        len: units.len(),
        observed_state: report.state,
        unresolved_diagnostics: report
            .tables
            .ivrs
            .diagnostics()
            .iter()
            .filter(|d| d.kind.requires_resolution())
            .count(),
    };
    for (index, unit) in units.iter().copied().enumerate() {
        let identity = UnitIdentity::from_unit(unit);
        if let Some(first) = units[..index]
            .iter()
            .position(|other| identity.same_capability(UnitIdentity::from_unit(*other)))
        {
            return Err(BindingError::DuplicateUnitIdentity { first, second: index });
        }
        let observation = report.hardware[index];
        if let Some(error) = observation.error {
            return Err(BindingError::Hardware { unit: index, error });
        }
        let (Some(pci), Some(registers), Some(mmio_bytes)) =
            (observation.pci, observation.registers, observation.mmio_bytes)
        else {
            return Err(BindingError::MissingObservation { unit: index });
        };
        if !(0x40..=0xec).contains(&identity.capability_offset)
            || identity.capability_offset & 3 != 0
        {
            return Err(BindingError::CapabilityOffset { unit: index });
        }
        for (form_index, form) in report.tables.ivrs.forms().iter().enumerate() {
            if usize::from(form.unit_index) != index {
                continue;
            }
            // Extended attributes bit 0 is HATDis; legacy 10h bit 0 instead
            // reports XTSup. HATDis makes HATS meaningless and forbids this
            // profile's nonzero host root (48882-3.11 physical pp300,302).
            if matches!(form.kind, 0x11 | 0x40) && form.feature_info & 1 != 0 {
                return Err(BindingError::HostTranslationDisabled {
                    unit: index,
                    form: form_index,
                });
            }
            if form.efr.is_some() && form.efr != registers.extended_features
                || form.efr2.is_some() && form.efr2 != registers.extended_features2
            {
                return Err(BindingError::FirmwareFeatures { unit: index, form: form_index });
            }
        }
        let details = profile::validate(pci, registers)
            .map_err(|error| BindingError::Profile { unit: index, error })?;
        if usize::from(identity.capability_offset) + details.capability_bytes > 256 {
            return Err(BindingError::CapabilityOffset { unit: index });
        }
        if pci.base_low & 1 == 0
            || identity.mmio_base == 0
            || (u64::from(pci.base_high) << 32) | u64::from(pci.base_low & 0xffff_c000)
                != identity.mmio_base
        {
            return Err(BindingError::MmioIdentity { unit: index });
        }
        if mmio_bytes != details.aperture_bytes {
            return Err(BindingError::ApertureMismatch {
                unit: index,
                expected: details.aperture_bytes,
                observed: mmio_bytes,
            });
        }
        let control_aperture = ranges::checked(
            policy,
            identity.mmio_base,
            mmio_bytes,
            mmio_bytes,
            Region::ControlAperture { unit: index },
        )?;
        let configuration_page = ranges::configuration_page(policy, report, identity, index)?;
        if configuration_page.base() != pci.config_page {
            return Err(BindingError::EcamIdentity { unit: index });
        }
        // Assignment identities were checked as a complete bijection above.
        let Some((assignment_index, assignment)) =
            assignments.iter().enumerate().find(|(_, a)| a.identity == identity)
        else {
            return Err(BindingError::UnknownUnit { assignment: index });
        };
        ranges::iommu_width(details.physical_bits, protected_pool, index, Region::ProtectedPool)?;
        ranges::iommu_width(
            details.physical_bits,
            assignment.extent,
            index,
            Region::Bank { assignment: assignment_index },
        )?;
        ranges::control_disjoint(report, protected_pool, &plan, control_aperture, index)?;
        plan.units[index] = Some(UninstalledUnitPlan {
            unit_index: index as u16,
            identity,
            configuration_page,
            control_aperture,
            bank: assignment.extent,
            resource_header: assignment.storage.header(),
            observed_pci: pci,
            observed_registers: registers,
            profile_zero_control_mask: details.zero_control_mask,
            iommu_physical_bits: details.physical_bits,
        });
    }
    // Check configured basic pointers even if their enable bits are clear: clear
    // does not establish drain or permit reuse (48882-3.11 pp221,252-256).
    ranges::observed_buffers(policy, report, protected_pool, &plan)?;
    for (index, assignment) in assignments.iter().enumerate() {
        assignment
            .storage
            .verify(policy, assignment.extent.base())
            .map_err(|error| BindingError::Resources { assignment: index, error })?;
    }
    Ok(plan)
}
