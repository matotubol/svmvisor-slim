use super::super::{
    MAX_OBSERVED_UNITS, ObservationState, RegisterObservation,
    binding::{UninstalledBindingPlan, UninstalledUnitPlan, UnitIdentity},
    resources::{COMMAND_OFFSET, COMPLETION_OFFSET},
};
use crate::memory::{
    address::{AddressPolicy, PhysicalRange},
    iommu::queue::CommandRingGeometry,
};

const BASE: u64 = 0x000f_ffff_ffff_f000;
const MAX_COVERAGE_RANGES: usize = 128;
pub(super) const ENABLES: u64 = 1 | (1 << 2) | (1 << 12);
pub(super) const RUN: u64 = (1 << 3) | (1 << 4);
pub(super) const CONTROL_KEEP: u64 = (127 << 5) | (1 << 23) | (1 << 41);

/// Required ranges are checked completely, including allocation padding. These
/// caller-supplied interval sets are numeric claims only; Backend::acquire must
/// establish and retain their actual meaning on every CPU and DMA route.
pub struct Coverage<'a> {
    pub protected: &'a [PhysicalRange],
    pub cpu_denied: &'a [PhysicalRange],
    pub dma_denied: &'a [PhysicalRange],
    pub retained: &'a [PhysicalRange],
    pub writable_wb: &'a [PhysicalRange],
    pub control_denied: &'a [PhysicalRange],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageKind {
    Protected,
    CpuDenied,
    DmaDenied,
    Retained,
    WritableWb,
    ControlDenied,
}

/// Two retained destinations for a downstream composition owner. Capacity is
/// explicit and charged to both generations; the root-only deny bank cannot be
/// silently advertised as storage for arbitrary Windows mappings. The backend
/// validates each actual composed image against these capacities before use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationSpace {
    pub identity: UnitIdentity,
    pub generations: [PhysicalRange; 2],
    pub required_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitPlan {
    pub binding: UninstalledUnitPlan,
    pub old_commands: CommandRingGeometry,
    pub old_device_table: PhysicalRange,
    pub old_event_log: PhysicalRange,
    pub commands: CommandRingGeometry,
    pub completion_base: u64,
    pub publication: Option<PublicationSpace>,
}

/// Copied descriptors only. Allocation lifetime is owned by the backend, never
/// by these numbers. Preparing a plan performs no access to physical addresses.
#[derive(Clone, Debug)]
pub struct Plan {
    pub(super) policy: AddressPolicy,
    pub(super) units: [Option<UnitPlan>; MAX_OBSERVED_UNITS],
    pub(super) len: usize,
}

impl Plan {
    pub fn prepare(
        policy: AddressPolicy,
        binding: &UninstalledBindingPlan,
        coverage: Coverage<'_>,
        publication: &[PublicationSpace],
    ) -> Result<Self, AdmissionError> {
        if binding.is_empty() || binding.len() > MAX_OBSERVED_UNITS {
            return Err(AdmissionError::UnitCount);
        }
        if binding.observed_state() != ObservationState::Observed
            || binding.unresolved_diagnostics() != 0
        {
            return Err(AdmissionError::UnresolvedInventory);
        }
        if publication.len() > binding.len() {
            return Err(AdmissionError::PublicationAssignment);
        }
        for (kind, ranges) in coverage.sets() {
            validate_set(policy, kind, ranges)?;
        }
        // Every protected range (not merely each hardware bank) must survive
        // both CPU and DMA access denial, with the whole allocation retained.
        for &protected in coverage.protected {
            coverage.require(protected, CoverageKind::CpuDenied)?;
            coverage.require(protected, CoverageKind::DmaDenied)?;
            coverage.require(protected, CoverageKind::Retained)?;
        }
        for (index, space) in publication.iter().enumerate() {
            if !binding.units().any(|unit| unit.identity == space.identity)
                || publication[..index].iter().any(|other| other.identity == space.identity)
                || space.required_bytes == 0
                || space.required_bytes & 4095 != 0
            {
                return Err(AdmissionError::PublicationAssignment);
            }
            for &range in &space.generations {
                if range.len() < space.required_bytes {
                    return Err(AdmissionError::PublicationCapacity);
                }
                validate_page_range(policy, range)?;
                coverage.private_memory(range)?;
                for unit in binding.units() {
                    if overlap(range, unit.bank)
                        || overlap(range, unit.control_aperture)
                        || overlap(range, unit.configuration_page)
                    {
                        return Err(AdmissionError::Overlap);
                    }
                }
            }
            if overlap(space.generations[0], space.generations[1]) {
                return Err(AdmissionError::Overlap);
            }
            for other in &publication[..index] {
                for first in space.generations {
                    for second in other.generations {
                        if overlap(first, second) {
                            return Err(AdmissionError::Overlap);
                        }
                    }
                }
            }
        }
        let mut plan = Self { policy, units: [None; MAX_OBSERVED_UNITS], len: binding.len() };
        for (index, unit) in binding.units().enumerate() {
            validate_running_profile(unit.observed_registers)?;
            coverage.private_memory(unit.bank)?;
            coverage.require(unit.control_aperture, CoverageKind::ControlDenied)?;
            coverage.require(unit.configuration_page, CoverageKind::ControlDenied)?;
            let old_commands = ring(policy, unit.observed_registers.command_buffer)?;
            let old_device_table = policy
                .validate(
                    unit.observed_registers.device_table & BASE,
                    ((unit.observed_registers.device_table & 511) + 1) * 4096,
                    4096,
                )
                .map_err(|_| AdmissionError::Address)?;
            let old_event_log = ring(policy, unit.observed_registers.event_log)?.backing();
            for old in [old_commands.backing(), old_device_table, old_event_log] {
                for kind in
                    [CoverageKind::CpuDenied, CoverageKind::DmaDenied, CoverageKind::Retained]
                {
                    coverage.require(old, kind)?;
                }
                // Old rings/tables remain retained after success and failure;
                // no DMA drain is used as authority to reclaim this backing.
                for other in binding.units() {
                    if overlap(old, other.bank)
                        || overlap(old, other.control_aperture)
                        || overlap(old, other.configuration_page)
                    {
                        return Err(AdmissionError::Overlap);
                    }
                }
                for space in publication {
                    if space.generations.iter().any(|range| overlap(old, *range)) {
                        return Err(AdmissionError::Overlap);
                    }
                }
                if old.last_byte() >> unit.iommu_physical_bits != 0 {
                    return Err(AdmissionError::Address);
                }
            }
            coverage.require(old_commands.backing(), CoverageKind::WritableWb)?;
            let unit_publication =
                publication.iter().find(|space| space.identity == unit.identity).copied();
            if unit_publication.is_some_and(|space| {
                space
                    .generations
                    .iter()
                    .any(|range| range.last_byte() >> unit.iommu_physical_bits != 0)
            }) {
                return Err(AdmissionError::Address);
            }
            plan.units[index] = Some(UnitPlan {
                binding: *unit,
                old_commands,
                old_device_table,
                old_event_log,
                commands: CommandRingGeometry::new(policy, unit.bank.base() + COMMAND_OFFSET, 1)
                    .map_err(|_| AdmissionError::Address)?,
                completion_base: unit.bank.base() + COMPLETION_OFFSET,
                publication: unit_publication,
            });
        }
        // Even old buffers belonging to different units may not alias. In
        // particular a completion on one engine never lends the other's ring.
        for (index, first) in plan.units().enumerate() {
            let ranges =
                [first.old_commands.backing(), first.old_device_table, first.old_event_log];
            for (r, &range) in ranges.iter().enumerate() {
                if ranges[..r].iter().any(|other| overlap(range, *other)) {
                    return Err(AdmissionError::Overlap);
                }
                for second in plan.units().take(index) {
                    if [
                        second.old_commands.backing(),
                        second.old_device_table,
                        second.old_event_log,
                    ]
                    .iter()
                    .any(|other| overlap(range, *other))
                    {
                        return Err(AdmissionError::Overlap);
                    }
                }
            }
        }
        Ok(plan)
    }

    pub fn units(&self) -> impl Iterator<Item = &UnitPlan> {
        self.units[..self.len].iter().flatten()
    }
    pub fn unit(&self, index: usize) -> Option<&UnitPlan> {
        self.units.get(index).and_then(Option::as_ref)
    }
    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Coverage<'_> {
    fn sets(&self) -> [(CoverageKind, &[PhysicalRange]); 6] {
        [
            (CoverageKind::Protected, self.protected),
            (CoverageKind::CpuDenied, self.cpu_denied),
            (CoverageKind::DmaDenied, self.dma_denied),
            (CoverageKind::Retained, self.retained),
            (CoverageKind::WritableWb, self.writable_wb),
            (CoverageKind::ControlDenied, self.control_denied),
        ]
    }

    fn require(&self, range: PhysicalRange, kind: CoverageKind) -> Result<(), AdmissionError> {
        let ranges = self.sets().into_iter().find(|(candidate, _)| *candidate == kind).unwrap().1;
        let mut next = range.base();
        for covering in ranges {
            if covering.last_byte() < next {
                continue;
            }
            if covering.base() > next {
                break;
            }
            if covering.last_byte() >= range.last_byte() {
                return Ok(());
            }
            next = covering.last_byte() + 1;
        }
        Err(AdmissionError::Coverage { kind, range })
    }

    fn private_memory(&self, range: PhysicalRange) -> Result<(), AdmissionError> {
        for kind in [
            CoverageKind::Protected,
            CoverageKind::CpuDenied,
            CoverageKind::DmaDenied,
            CoverageKind::Retained,
            CoverageKind::WritableWb,
        ] {
            self.require(range, kind)?;
        }
        Ok(())
    }
}

fn validate_set(
    policy: AddressPolicy,
    kind: CoverageKind,
    ranges: &[PhysicalRange],
) -> Result<(), AdmissionError> {
    if ranges.is_empty() || ranges.len() > MAX_COVERAGE_RANGES {
        return Err(AdmissionError::CoverageSet(kind));
    }
    for (index, &range) in ranges.iter().enumerate() {
        validate_page_range(policy, range)?;
        if index != 0 && ranges[index - 1].last_byte() >= range.base() {
            return Err(AdmissionError::CoverageSet(kind));
        }
    }
    Ok(())
}

fn validate_page_range(policy: AddressPolicy, range: PhysicalRange) -> Result<(), AdmissionError> {
    if range.len() & 4095 != 0 {
        return Err(AdmissionError::Address);
    }
    policy.validate(range.base(), range.len(), 4096).map_err(|_| AdmissionError::Address)?;
    Ok(())
}

pub(super) fn overlap(first: PhysicalRange, second: PhysicalRange) -> bool {
    first.base() <= second.last_byte() && second.base() <= first.last_byte()
}

fn ring(policy: AddressPolicy, raw: u64) -> Result<CommandRingGeometry, AdmissionError> {
    let length = raw >> 56 & 15;
    if length < 8 || raw & BASE == 0 {
        return Err(AdmissionError::OldQueue);
    }
    CommandRingGeometry::new(policy, raw & BASE, 1usize << (length - 8))
        .map_err(|_| AdmissionError::OldQueue)
}

pub(super) fn validate_running_profile(
    registers: RegisterObservation,
) -> Result<(), AdmissionError> {
    if registers.extended_features.unwrap_or(0) & (1 << 6) == 0 {
        return Err(AdmissionError::InvalidateAllUnsupported);
    }
    // Narrow takeover only: old DMA/command/event engines already running,
    // no pending events, no exclusion or optional active mode. Read-only CRW
    // and documented reserved control read bits are not written back.
    let ignored = (15 << 18) | (1 << 49) | (1 << 57);
    if registers.control & ENABLES != ENABLES
        || registers.status & RUN != RUN
        || registers.status & 3 != 0
        || registers.control & !(CONTROL_KEEP | ENABLES | (3 << 3) | ignored) != 0
        || registers.exclusion_base & 1 != 0
        || registers.device_table & BASE == 0
    {
        return Err(AdmissionError::OldProfile);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    UnitCount,
    UnresolvedInventory,
    Address,
    Overlap,
    OldQueue,
    OldProfile,
    InvalidateAllUnsupported,
    PublicationAssignment,
    PublicationCapacity,
    CoverageSet(CoverageKind),
    Coverage { kind: CoverageKind, range: PhysicalRange },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeBlocker {
    CurrentRequesterRoutingA0A5AndAliasRange,
    IvmdReservationAndBypassPolicy,
    CompleteFabricB8BcControlMap,
    ResetPowerAndSmmControlClosure,
    RequesterQuiescenceAndRemoteIotlbDrain,
    OldQueueHandoffAndCompletionCellExclusivity,
    AllCpuAndDmaMemoryIntegrity,
    GuestTableCpuAndDmaWriteTracking,
    WindowsInterruptEventAndLifecycleContract,
}

/// Exact unresolved native facts. Historical F7 disassembly, a numeric plan or
/// an injected backend cannot clear these. There is deliberately no boolean
/// "override", native constructor, hardware write, or reader activation here.
pub const fn native_blockers() -> &'static [NativeBlocker] {
    &[
        NativeBlocker::CurrentRequesterRoutingA0A5AndAliasRange,
        NativeBlocker::IvmdReservationAndBypassPolicy,
        NativeBlocker::CompleteFabricB8BcControlMap,
        NativeBlocker::ResetPowerAndSmmControlClosure,
        NativeBlocker::RequesterQuiescenceAndRemoteIotlbDrain,
        NativeBlocker::OldQueueHandoffAndCompletionCellExclusivity,
        NativeBlocker::AllCpuAndDmaMemoryIntegrity,
        NativeBlocker::GuestTableCpuAndDmaWriteTracking,
        NativeBlocker::WindowsInterruptEventAndLifecycleContract,
    ]
}

/// Fail-closed native entry boundary. An injected transaction can exercise the
/// protocol without changing this result or creating reader authority.
pub fn require_native_admission() -> Result<(), &'static [NativeBlocker]> {
    Err(native_blockers())
}
