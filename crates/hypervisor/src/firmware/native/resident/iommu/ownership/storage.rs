use super::super::{
    MAX_OBSERVED_UNITS, Report,
    binding::UnitIdentity,
    resources::{ResourceError, ResourceStorage},
};
use super::{AdmissionError, admission::overlap};
use crate::{
    host::resident::IOMMU_RESOURCE_BYTES,
    memory::address::{AddressPolicy, PhysicalRange},
};

/// Actual exclusive disconnected storage, not merely an extent descriptor.
/// The caller allocates it without placing a multi-MiB object on the stack.
pub struct BankStorage<'a> {
    pub identity: UnitIdentity,
    pub extent: PhysicalRange,
    pub storage: &'a mut ResourceStorage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BankError {
    Admission(AdmissionError),
    Resource { bank: usize, error: ResourceError },
}

/// Initialize one real bank per declared physical unit. Complete identity,
/// extent, overlap and header/address preflight precedes the first mutation.
/// A later construction error may leave earlier banks initialized, never live.
/// `binding::bind` must subsequently validate the report/profile and all words.
/// This allocates nothing. The native allocator separately retains a bounded
/// bank and two composition generations for every supported native unit slot.
pub fn prepare_banks(
    policy: AddressPolicy,
    report: &Report,
    pool: PhysicalRange,
    banks: &mut [BankStorage<'_>],
) -> Result<(), BankError> {
    let fail = |error| BankError::Admission(error);
    let units = report.tables.ivrs.units();
    if !report.tables.is_complete()
        || units.is_empty()
        || units.len() > MAX_OBSERVED_UNITS
        || banks.len() != units.len()
    {
        return Err(fail(AdmissionError::UnitCount));
    }
    policy.validate(pool.base(), pool.len(), 4096).map_err(|_| fail(AdmissionError::Address))?;
    if pool.len() & 4095 != 0 {
        return Err(fail(AdmissionError::Address));
    }
    for (index, bank) in banks.iter().enumerate() {
        if !units.iter().any(|unit| UnitIdentity::from_unit(*unit) == bank.identity)
            || banks[..index].iter().any(|other| other.identity == bank.identity)
        {
            return Err(fail(AdmissionError::PublicationAssignment));
        }
        policy
            .validate(bank.extent.base(), bank.extent.len(), 4096)
            .map_err(|_| fail(AdmissionError::Address))?;
        if bank.extent.len() != IOMMU_RESOURCE_BYTES
            || bank.extent.base() < pool.base()
            || bank.extent.last_byte() > pool.last_byte()
        {
            return Err(fail(AdmissionError::Address));
        }
        if banks[..index].iter().any(|other| overlap(bank.extent, other.extent)) {
            return Err(fail(AdmissionError::Overlap));
        }
        bank.storage
            .preflight_prepare(policy, bank.extent.base())
            .map_err(|error| BankError::Resource { bank: index, error })?;
    }
    for (index, bank) in banks.iter_mut().enumerate() {
        bank.storage
            .prepare(policy, bank.extent.base())
            .map_err(|error| BankError::Resource { bank: index, error })?;
    }
    Ok(())
}
