//! Stopped instruction adapters. The supplied Bus already holds an explicit
//! effect owner; the missing-owner path commits neither registers nor RIP.

use super::{ConfigAccess, Error};
use crate::svm::{
    diagnostic_config::PreparedIo,
    mmio::{Direction, PreparedMmio},
};

/// Caller has already applied same-CPU HWCR/SMI-trap precedence and holds the
/// shared route gate. No hardware CF8/CFC cycle is performed by this adapter.
pub fn complete_io(
    prepared: PreparedIo<'_>,
    owner: Option<&mut dyn ConfigAccess>,
) -> Result<(), Error> {
    let owner = owner.ok_or(Error::MissingOwner)?;
    let write = (!prepared.input()).then(|| prepared.output_value());
    let value = owner.io(prepared.port(), prepared.width_bytes(), write)?;
    prepared.commit(value);
    Ok(())
}

/// Preparation's translation callback must already have checked UC and the
/// complete operand span. This adds the target PPR's accumulator-only ECAM
/// restriction and uses the identical bank as legacy configuration data I/O.
pub fn complete_ecam(
    prepared: PreparedMmio<'_>,
    owner: Option<&mut dyn ConfigAccess>,
) -> Result<(), Error> {
    let owner = owner.ok_or(Error::MissingOwner)?;
    if !prepared.accumulator_operand() {
        return Err(Error::NonAccumulator);
    }
    let access = prepared.access();
    let value = owner.ecam(
        access.guest_physical,
        access.linear.bytes,
        access.write_value.map(|value| value as u32),
    )?;
    match access.linear.direction {
        Direction::Read => prepared.commit_read(u64::from(value)),
        Direction::Write => prepared.commit_write(),
    }
    .map_err(|_| Error::Commit)
}
