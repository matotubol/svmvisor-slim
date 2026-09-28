//! Optional page-table diagnostics using fresh physical reads and process identity checks.

use svmvisor_card_abi::diagnostic::DiagnosticObservation;
use svmvisor_hypervisor::reader::{
    paging,
    process::{self, ProcessError, ProcessObservation},
};

use crate::{bridge::ReadBridge, profile::KernelProfile};

pub use svmvisor_hypervisor::reader::paging::{
    PagingConfig, PagingError, PagingLevel, Translation, WalkEntry, WalkTrace,
};

/// A best-effort address observation bracketed by matching process-identity checks.
/// This does not pin pages, certify access permissions or establish an atomic snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressExplanation {
    pub pid: u32,
    pub created: u64,
    pub paging: PagingConfig,
    pub walk: WalkTrace,
}

#[derive(Debug)]
pub(crate) enum AddressError {
    Identity(ProcessError),
    Backend(String),
}

/// Two bounded identity checks plus one four-level walk: at most 124 physical reads.
/// Revalidation has no list traversal, retry or translation cache. Every physical request
/// shares the phase deadline that the caller set before entering this function.
pub(crate) fn explain(
    config: PagingConfig,
    profile: &KernelProfile,
    kernel_root: u64,
    identity: ProcessObservation,
    va: u64,
    bridge: &mut ReadBridge,
) -> Result<WalkTrace, AddressError> {
    let mut backend_error = None;
    let mut read = |pa, bytes: &mut [u8]| {
        bridge.read(pa, bytes).map_err(|error| {
            backend_error = Some(error);
            PagingError::PhysicalRead
        })
    };
    let result = observe(config, profile, kernel_root, identity, va, &mut read);
    if let Some(error) = backend_error {
        return Err(AddressError::Backend(error));
    }
    result.map_err(AddressError::Identity)
}

/// Replay the sampled entries locally through the same walker. This verifies the sequence
/// and derives levels, indices, failure and translation without any additional guest reads.
pub(crate) fn decode(
    bytes: &[u8],
    config: PagingConfig,
    root: u64,
    va: u64,
) -> Result<WalkTrace, String> {
    let observation = DiagnosticObservation::decode(bytes)
        .map_err(|error| format!("invalid diagnostic observation: {error:?}"))?;
    if observation.root != root
        || observation.address != va
        || observation.physical_bits != config.physical_bits()
        || observation.nxe != config.nxe()
        || observation.page_1g != config.page_1g()
    {
        return Err("diagnostic root, address or paging profile mismatch".into());
    }
    let mut consumed = 0;
    let walk = paging::trace(config, root, va, &mut |address, output| {
        let entry = observation
            .entries
            .get(consumed)
            .filter(|_| consumed < observation.count)
            .ok_or(PagingError::PhysicalRead)?;
        if entry.address != address || output.len() != 8 {
            return Err(PagingError::PhysicalRead);
        }
        output.copy_from_slice(&entry.value.to_le_bytes());
        consumed += 1;
        Ok(())
    });
    if consumed != observation.count || walk.result == Err(PagingError::PhysicalRead) {
        return Err("diagnostic entry sequence mismatch".into());
    }
    Ok(walk)
}

fn observe(
    config: PagingConfig,
    profile: &KernelProfile,
    kernel_root: u64,
    identity: ProcessObservation,
    va: u64,
    read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), PagingError>,
) -> Result<WalkTrace, ProcessError> {
    process::revalidate(config, profile.process(), kernel_root, identity, read)?;
    let walk = paging::trace(config, identity.kernel_root_pa, va, read);
    // A transport failure ends the operation immediately, as it does for normal reads.
    if walk.result == Err(PagingError::PhysicalRead) {
        return Ok(walk);
    }
    process::revalidate(config, profile.process(), kernel_root, identity, read)?;
    Ok(walk)
}

#[cfg(test)]
mod tests {
    use super::*;

    use svmvisor_card_abi::diagnostic::DiagnosticEntry;

    fn observation() -> DiagnosticObservation {
        DiagnosticObservation {
            root: 0x1000,
            address: 0x1234,
            physical_bits: 48,
            nxe: true,
            page_1g: true,
            count: 2,
            entries: [
                DiagnosticEntry { address: 0x1000, value: 0x2001 },
                DiagnosticEntry { address: 0x2000, value: 0x81 },
                DiagnosticEntry::EMPTY,
                DiagnosticEntry::EMPTY,
            ],
        }
    }

    #[test]
    fn replay_validates_context_and_every_consumed_entry() {
        let config = PagingConfig::new(48, true, true).unwrap();
        let original = observation();
        let trace = decode(&original.encode().unwrap(), config, 0x1000, 0x1234).unwrap();
        assert_eq!(trace.result.unwrap().pa(), 0x1234);
        for change in 0..9 {
            let mut value = original;
            match change {
                0 => value.root += 0x1000,
                1 => value.address += 1,
                2 => value.physical_bits -= 1,
                3 => value.nxe = false,
                4 => value.page_1g = false,
                5 => value.entries[1].address += 8,
                6 => value.entries[0].value = 0x3001,
                7 => value.entries[0].value = 0, // Premature stop with an extra entry.
                _ => {
                    value.count = 1;
                    value.entries[1] = DiagnosticEntry::EMPTY;
                }
            }
            assert!(
                decode(&value.encode().unwrap(), config, 0x1000, 0x1234).is_err(),
                "case {change}"
            );
        }
    }

    #[test]
    fn replay_preserves_raw_nonpresent_bits_and_reserved_bit_failures() {
        let config = PagingConfig::new(48, true, true).unwrap();
        for (raw, error) in
            [(u64::MAX - 1, PagingError::NotPresent), (0x0081, PagingError::ReservedBitsSet)]
        {
            let mut value = observation();
            value.count = 1;
            value.entries[0].value = raw;
            value.entries[1] = DiagnosticEntry::EMPTY;
            let trace = decode(&value.encode().unwrap(), config, 0x1000, 0x1234).unwrap();
            assert_eq!(trace.result, Err(error));
            assert_eq!(trace.entries[0].unwrap().raw, Some(raw));
        }
    }
}
