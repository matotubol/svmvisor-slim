//! ACPI_Spec_6.6 p179 delegates the MCFG payload to PCI Firmware Spec.
//! The 44-byte header / 16-byte allocation layout is cross-checked against
//! https://github.com/tianocore/edk2/blob/master/MdePkg/Include/IndustryStandard/MemoryMappedConfigurationSpaceAccessTable.h
//! Bus-zero-relative bases (including nonzero start buses) are documented at
//! https://docs.kernel.org/PCI/acpi-info.html . One MiB per bus also follows
//! 57896-3.00_PPR p210. Multiple disjoint ranges per segment are permitted;
//! neither overlapping bus ownership nor physical ECAM aliasing is accepted.

use super::acpi::Bytes;
use super::{Limit, Mcfg, McfgAllocation, ParseError, ParseErrorKind, validate_sdt};

pub fn parse_mcfg(bytes: &[u8]) -> Result<Mcfg, ParseError> {
    let mut out = Mcfg::EMPTY;
    parse_mcfg_into(bytes, &mut out)?;
    Ok(out)
}

/// Output is empty on failure; successful records own no input references.
pub fn parse_mcfg_into(bytes: &[u8], out: &mut Mcfg) -> Result<(), ParseError> {
    out.clear();
    let result = parse(bytes, out);
    if result.is_err() {
        out.clear();
    }
    result
}

fn parse(bytes: &[u8], out: &mut Mcfg) -> Result<(), ParseError> {
    out.header = validate_sdt(bytes, *b"MCFG")?;
    let r = Bytes::new(bytes, *b"MCFG", 0);
    if out.header.revision != 1 {
        return Err(r.fail(8, ParseErrorKind::UnsupportedRevision));
    }
    r.zero(36, 8)?;
    if (bytes.len() - 44) % 16 != 0 {
        return Err(r.fail(4, ParseErrorKind::InvalidLength));
    }
    for offset in (44..bytes.len()).step_by(16) {
        let base = r.u64(offset)?;
        let segment = r.u16(offset + 8)?;
        let start_bus = r.u8(offset + 10)?;
        let end_bus = r.u8(offset + 11)?;
        r.zero(offset + 12, 4)?;
        if start_bus > end_bus {
            return Err(r.fail(offset + 10, ParseErrorKind::InvalidRange));
        }
        if base & ((1 << 20) - 1) != 0 {
            return Err(r.fail(offset, ParseErrorKind::MisalignedAddress));
        }
        let start = base
            .checked_add((start_bus as u64) << 20)
            .ok_or_else(|| r.fail(offset, ParseErrorKind::AddressOverflow))?;
        let last = base
            .checked_add((((end_bus as u64) + 1) << 20) - 1)
            .ok_or_else(|| r.fail(offset, ParseErrorKind::AddressOverflow))?;
        for prior in out.allocations() {
            if prior.segment == segment && prior.start_bus <= end_bus && start_bus <= prior.end_bus
            {
                return Err(r.fail(offset, ParseErrorKind::ConflictingEcamBuses));
            }
            if prior.start <= last && start <= prior.last {
                return Err(r.fail(offset, ParseErrorKind::OverlappingEcam));
            }
        }
        out.allocations.push(
            McfgAllocation {
                offset: offset as u32,
                base,
                segment,
                start_bus,
                end_bus,
                start,
                last,
            },
            *b"MCFG",
            offset,
            Limit::McfgAllocations,
        )?;
    }
    if out.allocations().is_empty() {
        return Err(r.fail(44, ParseErrorKind::MissingMcfgAllocation));
    }
    Ok(())
}
