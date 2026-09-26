//! Descriptor policy limited to preboot acquisition; generic RAM readers do
//! not gain access to ACPI reclaim/NVS or MMIO through this module.
use super::ReadError;
use crate::{
    boot::memory::{MemoryDescriptor, ValidatedMemoryMap},
    host::paging::PagingConfig,
    memory::address::AddressPolicy,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryKind {
    Firmware,
    Acpi,
    PageTable,
    Mmio,
}

/// Root cache preflight for the native adapter. The descriptor, live mapping,
/// parent-entry cache bits and effective target-page MTRRs still require their
/// own checks. APM Vol2 physical p220: with CR4.PCIDE set, CR3[11:0] is a PCID,
/// not root PWT/PCD. This alone does not admit a physical read.
pub fn root_cache_preflight(
    policy: AddressPolicy,
    config: PagingConfig,
    mtrr_physical_bits: u8,
    pat: u64,
) -> Result<(), ReadError> {
    if config.physical_bits != policy.physical_bits()
        || mtrr_physical_bits != policy.physical_bits()
        || pat & 255 != 6
        || (!config.pcid && config.cr3 & 0x18 != 0)
    {
        return Err(ReadError::CacheType);
    }
    Ok(())
}

/// Metadata is necessary, not sufficient: a native adapter must separately
/// validate live translations and effective PAT/MTRR cache type before access.
pub fn descriptor_span(
    map: &[MemoryDescriptor],
    policy: AddressPolicy,
    kind: MemoryKind,
    base: u64,
    bytes: u64,
) -> Result<(), ReadError> {
    policy.validate(base, bytes, 1).map_err(|_| ReadError::Address)?;
    ValidatedMemoryMap::new(map, policy.physical_bits()).map_err(|_| ReadError::MemoryMap)?;
    let end = base.checked_add(bytes).ok_or(ReadError::Address)?;
    let mut cursor = base;
    for descriptor in map {
        // ValidatedMemoryMap has checked these products and sums, including
        // every unused descriptor, before any native read is authorized.
        let last = descriptor.physical_start + descriptor.page_count * 4096;
        if last <= cursor {
            continue;
        }
        if descriptor.physical_start > cursor {
            return Err(ReadError::MemoryMap);
        }
        let allowed = match kind {
            MemoryKind::Firmware => (1..=6).contains(&descriptor.memory_type),
            MemoryKind::Acpi => matches!(descriptor.memory_type, 9 | 10),
            MemoryKind::PageTable => (1..=7).contains(&descriptor.memory_type),
            MemoryKind::Mmio => descriptor.memory_type == 11,
        };
        if !allowed {
            return Err(ReadError::MemoryType);
        }
        if descriptor.attributes & 0x2000 != 0 {
            return Err(ReadError::ReadProtected);
        }
        let capability = if kind == MemoryKind::Mmio { 1 } else { 8 };
        if descriptor.attributes & capability == 0 {
            return Err(ReadError::CacheType);
        }
        cursor = last.min(end);
        if cursor == end {
            return Ok(());
        }
    }
    Err(ReadError::MemoryMap)
}
