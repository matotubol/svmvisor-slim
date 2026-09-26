//! Build an actual RSDP/XSDT/RSDT replacement from immutable acquired bytes.
//! This does not mutate firmware. The publisher owns guest-readable reserved
//! backing, configuration-table replacement, lifetime and readback verification.
//! ACPI_Spec_6.6 physical pp175-176,180-181, text and PNG checked.

use crate::{
    memory::iommu::{SDT_HEADER_LEN, validate_sdt},
    svm::pci::Region,
};

const MAX_ENTRIES: usize = 512;
const ROOT_BYTES: usize = SDT_HEADER_LEN + MAX_ENTRIES * 8;

pub struct Source<'a> {
    pub rsdp_address: u64,
    pub rsdp: &'a [u8],
    pub xsdt: &'a [u8],
    pub rsdt: Option<&'a [u8]>,
    pub ivrs_address: u64,
    pub ivrs: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub rsdp: u64,
    pub xsdt: u64,
    pub rsdt: u64,
    pub ivrs: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Source,
    Bounds,
    Address,
    Overlap,
    MissingIvrs,
    DuplicateTable,
    ChangedIvrs,
    HeaderUnavailable,
}

/// This output is copied to the separately reserved guest-visible assignments,
/// never exposed from the monitor's protected private pool. The IVRS bytes are
/// the exact Storage::view().ivrs supplied to prepare, not a second renderer.
pub struct Image {
    rsdp: [u8; 36],
    xsdt: [u8; ROOT_BYTES],
    rsdt: [u8; ROOT_BYTES],
    xsdt_len: usize,
    rsdt_len: usize,
    ready: bool,
}
impl Image {
    pub const EMPTY: Self = Self {
        rsdp: [0; 36],
        xsdt: [0; ROOT_BYTES],
        rsdt: [0; ROOT_BYTES],
        xsdt_len: 0,
        rsdt_len: 0,
        ready: false,
    };
    pub fn rsdp(&self) -> Option<&[u8]> {
        self.ready.then_some(&self.rsdp)
    }
    pub fn xsdt(&self) -> Option<&[u8]> {
        self.ready.then_some(&self.xsdt[..self.xsdt_len])
    }
    pub fn rsdt(&self) -> Option<&[u8]> {
        (self.ready && self.rsdt_len != 0).then_some(&self.rsdt[..self.rsdt_len])
    }

    /// `header` must read every referenced table header from the same immutable
    /// acquisition as the supplied roots. All entries are examined: an extra
    /// IVRS at another address is rejected, rather than selecting one winner.
    pub fn prepare(
        &mut self,
        source: Source<'_>,
        assigned: Assignment,
        replacement_ivrs: &[u8],
        mut header: impl FnMut(u64) -> Result<[u8; SDT_HEADER_LEN], Error>,
    ) -> Result<(), Error> {
        self.ready = false;
        self.xsdt_len = 0;
        self.rsdt_len = 0;
        self.rsdp.fill(0);
        self.xsdt.fill(0);
        self.rsdt.fill(0);
        let result = self.prepare_inner(source, assigned, replacement_ivrs, &mut header);
        if result.is_err() {
            self.rsdp.fill(0);
            self.xsdt.fill(0);
            self.rsdt.fill(0);
        }
        result
    }

    fn prepare_inner(
        &mut self,
        source: Source<'_>,
        assigned: Assignment,
        replacement: &[u8],
        header: &mut impl FnMut(u64) -> Result<[u8; SDT_HEADER_LEN], Error>,
    ) -> Result<(), Error> {
        validate_sdt(source.ivrs, *b"IVRS").map_err(|_| Error::Source)?;
        validate_sdt(replacement, *b"IVRS").map_err(|_| Error::Source)?;
        if source.rsdp.len() != 36
            || &source.rsdp[..8] != b"RSD PTR "
            || source.rsdp[15] != 2
            || u32_at(source.rsdp, 20) != 36
            || sum(&source.rsdp[..20]) != 0
            || sum(source.rsdp) != 0
            || source.rsdp[33..36] != [0, 0, 0]
            || source.rsdt.is_some() != (u32_at(source.rsdp, 16) != 0)
            || source.rsdt.is_some() != (assigned.rsdt != 0)
        {
            return Err(Error::Source);
        }
        let xsdt = u64_at(source.rsdp, 24);
        let rsdt = u64::from(u32_at(source.rsdp, 16));
        let old = [
            Region { base: source.rsdp_address, bytes: 36 },
            Region { base: xsdt, bytes: source.xsdt.len() as u64 },
            Region { base: source.ivrs_address, bytes: source.ivrs.len() as u64 },
            Region { base: rsdt, bytes: source.rsdt.map_or(0, |b| b.len()) as u64 },
        ];
        let new = [
            Region { base: assigned.rsdp, bytes: 36 },
            Region { base: assigned.xsdt, bytes: source.xsdt.len() as u64 },
            Region { base: assigned.ivrs, bytes: replacement.len() as u64 },
            Region { base: assigned.rsdt, bytes: source.rsdt.map_or(0, |b| b.len()) as u64 },
        ];
        let count = if source.rsdt.is_some() { 4 } else { 3 };
        if source.rsdt.is_some()
            && (assigned.rsdt > u64::from(u32::MAX) || assigned.ivrs > u64::from(u32::MAX))
        {
            return Err(Error::Address);
        }
        validate_ranges(&old[..count])?;
        validate_ranges(&new[..count])?;
        if old[..count].iter().any(|a| new[..count].iter().any(|b| a.overlaps(*b))) {
            return Err(Error::Overlap);
        }
        self.xsdt_len = replace_root(
            source.xsdt,
            *b"XSDT",
            8,
            xsdt,
            source.ivrs_address,
            source.ivrs,
            assigned.ivrs,
            &new[..count],
            header,
            &mut self.xsdt,
        )?;
        if let Some(bytes) = source.rsdt {
            self.rsdt_len = replace_root(
                bytes,
                *b"RSDT",
                4,
                rsdt,
                source.ivrs_address,
                source.ivrs,
                assigned.ivrs,
                &new[..count],
                header,
                &mut self.rsdt,
            )?;
        }
        // Source pointers other than the IVRS remain byte-for-byte unchanged.
        // Both RSDP checksums are recomputed after updating their root pointers.
        self.rsdp.copy_from_slice(source.rsdp);
        self.rsdp[16..20].copy_from_slice(&(assigned.rsdt as u32).to_le_bytes());
        self.rsdp[24..32].copy_from_slice(&assigned.xsdt.to_le_bytes());
        self.rsdp[8] = 0;
        self.rsdp[32] = 0;
        self.rsdp[8] = 0u8.wrapping_sub(sum(&self.rsdp[..20]));
        self.rsdp[32] = 0u8.wrapping_sub(sum(&self.rsdp));
        self.ready = true;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn replace_root(
    source: &[u8],
    signature: [u8; 4],
    width: usize,
    source_address: u64,
    old_ivrs: u64,
    old_bytes: &[u8],
    new_ivrs: u64,
    destinations: &[Region],
    header: &mut impl FnMut(u64) -> Result<[u8; SDT_HEADER_LEN], Error>,
    out: &mut [u8],
) -> Result<usize, Error> {
    let identity = validate_sdt(source, signature).map_err(|_| Error::Source)?;
    if identity.revision != 1
        || source.len() > ROOT_BYTES
        || (source.len() - SDT_HEADER_LEN) % width != 0
    {
        return Err(Error::Bounds);
    }
    let entries = &source[SDT_HEADER_LEN..];
    if entries.len() / width > MAX_ENTRIES {
        return Err(Error::Bounds);
    }
    let mut found = None;
    for (index, entry) in entries.chunks_exact(width).enumerate() {
        let address = if width == 8 { u64_at(entry, 0) } else { u64::from(u32_at(entry, 0)) };
        if address == 0
            || address == source_address
            || entries.chunks_exact(width).take(index).any(|other| other == entry)
        {
            return Err(Error::DuplicateTable);
        }
        let bytes = header(address)?;
        let length = u64::from(u32_at(&bytes, 4));
        let region = Region { base: address, bytes: length };
        if length < SDT_HEADER_LEN as u64 || !region.valid() || address + length > 1 << 48 {
            return Err(Error::Bounds);
        }
        if destinations.iter().any(|destination| destination.overlaps(region)) {
            return Err(Error::Overlap);
        }
        if &bytes[..4] == b"IVRS" {
            if found.replace(index).is_some() {
                return Err(Error::DuplicateTable);
            }
            if address != old_ivrs || bytes.as_slice() != &old_bytes[..SDT_HEADER_LEN] {
                return Err(Error::ChangedIvrs);
            }
        } else if address == old_ivrs {
            return Err(Error::ChangedIvrs);
        }
    }
    let index = found.ok_or(Error::MissingIvrs)?;
    out[..source.len()].copy_from_slice(source);
    let offset = SDT_HEADER_LEN + index * width;
    out[offset..offset + width].copy_from_slice(&new_ivrs.to_le_bytes()[..width]);
    out[9] = 0;
    out[9] = 0u8.wrapping_sub(sum(&out[..source.len()]));
    Ok(source.len())
}

fn validate_ranges(ranges: &[Region]) -> Result<(), Error> {
    for (index, range) in ranges.iter().enumerate() {
        if !range.valid()
            || range.base == 0
            || range.base & 3 != 0
            || range.base + range.bytes > 1 << 48
        {
            return Err(Error::Address);
        }
        if ranges[..index].iter().any(|other| other.overlaps(*range)) {
            return Err(Error::Overlap);
        }
    }
    Ok(())
}
fn sum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
