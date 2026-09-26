//! ACPI 6.6 pp175-176/181: prefer the ACPI 2 GUID, validate both RSDP
//! checksums, and use XSDT. Legacy-only roots are explicitly unsupported.
use super::{ObservationState, ReadError, ReadOnlyAccess};
use crate::memory::{
    address::AddressPolicy,
    iommu::{self, Discovery, MAX_TABLE_BYTES, ParseError, SDT_HEADER_LEN},
};

const MAX_CONFIGURATION_ENTRIES: usize = 1024;
const MAX_XSDT_ENTRIES: usize = 512;
const MAX_RSDP_BYTES: usize = 256;
const MAX_SYSTEM_HEADER: usize = 4096;
// EFI GUID wire order, as stored in x64 EFI_CONFIGURATION_TABLE.
const ACPI2: [u8; 16] = [
    0x71, 0xe8, 0x68, 0x88, 0xf1, 0xe4, 0xd3, 0x11, 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81,
];
const ACPI1: [u8; 16] = [
    0x30, 0x2d, 0x9d, 0xeb, 0x88, 0x2d, 0xd3, 0x11, 0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d,
];

/// Fixed backing belongs in preallocated firmware storage, not a small UEFI
/// stack. Temporary bytes never become borrowed fields of the resulting report.
pub struct Scratch {
    root: [u8; SDT_HEADER_LEN + MAX_XSDT_ENTRIES * 8],
    ivrs: [u8; MAX_TABLE_BYTES],
    mcfg: [u8; MAX_TABLE_BYTES],
}

impl Scratch {
    pub const EMPTY: Self = Self {
        root: [0; SDT_HEADER_LEN + MAX_XSDT_ENTRIES * 8],
        ivrs: [0; MAX_TABLE_BYTES],
        mcfg: [0; MAX_TABLE_BYTES],
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcquisitionError {
    Read(ReadError),
    Bounds,
    MissingAcpi,
    LegacyAcpiOnly,
    DuplicateRoot,
    InvalidSystemTable,
    InvalidRsdp,
    InvalidXsdt,
    DuplicateTable,
    MissingIvrs,
    MissingMcfg,
    ChangedTable,
    Table(ParseError),
}

impl AcquisitionError {
    pub fn state(self) -> ObservationState {
        use iommu::ParseErrorKind as P;
        match self {
            Self::MissingAcpi
            | Self::MissingIvrs
            | Self::MissingMcfg
            | Self::Read(
                ReadError::Unavailable
                | ReadError::Mapping
                | ReadError::MemoryMap
                | ReadError::MemoryType
                | ReadError::ReadProtected
                | ReadError::CacheType,
            ) => ObservationState::Unavailable,
            Self::LegacyAcpiOnly | Self::Bounds | Self::Read(ReadError::Unsupported) => {
                ObservationState::Unsupported
            }
            Self::DuplicateRoot | Self::DuplicateTable | Self::ChangedTable => {
                ObservationState::Ambiguous
            }
            Self::Table(ParseError {
                kind:
                    P::UnsupportedRevision
                    | P::UnsupportedBlock(_)
                    | P::UnsupportedDeviceEntry(_)
                    | P::UnsupportedUidFormat(_)
                    | P::LimitExceeded(_),
                ..
            }) => ObservationState::Unsupported,
            Self::Table(ParseError {
                kind:
                    P::DuplicateForm
                    | P::ConflictingUnitIdentity
                    | P::ConflictingMmioAddress
                    | P::OverlappingEcam
                    | P::ConflictingEcamBuses,
                ..
            }) => ObservationState::Ambiguous,
            _ => ObservationState::Malformed,
        }
    }
}

pub(super) fn acquire_tables(
    access: &mut impl ReadOnlyAccess,
    policy: AddressPolicy,
    system_table: u64,
    scratch: &mut Scratch,
    out: &mut Discovery,
) -> Result<(), AcquisitionError> {
    let rsdp = configuration_root(access, policy, system_table, &mut scratch.root)?;
    let xsdt = xsdt_address(access, policy, rsdp)?;
    let root_len = copy_sdt(access, policy, xsdt, *b"XSDT", &mut scratch.root)?;
    let root = scratch.root.get(..root_len).ok_or(AcquisitionError::Bounds)?;
    if root.get(8) != Some(&1) || (root_len - SDT_HEADER_LEN) % 8 != 0 {
        return Err(AcquisitionError::InvalidXsdt);
    }
    let entries = root.get(SDT_HEADER_LEN..).ok_or(AcquisitionError::Bounds)?;
    let mut ivrs = None;
    let mut mcfg = None;
    for (index, entry) in entries.chunks_exact(8).enumerate() {
        let address = u64_at(entry, 0)?;
        if address == xsdt || address == rsdp || address == 0 {
            return Err(AcquisitionError::InvalidXsdt);
        }
        // Repeated pointers are not silently counted or selected twice.
        if entries.chunks_exact(8).take(index).any(|other| other == entry) {
            return Err(AcquisitionError::DuplicateTable);
        }
        let mut header = [0u8; SDT_HEADER_LEN];
        read_acpi(access, policy, address, &mut header)?;
        let destination = match header.get(..4) {
            Some(b"IVRS") => &mut ivrs,
            Some(b"MCFG") => &mut mcfg,
            _ => continue,
        };
        if destination.replace((address, header)).is_some() {
            return Err(AcquisitionError::DuplicateTable);
        }
    }
    let (ivrs_address, ivrs_header) = ivrs.ok_or(AcquisitionError::MissingIvrs)?;
    let (mcfg_address, mcfg_header) = mcfg.ok_or(AcquisitionError::MissingMcfg)?;
    let ivrs_len = copy_sdt(access, policy, ivrs_address, *b"IVRS", &mut scratch.ivrs)?;
    let mcfg_len = copy_sdt(access, policy, mcfg_address, *b"MCFG", &mut scratch.mcfg)?;
    if scratch.ivrs.get(..SDT_HEADER_LEN) != Some(ivrs_header.as_slice())
        || scratch.mcfg.get(..SDT_HEADER_LEN) != Some(mcfg_header.as_slice())
    {
        return Err(AcquisitionError::ChangedTable);
    }
    iommu::discover_into(
        scratch.ivrs.get(..ivrs_len).ok_or(AcquisitionError::Bounds)?,
        scratch.mcfg.get(..mcfg_len).ok_or(AcquisitionError::Bounds)?,
        out,
    )
    .map_err(AcquisitionError::Table)
}

fn configuration_root(
    access: &mut impl ReadOnlyAccess,
    policy: AddressPolicy,
    address: u64,
    scratch: &mut [u8],
) -> Result<u64, AcquisitionError> {
    use uefi_raw::table::system::SystemTable;
    let mut header = [0u8; 24];
    read_firmware(access, policy, address, &mut header)?;
    let size = u32_at(&header, 12)? as usize;
    if u64_at(&header, 0)? != SystemTable::SIGNATURE
        || size < core::mem::size_of::<SystemTable>()
        || size > MAX_SYSTEM_HEADER
        || u32_at(&header, 20)? != 0
    {
        return Err(AcquisitionError::InvalidSystemTable);
    }
    let bytes = scratch.get_mut(..size).ok_or(AcquisitionError::Bounds)?;
    read_firmware(access, policy, address, bytes)?;
    if bytes.get(..24) != Some(header.as_slice()) || crc32_header(bytes) != u32_at(bytes, 16)? {
        return Err(AcquisitionError::InvalidSystemTable);
    }
    let count =
        u64_at(bytes, core::mem::offset_of!(SystemTable, number_of_configuration_table_entries))?;
    let base = u64_at(bytes, core::mem::offset_of!(SystemTable, configuration_table))?;
    if count == 0 {
        return Err(AcquisitionError::MissingAcpi);
    }
    if count > MAX_CONFIGURATION_ENTRIES as u64 {
        return Err(AcquisitionError::Bounds);
    }
    let length = count.checked_mul(24).ok_or(AcquisitionError::Bounds)?;
    policy.validate(base, length, 8).map_err(|_| AcquisitionError::Read(ReadError::Address))?;
    let mut selected = None;
    let mut legacy = false;
    for index in 0..count {
        let mut entry = [0u8; 24];
        read_firmware(access, policy, base + index * 24, &mut entry)?;
        if entry.get(..16) == Some(ACPI2.as_slice()) {
            if selected.replace(u64_at(&entry, 16)?).is_some() {
                return Err(AcquisitionError::DuplicateRoot);
            }
        } else if entry.get(..16) == Some(ACPI1.as_slice()) {
            legacy = true;
        }
    }
    selected.ok_or(if legacy {
        AcquisitionError::LegacyAcpiOnly
    } else {
        AcquisitionError::MissingAcpi
    })
}

fn xsdt_address(
    access: &mut impl ReadOnlyAccess,
    policy: AddressPolicy,
    rsdp: u64,
) -> Result<u64, AcquisitionError> {
    let mut initial = [0u8; 20];
    read_acpi(access, policy, rsdp, &mut initial)?;
    if initial.get(..8) != Some(b"RSD PTR ") || checksum(&initial) != 0 {
        return Err(AcquisitionError::InvalidRsdp);
    }
    if initial[15] < 2 {
        return Err(AcquisitionError::LegacyAcpiOnly);
    }
    let mut header = [0u8; 36];
    read_acpi(access, policy, rsdp, &mut header)?;
    let length = u32_at(&header, 20)? as usize;
    if length < 36 {
        return Err(AcquisitionError::InvalidRsdp);
    }
    if length > MAX_RSDP_BYTES {
        return Err(AcquisitionError::Bounds);
    }
    let mut copy = [0u8; MAX_RSDP_BYTES];
    let bytes = copy.get_mut(..length).ok_or(AcquisitionError::Bounds)?;
    read_acpi(access, policy, rsdp, bytes)?;
    if bytes.get(..20) != Some(initial.as_slice())
        || bytes.get(..36) != Some(header.as_slice())
        || bytes.get(33..36) != Some(&[0, 0, 0])
        || checksum(bytes) != 0
    {
        return Err(AcquisitionError::InvalidRsdp);
    }
    let xsdt = u64_at(bytes, 24)?;
    if xsdt == 0 {
        return Err(AcquisitionError::InvalidXsdt);
    }
    Ok(xsdt)
}

fn copy_sdt(
    access: &mut impl ReadOnlyAccess,
    policy: AddressPolicy,
    address: u64,
    signature: [u8; 4],
    out: &mut [u8],
) -> Result<usize, AcquisitionError> {
    let mut header = [0u8; SDT_HEADER_LEN];
    read_acpi(access, policy, address, &mut header)?;
    let length = u32_at(&header, 4)? as usize;
    if length < SDT_HEADER_LEN {
        return Err(AcquisitionError::InvalidXsdt);
    }
    if length > MAX_TABLE_BYTES {
        return Err(AcquisitionError::Bounds);
    }
    let bytes = out.get_mut(..length).ok_or(AcquisitionError::Bounds)?;
    read_acpi(access, policy, address, bytes)?;
    if bytes.get(..SDT_HEADER_LEN) != Some(header.as_slice()) {
        return Err(AcquisitionError::ChangedTable);
    }
    iommu::validate_sdt(bytes, signature).map_err(AcquisitionError::Table)?;
    Ok(length)
}

fn read_firmware(
    access: &mut impl ReadOnlyAccess,
    policy: AddressPolicy,
    address: u64,
    out: &mut [u8],
) -> Result<(), AcquisitionError> {
    policy
        .validate(address, out.len() as u64, 1)
        .map_err(|_| AcquisitionError::Read(ReadError::Address))?;
    if address == 0 {
        return Err(AcquisitionError::Read(ReadError::Address));
    }
    access.read_firmware(address, out).map_err(AcquisitionError::Read)
}
fn read_acpi(
    access: &mut impl ReadOnlyAccess,
    policy: AddressPolicy,
    address: u64,
    out: &mut [u8],
) -> Result<(), AcquisitionError> {
    policy
        .validate(address, out.len() as u64, 1)
        .map_err(|_| AcquisitionError::Read(ReadError::Address))?;
    if address == 0 {
        return Err(AcquisitionError::Read(ReadError::Address));
    }
    access.read_acpi(address, out).map_err(AcquisitionError::Read)
}
fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, AcquisitionError> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(AcquisitionError::Bounds)?
        .try_into()
        .map_err(|_| AcquisitionError::Bounds)?;
    Ok(u32::from_le_bytes(raw))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, AcquisitionError> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or(AcquisitionError::Bounds)?
        .try_into()
        .map_err(|_| AcquisitionError::Bounds)?;
    Ok(u64::from_le_bytes(raw))
}
pub(super) fn crc32_header(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for (offset, byte) in bytes.iter().enumerate() {
        crc ^= if (16..20).contains(&offset) { 0 } else { u32::from(*byte) };
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
