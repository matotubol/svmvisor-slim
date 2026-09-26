use super::{Limit, ParseError, ParseErrorKind, error};

pub const SDT_HEADER_LEN: usize = 36;
/// A local resource limit, not an architectural maximum.
pub const MAX_TABLE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcpiHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: [u8; 4],
    pub creator_revision: u32,
}

impl AcpiHeader {
    pub const EMPTY: Self = Self {
        signature: [0; 4],
        length: 0,
        revision: 0,
        oem_id: [0; 6],
        oem_table_id: [0; 8],
        oem_revision: 0,
        creator_id: [0; 4],
        creator_revision: 0,
    };
}

/// ACPI_Spec_6.6 p176, Table 5.4. No packed casts or unaligned dereferences.
/// Reject trailing bytes as well as truncation: callers must pass one table.
pub fn validate_sdt(bytes: &[u8], signature: [u8; 4]) -> Result<AcpiHeader, ParseError> {
    let reader = Bytes::new(bytes, signature, 0);
    reader.part(0, SDT_HEADER_LEN)?;
    if reader.array::<4>(0)? != signature {
        return Err(error(signature, 0, ParseErrorKind::BadSignature));
    }
    let length = reader.u32(4)?;
    if length as usize > MAX_TABLE_BYTES || bytes.len() > MAX_TABLE_BYTES {
        return Err(error(signature, 4, ParseErrorKind::LimitExceeded(Limit::TableBytes)));
    }
    if (length as usize) < SDT_HEADER_LEN {
        return Err(error(signature, 4, ParseErrorKind::InvalidLength));
    }
    if length as usize > bytes.len() {
        return Err(error(signature, 4, ParseErrorKind::Truncated));
    }
    if (length as usize) < bytes.len() {
        return Err(error(signature, length as usize, ParseErrorKind::TrailingBytes));
    }
    if bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0 {
        return Err(error(signature, 9, ParseErrorKind::BadChecksum));
    }
    Ok(AcpiHeader {
        signature,
        length,
        revision: bytes[8],
        oem_id: reader.array(10)?,
        oem_table_id: reader.array(16)?,
        oem_revision: reader.u32(24)?,
        creator_id: reader.array(28)?,
        creator_revision: reader.u32(32)?,
    })
}

pub(super) struct Bytes<'a> {
    pub data: &'a [u8],
    signature: [u8; 4],
    base: usize,
}

impl<'a> Bytes<'a> {
    pub fn new(data: &'a [u8], signature: [u8; 4], base: usize) -> Self {
        Self { data, signature, base }
    }

    pub fn fail(&self, offset: usize, kind: ParseErrorKind) -> ParseError {
        error(self.signature, self.base + offset, kind)
    }

    pub fn part(&self, offset: usize, length: usize) -> Result<&'a [u8], ParseError> {
        let end = offset
            .checked_add(length)
            .ok_or_else(|| self.fail(offset, ParseErrorKind::InvalidLength))?;
        self.data.get(offset..end).ok_or_else(|| self.fail(offset, ParseErrorKind::Truncated))
    }

    pub fn array<const N: usize>(&self, offset: usize) -> Result<[u8; N], ParseError> {
        let mut out = [0; N];
        out.copy_from_slice(self.part(offset, N)?);
        Ok(out)
    }

    pub fn u8(&self, offset: usize) -> Result<u8, ParseError> {
        Ok(self.part(offset, 1)?[0])
    }
    pub fn u16(&self, offset: usize) -> Result<u16, ParseError> {
        Ok(u16::from_le_bytes(self.array(offset)?))
    }
    pub fn u32(&self, offset: usize) -> Result<u32, ParseError> {
        Ok(u32::from_le_bytes(self.array(offset)?))
    }
    pub fn u64(&self, offset: usize) -> Result<u64, ParseError> {
        Ok(u64::from_le_bytes(self.array(offset)?))
    }

    pub fn zero(&self, offset: usize, length: usize) -> Result<(), ParseError> {
        if self.part(offset, length)?.iter().any(|byte| *byte != 0) {
            return Err(self.fail(offset, ParseErrorKind::ReservedField));
        }
        Ok(())
    }
}
