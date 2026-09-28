//! Raw page-walk evidence carried inside a checksummed batch response.
//! Entries are separately sampled observations, not an atomic mapping or access grant.

pub const BYTES: usize = 96;
pub const MAX_ENTRIES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticObservation {
    pub root: u64,
    pub address: u64,
    pub physical_bits: u8,
    pub nxe: bool,
    pub page_1g: bool,
    pub count: usize,
    pub entries: [DiagnosticEntry; MAX_ENTRIES],
}

impl DiagnosticObservation {
    pub const EMPTY: Self = Self {
        root: 0,
        address: 0,
        physical_bits: 32,
        nxe: false,
        page_1g: false,
        count: 0,
        entries: [DiagnosticEntry::EMPTY; MAX_ENTRIES],
    };

    pub fn decode(bytes: &[u8]) -> Result<Self, DiagnosticError> {
        let bytes: &[u8; BYTES] = bytes.try_into().map_err(|_| DiagnosticError::Length)?;
        let physical_bits = word(bytes, 16);
        let flags = word(bytes, 20);
        let count = word(bytes, 24) as usize;
        if !(32..=52).contains(&physical_bits)
            || flags & !3 != 0
            || count > MAX_ENTRIES
            || word(bytes, 28) != 0
        {
            return Err(DiagnosticError::Shape);
        }
        let mut observation = Self {
            root: wide(bytes, 0),
            address: wide(bytes, 8),
            physical_bits: physical_bits as u8,
            nxe: flags & 1 != 0,
            page_1g: flags & 2 != 0,
            count,
            entries: [DiagnosticEntry::EMPTY; MAX_ENTRIES],
        };
        for (index, entry) in observation.entries.iter_mut().enumerate() {
            *entry = DiagnosticEntry {
                address: wide(bytes, 32 + index * 16),
                value: wide(bytes, 40 + index * 16),
            };
        }
        observation.validate()?;
        Ok(observation)
    }

    pub fn encode(self) -> Result<[u8; BYTES], DiagnosticError> {
        self.validate()?;
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(&self.root.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.address.to_le_bytes());
        bytes[16..20].copy_from_slice(&u32::from(self.physical_bits).to_le_bytes());
        let flags = u32::from(self.nxe) | (u32::from(self.page_1g) << 1);
        bytes[20..24].copy_from_slice(&flags.to_le_bytes());
        bytes[24..28].copy_from_slice(&(self.count as u32).to_le_bytes());
        for (index, entry) in self.entries.iter().take(self.count).enumerate() {
            bytes[32 + index * 16..40 + index * 16].copy_from_slice(&entry.address.to_le_bytes());
            bytes[40 + index * 16..48 + index * 16].copy_from_slice(&entry.value.to_le_bytes());
        }
        Ok(bytes)
    }

    fn validate(self) -> Result<(), DiagnosticError> {
        if !(32..=52).contains(&self.physical_bits)
            || self.count > MAX_ENTRIES
            || self.entries[self.count..].iter().any(|entry| *entry != DiagnosticEntry::EMPTY)
        {
            return Err(DiagnosticError::Shape);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticEntry {
    pub address: u64,
    pub value: u64,
}

impl DiagnosticEntry {
    pub const EMPTY: Self = Self { address: 0, value: 0 };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticError {
    Length,
    Shape,
}

fn word(bytes: &[u8; BYTES], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn wide(bytes: &[u8; BYTES], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(count: usize) -> DiagnosticObservation {
        let mut observation = DiagnosticObservation {
            root: 0x1234_5000,
            address: 0xffff_f800_1234_5678,
            physical_bits: 48,
            nxe: true,
            page_1g: true,
            count,
            entries: [DiagnosticEntry::EMPTY; MAX_ENTRIES],
        };
        for (index, entry) in observation.entries.iter_mut().take(count).enumerate() {
            *entry = DiagnosticEntry { address: 0x2000 + index as u64 * 8, value: index as u64 };
        }
        observation
    }

    #[test]
    fn roundtrip_preserves_raw_entries_including_nonpresent_values() {
        for count in 0..=MAX_ENTRIES {
            let observation = observation(count);
            let bytes = observation.encode().unwrap();
            assert_eq!(DiagnosticObservation::decode(&bytes), Ok(observation));
            assert_eq!(&bytes[..8], &observation.root.to_le_bytes());
            assert_eq!(&bytes[8..16], &observation.address.to_le_bytes());
            assert_eq!(
                &bytes[16..32],
                &[48, 0, 0, 0, 3, 0, 0, 0, count as u8, 0, 0, 0, 0, 0, 0, 0]
            );
            assert!(bytes[32 + count * 16..].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn codec_rejects_bad_lengths_bounds_flags_reserved_and_unused_entries() {
        let bytes = observation(1).encode().unwrap();
        assert_eq!(DiagnosticObservation::decode(&bytes[..95]), Err(DiagnosticError::Length));
        assert_eq!(DiagnosticObservation::decode(&[0; 97]), Err(DiagnosticError::Length));
        for (offset, value) in
            [(16, 31), (16, 53), (17, 1), (20, 4), (24, 5), (28, 1), (48, 1), (88, 1)]
        {
            let mut changed = bytes;
            changed[offset] = value;
            assert_eq!(DiagnosticObservation::decode(&changed), Err(DiagnosticError::Shape));
        }
        for changed in [
            DiagnosticObservation { count: usize::MAX, ..observation(0) },
            DiagnosticObservation { physical_bits: 31, ..observation(0) },
            DiagnosticObservation { physical_bits: 53, ..observation(0) },
            DiagnosticObservation { count: 0, ..observation(1) },
        ] {
            assert_eq!(changed.encode(), Err(DiagnosticError::Shape));
        }
        for physical_bits in [32, 52] {
            let observation = DiagnosticObservation { physical_bits, ..observation(0) };
            assert_eq!(
                DiagnosticObservation::decode(&observation.encode().unwrap()),
                Ok(observation)
            );
        }
    }
}
