//! Fresh current-caller paging observations. These identify neither a kernel nor a System root.

use crate::batch::crc32;

pub const RESPONSE_BYTES: usize = 80;
pub const VERSION: u16 = 1;
const MAGIC: u32 = 0x5854_4353;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextObservation {
    pub session: u64,
    pub boot: u64,
    pub exit_sequence: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub lstar: u64,
    pub physical_bits: u8,
    pub cpu_slot: u32,
    pub page1gb: bool,
}

impl ContextObservation {
    pub fn decode(bytes: &[u8]) -> Result<Self, ContextError> {
        let bytes: &[u8; RESPONSE_BYTES] = bytes.try_into().map_err(|_| ContextError::Length)?;
        if word(bytes, 0) != MAGIC || word(bytes, 4) as u16 != VERSION {
            return Err(ContextError::Header);
        }
        if crc32(&bytes[..76]) != word(bytes, 76) {
            return Err(ContextError::Checksum);
        }
        let flags = word(bytes, 4) >> 16;
        let physical_bits = word(bytes, 64);
        if flags & !1 != 0 || word(bytes, 72) != 0 || !(32..=52).contains(&physical_bits) {
            return Err(ContextError::Shape);
        }
        let result = Self {
            session: wide(bytes, 8),
            boot: wide(bytes, 16),
            exit_sequence: wide(bytes, 24),
            cr3: wide(bytes, 32),
            cr4: wide(bytes, 40),
            efer: wide(bytes, 48),
            lstar: wide(bytes, 56),
            physical_bits: physical_bits as u8,
            cpu_slot: word(bytes, 68),
            page1gb: flags & 1 != 0,
        };
        if result.session == 0 || result.boot == 0 || result.exit_sequence == 0 {
            return Err(ContextError::Shape);
        }
        Ok(result)
    }

    pub fn encode(self) -> [u8; RESPONSE_BYTES] {
        let mut bytes = [0; RESPONSE_BYTES];
        bytes[..4].copy_from_slice(&MAGIC.to_le_bytes());
        let header = u32::from(VERSION) | (u32::from(self.page1gb) << 16);
        bytes[4..8].copy_from_slice(&header.to_le_bytes());
        for (index, value) in
            [self.session, self.boot, self.exit_sequence, self.cr3, self.cr4, self.efer, self.lstar]
                .into_iter()
                .enumerate()
        {
            bytes[8 + index * 8..16 + index * 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[64..68].copy_from_slice(&u32::from(self.physical_bits).to_le_bytes());
        bytes[68..72].copy_from_slice(&self.cpu_slot.to_le_bytes());
        let checksum = crc32(&bytes[..76]);
        bytes[76..80].copy_from_slice(&checksum.to_le_bytes());
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextError {
    Length,
    Header,
    Checksum,
    Shape,
}

fn word(bytes: &[u8; RESPONSE_BYTES], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn wide(bytes: &[u8; RESPONSE_BYTES], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation() -> ContextObservation {
        ContextObservation {
            session: 7,
            boot: 11,
            exit_sequence: 19,
            cr3: 0x1234_5007,
            cr4: 0x20,
            efer: 0xd01,
            lstar: 0xffff_f800_1234_5678,
            physical_bits: 48,
            cpu_slot: 3,
            page1gb: true,
        }
    }

    fn checksum(bytes: &mut [u8; RESPONSE_BYTES]) {
        let checksum = crc32(&bytes[..76]);
        bytes[76..80].copy_from_slice(&checksum.to_le_bytes());
    }

    #[test]
    fn roundtrip_preserves_raw_registers_and_current_call_correlation() {
        let observation = observation();
        let bytes = observation.encode();
        assert_eq!(ContextObservation::decode(&bytes), Ok(observation));
        assert_eq!(&bytes[32..40], &0x1234_5007u64.to_le_bytes());
        assert_eq!(&bytes[68..72], &3u32.to_le_bytes());
    }

    #[test]
    fn refuses_lengths_corruption_reserved_bits_and_missing_correlation() {
        let bytes = observation().encode();
        assert_eq!(ContextObservation::decode(&bytes[..79]), Err(ContextError::Length));
        let mut changed = bytes;
        changed[32] ^= 1;
        assert_eq!(ContextObservation::decode(&changed), Err(ContextError::Checksum));
        for offset in [6, 72] {
            changed = bytes;
            changed[offset] |= 2;
            checksum(&mut changed);
            assert_eq!(ContextObservation::decode(&changed), Err(ContextError::Shape));
        }
        for offset in [8, 16, 24] {
            changed = bytes;
            changed[offset..offset + 8].fill(0);
            checksum(&mut changed);
            assert_eq!(ContextObservation::decode(&changed), Err(ContextError::Shape));
        }
        changed = bytes;
        changed[65] = 1;
        checksum(&mut changed);
        assert_eq!(ContextObservation::decode(&changed), Err(ContextError::Shape));
    }
}
