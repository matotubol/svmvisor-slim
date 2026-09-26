use super::{
    ADDRESS_MASK, AddressPolicy, EncodingError, LEVEL_MASK, PERMISSIONS, Permissions, validate_page,
};

const VALID: u64 = 1;
const TRANSLATION_VALID: u64 = 1 << 1;
const FOUR_LEVEL_MODE: u64 = 4 << 9;
const ALLOWED_LOW: u64 = ADDRESS_MASK | PERMISSIONS | LEVEL_MASK | VALID | TRANSLATION_VALID;

/// Only bits 127:0 of a DTE, in least-significant-word-first order. This is
/// deliberately not a complete device-table entry or hardware-ready image.
///
/// V=TV=1 and Mode=4 are mandatory. The caller supplies DomainID and IR/IW;
/// all other lower-half fields are zero. This chooses no interrupt behavior:
/// IV and the independent interrupt controls reside in the missing upper half.
///
/// No `Default` exists: a zero DTE has V=0 and forwards addresses untranslated
/// (48882-3.11 p74). DomainID zero is a legal numeric identifier, but assigning
/// IDs consistently across all devices/tables is an external obligation (p70).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostDeviceEntry {
    words: [u64; 2],
}

impl HostDeviceEntry {
    /// Build an inert lower-half encoding. Root zero is a valid numeric page;
    /// this function does not establish that any page is allocated or usable.
    pub fn new(
        policy: AddressPolicy,
        root_address: u64,
        domain_id: u16,
        permissions: Permissions,
    ) -> Result<Self, EncodingError> {
        validate_page(policy, root_address)?;
        Ok(Self {
            words: [
                root_address | permissions.bits() | FOUR_LEVEL_MODE | TRANSLATION_VALID | VALID,
                u64::from(domain_id),
            ],
        })
    }

    /// Decode only the restricted lower-half profile. No upper-half bytes are
    /// accepted or inferred, and no statement about a complete DTE follows.
    pub fn decode(policy: AddressPolicy, words: [u64; 2]) -> Result<Self, EncodingError> {
        let unsupported = words[0] & !ALLOWED_LOW;
        if unsupported != 0 {
            return Err(EncodingError::UnsupportedBits { word: 0, bits: unsupported });
        }
        let unsupported = words[1] & !0xffff;
        if unsupported != 0 {
            return Err(EncodingError::UnsupportedBits { word: 1, bits: unsupported });
        }
        if words[0] & (VALID | TRANSLATION_VALID) != (VALID | TRANSLATION_VALID) {
            return Err(EncodingError::DeviceTranslationDisabled);
        }
        let mode = ((words[0] & LEVEL_MASK) >> 9) as u8;
        if mode != 4 {
            return Err(EncodingError::UnsupportedHostMode(mode));
        }
        validate_page(policy, words[0] & ADDRESS_MASK)?;
        Ok(Self { words })
    }

    /// DTE bits 63:0 followed by bits 127:64; no interrupt half is emitted.
    pub const fn words(self) -> [u64; 2] {
        self.words
    }

    pub const fn root_address(self) -> u64 {
        self.words[0] & ADDRESS_MASK
    }

    pub const fn domain_id(self) -> u16 {
        self.words[1] as u16
    }

    pub const fn permissions(self) -> Permissions {
        Permissions::from_word(self.words[0])
    }
}
