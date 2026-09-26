use super::{
    ADDRESS_MASK, AddressPolicy, EncodingError, LEVEL_MASK, PERMISSIONS, Permissions, validate_page,
};

const PRESENT: u64 = 1;
const FORCE_COHERENT: u64 = 1 << 60;
const ALLOWED_DIRECTORY: u64 = ADDRESS_MASK | PERMISSIONS | LEVEL_MASK | PRESENT;
const ALLOWED_LEAF: u64 = ADDRESS_MASK | PERMISSIONS | PRESENT | FORCE_COHERENT;

/// The four supported host levels. Their indices consume DVA bits 47:39,
/// 38:30, 29:21 and 20:12 respectively (48882-3.11 p82).
/// The resulting DVA space is unsigned 48-bit, not x86 canonical addressing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PageLevel {
    One = 1,
    Two = 2,
    Three = 3,
    Four = 4,
}

impl PageLevel {
    pub fn from_number(number: u8) -> Result<Self, EncodingError> {
        match number {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            3 => Ok(Self::Three),
            4 => Ok(Self::Four),
            _ => Err(EncodingError::UnsupportedPageLevel(number)),
        }
    }

    pub const fn number(self) -> u8 {
        self as u8
    }

    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Four => Some(Self::Three),
            Self::Three => Some(Self::Two),
            Self::Two => Some(Self::One),
            Self::One => None,
        }
    }
}

/// PTE.FC behavior, not evidence of a cache-safe mapping (48882-3.11 p83).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageCoherency {
    /// Preserve the originating transaction's coherent attribute.
    Inherit,
    /// Set the coherent attribute in the upstream request.
    ForceCoherent,
}

/// Canonical absent entry, contiguous directory link, or 4 KiB host leaf.
/// Encoded values are inert; this type does not find or modify any table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPageEntry {
    word: u64,
}

impl HostPageEntry {
    /// The only accepted PR=0 encoding. Hardware ignores the remaining bits,
    /// but the offline profile rejects stale address/permission data (p82).
    pub const ABSENT: Self = Self { word: 0 };

    /// Link exactly one level down. Level skipping, self-links by level and
    /// directories at level one are outside the profile. This does not inspect
    /// the destination page or detect physical graph cycles/overlap.
    pub fn directory(
        policy: AddressPolicy,
        current_level: PageLevel,
        next_table_address: u64,
        permissions: Permissions,
    ) -> Result<Self, EncodingError> {
        let next = current_level.next().ok_or(EncodingError::DirectoryAtLeafLevel)?;
        validate_page(policy, next_table_address)?;
        Ok(Self {
            word: next_table_address
                | permissions.bits()
                | (u64::from(next.number()) << 9)
                | PRESENT,
        })
    }

    /// A NextLevel=0 leaf, usable only in a level-one table. Bits A/D, U and
    /// migration state are zero. FC is an explicit numeric format choice.
    pub fn leaf_4k(
        policy: AddressPolicy,
        page_address: u64,
        permissions: Permissions,
        coherency: PageCoherency,
    ) -> Result<Self, EncodingError> {
        validate_page(policy, page_address)?;
        let fc = match coherency {
            PageCoherency::Inherit => 0,
            PageCoherency::ForceCoherent => FORCE_COHERENT,
        };
        Ok(Self { word: page_address | permissions.bits() | fc | PRESENT })
    }

    /// Validate an entry at its actual containing-table level. No raw word
    /// with ignored/unsupported bits is silently normalized. Not suitable for
    /// decoding another software owner's arbitrary AMD-compatible page tables.
    pub fn decode(
        policy: AddressPolicy,
        current_level: PageLevel,
        word: u64,
    ) -> Result<Self, EncodingError> {
        if word == 0 {
            return Ok(Self::ABSENT);
        }
        if word & PRESENT == 0 {
            return Err(EncodingError::NonCanonicalAbsent);
        }
        let next = ((word & LEVEL_MASK) >> 9) as u8;
        let allowed = if next == 0 {
            if current_level != PageLevel::One {
                return Err(EncodingError::LeafAtWrongLevel(current_level));
            }
            ALLOWED_LEAF
        } else {
            if current_level.next().map(PageLevel::number) != Some(next) {
                return Err(EncodingError::UnsupportedNextLevel { current: current_level, next });
            }
            ALLOWED_DIRECTORY
        };
        let unsupported = word & !allowed;
        if unsupported != 0 {
            return Err(EncodingError::UnsupportedBits { word: 0, bits: unsupported });
        }
        validate_page(policy, word & ADDRESS_MASK)?;
        Ok(Self { word })
    }

    pub const fn word(self) -> u64 {
        self.word
    }

    pub const fn is_present(self) -> bool {
        self.word & PRESENT != 0
    }

    /// Numeric next-table or leaf-page address. An absent entry has no address.
    pub const fn address(self) -> Option<u64> {
        if self.is_present() { Some(self.word & ADDRESS_MASK) } else { None }
    }

    pub const fn permissions(self) -> Option<Permissions> {
        if self.is_present() { Some(Permissions::from_word(self.word)) } else { None }
    }

    pub const fn next_level(self) -> Option<PageLevel> {
        match (self.word & LEVEL_MASK) >> 9 {
            1 => Some(PageLevel::One),
            2 => Some(PageLevel::Two),
            3 => Some(PageLevel::Three),
            _ => None,
        }
    }

    /// Only leaf entries have the FC field. Directory bit 60 is reserved.
    pub const fn coherency(self) -> Option<PageCoherency> {
        if !self.is_present() || self.word & LEVEL_MASK != 0 {
            None
        } else if self.word & FORCE_COHERENT == 0 {
            Some(PageCoherency::Inherit)
        } else {
            Some(PageCoherency::ForceCoherent)
        }
    }
}
