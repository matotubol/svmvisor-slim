use super::{AddressPolicy, EncodingError};

// DTE bits 179:134 carry SPA[51:6], but the specified alignment is 128 bytes:
// bit 134 must also be zero. Keep it in the field mask so validation catches it.
// Layout: 48882-3.11 p63, field definitions pp65-67, controls pp74-75.
const TABLE_ADDRESS: u64 = 0x000f_ffff_ffff_ffc0;
const TABLE_LENGTH: u64 = 0xf << 1;
const INTERRUPT_VALID: u64 = 1;
const INTERRUPT_CONTROL: u64 = 3 << 60;
const REMAP_BASIC: u64 = 2 << 60;
const ALLOWED_DTE: u64 = TABLE_ADDRESS | TABLE_LENGTH | INTERRUPT_VALID | INTERRUPT_CONTROL;

/// Explicit policy for the interrupt controls available in a DTE.
///
/// Both variants set IV=1 and clear Lint0Pass, Lint1Pass, NMIPass, InitPass and
/// EIntPass, so those classes are target aborted. IG=0 does not suppress faults.
/// SMI remains controlled by the separate optional SMI filter, not these bits:
/// neither variant means all interrupts are blocked (48882-3.11 pp55,74-75).
/// SysMgt=0 in the translation half is not a substitute for that SMI filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DteInterruptPolicy {
    /// Target abort fixed/arbitrated interrupts as well as the five pass-bit
    /// classes. Ignored interrupt-table fields are canonically zero.
    AbortControlled,
    /// Remap fixed/arbitrated messages through 32-bit basic IRTEs. GAEn must be
    /// zero; the separate hardware control selects the entry format (p93).
    /// This is a numeric table reference, not proof of its contents or ownership.
    RemapBasic(BasicInterruptTable),
}

impl DteInterruptPolicy {
    pub(super) fn validate(self, policy: AddressPolicy) -> Result<(), EncodingError> {
        if let Self::RemapBasic(table) = self {
            BasicInterruptTable::new(policy, table.root_address, table.entry_count)?;
        }
        Ok(())
    }

    pub(super) const fn word(self) -> u64 {
        match self {
            Self::AbortControlled => INTERRUPT_VALID,
            Self::RemapBasic(table) => {
                table.root_address
                    | ((table.entry_count.trailing_zeros() as u64) << 1)
                    | REMAP_BASIC
                    | INTERRUPT_VALID
            }
        }
    }

    pub(super) fn decode(policy: AddressPolicy, words: [u64; 2]) -> Result<Self, EncodingError> {
        let unsupported = words[0] & !ALLOWED_DTE;
        if unsupported != 0 {
            return Err(EncodingError::UnsupportedBits { word: 2, bits: unsupported });
        }
        if words[1] != 0 {
            return Err(EncodingError::UnsupportedBits { word: 3, bits: words[1] });
        }
        if words[0] & INTERRUPT_VALID == 0 {
            return Err(EncodingError::DeviceInterruptMappingDisabled);
        }
        let control = ((words[0] & INTERRUPT_CONTROL) >> 60) as u8;
        match control {
            0 => {
                if words[0] & (TABLE_ADDRESS | TABLE_LENGTH) != 0 {
                    return Err(EncodingError::NonCanonicalInterruptTable);
                }
                Ok(Self::AbortControlled)
            }
            2 => {
                let length = ((words[0] & TABLE_LENGTH) >> 1) as u8;
                // 1024/2048-entry tables are outside this basic 512-entry
                // routing profile; 12..15 are hardware-reserved (pp67,90).
                if length > 9 {
                    return Err(EncodingError::UnsupportedInterruptTableLength(length));
                }
                BasicInterruptTable::new(policy, words[0] & TABLE_ADDRESS, 1u16 << length)
                    .map(Self::RemapBasic)
            }
            _ => Err(EncodingError::UnsupportedInterruptControl(control)),
        }
    }
}

/// Numeric backing extent for a basic (32-bit) interrupt remapping table.
///
/// The root is 128-byte aligned and the count is a power of two in 1..=512.
/// Every byte of the encoded `4 * entry_count` extent is checked. Additional
/// allocator padding is not described here and needs separate validation and
/// protection. Zero is a legal numeric root, not a claim of allocated memory.
///
/// GAEn=0 and ordinary interrupt routing are external prerequisites. The 512
/// bound avoids relying on optional 2K routing (48882-3.11 pp66-67,90-93).
/// This value does not inspect entries, acquire backing or verify those controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BasicInterruptTable {
    root_address: u64,
    entry_count: u16,
}

impl BasicInterruptTable {
    pub fn new(
        policy: AddressPolicy,
        root_address: u64,
        entry_count: u16,
    ) -> Result<Self, EncodingError> {
        if !entry_count.is_power_of_two() || entry_count > 512 {
            return Err(EncodingError::UnsupportedInterruptEntryCount(entry_count));
        }
        policy
            .validate(root_address, u64::from(entry_count) * 4, 128)
            .map_err(EncodingError::Address)?;
        Ok(Self { root_address, entry_count })
    }

    pub const fn root_address(self) -> u64 {
        self.root_address
    }

    pub const fn entry_count(self) -> u16 {
        self.entry_count
    }

    /// Entire encoded table extent; this is not rounded to a page.
    pub const fn byte_len(self) -> u64 {
        self.entry_count as u64 * 4
    }
}

const REMAP_ENABLE: u32 = 1;
const ALLOWED_IRTE: u32 = 0x00ff_ff01;

/// Strict 32-bit basic IRTE: canonical target abort, or fixed delivery to one
/// physical APIC destination with no requested EOI and no fault suppression.
/// GAEn=0 is required externally (48882-3.11 pp91-93).
///
/// Logical/arbitrated delivery, broadcast destination FFh, GuestMode, RqEoi and
/// SupIOPF are outside this profile. Vectors 00h..0Fh are not accepted by the
/// local APIC's ordinary vector registers (24593_3.44_APM_Vol2 pp707,709).
/// Destination/vector allocation, device MSI programming, IRTE indexing and
/// interrupt ownership remain external; numeric encoding establishes none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BasicInterruptEntry {
    word: u32,
}

impl BasicInterruptEntry {
    /// RemapEn=0 target aborts; unlike DTE IV=0, this does not mean passthrough.
    /// SupIOPF=0 retains event logging subject to global controls (p92).
    pub const ABORT: Self = Self { word: 0 };

    /// Fixed physical delivery to a non-broadcast 8-bit destination.
    pub fn fixed(destination: u8, vector: u8) -> Result<Self, EncodingError> {
        if destination == u8::MAX {
            return Err(EncodingError::UnsupportedInterruptDestination(destination));
        }
        if vector < 0x10 {
            return Err(EncodingError::UnsupportedInterruptVector(vector));
        }
        Ok(Self { word: (u32::from(vector) << 16) | (u32::from(destination) << 8) | REMAP_ENABLE })
    }

    pub fn decode(word: u32) -> Result<Self, EncodingError> {
        if word == 0 {
            return Ok(Self::ABORT);
        }
        if word & REMAP_ENABLE == 0 {
            return Err(EncodingError::NonCanonicalAbortedInterrupt);
        }
        let unsupported = word & !ALLOWED_IRTE;
        if unsupported != 0 {
            return Err(EncodingError::UnsupportedBits { word: 0, bits: u64::from(unsupported) });
        }
        Self::fixed((word >> 8) as u8, (word >> 16) as u8)
    }

    pub const fn word(self) -> u32 {
        self.word
    }

    pub const fn is_remapped(self) -> bool {
        self.word & REMAP_ENABLE != 0
    }

    pub const fn destination(self) -> Option<u8> {
        if self.is_remapped() { Some((self.word >> 8) as u8) } else { None }
    }

    pub const fn vector(self) -> Option<u8> {
        if self.is_remapped() { Some((self.word >> 16) as u8) } else { None }
    }
}
