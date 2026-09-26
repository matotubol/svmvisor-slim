use super::{AddressPolicy, DteInterruptPolicy, EncodingError, HostDeviceEntry};

/// A complete 256-bit DTE in the restricted host profile. `words()` emits all
/// four words; the Rust value itself is not a hardware memory layout.
///
/// The translation half retains V=TV=1, Mode=4 and explicit IR/IW/DomainID.
/// Interrupt policy is mandatory: IV=1, with either controlled aborts or basic
/// remapping, and no passthrough bits. SMI is outside the DTE's control and can
/// still pass without a separately established SMI filter (48882-3.11 p75).
/// Basic remapping requires GAEn=0; the DTE cannot select the IRTE size (p93).
///
/// No default, implicit conversion from the lower half, feature admission,
/// requester/special-device policy, protected backing or installation is supplied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompleteHostDeviceEntry {
    translation: HostDeviceEntry,
    interrupts: DteInterruptPolicy,
}

impl CompleteHostDeviceEntry {
    /// Combine explicit translation and interrupt fields, revalidating both
    /// numeric backing ranges against this call's physical-address policy.
    pub fn new(
        policy: AddressPolicy,
        translation: HostDeviceEntry,
        interrupts: DteInterruptPolicy,
    ) -> Result<Self, EncodingError> {
        let translation = HostDeviceEntry::decode(policy, translation.words())?;
        interrupts.validate(policy)?;
        Ok(Self { translation, interrupts })
    }

    /// Strictly decode all 256 bits in the restricted profile. Unsupported,
    /// reserved and noncanonical ignored fields are errors, including IV=0.
    /// The supplied words do not establish GAEn=0 or any runtime protection.
    pub fn decode(policy: AddressPolicy, words: [u64; 4]) -> Result<Self, EncodingError> {
        let translation = HostDeviceEntry::decode(policy, [words[0], words[1]])?;
        let interrupts = DteInterruptPolicy::decode(policy, [words[2], words[3]])?;
        Ok(Self { translation, interrupts })
    }

    /// DTE bits 63:0, 127:64, 191:128 and 255:192, respectively.
    /// All 32 bytes are represented; no missing half is inferred by a caller.
    pub const fn words(self) -> [u64; 4] {
        let low = self.translation.words();
        [low[0], low[1], self.interrupts.word(), 0]
    }

    /// The unchanged restricted lower-half value used by the offline walker.
    pub const fn translation(self) -> HostDeviceEntry {
        self.translation
    }

    pub const fn interrupt_policy(self) -> DteInterruptPolicy {
        self.interrupts
    }
}
