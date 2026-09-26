//! Deliberately small public terminal report. No register or address fields.
//!
//! This is diagnostic output, not an authenticated ownership assertion or an
//! input protocol. A missing record proves nothing about runtime progress.

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    Other = 1,
    ConfigurationAccess = 2,
    ConfigurationRoute = 3,
    SmiConfigurationTrap = 4,
    MemoryPolicy = 5,
    ArchitecturalControl = 6,
}

/// Existing eight-DWORD journal format, phase 15h/detail 8, version 1.
/// Sequence and boot identify this boot's record. All remaining words come
/// from fixed constants or the closed reason enum; even a timestamp is absent.
#[inline]
pub const fn record(sequence: u32, boot: u32, reason: StopReason) -> [u32; 8] {
    [sequence, boot, 0, 0, 1 | ((reason as u32) << 8), 0, 0, 0x0008_0015]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_record_has_no_free_form_payload() {
        for reason in [
            StopReason::Other,
            StopReason::ConfigurationAccess,
            StopReason::ConfigurationRoute,
            StopReason::SmiConfigurationTrap,
            StopReason::MemoryPolicy,
            StopReason::ArchitecturalControl,
        ] {
            let words = record(7, 9, reason);
            assert_eq!(&words[..4], &[7, 9, 0, 0]);
            assert_eq!(words[4], 1 | ((reason as u32) << 8));
            assert_eq!(&words[5..], &[0, 0, 0x0008_0015]);
        }
    }
}
