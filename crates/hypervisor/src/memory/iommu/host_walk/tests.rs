use super::*;
use crate::memory::address::{AddressError, EncryptionState};

const RW: Permissions = Permissions::ReadWrite;
const LEVELS: [PageLevel; 4] = [PageLevel::Four, PageLevel::Three, PageLevel::Two, PageLevel::One];
// Independent literal words: PR=1, IW/IR at 62/61, next level at 11:9.
const WORDS: [u64; 4] =
    [0x6000_0000_0020_0601, 0x6000_0000_0030_0401, 0x6000_0000_0040_0201, 0x7000_0000_1234_5001];

fn policy(bits: u8) -> AddressPolicy {
    AddressPolicy::new(bits, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

fn device() -> HostDeviceEntry {
    HostDeviceEntry::decode(policy(52), [0x6000_0000_0010_0803, 0x31]).unwrap()
}

#[test]
fn literal_words_select_each_unsigned_dva_index_and_leaf_offset() {
    let io_address = (0x101 << 39) | (0x82 << 30) | (0x43 << 21) | (0x24 << 12) | 0xabc;
    let expected_reads = [0x10_0808, 0x20_0410, 0x30_0218, 0x40_0120];
    let mut reads = 0;
    let result = walk(policy(52), device(), io_address, |address| {
        assert_eq!(address, expected_reads[reads]);
        let word = WORDS[reads];
        reads += 1;
        Ok::<_, ()>(word)
    })
    .unwrap();
    assert_eq!(reads, MAX_WORD_READS);
    assert_eq!(
        result,
        Some(HostTranslation {
            system_address: 0x1234_5abc,
            permissions: RW,
            coherency: PageCoherency::ForceCoherent,
        })
    );
}

#[test]
fn permissions_are_intersected_at_device_and_all_four_levels() {
    let choices = [Permissions::None, Permissions::Read, Permissions::Write, RW];
    for combination in 0..1024 {
        let flags: [Permissions; 5] =
            core::array::from_fn(|i| choices[(combination >> (i * 2)) & 3]);
        let device = HostDeviceEntry::new(policy(52), 0x10_0000, 1, flags[0]).unwrap();
        let mut reads = 0;
        let result = walk(policy(52), device, 0, |address| {
            assert_eq!(address, ((reads + 1) as u64) << 20);
            let entry = if reads == 3 {
                HostPageEntry::leaf_4k(policy(52), 0x1234_5000, flags[4], PageCoherency::Inherit)
            } else {
                HostPageEntry::directory(
                    policy(52),
                    LEVELS[reads],
                    ((reads + 2) as u64) << 20,
                    flags[reads + 1],
                )
            }
            .unwrap();
            reads += 1;
            Ok::<_, ()>(entry.word())
        })
        .unwrap()
        .unwrap();
        assert_eq!(result.permissions.allows_read(), flags.iter().all(|p| p.allows_read()));
        assert_eq!(result.permissions.allows_write(), flags.iter().all(|p| p.allows_write()));
        assert_eq!(result.coherency, PageCoherency::Inherit);
        assert_eq!(reads, MAX_WORD_READS);
    }
}

#[test]
fn absent_at_any_level_stops_without_following_its_address() {
    for absent in 0..4 {
        let mut reads = 0;
        let result = walk(policy(52), device(), 0, |_| {
            let word = if reads == absent { 0 } else { WORDS[reads] };
            reads += 1;
            Ok::<_, ()>(word)
        });
        assert_eq!(result, Ok(None));
        assert_eq!(reads, absent + 1);
    }
}

#[test]
fn callback_failure_keeps_location_and_stops_at_every_level() {
    for failure in 0..4 {
        let mut reads = 0;
        let result = walk(policy(52), device(), 0, |_| {
            let index = reads;
            reads += 1;
            if index == failure { Err(0x5a) } else { Ok(WORDS[index]) }
        });
        assert_eq!(
            result,
            Err(WalkError::Read {
                level: LEVELS[failure],
                entry_address: ((failure + 1) as u64) << 20,
                error: 0x5a,
            })
        );
        assert_eq!(reads, failure + 1);
    }
}

#[test]
fn malformed_or_unsupported_words_never_become_absent_or_trigger_an_extra_read() {
    for (index, mutation) in [(0, 1 << 9), (1, 1 << 60), (3, 1 << 52), (3, 1)] {
        let mut reads = 0;
        let result = walk(policy(52), device(), 0, |_| {
            let value = WORDS[reads] ^ if reads == index { mutation } else { 0 };
            reads += 1;
            Ok::<_, ()>(value)
        });
        assert!(
            matches!(result, Err(WalkError::PageEncoding { level, .. }) if level == LEVELS[index])
        );
        assert_eq!(reads, index + 1);
    }
}

#[test]
fn out_of_width_or_x86_sign_extended_addresses_read_nothing() {
    for address in [1 << 48, 0xffff_8000_0000_0000, u64::MAX] {
        assert_eq!(
            walk(policy(52), device(), address, |_| -> Result<u64, ()> {
                panic!("out-of-profile address must not fetch tables")
            }),
            Err(WalkError::IoAddressOutsideWidth)
        );
    }
}

#[test]
fn highest_unsigned_address_uses_the_last_word_of_each_table() {
    let mut reads = 0;
    let result = walk(policy(52), device(), (1 << 48) - 1, |address| {
        assert_eq!(address, (((reads + 1) as u64) << 20) + 4088);
        let word = WORDS[reads];
        reads += 1;
        Ok::<_, ()>(word)
    })
    .unwrap()
    .unwrap();
    assert_eq!(result.system_address, 0x1234_5fff);
    assert_eq!(reads, MAX_WORD_READS);
}

#[test]
fn root_is_revalidated_against_the_current_address_policy_before_reading() {
    let device = HostDeviceEntry::new(policy(52), 1 << 40, 0, RW).unwrap();
    assert_eq!(
        walk(policy(32), device, 0, |_| -> Result<u64, ()> {
            panic!("invalid root must not be fetched")
        }),
        Err(WalkError::DeviceEncoding(EncodingError::Address(AddressError::OutsidePhysicalWidth)))
    );
}

#[test]
fn an_out_of_width_leaf_is_an_error_without_any_payload_read() {
    let mut reads = 0;
    let result = walk(policy(32), device(), 0, |_| {
        let word = if reads == 3 { WORDS[reads] | (1 << 40) } else { WORDS[reads] };
        reads += 1;
        Ok::<_, ()>(word)
    });
    assert_eq!(
        result,
        Err(WalkError::PageEncoding {
            level: PageLevel::One,
            entry_address: 0x40_0000,
            error: EncodingError::Address(AddressError::OutsidePhysicalWidth),
        })
    );
    assert_eq!(reads, MAX_WORD_READS);
}
