use super::*;
use crate::memory::address::EncryptionState;

fn policy(bits: u8) -> AddressPolicy {
    AddressPolicy::new(bits, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

#[test]
fn device_translation_half_has_the_documented_known_words() {
    // Figure 7 / Table 7, 48882-3.11 p63, pp70-74:
    // IW bit 62, IR bit 61, root bits 51:12, Mode bits 11:9 (value 4),
    // TV bit 1 and V bit 0 are set;
    // DomainID=79:64. This expectation is a literal, not encoder constants.
    let entry =
        HostDeviceEntry::new(policy(48), 0x1_2345_6000, 0x4321, Permissions::ReadWrite).unwrap();
    assert_eq!(entry.words(), [0x6000_0001_2345_6803, 0x4321]);
    let decoded = HostDeviceEntry::decode(policy(48), [0x6000_0001_2345_6803, 0x4321]).unwrap();
    assert_eq!(decoded.root_address(), 0x1_2345_6000);
    assert_eq!(decoded.domain_id(), 0x4321);
    assert_eq!(decoded.permissions(), Permissions::ReadWrite);
    assert_eq!(core::mem::size_of::<HostDeviceEntry>(), 16);
}

#[test]
fn permission_words_use_amd_io_bits_instead_of_cpu_write_bit() {
    // I/O IR/IW are bits 61/62, not CPU PTE.R/W (48882-3.11 pp83,85).
    for (permission, high, read, write) in [
        (Permissions::None, 0x0000_0000_0000_0000, false, false),
        (Permissions::Read, 0x2000_0000_0000_0000, true, false),
        (Permissions::Write, 0x4000_0000_0000_0000, false, true),
        (Permissions::ReadWrite, 0x6000_0000_0000_0000, true, true),
    ] {
        let entry =
            HostPageEntry::leaf_4k(policy(48), 0, permission, PageCoherency::Inherit).unwrap();
        assert_eq!(entry.word(), high | 1);
        assert_eq!(entry.permissions(), Some(permission));
        assert_eq!(permission.allows_read(), read);
        assert_eq!(permission.allows_write(), write);
        let device = HostDeviceEntry::new(policy(48), 0, 0, permission).unwrap();
        assert_eq!(device.words(), [high | 0x803, 0]);
    }
    // A CPU-style R/W or NX bit is not silently treated as an I/O permission.
    for word in [0x1003, 0x8000_0000_0000_1001] {
        assert!(matches!(
            HostPageEntry::decode(policy(48), PageLevel::One, word),
            Err(EncodingError::UnsupportedBits { .. })
        ));
    }
}

#[test]
fn zero_and_disabled_device_translation_are_not_deny_entries() {
    assert_eq!(
        HostDeviceEntry::decode(policy(48), [0, 0]),
        Err(EncodingError::DeviceTranslationDisabled)
    );
    // V=0 is passthrough (p74); TV=0 does not select this host profile.
    for low in [0x1800, 0x1801, 0x1802] {
        assert_eq!(
            HostDeviceEntry::decode(policy(48), [low, 1]),
            Err(EncodingError::DeviceTranslationDisabled)
        );
    }
}

#[test]
fn device_mode_zero_reserved_and_other_depths_are_rejected() {
    for mode in 0u8..8 {
        if mode == 4 {
            continue;
        }
        assert_eq!(
            HostDeviceEntry::decode(policy(48), [0x1003 | (u64::from(mode) << 9), 0]),
            Err(EncodingError::UnsupportedHostMode(mode))
        );
    }
}

#[test]
fn all_unsupported_device_half_bits_are_rejected() {
    // CXL/HAD/reserved, guest/PPR/GCR3 and bit 63 cannot enter this profile.
    for bit in (2..9).chain(52..61).chain(core::iter::once(63)) {
        let mask = 1u64 << bit;
        assert_eq!(
            HostDeviceEntry::decode(policy(52), [0x1803 | mask, 0]),
            Err(EncodingError::UnsupportedBits { word: 0, bits: mask }),
            "DTE bit {bit}"
        );
    }
    // Only DomainID occupies this word. In particular EX (103), I (96),
    // IoCtl (100:99), SysMgt (105:104) are never accepted by the codec.
    for bit in 16..64 {
        let mask = 1u64 << bit;
        assert_eq!(
            HostDeviceEntry::decode(policy(52), [0x1803, mask]),
            Err(EncodingError::UnsupportedBits { word: 1, bits: mask }),
            "DTE bit {}",
            bit + 64
        );
    }
}

#[test]
fn numeric_domain_id_boundaries_remain_explicit() {
    for domain_id in [0, 1, u16::MAX] {
        let entry = HostDeviceEntry::new(policy(48), 0x1000, domain_id, Permissions::None).unwrap();
        assert_eq!(entry.words()[1], u64::from(domain_id));
        assert_eq!(
            HostDeviceEntry::decode(policy(48), entry.words()).unwrap().domain_id(),
            domain_id
        );
    }
}

#[test]
fn four_kib_leaf_known_word_and_force_coherent_are_exact() {
    // Figure 9, Table 17: PR bit 0, FC bit 60, IR bit 61 and IW bit 62 (pp82-84).
    let entry = HostPageEntry::leaf_4k(
        policy(48),
        0x8765_4000,
        Permissions::ReadWrite,
        PageCoherency::ForceCoherent,
    )
    .unwrap();
    assert_eq!(entry.word(), 0x7000_0000_8765_4001);
    let decoded = HostPageEntry::decode(policy(48), PageLevel::One, 0x7000_0000_8765_4001).unwrap();
    assert!(decoded.is_present());
    assert_eq!(decoded.address(), Some(0x8765_4000));
    assert_eq!(decoded.permissions(), Some(Permissions::ReadWrite));
    assert_eq!(decoded.coherency(), Some(PageCoherency::ForceCoherent));
    assert_eq!(decoded.next_level(), None);
    assert_eq!(core::mem::size_of::<HostPageEntry>(), 8);
}

#[test]
fn contiguous_directory_words_and_levels_are_exact() {
    // Figure 10 / Table 18, p85: NextLevel bits 11:9 identify the next table.
    for (level, next, expected) in [
        (PageLevel::Four, PageLevel::Three, 0x6000_0000_2468_a601),
        (PageLevel::Three, PageLevel::Two, 0x6000_0000_2468_a401),
        (PageLevel::Two, PageLevel::One, 0x6000_0000_2468_a201),
    ] {
        let encoded =
            HostPageEntry::directory(policy(48), level, 0x2468_a000, Permissions::ReadWrite)
                .unwrap();
        assert_eq!(encoded.word(), expected);
        let decoded = HostPageEntry::decode(policy(48), level, expected).unwrap();
        assert_eq!(decoded.address(), Some(0x2468_a000));
        assert_eq!(decoded.permissions(), Some(Permissions::ReadWrite));
        assert_eq!(decoded.next_level(), Some(next));
        assert_eq!(decoded.coherency(), None);
    }
    assert_eq!(
        HostPageEntry::directory(policy(48), PageLevel::One, 0x1000, Permissions::Read),
        Err(EncodingError::DirectoryAtLeafLevel)
    );
}

#[test]
fn absent_is_canonical_and_does_not_retain_stale_fields() {
    for level in [PageLevel::One, PageLevel::Two, PageLevel::Three, PageLevel::Four] {
        let absent = HostPageEntry::decode(policy(48), level, 0).unwrap();
        assert_eq!(absent, HostPageEntry::ABSENT);
        assert!(!absent.is_present());
        assert_eq!(absent.address(), None);
        assert_eq!(absent.permissions(), None);
        assert_eq!(absent.next_level(), None);
        assert_eq!(absent.coherency(), None);
        // Hardware ignores all these bits when PR=0; strict offline decoding
        // intentionally refuses to hide stale data by normalizing it (p82).
        for bit in 1..64 {
            assert_eq!(
                HostPageEntry::decode(policy(48), level, 1 << bit),
                Err(EncodingError::NonCanonicalAbsent)
            );
        }
    }
}

#[test]
fn physical_page_zero_and_no_permissions_are_not_absent() {
    let present =
        HostPageEntry::leaf_4k(policy(48), 0, Permissions::None, PageCoherency::Inherit).unwrap();
    assert_eq!(present.word(), 1);
    assert_eq!(present.address(), Some(0));
    assert_eq!(present.permissions(), Some(Permissions::None));
    assert_ne!(present, HostPageEntry::ABSENT);
}

#[test]
fn all_unsupported_leaf_bits_are_rejected() {
    // Includes CPU ignored bits, A/D, U, migration fields and reserved bits.
    for bit in (1..9).chain(52..60).chain(core::iter::once(63)) {
        let mask = 1u64 << bit;
        assert_eq!(
            HostPageEntry::decode(policy(52), PageLevel::One, 0x1001 | mask),
            Err(EncodingError::UnsupportedBits { word: 0, bits: mask }),
            "leaf bit {bit}"
        );
    }
}

#[test]
fn all_unsupported_directory_bits_including_fc_are_rejected() {
    for bit in (1..9).chain(52..61).chain(core::iter::once(63)) {
        let mask = 1u64 << bit;
        assert_eq!(
            HostPageEntry::decode(policy(52), PageLevel::Four, 0x1601 | mask),
            Err(EncodingError::UnsupportedBits { word: 0, bits: mask }),
            "directory bit {bit}"
        );
    }
}

#[test]
fn every_next_level_encoding_is_checked_in_its_containing_level() {
    for level in [PageLevel::One, PageLevel::Two, PageLevel::Three, PageLevel::Four] {
        for next in 0u8..8 {
            let result = HostPageEntry::decode(policy(48), level, 0x1001 | (u64::from(next) << 9));
            if next == 0 && level == PageLevel::One {
                assert!(result.is_ok());
            } else if next == 0 {
                // Default large leaves at levels 2/3/4 are intentionally absent.
                assert_eq!(result, Err(EncodingError::LeafAtWrongLevel(level)));
            } else if level.next().map(PageLevel::number) == Some(next) {
                assert!(result.is_ok());
            } else {
                // Includes skip-level links, equal/higher levels and the
                // NextLevel=7 enlarged-page encoding (pp80-81).
                assert_eq!(
                    result,
                    Err(EncodingError::UnsupportedNextLevel { current: level, next })
                );
            }
        }
    }
}

#[test]
fn only_levels_one_through_four_exist_in_the_profile() {
    for number in 0..=u8::MAX {
        let result = PageLevel::from_number(number);
        if (1..=4).contains(&number) {
            assert_eq!(result.unwrap().number(), number);
        } else {
            assert_eq!(result, Err(EncodingError::UnsupportedPageLevel(number)));
        }
    }
}

#[test]
fn final_complete_page_of_each_physical_width_is_validated() {
    for bits in [32, 40, 48, 52] {
        let address_policy = policy(bits);
        let last_page = (1u64 << bits) - 4096;
        let device = HostDeviceEntry::new(address_policy, last_page, 1, Permissions::Read).unwrap();
        assert_eq!(device.root_address(), last_page);
        assert_eq!(HostDeviceEntry::decode(address_policy, device.words()), Ok(device));
        let leaf = HostPageEntry::leaf_4k(
            address_policy,
            last_page,
            Permissions::Write,
            PageCoherency::Inherit,
        )
        .unwrap();
        assert_eq!(HostPageEntry::decode(address_policy, PageLevel::One, leaf.word()), Ok(leaf));
        let outside = 1u64 << bits;
        assert_eq!(
            HostDeviceEntry::new(address_policy, outside, 1, Permissions::Read),
            Err(EncodingError::Address(AddressError::OutsidePhysicalWidth))
        );
        assert_eq!(
            HostPageEntry::directory(address_policy, PageLevel::Four, outside, Permissions::Read),
            Err(EncodingError::Address(AddressError::OutsidePhysicalWidth))
        );
    }
}

#[test]
fn constructors_never_truncate_misaligned_or_overwide_addresses() {
    for address in [1, 0xfff, 0x1001, 0xffff_ffff_ffff_ffff] {
        let expected = Err(EncodingError::Address(AddressError::Misaligned));
        assert_eq!(
            HostDeviceEntry::new(policy(52), address, 0, Permissions::None).map(|_| ()),
            expected
        );
        assert_eq!(
            HostPageEntry::directory(policy(52), PageLevel::Four, address, Permissions::None)
                .map(|_| ()),
            expected
        );
        assert_eq!(
            HostPageEntry::leaf_4k(policy(52), address, Permissions::None, PageCoherency::Inherit)
                .map(|_| ()),
            expected
        );
    }
    // The top aligned u64 page must be refused, never masked down to bit 51.
    for address in [1u64 << 52, u64::MAX - 4095] {
        assert_eq!(
            HostDeviceEntry::new(policy(52), address, 0, Permissions::None),
            Err(EncodingError::Address(AddressError::OutsidePhysicalWidth))
        );
        assert_eq!(
            HostPageEntry::leaf_4k(policy(52), address, Permissions::None, PageCoherency::Inherit),
            Err(EncodingError::Address(AddressError::OutsidePhysicalWidth))
        );
    }
}

#[test]
fn decoders_apply_the_supplied_physical_width_to_encoded_pages() {
    assert_eq!(
        HostDeviceEntry::decode(policy(40), [0x0000_0100_0000_0803, 0]),
        Err(EncodingError::Address(AddressError::OutsidePhysicalWidth))
    );
    assert_eq!(
        HostPageEntry::decode(policy(40), PageLevel::One, 0x0000_0100_0000_0001),
        Err(EncodingError::Address(AddressError::OutsidePhysicalWidth))
    );
    assert_eq!(
        HostPageEntry::decode(policy(40), PageLevel::Four, 0x0000_0100_0000_0601),
        Err(EncodingError::Address(AddressError::OutsidePhysicalWidth))
    );
}

#[test]
fn encoded_encryption_bit_is_not_accepted_as_an_address_bit() {
    let address_policy =
        AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: Some(47) }).unwrap();
    let address = 1u64 << 47;
    assert_eq!(
        HostDeviceEntry::new(address_policy, address, 0, Permissions::None),
        Err(EncodingError::Address(AddressError::EncryptionBitEncoded))
    );
    assert_eq!(
        HostDeviceEntry::decode(address_policy, [address | 0x803, 0]),
        Err(EncodingError::Address(AddressError::EncryptionBitEncoded))
    );
    assert_eq!(
        HostPageEntry::decode(address_policy, PageLevel::One, address | 1),
        Err(EncodingError::Address(AddressError::EncryptionBitEncoded))
    );
    // Existing AddressPolicy also validates every byte: a low hypothetical
    // encryption bit cannot be crossed by a page with zero-looking endpoints.
    let small_bit_policy =
        AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: Some(11) }).unwrap();
    assert_eq!(
        HostPageEntry::leaf_4k(small_bit_policy, 0, Permissions::Read, PageCoherency::Inherit),
        Err(EncodingError::Address(AddressError::EncryptionBitEncoded))
    );
}
