//! Independent literal encodings for complete DTEs and basic interrupt entries.
//! All tables and addresses here are inert numeric values; no hardware is used.
use svmvisor_hypervisor::memory::{
    address::{AddressError, AddressPolicy, EncryptionState},
    iommu::tables::{
        BasicInterruptEntry, BasicInterruptTable, CompleteHostDeviceEntry, DteInterruptPolicy,
        EncodingError, HostDeviceEntry, Permissions,
    },
};

fn policy(bits: u8) -> AddressPolicy {
    AddressPolicy::new(bits, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

fn translation() -> HostDeviceEntry {
    HostDeviceEntry::new(policy(52), 0, 0, Permissions::None).unwrap()
}

#[test]
fn complete_abort_has_four_independently_expected_words() {
    // 48882-3.11 p63 / pp65-75: Mode=4, V=TV=1, IR=IW=1, DomainID=4321h.
    // Word 2 contains IV at absolute bit128, with IntCtl/pass bits all zero.
    // Word 3 is zero, including every vIOMMU/attribute field.
    let expected = [0x6000_0001_2345_6803, 0x4321, 0x0000_0000_0000_0001, 0];
    let lower =
        HostDeviceEntry::new(policy(48), 0x1_2345_6000, 0x4321, Permissions::ReadWrite).unwrap();
    let complete =
        CompleteHostDeviceEntry::new(policy(48), lower, DteInterruptPolicy::AbortControlled)
            .unwrap();
    assert_eq!(complete.words(), expected);
    let decoded = CompleteHostDeviceEntry::decode(policy(48), expected).unwrap();
    assert_eq!(decoded.translation(), lower);
    assert_eq!(decoded.interrupt_policy(), DteInterruptPolicy::AbortControlled);
    assert_eq!(decoded, complete);
    // This is intentionally still the lower-half API, used by image/walk code.
    assert_eq!(lower.words(), [0x6000_0001_2345_6803, 0x4321]);
}

#[test]
fn complete_basic_remapping_has_documented_root_length_and_control_positions() {
    // SPA[51:6] is in DTE[179:134]; IntTabLen=9 is in [132:129], IV in [128],
    // IntCtl=10b in [189:188]. The 128-byte alignment permits an 80h low byte.
    let table = BasicInterruptTable::new(policy(48), 0x2_3456_7880, 512).unwrap();
    let lower =
        HostDeviceEntry::new(policy(48), 0x1_2345_6000, 0x4321, Permissions::ReadWrite).unwrap();
    let expected = [0x6000_0001_2345_6803, 0x4321, 0x2000_0002_3456_7893, 0];
    let entry =
        CompleteHostDeviceEntry::new(policy(48), lower, DteInterruptPolicy::RemapBasic(table))
            .unwrap();
    assert_eq!(entry.words(), expected);
    let decoded = CompleteHostDeviceEntry::decode(policy(48), expected).unwrap();
    assert_eq!(decoded.interrupt_policy(), DteInterruptPolicy::RemapBasic(table));
    assert_eq!(table.root_address(), 0x2_3456_7880);
    assert_eq!(table.entry_count(), 512);
    assert_eq!(table.byte_len(), 2048);
}

#[test]
fn zero_padding_a_lower_half_never_creates_an_accepted_complete_entry() {
    for upper in [0, 0x1000_0000_0000_0000, 0x2000_0000_0000_0000] {
        assert_eq!(
            CompleteHostDeviceEntry::decode(policy(52), [0x803, 0, upper, 0]),
            Err(EncodingError::DeviceInterruptMappingDisabled)
        );
    }
    assert_eq!(
        CompleteHostDeviceEntry::decode(policy(52), [0, 0, 0, 0]),
        Err(EncodingError::DeviceTranslationDisabled)
    );
    for lower in [0x800, 0x801, 0x802] {
        assert_eq!(
            CompleteHostDeviceEntry::decode(policy(52), [lower, 0, 1, 0]),
            Err(EncodingError::DeviceTranslationDisabled)
        );
    }
    for mode in [0, 1, 2, 3, 5, 6, 7] {
        assert_eq!(
            CompleteHostDeviceEntry::decode(policy(52), [3 | (mode << 9), 0, 1, 0]),
            Err(EncodingError::UnsupportedHostMode(mode as u8))
        );
    }
}

#[test]
fn passthrough_reserved_and_stale_interrupt_policies_are_rejected() {
    for (raw, control) in [(0x1000_0000_0000_0001, 1), (0x3000_0000_0000_0001, 3)] {
        assert_eq!(
            CompleteHostDeviceEntry::decode(policy(52), [0x803, 0, raw, 0]),
            Err(EncodingError::UnsupportedInterruptControl(control))
        );
    }
    // IntCtl=00 ignores root and length in hardware, but stale data is refused.
    for bit in (1..5).chain(6..52) {
        assert_eq!(
            CompleteHostDeviceEntry::decode(policy(52), [0x803, 0, 1 | (1 << bit), 0]),
            Err(EncodingError::NonCanonicalInterruptTable),
            "ignored DTE bit {}",
            bit + 128
        );
    }
}

#[test]
fn complete_decoder_rejects_every_unsupported_bit_in_every_word() {
    let base = [0x803, 0, 0x2000_0000_0010_0013, 0];
    // Lower reserved, CXL/HAD/PPR/guest fields; upper IG, reserved,
    // GuestPagingMode, HPTMode and all five pass bits. Word3 is wholly unsupported.
    let unsupported: [Vec<u8>; 4] = [
        (2..9).chain(52..61).chain([63]).collect(),
        (16..64).collect(),
        [5].into_iter().chain(52..60).chain(62..64).collect(),
        (0..64).collect(),
    ];
    for (word, bits) in unsupported.into_iter().enumerate() {
        for bit in bits {
            let mut mutated = base;
            let mask = 1u64 << bit;
            mutated[word] |= mask;
            assert_eq!(
                CompleteHostDeviceEntry::decode(policy(52), mutated),
                Err(EncodingError::UnsupportedBits { word: word as u8, bits: mask }),
                "DTE bit {}",
                word * 64 + usize::from(bit)
            );
        }
    }
}

#[test]
fn all_interrupt_length_encodings_are_bounded() {
    for (count, raw) in [
        (1, 0x2000_0000_0000_0001),
        (2, 0x2000_0000_0000_0003),
        (4, 0x2000_0000_0000_0005),
        (8, 0x2000_0000_0000_0007),
        (16, 0x2000_0000_0000_0009),
        (32, 0x2000_0000_0000_000b),
        (64, 0x2000_0000_0000_000d),
        (128, 0x2000_0000_0000_000f),
        (256, 0x2000_0000_0000_0011),
        (512, 0x2000_0000_0000_0013),
    ] {
        let table = BasicInterruptTable::new(policy(52), 0, count).unwrap();
        let entry = CompleteHostDeviceEntry::new(
            policy(52),
            translation(),
            DteInterruptPolicy::RemapBasic(table),
        )
        .unwrap();
        assert_eq!(entry.words(), [0x803, 0, raw, 0]);
        assert_eq!(CompleteHostDeviceEntry::decode(policy(52), [0x803, 0, raw, 0]), Ok(entry));
    }
    // Lengths 10/11 are hardware formats outside our 512-entry profile;
    // 12..15 are hardware-reserved. None may be normalized or clamped.
    for length in 10..16 {
        let raw = 0x2000_0000_0000_0001 | (u64::from(length) << 1);
        assert_eq!(
            CompleteHostDeviceEntry::decode(policy(52), [0x803, 0, raw, 0]),
            Err(EncodingError::UnsupportedInterruptTableLength(length))
        );
    }
    for count in [0, 3, 6, 511, 513, 1024, 2048, 32768, u16::MAX] {
        assert_eq!(
            BasicInterruptTable::new(policy(52), 0, count),
            Err(EncodingError::UnsupportedInterruptEntryCount(count))
        );
    }
}

#[test]
fn interrupt_roots_require_128_byte_alignment_without_truncation() {
    for root in [1, 63, 64, 127, 129, u64::MAX] {
        assert_eq!(
            BasicInterruptTable::new(policy(52), root, 1),
            Err(EncodingError::Address(AddressError::Misaligned))
        );
    }
    // DTE bit134 is part of the architectural pointer field, but setting it
    // violates the 128-byte rule; accepting a 64-byte root would be wrong.
    assert_eq!(
        CompleteHostDeviceEntry::decode(policy(52), [0x803, 0, 0x2000_0000_0000_0041, 0]),
        Err(EncodingError::Address(AddressError::Misaligned))
    );
    for root in [1 << 52, u64::MAX - 127] {
        assert_eq!(
            BasicInterruptTable::new(policy(52), root, 1),
            Err(EncodingError::Address(AddressError::OutsidePhysicalWidth))
        );
    }
    assert_eq!(
        BasicInterruptTable::new(policy(52), u64::MAX - 127, 512),
        Err(EncodingError::Address(AddressError::Overflow))
    );
}

#[test]
fn entire_interrupt_table_must_fit_physical_width() {
    for bits in [32, 40, 48, 52] {
        for count in [1, 2, 16, 32, 64, 128, 256, 512] {
            let len = u64::from(count) * 4;
            let base = (1u64 << bits) - len.max(128);
            let table = BasicInterruptTable::new(policy(bits), base, count).unwrap();
            let entry = CompleteHostDeviceEntry::new(
                policy(bits),
                translation(),
                DteInterruptPolicy::RemapBasic(table),
            )
            .unwrap();
            assert_eq!(table.byte_len(), len);
            assert_eq!(CompleteHostDeviceEntry::decode(policy(bits), entry.words()), Ok(entry));
        }
        let root = (1u64 << bits) - 128;
        assert_eq!(
            BasicInterruptTable::new(policy(bits), root, 512),
            Err(EncodingError::Address(AddressError::OutsidePhysicalWidth))
        );
        assert_eq!(
            CompleteHostDeviceEntry::decode(
                policy(bits),
                [0x803, 0, 0x2000_0000_0000_0013 | root, 0],
            ),
            Err(EncodingError::Address(AddressError::OutsidePhysicalWidth))
        );
    }
}

#[test]
fn constructor_revalidates_both_backing_ranges_under_its_current_policy() {
    let high_lower = HostDeviceEntry::new(policy(52), 1 << 40, 0, Permissions::None).unwrap();
    assert_eq!(
        CompleteHostDeviceEntry::new(policy(40), high_lower, DteInterruptPolicy::AbortControlled),
        Err(EncodingError::Address(AddressError::OutsidePhysicalWidth))
    );
    let high_table = BasicInterruptTable::new(policy(52), 1 << 40, 512).unwrap();
    assert_eq!(
        CompleteHostDeviceEntry::new(
            policy(40),
            translation(),
            DteInterruptPolicy::RemapBasic(high_table),
        ),
        Err(EncodingError::Address(AddressError::OutsidePhysicalWidth))
    );
    let crossing_table = BasicInterruptTable::new(policy(52), 0xffff_ff80, 512).unwrap();
    assert_eq!(
        CompleteHostDeviceEntry::new(
            policy(32),
            translation(),
            DteInterruptPolicy::RemapBasic(crossing_table),
        ),
        Err(EncodingError::Address(AddressError::OutsidePhysicalWidth))
    );
}

#[test]
fn encryption_bit_is_checked_across_the_full_interrupt_extent() {
    let encrypted_bit =
        AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: Some(47) }).unwrap();
    assert_eq!(
        BasicInterruptTable::new(encrypted_bit, 1 << 47, 1),
        Err(EncodingError::Address(AddressError::EncryptionBitEncoded))
    );
    assert_eq!(
        CompleteHostDeviceEntry::decode(encrypted_bit, [0x803, 0, 0x2000_8000_0000_0001, 0]),
        Err(EncodingError::Address(AddressError::EncryptionBitEncoded))
    );
    let crossing =
        AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: Some(12) }).unwrap();
    let table = BasicInterruptTable::new(policy(52), 0xf80, 512).unwrap();
    assert_eq!(
        CompleteHostDeviceEntry::new(
            crossing,
            translation(),
            DteInterruptPolicy::RemapBasic(table)
        ),
        Err(EncodingError::Address(AddressError::EncryptionBitEncoded))
    );
    assert_eq!(
        CompleteHostDeviceEntry::decode(crossing, [0x803, 0, 0x2000_0000_0000_0f93, 0]),
        Err(EncodingError::Address(AddressError::EncryptionBitEncoded))
    );
    // Both endpoints have bit8=0, but 128..639 spans its entire set region.
    let middle =
        AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: Some(8) }).unwrap();
    assert_eq!(
        BasicInterruptTable::new(middle, 128, 128),
        Err(EncodingError::Address(AddressError::EncryptionBitEncoded))
    );
}

#[test]
fn basic_interrupt_words_encode_fixed_physical_delivery_and_canonical_abort() {
    // 48882-3.11 pp91-92: vector[23:16], destination[15:8], RemapEn[0].
    // This literal leaves GuestMode, DM, RqEoi, IntType and SupIOPF cleared.
    for (destination, vector, expected) in
        [(0x2a, 0xd4, 0x00d4_2a01), (0, 0x10, 0x0010_0001), (0xfe, 0xff, 0x00ff_fe01)]
    {
        let entry = BasicInterruptEntry::fixed(destination, vector).unwrap();
        assert_eq!(entry.word(), expected);
        let decoded = BasicInterruptEntry::decode(expected).unwrap();
        assert!(decoded.is_remapped());
        assert_eq!(decoded.destination(), Some(destination));
        assert_eq!(decoded.vector(), Some(vector));
        assert_eq!(decoded, entry);
    }
    let abort = BasicInterruptEntry::decode(0).unwrap();
    assert_eq!(abort, BasicInterruptEntry::ABORT);
    assert!(!abort.is_remapped());
    assert_eq!(abort.destination(), None);
    assert_eq!(abort.vector(), None);
}

#[test]
fn basic_interrupt_decoder_refuses_unsupported_or_stale_fields() {
    // Includes SupIOPF, arbitrated/reserved IntType, RqEoi, DM, GuestMode,
    // plus every reserved top bit. No mask silently discards these fields.
    for bit in (1..8).chain(24..32) {
        let mask = 1u32 << bit;
        assert_eq!(
            BasicInterruptEntry::decode(0x00d4_2a01 | mask),
            Err(EncodingError::UnsupportedBits { word: 0, bits: u64::from(mask) })
        );
    }
    for bit in 1..32 {
        assert_eq!(
            BasicInterruptEntry::decode(1 << bit),
            Err(EncodingError::NonCanonicalAbortedInterrupt)
        );
    }
    for vector in 0..16 {
        assert_eq!(
            BasicInterruptEntry::fixed(0, vector),
            Err(EncodingError::UnsupportedInterruptVector(vector))
        );
        assert_eq!(
            BasicInterruptEntry::decode((u32::from(vector) << 16) | 1),
            Err(EncodingError::UnsupportedInterruptVector(vector))
        );
    }
    assert_eq!(
        BasicInterruptEntry::fixed(0xff, 0x80),
        Err(EncodingError::UnsupportedInterruptDestination(0xff))
    );
    assert_eq!(
        BasicInterruptEntry::decode(0x0080_ff01),
        Err(EncodingError::UnsupportedInterruptDestination(0xff))
    );
}
