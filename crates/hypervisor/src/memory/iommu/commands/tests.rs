use super::*;
use crate::memory::address::EncryptionState;

fn policy(bits: u8) -> AddressPolicy {
    AddressPolicy::new(bits, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

#[test]
fn device_entry_encoding_matches_the_manual_words() {
    // Figure 45 / Table 35, 48882-3.11 pp125-126: opcode +04[31:28],
    // DeviceID +00[15:0], every remaining operand bit zero.
    let encoded = HostCommand::invalidate_device_entry(0x4321);
    assert_eq!(encoded.words(), [0x2000_0000_0000_4321, 0]);
}

#[test]
fn device_entry_decoding_uses_an_independent_literal_vector() {
    let decoded = HostCommand::decode(policy(32), [0x2000_0000_0000_abcd, 0]).unwrap();
    assert_eq!(decoded.operands(), CommandOperands::InvalidateDeviceEntry { device_id: 0xabcd });
}

#[test]
fn one_page_encoding_matches_the_manual_words() {
    // Figure 46 / Table 36, pp127-128: DomainID +04[15:0], PDE +08[1],
    // S=GN=PASID=0. Literal expectations do not use implementation masks.
    for (directories, expected) in [
        (PageDirectoryInvalidation::TranslationsOnly, 0x0000_1234_5678_9000),
        (PageDirectoryInvalidation::IncludeDirectories, 0x0000_1234_5678_9002),
    ] {
        let encoded =
            HostCommand::invalidate_page_4k(0xabcd, 0x1234_5678_9000, directories).unwrap();
        assert_eq!(encoded.words(), [0x3000_abcd_0000_0000, expected]);
    }
}

#[test]
fn one_page_decoding_uses_an_independent_literal_vector() {
    let decoded =
        HostCommand::decode(policy(52), [0x3000_1357_0000_0000, 0x0000_fedc_ba98_0002]).unwrap();
    assert_eq!(
        decoded.operands(),
        CommandOperands::InvalidatePage4k {
            domain_id: 0x1357,
            io_address: 0xfedc_ba98_0000,
            directories: PageDirectoryInvalidation::IncludeDirectories,
        }
    );
}

#[test]
fn domain_encoding_uses_the_exact_command_sentinel() {
    // p126 software note: Address[63:12]=7_FFFF_FFFF_FFFFh, PDE=S=1.
    // This is not the 52-bit PTE address example from Table 14 on p80.
    assert_eq!(
        HostCommand::invalidate_domain(0x4321).words(),
        [0x3000_4321_0000_0000, 0x7fff_ffff_ffff_f003]
    );
}

#[test]
fn domain_decoding_uses_an_independent_literal_vector() {
    let decoded =
        HostCommand::decode(policy(32), [0x3000_ffff_0000_0000, 0x7fff_ffff_ffff_f003]).unwrap();
    assert_eq!(decoded.operands(), CommandOperands::InvalidateDomain { domain_id: 0xffff });
}

#[test]
fn completion_encoding_matches_the_manual_words() {
    // Figure 44 / Table 34, pp124-125: address [51:3], f bit 2, i=0,
    // s bit 0; the second word is unmodified Store Data[63:0].
    let encoded = HostCommand::completion_wait(
        policy(52),
        0x000a_bcde_f012_3458,
        0x8877_6655_4433_2211,
        CompletionOrdering::WaitBeforeSubsequent,
    )
    .unwrap();
    assert_eq!(encoded.words(), [0x100a_bcde_f012_345d, 0x8877_6655_4433_2211]);
}

#[test]
fn completion_decoding_uses_an_independent_literal_vector() {
    let decoded =
        HostCommand::decode(policy(48), [0x1000_0001_2345_6781, 0xfedc_ba98_7654_3210]).unwrap();
    assert_eq!(
        decoded.operands(),
        CommandOperands::CompletionWait {
            store_address: 0x0000_0001_2345_6780,
            store_data: 0xfedc_ba98_7654_3210,
            ordering: CompletionOrdering::AllowIndependentSubsequent,
        }
    );
}

#[test]
fn command_word_and_little_endian_byte_order_are_explicit() {
    let words = HostCommand::completion_wait(
        policy(48),
        0x0000_1234_5678_9000,
        0x0807_0605_0403_0201,
        CompletionOrdering::WaitBeforeSubsequent,
    )
    .unwrap()
    .words();
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&words[0].to_le_bytes());
    bytes[8..].copy_from_slice(&words[1].to_le_bytes());
    assert_eq!(bytes, [0x05, 0x90, 0x78, 0x56, 0x34, 0x12, 0x00, 0x10, 1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn every_other_opcode_is_rejected_including_zero_and_optional_commands() {
    for opcode in 0u8..16 {
        if (1..=4).contains(&opcode) {
            continue;
        }
        assert_eq!(
            HostCommand::decode(policy(52), [u64::from(opcode) << 60, 0]),
            Err(CommandError::UnsupportedOpcode(opcode))
        );
    }
}

#[test]
fn remote_iotlb_vectors_preserve_distinct_requester_queue_and_depth() {
    let target = IotlbTarget { device_id: 0xabcd, queue_id: 0x1357, max_pending: 0x42 };
    assert_eq!(
        HostCommand::invalidate_iotlb_page_4k(target, 0xfedc_ba98_7000).unwrap().words(),
        [0x4000_1357_4200_abcd, 0x0000_fedc_ba98_7000]
    );
    assert_eq!(
        HostCommand::decode(policy(32), [0x4000_1234_ff00_5678, 0x7fff_ffff_ffff_f001])
            .unwrap()
            .operands(),
        CommandOperands::InvalidateIotlbAll {
            target: IotlbTarget { device_id: 0x5678, queue_id: 0x1234, max_pending: 0xff }
        }
    );
    assert_eq!(
        HostCommand::invalidate_iotlb_all(target).words(),
        [0x4000_1357_4200_abcd, 0x7fff_ffff_ffff_f001]
    );
}

#[test]
fn remote_iotlb_rejects_pasid_enhanced_types_reserved_bits_and_invalid_sentinels() {
    for bit in (16..24).chain(48..60) {
        let bits = 1u64 << bit;
        assert_eq!(
            HostCommand::decode(policy(48), [0x4000_0000_0000_0000 | bits, 0x1000]),
            Err(CommandError::UnsupportedBits { word: 0, bits })
        );
    }
    for bit in 1..12 {
        let bits = 1u64 << bit;
        assert_eq!(
            HostCommand::decode(policy(48), [0x4000_0000_0000_0000, 0x1000 | bits]),
            Err(CommandError::UnsupportedBits { word: 1, bits })
        );
    }
    for address in [1, 0x1001, 0xffff_ffff_ffff_f001, 0x7fff_ffff_ffff_e001] {
        assert_eq!(
            HostCommand::decode(policy(48), [0x4000_0000_0000_0000, address]),
            Err(CommandError::UnsupportedPageRange)
        );
    }
    assert_eq!(
        HostCommand::decode(policy(48), [0x4000_0000_0000_0000, 1 << 48]),
        Err(CommandError::IoAddressOutsideWidth)
    );
}

#[test]
fn all_device_entry_reserved_operand_bits_are_rejected() {
    for bit in 16..60 {
        let bits = 1u64 << bit;
        assert_eq!(
            HostCommand::decode(policy(52), [0x2000_0000_0000_4321 | bits, 0]),
            Err(CommandError::UnsupportedBits { word: 0, bits }),
            "first-word bit {bit}"
        );
    }
    for bit in 0..64 {
        let bits = 1u64 << bit;
        assert_eq!(
            HostCommand::decode(policy(52), [0x2000_0000_0000_4321, bits]),
            Err(CommandError::UnsupportedBits { word: 1, bits }),
            "second-word bit {bit}"
        );
    }
}

#[test]
fn page_invalidation_rejects_reserved_guest_and_ignored_pasid_bits() {
    // PASID +00[19:0] is ignored when GN=0 by hardware, but not accepted here.
    for bit in (0..32).chain(48..60) {
        let bits = 1u64 << bit;
        assert_eq!(
            HostCommand::decode(policy(52), [0x3000_1234_0000_0000 | bits, 0x2000]),
            Err(CommandError::UnsupportedBits { word: 0, bits }),
            "first-word bit {bit}"
        );
    }
    // GN +08[2] and reserved +08[11:3] are never accepted for either range.
    for bit in 2..12 {
        let bits = 1u64 << bit;
        for address in [0x2000, 0x7fff_ffff_ffff_f003] {
            assert_eq!(
                HostCommand::decode(policy(52), [0x3000_1234_0000_0000, address | bits]),
                Err(CommandError::UnsupportedBits { word: 1, bits }),
                "second-word bit {bit}"
            );
        }
    }
}

#[test]
fn completion_rejects_interrupt_and_all_reserved_address_bits() {
    for bit in core::iter::once(1).chain(52..60) {
        let bits = 1u64 << bit;
        assert_eq!(
            HostCommand::decode(policy(52), [0x1000_0000_0000_1005 | bits, u64::MAX]),
            Err(CommandError::UnsupportedBits { word: 0, bits }),
            "first-word bit {bit}"
        );
    }
}

#[test]
fn completion_never_accepts_a_no_store_command_with_stale_operands() {
    for address_and_flags in [0, 4, 0x1000, 0x1004] {
        for store_data in [0, 1, u64::MAX] {
            assert_eq!(
                HostCommand::decode(
                    policy(52),
                    [0x1000_0000_0000_0000 | address_and_flags, store_data]
                ),
                Err(CommandError::CompletionStoreDisabled)
            );
        }
    }
}

#[test]
fn size_one_accepts_only_the_whole_domain_sentinel_with_pde_set() {
    for encoded_range in
        [1, 3, 0x1001, 0x1003, 0x0007_ffff_ffff_f003, 0x7fff_ffff_ffff_f001, 0xffff_ffff_ffff_f003]
    {
        assert_eq!(
            HostCommand::decode(policy(52), [0x3000_0000_0000_0000, encoded_range]),
            Err(CommandError::UnsupportedPageRange)
        );
    }
    for bit in 12..64 {
        assert_eq!(
            HostCommand::decode(
                policy(52),
                [0x3000_0000_0000_0000, 0x7fff_ffff_ffff_f003 ^ (1 << bit)]
            ),
            Err(CommandError::UnsupportedPageRange),
            "changed sentinel bit {bit}"
        );
    }
    // A sentinel without S is an overwide one-page DVA, never silently fixed.
    assert_eq!(
        HostCommand::decode(policy(52), [0x3000_0000_0000_0000, 0x7fff_ffff_ffff_f002]),
        Err(CommandError::IoAddressOutsideWidth)
    );
}

#[test]
fn identifier_boundaries_are_explicit_u16_values() {
    for identifier in [0, 1, u16::MAX] {
        let device = HostCommand::invalidate_device_entry(identifier);
        assert_eq!(device.words(), [0x2000_0000_0000_0000 | u64::from(identifier), 0]);
        let domain = HostCommand::invalidate_domain(identifier);
        assert_eq!(
            domain.words(),
            [0x3000_0000_0000_0000 | (u64::from(identifier) << 32), 0x7fff_ffff_ffff_f003]
        );
        assert_eq!(HostCommand::decode(policy(32), device.words()), Ok(device));
        assert_eq!(HostCommand::decode(policy(32), domain.words()), Ok(domain));
    }
}

#[test]
fn one_page_alignment_width_and_overflow_never_truncate_the_operand() {
    for offset in 1..4096 {
        assert_eq!(
            HostCommand::invalidate_page_4k(
                0,
                0x1000 + offset,
                PageDirectoryInvalidation::TranslationsOnly
            ),
            Err(CommandError::IoAddressMisaligned)
        );
    }
    for address in [1 << 48, 0xffff_8000_0000_0000, u64::MAX - 4095] {
        assert_eq!(
            HostCommand::invalidate_page_4k(
                0,
                address,
                PageDirectoryInvalidation::TranslationsOnly
            ),
            Err(CommandError::IoAddressOutsideWidth)
        );
    }
    for address in [u64::MAX - 4094, u64::MAX] {
        assert_eq!(
            HostCommand::invalidate_page_4k(
                0,
                address,
                PageDirectoryInvalidation::TranslationsOnly
            ),
            Err(CommandError::IoAddressOverflow)
        );
    }
    let final_page = HostCommand::invalidate_page_4k(
        0,
        0x0000_ffff_ffff_f000,
        PageDirectoryInvalidation::TranslationsOnly,
    )
    .unwrap();
    assert_eq!(final_page.words(), [0x3000_0000_0000_0000, 0x0000_ffff_ffff_f000]);
    assert_eq!(HostCommand::decode(policy(32), final_page.words()), Ok(final_page));
}

#[test]
fn page_decode_rejects_every_bit_above_the_four_level_dva_width() {
    for bit in 48..64 {
        assert_eq!(
            HostCommand::decode(policy(52), [0x3000_0000_0000_0000, 0x1000 | (1 << bit)]),
            Err(CommandError::IoAddressOutsideWidth)
        );
    }
}

#[test]
fn physical_width_and_encryption_checks_do_not_apply_to_dvas_or_sentinels() {
    let address_policy =
        AddressPolicy::new(32, EncryptionState::Unencrypted { encryption_bit: Some(47) }).unwrap();
    let page_words = [0x3000_1234_0000_0000, 0x0000_8000_0000_0000];
    let page = HostCommand::decode(address_policy, page_words).unwrap();
    assert_eq!(page.words(), page_words);
    let domain_words = [0x3000_1234_0000_0000, 0x7fff_ffff_ffff_f003];
    let domain = HostCommand::decode(address_policy, domain_words).unwrap();
    assert_eq!(domain.words(), domain_words);
}

#[test]
fn completion_checks_the_last_eight_bytes_at_each_physical_width() {
    for bits in [32, 40, 48, 52] {
        let last_store = (1u64 << bits) - 8;
        let encoded = HostCommand::completion_wait(
            policy(bits),
            last_store,
            u64::MAX,
            CompletionOrdering::AllowIndependentSubsequent,
        )
        .unwrap();
        assert_eq!(encoded.words(), [0x1000_0000_0000_0001 | last_store, u64::MAX]);
        assert_eq!(HostCommand::decode(policy(bits), encoded.words()), Ok(encoded));
        assert_eq!(
            HostCommand::completion_wait(
                policy(bits),
                1u64 << bits,
                0,
                CompletionOrdering::WaitBeforeSubsequent,
            ),
            Err(CommandError::StoreAddress(AddressError::OutsidePhysicalWidth))
        );
    }
}

#[test]
fn completion_alignment_and_top_of_u64_addresses_never_wrap_or_mask() {
    for address in [1, 2, 3, 4, 5, 6, 7, 0x1001, u64::MAX] {
        assert_eq!(
            HostCommand::completion_wait(
                policy(52),
                address,
                0,
                CompletionOrdering::WaitBeforeSubsequent,
            ),
            Err(CommandError::StoreAddress(AddressError::Misaligned))
        );
    }
    // An aligned 8-byte range cannot overflow u64; its top possible range is
    // still outside the 52-bit format. Misaligned wrapping candidates fail too.
    for address in [1 << 52, u64::MAX - 7] {
        assert_eq!(
            HostCommand::completion_wait(
                policy(52),
                address,
                0,
                CompletionOrdering::WaitBeforeSubsequent,
            ),
            Err(CommandError::StoreAddress(AddressError::OutsidePhysicalWidth))
        );
    }
}

#[test]
fn completion_decode_reapplies_width_and_encryption_policy() {
    let words = [0x1000_8000_0000_0001, 0xffff_ffff_ffff_ffff];
    assert!(HostCommand::decode(policy(52), words).is_ok());
    assert_eq!(
        HostCommand::decode(policy(40), words),
        Err(CommandError::StoreAddress(AddressError::OutsidePhysicalWidth))
    );
    let encrypted =
        AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: Some(47) }).unwrap();
    assert_eq!(
        HostCommand::decode(encrypted, words),
        Err(CommandError::StoreAddress(AddressError::EncryptionBitEncoded))
    );
    assert_eq!(
        HostCommand::completion_wait(
            encrypted,
            1 << 47,
            0,
            CompletionOrdering::WaitBeforeSubsequent,
        ),
        Err(CommandError::StoreAddress(AddressError::EncryptionBitEncoded))
    );
    // Every byte is checked, even when a hypothetical low encryption bit is
    // clear at the base; this 8-byte range crosses that bit's toggle.
    let low_bit =
        AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: Some(2) }).unwrap();
    assert_eq!(
        HostCommand::decode(low_bit, [0x1000_0000_0000_0001, 0]),
        Err(CommandError::StoreAddress(AddressError::EncryptionBitEncoded))
    );
}

#[test]
fn zero_numeric_addresses_and_arbitrary_store_data_are_not_runtime_state() {
    let page =
        HostCommand::invalidate_page_4k(0, 0, PageDirectoryInvalidation::TranslationsOnly).unwrap();
    assert_eq!(page.words(), [0x3000_0000_0000_0000, 0]);
    for data in [0, 1, u64::MAX, 0x1000_0000_0000_0000] {
        let completion = HostCommand::completion_wait(
            policy(32),
            0,
            data,
            CompletionOrdering::AllowIndependentSubsequent,
        )
        .unwrap();
        assert_eq!(completion.words(), [0x1000_0000_0000_0001, data]);
        assert_eq!(HostCommand::decode(policy(32), completion.words()), Ok(completion));
    }
}

#[test]
fn arbitrary_fixed_size_inputs_fail_boundedly_without_normalization() {
    // A deterministic hostile corpus supplements independent conformance and
    // per-bit tests. Decode has no callback, unbounded input or mutable output.
    let mut state = 0xcafe_f00d_1234_5678u64;
    for index in 0..8192 {
        state = state.wrapping_mul(0xd134_2543_de82_ef95).rotate_left(17);
        let first = state;
        state = state.wrapping_mul(0xd134_2543_de82_ef95).rotate_left(29);
        let words = [first, state];
        if let Ok(command) = HostCommand::decode(policy(52), words) {
            assert_eq!(command.words(), words, "corpus item {index}");
        }
    }
}
