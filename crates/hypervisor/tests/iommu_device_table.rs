//! Independently inspect every emitted DTE word and every transactional refusal.
//! All addresses and register values are inert; these tests access no hardware.
use svmvisor_hypervisor::memory::{
    address::{AddressError, AddressPolicy, EncryptionState},
    iommu::{
        device_table::{
            self, Assignment, BuildError, DeviceTablePage, InputEntry, MAX_ASSIGNMENTS,
            MAX_BACKING_PAGES, TABLE_PAGES,
        },
        tables::{
            BasicInterruptTable, CompleteHostDeviceEntry, DteInterruptPolicy, EncodingError,
            HostDeviceEntry, Permissions,
        },
    },
};

const BASE: u64 = 0x1234_5000;
const ROOT: u64 = 0x2345_6000;

fn policy(bits: u8) -> AddressPolicy {
    AddressPolicy::new(bits, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

fn entry(root: u64, domain: u16, permissions: Permissions) -> CompleteHostDeviceEntry {
    CompleteHostDeviceEntry::new(
        policy(52),
        HostDeviceEntry::new(policy(52), root, domain, permissions).unwrap(),
        DteInterruptPolicy::AbortControlled,
    )
    .unwrap()
}

fn default_entry() -> CompleteHostDeviceEntry {
    entry(ROOT, 0x1234, Permissions::None)
}

fn remapped(root: u64, domain: u16, interrupt_root: u64) -> CompleteHostDeviceEntry {
    CompleteHostDeviceEntry::new(
        policy(52),
        HostDeviceEntry::new(policy(52), root, domain, Permissions::None).unwrap(),
        DteInterruptPolicy::RemapBasic(
            BasicInterruptTable::new(policy(52), interrupt_root, 512).unwrap(),
        ),
    )
    .unwrap()
}

fn storage(count: usize) -> Vec<DeviceTablePage> {
    // Seed nonzero words without exposing a mutable raw-page API. Each page
    // contains a complete, previously built pattern, including spare capacity.
    let mut seed = vec![DeviceTablePage::ZERO; 512];
    device_table::build(policy(52), BASE, &mut seed, default_entry(), &[]).unwrap();
    vec![seed[0].clone(); count]
}

fn assert_unchanged(
    policy: AddressPolicy,
    base: u64,
    storage: &mut [DeviceTablePage],
    default: CompleteHostDeviceEntry,
    assignments: &[Assignment],
    expected: BuildError,
) {
    let before = storage.to_vec();
    assert_eq!(
        device_table::build(policy, base, storage, default, assignments).unwrap_err(),
        expected
    );
    assert_eq!(storage, before.as_slice());
}

#[test]
fn physical_layout_and_full_size_register_are_exact() {
    assert_eq!(core::mem::size_of::<DeviceTablePage>(), 4096);
    assert_eq!(core::mem::align_of::<DeviceTablePage>(), 4096);
    assert_eq!(device_table::ENTRY_COUNT, 65_536);
    assert_eq!(device_table::ENTRY_BYTES, 32);
    assert_eq!(device_table::ENTRIES_PER_PAGE, 128);
    assert_eq!(device_table::TABLE_BYTES, 0x20_0000);
    assert_eq!(TABLE_PAGES, 512);
    let mut storage = storage(512);
    let image = device_table::build(policy(52), BASE, &mut storage, default_entry(), &[]).unwrap();
    assert_eq!(image.pages().len(), 512);
    assert_eq!(image.table_range().base(), BASE);
    assert_eq!(image.table_range().len(), 0x20_0000);
    assert_eq!(image.table_range().last_byte(), BASE + 0x1f_ffff);
    assert_eq!(image.backing_range(), image.table_range());
    // The 4 KiB-aligned BASE is deliberately not 2 MiB-aligned. Reserved
    // register bits 11:9 and 63:52 stay clear; Size is linear pages minus one.
    assert_eq!(image.base_register_value(), 0x1234_51ff);
    assert_eq!(image.base_register_value() & 0xfff, 511);
    assert_eq!(((image.base_register_value() & 511) + 1) * 4096, 2_097_152);
    let start = image.pages().as_ptr() as usize;
    for (index, page) in image.pages().iter().enumerate() {
        assert_eq!(page as *const DeviceTablePage as usize, start + index * 4096);
        assert_eq!(page.words().as_ptr() as usize, start + index * 4096);
    }
}

#[test]
fn every_default_word_is_an_explicit_non_passthrough_entry() {
    let mut storage = vec![DeviceTablePage::ZERO; 512];
    let image = device_table::build(policy(52), BASE, &mut storage, default_entry(), &[]).unwrap();
    let expected = [0x2345_6803, 0x1234, 1, 0];
    for device in 0..65_536usize {
        let raw = image.pages()[device / 128].words();
        for word in 0..4 {
            assert_eq!(raw[(device % 128) * 4 + word], expected[word], "{device:04x}/{word}");
        }
        assert_eq!(image.entry_words(device as u16), expected);
    }
}

#[test]
fn independent_range_oracle_checks_all_words_at_page_bus_and_requester_boundaries() {
    let ranges = [
        Assignment { first: 0, last: 0, entry: entry(0x1000, 1, Permissions::Read) },
        Assignment { first: 127, last: 128, entry: entry(0x2000, 2, Permissions::Write) },
        Assignment { first: 129, last: 255, entry: entry(0x2000, 2, Permissions::ReadWrite) },
        Assignment { first: 256, last: 256, entry: remapped(0x3000, 3, 0x3456_7880) },
        Assignment { first: 32767, last: 32768, entry: entry(0x4000, 4, Permissions::None) },
        Assignment { first: 65534, last: 65535, entry: entry(0x5000, 5, Permissions::ReadWrite) },
    ];
    let mut storage = storage(514);
    let before_spare = storage[512..].to_vec();
    let image =
        device_table::build(policy(48), BASE, &mut storage, default_entry(), &ranges).unwrap();
    assert_eq!(image.table_range().len(), 2_097_152);
    assert_eq!(image.backing_range().len(), 2_105_344);
    assert_eq!(image.base_register_value(), 0x1234_51ff);
    for device in 0..65_536usize {
        // Literal bit placements and independent DeviceID predicates, without
        // calling the entry encoders/decoders or searching the input ranges.
        let expected = match device {
            0 => [0x2000_0000_0000_1803, 1, 1, 0],
            127..=128 => [0x4000_0000_0000_2803, 2, 1, 0],
            129..=255 => [0x6000_0000_0000_2803, 2, 1, 0],
            256 => [0x3803, 3, 0x2000_0000_3456_7893, 0],
            32767..=32768 => [0x4803, 4, 1, 0],
            65534..=65535 => [0x6000_0000_0000_5803, 5, 1, 0],
            _ => [0x2345_6803, 0x1234, 1, 0],
        };
        for word in 0..4 {
            let actual = image.pages()[device / 128].words()[(device % 128) * 4 + word];
            assert_eq!(actual, expected[word], "{device:04x}/{word}");
        }
        assert_eq!(image.entry_words(device as u16), expected);
    }
    assert_eq!(&storage[512..], before_spare.as_slice());
}

#[test]
fn a_fully_overridden_default_is_validated_but_not_an_emitted_domain() {
    let ranges = [
        Assignment { first: 0, last: 32767, entry: entry(0x1000, 0x1234, Permissions::Read) },
        Assignment { first: 32768, last: 65535, entry: entry(0x1000, 0x1234, Permissions::Write) },
    ];
    let mut storage = storage(512);
    let image =
        device_table::build(policy(52), BASE, &mut storage, default_entry(), &ranges).unwrap();
    for device in 0..65_536usize {
        let first = if device < 32768 { 0x2000_0000_0000_1803 } else { 0x4000_0000_0000_1803 };
        let expected = [first, 0x1234, 1, 0];
        for word in 0..4 {
            assert_eq!(
                image.pages()[device / 128].words()[(device % 128) * 4 + word],
                expected[word]
            );
        }
    }
    assert_unchanged(
        policy(32),
        BASE,
        &mut storage,
        entry(1 << 32, 0, Permissions::None),
        &ranges,
        BuildError::Encoding {
            input: InputEntry::Default,
            error: EncodingError::Address(AddressError::OutsidePhysicalWidth),
        },
    );
}

#[test]
fn default_permissions_and_interrupt_remapping_are_refused_transactionally() {
    let mut storage = storage(513);
    let ranges = [Assignment { first: 0, last: 65535, entry: default_entry() }];
    for permissions in [Permissions::Read, Permissions::Write, Permissions::ReadWrite] {
        assert_unchanged(
            policy(52),
            BASE,
            &mut storage,
            entry(ROOT, 0x1234, permissions),
            &ranges,
            BuildError::DefaultAllowsDma,
        );
    }
    assert_unchanged(
        policy(52),
        BASE,
        &mut storage,
        remapped(ROOT, 0x1234, 0x4567_8000),
        &ranges,
        BuildError::DefaultRemapsInterrupts,
    );
}

#[test]
fn reversed_overlapping_duplicate_and_unsorted_ranges_leave_all_storage_unchanged() {
    let mut storage = storage(513);
    let range = |first, last| Assignment { first, last, entry: default_entry() };
    for (ranges, error) in [
        (vec![range(1, 0)], BuildError::ReversedAssignment { assignment: 0 }),
        (vec![range(65535, 0)], BuildError::ReversedAssignment { assignment: 0 }),
        (vec![range(10, 20), range(20, 30)], BuildError::UnsortedOrOverlapping { assignment: 1 }),
        (vec![range(10, 20), range(10, 20)], BuildError::UnsortedOrOverlapping { assignment: 1 }),
        (vec![range(10, 20), range(0, 9)], BuildError::UnsortedOrOverlapping { assignment: 1 }),
        (
            vec![range(65535, 65535), range(0, 0)],
            BuildError::UnsortedOrOverlapping { assignment: 1 },
        ),
    ] {
        assert_unchanged(policy(52), BASE, &mut storage, default_entry(), &ranges, error);
    }
}

#[test]
fn domain_consistency_checks_defaults_and_nonadjacent_overrides() {
    let mut storage = storage(512);
    assert_unchanged(
        policy(52),
        BASE,
        &mut storage,
        default_entry(),
        &[Assignment { first: 0, last: 65534, entry: entry(0x1000, 0x1234, Permissions::None) }],
        BuildError::InconsistentDomain {
            first: InputEntry::Default,
            second: InputEntry::Assignment(0),
            domain_id: 0x1234,
        },
    );
    let ranges = [
        Assignment { first: 0, last: 0, entry: entry(0x1000, 1, Permissions::None) },
        Assignment { first: 1, last: 1, entry: entry(0x2000, 2, Permissions::None) },
        Assignment { first: 65535, last: 65535, entry: entry(0x3000, 1, Permissions::None) },
    ];
    assert_unchanged(
        policy(52),
        BASE,
        &mut storage,
        default_entry(),
        &ranges,
        BuildError::InconsistentDomain {
            first: InputEntry::Assignment(0),
            second: InputEntry::Assignment(2),
            domain_id: 1,
        },
    );
}

#[test]
fn bounds_refuse_insufficient_or_excess_capacity_and_too_many_ranges() {
    for count in [0, 1, 511, MAX_BACKING_PAGES + 1] {
        let mut storage = storage(count);
        let expected = if count > MAX_BACKING_PAGES {
            BuildError::TooManyBackingPages
        } else {
            BuildError::InsufficientCapacity { available: count }
        };
        assert_unchanged(policy(52), BASE, &mut storage, default_entry(), &[], expected);
    }
    let mut storage = storage(512);
    let ranges =
        vec![Assignment { first: 0, last: 0, entry: default_entry() }; MAX_ASSIGNMENTS + 1];
    assert_unchanged(
        policy(52),
        BASE,
        &mut storage,
        default_entry(),
        &ranges,
        BuildError::TooManyAssignments,
    );
}

#[test]
fn numeric_backing_rejects_misalignment_overflow_and_last_byte_width_crossing() {
    let mut storage = storage(512);
    for (base, bits, error) in [
        (BASE + 1, 52, AddressError::Misaligned),
        (u64::MAX - 0xfff, 52, AddressError::Overflow),
        ((1 << 32) - 0x1f_f000, 32, AddressError::OutsidePhysicalWidth),
        ((1 << 52) - 0x1f_f000, 52, AddressError::OutsidePhysicalWidth),
    ] {
        assert_unchanged(
            policy(bits),
            base,
            &mut storage,
            default_entry(),
            &[],
            BuildError::BackingAddress(error),
        );
    }
    let image =
        device_table::build(policy(32), (1 << 32) - 0x20_0000, &mut storage, default_entry(), &[])
            .unwrap();
    assert_eq!(image.table_range().last_byte(), 0xffff_ffff);
    assert_eq!(image.base_register_value(), 0xffe0_01ff);
}

#[test]
fn unused_capacity_is_included_in_width_and_encryption_checks() {
    let mut storage = storage(513);
    // The 512 used pages fit exactly; only the spare page crosses the boundary.
    assert_unchanged(
        policy(32),
        (1 << 32) - 0x20_0000,
        &mut storage,
        default_entry(),
        &[],
        BuildError::BackingAddress(AddressError::OutsidePhysicalWidth),
    );
    let encrypted =
        AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: Some(32) }).unwrap();
    assert_unchanged(
        encrypted,
        (1 << 32) - 0x20_0000,
        &mut storage,
        default_entry(),
        &[],
        BuildError::BackingAddress(AddressError::EncryptionBitEncoded),
    );
    // Same clear bit at both endpoints, but an interior encryption-bit cycle.
    let low_bit =
        AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: Some(20) }).unwrap();
    assert_unchanged(
        low_bit,
        0,
        &mut storage,
        default_entry(),
        &[],
        BuildError::BackingAddress(AddressError::EncryptionBitEncoded),
    );
}

#[test]
fn current_policy_revalidates_every_override_and_the_whole_interrupt_extent() {
    let mut storage = storage(513);
    let valid = Assignment { first: 0, last: 0, entry: entry(0x1000, 1, Permissions::Read) };
    for invalid in [
        entry(1 << 32, 2, Permissions::None),
        // Interrupt root is below 2^32, but its 2,048-byte extent crosses it.
        remapped(0x2000, 2, (1 << 32) - 128),
    ] {
        let ranges = [valid, Assignment { first: 65535, last: 65535, entry: invalid }];
        assert_unchanged(
            policy(32),
            BASE,
            &mut storage,
            default_entry(),
            &ranges,
            BuildError::Encoding {
                input: InputEntry::Assignment(1),
                error: EncodingError::Address(AddressError::OutsidePhysicalWidth),
            },
        );
        let encrypted =
            AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: Some(32) })
                .unwrap();
        assert_unchanged(
            encrypted,
            BASE,
            &mut storage,
            default_entry(),
            &ranges,
            BuildError::Encoding {
                input: InputEntry::Assignment(1),
                error: EncodingError::Address(AddressError::EncryptionBitEncoded),
            },
        );
    }
}

#[test]
fn maximum_bounds_emit_all_words_and_preserve_all_spare_pages() {
    let mut storage = storage(MAX_BACKING_PAGES);
    let before_spare = storage[512..].to_vec();
    let ranges: Vec<_> = (0..MAX_ASSIGNMENTS)
        .map(|index| Assignment {
            first: (index * 16) as u16,
            last: (index * 16 + 15) as u16,
            entry: entry(0x1000 + index as u64 * 4096, index as u16, Permissions::Read),
        })
        .collect();
    let image =
        device_table::build(policy(52), BASE, &mut storage, default_entry(), &ranges).unwrap();
    assert_eq!(image.backing_range().len(), 4_194_304);
    assert_eq!(image.base_register_value(), 0x1234_51ff);
    for device in 0..65_536usize {
        let domain = device / 16;
        let expected = [0x2000_0000_0000_1803 + domain as u64 * 4096, domain as u64, 1, 0];
        for word in 0..4 {
            assert_eq!(
                image.pages()[device / 128].words()[(device % 128) * 4 + word],
                expected[word]
            );
        }
    }
    assert_eq!(&storage[512..], before_spare.as_slice());
}
