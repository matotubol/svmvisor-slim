use super::*;
use crate::memory::address::EncryptionState;
use crate::memory::iommu::host_walk::{HostTranslation, walk};
use crate::memory::iommu::tables::HostDeviceEntry;

const PAGE: u64 = PAGE_BYTES as u64;
const BACKING: u64 = 0x0010_0000;
const RW: Permissions = Permissions::ReadWrite;

fn policy() -> AddressPolicy {
    AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

fn mapping(io_base: u64, system_base: u64, len: u64) -> MappingRange {
    MappingRange { io_base, system_base, len, permissions: RW, coherency: PageCoherency::Inherit }
}

fn dirty<const N: usize>() -> [TablePage; N] {
    core::array::from_fn(|index| TablePage {
        words: [0xaa00_0000_0000_0000 | index as u64; WORDS_PER_PAGE],
    })
}

fn translate(image: &HostPageTableImage<'_>, address: u64) -> Option<HostTranslation> {
    let device = HostDeviceEntry::new(policy(), image.root_address(), 7, RW).unwrap();
    walk(policy(), device, address, |address| image.read_word(address).ok_or(())).unwrap()
}

fn unchanged(
    address_policy: AddressPolicy,
    backing_base: u64,
    mappings: &[MappingRange],
    protected: &[ProtectedRange],
    expected: BuildError,
) {
    let mut storage = dirty::<4>();
    let before = storage.clone();
    assert_eq!(
        build(address_policy, backing_base, &mut storage, mappings, protected).err(),
        Some(expected)
    );
    assert_eq!(storage, before);
}

#[test]
fn actual_words_match_manual_layout_and_walk_each_nonzero_index() {
    let io = (0x101 << 39) | (0x82 << 30) | (0x43 << 21) | (0x24 << 12);
    let mappings = [MappingRange {
        coherency: PageCoherency::ForceCoherent,
        ..mapping(io, 0x1234_5000, PAGE)
    }];
    let mut storage = dirty::<4>();
    let image = build(policy(), BACKING, &mut storage, &mappings, &[]).unwrap();
    assert_eq!(image.root_address(), BACKING);
    assert_eq!(image.pages().len(), 4);
    // Independent literals: IR/IW at 61/62, FC at 60, NextLevel at 11:9, PR at 0.
    let expected = [
        (0x101, 0x6000_0000_0010_1601),
        (0x82, 0x6000_0000_0010_2401),
        (0x43, 0x6000_0000_0010_3201),
        (0x24, 0x7000_0000_1234_5001),
    ];
    for (page, (index, word)) in image.pages().iter().zip(expected) {
        for (slot, actual) in page.words().iter().enumerate() {
            assert_eq!(*actual, if slot == index { word } else { 0 });
        }
    }
    for offset in [0, 0xabc, PAGE - 1] {
        assert_eq!(
            translate(&image, io + offset),
            Some(HostTranslation {
                system_address: 0x1234_5000 + offset,
                permissions: RW,
                coherency: PageCoherency::ForceCoherent,
            })
        );
    }
    for absent in [0, io - 1, io + PAGE, (1 << 48) - 1] {
        assert_eq!(translate(&image, absent), None);
    }
}

#[test]
fn all_permission_and_coherency_choices_survive_shared_directories() {
    let permissions = [Permissions::None, Permissions::Read, Permissions::Write, RW];
    let mappings: [MappingRange; 8] = core::array::from_fn(|index| MappingRange {
        permissions: permissions[index / 2],
        coherency: if index % 2 == 0 {
            PageCoherency::Inherit
        } else {
            PageCoherency::ForceCoherent
        },
        ..mapping(index as u64 * PAGE, 0x0020_0000 + index as u64 * PAGE, PAGE)
    });
    let mut storage = dirty::<4>();
    let image = build(policy(), BACKING, &mut storage, &mappings, &[]).unwrap();
    for (index, mapping) in mappings.iter().enumerate() {
        let translation = translate(&image, mapping.io_base + PAGE - 1).unwrap();
        assert_eq!(translation.system_address, mapping.system_base + PAGE - 1);
        assert_eq!(translation.permissions, mapping.permissions);
        assert_eq!(translation.coherency, mapping.coherency);
        let ir = u64::from(mapping.permissions.allows_read()) << 61;
        let iw = u64::from(mapping.permissions.allows_write()) << 62;
        let fc = u64::from(mapping.coherency == PageCoherency::ForceCoherent) << 60;
        assert_eq!(image.pages()[3].words()[index], mapping.system_base | ir | iw | fc | 1);
    }
}

#[test]
fn empty_mappings_emit_one_absent_root_and_preserve_unused_pages() {
    let mut storage = dirty::<5>();
    let before = storage.clone();
    let image = build(policy(), BACKING, &mut storage, &[], &[]).unwrap();
    assert_eq!(image.pages().len(), 1);
    assert!(image.pages()[0].words().iter().all(|word| *word == 0));
    assert_eq!(image.backing_range().base(), BACKING);
    assert_eq!(image.backing_range().len(), 5 * PAGE);
    for io in [0, PAGE - 1, 1 << 47, (1 << 48) - 1] {
        assert_eq!(translate(&image, io), None);
    }
    assert_eq!(&storage[1..], &before[1..]);
}

#[test]
fn snapshot_lookup_rejects_misalignment_overflow_and_unused_capacity() {
    let mut storage = dirty::<5>();
    let before = storage.clone();
    let image = build(policy(), BACKING, &mut storage, &[mapping(0, 0, PAGE)], &[]).unwrap();
    assert_eq!(image.read_word(BACKING), Some(0x6000_0000_0010_1601));
    assert_eq!(image.read_word(BACKING + 4 * PAGE - 8), Some(0));
    for address in [
        0,
        BACKING - 8,
        BACKING + 1,
        BACKING + 4 * PAGE,
        BACKING + 5 * PAGE,
        u64::MAX - 7,
        u64::MAX,
    ] {
        assert_eq!(image.read_word(address), None);
    }
    assert_eq!(&storage[4..], &before[4..]);
}

#[test]
fn crossed_directory_boundaries_have_exact_capacity_and_walk_both_edges() {
    for (shift, required) in [(21, 5), (30, 6), (39, 7)] {
        let boundary = 1u64 << shift;
        let mappings = [mapping(boundary - PAGE, 0x0020_0000, 2 * PAGE)];
        let mut storage = dirty::<7>();
        let before = storage.clone();
        assert_eq!(
            build(policy(), BACKING, &mut storage[..required - 1], &mappings, &[]).err(),
            Some(BuildError::InsufficientCapacity {
                required: required as u64,
                available: required - 1,
            })
        );
        assert_eq!(storage, before);
        let image = build(policy(), BACKING, &mut storage[..required], &mappings, &[]).unwrap();
        assert_eq!(image.pages().len(), required);
        for offset in [0, PAGE - 1, PAGE, 2 * PAGE - 1] {
            assert_eq!(
                translate(&image, boundary - PAGE + offset).unwrap().system_address,
                0x0020_0000 + offset
            );
        }
        assert_eq!(translate(&image, boundary - PAGE - 1), None);
        assert_eq!(translate(&image, boundary + PAGE), None);
    }
}

#[test]
fn first_and_last_io_and_physical_pages_are_legal() {
    let mappings = [mapping(0, 0, PAGE), mapping((1 << 48) - PAGE, (1 << 52) - PAGE, PAGE)];
    let mut storage = dirty::<7>();
    let image = build(policy(), BACKING, &mut storage, &mappings, &[]).unwrap();
    assert_eq!(image.pages().len(), 7);
    assert_eq!(translate(&image, 0).unwrap().system_address, 0);
    assert_eq!(translate(&image, PAGE - 1).unwrap().system_address, PAGE - 1);
    assert_eq!(translate(&image, (1 << 48) - PAGE).unwrap().system_address, (1 << 52) - PAGE);
    assert_eq!(translate(&image, (1 << 48) - 1).unwrap().system_address, (1 << 52) - 1);
    assert_eq!(translate(&image, PAGE), None);
    assert_eq!(translate(&image, (1 << 48) - PAGE - 1), None);
}

#[test]
fn unprotected_physical_aliases_keep_independent_leaf_attributes() {
    let mappings = [
        mapping(0, 0x0020_0000, PAGE),
        MappingRange {
            permissions: Permissions::Read,
            coherency: PageCoherency::ForceCoherent,
            ..mapping(1 << 47, 0x0020_0000, PAGE)
        },
    ];
    let mut storage = dirty::<7>();
    let image = build(policy(), BACKING, &mut storage, &mappings, &[]).unwrap();
    for mapping in mappings {
        let result = translate(&image, mapping.io_base + 17).unwrap();
        assert_eq!(result.system_address, 0x0020_0011);
        assert_eq!(result.permissions, mapping.permissions);
        assert_eq!(result.coherency, mapping.coherency);
    }
}

#[test]
fn protected_outputs_are_rejected_through_every_dva_alias_even_with_no_permissions() {
    let protected = [ProtectedRange { base: 0x0020_0000, len: 2 * PAGE }];
    for io in [0, 0x0020_0000, 1 << 47, (1 << 48) - PAGE] {
        for permissions in [Permissions::None, Permissions::Read, Permissions::Write, RW] {
            for physical in [protected[0].base, protected[0].base + PAGE] {
                unchanged(
                    policy(),
                    BACKING,
                    &[MappingRange { permissions, ..mapping(io, physical, PAGE) }],
                    &protected,
                    BuildError::ProtectedOutput { mapping: 0, protected: 0 },
                );
            }
        }
    }
    for (base, len) in [(0x001f_f000, 2 * PAGE), (0x0020_1000, 2 * PAGE), (0x001f_f000, 4 * PAGE)] {
        unchanged(
            policy(),
            BACKING,
            &[mapping(0, base, len)],
            &protected,
            BuildError::ProtectedOutput { mapping: 0, protected: 0 },
        );
    }
}

#[test]
fn every_assigned_backing_page_is_excluded_including_unused_capacity() {
    for io in [0, BACKING, 1 << 47] {
        for page in 0..6 {
            let mut storage = dirty::<6>();
            let before = storage.clone();
            let mappings = [MappingRange {
                permissions: Permissions::None,
                ..mapping(io, BACKING + page * PAGE, PAGE)
            }];
            assert_eq!(
                build(policy(), BACKING, &mut storage, &mappings, &[]).err(),
                Some(BuildError::TableBackingOutput { mapping: 0 })
            );
            assert_eq!(storage, before);
        }
    }
    unchanged(
        policy(),
        BACKING,
        &[mapping(0, BACKING - PAGE, 2 * PAGE)],
        &[],
        BuildError::TableBackingOutput { mapping: 0 },
    );
    unchanged(
        policy(),
        BACKING,
        &[mapping(0, BACKING - PAGE, 6 * PAGE)],
        &[],
        BuildError::TableBackingOutput { mapping: 0 },
    );
}

#[test]
fn adjacent_outputs_do_not_intersect_protection_or_backing() {
    let protected = [ProtectedRange { base: 0x0020_0000, len: 2 * PAGE }];
    let mappings = [
        mapping(0, BACKING - PAGE, PAGE),
        mapping(PAGE, BACKING + 4 * PAGE, PAGE),
        mapping(2 * PAGE, protected[0].base - PAGE, PAGE),
        mapping(3 * PAGE, protected[0].base + protected[0].len, PAGE),
    ];
    let mut storage = dirty::<4>();
    let image = build(policy(), BACKING, &mut storage, &mappings, &protected).unwrap();
    for mapping in mappings {
        assert_eq!(translate(&image, mapping.io_base).unwrap().system_address, mapping.system_base);
    }
}

#[test]
fn invalid_mapping_ranges_leave_all_backing_unchanged() {
    let cases = [
        (
            mapping(0, 0, 0),
            BuildError::Address {
                range: InputRange::MappingIo(0),
                error: AddressError::EmptyRange,
            },
        ),
        (
            mapping(1, 0, PAGE),
            BuildError::Address {
                range: InputRange::MappingIo(0),
                error: AddressError::Misaligned,
            },
        ),
        (
            mapping(0, 1, PAGE),
            BuildError::Address {
                range: InputRange::MappingSystem(0),
                error: AddressError::Misaligned,
            },
        ),
        (mapping(0, 0, PAGE + 1), BuildError::LengthNotPageAligned(InputRange::MappingIo(0))),
        (
            mapping(u64::MAX - PAGE + 1, 0, 2 * PAGE),
            BuildError::Address { range: InputRange::MappingIo(0), error: AddressError::Overflow },
        ),
        (
            mapping(0, u64::MAX - PAGE + 1, 2 * PAGE),
            BuildError::Address {
                range: InputRange::MappingSystem(0),
                error: AddressError::Overflow,
            },
        ),
        (mapping(1 << 48, 0, PAGE), BuildError::IoAddressOutsideWidth { mapping: 0 }),
        (mapping((1 << 48) - PAGE, 0, 2 * PAGE), BuildError::IoAddressOutsideWidth { mapping: 0 }),
        (mapping(0xffff_8000_0000_0000, 0, PAGE), BuildError::IoAddressOutsideWidth { mapping: 0 }),
        (
            mapping(0, 1 << 52, PAGE),
            BuildError::Address {
                range: InputRange::MappingSystem(0),
                error: AddressError::OutsidePhysicalWidth,
            },
        ),
        (
            mapping(0, (1 << 52) - PAGE, 2 * PAGE),
            BuildError::Address {
                range: InputRange::MappingSystem(0),
                error: AddressError::OutsidePhysicalWidth,
            },
        ),
    ];
    for (mapping, error) in cases {
        unchanged(policy(), BACKING, &[mapping], &[], error);
    }
}

#[test]
fn unsorted_duplicate_or_overlapping_dva_ranges_are_transactional_failures() {
    for mappings in [
        [mapping(PAGE, 0, PAGE), mapping(0, PAGE, PAGE)],
        [mapping(0, 0, PAGE), mapping(0, PAGE, PAGE)],
        [mapping(0, 0, 2 * PAGE), mapping(PAGE, 3 * PAGE, PAGE)],
    ] {
        unchanged(
            policy(),
            BACKING,
            &mappings,
            &[],
            BuildError::UnsortedOrOverlapping(InputRange::MappingIo(1)),
        );
    }
    unchanged(
        policy(),
        BACKING,
        &[mapping(0, 0, PAGE), mapping(PAGE, 1, PAGE)],
        &[],
        BuildError::Address {
            range: InputRange::MappingSystem(1),
            error: AddressError::Misaligned,
        },
    );
}

#[test]
fn every_protected_range_is_validated_before_output_is_touched() {
    let mappings = [mapping(0, 0, PAGE)];
    for (range, expected) in [
        (
            ProtectedRange { base: PAGE, len: 0 },
            BuildError::Address {
                range: InputRange::Protected(0),
                error: AddressError::EmptyRange,
            },
        ),
        (
            ProtectedRange { base: PAGE + 1, len: PAGE },
            BuildError::Address {
                range: InputRange::Protected(0),
                error: AddressError::Misaligned,
            },
        ),
        (
            ProtectedRange { base: PAGE, len: PAGE + 1 },
            BuildError::LengthNotPageAligned(InputRange::Protected(0)),
        ),
        (
            ProtectedRange { base: u64::MAX - PAGE + 1, len: 2 * PAGE },
            BuildError::Address { range: InputRange::Protected(0), error: AddressError::Overflow },
        ),
        (
            ProtectedRange { base: (1 << 52) - PAGE, len: 2 * PAGE },
            BuildError::Address {
                range: InputRange::Protected(0),
                error: AddressError::OutsidePhysicalWidth,
            },
        ),
    ] {
        unchanged(policy(), BACKING, &mappings, &[range], expected);
    }
    for ranges in [
        [
            ProtectedRange { base: 3 * PAGE, len: PAGE },
            ProtectedRange { base: 2 * PAGE, len: PAGE },
        ],
        [
            ProtectedRange { base: 2 * PAGE, len: PAGE },
            ProtectedRange { base: 2 * PAGE, len: PAGE },
        ],
        [
            ProtectedRange { base: 2 * PAGE, len: 2 * PAGE },
            ProtectedRange { base: 3 * PAGE, len: PAGE },
        ],
    ] {
        unchanged(
            policy(),
            BACKING,
            &mappings,
            &ranges,
            BuildError::UnsortedOrOverlapping(InputRange::Protected(1)),
        );
    }
    unchanged(
        policy(),
        BACKING,
        &mappings,
        &[
            ProtectedRange { base: 2 * PAGE, len: PAGE },
            ProtectedRange { base: 3 * PAGE + 1, len: PAGE },
        ],
        BuildError::Address { range: InputRange::Protected(1), error: AddressError::Misaligned },
    );
}

#[test]
fn protected_lookup_handles_gaps_and_reports_the_first_intersection() {
    let protected = [
        ProtectedRange { base: 4 * PAGE, len: PAGE },
        ProtectedRange { base: 8 * PAGE, len: PAGE },
        ProtectedRange { base: 12 * PAGE, len: 2 * PAGE },
    ];
    for (index, range) in protected.iter().enumerate() {
        unchanged(
            policy(),
            BACKING,
            &[mapping(0, range.base, PAGE)],
            &protected,
            BuildError::ProtectedOutput { mapping: 0, protected: index },
        );
    }
    unchanged(
        policy(),
        BACKING,
        &[mapping(0, 7 * PAGE, 8 * PAGE)],
        &protected,
        BuildError::ProtectedOutput { mapping: 0, protected: 1 },
    );
    let mut storage = dirty::<4>();
    let mappings = [
        mapping(0, 0, 4 * PAGE),
        mapping(4 * PAGE, 5 * PAGE, 3 * PAGE),
        mapping(7 * PAGE, 14 * PAGE, PAGE),
    ];
    build(policy(), BACKING, &mut storage, &mappings, &protected).unwrap();
}

#[test]
fn whole_backing_and_output_ranges_obey_width_and_encryption_policy() {
    for (base, error) in [
        (BACKING + 1, AddressError::Misaligned),
        ((1 << 52) - 3 * PAGE, AddressError::OutsidePhysicalWidth),
        (u64::MAX - PAGE + 1, AddressError::Overflow),
    ] {
        unchanged(
            policy(),
            base,
            &[],
            &[],
            BuildError::Address { range: InputRange::Backing, error },
        );
    }
    let encrypted =
        AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: Some(20) }).unwrap();
    unchanged(
        encrypted,
        BACKING,
        &[],
        &[],
        BuildError::Address {
            range: InputRange::Backing,
            error: AddressError::EncryptionBitEncoded,
        },
    );
    unchanged(
        encrypted,
        0x8000,
        &[mapping(0, (1 << 20) - PAGE, 2 * PAGE)],
        &[],
        BuildError::Address {
            range: InputRange::MappingSystem(0),
            error: AddressError::EncryptionBitEncoded,
        },
    );
    // Both endpoints have encryption bit 20 clear, but the interior sets it.
    unchanged(
        encrypted,
        0x8000,
        &[mapping(0, 2 << 20, (2 << 20) + PAGE)],
        &[],
        BuildError::Address {
            range: InputRange::MappingSystem(0),
            error: AddressError::EncryptionBitEncoded,
        },
    );
    unchanged(
        encrypted,
        0x8000,
        &[],
        &[ProtectedRange { base: 1 << 20, len: PAGE }],
        BuildError::Address {
            range: InputRange::Protected(0),
            error: AddressError::EncryptionBitEncoded,
        },
    );
}

#[test]
fn zero_insufficient_and_exact_capacity_are_distinguished_before_writes() {
    let mut none = [];
    assert_eq!(
        build(policy(), 0, &mut none, &[], &[]).err(),
        Some(BuildError::InsufficientCapacity { required: 1, available: 0 })
    );
    assert_eq!(
        build(policy(), 0, &mut none, &[mapping(0, PAGE, PAGE)], &[]).err(),
        Some(BuildError::InsufficientCapacity { required: 4, available: 0 })
    );
    let mut storage = dirty::<4>();
    let before = storage.clone();
    assert_eq!(
        build(policy(), BACKING, &mut storage[..3], &[mapping(0, 0, PAGE)], &[]).err(),
        Some(BuildError::InsufficientCapacity { required: 4, available: 3 })
    );
    assert_eq!(storage, before);
    build(policy(), BACKING, &mut storage, &[mapping(0, 0, PAGE)], &[]).unwrap();
}

#[test]
fn large_ranges_are_sized_arithmetically_without_emission_or_large_buffers() {
    // 32 GiB requires 16,384 L1 + 32 L2 + 1 L3 + 1 root pages.
    unchanged(
        policy(),
        1 << 40,
        &[mapping(0, 0, 32 << 30)],
        &[],
        BuildError::InsufficientCapacity { required: 16_418, available: 4 },
    );
    // The full 48-bit DVA space: 2^27 + 2^18 + 2^9 + one root.
    unchanged(
        policy(),
        BACKING,
        &[mapping(0, 1 << 48, 1 << 48)],
        &[],
        BuildError::InsufficientCapacity { required: 134_480_385, available: 4 },
    );
}

#[test]
fn explicit_resource_limits_refuse_work_before_any_output_mutation() {
    let mappings = [mapping(0, 0, PAGE); MAX_MAPPING_RANGES + 1];
    unchanged(policy(), BACKING, &mappings, &[], BuildError::LimitExceeded(Limit::MappingRanges));
    let protected = [ProtectedRange { base: 0, len: PAGE }; MAX_PROTECTED_RANGES + 1];
    unchanged(
        policy(),
        BACKING,
        &[],
        &protected,
        BuildError::LimitExceeded(Limit::ProtectedRanges),
    );
    // Capacity is checked as a count before storage is accessed. No 128 MiB
    // allocation is needed to exercise rejection of an oversized table span.
    assert_eq!(
        prepare(policy(), BACKING, MAX_TABLE_PAGES + 1, &[], &[]).err(),
        Some(BuildError::LimitExceeded(Limit::TablePages))
    );
}

#[test]
fn numeric_zero_root_is_legal_but_its_entire_assigned_span_is_excluded() {
    let mut storage = dirty::<4>();
    let image = build(policy(), 0, &mut storage, &[mapping(0, BACKING, PAGE)], &[]).unwrap();
    assert_eq!(image.root_address(), 0);
    assert_eq!(translate(&image, 0).unwrap().system_address, BACKING);
    unchanged(
        policy(),
        0,
        &[mapping(1 << 47, 0, PAGE)],
        &[],
        BuildError::TableBackingOutput { mapping: 0 },
    );
}
