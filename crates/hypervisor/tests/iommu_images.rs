//! Cross-check generated immutable images through the independent host walker.
//! These tests exercise numeric snapshots only; no device or physical access.
use std::collections::BTreeSet;

use svmvisor_hypervisor::memory::{
    address::{AddressPolicy, EncryptionState},
    iommu::{
        host_walk::{self, WalkError},
        image::{self, BuildError, MappingRange, ProtectedRange, TablePage},
        tables::{HostDeviceEntry, PageCoherency, Permissions},
    },
};

const PAGE: u64 = 4096;
const BACKING: u64 = 1 << 40;

fn policy() -> AddressPolicy {
    AddressPolicy::new(52, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

#[test]
fn sparse_images_walk_across_every_directory_boundary_and_the_top_dva_page() {
    let ranges = [
        (0, 2, Permissions::None),
        ((1 << 21) - PAGE, 3, Permissions::Read),
        ((1 << 30) - PAGE, 3, Permissions::Write),
        ((1 << 39) - PAGE, 3, Permissions::ReadWrite),
        ((1 << 48) - 2 * PAGE, 2, Permissions::ReadWrite),
    ];
    let mappings: Vec<_> = ranges
        .into_iter()
        .enumerate()
        .map(|(index, (io_base, pages, permissions))| MappingRange {
            io_base,
            system_base: 0x200_0000 + index as u64 * 0x1_0000,
            len: pages * PAGE,
            permissions,
            coherency: if index % 2 == 0 {
                PageCoherency::Inherit
            } else {
                PageCoherency::ForceCoherent
            },
        })
        .collect();
    // Enumerate the small expected page set, independently of the builder's
    // range sizing and allocation. Each distinct prefix needs one child table.
    let mut prefixes = BTreeSet::new();
    for mapping in &mappings {
        for offset in (0..mapping.len).step_by(PAGE as usize) {
            for shift in [21, 30, 39] {
                prefixes.insert((shift, (mapping.io_base + offset) >> shift));
            }
        }
    }
    let expected_pages = 1 + prefixes.len();
    let mut storage = vec![TablePage::ZERO; expected_pages + 2];
    let image = image::build(policy(), BACKING, &mut storage, &mappings, &[]).unwrap();
    assert_eq!(image.root_address(), BACKING);
    assert_eq!(image.pages().len(), expected_pages);
    assert_eq!(image.backing_range().len(), (expected_pages as u64 + 2) * PAGE);
    assert_eq!(image.read_word(BACKING + expected_pages as u64 * PAGE), None);
    let device =
        HostDeviceEntry::new(policy(), image.root_address(), 37, Permissions::ReadWrite).unwrap();
    for mapping in &mappings {
        for page in (0..mapping.len).step_by(PAGE as usize) {
            for within in [0, 1, 2048, PAGE - 1] {
                let offset = page + within;
                let mut reads = 0;
                let actual =
                    host_walk::walk(policy(), device, mapping.io_base + offset, |address| {
                        reads += 1;
                        image.read_word(address).ok_or(address)
                    })
                    .unwrap()
                    .unwrap();
                assert_eq!(reads, 4);
                assert_eq!(actual.system_address, mapping.system_base + offset);
                assert_eq!(actual.permissions, mapping.permissions);
                assert_eq!(actual.coherency, mapping.coherency);
            }
        }
    }
    for io in [2 * PAGE, 1 << 20, (1 << 21) + 2 * PAGE, 1 << 38, (1 << 48) - 3 * PAGE] {
        assert_eq!(
            host_walk::walk(policy(), device, io, |address| image
                .read_word(address)
                .ok_or(address)),
            Ok(None)
        );
    }
    assert_eq!(
        host_walk::walk(policy(), device, 1 << 48, |_| -> Result<u64, ()> {
            panic!("an out-of-width DVA must not request any word")
        }),
        Err(WalkError::IoAddressOutsideWidth)
    );
}

#[test]
fn device_permissions_still_restrict_a_generated_writable_leaf() {
    let mapping = MappingRange {
        io_base: 1 << 47,
        system_base: 0x800_0000,
        len: PAGE,
        permissions: Permissions::ReadWrite,
        coherency: PageCoherency::ForceCoherent,
    };
    let mut storage = vec![TablePage::ZERO; 4];
    let image = image::build(policy(), BACKING, &mut storage, &[mapping], &[]).unwrap();
    let device =
        HostDeviceEntry::new(policy(), image.root_address(), 1, Permissions::Read).unwrap();
    let actual = host_walk::walk(policy(), device, mapping.io_base + 31, |address| {
        image.read_word(address).ok_or(address)
    })
    .unwrap()
    .unwrap();
    assert_eq!(actual.system_address, mapping.system_base + 31);
    assert_eq!(actual.permissions, Permissions::Read);
    assert_eq!(actual.coherency, PageCoherency::ForceCoherent);
}

#[test]
fn physical_aliases_work_only_outside_the_protected_output_set() {
    let first = MappingRange {
        io_base: 0,
        system_base: 0x800_0000,
        len: 2 * PAGE,
        permissions: Permissions::ReadWrite,
        coherency: PageCoherency::Inherit,
    };
    let second = MappingRange { io_base: 1 << 39, ..first };
    let mut storage = vec![TablePage::ZERO; 8];
    {
        let image = image::build(policy(), BACKING, &mut storage, &[first, second], &[]).unwrap();
        let device =
            HostDeviceEntry::new(policy(), image.root_address(), 1, Permissions::ReadWrite)
                .unwrap();
        for offset in [0, PAGE - 1, PAGE, 2 * PAGE - 1] {
            for mapping in [first, second] {
                let actual =
                    host_walk::walk(policy(), device, mapping.io_base + offset, |address| {
                        image.read_word(address).ok_or(address)
                    })
                    .unwrap()
                    .unwrap();
                assert_eq!(actual.system_address, first.system_base + offset);
            }
        }
    }
    let previous = storage.clone();
    let protected = [ProtectedRange { base: first.system_base + PAGE, len: PAGE }];
    assert!(matches!(
        image::build(policy(), BACKING, &mut storage, &[first, second], &protected),
        Err(BuildError::ProtectedOutput { mapping: 0, protected: 0 })
    ));
    assert_eq!(storage, previous);
}
