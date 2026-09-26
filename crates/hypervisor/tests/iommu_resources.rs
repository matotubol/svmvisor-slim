//! Inspect the actual retained byte layout independently of the builders.
use std::alloc::{Layout, alloc_zeroed, handle_alloc_error};
use svmvisor_hypervisor::{
    firmware::native::resident::iommu::resources::{
        COMPOSITION_TABLE_OFFSET, COMPOSITION_TABLE_PAGES, CompositionStorage, ResourceError,
        ResourceHeader, ResourceStorage,
    },
    memory::address::{AddressPolicy, EncryptionState},
};

fn policy() -> AddressPolicy {
    AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

fn storage() -> Box<ResourceStorage> {
    let layout = Layout::new::<ResourceStorage>();
    let raw = unsafe { alloc_zeroed(layout) };
    if raw.is_null() {
        handle_alloc_error(layout);
    }
    // All fields are integer words, valid when zero, in aligned heap backing.
    unsafe { Box::from_raw(raw.cast()) }
}

fn words(storage: &ResourceStorage) -> &[u64] {
    unsafe { std::slice::from_raw_parts(std::ptr::from_ref(storage).cast(), 0x210000 / 8) }
}

fn words_mut(storage: &mut ResourceStorage) -> &mut [u64] {
    unsafe { std::slice::from_raw_parts_mut(std::ptr::from_mut(storage).cast(), 0x210000 / 8) }
}

#[test]
fn native_sized_storage_prepares_every_byte_in_place_with_no_passthrough_entries() {
    assert_eq!(std::mem::size_of::<ResourceStorage>(), 0x210000);
    assert_eq!(std::mem::align_of::<ResourceStorage>(), 4096);
    assert_eq!(std::mem::size_of::<ResourceHeader>(), 128);
    for base in [0x310000, 0x410000, 0x2200000] {
        let mut storage = storage();
        // Nonzero stale contents outside the publication header must all be replaced.
        words_mut(&mut storage)[16..].fill(0x5555_aaaa_3333_cccc);
        storage.prepare(policy(), base).unwrap();
        storage.verify(policy(), base).unwrap();
        let raw = words(&storage);
        assert_eq!(
            &raw[..16],
            &[
                u64::from_le_bytes(*b"IOUNINST"),
                1,
                0x210000,
                base,
                (base + 0x1000) | 0x1ff,
                base + 0x201000,
                (base + 0x202000) | 0x0800_0000_0000_0000,
                (base + 0x203000) | 0x0800_0000_0000_0000,
                base + 0x204000,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        );
        assert!(raw[16..0x1000 / 8].iter().all(|word| *word == 0));
        for id in 0..65536 {
            let first = 0x1000 / 8 + id * 4;
            assert_eq!(&raw[first..first + 4], &[(base + 0x201000) | 0x803, 0, 1, 0]);
        }
        // Empty root, command/event/completion pages and all eleven padding pages.
        assert!(raw[0x201000 / 8..].iter().all(|word| *word == 0));
        let before = raw.to_vec();
        assert_eq!(storage.prepare(policy(), base), Err(ResourceError::AlreadyPrepared));
        assert_eq!(words(&storage), before);
    }
}

#[test]
fn all_header_fields_and_each_resource_region_are_checked() {
    let mut storage = storage();
    let base = 0x310000;
    storage.prepare(policy(), base).unwrap();
    for index in 0..16 {
        words_mut(&mut storage)[index] ^= 1;
        assert_eq!(storage.header().validate(policy(), base), Err(ResourceError::Header));
        words_mut(&mut storage)[index] ^= 1;
    }
    // Both ends of each region, including header slack and unused final capacity.
    for byte in [
        128, 4088, 0x1000, 0x200ff8, 0x201000, 0x201ff8, 0x202000, 0x202ff8, 0x203000, 0x203ff8,
        0x204000, 0x204ff8, 0x205000, 0x20fff8,
    ] {
        words_mut(&mut storage)[byte / 8] ^= 1;
        assert_eq!(storage.verify(policy(), base), Err(ResourceError::Contents));
        // The header alone intentionally makes no claim about payload integrity.
        storage.header().validate(policy(), base).unwrap();
        words_mut(&mut storage)[byte / 8] ^= 1;
    }
    storage.verify(policy(), base).unwrap();
    assert_eq!(storage.header().validate(policy(), base + 4096), Err(ResourceError::Header));
}

#[test]
fn complete_assigned_extent_is_validated_before_mutation_or_header_publication() {
    let mut storage = storage();
    for (address_policy, base) in [
        (policy(), 0x310001),
        (policy(), u64::MAX & !4095),
        (
            AddressPolicy::new(32, EncryptionState::Unencrypted { encryption_bit: None }).unwrap(),
            0xffe00000,
        ),
        // Starts below the encoded encryption bit but crosses it in padding.
        (
            AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: Some(24) })
                .unwrap(),
            0xdf1000,
        ),
    ] {
        let before = words(&storage).to_vec();
        assert!(matches!(storage.prepare(address_policy, base), Err(ResourceError::Address(_))));
        assert_eq!(words(&storage), before);
        assert!(storage.header().validate(policy(), 0x310000).is_err());
    }
}

#[test]
fn composed_generations_have_real_disjoint_pages_and_clear_all_unused_capacity() {
    assert_eq!(std::mem::size_of::<CompositionStorage>(), 0x300000);
    assert_eq!(std::mem::align_of::<CompositionStorage>(), 4096);
    assert_eq!(COMPOSITION_TABLE_OFFSET, 0x200000);
    assert_eq!(COMPOSITION_TABLE_PAGES, 256);
    let layout = Layout::new::<CompositionStorage>();
    let raw = unsafe { alloc_zeroed(layout) };
    if raw.is_null() {
        handle_alloc_error(layout);
    }
    // Exactly the integer-only object initialized by the native installer.
    let mut image: Box<CompositionStorage> = unsafe { Box::from_raw(raw.cast()) };
    let base = std::ptr::from_ref(image.as_ref()) as usize;
    assert_eq!(image.device_table().as_ptr() as usize, base);
    assert_eq!(image.tables().as_ptr() as usize, base + 0x200000);
    assert!(image.is_empty());
    for page in image.device_table_mut() {
        page.fill(0xdead_beef_cafe_babe);
    }
    for page in image.tables_mut() {
        page.fill(0xcafe_babe_dead_beef);
    }
    assert!(!image.is_empty());
    image.clear();
    // Inspect the full representation, including the final page and word.
    let words = unsafe { std::slice::from_raw_parts(base as *const u64, 0x300000 / 8) };
    assert!(words.iter().all(|word| *word == 0));
    assert!(image.is_empty());
}
