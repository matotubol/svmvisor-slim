//! Resident private-root layout and host APIC ID admission (host::resident).

use svmvisor_hypervisor::host::resident::{
    CACHE_SHARED_BYTES, CACHE_SHARED_OFFSET, DIRECTORY_VERSION, IMAGE_LIMIT_OFFSET,
    STARTUP_PAGE_OFFSET, is_valid_pool_slot,
};

#[test]
fn resident_image_stops_below_shared_cache_diagnostic_and_startup_pages() {
    assert_eq!(DIRECTORY_VERSION, 17);
    assert_eq!(IMAGE_LIMIT_OFFSET, 0xf0000);
    assert_eq!(IMAGE_LIMIT_OFFSET, CACHE_SHARED_OFFSET);
    assert_eq!(CACHE_SHARED_BYTES, 0x8000);
    assert_eq!(CACHE_SHARED_OFFSET & 4095, 0);
    assert_eq!(CACHE_SHARED_BYTES & 4095, 0);
    assert!(CACHE_SHARED_OFFSET + CACHE_SHARED_BYTES <= 0xfb000);
    assert!(STARTUP_PAGE_OFFSET >= IMAGE_LIMIT_OFFSET && STARTUP_PAGE_OFFSET < 0x100000);
    let script = include_str!("../payload.ld");
    let bound = format!("ASSERT(image_bss_end <= {:#x},", 0x100000 + IMAGE_LIMIT_OFFSET);
    assert_eq!(script.matches("ASSERT(").count(), 1);
    assert!(script.contains(&bound), "{bound}");
}

#[test]
fn host_apic_ids_fit_the_bootstrap_inventory() {
    let pool = 0x200000;
    let bytes = 24 * 0x100000 + 0x3262000;
    // This machine's 24 IDs, one per dense slot.
    for (slot, id) in (0..=11).chain(16..=27).enumerate() {
        let slot = slot as u64;
        assert!(is_valid_pool_slot(pool + slot * 0x100000, pool, bytes, slot, id), "id {id}");
    }
    assert!(is_valid_pool_slot(pool, pool, bytes, 0, 254));
    for id in [255, 256, 511, 4095, u64::MAX] {
        assert!(!is_valid_pool_slot(pool, pool, bytes, 0, id), "id {id}");
    }
}
