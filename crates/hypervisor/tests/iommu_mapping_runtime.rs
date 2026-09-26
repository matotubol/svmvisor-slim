//! Offline execution of the actual bounded native workspace, page builders and
//! NPT source guards. No MMIO, APIC, firmware, physical memory or DMA is touched.

use svmvisor_hypervisor::{
    arch::x86_64::capabilities::EvidenceFlag,
    host::{
        paging::{self, PagingConfig},
        resident::iommu_runtime::{self, NativeWorkspace},
    },
    memory::{
        address::{AddressPolicy, EncryptionState},
        iommu::{
            image::{MappingRange, ProtectedRange},
            physical::PhysicalUnit,
            tables::{PageCoherency, Permissions},
            virtualized::{
                compose::{GuestHostRange, HostMap, mixed},
                device::{Device, WorkKind, WriteResult},
                snapshot::{Capture, CaptureError, CapturePage, SnapshotPage},
            },
        },
        npt::{
            CACHE_TABLE_COUNT, CacheMapping, CacheNptError, ControlPageDenials, IdentityNpt,
            NptEvidence, retype_identity_policy_with_guards,
            table_guard::{
                TableWriteDenials, protect_identity_tables, verify_identity_table_guards,
                verify_identity_tables,
            },
        },
    },
};

const RW: u64 = 3 << 61;
fn policy() -> AddressPolicy {
    AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}
fn maps() -> [GuestHostRange; 1] {
    [GuestHostRange {
        guest_base: 0,
        host_base: 0x100000,
        len: 0x100000,
        permissions: Permissions::ReadWrite,
    }]
}
fn put(page: &mut [u8; 4096], index: usize, word: u64) {
    page[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
}

#[test]
fn closure_captures_inactive_dtes_then_all_translation_and_interrupt_sources() {
    let ranges = maps();
    let host = HostMap::new(policy(), &ranges, &[]).unwrap();
    let mut pages = vec![SnapshotPage::EMPTY; 16];
    let mut requests = vec![CapturePage::EMPTY; 16];
    let mut capture = Capture::new(&mut pages, &mut requests, &host, 0x1000, 8192).unwrap();
    // BOTH device pages are required even when the second has only old V=IV=0.
    assert_eq!(capture.requests().len(), 2);
    let mut dte = [0; 4096];
    put(&mut dte, 0, 0x3000 | (2 << 9) | RW | 3);
    put(&mut dte, 1, 7);
    // 2048 IRTEs straddle three pages when the legal root is only128-byte aligned.
    put(&mut dte, 2, 0x6080 | (11 << 1) | (2 << 60) | 1);
    let request = capture.next_page().unwrap();
    assert_eq!(request.host_page, 0x101000);
    capture.supply(request, &dte).unwrap();
    while let Some(request) = capture.next_page() {
        let mut page = [0; 4096];
        if request.guest_page == 0x3000 {
            put(&mut page, 0, 0x4000 | (1 << 9) | RW | 1);
        }
        if request.guest_page == 0x4000 {
            put(&mut page, 5, 0x9000 | RW | 1);
        }
        capture.supply(request, &page).unwrap();
    }
    let snapshot = capture.finish().unwrap();
    let guest: Vec<_> =
        snapshot.snapshot().unwrap().pages().iter().map(SnapshotPage::guest_page).collect();
    assert_eq!(guest, [0x1000, 0x2000, 0x3000, 0x4000, 0x6000, 0x7000, 0x8000]);
}

#[test]
fn closure_refuses_capacity_missing_sources_and_protected_links_without_a_partial_snapshot() {
    let ranges = maps();
    let host = HostMap::new(policy(), &ranges, &[]).unwrap();
    let mut pages = vec![SnapshotPage::EMPTY; 1];
    let mut requests = vec![CapturePage::EMPTY; 1];
    assert!(matches!(
        Capture::new(&mut pages, &mut requests, &host, 0x1000, 8192),
        Err(CaptureError::Capacity)
    ));
    let mut capture = Capture::new(&mut pages, &mut requests, &host, 0x1000, 4096).unwrap();
    let mut dte = [0; 4096];
    put(&mut dte, 0, 0x3000 | (2 << 9) | RW | 3);
    assert_eq!(capture.supply(capture.next_page().unwrap(), &dte), Err(CaptureError::Capacity));
    assert!(matches!(capture.finish(), Err(CaptureError::Incomplete)));
    let protected = [ProtectedRange { base: 0x103000, len: 4096 }];
    let host = HostMap::new(policy(), &ranges, &protected).unwrap();
    let mut pages = vec![SnapshotPage::EMPTY; 4];
    let mut requests = vec![CapturePage::EMPTY; 4];
    let mut capture = Capture::new(&mut pages, &mut requests, &host, 0x1000, 4096).unwrap();
    assert_eq!(
        capture.supply(capture.next_page().unwrap(), &dte),
        Err(CaptureError::ProtectedSource(0x3000))
    );
    assert!(matches!(capture.finish(), Err(CaptureError::Incomplete)));
}

#[test]
fn closure_rejects_inconsistent_physical_alias_samples() {
    let ranges = [
        GuestHostRange {
            guest_base: 0x1000,
            host_base: 0x100000,
            len: 4096,
            permissions: Permissions::ReadWrite,
        },
        GuestHostRange {
            guest_base: 0x2000,
            host_base: 0x100000,
            len: 4096,
            permissions: Permissions::ReadWrite,
        },
    ];
    let host = HostMap::new(policy(), &ranges, &[]).unwrap();
    let mut pages = vec![SnapshotPage::EMPTY; 4];
    let mut requests = vec![CapturePage::EMPTY; 4];
    let mut capture = Capture::new(&mut pages, &mut requests, &host, 0x1000, 8192).unwrap();
    capture.supply(capture.next_page().unwrap(), &[0; 4096]).unwrap();
    let mut changed = [0; 4096];
    changed[7] = 0xa5; // Ignored old V=IV=0 payload, still a contradictory alias.
    assert!(matches!(
        capture.supply(capture.next_page().unwrap(), &changed),
        Err(CaptureError::Snapshot(_))
    ));
    assert!(matches!(capture.finish(), Err(CaptureError::Incomplete)));
}

fn range(io: u64, host: u64, len: u64, permissions: Permissions) -> MappingRange {
    MappingRange {
        io_base: io,
        system_base: host,
        len,
        permissions,
        coherency: PageCoherency::ForceCoherent,
    }
}

#[test]
fn mixed_native_image_preserves_nonidentity_permissions_and_clears_reused_storage() {
    let mappings = [
        range(0, 0x1_0000_0000, 1 << 30, Permissions::ReadWrite),
        range(1 << 30, 0x2_0000_0000, 1 << 21, Permissions::Read),
        range((1 << 30) + (1 << 21), 0x3_0000_5000, 4096, Permissions::Write),
    ];
    let mut tables = vec![[0xa5; 512]; 256];
    let image = mixed::build(policy(), 0x40000000, &mut tables, &mappings, &[]).unwrap();
    assert_eq!(image.used_pages, 4);
    assert_eq!(
        mixed::walk(&tables, image, 0x3456).unwrap(),
        Some((0x1_0000_3456, Permissions::ReadWrite))
    );
    assert_eq!(
        mixed::walk(&tables, image, (1 << 30) + 90).unwrap(),
        Some((0x2_0000_005a, Permissions::Read))
    );
    assert_eq!(
        mixed::walk(&tables, image, (1 << 30) + (1 << 21) + 123).unwrap(),
        Some((0x3_0000_507b, Permissions::Write))
    );
    assert_eq!(mixed::walk(&tables, image, (1 << 30) + (1 << 21) + 4096).unwrap(), None);
    assert_eq!(mixed::verify(policy(), image.root, &tables, &mappings, &[]), Ok(image));
    assert!(tables[image.used_pages..].iter().flatten().all(|word| *word == 0));
    tables[255][511] = 1;
    assert_eq!(
        mixed::verify(policy(), image.root, &tables, &mappings, &[]),
        Err(mixed::Error::Contents)
    );
}

#[test]
fn mixed_image_capacity_and_every_protected_output_refuse_before_mutation() {
    let mut tables = vec![[0xa5; 512]; 3];
    let old = tables.clone();
    let mappings = [range(0, 0x1_0000_1000, 4096, Permissions::ReadWrite)];
    assert!(matches!(
        mixed::build(policy(), 0x40000000, &mut tables, &mappings, &[]),
        Err(mixed::Error::Capacity { .. })
    ));
    assert_eq!(tables, old);
    let mappings = [range(0, 0x40002000, 4096, Permissions::None)];
    assert_eq!(
        mixed::build(policy(), 0x40000000, &mut tables, &mappings, &[]),
        Err(mixed::Error::BackingOutput)
    );
    assert_eq!(tables, old);
    let mappings = [range(0, 0x80000000, 4096, Permissions::Read)];
    let protected = [ProtectedRange { base: 0x80000000, len: 4096 }];
    assert_eq!(
        mixed::build(policy(), 0x40000000, &mut tables, &mappings, &protected),
        Err(mixed::Error::ProtectedOutput)
    );
    assert_eq!(tables, old);
}

fn npt() -> (u64, Vec<[u8; 4096]>) {
    let root = 0x10000000;
    let mut tables = vec![[0; 4096]; CACHE_TABLE_COUNT];
    let evidence = NptEvidence {
        nx_supported: EvidenceFlag::Set,
        host_nxe: EvidenceFlag::Set,
        host_four_level: EvidenceFlag::Set,
    };
    IdentityNpt::new_with_denied_ranges(
        &mut tables,
        root,
        policy(),
        policy().validate(root, 1 << 20, 4096).unwrap(),
        evidence,
        EvidenceFlag::Set,
        6,
        &ControlPageDenials::EMPTY,
    )
    .unwrap();
    (root, tables)
}
fn translate(tables: &[[u8; 4096]], root: u64, gpa: u64) -> Option<paging::Translation> {
    paging::translate(
        PagingConfig {
            cr3: root,
            physical_bits: 48,
            la57: false,
            nxe: true,
            pcid: false,
            page1gb: true,
        },
        gpa,
        |address| {
            let offset = address.checked_sub(root)? as usize;
            let page = tables.get(offset / 4096)?;
            let index = offset & 4095;
            Some(u64::from_le_bytes(page[index..index + 8].try_into().ok()?))
        },
    )
    .ok()
}

#[test]
fn installed_npt_source_guards_remain_readable_and_survive_cache_rebuilds() {
    let (root, source) = npt();
    let sources = [0x20003000, 0x40009000];
    let guards = TableWriteDenials::new(policy(), &sources).unwrap();
    let mut staged = vec![[0; 4096]; CACHE_TABLE_COUNT];
    protect_identity_tables(&source, &mut staged, root, policy(), guards).unwrap();
    verify_identity_tables(&staged, root, guards).unwrap();
    for page in sources {
        let translation = translate(&staged, root, page).unwrap();
        assert!(!translation.writable);
        assert_eq!(translation.physical_address, page);
        assert!(translate(&staged, root, page + 4096).unwrap().writable);
    }
    assert!(translate(&staged, root, root).is_none());
    let mut retyped = vec![[0; 4096]; CACHE_TABLE_COUNT];
    retype_identity_policy_with_guards(
        &staged,
        &mut retyped,
        root,
        policy(),
        &ControlPageDenials::EMPTY,
        guards,
        |_, _| Ok(Some(CacheMapping::Pat(5))),
    )
    .unwrap();
    verify_identity_tables(&retyped, root, guards).unwrap();
    for page in sources {
        let translation = translate(&retyped, root, page).unwrap();
        assert!(!translation.writable);
        assert_eq!(translation.pat_index, 5);
    }
    assert!(translate(&retyped, root, root).is_none());
    let mut quarantined = vec![[0; 4096]; CACHE_TABLE_COUNT];
    retype_identity_policy_with_guards(
        &retyped,
        &mut quarantined,
        root,
        policy(),
        &ControlPageDenials::EMPTY,
        guards,
        |_, _| Ok(Some(CacheMapping::Quarantine)),
    )
    .unwrap();
    verify_identity_table_guards(&quarantined, root, guards).unwrap();
    assert!(verify_identity_tables(&quarantined, root, guards).is_err());
    retype_identity_policy_with_guards(
        &quarantined,
        &mut retyped,
        root,
        policy(),
        &ControlPageDenials::EMPTY,
        guards,
        |_, _| Ok(Some(CacheMapping::Pat(0))),
    )
    .unwrap();
    verify_identity_table_guards(&retyped, root, guards).unwrap();
    verify_identity_tables(&retyped, root, guards).unwrap();
}

#[test]
fn source_guard_capacity_failure_preserves_source_and_zeros_unusable_destination() {
    let (root, source) = npt();
    let old = source.clone();
    let sources = [0x20003000, 0x40009000];
    let guards = TableWriteDenials::new(policy(), &sources).unwrap();
    let mut too_small = vec![[0xa5; 4096]; 3];
    assert_eq!(
        protect_identity_tables(&source, &mut too_small, root, policy(), guards),
        Err(CacheNptError::Storage)
    );
    assert_eq!(source, old);
    assert!(too_small.iter().flatten().all(|byte| *byte == 0));
    assert!(TableWriteDenials::new(policy(), &[0x4000, 0x3000]).is_err());
    assert!(TableWriteDenials::new(policy(), &[0x4000, 0x4000]).is_err());
}

#[test]
fn source_guard_verification_rejects_writable_leaf_and_malformed_parent() {
    let (root, source) = npt();
    let sources = [0x20003000];
    let guards = TableWriteDenials::new(policy(), &sources).unwrap();
    let mut staged = vec![[0; 4096]; CACHE_TABLE_COUNT];
    protect_identity_tables(&source, &mut staged, root, policy(), guards).unwrap();
    let clean = staged.clone();
    let mut table = 0;
    for level in (1..=4).rev() {
        let index = ((sources[0] >> (12 + 9 * (level - 1))) & 511) as usize;
        let entry = u64::from_le_bytes(staged[table][index * 8..index * 8 + 8].try_into().unwrap());
        if level == 1 {
            staged[table][index * 8..index * 8 + 8].copy_from_slice(&(entry | 2).to_le_bytes());
        } else {
            table = (((entry & 0x000f_ffff_ffff_f000) - root) / 4096) as usize;
        }
    }
    assert_eq!(verify_identity_table_guards(&staged, root, guards), Err(CacheNptError::Entry));
    staged = clean;
    let parent = u64::from_le_bytes(staged[0][..8].try_into().unwrap());
    staged[0][..8].copy_from_slice(&(parent | (1 << 9)).to_le_bytes());
    assert_eq!(verify_identity_table_guards(&staged, root, guards), Err(CacheNptError::Entry));
}

#[test]
fn one_retained_workspace_serializes_all_units_and_initializes_each_typed_cell() {
    let layout = std::alloc::Layout::new::<NativeWorkspace>();
    assert!(layout.size() <= iommu_runtime::WORKSPACE_BYTES);
    // SAFETY: fresh aligned exclusive inert heap allocation, never hardware-visible.
    let workspace = unsafe { std::alloc::alloc(layout).cast::<NativeWorkspace>() };
    assert!(!workspace.is_null());
    unsafe {
        iommu_runtime::initialize_workspace(workspace);
    }
    let mut guard = unsafe { iommu_runtime::try_lock_workspace(workspace) }.unwrap();
    assert!(unsafe { iommu_runtime::try_lock_workspace(workspace) }.is_none());
    let parts = guard.parts();
    assert_eq!(parts.pages.len(), 4096);
    assert!(parts.pages.iter().all(|page| page.bytes().iter().all(|b| *b == 0)));
    assert!(parts.mappings.iter().all(|range| range.permissions == Permissions::None));
    let unit = PhysicalUnit {
        segment: 0,
        device_id: 0xa0,
        capability_offset: 0x40,
        mmio_base: 0xfed80000,
    };
    assert!(guard.bind_unit(0, unit, 7));
    assert!(!guard.bind_unit(0, unit, 7));
    assert!(guard.device(0).is_some());
    assert!(guard.device(1).is_none());
    drop(guard);
    assert!(unsafe { iommu_runtime::try_lock_workspace(workspace) }.is_some());
    // SAFETY: every guard/reference has ended; retained hardware never saw this allocation.
    unsafe {
        std::alloc::dealloc(workspace.cast(), layout);
    }
}

#[test]
fn table_writes_get_exact_publication_keys_without_requiring_a_guest_command() {
    let unit = PhysicalUnit {
        segment: 0,
        device_id: 0xa0,
        capability_offset: 0x40,
        mmio_base: 0xfed80000,
    };
    let mut device = Device::new(unit, 44);
    assert_eq!(device.write(0x2020, 8, 0).unwrap(), WriteResult::Committed);
    let work = device.tables_changed(13).unwrap();
    assert_eq!(work.key.unit, unit);
    assert_eq!(work.key.epoch, 44);
    assert_eq!(work.key.generation, 1);
    assert_eq!(work.kind, WorkKind::TableWrite { source_generation: 13 });
    assert!(device.tables_changed(14).is_err());
}
