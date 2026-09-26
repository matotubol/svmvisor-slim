use svmvisor_hypervisor::memory::{
    address::{AddressPolicy, EncryptionState},
    iommu::{
        host_walk,
        image::{MappingRange, ProtectedRange, TablePage},
        physical::PhysicalUnit,
        tables::{HostDeviceEntry, PageCoherency, Permissions},
        virtualized::{
            compose::{self, ComposeError, GuestHostRange, HostMap},
            device::{
                Command, CommandError, Device, DeviceError, InvalidationRange, WriteResult,
                guest_ring_register,
            },
            guest::{
                self, DecodeError, DeviceEntry, InterruptDelivery, InterruptEntry, InterruptMode,
                TranslationMode, WalkError,
            },
            snapshot::{
                Dependencies, Dependency, Snapshot, SnapshotError, SnapshotPage, TrackedSnapshot,
                Writer,
            },
        },
    },
};

const RW: u64 = 3 << 61;
const READ: u64 = 1 << 61;
const HOST: u64 = 0x8000_0000;

fn page(guest: u64, entries: &[(usize, u64)]) -> SnapshotPage {
    let mut bytes = [0u8; 4096];
    for &(index, value) in entries {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    SnapshotPage::copy(guest, HOST + guest, &bytes).unwrap()
}

fn dte(mode: u8, root: u64) -> DeviceEntry {
    DeviceEntry::decode([3 | (u64::from(mode) << 9) | root | RW, 11, 0, 0]).unwrap()
}

fn policy() -> AddressPolicy {
    AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

fn unit() -> PhysicalUnit {
    PhysicalUnit { segment: 0, device_id: 2, capability_offset: 0x40, mmio_base: 0xfed8_0000 }
}

#[test]
fn guest_device_validity_and_ignored_fields_are_not_host_codec_rules() {
    let bypass = DeviceEntry::decode([u64::MAX & !1, u64::MAX, 0, u64::MAX]).unwrap();
    assert_eq!(bypass.mode, TranslationMode::Bypass);
    assert_eq!(bypass.permissions, Permissions::ReadWrite);
    let unavailable =
        DeviceEntry::decode([1 | (7 << 9) | 0x000f_ffff_ffff_f000 | RW, 0, 0, 0]).unwrap();
    assert_eq!(unavailable.mode, TranslationMode::Unavailable);
    let identity = dte(0, 0x000f_ffff_ffff_f000);
    assert_eq!(identity.mode, TranslationMode::Identity);
    for management in 0..=3u64 {
        let entry = DeviceEntry::decode([3 | RW, (management << 40) | (2 << 35), 0, 0]).unwrap();
        assert_eq!(entry.sys_mgt, management as u8);
        assert_eq!(entry.io_ctl, 2);
    }
    assert!(matches!(
        DeviceEntry::decode([3 | RW, 3 << 35, 0, 0]),
        Err(DecodeError::Reserved { .. })
    ));
    assert!(matches!(
        DeviceEntry::decode([3 | RW | (5 << 9), 0, 0, 0]),
        Err(DecodeError::UnsupportedMode(5))
    ));
}

#[test]
fn basic_interrupt_tables_allow_full_architectural_lengths_and_delivery() {
    for length in 0..=11 {
        let entry = DeviceEntry::decode([0, 0, 0x1080 | (2 << 60) | (length << 1) | 1, 0]).unwrap();
        assert_eq!(entry.interrupt, InterruptMode::Remap { root: 0x1080, entries: 1 << length });
    }
    assert_eq!(
        DeviceEntry::decode([0, 0, 0x1080 | (2 << 60) | (12 << 1) | 1, 0]),
        Err(DecodeError::InvalidInterruptLength)
    );
    assert_eq!(
        DeviceEntry::decode([0, 0, 0x1040 | (2 << 60) | 1, 0]),
        Err(DecodeError::AddressWidth)
    );
    let entry =
        InterruptEntry::decode(1 | 2 | 4 | 0x20 | 0x40 | (0xa5 << 8) | (0xf1 << 16)).unwrap();
    assert!(entry.enabled && entry.suppress_fault && entry.logical && entry.request_eoi);
    assert_eq!(entry.delivery, InterruptDelivery::Arbitrated);
    assert_eq!((entry.destination, entry.vector), (0xa5, 0xf1));
    assert!(InterruptEntry::decode(1 | (2 << 2)).is_err());
    assert!(InterruptEntry::decode(1 | (1 << 7)).is_err());
}

#[test]
fn skipped_walk_intersects_permissions_and_accepts_ignored_pte_bits() {
    let pages = [
        page(0x1000, &[(1, 0x2000 | (1 << 9) | READ | 1)]),
        page(0x2000, &[(9, 0x50000 | RW | (1 << 63) | (1 << 59) | 0x1ff)]),
    ];
    let snapshot = Snapshot::new(&pages).unwrap();
    let mut entries = [Dependency::EMPTY; 8];
    let mut deps = Dependencies::new(&mut entries);
    let io = (1 << 39) | 0x9123;
    let actual = guest::walk(&snapshot, dte(4, 0x1000), true, None, io, &mut deps).unwrap();
    assert_eq!(actual.guest_address, 0x50123);
    assert_eq!(actual.permissions, Permissions::Read);
    assert_eq!(deps.entries().len(), 2);
    assert_eq!(
        guest::walk(&snapshot, dte(4, 0x1000), true, None, io | (1 << 21), &mut deps),
        Err(WalkError::SkippedAddressBits)
    );
    assert_eq!(
        guest::walk(&snapshot, dte(1, 0x2000), true, None, 1 << 21, &mut deps),
        Err(WalkError::SkippedAddressBits)
    );
}

#[test]
fn large_leaf_sizes_and_replication_use_the_indexed_entry() {
    for exponent in 13..=20 {
        let encoded = ((1u64 << (exponent - 1)) - 1) & !0xfff;
        let value = 0x4000_0000 | encoded | (7 << 9) | RW | 1;
        let pages = [page(0x1000, &[(0, value), (1, value)])];
        let snapshot = Snapshot::new(&pages).unwrap();
        let mut entries = [Dependency::EMPTY; 2];
        let mut deps = Dependencies::new(&mut entries);
        let actual = guest::walk(&snapshot, dte(1, 0x1000), true, None, 0x1123, &mut deps).unwrap();
        assert_eq!(actual.guest_address, 0x4000_1123);
        assert_eq!(actual.page_size, 1 << exponent);
    }
    let pages = [page(0x1000, &[(1, 0x400000 | RW | 1)])];
    let snapshot = Snapshot::new(&pages).unwrap();
    let mut entries = [Dependency::EMPTY; 2];
    let actual = guest::walk(
        &snapshot,
        dte(2, 0x1000),
        true,
        None,
        0x200123,
        &mut Dependencies::new(&mut entries),
    )
    .unwrap();
    assert_eq!((actual.guest_address, actual.page_size), (0x400123, 1 << 21));
}

#[test]
fn malformed_or_missing_pages_never_turn_into_identity() {
    let cases = [
        (u64::MAX & !1, WalkError::NotPresent),
        (RW | 1 | (1 << 52), WalkError::Decode(DecodeError::Reserved { word: 0, bits: 1 << 52 })),
        (RW | 1 | (1 << 9), WalkError::Decode(DecodeError::InvalidLevel)),
    ];
    for (raw, expected) in cases {
        let pages = [page(0x1000, &[(0, raw)])];
        let snapshot = Snapshot::new(&pages).unwrap();
        let mut entries = [Dependency::EMPTY; 2];
        assert_eq!(
            guest::walk(
                &snapshot,
                dte(1, 0x1000),
                true,
                None,
                0,
                &mut Dependencies::new(&mut entries)
            ),
            Err(expected)
        );
    }
    let snapshot = Snapshot::new(&[]).unwrap();
    let mut entries = [Dependency::EMPTY; 2];
    assert!(
        guest::walk(&snapshot, dte(4, 0x1000), true, None, 0, &mut Dependencies::new(&mut entries))
            .is_err()
    );
}

#[test]
fn full_nonidentity_composition_builds_real_host_tables_and_protected_holes() {
    let pages = [
        page(0x1000, &[(0, 0x2000 | (1 << 9) | RW | 1)]),
        page(0x2000, &[(9, 0x50000 | RW | 1), (10, 0x51000 | RW | 1)]),
    ];
    let tracked = TrackedSnapshot::new(&pages).unwrap();
    let ranges = [GuestHostRange {
        guest_base: 0,
        host_base: HOST,
        len: 0x100000,
        permissions: Permissions::ReadWrite,
    }];
    let protected = [ProtectedRange { base: HOST + 0x50000, len: 4096 }];
    let map = HostMap::new(policy(), &ranges, &protected).unwrap();
    let empty = MappingRange {
        io_base: 0,
        system_base: 0,
        len: 0,
        permissions: Permissions::None,
        coherency: PageCoherency::Inherit,
    };
    let mut output = [empty; 16];
    let mut dep_storage = [Dependency::EMPTY; 8];
    let mut deps = Dependencies::new(&mut dep_storage);
    let composed =
        compose::compose(&tracked, dte(4, 0x1000), true, None, &map, &mut output, &mut deps)
            .unwrap();
    assert_eq!(composed.ranges().len(), 1);
    let mut tables = vec![TablePage::ZERO; 4];
    let image = composed.build_image(policy(), 0x9000_0000, &mut tables, &protected).unwrap();
    let device =
        HostDeviceEntry::new(policy(), image.root_address(), 71, Permissions::ReadWrite).unwrap();
    let walk =
        |io| host_walk::walk(policy(), device, io, |key| image.read_word(key).ok_or(key)).unwrap();
    assert!(walk(0x9000).is_none());
    assert_eq!(walk(0xa123).unwrap().system_address, HOST + 0x51123);
}

#[test]
fn all_guest_bypass_states_still_exclude_host_memory_and_table_dma_writes() {
    let pages = [page(0x1000, &[])];
    let tracked = TrackedSnapshot::new(&pages).unwrap();
    let ranges = [
        GuestHostRange {
            guest_base: 0,
            host_base: HOST,
            len: 0x10000,
            permissions: Permissions::ReadWrite,
        },
        GuestHostRange {
            guest_base: 0x100000,
            host_base: HOST + 0x1000,
            len: 4096,
            permissions: Permissions::ReadWrite,
        },
    ];
    let protected = [ProtectedRange { base: HOST + 0x5000, len: 4096 }];
    let map = HostMap::new(policy(), &ranges, &protected).unwrap();
    for (enabled, device, exclusion) in [
        (false, dte(4, 0x1000), None),
        (true, DeviceEntry::decode([0; 4]).unwrap(), None),
        (true, dte(0, 0), None),
        (
            true,
            DeviceEntry::decode([1, 0, 0, 0]).unwrap(),
            Some(guest::Exclusion { base: 0, limit: 0x1f_ffff, allow_all: true }),
        ),
    ] {
        let mut output = [MappingRange {
            io_base: 0,
            system_base: 0,
            len: 0,
            permissions: Permissions::None,
            coherency: PageCoherency::Inherit,
        }; 16];
        let mut deps = [Dependency::EMPTY; 4];
        let composed = compose::compose(
            &tracked,
            device,
            enabled,
            exclusion,
            &map,
            &mut output,
            &mut Dependencies::new(&mut deps),
        )
        .unwrap();
        for range in composed.ranges() {
            assert!(
                range.system_base + range.len <= HOST + 0x5000
                    || range.system_base >= HOST + 0x6000
            );
            if range.system_base == HOST + 0x1000 {
                assert_eq!(range.permissions, Permissions::Read);
            }
        }
        let aliases: Vec<_> =
            composed.ranges().iter().filter(|r| r.system_base == HOST + 0x1000).collect();
        assert_eq!(aliases.len(), 2);
    }
}

#[test]
fn cpu_dma_and_monitor_mutation_of_any_source_alias_poison_the_capture() {
    let page_a = page(0x1000, &[]);
    let page_b = SnapshotPage::copy(0x2000, HOST + 0x1000, &[0; 4096]).unwrap();
    let pages = [page_a, page_b];
    for writer in [Writer::Cpu, Writer::Dma, Writer::Monitor] {
        let mut tracked = TrackedSnapshot::new(&pages).unwrap();
        assert!(!tracked.observe_write(HOST + 0x3000, 1, writer).unwrap());
        assert!(tracked.snapshot().is_ok());
        assert!(tracked.observe_write(HOST + 0x1fff, 2, writer).unwrap());
        assert_eq!(tracked.snapshot().unwrap_err(), SnapshotError::Stale);
    }
    let different = SnapshotPage::copy(0x2000, HOST + 0x1000, &[1; 4096]).unwrap();
    assert!(matches!(
        Snapshot::new(&[pages[0].clone(), different]),
        Err(SnapshotError::InconsistentAlias)
    ));
}

#[test]
fn capture_source_must_match_admitted_guest_to_host_mapping() {
    let pages = [page(0x1000, &[])];
    let tracked = TrackedSnapshot::new(&pages).unwrap();
    let ranges = [GuestHostRange {
        guest_base: 0,
        host_base: HOST + 4096,
        len: 0x10000,
        permissions: Permissions::ReadWrite,
    }];
    let map = HostMap::new(policy(), &ranges, &[]).unwrap();
    let mut output = [];
    let mut deps = [];
    assert!(matches!(
        compose::compose(
            &tracked,
            dte(0, 0),
            true,
            None,
            &map,
            &mut output,
            &mut Dependencies::new(&mut deps)
        ),
        Err(ComposeError::SnapshotAliasMismatch(0x1000))
    ));
}

#[test]
fn baseline_commands_preserve_full_semantics_without_native_pointers() {
    assert_eq!(
        Command::decode([(1 << 60) | 0x12348 | 7, 0xdead_beef]).unwrap(),
        Command::Completion { store: Some((0x12348, 0xdead_beef)), interrupt: true, flush: true }
    );
    // Ignored address/data are accepted for s=0; high reserved bits are not.
    assert!(Command::decode([(1 << 60) | 0x000f_ffff_ffff_fff8, u64::MAX]).is_ok());
    assert_eq!(Command::decode([(1 << 60) | (1 << 55), 0]), Err(CommandError::Reserved));
    assert_eq!(
        Command::decode([(3 << 60) | (17 << 32), 0x7fff_ffff_ffff_f003]).unwrap(),
        Command::InvalidatePages { domain: 17, range: InvalidationRange::All, directories: true }
    );
    assert_eq!(
        Command::decode([(3 << 60) | (17 << 32), 0x501003]).unwrap(),
        Command::InvalidatePages {
            domain: 17,
            range: InvalidationRange::Page { base: 0x500000, bytes: 0x4000 },
            directories: true
        }
    );
    assert_eq!(
        Command::decode([(5 << 60) | 0xffff, 0]).unwrap(),
        Command::InvalidateInterrupts { device: 0xffff }
    );
    for opcode in [0, 4, 6, 7, 8, 15] {
        assert_eq!(Command::decode([opcode << 60, 0]), Err(CommandError::Opcode(opcode as u8)));
    }
    assert!(Command::decode([3 << 60, 4]).is_err());
}

#[test]
fn all_queue_sizes_and_mmio_lanes_are_bounded_and_feature_reads_are_zero() {
    let mut device = Device::new(unit(), 1);
    assert_eq!(device.read(0x18, 8).unwrap(), 1 << 10);
    for order in 8..=15 {
        let value = guest_ring_register(0x10000, order).unwrap();
        assert_eq!(device.write(8, 8, value).unwrap(), WriteResult::Committed);
        assert_eq!(device.registers().command_ring().unwrap().bytes, 16 << order);
        for width in [1, 2, 4, 8] {
            for offset in (0..8).step_by(width as usize) {
                let mask = if width == 8 { u64::MAX } else { (1u64 << (8 * width)) - 1 };
                assert_eq!(device.read(8 + offset, width).unwrap(), (value >> (8 * offset)) & mask);
            }
        }
    }
    assert!(device.read(7, 8).is_err());
    assert!(device.read(0x4000, 1).is_err());
    assert!(device.read(0x1ff8, 8).is_err());
    for offset in [0x30, 0x1a0, 0x100] {
        device.write(offset, 8, u64::MAX).unwrap();
        assert_eq!(device.read(offset, 8).unwrap(), 0);
    }
}

#[test]
fn enabling_or_disabling_translation_requires_a_physical_receipt() {
    let mut device = Device::new(unit(), 17);
    let work = match device.write(0x18, 8, 0x1001).unwrap() {
        WriteResult::Pending(work) => work,
        _ => panic!("enable was acknowledged before physical publication"),
    };
    assert_eq!(work.key.epoch, 17);
    assert_eq!(work.key.generation, 1);
    assert!(!device.registers().enabled());
    assert_eq!(device.read(0x2020, 8).unwrap(), 0);
    assert_eq!(device.write(0x18, 8, 0), Err(DeviceError::Busy));
    assert_eq!(device.pending(), Some(work));
}

#[test]
fn manually_constructed_modes_and_exclusions_fail_without_panicking() {
    let tracked = TrackedSnapshot::new(&[]).unwrap();
    let snapshot = tracked.snapshot().unwrap();
    let map = HostMap::new(policy(), &[], &[]).unwrap();
    for levels in [0, 5, 255] {
        let mut device = dte(0, 0);
        device.mode = TranslationMode::Paging { root: 0, levels };
        let mut deps = [];
        assert_eq!(
            guest::walk(snapshot, device, true, None, 0, &mut Dependencies::new(&mut deps)),
            Err(WalkError::Decode(DecodeError::InvalidLevel))
        );
        assert!(matches!(
            compose::compose(
                &tracked,
                device,
                true,
                None,
                &map,
                &mut [],
                &mut Dependencies::new(&mut deps)
            ),
            Err(ComposeError::Guest(WalkError::Decode(DecodeError::InvalidLevel)))
        ));
    }
    for root in [1, 1 << 48, u64::MAX] {
        let mut device = dte(0, 0);
        device.mode = TranslationMode::Paging { root, levels: 4 };
        assert_eq!(
            guest::walk(snapshot, device, true, None, 0, &mut Dependencies::new(&mut [])),
            Err(WalkError::Decode(DecodeError::AddressWidth))
        );
    }
    for exclusion in [
        guest::Exclusion { base: 1, limit: 4095, allow_all: true },
        guest::Exclusion { base: 4096, limit: 4095, allow_all: true },
        guest::Exclusion { base: 0, limit: 1 << 48, allow_all: true },
    ] {
        assert_eq!(
            guest::walk(
                snapshot,
                dte(0, 0),
                true,
                Some(exclusion),
                0,
                &mut Dependencies::new(&mut [])
            ),
            Err(WalkError::InvalidExclusion)
        );
    }
}

#[test]
fn basic_interrupt_actions_preserve_guest_delivery_and_suppression() {
    let incoming = guest::InterruptMessage {
        delivery: InterruptDelivery::Fixed,
        logical: false,
        request_eoi: false,
        destination: 1,
        vector: 32,
    };
    let encoded = 1 | 2 | 4 | 0x20 | 0x40 | (0xa5 << 8) | (0xf1 << 16);
    let pages = [page(0x1000, &[(0, encoded | (2u64 << 32))])];
    let snapshot = Snapshot::new(&pages).unwrap();
    let device = DeviceEntry::decode([0, 0, 0x1000 | (2 << 60) | (1 << 1) | 1, 0]).unwrap();
    let mut storage = [Dependency::EMPTY; 2];
    let mut deps = Dependencies::new(&mut storage);
    assert_eq!(
        guest::remap_interrupt(&snapshot, device, true, 0, incoming, &mut deps).unwrap(),
        guest::InterruptAction::Deliver(guest::InterruptMessage {
            delivery: InterruptDelivery::Arbitrated,
            logical: true,
            request_eoi: true,
            destination: 0xa5,
            vector: 0xf1
        })
    );
    assert_eq!(
        guest::remap_interrupt(&snapshot, device, true, 1, incoming, &mut deps).unwrap(),
        guest::InterruptAction::Abort { report: false }
    );
    assert_eq!(
        guest::remap_interrupt(&snapshot, device, false, 0, incoming, &mut deps).unwrap(),
        guest::InterruptAction::Deliver(incoming)
    );
    assert_eq!(deps.entries()[0].roles, 4);
}
