//! Offline fixtures only: no callback, MMIO access, register write or installation.
use std::alloc::{Layout, alloc_zeroed, handle_alloc_error};
use svmvisor_hypervisor::{
    firmware::native::resident::iommu::{
        AcquisitionError, HardwareError, ObservationState, PciObservation, ReadError,
        RegisterObservation, Report, UnitObservation,
        binding::{
            BindingError, ObservedBuffer, ProfileError, Region, ResourceProfile, UnitAssignment,
            UnitIdentity, bind,
        },
        resources::{ResourceError, ResourceStorage},
    },
    host::resident::IOMMU_RESOURCE_BYTES,
    memory::{
        address::{AddressError, AddressPolicy, EncryptionState, PhysicalRange},
        iommu::discover,
    },
};

const BANK: u64 = 0x1010_0000;
const MMIO: u64 = 0xfd00_0000;

fn policy() -> AddressPolicy {
    AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

fn extent(base: u64, bytes: u64) -> PhysicalRange {
    policy().validate(base, bytes, 1).unwrap()
}

fn pool() -> PhysicalRange {
    extent(0x1000_0000, 0x400_0000)
}

fn storage(base: u64) -> Box<ResourceStorage> {
    let layout = Layout::new::<ResourceStorage>();
    let raw = unsafe { alloc_zeroed(layout) };
    if raw.is_null() {
        handle_alloc_error(layout);
    }
    // Integer-only object in aligned, exclusive host heap storage.
    let mut storage: Box<ResourceStorage> = unsafe { Box::from_raw(raw.cast()) };
    storage.prepare(policy(), base).unwrap();
    storage
}

fn set16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn set32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn set64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn checksum(bytes: &mut [u8]) {
    bytes[9] = 0;
    bytes[9] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
}

fn sdt(signature: &[u8; 4], bytes: usize) -> Vec<u8> {
    let mut table = vec![0; bytes];
    table[..4].copy_from_slice(signature);
    set32(&mut table, 4, bytes as u32);
    table[8] = 1;
    table
}

fn report_with_bases(bases: &[u64], features: Option<u64>) -> Report {
    let mut ivrs = sdt(b"IVRS", 48 + 28 * bases.len());
    for (index, base) in bases.iter().enumerate() {
        let start = 48 + 28 * index;
        ivrs[start] = 0x10;
        set16(&mut ivrs, start + 2, 28);
        set16(&mut ivrs, start + 4, 0x100 + index as u16);
        set16(&mut ivrs, start + 6, 0x40);
        set64(&mut ivrs, start + 8, *base);
        ivrs[start + 24] = 2;
        set16(&mut ivrs, start + 25, 0x200 + index as u16);
    }
    checksum(&mut ivrs);
    let mut mcfg = sdt(b"MCFG", 60);
    set64(&mut mcfg, 44, 0xe000_0000);
    mcfg[55] = 255;
    checksum(&mut mcfg);
    let mut report = Report::EMPTY;
    report.tables = discover(&ivrs, &mcfg).unwrap();
    report.state = ObservationState::Observed;
    for (index, base) in bases.iter().enumerate() {
        report.hardware[index] = UnitObservation {
            pci: Some(PciObservation {
                config_page: 0xe000_0000 + ((0x100 + index as u64) << 12),
                vendor_device: 0x1649_1022,
                command_status: 1 << 20,
                class_revision: 0x0806_0000,
                capability_header: 0x000b_000f | if features.is_some() { 1 << 27 } else { 0 },
                base_low: *base as u32 | 1,
                base_high: (*base >> 32) as u32,
                range: 0,
                miscellaneous0: (48 << 15) | (48 << 8),
                miscellaneous1: None,
            }),
            mmio_bytes: Some(if features.is_some_and(|v| v & (1 << 9) != 0) {
                0x80000
            } else {
                0x4000
            }),
            registers: Some(RegisterObservation {
                device_table: 0,
                command_buffer: 8 << 56,
                event_log: 8 << 56,
                control: 1 << 10,
                exclusion_base: 0,
                exclusion_limit: 0,
                extended_features: features,
                extended_features2: features.map(|_| 0),
                command_head: 0,
                command_tail: 0,
                event_head: 0,
                event_tail: 0,
                status: 0,
            }),
            error: None,
        };
    }
    report
}

fn report() -> Report {
    report_with_bases(&[MMIO], None)
}

fn assignment<'a>(
    report: &Report,
    index: usize,
    base: u64,
    storage: &'a ResourceStorage,
) -> UnitAssignment<'a> {
    UnitAssignment {
        identity: UnitIdentity::from_unit(report.tables.ivrs.units()[index]),
        extent: extent(base, IOMMU_RESOURCE_BYTES),
        storage,
    }
}

fn check(report: &Report, storage: &ResourceStorage) -> Result<(), BindingError> {
    bind(policy(), report, pool(), &[assignment(report, 0, BANK, storage)]).map(|_| ())
}

#[test]
fn explicit_identity_yields_only_a_copied_uninstalled_plan() {
    let report = report();
    let storage = storage(BANK);
    let plan = bind(policy(), &report, pool(), &[assignment(&report, 0, BANK, &storage)]).unwrap();
    assert_eq!(plan.len(), 1);
    assert!(!plan.is_empty());
    assert_eq!(plan.units().count(), 1);
    assert_eq!(plan.profile(), ResourceProfile::DenyEmptyUnsegmentedBasic);
    assert_eq!(plan.observed_state(), ObservationState::Observed);
    assert_eq!(plan.unresolved_diagnostics(), 0);
    let unit = *plan.unit(0).unwrap();
    assert_eq!(
        unit.identity,
        UnitIdentity { segment: 0, device_id: 0x100, capability_offset: 0x40, mmio_base: MMIO }
    );
    assert_eq!(
        (unit.configuration_page.base(), unit.configuration_page.len()),
        (0xe010_0000, 4096)
    );
    assert_eq!((unit.control_aperture.base(), unit.control_aperture.len()), (MMIO, 0x4000));
    assert_eq!((unit.bank.base(), unit.bank.len()), (BANK, 0x210000));
    assert_eq!(unit.observed_registers, report.hardware[0].registers.unwrap());
    assert!(plan.unit(1).is_none());
    // No retained borrow, freshness token or hardware access is necessary to
    // retain these numbers after both original inputs are gone.
    drop(storage);
    drop(report);
    unit.resource_header.validate(policy(), BANK).unwrap();
}

#[test]
fn every_identity_component_is_required_without_first_or_last_match_selection() {
    let report = report();
    let storage = storage(BANK);
    for field in 0..4 {
        let mut assigned = assignment(&report, 0, BANK, &storage);
        match field {
            0 => assigned.identity.segment ^= 1,
            1 => assigned.identity.device_id ^= 1,
            2 => assigned.identity.capability_offset += 4,
            _ => assigned.identity.mmio_base += 0x4000,
        }
        assert_eq!(
            bind(policy(), &report, pool(), &[assigned]),
            Err(BindingError::UnknownUnit { assignment: 0 })
        );
    }
}

#[test]
fn absent_partial_failed_or_extra_observations_cannot_bind() {
    let storage = storage(BANK);
    let mut report = report();
    for state in [
        ObservationState::Unavailable,
        ObservationState::Unsupported,
        ObservationState::Malformed,
        ObservationState::Partial,
    ] {
        report.state = state;
        assert_eq!(check(&report, &storage), Err(BindingError::ObservationState(state)));
    }
    report.state = ObservationState::Observed;
    report.failure = Some(AcquisitionError::Read(ReadError::Unavailable));
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::Acquisition(AcquisitionError::Read(ReadError::Unavailable)))
    );
    report.failure = None;
    let complete = report.hardware[0];
    for field in 0..3 {
        report.hardware[0] = complete;
        match field {
            0 => report.hardware[0].pci = None,
            1 => report.hardware[0].registers = None,
            _ => report.hardware[0].mmio_bytes = None,
        }
        assert_eq!(check(&report, &storage), Err(BindingError::MissingObservation { unit: 0 }));
    }
    report.hardware[0] = complete;
    report.hardware[0].error = Some(HardwareError::ChangingConfiguration);
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::Hardware { unit: 0, error: HardwareError::ChangingConfiguration })
    );
    report.hardware[0] = complete;
    report.hardware[1] = complete;
    assert_eq!(check(&report, &storage), Err(BindingError::UnexpectedObservation { unit: 1 }));
    report.tables.clear();
    assert_eq!(bind(policy(), &report, pool(), &[]), Err(BindingError::IncompleteTables));
}

#[test]
fn pc_support_controls_the_entire_aperture_and_alignment() {
    let storage = storage(BANK);
    let mut report = report_with_bases(&[MMIO], Some(1 << 9));
    let plan = bind(policy(), &report, pool(), &[assignment(&report, 0, BANK, &storage)]).unwrap();
    assert_eq!(plan.unit(0).unwrap().control_aperture.len(), 0x80000);
    report.hardware[0].mmio_bytes = Some(0x4000);
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::ApertureMismatch { unit: 0, expected: 0x80000, observed: 0x4000 })
    );
    let report = report_with_bases(&[MMIO + 0x4000], Some(1 << 9));
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::Address {
            region: Region::ControlAperture { unit: 0 },
            error: AddressError::Misaligned
        })
    );
}

#[test]
fn effective_apertures_cannot_cover_another_unit_or_ecam() {
    let first = storage(BANK);
    let second_base = BANK + IOMMU_RESOURCE_BYTES;
    let second = storage(second_base);
    // Parser admits the separate minimum windows. PCSup expands unit zero.
    let mut report = report_with_bases(&[MMIO, MMIO + 0x4000], None);
    report.hardware[0].pci.as_mut().unwrap().capability_header |= 1 << 27;
    report.hardware[0].registers.as_mut().unwrap().extended_features = Some(1 << 9);
    report.hardware[0].registers.as_mut().unwrap().extended_features2 = Some(0);
    report.hardware[0].mmio_bytes = Some(0x80000);
    assert_eq!(
        bind(
            policy(),
            &report,
            pool(),
            &[assignment(&report, 0, BANK, &first), assignment(&report, 1, second_base, &second)]
        ),
        Err(BindingError::Overlap {
            first: Region::ControlAperture { unit: 1 },
            second: Region::ControlAperture { unit: 0 }
        })
    );
    let report = report_with_bases(&[0xe0080000], Some(1 << 9));
    assert_eq!(
        check(&report, &first),
        Err(BindingError::Overlap {
            first: Region::ControlAperture { unit: 0 },
            second: Region::Ecam { allocation: 0 }
        })
    );
    for features in [None, Some(1 << 9)] {
        let report = report_with_bases(&[0xfed8_0000], features);
        assert_eq!(
            check(&report, &first),
            Err(BindingError::Overlap {
                first: Region::ControlAperture { unit: 0 },
                second: Region::PlatformControl
            })
        );
    }
}

#[test]
fn multiple_units_require_complete_separate_banks_and_accept_reordered_assignments() {
    let report = report_with_bases(&[MMIO, MMIO + 0x80000], None);
    let first = storage(BANK);
    let second_base = BANK + IOMMU_RESOURCE_BYTES;
    let second = storage(second_base);
    assert_eq!(
        bind(policy(), &report, pool(), &[assignment(&report, 0, BANK, &first)]),
        Err(BindingError::AssignmentCount { units: 2, assignments: 1 })
    );
    assert_eq!(
        bind(
            policy(),
            &report,
            pool(),
            &[assignment(&report, 0, BANK, &first), assignment(&report, 0, BANK, &first)]
        ),
        Err(BindingError::DuplicateAssignment { first: 0, second: 1 })
    );
    assert_eq!(
        bind(
            policy(),
            &report,
            pool(),
            &[assignment(&report, 0, BANK, &first), assignment(&report, 1, second_base, &first)]
        ),
        Err(BindingError::ReusedStorage { first: 0, second: 1 })
    );
    assert_eq!(
        bind(
            policy(),
            &report,
            pool(),
            &[assignment(&report, 0, BANK, &first), assignment(&report, 1, BANK + 4096, &second)]
        ),
        Err(BindingError::Overlap {
            first: Region::Bank { assignment: 1 },
            second: Region::Bank { assignment: 0 }
        })
    );
    let plan = bind(
        policy(),
        &report,
        pool(),
        &[assignment(&report, 1, second_base, &second), assignment(&report, 0, BANK, &first)],
    )
    .unwrap();
    assert_eq!(plan.len(), 2);
    assert_eq!(plan.unit(0).unwrap().bank.base(), BANK);
    assert_eq!(plan.unit(1).unwrap().bank.base(), second_base);
}

#[test]
fn whole_bank_and_pool_extents_include_all_assigned_padding() {
    let report = report();
    let storage = storage(BANK);
    let exact_pool = extent(BANK, IOMMU_RESOURCE_BYTES);
    bind(policy(), &report, exact_pool, &[assignment(&report, 0, BANK, &storage)]).unwrap();
    assert_eq!(
        bind(
            policy(),
            &report,
            extent(BANK, IOMMU_RESOURCE_BYTES - 4096),
            &[assignment(&report, 0, BANK, &storage)]
        ),
        Err(BindingError::BankOutsidePool { assignment: 0 })
    );
    assert_eq!(
        bind(
            policy(),
            &report,
            extent(BANK, IOMMU_RESOURCE_BYTES + 1),
            &[assignment(&report, 0, BANK, &storage)]
        ),
        Err(BindingError::PartialPoolPage)
    );
    let mut assigned = assignment(&report, 0, BANK, &storage);
    assigned.extent = extent(BANK, IOMMU_RESOURCE_BYTES - 4096);
    assert_eq!(
        bind(policy(), &report, pool(), &[assigned]),
        Err(BindingError::BankSize { assignment: 0 })
    );
    let narrow =
        AddressPolicy::new(32, EncryptionState::Unencrypted { encryption_bit: None }).unwrap();
    assert_eq!(
        bind(
            narrow,
            &report,
            extent(0xfffff000, 0x2000),
            &[assignment(&report, 0, BANK, &storage)]
        ),
        Err(BindingError::Address {
            region: Region::ProtectedPool,
            error: AddressError::OutsidePhysicalWidth
        })
    );
    let encrypted_bit =
        AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: Some(28) }).unwrap();
    assert_eq!(
        bind(encrypted_bit, &report, pool(), &[assignment(&report, 0, BANK, &storage)]),
        Err(BindingError::Address {
            region: Region::ProtectedPool,
            error: AddressError::EncryptionBitEncoded
        })
    );
}

#[test]
fn whole_pool_is_disjoint_from_configuration_and_control_bytes() {
    let storage = storage(BANK);
    let report = report();
    assert_eq!(
        bind(
            policy(),
            &report,
            extent(0xe0000000, 0x100000),
            &[assignment(&report, 0, BANK, &storage)]
        ),
        Err(BindingError::Overlap {
            first: Region::ProtectedPool,
            second: Region::Ecam { allocation: 0 }
        })
    );
    let report = report_with_bases(&[0x10000000], None);
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::Overlap {
            first: Region::ControlAperture { unit: 0 },
            second: Region::ProtectedPool
        })
    );
}

#[test]
fn observed_pci_and_feature_presence_are_cross_checked() {
    let storage = storage(BANK);
    for change in 0..9 {
        let mut report = report();
        let pci = report.hardware[0].pci.as_mut().unwrap();
        let expected = match change {
            0 => {
                pci.config_page += 4096;
                BindingError::EcamIdentity { unit: 0 }
            }
            1 => {
                pci.base_low ^= 0x4000;
                BindingError::MmioIdentity { unit: 0 }
            }
            2 => {
                pci.base_low &= !1;
                BindingError::MmioIdentity { unit: 0 }
            }
            3 => {
                pci.capability_header ^= 1;
                BindingError::Profile { unit: 0, error: ProfileError::CapabilityIdentity }
            }
            4 => {
                pci.capability_header |= 1 << 27;
                BindingError::Profile { unit: 0, error: ProfileError::FeaturePresence }
            }
            5 => {
                pci.miscellaneous1 = Some(0);
                BindingError::Profile { unit: 0, error: ProfileError::FeaturePresence }
            }
            6 => {
                pci.vendor_device = u32::MAX;
                BindingError::Profile { unit: 0, error: ProfileError::PciFunction }
            }
            7 => {
                pci.class_revision = 0x03000000;
                BindingError::Profile { unit: 0, error: ProfileError::PciFunction }
            }
            _ => {
                pci.command_status = 0;
                BindingError::Profile { unit: 0, error: ProfileError::PciFunction }
            }
        };
        assert_eq!(check(&report, &storage), Err(expected));
    }
}

#[test]
fn mode_four_and_basic_interrupt_profile_require_valid_width_support() {
    let storage = storage(BANK);
    for width in [0, 32, 40, 47, 49, 127] {
        let mut report = report();
        report.hardware[0].pci.as_mut().unwrap().miscellaneous0 = (width << 15) | (48 << 8);
        assert_eq!(
            check(&report, &storage),
            Err(BindingError::Profile {
                unit: 0,
                error: ProfileError::VirtualAddressWidth(width as u8)
            })
        );
    }
    for width in [0, 32, 39, 41, 49, 53, 127] {
        let mut report = report();
        report.hardware[0].pci.as_mut().unwrap().miscellaneous0 = (48 << 15) | (width << 8);
        assert_eq!(
            check(&report, &storage),
            Err(BindingError::Profile {
                unit: 0,
                error: ProfileError::PhysicalAddressWidth(width as u8)
            })
        );
    }
    let report = report_with_bases(&[MMIO], Some(3 << 10));
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::Profile { unit: 0, error: ProfileError::HostTranslationLevels })
    );
    let mut report = report_with_bases(&[MMIO], Some(0));
    report.hardware[0].registers.as_mut().unwrap().extended_features2 = Some(2 << 8);
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::Profile { unit: 0, error: ProfileError::InterruptRemapSupport })
    );
}

#[test]
fn optional_support_is_not_enablement_but_each_enabled_extra_mode_refuses() {
    let storage = storage(BANK);
    let features = (1 << 1)
        | (1 << 2)
        | (1 << 4)
        | (1 << 7)
        | (1 << 16)
        | (1 << 24)
        | (1 << 28)
        | (1 << 37)
        | (1 << 38)
        | (1 << 40)
        | (1 << 41)
        | (1 << 42)
        | (1 << 50)
        | (1 << 55);
    let mut report = report_with_bases(&[MMIO], Some(features));
    report.hardware[0].registers.as_mut().unwrap().extended_features2 = Some((1 << 2) | (1 << 8));
    check(&report, &storage).unwrap();
    for bit in [
        1, 13, 14, 15, 16, 17, 22, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
        40, 42, 43, 44, 45, 46, 47, 48, 50, 51, 52, 53, 54, 55, 56, 58, 59, 60, 61, 62, 63,
    ] {
        report.hardware[0].registers.as_mut().unwrap().control = (1 << 10) | (1 << bit);
        assert_eq!(
            check(&report, &storage),
            Err(BindingError::Profile { unit: 0, error: ProfileError::Control { bits: 1 << bit } }),
            "control bit {bit}"
        );
    }
    report.hardware[0].registers.as_mut().unwrap().control = 1 << 10;
    for bit in [5, 6, 7, 8, 9, 10, 11, 12, 15, 16, 17, 18] {
        report.hardware[0].registers.as_mut().unwrap().status = 1 << bit;
        assert_eq!(
            check(&report, &storage),
            Err(BindingError::Profile { unit: 0, error: ProfileError::Status { bits: 1 << bit } })
        );
    }
}

#[test]
fn reserved_read_bits_are_not_interpreted_as_current_modes() {
    let storage = storage(BANK);
    let mut report = report_with_bases(&[MMIO], Some((15 << 57) | (1 << 30) | (3 << 26)));
    let r = report.hardware[0].registers.as_mut().unwrap();
    r.control |= (15 << 18) | (1 << 49) | (1 << 57);
    r.status |= (3 << 13) | (!0 << 19);
    r.extended_features2 = Some((!0 << 17) | (1 << 10) | 1);
    check(&report, &storage).unwrap();
}

#[test]
fn active_basic_state_is_preserved_without_claiming_quiescence_or_reset() {
    let storage = storage(BANK);
    let mut report = report();
    let r = report.hardware[0].registers.as_mut().unwrap();
    r.control |= 1 | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 12);
    r.device_table = 0x2000_01ff;
    r.command_buffer = (8 << 56) | 0x2020_0000;
    r.event_log = (8 << 56) | 0x2020_1000;
    r.command_head = 0x10;
    r.command_tail = 0x20;
    r.event_tail = 0x30;
    r.status = 31;
    let plan = bind(policy(), &report, pool(), &[assignment(&report, 0, BANK, &storage)]).unwrap();
    assert_eq!(plan.unit(0).unwrap().observed_registers, report.hardware[0].registers.unwrap());
    for (buffer, field) in
        [(ObservedBuffer::DeviceTable, 0), (ObservedBuffer::Command, 1), (ObservedBuffer::Event, 2)]
    {
        let original = report.hardware[0].registers.unwrap();
        let r = report.hardware[0].registers.as_mut().unwrap();
        match field {
            0 => r.device_table = BANK | 511,
            1 => r.command_buffer = (8 << 56) | BANK,
            _ => r.event_log = (8 << 56) | BANK,
        }
        assert_eq!(
            check(&report, &storage),
            Err(BindingError::Overlap {
                first: Region::ObservedBuffer { unit: 0, buffer },
                second: Region::ProtectedPool
            })
        );
        report.hardware[0].registers = Some(original);
    }
}

#[test]
fn disabled_or_running_basic_buffers_still_cannot_alias_candidate_backing() {
    let storage = storage(BANK);
    let mut report = report();
    report.hardware[0].registers.as_mut().unwrap().event_log = (8 << 56) | 0xfed80000;
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::Overlap {
            first: Region::ObservedBuffer { unit: 0, buffer: ObservedBuffer::Event },
            second: Region::PlatformControl
        })
    );
    report.hardware[0].registers.as_mut().unwrap().event_log = (8 << 56) | (BANK + 0x20f000);
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::Overlap {
            first: Region::ObservedBuffer { unit: 0, buffer: ObservedBuffer::Event },
            second: Region::ProtectedPool
        })
    );
    report.hardware[0].registers.as_mut().unwrap().event_log = 8 << 56;
    report.hardware[0].registers.as_mut().unwrap().status = 1 << 4;
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::ObservedBuffer { unit: 0, buffer: ObservedBuffer::Command })
    );
    report.hardware[0].registers.as_mut().unwrap().command_buffer = (8 << 56) | 0x2020_0000;
    report.hardware[0].registers.as_mut().unwrap().command_tail = 0x1000;
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::ObservedBuffer { unit: 0, buffer: ObservedBuffer::Command })
    );
}

#[test]
fn exclusions_and_invalid_invalidation_timeout_remain_explicit_refusals() {
    let storage = storage(BANK);
    let mut report = report();
    report.hardware[0].registers.as_mut().unwrap().exclusion_base = 0x8000_0001;
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::Profile { unit: 0, error: ProfileError::ExclusionEnabled })
    );
    report.hardware[0].registers.as_mut().unwrap().exclusion_base = 0;
    report.hardware[0].registers.as_mut().unwrap().control |= 7 << 5;
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::Profile { unit: 0, error: ProfileError::InvalidationTimeout })
    );
}

#[test]
fn payload_check_includes_last_padding_word_even_with_an_unchanged_valid_header() {
    let report = report();
    let mut storage = storage(BANK);
    storage.header().validate(policy(), BANK).unwrap();
    let last = IOMMU_RESOURCE_BYTES as usize / 8 - 1;
    // A test-only corruption of integer backing, without touching its header.
    let words = unsafe {
        std::slice::from_raw_parts_mut(
            std::ptr::from_mut(&mut *storage).cast::<u64>(),
            IOMMU_RESOURCE_BYTES as usize / 8,
        )
    };
    words[last] = 1;
    storage.header().validate(policy(), BANK).unwrap();
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::Resources { assignment: 0, error: ResourceError::Contents })
    );
}

#[test]
fn captured_table_ambiguity_is_preserved_and_never_becomes_topology_authority() {
    let storage = storage(BANK);
    let mut report = report();
    report.tables = discover(
        include_bytes!("fixtures/iommu/windows-2026-09-26/IVRS.bin"),
        include_bytes!("fixtures/iommu/windows-2026-09-26/MCFG.bin"),
    )
    .unwrap();
    report.state = ObservationState::Ambiguous;
    let unit = report.tables.ivrs.units()[0];
    let efr_form = report.tables.ivrs.forms().iter().find(|form| form.efr.is_some()).unwrap();
    let original_diagnostics = report.tables.ivrs.diagnostics().to_vec();
    let allocation = report.tables.mcfg.allocations()[0];
    let pci = report.hardware[0].pci.as_mut().unwrap();
    pci.config_page = allocation.address(unit.device_id, 0).unwrap();
    pci.base_low = unit.mmio_base as u32 | 1;
    pci.base_high = (unit.mmio_base >> 32) as u32;
    pci.capability_header |= 1 << 27;
    // The real fixture has firmware tables only. Hardware fields below remain
    // synthetic, explicitly not a Windows or preboot register observation.
    report.hardware[0].registers.as_mut().unwrap().extended_features = efr_form.efr;
    report.hardware[0].registers.as_mut().unwrap().extended_features2 = efr_form.efr2;
    report.hardware[0].mmio_bytes =
        Some(if efr_form.efr.unwrap() & (1 << 9) != 0 { 0x80000 } else { 0x4000 });
    let plan = bind(policy(), &report, pool(), &[assignment(&report, 0, BANK, &storage)]).unwrap();
    assert_eq!(plan.observed_state(), ObservationState::Ambiguous);
    assert!(plan.unresolved_diagnostics() > 0);
    assert_eq!(report.tables.ivrs.diagnostics(), original_diagnostics);
    // Mismatching a copied EFR image is a local binding refusal, independent of
    // the separate requester ambiguity still present in the same immutable report.
    let observed = report.hardware[0].registers.as_mut().unwrap();
    observed.extended_features2 = observed.extended_features2.map(|value| value ^ 1);
    assert!(matches!(check(&report, &storage), Err(BindingError::FirmwareFeatures { .. })));
}

#[test]
fn extended_host_translation_disable_overrides_hats_without_misreading_legacy_xtsup() {
    let storage = storage(BANK);
    for kind in [0x10, 0x11, 0x40] {
        for hat_disabled in [false, true] {
            let header_bytes = if kind == 0x10 { 24 } else { 40 };
            let mut ivrs = sdt(b"IVRS", 48 + header_bytes + 4);
            ivrs[8] = 2;
            set32(&mut ivrs, 36, 1);
            ivrs[48] = kind;
            set16(&mut ivrs, 50, (header_bytes + 4) as u16);
            set16(&mut ivrs, 52, 0x100);
            set16(&mut ivrs, 54, 0x40);
            set64(&mut ivrs, 56, MMIO);
            set32(&mut ivrs, 68, u32::from(hat_disabled));
            ivrs[48 + header_bytes] = 2;
            set16(&mut ivrs, 49 + header_bytes, 0x200);
            checksum(&mut ivrs);
            let mut mcfg = sdt(b"MCFG", 60);
            set64(&mut mcfg, 44, 0xe000_0000);
            mcfg[55] = 255;
            checksum(&mut mcfg);
            let mut report = report_with_bases(&[MMIO], Some(0));
            report.tables = discover(&ivrs, &mcfg).unwrap();
            if kind != 0x10 && hat_disabled {
                assert_eq!(
                    check(&report, &storage),
                    Err(BindingError::HostTranslationDisabled { unit: 0, form: 0 })
                );
                // HATDis explicitly makes HATS irrelevant, including when its
                // saved value would otherwise be a reserved level encoding.
                report.hardware[0].registers.as_mut().unwrap().extended_features = Some(3 << 10);
                assert_eq!(
                    check(&report, &storage),
                    Err(BindingError::HostTranslationDisabled { unit: 0, form: 0 })
                );
            } else {
                check(&report, &storage).unwrap();
            }
        }
    }
}

#[test]
fn whole_pool_must_fit_iommu_output_width_and_avoid_firmware_reservations() {
    let storage = storage(BANK);
    let mut report = report();
    report.hardware[0].pci.as_mut().unwrap().miscellaneous0 = (48 << 15) | (40 << 8);
    assert_eq!(
        bind(
            policy(),
            &report,
            extent(pool().base(), (1 << 40) - pool().base() + 4096),
            &[assignment(&report, 0, BANK, &storage)]
        ),
        Err(BindingError::Overlap {
            first: Region::ProtectedPool,
            second: Region::PlatformControl
        })
    );
    // Use a separate high assignment to isolate the IOMMU width check from
    // intervening control/ECAM regions. The bank itself remains CPU-addressable.
    let high_base = 1 << 40;
    let high_bank = self::storage(high_base);
    assert_eq!(
        bind(
            policy(),
            &report,
            extent(high_base, IOMMU_RESOURCE_BYTES),
            &[assignment(&report, 0, high_base, &high_bank)]
        ),
        Err(BindingError::IommuAddressWidth { unit: 0, region: Region::ProtectedPool })
    );
    report.tables = discover(
        include_bytes!("fixtures/iommu/windows-2026-09-26/IVRS.bin"),
        include_bytes!("fixtures/iommu/windows-2026-09-26/MCFG.bin"),
    )
    .unwrap();
    let region = report.tables.ivrs.memory_regions()[0];
    assert_eq!(
        bind(
            policy(),
            &report,
            extent(region.start & !4095, 4096),
            &[assignment(&report, 0, BANK, &storage)]
        ),
        Err(BindingError::Overlap {
            first: Region::ProtectedPool,
            second: Region::FirmwareReservation { index: 0 }
        })
    );
}

#[test]
fn complete_old_buffer_extents_cannot_cross_into_pool_or_control_pages() {
    let storage = storage(BANK);
    let mut report = report();
    report.hardware[0].registers.as_mut().unwrap().device_table = (pool().base() - 4096) | 511;
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::Overlap {
            first: Region::ObservedBuffer { unit: 0, buffer: ObservedBuffer::DeviceTable },
            second: Region::ProtectedPool
        })
    );
    report.hardware[0].registers.as_mut().unwrap().device_table = 0;
    report.hardware[0].registers.as_mut().unwrap().command_buffer = (15 << 56) | (MMIO - 4096);
    assert_eq!(
        check(&report, &storage),
        Err(BindingError::Overlap {
            first: Region::ObservedBuffer { unit: 0, buffer: ObservedBuffer::Command },
            second: Region::ControlAperture { unit: 0 }
        })
    );
}
