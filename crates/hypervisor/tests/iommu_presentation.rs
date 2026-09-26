//! Offline preparation/publication and effect contracts. The recording owner
//! does not establish physical identity, native DMA, firmware publication or
//! Windows compatibility; no hardware access occurs in this test executable.
use svmvisor_hypervisor::{
    arch::x86_64::msr::{TARGET_PHYSICAL_BITS, TARGET_SIGNATURE},
    firmware::native::resident::iommu::{
        self as native, ObservationState, PciObservation, RegisterObservation, Report,
        UnitObservation,
    },
    memory::iommu::{
        self, MemorySemantics,
        virtualized::presentation::{
            self, PreparationError, PublicationOwner, PublishError, Storage, View,
        },
    },
    svm::{
        configuration::{ConfigurationRoute, ScalarTarget},
        pci::{
            self, ConfigAccess, Msi, Region,
            iommu::{Bank, CAPABILITY_HEADER, Effects, IommuFunction, MISCELLANEOUS},
        },
    },
};

const ECAM: u64 = 0xe000_0000;
const MMIO: u64 = 0xfd00_0000;
const BDF: u16 = 2;

fn route() -> ConfigurationRoute {
    ConfigurationRoute::admit_target(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, ECAM | 0x21).unwrap()
}
fn set16(b: &mut [u8], p: usize, v: u16) {
    b[p..p + 2].copy_from_slice(&v.to_le_bytes());
}
fn set32(b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&v.to_le_bytes());
}
fn set64(b: &mut [u8], p: usize, v: u64) {
    b[p..p + 8].copy_from_slice(&v.to_le_bytes());
}
fn checksum(b: &mut [u8]) {
    b[9] = 0;
    b[9] = 0u8.wrapping_sub(b.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
}
fn sdt(signature: &[u8; 4], bytes: usize) -> Vec<u8> {
    let mut out = vec![0; bytes];
    out[..4].copy_from_slice(signature);
    set32(&mut out, 4, bytes as u32);
    out[8] = 1;
    out
}
fn source() -> (Vec<u8>, Vec<u8>) {
    let uid = b"\\_SB.TEST";
    let form_bytes = 40 + 4 + 8 + 16 + 22 + uid.len();
    let mut ivrs = sdt(b"IVRS", 48 + form_bytes + 3 * 32);
    ivrs[8] = 2;
    set32(&mut ivrs, 36, MISCELLANEOUS | 3);
    ivrs[48] = 0x40;
    ivrs[49] = 0x20;
    set16(&mut ivrs, 50, form_bytes as u16);
    set16(&mut ivrs, 52, BDF);
    set16(&mut ivrs, 54, 0x90);
    set64(&mut ivrs, 56, MMIO);
    set64(&mut ivrs, 72, (1 << 9) | 2); // Physical counters/PPR not copied.
    ivrs[88] = 2;
    set16(&mut ivrs, 89, 0x100);
    ivrs[92] = 0x42;
    set16(&mut ivrs, 93, 0x200);
    set16(&mut ivrs, 97, 0x100);
    for (offset, source, handle, variety) in [(100, 0xa0, 1, 1), (108, 0xa1, 0, 2)] {
        ivrs[offset] = 0x48;
        ivrs[offset + 4] = handle;
        set16(&mut ivrs, offset + 5, source);
        ivrs[offset + 7] = variety;
    }
    ivrs[116] = 0xf0;
    set16(&mut ivrs, 117, 0x300);
    ivrs[120..128].copy_from_slice(b"AMDI0090");
    ivrs[136] = 2;
    ivrs[137] = uid.len() as u8;
    ivrs[138..138 + uid.len()].copy_from_slice(uid);
    for (index, kind, flags) in [(0, 0x20, 0), (1, 0x21, 7), (2, 0x22, 8)] {
        let p = 48 + form_bytes + index * 32;
        ivrs[p] = kind;
        ivrs[p + 1] = flags;
        set16(&mut ivrs, p + 2, 32);
        if kind != 0x20 {
            set16(&mut ivrs, p + 4, 0x100);
        }
        if kind == 0x22 {
            set16(&mut ivrs, p + 6, 0x105);
        }
        set64(&mut ivrs, p + 16, (1 + index as u64) * 4096);
        set64(&mut ivrs, p + 24, 4096);
    }
    checksum(&mut ivrs);
    let mut mcfg = sdt(b"MCFG", 60);
    set64(&mut mcfg, 44, ECAM);
    mcfg[55] = 255;
    checksum(&mut mcfg);
    (ivrs, mcfg)
}
fn report() -> Report {
    let (ivrs, mcfg) = source();
    let mut report = Report::EMPTY;
    report.tables = iommu::discover(&ivrs, &mcfg).unwrap();
    assert!(
        !report.tables.ivrs.has_unresolved_diagnostics(),
        "{:?}",
        report.tables.ivrs.diagnostics()
    );
    report.state = ObservationState::Observed;
    report.hardware[0] = UnitObservation {
        error: None,
        mmio_bytes: Some(0x80000),
        pci: Some(PciObservation {
            config_page: ECAM + (u64::from(BDF) << 12),
            vendor_device: 0x1649_1022,
            command_status: 0x100006,
            class_revision: 0x08060001,
            capability_header: 0x080b000f,
            base_low: MMIO as u32 | 1,
            base_high: 0,
            range: 0,
            miscellaneous0: MISCELLANEOUS,
            miscellaneous1: None,
        }),
        registers: Some(RegisterObservation {
            device_table: 0,
            command_buffer: 8 << 56,
            event_log: 8 << 56,
            control: 1,
            exclusion_base: 0,
            exclusion_limit: 0,
            extended_features: Some(0x202),
            extended_features2: Some(0),
            command_head: 0,
            command_tail: 0,
            event_head: 0,
            event_tail: 0,
            status: 0,
        }),
    };
    report
}

#[derive(Default)]
struct Owner {
    publish: Vec<u8>,
    calls: Vec<&'static str>,
    reject: Option<&'static str>,
    transitions: Vec<(u16, u16)>,
    msi: Vec<Msi>,
}
impl PublicationOwner for Owner {
    fn admit(&mut self, view: View<'_>) -> Result<(), PublishError> {
        self.calls.push("admit");
        assert_eq!(view.units[0].physical_mmio_bytes, 0x80000);
        assert_eq!(view.functions[0].allowed().bytes, 0x4000);
        if self.reject == Some("admit") { Err(PublishError::Owner) } else { Ok(()) }
    }
    fn replace_ivrs(&mut self, view: View<'_>) -> Result<(), PublishError> {
        self.calls.push("replace");
        self.publish = view.ivrs.to_vec();
        if self.reject == Some("replace") { Err(PublishError::Firmware) } else { Ok(()) }
    }
    fn verify(&mut self, view: View<'_>) -> Result<(), PublishError> {
        self.calls.push("verify");
        if self.reject == Some("verify") || self.publish != view.ivrs {
            Err(PublishError::Verification)
        } else {
            Ok(())
        }
    }
}
impl Effects for Owner {
    fn revalidate(&mut self, r: ConfigurationRoute, f: &[IommuFunction]) -> Result<(), pci::Error> {
        assert_eq!(r, route());
        assert!(!f.is_empty());
        if self.reject == Some("revalidate") { Err(pci::Error::OwnerRejected) } else { Ok(()) }
    }
    fn apply(&mut self, before: &IommuFunction, after: &IommuFunction) -> Result<(), pci::Error> {
        self.transitions.push((before.command(), after.command()));
        if self.reject == Some("apply") { Err(pci::Error::OwnerRejected) } else { Ok(()) }
    }
    fn interrupt(&mut self, _: u16, message: Msi) -> Result<(), pci::Error> {
        self.msi.push(message);
        Ok(())
    }
}
fn target(register: u16, width: u8) -> ScalarTarget {
    ScalarTarget { bdf: BDF, register, width }
}

#[test]
fn native_preparation_generates_coherent_firmware_without_publishing() {
    let mut storage = Box::new(Storage::EMPTY);
    native::presentation::prepare(&mut storage, &report(), route()).unwrap();
    assert!(!storage.is_active());
    assert!(storage.bank(route(), &mut Owner::default()).is_err());
    let view = storage.view(route()).unwrap();
    let parsed = iommu::parse_ivrs(view.ivrs).unwrap();
    assert_eq!(parsed.header.revision, 2);
    assert_eq!(parsed.iv_info, MISCELLANEOUS | 3);
    assert_eq!(parsed.units()[0].capability_offset, 0x40);
    assert_eq!(parsed.forms()[0].kind, 0x40);
    assert_eq!(parsed.forms()[0].feature_info, 0);
    assert_eq!(parsed.forms()[0].efr, Some(0));
    assert_eq!(parsed.forms()[0].efr2, Some(0));
    assert_eq!(parsed.requester_scopes()[1].alias_source, Some(0x100));
    assert_eq!(parsed.special_devices().len(), 2);
    assert_eq!(parsed.acpi_devices()[0].uid(), b"\\_SB.TEST");
    assert_eq!(parsed.memory_regions().len(), 3);
    assert_eq!(parsed.memory_regions()[2].semantics, MemorySemantics::Exclusion);
    assert!(!parsed.has_unresolved_diagnostics());
}

#[test]
fn native_success_connects_one_shared_io_ecam_bank_and_full_aperture_dispatch() {
    let mut storage = Box::new(Storage::EMPTY);
    native::presentation::prepare(&mut storage, &report(), route()).unwrap();
    let mut owner = Owner::default();
    storage.publish(route(), &mut owner).unwrap();
    assert_eq!(owner.calls, ["admit", "replace", "verify"]);
    assert_eq!(storage.mmio_route(MMIO + 0x2020, 8).unwrap().offset, 0x2020);
    assert_eq!(storage.mmio_route(MMIO + 0x4000, 8), Err(pci::Error::UnsupportedControl));
    assert_eq!(storage.mmio_route(MMIO + 0x80000, 8), Err(pci::Error::NoDecode));
    {
        let mut bank = storage.bank(route(), &mut owner).unwrap();
        bank.io(0xcf8, 4, Some(0x8000_0000 | u32::from(BDF) << 8 | 0x40)).unwrap();
        assert_eq!(bank.io(0xcfc, 4, None).unwrap(), CAPABILITY_HEADER | 0x6000);
        assert_eq!(
            bank.ecam(ECAM + (u64::from(BDF) << 12) + 0x40, 4, None).unwrap(),
            CAPABILITY_HEADER | 0x6000
        );
        assert_eq!(
            bank.access(ScalarTarget { bdf: 0x78, register: 0, width: 4 }, None),
            Err(pci::Error::MissingOwner)
        );
        assert_eq!(
            bank.access(ScalarTarget { bdf: 0x78, register: 0xb8, width: 4 }, None),
            Err(pci::Error::SensitiveControl)
        );
        bank.access(target(0x64, 4), Some(0xfee0_0000)).unwrap();
        bank.access(target(0x6c, 2), Some(0x51)).unwrap();
        bank.access(target(0x62, 1), Some(1)).unwrap();
        bank.interrupt(BDF).unwrap();
    }
    assert_eq!(owner.msi, [Msi { enabled: true, address: 0xfee0_0000, data: 0x51 }]);
    let mut bank = storage.bank(route(), &mut owner).unwrap();
    assert_eq!(bank.io(0xcf8, 4, None).unwrap(), 0x8000_0240);
    bank.access(target(0x44, 4), Some(0x8000_0000)).unwrap();
    assert_eq!(bank.access(target(0x44, 4), None).unwrap(), MMIO as u32 | 1);
    assert_eq!(bank.access(target(0x50, 4), None).unwrap(), MISCELLANEOUS);
}

#[test]
fn publication_failures_never_activate_or_retry_after_partial_effects() {
    for stage in ["admit", "replace", "verify"] {
        let mut storage = Box::new(Storage::EMPTY);
        native::presentation::prepare(&mut storage, &report(), route()).unwrap();
        let mut owner = Owner { reject: Some(stage), ..Owner::default() };
        assert!(storage.publish(route(), &mut owner).is_err());
        assert!(!storage.is_active());
        assert!(storage.publish(route(), &mut Owner::default()).is_err());
        assert!(storage.bank(route(), &mut Owner::default()).is_err());
    }
}

#[test]
fn configuration_effect_failure_poison_survives_reborrowing() {
    let mut storage = Box::new(Storage::EMPTY);
    native::presentation::prepare(&mut storage, &report(), route()).unwrap();
    storage.publish(route(), &mut Owner::default()).unwrap();
    let mut owner = Owner { reject: Some("apply"), ..Owner::default() };
    assert_eq!(
        storage.bank(route(), &mut owner).unwrap().access(target(4, 2), Some(2)),
        Err(pci::Error::OwnerRejected)
    );
    assert!(!storage.is_active());
    assert!(storage.bank(route(), &mut Owner::default()).is_err());
}

#[test]
fn actual_saved_ambiguous_inventory_cannot_become_virtual_firmware() {
    let mut report = Report::EMPTY;
    report.tables = iommu::discover(
        include_bytes!("fixtures/iommu/windows-2026-09-26/IVRS.bin"),
        include_bytes!("fixtures/iommu/windows-2026-09-26/MCFG.bin"),
    )
    .unwrap();
    report.state = ObservationState::Ambiguous;
    let mut storage = Box::new(Storage::EMPTY);
    assert_eq!(
        native::presentation::prepare(&mut storage, &report, route()),
        Err(PreparationError::UnresolvedInventory)
    );
    assert_eq!(storage.preparation_error(), PreparationError::UnresolvedInventory.code());
    assert!(storage.view(route()).is_err());
}

#[test]
fn failed_capture_and_observation_mismatch_are_retained_refusals() {
    let mut incomplete = Box::new(Storage::EMPTY);
    assert_eq!(
        native::presentation::prepare(&mut incomplete, &Report::EMPTY, route()),
        Err(PreparationError::IncompleteReport)
    );
    let mut changed = report();
    changed.hardware[0].pci.as_mut().unwrap().base_low ^= 0x4000;
    let mut storage = Box::new(Storage::EMPTY);
    assert_eq!(
        native::presentation::prepare(&mut storage, &changed, route()),
        Err(PreparationError::Profile)
    );
    assert!(!storage.is_active());
    let (mut ivrs, mcfg) = source();
    set64(&mut ivrs, 56, 0xfed80000);
    checksum(&mut ivrs);
    let mut aliased = report();
    aliased.tables = iommu::discover(&ivrs, &mcfg).unwrap();
    aliased.hardware[0].pci.as_mut().unwrap().base_low = 0xfed80001;
    let mut storage = Box::new(Storage::EMPTY);
    assert_eq!(
        native::presentation::prepare(&mut storage, &aliased, route()),
        Err(PreparationError::Profile)
    );
    assert!(!storage.is_active());
}

#[test]
fn no_ats_claim_is_silently_hidden() {
    let (mut bytes, _) = source();
    bytes[91] = 8;
    bytes[95] = 8;
    checksum(&mut bytes);
    let source = iommu::parse_ivrs(&bytes).unwrap();
    let mut out = [0x55; 1024];
    let unit = presentation::Unit { segment: 0, device_id: BDF, mmio_base: MMIO };
    assert_eq!(
        presentation::render(&source, &[unit], &mut out),
        Err(presentation::Error::UnsupportedAts)
    );
    assert!(out.iter().all(|b| *b == 0));
}

#[test]
fn dma_remap_declaration_requires_the_actual_acpi_string_identity() {
    let (mut bytes, _) = source();
    let old_length = u16::from_le_bytes(bytes[50..52].try_into().unwrap());
    let removed = usize::from(bytes[137]) - 4;
    bytes.drain(142..142 + removed);
    bytes[136] = 1;
    bytes[137] = 4;
    set32(&mut bytes, 138, 7);
    set16(&mut bytes, 50, old_length - removed as u16);
    let length = bytes.len() as u32;
    set32(&mut bytes, 4, length);
    // Parsing already refuses integer UIDs with DMA-remap support. Also prove
    // the renderer rejects a later caller-added preboot requirement.
    set32(&mut bytes, 36, MISCELLANEOUS | 1);
    checksum(&mut bytes);
    let mut parsed = iommu::parse_ivrs(&bytes).unwrap();
    parsed.iv_info |= 2;
    let mut output = [0x55; 1024];
    let unit = presentation::Unit { segment: 0, device_id: BDF, mmio_base: MMIO };
    assert_eq!(
        presentation::render(&parsed, &[unit], &mut output),
        Err(presentation::Error::AcpiStringIdentityRequired)
    );
    assert!(output.iter().all(|byte| *byte == 0));
}

fn roots_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut rsdp = vec![0; 36];
    rsdp[..8].copy_from_slice(b"RSD PTR ");
    rsdp[15] = 2;
    set32(&mut rsdp, 16, 0x20000);
    set32(&mut rsdp, 20, 36);
    set64(&mut rsdp, 24, 0x21000);
    rsdp[8] = 0u8.wrapping_sub(rsdp[..20].iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
    rsdp[32] = 0u8.wrapping_sub(rsdp.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
    let mut xsdt = sdt(b"XSDT", 52);
    set64(&mut xsdt, 36, 0x22000);
    set64(&mut xsdt, 44, 0x23000);
    checksum(&mut xsdt);
    let mut rsdt = sdt(b"RSDT", 44);
    set32(&mut rsdt, 36, 0x23000);
    set32(&mut rsdt, 40, 0x22000);
    checksum(&mut rsdt);
    let mut apic = sdt(b"APIC", 36);
    checksum(&mut apic);
    (rsdp, xsdt, rsdt, apic)
}

#[test]
fn concrete_root_replacement_updates_both_paths_preserving_other_tables() {
    use native::presentation::roots::{Assignment, Image, Source};
    let (rsdp, xsdt, rsdt, apic) = roots_fixture();
    let (ivrs, _) = source();
    let mut storage = Box::new(Storage::EMPTY);
    native::presentation::prepare(&mut storage, &report(), route()).unwrap();
    let view = storage.view(route()).unwrap();
    let mut image = Image::EMPTY;
    image
        .prepare(
            Source {
                rsdp_address: 0x10000,
                rsdp: &rsdp,
                xsdt: &xsdt,
                rsdt: Some(&rsdt),
                ivrs_address: 0x22000,
                ivrs: &ivrs,
            },
            Assignment { rsdp: 0x100000, xsdt: 0x101000, rsdt: 0x102000, ivrs: 0x110000 },
            view.ivrs,
            |address| {
                Ok(if address == 0x22000 {
                    ivrs[..36].try_into().unwrap()
                } else {
                    apic[..36].try_into().unwrap()
                })
            },
        )
        .unwrap();
    let rsdp = image.rsdp().unwrap();
    assert_eq!(rsdp[..20].iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)), 0);
    assert_eq!(rsdp.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)), 0);
    assert_eq!(u64::from_le_bytes(rsdp[24..32].try_into().unwrap()), 0x101000);
    assert_eq!(u32::from_le_bytes(rsdp[16..20].try_into().unwrap()), 0x102000);
    let xsdt = image.xsdt().unwrap();
    let rsdt = image.rsdt().unwrap();
    iommu::validate_sdt(xsdt, *b"XSDT").unwrap();
    iommu::validate_sdt(rsdt, *b"RSDT").unwrap();
    assert_eq!(u64::from_le_bytes(xsdt[36..44].try_into().unwrap()), 0x110000);
    assert_eq!(u64::from_le_bytes(xsdt[44..52].try_into().unwrap()), 0x23000);
    assert_eq!(u32::from_le_bytes(rsdt[36..40].try_into().unwrap()), 0x23000);
    assert_eq!(u32::from_le_bytes(rsdt[40..44].try_into().unwrap()), 0x110000);
}

#[test]
fn root_replacement_rejects_duplicate_ivrs_and_destination_aliases() {
    use native::presentation::roots::{Assignment, Error, Image, Source};
    let (rsdp, xsdt, rsdt, apic) = roots_fixture();
    let (ivrs, _) = source();
    for duplicate in [false, true] {
        let mut image = Image::EMPTY;
        let assigned = Assignment {
            rsdp: 0x100000,
            xsdt: 0x101000,
            rsdt: 0x102000,
            ivrs: if duplicate { 0x110000 } else { 0x23000 },
        };
        let result = image.prepare(
            Source {
                rsdp_address: 0x10000,
                rsdp: &rsdp,
                xsdt: &xsdt,
                rsdt: Some(&rsdt),
                ivrs_address: 0x22000,
                ivrs: &ivrs,
            },
            assigned,
            &ivrs,
            |address| {
                Ok(if duplicate || address == 0x22000 {
                    ivrs[..36].try_into().unwrap()
                } else {
                    apic[..36].try_into().unwrap()
                })
            },
        );
        assert_eq!(result, Err(if duplicate { Error::DuplicateTable } else { Error::Overlap }));
        assert!(image.rsdp().is_none());
        assert!(image.xsdt().is_none());
    }
}

#[test]
fn unlocked_base_must_complete_owner_effect_then_locks_all_capability_lanes() {
    let allowed = Region { base: 0x8000_0000, bytes: 0x8000 };
    let mut functions = [IommuFunction::new(BDF, 0x1649_1022, 0, allowed, false).unwrap()];
    let mut selector = 0;
    let mut poisoned = 0;
    let mut owner = Owner::default();
    {
        let mut bank =
            Bank::new(route(), &mut functions, &mut selector, &mut poisoned, &mut owner).unwrap();
        bank.access(target(0x44, 4), Some(0x8000_4001)).unwrap();
        bank.access(target(0x48, 4), Some(0x1234)).unwrap();
        bank.access(target(0x44, 1), Some(0)).unwrap();
        assert_eq!(bank.access(target(0x44, 4), None).unwrap(), 0x8000_4001);
        assert_eq!(bank.access(target(0x48, 4), None).unwrap(), 0);
        assert_eq!(bank.access(target(4, 2), Some(1)), Err(pci::Error::UnsupportedControl));
        assert_eq!(bank.access(target(0x62, 1), Some(0x11)), Err(pci::Error::UnsupportedControl));
    }
    assert_eq!(owner.transitions.len(), 1);
    assert_eq!(poisoned, 0);
}

#[test]
fn renderer_clears_partial_buffer_and_never_truncates_widths() {
    let source = report();
    let unit = presentation::Unit { segment: 0, device_id: BDF, mmio_base: MMIO };
    let mut out = [0x55; 80];
    assert_eq!(
        presentation::render(&source.tables.ivrs, &[unit], &mut out),
        Err(presentation::Error::Capacity)
    );
    assert_eq!(out, [0; 80]);
    let unit = presentation::Unit { mmio_base: 1 << 48, ..unit };
    assert_eq!(
        presentation::render(&source.tables.ivrs, &[unit], &mut out),
        Err(presentation::Error::UnitIdentity)
    );
}
