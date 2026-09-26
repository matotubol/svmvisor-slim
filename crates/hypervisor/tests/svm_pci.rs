use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use svmvisor_hypervisor::{
    arch::x86_64::{
        capabilities::{
            CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures, ValidatedCapabilities,
        },
        msr::{TARGET_PHYSICAL_BITS, TARGET_SIGNATURE},
        registers::GuestRegisters,
    },
    memory::address::EncryptionState,
    svm::{
        configuration::{ConfigurationRoute, ScalarTarget},
        diagnostic_config::prepare_io,
        mmio,
        pci::{
            Bar, BarKind, Bridge, Bus, BusPolicy, ConfigOwner, Error, Function, FunctionSpec,
            Header, Interrupt, RefuseOwner, Region, Space, Transition, transport,
        },
        vmcb::Vmcb,
    },
};

const ECAM: u64 = 0xe000_0000;
const MEMORY: Region = Region { base: 0x8000_0000, bytes: 0x0100_0000 };

#[derive(Default)]
struct Record {
    commands: Vec<(u16, u16, u16)>,
    dma: Vec<(u16, u64, u64, bool)>,
    interrupts: Vec<(Interrupt, bool)>,
}

#[derive(Default)]
struct Owner {
    records: Rc<RefCell<Record>>,
    reject: Rc<Cell<bool>>,
    stale: Rc<Cell<bool>>,
}

impl ConfigOwner for Owner {
    fn admit(&mut self, _: BusPolicy, _: &[Region], _: &[Function]) -> Result<(), Error> {
        Ok(())
    }
    fn revalidate(&mut self) -> Result<(), Error> {
        if self.stale.get() { Err(Error::MissingOwner) } else { Ok(()) }
    }
    fn apply(&mut self, transition: Transition<'_>) -> Result<(), Error> {
        if self.reject.get() {
            return Err(Error::OwnerRejected);
        }
        self.records.borrow_mut().commands.push((
            transition.before.spec().bdf,
            transition.before.command(),
            transition.after.command(),
        ));
        Ok(())
    }
    fn dma(&mut self, bdf: u16, address: u64, bytes: u64, write: bool) -> Result<(), Error> {
        self.records.borrow_mut().dma.push((bdf, address, bytes, write));
        Ok(())
    }
    fn interrupt(&mut self, interrupt: Interrupt, asserted: bool) -> Result<(), Error> {
        self.records.borrow_mut().interrupts.push((interrupt, asserted));
        Ok(())
    }
}

fn policy() -> BusPolicy {
    BusPolicy {
        route: ConfigurationRoute::admit_target(
            TARGET_SIGNATURE,
            TARGET_PHYSICAL_BITS,
            ECAM | 0x21,
        )
        .unwrap(),
        memory: MEMORY,
        io: Region { base: 0x1000, bytes: 0xe000 },
    }
}

fn spec(bdf: u16) -> FunctionSpec {
    FunctionSpec {
        bdf,
        parent: None,
        vendor: 0x1234,
        device: 0x5678,
        class_code: 0xff0000,
        revision: 3,
        multifunction: false,
        header: Header::Endpoint { subsystem_vendor: 0xabcd, subsystem_device: 0x9012 },
        bars: [None; 6],
        msi: true,
        interrupt_pin: 1,
    }
}

fn bar(kind: BarKind, base: u64, bytes: u64) -> Bar {
    Bar { kind, initial_base: base, bytes, allowed: MEMORY }
}

fn read(bus: &mut Bus<'_>, bdf: u16, register: u16, width: u8) -> u32 {
    bus.access(ScalarTarget { bdf, register, width }, None).unwrap()
}

fn write(bus: &mut Bus<'_>, bdf: u16, register: u16, width: u8, value: u32) -> Result<u32, Error> {
    bus.access(ScalarTarget { bdf, register, width }, Some(value))
}

#[test]
fn enumeration_lanes_capability_chain_and_absence_share_one_bank() {
    let mut functions = [Function::new(spec(0x10)).unwrap()];
    let mut owner = Owner::default();
    let mut bus = Bus::new(policy(), &[], &mut functions, &mut owner).unwrap();
    assert_eq!(read(&mut bus, 0x10, 0, 4), 0x5678_1234);
    assert_eq!(read(&mut bus, 0x10, 1, 2), 0x7812);
    assert_eq!(read(&mut bus, 0x10, 0x34, 1), 0x40);
    assert_eq!(read(&mut bus, 0x10, 0x40, 4), 0x0080_0005);
    assert_eq!(read(&mut bus, 0x10, 0x41, 1), 0); // End of chain.
    assert_eq!(read(&mut bus, 0x10, 0x2c, 4), 0x9012_abcd);
    assert_eq!(read(&mut bus, 0x11, 0, 4), u32::MAX);
    assert_eq!(read(&mut bus, 0x11, 2, 2), 0xffff);
    write(&mut bus, 0x11, 4, 2, 4).unwrap(); // Explicit absent function write.
    write(&mut bus, 0x10, 0, 4, 0).unwrap();
    assert_eq!(read(&mut bus, 0x10, 0, 4), 0x5678_1234);
    for register in [0x80, 0x100, 0xffc] {
        assert_eq!(read(&mut bus, 0x10, register, 4), 0)
    }
    bus.io(0xcf8, 4, Some(0x8000_1000)).unwrap();
    assert_eq!(bus.io(0xcfc, 4, None), Ok(0x5678_1234));
    assert_eq!(bus.ecam(ECAM + (0x10 << 12), 4, None), Ok(0x5678_1234));
}

#[test]
fn bar_sizing_relocation_and_command_gate_real_virtual_decodes() {
    let mut device = spec(0x10);
    device.bars[0] = Some(bar(BarKind::Memory32 { prefetchable: false }, 0, 0x1000));
    device.bars[2] = Some(bar(BarKind::Memory64 { prefetchable: true }, 0, 0x20_0000));
    let mut functions = [Function::new(device).unwrap()];
    let mut owner = Owner::default();
    let records = owner.records.clone();
    let mut bus = Bus::new(policy(), &[], &mut functions, &mut owner).unwrap();
    for slot in [0x10, 0x18, 0x1c] {
        write(&mut bus, 0x10, slot, 4, u32::MAX).unwrap();
    }
    assert_eq!(read(&mut bus, 0x10, 0x10, 4), 0xffff_f000);
    assert_eq!(read(&mut bus, 0x10, 0x18, 4), 0xffe0_000c);
    assert_eq!(read(&mut bus, 0x10, 0x1c, 4), u32::MAX);
    assert_eq!(write(&mut bus, 0x10, 4, 2, 6), Err(Error::UnassignedBar));
    write(&mut bus, 0x10, 0x10, 4, 0x8000_0765).unwrap(); // Alignment/RO attributes.
    write(&mut bus, 0x10, 0x18, 4, 0x8040_0000).unwrap();
    write(&mut bus, 0x10, 0x1c, 4, 0).unwrap();
    assert_eq!(read(&mut bus, 0x10, 0x10, 4), 0x8000_0000);
    assert_eq!(bus.decode(Space::Memory, 0x8000_0020, 4), Err(Error::NoDecode));
    assert_eq!(bus.dma(0x10, 0x1234_5000, 8, true), Err(Error::BusMasterDisabled));
    write(&mut bus, 0x10, 4, 2, 6).unwrap();
    let decoded = bus.decode(Space::Memory, 0x8000_0020, 4).unwrap();
    assert_eq!((decoded.bdf, decoded.bar, decoded.offset, decoded.bytes), (0x10, 0, 0x20, 4));
    assert_eq!(bus.decode(Space::Memory, 0x8000_0fff, 2), Err(Error::NoDecode));
    bus.dma(0x10, 0x1234_5000, 8, true).unwrap();
    assert_eq!(records.borrow().dma, [(0x10, 0x1234_5000, 8, true)]);
    assert_eq!(write(&mut bus, 0x10, 0x10, 4, 0x8020_0000), Err(Error::DecodeEnabled));
    write(&mut bus, 0x10, 4, 2, 0).unwrap();
    assert_eq!(records.borrow().commands.last(), Some(&(0x10, 6, 0)));
    assert_eq!(bus.decode(Space::Memory, 0x8000_0020, 4), Err(Error::NoDecode));
}

#[test]
fn io_bar_masks_and_bme_are_independent_of_memory_decode() {
    let mut device = spec(0x10);
    device.bars[0] =
        Some(Bar { kind: BarKind::Io, bytes: 0x100, initial_base: 0x2000, allowed: policy().io });
    let mut functions = [Function::new(device).unwrap()];
    let mut owner = Owner::default();
    let mut bus = Bus::new(policy(), &[], &mut functions, &mut owner).unwrap();
    write(&mut bus, 0x10, 0x10, 4, u32::MAX).unwrap();
    assert_eq!(read(&mut bus, 0x10, 0x10, 4), 0xffff_ff01);
    write(&mut bus, 0x10, 0x10, 4, 0x2300).unwrap();
    write(&mut bus, 0x10, 4, 2, 1).unwrap();
    assert_eq!(bus.decode(Space::Io, 0x2345, 1).unwrap().offset, 0x45);
    assert_eq!(bus.decode(Space::Memory, 0x2345, 1), Err(Error::NoDecode));
    assert_eq!(bus.dma(0x10, 0x2000, 1, false), Err(Error::BusMasterDisabled));
}

#[test]
fn invalid_bar_enable_and_overlap_do_not_reach_owner() {
    let mut first = spec(0x10);
    first.bars[0] = Some(bar(BarKind::Memory32 { prefetchable: false }, 0x8000_0000, 0x1000));
    let mut second = first;
    second.bdf = 0x18;
    let mut functions = [Function::new(first).unwrap(), Function::new(second).unwrap()];
    let mut owner = Owner::default();
    let records = owner.records.clone();
    let mut bus = Bus::new(policy(), &[], &mut functions, &mut owner).unwrap();
    write(&mut bus, 0x10, 4, 2, 2).unwrap();
    let before = records.borrow().commands.len();
    assert_eq!(write(&mut bus, 0x18, 4, 2, 2), Err(Error::Overlap));
    assert_eq!(read(&mut bus, 0x18, 4, 2), 0);
    assert_eq!(records.borrow().commands.len(), before);
    write(&mut bus, 0x18, 0x10, 4, 0xffff_0000).unwrap();
    assert_eq!(write(&mut bus, 0x18, 4, 2, 4), Err(Error::OutsidePolicy));
    assert_eq!(write(&mut bus, 0x18, 4, 2, 0x40), Err(Error::UnsupportedControl));
    assert!(!bus.poisoned());
}

fn bridge_functions() -> [Function; 2] {
    let mut bridge = spec(8);
    bridge.class_code = 0x060400;
    bridge.header = Header::Bridge(Bridge {
        secondary: 1,
        subordinate: 1,
        memory: Some(MEMORY),
        io: Some(policy().io),
    });
    bridge.msi = false;
    let mut endpoint = spec(0x100);
    endpoint.parent = Some(8);
    endpoint.bars[0] = Some(bar(BarKind::Memory32 { prefetchable: false }, 0x8000_0000, 0x1000));
    [Function::new(bridge).unwrap(), Function::new(endpoint).unwrap()]
}

#[test]
fn bridge_windows_bus_visibility_and_upstream_bus_master_are_effective() {
    let mut functions = bridge_functions();
    let mut owner = Owner::default();
    let mut bus = Bus::new(policy(), &[], &mut functions, &mut owner).unwrap();
    assert_eq!(read(&mut bus, 8, 0x0e, 1), 1);
    assert_eq!(read(&mut bus, 8, 0x18, 4), 0x0001_0100);
    write(&mut bus, 0x100, 4, 2, 6).unwrap();
    assert_eq!(bus.decode(Space::Memory, 0x8000_0000, 4), Err(Error::NoDecode));
    write(&mut bus, 8, 0x20, 4, 0x8000_8000).unwrap(); // 80000000..800fffff.
    write(&mut bus, 8, 4, 2, 2).unwrap();
    assert_eq!(bus.decode(Space::Memory, 0x8000_0000, 4).unwrap().bdf, 0x100);
    assert_eq!(bus.dma(0x100, 0x1000, 4, true), Err(Error::BusMasterDisabled));
    write(&mut bus, 8, 4, 2, 6).unwrap();
    bus.dma(0x100, 0x1000, 4, true).unwrap();
    assert_eq!(write(&mut bus, 8, 0x3e, 2, 0x40), Err(Error::UnsupportedControl));
    write(&mut bus, 8, 4, 2, 0).unwrap();
    assert_eq!(write(&mut bus, 8, 0x19, 1, 2), Err(Error::UnsupportedBusChange));
    assert_eq!(write(&mut bus, 8, 0x20, 4, 0x9000_9000), Err(Error::OutsidePolicy));
    assert_eq!(read(&mut bus, 8, 0x20, 4), 0x8000_8000);
    write(&mut bus, 8, 0x1a, 1, 0).unwrap();
    assert_eq!(read(&mut bus, 0x100, 0, 4), u32::MAX);
    assert_eq!(bus.dma(0x100, 0x1000, 4, false), Err(Error::OutsidePolicy));
    write(&mut bus, 8, 0x1a, 1, 1).unwrap();
    assert_eq!(read(&mut bus, 0x100, 0, 4), 0x5678_1234);
}

#[test]
fn msi_and_intx_are_delivered_only_through_the_interrupt_owner() {
    let mut functions = [Function::new(spec(0x10)).unwrap()];
    let mut owner = Owner::default();
    let records = owner.records.clone();
    let mut bus = Bus::new(policy(), &[], &mut functions, &mut owner).unwrap();
    write(&mut bus, 0x10, 0x3c, 1, 17).unwrap();
    bus.interrupt(0x10, true).unwrap();
    assert_eq!(read(&mut bus, 0x10, 6, 2) & 8, 8);
    bus.interrupt(0x10, false).unwrap();
    write(&mut bus, 0x10, 4, 2, 0x400).unwrap();
    assert_eq!(bus.interrupt(0x10, true), Err(Error::InterruptDisabled));
    write(&mut bus, 0x10, 0x44, 4, 0xfee0_8003).unwrap();
    write(&mut bus, 0x10, 0x48, 4, 0x1234).unwrap();
    write(&mut bus, 0x10, 0x4c, 2, 0x71).unwrap();
    assert_eq!(write(&mut bus, 0x10, 0x42, 2, 0x91), Err(Error::UnsupportedControl));
    write(&mut bus, 0x10, 0x42, 1, 0x81).unwrap();
    assert_eq!(read(&mut bus, 0x10, 0x42, 2), 0x81);
    assert_eq!(bus.interrupt(0x10, true), Err(Error::BusMasterDisabled));
    write(&mut bus, 0x10, 4, 2, 0x404).unwrap(); // INTx disable does not mask MSI.
    bus.interrupt(0x10, true).unwrap();
    assert_eq!(
        records.borrow().interrupts,
        [
            (Interrupt::Intx { bdf: 0x10, pin: 1, line: 17 }, true),
            (Interrupt::Intx { bdf: 0x10, pin: 1, line: 17 }, false),
            (Interrupt::Msi { bdf: 0x10, address: 0x1234_fee0_8000, data: 0x71 }, true),
        ]
    );
}

#[test]
fn status_rw1c_respects_byte_lanes_and_preserves_command() {
    let mut functions = [Function::new(spec(0x10)).unwrap()];
    let mut owner = Owner::default();
    let mut bus = Bus::new(policy(), &[], &mut functions, &mut owner).unwrap();
    write(&mut bus, 0x10, 4, 2, 4).unwrap();
    bus.report_status(0x10, 0xf900).unwrap();
    write(&mut bus, 0x10, 7, 1, 0x20).unwrap();
    assert_eq!(read(&mut bus, 0x10, 4, 4), 0xd910_0004);
    write(&mut bus, 0x10, 6, 2, 0xffff).unwrap();
    assert_eq!(read(&mut bus, 0x10, 4, 4), 0x0010_0004);
}

#[test]
fn missing_owner_and_sensitive_or_malformed_operands_never_become_native_cycles() {
    let mut functions = [Function::new(spec(0x10)).unwrap()];
    assert!(matches!(
        Bus::new(policy(), &[], &mut functions, &mut RefuseOwner),
        Err(Error::MissingOwner)
    ));
    let mut owner = Owner::default();
    let mut bus = Bus::new(policy(), &[], &mut functions, &mut owner).unwrap();
    for bdf in [0, 0x10, 0x100] {
        for register in 0xb8..0xc0 {
            for write_value in [None, Some(0)] {
                assert_eq!(
                    bus.access(ScalarTarget { bdf, register, width: 1 }, write_value),
                    Err(Error::SensitiveControl)
                );
            }
        }
    }
    for (register, width) in [(3, 2), (0, 8), (4096, 4)] {
        assert_eq!(
            bus.access(ScalarTarget { bdf: 0x10, register, width }, None),
            Err(Error::InvalidAccess)
        );
    }
    assert!(bus.io(0xcfc, 4, None).is_err()); // ConfigEn=0 is not PCI absence.
    assert!(bus.io(0xcf9, 1, Some(6)).is_err());
    assert!(bus.io(0xcf8, 4, Some(0x8100_0000)).is_err());
    assert!(bus.ecam(ECAM - 1, 1, None).is_err());
}

#[test]
fn constructors_refuse_sensitive_functions_protected_resources_and_ambiguous_topology() {
    let mut host = spec(0);
    host.class_code = 0x060000;
    assert_eq!(Function::new(host), Err(Error::InvalidFunction));
    assert_eq!(Function::new(spec(0xc0)), Err(Error::InvalidFunction));
    let mut endpoint = spec(0x10);
    endpoint.bars[0] = Some(bar(BarKind::Memory64 { prefetchable: false }, 0x8000_0000, 4096));
    endpoint.bars[1] = Some(bar(BarKind::Memory32 { prefetchable: false }, 0x8000_1000, 4096));
    assert_eq!(Function::new(endpoint), Err(Error::InvalidBar));
    endpoint.bars[1] = None;
    let mut functions = [Function::new(endpoint).unwrap()];
    let mut owner = Owner::default();
    assert!(matches!(
        Bus::new(
            policy(),
            &[Region { base: 0x8000_0000, bytes: 4096 }],
            &mut functions,
            &mut owner
        ),
        Err(Error::OutsidePolicy)
    ));
    let mut orphan = [Function::new(spec(0x100)).unwrap()];
    assert!(matches!(
        Bus::new(policy(), &[], &mut orphan, &mut owner),
        Err(Error::InvalidTopology)
    ));
    let mut duplicate = [Function::new(spec(0x10)).unwrap(); 2];
    assert!(matches!(
        Bus::new(policy(), &[], &mut duplicate, &mut owner),
        Err(Error::DuplicateFunction)
    ));
}

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: test-owned inert VMCB and checked fixture offsets.
    unsafe {
        core::ptr::from_mut(vmcb).cast::<u8>().add(offset).cast::<u64>().write_unaligned(value);
    }
}

fn io_fixture(input: bool, port: u16, width: u8, value: u64) -> Vmcb {
    let mut vmcb = Vmcb::new();
    for (offset, value) in [
        (0x068, 1),
        (0x070, 0x7b),
        (0x078, u64::from(port) << 16 | u64::from(width) << 4 | u64::from(input)),
        (0x080, 0x4002),
        (0x0c8, u64::MAX),
        (0x410, 0x29b << 16),
        (0x4d0, 0x1500),
        (0x570, 0x10002),
        (0x578, 0x4000),
        (0x5f8, value),
    ] {
        put(&mut vmcb, offset, value);
    }
    vmcb
}

#[test]
fn prepared_io_commits_only_after_owner_effect_and_failure_poisoning_is_permanent() {
    let mut functions = [Function::new(spec(0x10)).unwrap()];
    let mut owner = Owner::default();
    let reject = owner.reject.clone();
    let records = owner.records.clone();
    let mut bus = Bus::new(policy(), &[], &mut functions, &mut owner).unwrap();
    let mut selector = io_fixture(false, 0xcf8, 4, 0x8000_1004);
    transport::complete_io(prepare_io(&mut selector).unwrap(), Some(&mut bus)).unwrap();
    let mut command = io_fixture(false, 0xcfc, 2, 4);
    transport::complete_io(prepare_io(&mut command).unwrap(), Some(&mut bus)).unwrap();
    assert_eq!(records.borrow().commands, [(0x10, 0, 4)]);
    assert_eq!(command.guest_rip(), 0x4002);
    let mut query = io_fixture(true, 0xcfc, 2, 0x1234_5678_aaaa_ffff);
    transport::complete_io(prepare_io(&mut query).unwrap(), Some(&mut bus)).unwrap();
    assert_eq!(query.guest_rax(), 0x1234_5678_aaaa_0004);
    reject.set(true);
    let mut disable = io_fixture(false, 0xcfc, 2, 0);
    let before = *disable.bytes();
    assert_eq!(
        transport::complete_io(prepare_io(&mut disable).unwrap(), Some(&mut bus)),
        Err(Error::OwnerRejected)
    );
    assert_eq!(*disable.bytes(), before);
    assert!(bus.poisoned());
    reject.set(false);
    assert_eq!(
        bus.access(ScalarTarget { bdf: 0x10, register: 4, width: 2 }, None),
        Err(Error::MissingOwner)
    );
    drop(bus);
    assert_eq!(functions[0].command(), 4);
}

#[test]
fn prepared_io_missing_owner_keeps_every_vmcb_byte() {
    let mut vmcb = io_fixture(true, 0xcfc, 4, 0xffff);
    let before = *vmcb.bytes();
    assert_eq!(
        transport::complete_io(prepare_io(&mut vmcb).unwrap(), None),
        Err(Error::MissingOwner)
    );
    assert_eq!(*vmcb.bytes(), before);
}

fn caps() -> ValidatedCapabilities {
    CapabilityEvidence {
        vendor: CpuVendor::Amd,
        svm: EvidenceFlag::Set,
        nested_paging: EvidenceFlag::Set,
        svm_revision: Some(1),
        asid_count: Some(16),
        physical_address_bits: Some(48),
        vm_cr_svmdis: EvidenceFlag::Clear,
        hypervisor_present: EvidenceFlag::Clear,
        encryption: EncryptionState::Unencrypted { encryption_bit: None },
        optional: OptionalFeatures { decode_assists: true, ..Default::default() },
    }
    .validate()
    .unwrap()
}

fn mmio_fixture(register: u16, write: bool, accumulator: bool) -> (Vmcb, GuestRegisters) {
    let gpa = ECAM + (0x10 << 12) + u64::from(register);
    let mut vmcb = Vmcb::new();
    for (offset, value) in [
        (0x068, 1),
        (0x070, 0x400),
        (0x078, (1 << 32) | 5 | if write { 2 } else { 0 }),
        (0x080, gpa),
        (0x090, 1),
        (0x0c8, u64::MAX),
        (0x410, 0x29b << 16),
        (0x4d0, 0x1500),
        (0x548, 0x20),
        (0x558, 0x8000_0011),
        (0x560, 0x400),
        (0x570, 0x10002),
        (0x578, 0x4000),
        (0x5f8, 4),
    ] {
        put(&mut vmcb, offset, value)
    }
    // MOV EAX,[RBX] / MOV [RBX],EAX (ECX when accumulator=false).
    let code: [u8; 2] = [if write { 0x89 } else { 0x8b }, if accumulator { 3 } else { 0x0b }];
    let encoded = u64::from(code[0]) << 8 | u64::from(code[1]) << 16 | 2;
    put(&mut vmcb, 0x0d0, encoded);
    (vmcb, GuestRegisters { rbx: gpa, ..Default::default() })
}

#[test]
fn ecam_preparer_and_effect_owner_share_legacy_state_without_opening_pages() {
    let mut functions = [Function::new(spec(0x10)).unwrap()];
    let mut owner = Owner::default();
    let mut bus = Bus::new(policy(), &[], &mut functions, &mut owner).unwrap();
    let (mut vmcb, mut frame) = mmio_fixture(4, true, true);
    let gpa = frame.rbx;
    let prepared = mmio::prepare(&mut vmcb, &mut frame, &caps(), |_, access| {
        assert_eq!(access.address, gpa);
        Ok::<_, ()>(gpa)
    })
    .unwrap();
    transport::complete_ecam(prepared, Some(&mut bus)).unwrap();
    assert_eq!(vmcb.guest_rip(), 0x4002);
    bus.io(0xcf8, 4, Some(0x8000_1004)).unwrap();
    assert_eq!(bus.io(0xcfc, 2, None), Ok(4));
    let (mut read, mut frame) = mmio_fixture(0, false, true);
    let gpa = frame.rbx;
    let prepared = mmio::prepare(&mut read, &mut frame, &caps(), |_, _| Ok::<_, ()>(gpa)).unwrap();
    transport::complete_ecam(prepared, Some(&mut bus)).unwrap();
    assert_eq!(read.guest_rax(), 0x5678_1234);
    for (register, accumulator, expected) in
        [(0, false, Error::NonAccumulator), (0xb8, true, Error::SensitiveControl)]
    {
        let (mut vmcb, mut frame) = mmio_fixture(register, true, accumulator);
        let before = *vmcb.bytes();
        let gpa = frame.rbx;
        let prepared =
            mmio::prepare(&mut vmcb, &mut frame, &caps(), |_, _| Ok::<_, ()>(gpa)).unwrap();
        assert_eq!(transport::complete_ecam(prepared, Some(&mut bus)), Err(expected));
        assert_eq!(*vmcb.bytes(), before);
    }
}

#[test]
fn owner_lifetime_loss_stops_even_read_only_enumeration() {
    let mut functions = [Function::new(spec(0x10)).unwrap()];
    let mut owner = Owner::default();
    let stale = owner.stale.clone();
    let mut bus = Bus::new(policy(), &[], &mut functions, &mut owner).unwrap();
    stale.set(true);
    assert_eq!(bus.ecam(ECAM + (0x10 << 12), 4, None), Err(Error::MissingOwner));
    assert!(bus.poisoned());
    stale.set(false);
    assert_eq!(bus.ecam(ECAM + (0x10 << 12), 4, None), Err(Error::MissingOwner));
}
