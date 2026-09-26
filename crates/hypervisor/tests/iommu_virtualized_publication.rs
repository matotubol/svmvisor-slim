//! The virtual device consumes receipts issued by the actual owner transaction,
//! with copied guest tables composed into retained host pages by its backend.
//! All register/queue/DMA effects are a deterministic model, never native I/O.
#[path = "ownership_support/mod.rs"]
mod ownership_support;

use ownership_support::{Fixture, Mock, Sim, limits, policy};
use std::{cell::RefCell, rc::Rc};
use svmvisor_hypervisor::{
    firmware::native::resident::iommu::{
        RegisterObservation,
        binding::UnitIdentity,
        ownership::{
            Backend, BackendError, Fence, Plan, PublicationSlot, Register, Step as OwnerStep,
            Transaction, UnitPlan,
        },
    },
    memory::iommu::{
        host_walk,
        image::{MappingRange, ProtectedRange, TablePage},
        physical::{DrainReceipt, PublicationKey},
        tables::{HostDeviceEntry, PageCoherency, Permissions},
        virtualized::{
            compose::{self, GuestHostRange, HostMap},
            device::{
                CommandError, Device, DeviceError, Event, FaultAccess, FaultReason, GuestFault,
                GuestRam, MemoryError, PhysicalWork, Step, WorkKind, WriteResult,
                guest_ring_register,
            },
            guest::DeviceEntry,
            registers,
            snapshot::{Dependencies, Dependency, Snapshot, SnapshotPage, TrackedSnapshot},
        },
    },
};

const HOST: u64 = 0x8000_0000;
const RW: u64 = 3 << 61;
const CONTROL: u64 = 1 | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 10) | (1 << 12);
const EMPTY_MAPPING: MappingRange = MappingRange {
    io_base: 0,
    system_base: 0,
    len: 0,
    permissions: Permissions::None,
    coherency: PageCoherency::Inherit,
};

fn page(gpa: u64, words: &[(usize, u64)]) -> SnapshotPage {
    let mut bytes = [0; 4096];
    for &(index, value) in words {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    SnapshotPage::copy(gpa, HOST + gpa, &bytes).unwrap()
}

fn sources() -> Vec<SnapshotPage> {
    vec![page(0x1000, &[(0, 0x2000 | (1 << 9) | RW | 1)]), page(0x2000, &[(9, 0x50000 | RW | 1)])]
}

fn host_ranges() -> [GuestHostRange; 2] {
    [
        GuestHostRange {
            guest_base: 0,
            host_base: HOST,
            len: 0x100000,
            permissions: Permissions::ReadWrite,
        },
        GuestHostRange {
            guest_base: 0x100000,
            host_base: HOST + 0x1000,
            len: 4096,
            permissions: Permissions::ReadWrite,
        },
    ]
}

#[derive(Default)]
struct CompositionState {
    staged: Option<PhysicalWork>,
    enabled: bool,
    installed: Vec<(PublicationKey, u64, Option<u64>)>,
}

struct ComposingBackend {
    inner: Mock,
    state: Rc<RefCell<CompositionState>>,
    slots: [Vec<TablePage>; 2],
    active_device: Option<HostDeviceEntry>,
    source_pages: Vec<SnapshotPage>,
}

impl ComposingBackend {
    fn new(inner: Mock) -> Self {
        Self {
            inner,
            state: Rc::new(RefCell::new(CompositionState::default())),
            slots: [vec![TablePage::ZERO; 16], vec![TablePage::ZERO; 16]],
            active_device: None,
            source_pages: sources(),
        }
    }
}

impl Backend for ComposingBackend {
    fn acquire(&mut self, epoch: u64, plan: &Plan) -> Result<(), BackendError> {
        self.inner.acquire(epoch, plan)
    }
    fn verify_and_publish_bank(&mut self, unit: &UnitPlan) -> Result<(), BackendError> {
        self.inner.verify_and_publish_bank(unit)
    }
    fn request_quiescence(&mut self, unit: UnitIdentity, epoch: u64) -> Result<(), BackendError> {
        self.inner.request_quiescence(unit, epoch)
    }
    fn poll_quiescence(&mut self, unit: UnitIdentity, epoch: u64) -> Result<bool, BackendError> {
        self.inner.poll_quiescence(unit, epoch)
    }
    fn observe(
        &mut self,
        unit: UnitIdentity,
        epoch: u64,
    ) -> Result<RegisterObservation, BackendError> {
        self.inner.observe(unit, epoch)
    }
    fn write_command(
        &mut self,
        unit: UnitIdentity,
        address: u64,
        words: [u64; 2],
    ) -> Result<(), BackendError> {
        self.inner.write_command(unit, address, words)
    }
    fn read_completion(&mut self, unit: UnitIdentity, address: u64) -> Result<u64, BackendError> {
        self.inner.read_completion(unit, address)
    }
    fn fence(&mut self, unit: UnitIdentity, fence: Fence) -> Result<(), BackendError> {
        self.inner.fence(unit, fence)
    }
    fn write_register(
        &mut self,
        unit: UnitIdentity,
        register: Register,
        value: u64,
    ) -> Result<(), BackendError> {
        self.inner.write_register(unit, register, value)
    }

    fn publish_composed(
        &mut self,
        key: PublicationKey,
        unit: &UnitPlan,
        slot: PublicationSlot,
    ) -> Result<(), BackendError> {
        let mut state = self.state.borrow_mut();
        let work =
            state.staged.take().filter(|work| work.key == key).ok_or(BackendError::Composition)?;
        let enabled = match work.kind {
            WorkKind::Registers { after, .. } => after.enabled(),
            WorkKind::Reset => false,
            WorkKind::Command(_) | WorkKind::TableWrite { .. } => state.enabled,
        };
        let tracked =
            TrackedSnapshot::new(&self.source_pages).map_err(|_| BackendError::Composition)?;
        let ranges = host_ranges();
        // Includes all old/current retained owner resources and both output
        // generations; these addresses cannot be emitted as device outputs.
        let protected = [ProtectedRange { base: 0x1000_0000, len: 0x2400_0000 }];
        let host =
            HostMap::new(policy(), &ranges, &protected).map_err(|_| BackendError::Composition)?;
        let device = DeviceEntry::decode([3 | (4 << 9) | 0x1000 | RW, 11, 0, 0]).unwrap();
        let mut output = [EMPTY_MAPPING; 32];
        let mut dependencies = [Dependency::EMPTY; 8];
        let composed = compose::compose(
            &tracked,
            device,
            enabled,
            None,
            &host,
            &mut output,
            &mut Dependencies::new(&mut dependencies),
        )
        .map_err(|_| BackendError::Composition)?;
        let index = ((key.generation - 1) % 2) as usize;
        assert_eq!(slot.destination().len(), 16 * 4096);
        let image = composed
            .build_image(policy(), slot.destination().base(), &mut self.slots[index], &protected)
            .map_err(|_| BackendError::Composition)?;
        let physical =
            HostDeviceEntry::new(policy(), image.root_address(), 100, Permissions::ReadWrite)
                .map_err(|_| BackendError::Composition)?;
        let mapping = host_walk::walk(policy(), physical, 0x9123, |address| {
            image.read_word(address).ok_or(address)
        })
        .map_err(|_| BackendError::Composition)?
        .map(|translation| translation.system_address);
        if enabled && mapping != Some(HOST + 0x50123) {
            return Err(BackendError::Composition);
        }
        // The model has one active physical requester link and replaces it in
        // full. Both slot allocations are retained by this backend throughout.
        self.active_device = Some(physical);
        state.enabled = enabled;
        state.installed.push((key, image.root_address(), mapping));
        drop(state);
        self.inner.publish_composed(key, unit, slot)
    }
}

fn finish<B: Backend>(transaction: &mut Transaction<'_, B>) -> OwnerStep {
    for _ in 0..1100 {
        match transaction.step(1) {
            OwnerStep::Progress | OwnerStep::Pending => (),
            result => return result,
        }
    }
    panic!("bounded owner did not finish")
}

fn stage(state: &Rc<RefCell<CompositionState>>, work: PhysicalWork) {
    state.borrow_mut().staged = Some(work);
}

fn publish(
    transaction: &mut Transaction<'_, ComposingBackend>,
    state: &Rc<RefCell<CompositionState>>,
    work: PhysicalWork,
) -> DrainReceipt {
    stage(state, work);
    transaction.begin_publication(work.key, 1).unwrap();
    assert_eq!(finish(transaction), OwnerStep::Complete);
    transaction.mapping_receipt(work.key).unwrap()
}

fn enabled_device(
    transaction: &mut Transaction<'_, ComposingBackend>,
    state: &Rc<RefCell<CompositionState>>,
    memory: &mut GuestRam<'_>,
) -> Device {
    let unit = transaction.plan().units().next().unwrap().binding.identity.into();
    let mut device = Device::new(unit, 9);
    device.write(0, 8, 0x1000).unwrap();
    device.write(8, 8, guest_ring_register(0x3000, 8).unwrap()).unwrap();
    device.write(16, 8, guest_ring_register(0x4000, 8).unwrap()).unwrap();
    let WriteResult::Pending(work) = device.write(24, 8, CONTROL).unwrap() else { panic!() };
    let receipt = publish(transaction, state, work);
    device.complete(&receipt, memory).unwrap();
    device
}

fn retire_last_wait(sim: &Rc<RefCell<Sim>>) {
    let mut sim = sim.borrow_mut();
    let words = sim
        .commands
        .values()
        .filter(|words| words[0] >> 60 == 1)
        .max_by_key(|words| words[1])
        .copied()
        .unwrap();
    sim.completions.insert(words[0] & 0x000f_ffff_ffff_fff8, words[1]);
    sim.fetch_only = false;
}

#[test]
fn real_composition_and_owner_receipt_gate_virtual_store_and_msi() {
    let fixture = Fixture::new(1);
    let mut backend = ComposingBackend::new(fixture.backend());
    let state = Rc::clone(&backend.state);
    let sim = Rc::clone(&backend.inner.shared);
    let mut transaction =
        Transaction::new(&mut backend, fixture.plan.clone(), 9, 0, limits()).unwrap();
    assert_eq!(finish(&mut transaction), OwnerStep::Complete);
    let takeover = transaction.receipt(0).unwrap();
    let pages = sources();
    let tracked = TrackedSnapshot::new(&pages).unwrap();
    let ranges = host_ranges();
    let host = HostMap::new(policy(), &ranges, &[]).unwrap();
    let mut ram = vec![0; 0x101000];
    let mut memory = GuestRam::from_tracked(0, &mut ram, &tracked, &host).unwrap();
    let mut device = enabled_device(&mut transaction, &state, &mut memory);
    let command_pages = [page(
        0x3000,
        &[
            (0, (3 << 60) | (11 << 32)),
            (1, 0x7fff_ffff_ffff_f003),
            (2, (1 << 60) | 0x6000 | 7),
            (3, 0x1234_5678),
        ],
    )];
    let commands = Snapshot::new(&command_pages).unwrap();
    device.write(0x2008, 8, 32).unwrap();
    let Step::Pending(invalidate) = device.step(&commands, &mut memory).unwrap() else { panic!() };
    assert_eq!(device.read(0x2000, 8).unwrap(), 16);
    let fault = Event::io_page_fault(GuestFault {
        device: 0x200,
        domain: 11,
        device_address: 0xdead_0000,
        access: FaultAccess::Write,
        reason: FaultReason::Permission,
    });
    device.log_event(&mut memory, fault).unwrap();
    assert_eq!(device.read(0x2018, 8).unwrap(), 16);
    let invalidate_receipt = publish(&mut transaction, &state, invalidate);
    device.complete(&invalidate_receipt, &mut memory).unwrap();
    // Regression: committing pending physical work must not roll back an
    // asynchronously logged event, its tail, or its interrupt status.
    assert_eq!(device.read(0x2018, 8).unwrap(), 16);
    assert_eq!(device.read(0x2020, 8).unwrap() & registers::EVENT_INT, registers::EVENT_INT);
    assert_eq!(&memory.bytes()[0x4000..0x4008], &fault.words()[0].to_le_bytes());
    assert_eq!(&memory.bytes()[0x4008..0x4010], &0xdead_0000u64.to_le_bytes());
    assert!(device.take_interrupt());
    device.write(0x2020, 1, registers::EVENT_INT).unwrap();

    let Step::Pending(wait) = device.step(&commands, &mut memory).unwrap() else { panic!() };
    assert_eq!(device.read(0x2000, 8).unwrap(), 32);
    assert_eq!(device.complete(&takeover, &mut memory), Err(DeviceError::WrongReceipt));
    assert_eq!(device.complete(&invalidate_receipt, &mut memory), Err(DeviceError::WrongReceipt));
    sim.borrow_mut().fetch_only = true;
    stage(&state, wait);
    transaction.begin_publication(wait.key, 1).unwrap();
    // Quiescence checks precede the actual publication phase.
    for _ in 0..10 {
        assert!(matches!(transaction.step(1), OwnerStep::Progress | OwnerStep::Pending));
        if sim.borrow().published.contains(&wait.key) {
            break;
        }
    }
    assert!(transaction.mapping_receipt(wait.key).is_none());
    assert_eq!(transaction.step(1), OwnerStep::Pending);
    assert_eq!(&memory.bytes()[0x6000..0x6008], &[0; 8]);
    assert!(!device.take_interrupt());
    assert_eq!(device.read(0x2020, 8).unwrap() & registers::COMPLETION_INT, 0);
    retire_last_wait(&sim);
    assert_eq!(finish(&mut transaction), OwnerStep::Complete);
    let receipt = transaction.mapping_receipt(wait.key).unwrap();
    device.complete(&receipt, &mut memory).unwrap();
    assert_eq!(&memory.bytes()[0x6000..0x6008], &0x1234_5678u64.to_le_bytes());
    assert!(device.take_interrupt());
    assert_eq!(device.complete(&receipt, &mut memory), Err(DeviceError::NoPending));
    assert_eq!(state.borrow().installed.len(), 3);
    assert!(
        state.borrow().installed.iter().all(|(_, _, mapping)| *mapping == Some(HOST + 0x50123))
    );
    assert!(sim.borrow().commands.values().all(|words| matches!(words[0] >> 60, 1 | 8)));
    assert!(
        sim.borrow()
            .commands
            .values()
            .filter(|words| words[0] >> 60 == 1)
            .all(|words| words[0] & 0x000f_ffff_ffff_fff8 != 0x6000)
    );
}

#[test]
fn command_errors_stop_without_advancing_and_event_overflow_requires_restart() {
    let fixture = Fixture::new(1);
    let mut backend = ComposingBackend::new(fixture.backend());
    let state = Rc::clone(&backend.state);
    let mut transaction =
        Transaction::new(&mut backend, fixture.plan.clone(), 9, 0, limits()).unwrap();
    assert_eq!(finish(&mut transaction), OwnerStep::Complete);
    let mut ram = vec![0; 0x10000];
    let mut memory = GuestRam::new(0, &mut ram, &[]).unwrap();
    let mut device = enabled_device(&mut transaction, &state, &mut memory);
    let invalid = [page(0x3000, &[(0, 6 << 60)])];
    let snapshot = Snapshot::new(&invalid).unwrap();
    device.write(0x2008, 8, 16).unwrap();
    assert_eq!(
        device.step(&snapshot, &mut memory).unwrap(),
        Step::IllegalCommand(CommandError::Opcode(6))
    );
    assert_eq!(device.read(0x2000, 8).unwrap(), 0);
    assert!(!device.registers().command_running());
    assert_eq!(&memory.bytes()[0x4000..0x4008], &(5u64 << 60).to_le_bytes());
    assert_eq!(&memory.bytes()[0x4008..0x4010], &0x3000u64.to_le_bytes());
    // A low-byte control write cannot restart CmdBufEn in the untouched lane.
    device.write(0x18, 1, CONTROL & 255).unwrap();
    assert!(!device.registers().command_running());
    device.write(0x19, 1, (CONTROL >> 8) & 255).unwrap();
    assert!(device.registers().command_running());
    let empty = Snapshot::new(&[]).unwrap();
    assert!(matches!(device.step(&empty, &mut memory).unwrap(), Step::CommandMemoryFault(_)));
    assert!(!device.registers().command_running());
    assert_eq!(&memory.bytes()[0x4010..0x4018], &((6u64 << 60) | (1 << 57)).to_le_bytes());
    assert_eq!(&memory.bytes()[0x4018..0x4020], &0x3000u64.to_le_bytes());
    // HESup is not exposed, so optional hardware error registers remain zero.
    assert_eq!(device.read(0x40, 8).unwrap(), 0);

    device.write(0x18, 8, 1).unwrap();
    device.write(0x10, 8, guest_ring_register(0x4000, 8).unwrap()).unwrap();
    device.write(0x18, 8, CONTROL & !registers::COMMAND_EN).unwrap();
    for _ in 0..255 {
        device.log_event(&mut memory, Event::illegal_command(0x3000)).unwrap();
    }
    assert_eq!(device.read(0x2018, 8).unwrap(), 4080);
    device.log_event(&mut memory, Event::illegal_command(0x3000)).unwrap();
    assert!(!device.registers().event_running());
    assert_ne!(device.registers().status() & registers::EVENT_OVERFLOW, 0);
    device.write(0x2020, 1, registers::EVENT_OVERFLOW).unwrap();
    assert!(!device.registers().event_running());
    device.log_event(&mut memory, Event::illegal_command(0x3000)).unwrap();
    assert_eq!(device.read(0x2018, 8).unwrap(), 4080);
    device.write(0x2010, 8, 16).unwrap();
    device.write(0x18, 1, CONTROL & 255).unwrap();
    // Unlike CmdBufEn, rewriting EventLogEn=1 is explicitly ineffective.
    assert!(!device.registers().event_running());
    device.write(0x18, 1, (CONTROL & 255) & !registers::EVENT_EN).unwrap();
    device.write(0x18, 1, CONTROL & 255).unwrap();
    assert!(device.registers().event_running());
    device.log_event(&mut memory, Event::illegal_command(0x3000)).unwrap();
    assert_eq!(device.read(0x2018, 8).unwrap(), 0);
}

#[test]
fn completion_store_to_a_new_guest_alias_of_table_memory_is_refused() {
    let fixture = Fixture::new(1);
    let mut backend = ComposingBackend::new(fixture.backend());
    let state = Rc::clone(&backend.state);
    let mut transaction =
        Transaction::new(&mut backend, fixture.plan.clone(), 9, 0, limits()).unwrap();
    assert_eq!(finish(&mut transaction), OwnerStep::Complete);
    let pages = sources();
    let tracked = TrackedSnapshot::new(&pages).unwrap();
    let ranges = host_ranges();
    let host = HostMap::new(policy(), &ranges, &[]).unwrap();
    let mut ram = vec![0; 0x101000];
    let mut memory = GuestRam::from_tracked(0, &mut ram, &tracked, &host).unwrap();
    let mut device = enabled_device(&mut transaction, &state, &mut memory);
    let command_pages = [page(0x3000, &[(0, (1 << 60) | 0x100000 | 7), (1, 99)])];
    device.write(0x18, 8, CONTROL & !registers::EVENT_EN).unwrap();
    device.write(0x10, 8, guest_ring_register(0x100000, 8).unwrap()).unwrap();
    device.write(0x18, 8, CONTROL).unwrap();
    assert_eq!(
        device.log_event(&mut memory, Event::illegal_command(0x3000)),
        Err(DeviceError::Memory(MemoryError::ReadOnly))
    );
    assert_eq!(device.read(0x2018, 8).unwrap(), 0);
    assert_eq!(&memory.bytes()[0x100000..0x100010], &[0; 16]);
    let commands = Snapshot::new(&command_pages).unwrap();
    device.write(0x2008, 8, 16).unwrap();
    let Step::Pending(work) = device.step(&commands, &mut memory).unwrap() else { panic!() };
    let receipt = publish(&mut transaction, &state, work);
    assert_eq!(
        device.complete(&receipt, &mut memory),
        Err(DeviceError::Memory(MemoryError::ReadOnly))
    );
    assert_eq!(&memory.bytes()[0x100000..0x100008], &[0; 8]);
    assert!(device.pending().is_some());
    assert!(!device.take_interrupt());
    assert!(tracked.snapshot().is_ok());
}
