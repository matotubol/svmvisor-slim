#![allow(dead_code)]
use std::{
    alloc::{Layout, alloc_zeroed, handle_alloc_error},
    cell::RefCell,
    collections::BTreeMap,
    rc::Rc,
    sync::Arc,
};
use svmvisor_hypervisor::{
    firmware::native::resident::iommu::{
        ObservationState, PciObservation, RegisterObservation, Report, UnitObservation,
        binding::{UninstalledBindingPlan, UnitAssignment, UnitIdentity, bind},
        ownership::{
            Backend, BackendError, BankStorage, Coverage, Fence, Limits, Phase, Plan,
            PublicationKey, PublicationSlot, PublicationSpace, Register, Step, Transaction,
            UnitPlan, prepare_banks,
        },
        resources::ResourceStorage,
    },
    host::resident::IOMMU_RESOURCE_BYTES,
    memory::{
        address::{AddressPolicy, EncryptionState, PhysicalRange},
        iommu::discover,
    },
};

pub fn policy() -> AddressPolicy {
    AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}
pub fn range(base: u64, bytes: u64) -> PhysicalRange {
    policy().validate(base, bytes, 4096).unwrap()
}
pub fn bank_base(index: usize) -> u64 {
    0x1000_0000 + index as u64 * 0x400000
}
pub fn old_base(index: usize) -> u64 {
    0x3000_0000 + index as u64 * 0x400000
}
pub fn pool() -> PhysicalRange {
    range(0x1000_0000, 0x400_0000)
}

pub fn empty_bank() -> Box<ResourceStorage> {
    let layout = Layout::new::<ResourceStorage>();
    let raw = unsafe { alloc_zeroed(layout) };
    if raw.is_null() {
        handle_alloc_error(layout);
    }
    // Integer-only disconnected fixture storage; never supplied to hardware.
    unsafe { Box::from_raw(raw.cast()) }
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

pub fn report(count: usize) -> Report {
    report_with_mmio_stride(count, 0x4000)
}

pub fn report_with_mmio_stride(count: usize, stride: u64) -> Report {
    report_with_mmio_base(count, 0xfd00_0000, stride)
}

pub fn report_with_mmio_base(count: usize, first_mmio: u64, stride: u64) -> Report {
    let mut ivrs = sdt(b"IVRS", 48 + 28 * count);
    for index in 0..count {
        let start = 48 + 28 * index;
        ivrs[start] = 0x10;
        set16(&mut ivrs, start + 2, 28);
        set16(&mut ivrs, start + 4, 0x100 + index as u16);
        set16(&mut ivrs, start + 6, 0x40);
        set64(&mut ivrs, start + 8, first_mmio + index as u64 * stride);
        ivrs[start + 24] = 2;
        set16(&mut ivrs, start + 25, 0x200 + index as u16);
    }
    checksum(&mut ivrs);
    let mut mcfg = sdt(b"MCFG", 60);
    set64(&mut mcfg, 44, 0xe000_0000);
    mcfg[55] = 255;
    checksum(&mut mcfg);
    let mut out = Report::EMPTY;
    out.tables = discover(&ivrs, &mcfg).unwrap();
    out.state = ObservationState::Observed;
    for index in 0..count {
        let base = first_mmio + index as u64 * stride;
        out.hardware[index] = UnitObservation {
            pci: Some(PciObservation {
                config_page: 0xe010_0000 + index as u64 * 4096,
                vendor_device: 0x1649_1022,
                command_status: 1 << 20,
                class_revision: 0x0806_0000,
                capability_header: 0x080b_000f,
                base_low: base as u32 | 1,
                base_high: 0,
                range: 0,
                miscellaneous0: (48 << 15) | (48 << 8),
                miscellaneous1: None,
            }),
            mmio_bytes: Some(0x4000),
            error: None,
            registers: Some(RegisterObservation {
                device_table: old_base(index) | 511,
                command_buffer: old_base(index) + 0x200000 | (8 << 56),
                event_log: old_base(index) + 0x201000 | (8 << 56),
                control: 1 | (1 << 2) | (1 << 10) | (1 << 12),
                exclusion_base: 0,
                exclusion_limit: 0,
                extended_features: Some(1 << 6),
                extended_features2: Some(0),
                command_head: 0,
                command_tail: 0,
                event_head: 0,
                event_tail: 0,
                status: (1 << 3) | (1 << 4),
            }),
        };
    }
    out
}

pub struct Fixture {
    pub report: Report,
    pub banks: Vec<Arc<ResourceStorage>>,
    pub binding: UninstalledBindingPlan,
    pub publications: Vec<PublicationSpace>,
    pub plan: Plan,
}

impl Fixture {
    pub fn rebind(&mut self) {
        let assignments: Vec<_> = self
            .banks
            .iter()
            .enumerate()
            .map(|(index, bank)| UnitAssignment {
                identity: UnitIdentity::from_unit(self.report.tables.ivrs.units()[index]),
                extent: range(bank_base(index), IOMMU_RESOURCE_BYTES),
                storage: bank,
            })
            .collect();
        self.binding = bind(policy(), &self.report, pool(), &assignments).unwrap();
        let ram = [range(0x1000_0000, 0x2400_0000)];
        let controls = [range(0xe000_0000, 0x2000_0000)];
        self.plan =
            Plan::prepare(policy(), &self.binding, coverage(&ram, &controls), &self.publications)
                .unwrap();
    }
    pub fn new(count: usize) -> Self {
        let report = report(count);
        let mut banks: Vec<_> = (0..count).map(|_| empty_bank()).collect();
        let mut assignments: Vec<_> = banks
            .iter_mut()
            .enumerate()
            .map(|(index, bank)| BankStorage {
                identity: UnitIdentity::from_unit(report.tables.ivrs.units()[index]),
                extent: range(bank_base(index), IOMMU_RESOURCE_BYTES),
                storage: bank,
            })
            .collect();
        prepare_banks(policy(), &report, pool(), &mut assignments).unwrap();
        drop(assignments);
        let banks: Vec<Arc<ResourceStorage>> = banks.into_iter().map(Arc::from).collect();
        let assignments: Vec<_> = banks
            .iter()
            .enumerate()
            .map(|(index, bank)| UnitAssignment {
                identity: UnitIdentity::from_unit(report.tables.ivrs.units()[index]),
                extent: range(bank_base(index), IOMMU_RESOURCE_BYTES),
                storage: bank,
            })
            .collect();
        let binding = bind(policy(), &report, pool(), &assignments).unwrap();
        let publications: Vec<_> = binding
            .units()
            .enumerate()
            .map(|(index, unit)| PublicationSpace {
                identity: unit.identity,
                generations: [
                    range(0x2000_0000 + index as u64 * 0x200000, 0x10000),
                    range(0x2001_0000 + index as u64 * 0x200000, 0x10000),
                ],
                required_bytes: 0x10000,
            })
            .collect();
        let all_ram = [range(0x1000_0000, 0x2400_0000)];
        let controls = [range(0xe000_0000, 0x2000_0000)];
        let plan = Plan::prepare(policy(), &binding, coverage(&all_ram, &controls), &publications)
            .unwrap();
        Self { report, banks, binding, publications, plan }
    }

    pub fn backend(&self) -> Mock {
        Mock {
            banks: self.banks.clone(),
            shared: Rc::new(RefCell::new(Sim {
                registers: self.plan.units().map(|u| u.binding.observed_registers).collect(),
                effects: vec![],
                commands: BTreeMap::new(),
                completions: BTreeMap::new(),
                fail_at: None,
                fetch_only: false,
                quiesced: true,
                stop_pending: false,
                start_pending: false,
                epoch_lost: false,
                published: vec![],
                slots: vec![],
                readonly_control: 0,
            })),
        }
    }
}

pub fn coverage<'a>(ram: &'a [PhysicalRange], controls: &'a [PhysicalRange]) -> Coverage<'a> {
    Coverage {
        protected: ram,
        cpu_denied: ram,
        dma_denied: ram,
        retained: ram,
        writable_wb: ram,
        control_denied: controls,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    Acquire,
    Quiesce(usize),
    Quiescence(usize),
    Verify(usize),
    Observe(usize),
    Command(usize, u64, [u64; 2]),
    ReadCompletion(usize, u64),
    Fence(usize, Fence),
    Write(usize, Register, u64),
    Compose(PublicationKey),
}

pub struct Sim {
    pub registers: Vec<RegisterObservation>,
    pub effects: Vec<Effect>,
    pub commands: BTreeMap<u64, [u64; 2]>,
    pub completions: BTreeMap<u64, u64>,
    pub fail_at: Option<usize>,
    pub fetch_only: bool,
    pub quiesced: bool,
    pub stop_pending: bool,
    pub start_pending: bool,
    pub epoch_lost: bool,
    pub published: Vec<PublicationKey>,
    pub slots: Vec<PublicationSlot>,
    pub readonly_control: u64,
}
impl Sim {
    fn effect(&mut self, effect: Effect) -> Result<(), BackendError> {
        self.effects.push(effect);
        if self.fail_at == Some(self.effects.len() - 1) {
            Err(BackendError::Device)
        } else if self.epoch_lost {
            Err(BackendError::ControlLost)
        } else {
            Ok(())
        }
    }
}
pub struct Mock {
    banks: Vec<Arc<ResourceStorage>>,
    pub shared: Rc<RefCell<Sim>>,
}
fn index(unit: UnitIdentity) -> usize {
    usize::from(unit.device_id - 0x100)
}

impl Backend for Mock {
    fn acquire(&mut self, _epoch: u64, _plan: &Plan) -> Result<(), BackendError> {
        self.shared.borrow_mut().effect(Effect::Acquire)
    }
    fn verify_and_publish_bank(&mut self, unit: &UnitPlan) -> Result<(), BackendError> {
        let index = index(unit.binding.identity);
        self.banks[index]
            .verify(policy(), unit.binding.bank.base())
            .map_err(|_| BackendError::Memory)?;
        self.shared.borrow_mut().effect(Effect::Verify(index))
    }
    fn request_quiescence(&mut self, unit: UnitIdentity, _epoch: u64) -> Result<(), BackendError> {
        self.shared.borrow_mut().effect(Effect::Quiesce(index(unit)))
    }
    fn poll_quiescence(&mut self, unit: UnitIdentity, _epoch: u64) -> Result<bool, BackendError> {
        let mut state = self.shared.borrow_mut();
        state.effect(Effect::Quiescence(index(unit)))?;
        Ok(state.quiesced)
    }
    fn observe(
        &mut self,
        unit: UnitIdentity,
        _epoch: u64,
    ) -> Result<RegisterObservation, BackendError> {
        let mut state = self.shared.borrow_mut();
        state.effect(Effect::Observe(index(unit)))?;
        let mut observed = state.registers[index(unit)];
        observed.control |= state.readonly_control;
        Ok(observed)
    }
    fn write_command(
        &mut self,
        unit: UnitIdentity,
        address: u64,
        words: [u64; 2],
    ) -> Result<(), BackendError> {
        let mut state = self.shared.borrow_mut();
        state.commands.insert(address, words);
        state.effect(Effect::Command(index(unit), address, words))
    }
    fn read_completion(&mut self, unit: UnitIdentity, address: u64) -> Result<u64, BackendError> {
        let mut state = self.shared.borrow_mut();
        state.effect(Effect::ReadCompletion(index(unit), address))?;
        Ok(*state.completions.get(&address).unwrap_or(&0))
    }
    fn fence(&mut self, unit: UnitIdentity, fence: Fence) -> Result<(), BackendError> {
        self.shared.borrow_mut().effect(Effect::Fence(index(unit), fence))
    }
    fn write_register(
        &mut self,
        unit: UnitIdentity,
        register: Register,
        value: u64,
    ) -> Result<(), BackendError> {
        let index = index(unit);
        let mut state = self.shared.borrow_mut();
        match register {
            Register::DeviceTable => state.registers[index].device_table = value,
            Register::CommandBase => state.registers[index].command_buffer = value,
            Register::EventBase => state.registers[index].event_log = value,
            Register::EventHead => state.registers[index].event_head = value,
            Register::EventTail => state.registers[index].event_tail = value,
            Register::CommandHead => state.registers[index].command_head = value,
            Register::Control => {
                state.registers[index].control = value;
                if value & (1 << 12) == 0 && !state.stop_pending {
                    state.registers[index].status &= !(1 << 4);
                }
                if value & (1 << 2) == 0 && !state.stop_pending {
                    state.registers[index].status &= !(1 << 3);
                }
                if value & (1 << 12) != 0 && !state.start_pending {
                    state.registers[index].status |= 1 << 4;
                }
                if value & (1 << 2) != 0 && !state.start_pending {
                    state.registers[index].status |= 1 << 3;
                }
            }
            Register::CommandTail => {
                state.registers[index].command_tail = value;
                if state.registers[index].status & (1 << 4) != 0 {
                    let ring = state.registers[index].command_buffer & 0x000f_ffff_ffff_f000;
                    let mut head = state.registers[index].command_head;
                    for _ in 0..256 {
                        if head == value {
                            break;
                        }
                        let words = *state
                            .commands
                            .get(&(ring + head))
                            .expect("command published before tail");
                        if words[0] >> 60 == 1 && !state.fetch_only {
                            state.completions.insert(words[0] & 0x000f_ffff_ffff_fff8, words[1]);
                        }
                        head = (head + 16) % 4096;
                    }
                    state.registers[index].command_head = head;
                }
            }
        }
        // Fail AFTER applying the modeled write: callers must retain backing
        // even when the underlying bus reports an error after a posted effect.
        state.effect(Effect::Write(index, register, value))
    }
    fn publish_composed(
        &mut self,
        key: PublicationKey,
        _unit: &UnitPlan,
        slot: PublicationSlot,
    ) -> Result<(), BackendError> {
        let mut state = self.shared.borrow_mut();
        state.published.push(key);
        state.slots.push(slot);
        state.effect(Effect::Compose(key))
    }
}

pub fn limits() -> Limits {
    Limits { max_steps: 1000, timeout_ticks: 10000 }
}
pub fn finish(tx: &mut Transaction<'_, Mock>) -> Step {
    for _ in 0..1100 {
        match tx.step(1) {
            Step::Progress | Step::Pending => {}
            result => return result,
        }
    }
    panic!("transaction exceeded declared step bound")
}
pub fn advance_to(tx: &mut Transaction<'_, Mock>, phase: Phase) {
    for _ in 0..1000 {
        if tx.phase() == phase {
            return;
        }
        assert!(matches!(tx.step(1), Step::Progress | Step::Pending));
    }
    panic!("phase not reached")
}
