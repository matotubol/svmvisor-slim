mod ownership_support;
use ownership_support::{Fixture, policy, range};
use std::{
    alloc::{Layout, alloc_zeroed, handle_alloc_error},
    collections::BTreeMap,
};
use svmvisor_hypervisor::{
    boot::memory::MemoryDescriptor,
    firmware::native::resident::iommu::{
        RegisterObservation,
        ownership::{
            Fence, Register,
            cold::{self, Access, Error, ImageError, Limits},
        },
        resources::{COMPLETION_OFFSET, CompositionStorage},
    },
    memory::iommu::tables::DteInterruptPolicy,
};

fn storage() -> Box<CompositionStorage> {
    let layout = Layout::new::<CompositionStorage>();
    let raw = unsafe { alloc_zeroed(layout) };
    if raw.is_null() {
        handle_alloc_error(layout);
    }
    unsafe { Box::from_raw(raw.cast()) }
}
fn ram(base: u64, len: u64, kind: u32) -> MemoryDescriptor {
    MemoryDescriptor {
        memory_type: kind,
        physical_start: base,
        page_count: len / 4096,
        attributes: 8,
    }
}
fn translate(storage: &CompositionStorage, root: u64, address: u64) -> Option<(u64, u8)> {
    let mut page = 0usize;
    for level in (1..=4).rev() {
        let shift = 12 + 9 * (level - 1);
        let word = storage.tables()[page][((address >> shift) & 511) as usize];
        if word & 1 == 0 {
            return None;
        }
        let base = word & 0x000f_ffff_ffff_f000;
        let next = (word >> 9) & 7;
        if next == 0 {
            return Some((base + (address & ((1 << shift) - 1)), level));
        }
        assert_eq!(next, u64::from(level - 1));
        page = ((base - root) / 4096) as usize;
    }
    unreachable!()
}

#[test]
fn mixed_identity_maps_64gib_with_exact_page_holes_and_no_mmio_or_acpi() {
    let mut storage = storage();
    let base = 0x1100_0000;
    let map = [
        ram(0, 0x9000_0000, 7),
        ram(0x9000_0000, 0x1000, 10),
        ram(0x9000_1000, (64 << 30) - 0x9000_1000, 7),
        ram(64 << 30, 0x1000, 11),
    ];
    let excluded = [range(0x1000_1000, 0x0400_0000)];
    let image = cold::prepare_identity(
        &mut storage,
        policy(),
        base,
        &map,
        &excluded,
        DteInterruptPolicy::AbortControlled,
    )
    .unwrap();
    assert!(image.used_pages < 16);
    assert_eq!(translate(&storage, image.root, 32 << 30), Some((32 << 30, 3)));
    assert_eq!(translate(&storage, image.root, 0x0200_0000), Some((0x0200_0000, 2)));
    assert_eq!(translate(&storage, image.root, 0x1000_0000), Some((0x1000_0000, 1)));
    for address in [0x1000_1000, 0x13ff_f000, 0x1400_0000, 0x9000_0000, 64 << 30] {
        assert_eq!(translate(&storage, image.root, address), None, "{address:x}");
    }
    assert_eq!(translate(&storage, image.root, 0x1400_1000), Some((0x1400_1000, 1)));
    assert_eq!(
        cold::verify_identity(
            &storage,
            policy(),
            base,
            &map,
            &excluded,
            DteInterruptPolicy::AbortControlled
        ),
        Ok(image)
    );
    storage.tables_mut()[255][511] = 1;
    assert_eq!(
        cold::verify_identity(
            &storage,
            policy(),
            base,
            &map,
            &excluded,
            DteInterruptPolicy::AbortControlled
        ),
        Err(ImageError::Contents)
    );
}

#[test]
fn capacity_refusal_precedes_any_image_store() {
    let mut storage = storage();
    storage.device_table_mut()[0][0] = 0x1234;
    let map: Vec<_> = (1..=128).map(|n| ram(n << 30, 4096, 7)).collect();
    assert_eq!(
        cold::prepare_identity(
            &mut storage,
            policy(),
            0x1000_0000,
            &map,
            &[range(0x1000_0000, 0x300000)],
            DteInterruptPolicy::AbortControlled
        ),
        Err(ImageError::Capacity)
    );
    assert_eq!(storage.device_table()[0][0], 0x1234);
}

#[derive(Debug, PartialEq, Eq)]
enum Effect {
    Register(Register, u64),
    Command([u64; 2]),
    Fence(Fence),
}
struct Sim {
    r: RegisterObservation,
    words: BTreeMap<u64, [u64; 2]>,
    cells: BTreeMap<u64, u64>,
    effects: Vec<Effect>,
    fetch_only: bool,
}
impl Sim {
    fn new(r: RegisterObservation) -> Self {
        Self {
            r,
            words: BTreeMap::new(),
            cells: BTreeMap::new(),
            effects: vec![],
            fetch_only: false,
        }
    }
}
impl Access for Sim {
    fn observe(&mut self) -> Result<RegisterObservation, Error> {
        Ok(self.r)
    }
    fn write_register(&mut self, register: Register, value: u64) -> Result<(), Error> {
        self.effects.push(Effect::Register(register, value));
        match register {
            Register::Control => {
                self.r.control = value;
                self.r.status = if value & (1 << 12) != 0 { 16 } else { 0 }
                    | if value & 4 != 0 { 8 } else { 0 };
            }
            Register::DeviceTable => self.r.device_table = value,
            Register::CommandBase => self.r.command_buffer = value,
            Register::CommandHead => self.r.command_head = value,
            Register::CommandTail => {
                let base = self.r.command_buffer & 0x000f_ffff_ffff_f000;
                let bytes = 16 << ((self.r.command_buffer >> 56) & 15);
                while self.r.command_head != value {
                    let words = self.words[&(base + self.r.command_head)];
                    if words[0] >> 60 == 1 && !self.fetch_only {
                        self.cells.insert(words[0] & 0x000f_ffff_ffff_fff8, words[1]);
                    }
                    self.r.command_head = (self.r.command_head + 16) % bytes;
                }
                self.r.command_tail = value;
            }
            Register::EventBase => self.r.event_log = value,
            Register::EventHead => self.r.event_head = value,
            Register::EventTail => self.r.event_tail = value,
        }
        Ok(())
    }
    fn write_command(&mut self, address: u64, words: [u64; 2]) -> Result<(), Error> {
        self.words.insert(address, words);
        self.effects.push(Effect::Command(words));
        Ok(())
    }
    fn read_completion(&mut self, address: u64) -> Result<u64, Error> {
        Ok(*self.cells.get(&address).unwrap_or(&0))
    }
    fn fence(&mut self, fence: Fence) -> Result<(), Error> {
        self.effects.push(Effect::Fence(fence));
        Ok(())
    }
}

#[test]
fn stopped_old_engines_are_started_drained_then_replaced_without_disabling_iommu() {
    let fixture = Fixture::new(1);
    let mut unit = *fixture.binding.unit(0).unwrap();
    unit.observed_registers.control &= !((1 << 12) | 4);
    unit.observed_registers.status = 0;
    let mut sim = Sim::new(unit.observed_registers);
    let result =
        cold::publish(&mut sim, policy(), &unit, 0x2000_01ff, Limits { polls: 3 }).unwrap();
    assert_eq!(result.device_table(), 0x2000_01ff);
    assert_eq!(sim.cells[&(unit.bank.base() + COMPLETION_OFFSET)], 1);
    let root = sim
        .effects
        .iter()
        .position(|e| matches!(e, Effect::Register(Register::DeviceTable, _)))
        .unwrap();
    assert!(sim.effects[..root].contains(&Effect::Fence(Fence::AcquireCompletion)));
    assert_eq!(sim.effects[root - 1], Effect::Fence(Fence::PublishMemoryBeforeMmio));
    assert!(
        sim.effects
            .iter()
            .all(|e| !matches!(e, Effect::Register(Register::Control, value) if value & 1 == 0))
    );
}

#[test]
fn baseline_without_iasup_invalidates_all_requesters_domains_and_interrupts() {
    let fixture = Fixture::new(1);
    let mut unit = *fixture.binding.unit(0).unwrap();
    unit.observed_registers.extended_features = Some(0);
    let mut sim = Sim::new(unit.observed_registers);
    let result =
        cold::publish(&mut sim, policy(), &unit, 0x2000_01ff, Limits { polls: 3 }).unwrap();
    assert_eq!(result.completion(), (3 * 65536 + 253) / 254);
    let commands: Vec<_> = sim
        .effects
        .iter()
        .filter_map(|e| if let Effect::Command(w) = e { Some(*w) } else { None })
        .collect();
    for op in [2, 3, 5] {
        assert_eq!(commands.iter().filter(|w| w[0] >> 60 == op).count(), 65536);
    }
    assert!(!commands.iter().any(|w| w[0] >> 60 == 8));
}

#[test]
fn fetched_heads_never_substitute_for_completion_and_bad_geometry_has_no_effect() {
    let fixture = Fixture::new(1);
    let mut unit = *fixture.binding.unit(0).unwrap();
    let mut sim = Sim::new(unit.observed_registers);
    sim.fetch_only = true;
    assert_eq!(
        cold::publish(&mut sim, policy(), &unit, 0x2000_01ff, Limits { polls: 3 }),
        Err(Error::Timeout)
    );
    assert!(!sim.effects.iter().any(|e| matches!(e, Effect::Register(Register::DeviceTable, _))));
    unit.observed_registers.control &= !(1 << 12);
    unit.observed_registers.command_tail = 3;
    let mut sim = Sim::new(unit.observed_registers);
    assert_eq!(
        cold::publish(&mut sim, policy(), &unit, 0x2000_01ff, Limits { polls: 3 }),
        Err(Error::OldCommandBuffer)
    );
    assert!(sim.effects.is_empty());
    unit.observed_registers.control = 0;
    let mut sim = Sim::new(unit.observed_registers);
    assert_eq!(
        cold::publish(&mut sim, policy(), &unit, 0x2000_01ff, Limits { polls: 3 }),
        Err(Error::UntranslatedTraffic)
    );
    assert!(sim.effects.is_empty());
}

#[test]
fn old_dte_bypass_and_remote_cache_enables_are_not_admitted() {
    let valid = [0x9000 | 0x803 | (3 << 61), 1, 1, 0];
    assert_eq!(cold::validate_old_dte(policy(), valid), Ok(()));
    for bit in [32, 39, 40] {
        let mut words = valid;
        words[1] |= 1 << bit;
        assert_eq!(cold::validate_old_dte(policy(), words), Err(Error::OldDeviceBypass));
    }
    for clear in [1, 2, 0xe00] {
        let mut words = valid;
        words[0] &= !clear;
        assert_eq!(cold::validate_old_dte(policy(), words), Err(Error::OldDeviceBypass));
    }
}

#[test]
fn completed_receipt_rechecks_engines_control_and_completion_before_multiunit_release() {
    let fixture = Fixture::new(1);
    let unit = *fixture.binding.unit(0).unwrap();
    let mut sim = Sim::new(unit.observed_registers);
    let result =
        cold::publish(&mut sim, policy(), &unit, 0x2000_01ff, Limits { polls: 3 }).unwrap();
    result.revalidate(&mut sim).unwrap();
    sim.r.status &= !8;
    assert_eq!(result.revalidate(&mut sim), Err(Error::EngineStopped));
    sim.r.status |= 8;
    sim.r.device_table ^= 0x1000;
    assert_eq!(result.revalidate(&mut sim), Err(Error::Changed));
    sim.r.device_table ^= 0x1000;
    sim.cells.insert(unit.bank.base() + COMPLETION_OFFSET + 8, 0);
    assert_eq!(result.revalidate(&mut sim), Err(Error::Timeout));
}

#[test]
fn unit_physical_width_refuses_unrepresentable_ram_before_stores() {
    use svmvisor_hypervisor::memory::address::{AddressPolicy, EncryptionState};
    let mut storage = storage();
    storage.device_table_mut()[0][0] = 123;
    let narrow =
        AddressPolicy::new(40, EncryptionState::Unencrypted { encryption_bit: None }).unwrap();
    let map = [ram(1 << 40, 4096, 7)];
    assert_eq!(
        cold::prepare_identity(
            &mut storage,
            narrow,
            0x1000_0000,
            &map,
            &[range(0x1000_0000, 0x300000)],
            DteInterruptPolicy::AbortControlled
        ),
        Err(ImageError::MemoryMap)
    );
    assert_eq!(storage.device_table()[0][0], 123);
}

#[test]
fn all_old_command_event_and_device_extents_are_disjoint_before_publication() {
    let fixture = Fixture::new(2);
    let units: Vec<_> = fixture.binding.units().copied().collect();
    assert_eq!(cold::validate_old_buffers(policy(), &units), Ok(()));
    for alias in 0..5 {
        let mut bad = units.clone();
        let first = bad[0].observed_registers;
        match alias {
            0 => bad[0].observed_registers.command_buffer = (first.device_table & !511) | (8 << 56),
            1 => bad[0].observed_registers.event_log = first.command_buffer,
            2 => bad[1].observed_registers.command_buffer = first.command_buffer,
            3 => bad[1].observed_registers.event_log = (first.device_table & !511) | (8 << 56),
            4 => bad[1].observed_registers.device_table = first.device_table,
            _ => unreachable!(),
        }
        assert_eq!(
            cold::validate_old_buffers(policy(), &bad),
            Err(Error::OldBufferAlias),
            "alias {alias}"
        );
    }
    let mut bad = units;
    bad[1].observed_registers.command_tail = 3;
    assert_eq!(cold::validate_old_buffers(policy(), &bad), Err(Error::OldCommandBuffer));
}
