//! Serialized virtual register/command machine. Guest commands never reach the
//! native queue. Each request waits for the matching owner-issued drain receipt.
//! The receipt producer separately owns and verifies private composed images.
//! Sources: 48882-3.11 physical pp122-128,131,138-140,158-160,214-224,252-256.

use super::compose::{GuestHostRange, HostMap};
use super::registers::{self, RegisterError, Registers};
use super::snapshot::{Snapshot, SnapshotError, SnapshotPage, TrackedSnapshot};
use super::{ADDRESS, PAGE, guest_span};
use crate::memory::iommu::physical::{DrainReceipt, PhysicalUnit, PublicationKey};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidationRange {
    Page { base: u64, bytes: u64 },
    All,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Completion { store: Option<(u64, u64)>, interrupt: bool, flush: bool },
    InvalidateDevice { device: u16 },
    InvalidatePages { domain: u16, range: InvalidationRange, directories: bool },
    InvalidateInterrupts { device: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandError {
    Opcode(u8),
    Reserved,
    CompletionAddress,
    InvalidRange,
}

impl Command {
    pub fn decode(words: [u64; 2]) -> Result<Self, CommandError> {
        let opcode = (words[0] >> 60) as u8;
        match opcode {
            1 => {
                if words[0] & !(0xf000_0000_0000_0000 | 0x000f_ffff_ffff_ffff) != 0 {
                    return Err(CommandError::Reserved);
                }
                let address = words[0] & 0x000f_ffff_ffff_fff8;
                let store = if words[0] & 1 != 0 {
                    if !guest_span(address, 8, 8) {
                        return Err(CommandError::CompletionAddress);
                    }
                    Some((address, words[1]))
                } else {
                    None
                };
                Ok(Self::Completion {
                    store,
                    interrupt: words[0] & 2 != 0,
                    flush: words[0] & 4 != 0,
                })
            }
            2 | 5 => {
                if words[0] & 0x0fff_ffff_ffff_0000 != 0 || words[1] != 0 {
                    return Err(CommandError::Reserved);
                }
                if opcode == 2 {
                    Ok(Self::InvalidateDevice { device: words[0] as u16 })
                } else {
                    Ok(Self::InvalidateInterrupts { device: words[0] as u16 })
                }
            }
            3 => {
                // PASID and GN are zero in the no-two-level-translation profile.
                if words[0] & 0x0fff_0000_ffff_ffff != 0 || words[1] & 0xffc != 0 {
                    return Err(CommandError::Reserved);
                }
                let address = words[1] & !0xfff;
                let range = if words[1] & 1 == 0 {
                    InvalidationRange::Page { base: address, bytes: PAGE }
                } else {
                    let shift = (address >> 12).trailing_ones() + 13;
                    if shift > 64 {
                        return Err(CommandError::InvalidRange);
                    }
                    if shift == 64 {
                        InvalidationRange::All
                    } else {
                        let bytes = 1u64 << shift;
                        InvalidationRange::Page { base: address & !(bytes - 1), bytes }
                    }
                };
                Ok(Self::InvalidatePages {
                    domain: (words[0] >> 32) as u16,
                    range,
                    directories: words[1] & 2 != 0,
                })
            }
            _ => Err(CommandError::Opcode(opcode)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkKind {
    /// Recompose every affected requester before changing the visible register
    /// bank. Guest disable/exclusion changes still use private host translation.
    Registers {
        before: Registers,
        after: Registers,
    },
    Command(Command),
    /// A protected source was changed by an arbitrarily encoded CPU instruction.
    /// This path is independent of guest invalidation commands: old V=IV=0 DTEs
    /// and disabled IRTEs may become usable without one (48882-3.11 pp77,121).
    TableWrite {
        source_generation: u64,
    },
    Reset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysicalWork {
    pub key: PublicationKey,
    pub kind: WorkKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pending {
    work: PhysicalWork,
    next: Registers,
    register_write: Option<(u16, u8, u64)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteResult {
    Committed,
    Pending(PhysicalWork),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Idle,
    Pending(PhysicalWork),
    IllegalCommand(CommandError),
    CommandMemoryFault(SnapshotError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceError {
    Register(RegisterError),
    Snapshot(SnapshotError),
    Memory(MemoryError),
    Busy,
    NoPending,
    WrongReceipt,
    GenerationExhausted,
}

#[derive(Debug)]
pub struct Device {
    unit: PhysicalUnit,
    epoch: u64,
    generation: u64,
    registers: Registers,
    pending: Option<Pending>,
    interrupt_latched: bool,
}

impl Device {
    /// Construct disconnected reset state for one explicitly identified unit.
    /// This does not admit that unit or authorize the native backend.
    pub const fn new(unit: PhysicalUnit, epoch: u64) -> Self {
        Self {
            unit,
            epoch,
            generation: 0,
            registers: Registers::RESET,
            pending: None,
            interrupt_latched: false,
        }
    }

    pub const fn registers(&self) -> &Registers {
        &self.registers
    }
    pub fn pending(&self) -> Option<PhysicalWork> {
        self.pending.map(|p| p.work)
    }
    pub fn read(&self, offset: u16, width: u8) -> Result<u64, DeviceError> {
        self.registers.read(offset, width).map_err(DeviceError::Register)
    }

    pub fn write(
        &mut self,
        offset: u16,
        width: u8,
        value: u64,
    ) -> Result<WriteResult, DeviceError> {
        if self.pending.is_some() {
            return Err(DeviceError::Busy);
        }
        let (next, changes_policy) =
            self.registers.prepare_write(offset, width, value).map_err(DeviceError::Register)?;
        if changes_policy {
            let kind = WorkKind::Registers { before: self.registers, after: next };
            let work = self.begin(kind, next)?;
            self.pending.as_mut().unwrap().register_write = Some((offset, width, value));
            return Ok(WriteResult::Pending(work));
        }
        let before = self.interrupt_asserted();
        self.registers = next;
        self.latch_transition(before);
        Ok(WriteResult::Committed)
    }

    /// Read at most one 16-byte guest command from an immutable owned copy.
    /// Strict serialization is permitted for f=0 as well as f=1. Validating and
    /// advancing CmdHead says fetched only; physical completion is separate.
    pub fn step(
        &mut self,
        snapshot: &Snapshot<'_>,
        memory: &mut impl GuestMemory,
    ) -> Result<Step, DeviceError> {
        if let Some(pending) = self.pending {
            return Ok(Step::Pending(pending.work));
        }
        if !self.registers.command_running()
            || self.registers.command_head == self.registers.command_tail
        {
            return Ok(Step::Idle);
        }
        let ring = self.registers.command_ring().map_err(DeviceError::Register)?;
        let address = ring.base + self.registers.command_head;
        let read = snapshot
            .read_u64(address)
            .and_then(|first| snapshot.read_u64(address + 8).map(|second| [first, second]));
        let words = match read {
            Ok(words) => words,
            Err(error) => {
                self.registers.status &= !registers::COMMAND_RUN;
                self.log_event(
                    memory,
                    Event::command_hardware_error(address, HardwareError::MasterAbort),
                )?;
                return Ok(Step::CommandMemoryFault(error));
            }
        };
        let command = match Command::decode(words) {
            Ok(command) => command,
            Err(error) => {
                // Invalid command retains its head and halts. Event data names
                // the guest command GPA, never a native queue or fault address.
                self.registers.status &= !registers::COMMAND_RUN;
                self.log_event(memory, Event::illegal_command(address))?;
                return Ok(Step::IllegalCommand(error));
            }
        };
        let mut next = self.registers;
        next.command_head = ring.next(next.command_head);
        let work = self.begin(WorkKind::Command(command), next)?;
        // Head may be reclaimed by guest software once captured; pending keeps
        // a private decoded command, including all completion operands.
        self.registers.command_head = next.command_head;
        Ok(Step::Pending(work))
    }

    pub fn reset(&mut self) -> Result<PhysicalWork, DeviceError> {
        if self.pending.is_some() {
            return Err(DeviceError::Busy);
        }
        self.begin(WorkKind::Reset, Registers::RESET)
    }

    pub fn tables_changed(&mut self, source_generation: u64) -> Result<PhysicalWork, DeviceError> {
        if self.pending.is_some() {
            return Err(DeviceError::Busy);
        }
        self.begin(WorkKind::TableWrite { source_generation }, self.registers)
    }

    fn begin(&mut self, kind: WorkKind, next: Registers) -> Result<PhysicalWork, DeviceError> {
        let generation = self.generation.checked_add(1).ok_or(DeviceError::GenerationExhausted)?;
        let key = PublicationKey { unit: self.unit, epoch: self.epoch, generation };
        let work = PhysicalWork { key, kind };
        self.pending = Some(Pending { work, next, register_write: None });
        self.generation = generation;
        Ok(work)
    }

    /// Only the physical owner can issue DrainReceipt. Its key and purpose must
    /// match this pending work; takeover receipts and old generations fail.
    /// Completion destinations are copied guest memory, never native stores.
    pub fn complete(
        &mut self,
        receipt: &DrainReceipt,
        memory: &mut impl GuestMemory,
    ) -> Result<(), DeviceError> {
        let pending = self.pending.ok_or(DeviceError::NoPending)?;
        if !receipt.is_mapping_publication() || !receipt.matches(pending.work.key) {
            return Err(DeviceError::WrongReceipt);
        }
        let before = self.interrupt_asserted();
        if let WorkKind::Command(Command::Completion { store, .. }) = pending.work.kind {
            if let Some((address, value)) = store {
                memory.write(address, &value.to_le_bytes()).map_err(DeviceError::Memory)?;
            }
        }
        // Events can arrive while physical work is pending. Reapply only the
        // prepared register lane to CURRENT state so asynchronous tail/status
        // changes survive. Commands changed their fetch head already and need
        // no register-bank replacement at all.
        if let Some((offset, width, value)) = pending.register_write {
            let (next, _) = self
                .registers
                .prepare_write(offset, width, value)
                .map_err(DeviceError::Register)?;
            self.registers = next;
        } else if matches!(pending.work.kind, WorkKind::Reset) {
            self.registers = pending.next;
        }
        if let WorkKind::Command(Command::Completion { interrupt: true, .. }) = pending.work.kind {
            self.registers.status |= registers::COMPLETION_INT;
        }
        if matches!(pending.work.kind, WorkKind::Reset) {
            self.interrupt_latched = false;
        }
        self.pending = None;
        self.latch_transition(before);
        Ok(())
    }

    /// The consumer routes this virtual MSI request through its admitted guest
    /// interrupt controller. Taking it is not proof of actual interrupt delivery.
    pub fn take_interrupt(&mut self) -> bool {
        let pending = self.interrupt_latched;
        self.interrupt_latched = false;
        pending
    }

    /// Native delivery must reserve a real interrupt-controller queue entry
    /// before acknowledging this latch. A failed injection must leave it set.
    pub const fn interrupt_pending(&self) -> bool {
        self.interrupt_latched
    }

    pub fn acknowledge_interrupt(&mut self) {
        self.interrupt_latched = false;
    }

    fn interrupt_asserted(&self) -> bool {
        (self.registers.control & registers::COMPLETION_INT_EN != 0
            && self.registers.status & registers::COMPLETION_INT != 0)
            || (self.registers.control & registers::EVENT_INT_EN != 0
                && self.registers.status & (registers::EVENT_INT | registers::EVENT_OVERFLOW) != 0)
    }

    fn latch_transition(&mut self, before: bool) {
        if !before && self.interrupt_asserted() {
            self.interrupt_latched = true;
        }
    }

    pub fn log_event(
        &mut self,
        memory: &mut impl GuestMemory,
        event: Event,
    ) -> Result<(), DeviceError> {
        if !self.registers.event_running() || self.registers.status & registers::EVENT_OVERFLOW != 0
        {
            return Ok(());
        }
        let ring = self.registers.event_ring().map_err(DeviceError::Register)?;
        let next = ring.next(self.registers.event_tail);
        let before = self.interrupt_asserted();
        if next == self.registers.event_head {
            self.registers.status |= registers::EVENT_OVERFLOW;
            self.registers.status &= !registers::EVENT_RUN;
        } else {
            let mut bytes = [0; 16];
            bytes[..8].copy_from_slice(&event.words[0].to_le_bytes());
            bytes[8..].copy_from_slice(&event.words[1].to_le_bytes());
            memory
                .write(ring.base + self.registers.event_tail, &bytes)
                .map_err(DeviceError::Memory)?;
            self.registers.event_tail = next;
            self.registers.status |= registers::EVENT_INT;
        }
        self.latch_transition(before);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    words: [u64; 2],
}

impl Event {
    pub const fn illegal_command(guest_command_address: u64) -> Self {
        Self { words: [5 << 60, guest_command_address & !15] }
    }
    pub const fn words(self) -> [u64; 2] {
        self.words
    }

    pub const fn command_hardware_error(guest_command_address: u64, kind: HardwareError) -> Self {
        Self { words: [(6 << 60) | ((kind as u64) << 57), guest_command_address & !15] }
    }

    /// Encode already-translated guest identity and DVA. There is intentionally
    /// no constructor accepting a raw native event record or native domain ID.
    /// Full SA/SE/IG/SupIOPF policy belongs to the guest request evaluator.
    pub const fn io_page_fault(fault: GuestFault) -> Self {
        let present = !matches!(fault.reason, FaultReason::NotPresent);
        let flags = ((present as u64) << 20)
            | ((matches!(fault.reason, FaultReason::Permission) as u64) << 22)
            | ((matches!(fault.reason, FaultReason::ReservedBits) as u64) << 23)
            | ((matches!(fault.access, FaultAccess::Write) as u64) << 21)
            | ((matches!(fault.access, FaultAccess::Interrupt) as u64) << 19);
        Self {
            words: [
                (2 << 60) | ((fault.domain as u64) << 32) | (flags << 32) | fault.device as u64,
                fault.device_address,
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HardwareError {
    MasterAbort = 1,
    TargetAbort = 2,
    Data = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultAccess {
    Read,
    Write,
    Interrupt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultReason {
    NotPresent,
    Permission,
    ReservedBits,
    InvalidLevel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestFault {
    pub device: u16,
    pub domain: u16,
    pub device_address: u64,
    pub access: FaultAccess,
    pub reason: FaultReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestReadOnly {
    pub base: u64,
    pub len: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryError {
    Range,
    ReadOnly,
    StaleCapture,
    Unavailable,
}

/// Guest-addressed output, shared by the copied model and the native scratch
/// adapter. Implementations preflight the ENTIRE write before the first store,
/// retain the destination and reject every alias of a protected/table page.
/// Successful return means the bytes were stored; it is not hardware ownership.
pub trait GuestMemory {
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError>;
}

/// One concrete safe copied-RAM window used by the disconnected device. It
/// cannot access physical memory. Native pinned guest-memory access and table
/// writes require a separate, currently absent integration. Every write checks
/// its entire span before mutating bytes. Read-only table destinations refuse.
pub struct GuestRam<'a> {
    base: u64,
    bytes: &'a mut [u8],
    read_only: &'a [GuestReadOnly],
    tables: Option<TableWriteGuards<'a>>,
}

struct TableWriteGuards<'a> {
    pages: &'a [SnapshotPage],
    maps: &'a [GuestHostRange],
    protected: &'a [crate::memory::iommu::image::ProtectedRange],
}

impl<'a> GuestRam<'a> {
    pub fn new(
        base: u64,
        bytes: &'a mut [u8],
        read_only: &'a [GuestReadOnly],
    ) -> Result<Self, MemoryError> {
        if !guest_span(base, bytes.len() as u64, 1) {
            return Err(MemoryError::Range);
        }
        for range in read_only {
            if !guest_span(range.base, range.len, 1) {
                return Err(MemoryError::Range);
            }
        }
        Ok(Self { base, bytes, read_only, tables: None })
    }

    /// Construct the event/completion RAM view for a model reusing captured
    /// tables. Guards are DERIVED from all captured host pages and the full RAM
    /// map, so aliases not named in the capture cannot bypass them. Monitor
    /// writes to those sources fail before mutation and leave the copy valid.
    /// `new` is only suitable for independent copied RAM with no table sources.
    pub fn from_tracked(
        base: u64,
        bytes: &'a mut [u8],
        tracked: &'a TrackedSnapshot<'_>,
        host: &'a HostMap<'_>,
    ) -> Result<Self, MemoryError> {
        let snapshot = tracked.snapshot().map_err(|_| MemoryError::StaleCapture)?;
        let mut memory = Self::new(base, bytes, &[])?;
        memory.tables = Some(TableWriteGuards {
            pages: snapshot.pages(),
            maps: host.ranges(),
            protected: host.protected(),
        });
        Ok(memory)
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
}

impl GuestMemory for GuestRam<'_> {
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len() as u64;
        if !guest_span(address, length, 1) {
            return Err(MemoryError::Range);
        }
        let offset = address.checked_sub(self.base).ok_or(MemoryError::Range)?;
        let end = offset.checked_add(length).ok_or(MemoryError::Range)?;
        if end > self.bytes.len() as u64 {
            return Err(MemoryError::Range);
        }
        if self
            .read_only
            .iter()
            .any(|range| address < range.base + range.len && range.base < address + length)
        {
            return Err(MemoryError::ReadOnly);
        }
        if let Some(guards) = &self.tables {
            let mut cursor = address;
            while cursor < address + length {
                let index = guards.maps.partition_point(|map| map.guest_base + map.len <= cursor);
                let map = guards
                    .maps
                    .get(index)
                    .filter(|map| map.guest_base <= cursor)
                    .ok_or(MemoryError::Range)?;
                if !map.permissions.allows_write() {
                    return Err(MemoryError::ReadOnly);
                }
                let end = (address + length).min(map.guest_base + map.len);
                let host = map.host_base + cursor - map.guest_base;
                let host_end = host + end - cursor;
                if guards.pages.iter().any(|page| {
                    host < page.source_host_page() + PAGE && page.source_host_page() < host_end
                }) || guards
                    .protected
                    .iter()
                    .any(|range| host < range.base + range.len && range.base < host_end)
                {
                    return Err(MemoryError::ReadOnly);
                }
                cursor = end;
            }
        }
        self.bytes[offset as usize..end as usize].copy_from_slice(bytes);
        Ok(())
    }
}

/// Encode register base operands in tests/adapters without granting native use.
pub fn guest_ring_register(base: u64, order: u8) -> Result<u64, RegisterError> {
    if !(8..=15).contains(&order) {
        return Err(RegisterError::RingLength);
    }
    if base & !ADDRESS != 0 || !guest_span(base, (1u64 << order) * 16, PAGE) {
        return Err(RegisterError::Address);
    }
    Ok(base | (u64::from(order) << 56))
}
