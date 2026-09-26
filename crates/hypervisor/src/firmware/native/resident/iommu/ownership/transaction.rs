use super::super::{
    MAX_OBSERVED_UNITS, RegisterObservation,
    resources::{DEVICE_TABLE_OFFSET, EVENT_OFFSET},
};
use super::{
    Backend, BackendError, DrainReceipt, Fence, Plan, PublicationKey, PublicationSlot, Register,
    UnitPlan,
    admission::{CONTROL_KEEP, ENABLES, RUN, validate_running_profile},
};
use crate::memory::iommu::{
    commands::{CompletionOrdering, HostCommand},
    queue::{COMPLETION_CELLS, CommandRingGeometry},
};

/// Bounds count all progress steps as well as polls. Ticks are supplied by the
/// trusted monotonic clock adapter; a stuck clock still exhausts max_steps.
/// No claim is made that CPU parking or a callback supplies a hardware deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_steps: u32,
    pub timeout_ticks: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Acquire,
    RequestQuiescence,
    AwaitQuiescence,
    VerifyBanks,
    Refresh,
    PublishOldDrain,
    AwaitOldDrain,
    StopEngines,
    AwaitStopped,
    Install,
    AwaitNewStart,
    AwaitNewDrain,
    OwnedQuiesced,
    RevalidateMappingQuiescence,
    PublishMapping,
    AwaitMapping,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleEvent {
    Reset,
    Suspend,
    PowerLoss,
    ControlLost,
    MemoryIntegrityLost,
    GuestTableTrackingLost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureReason {
    Limits,
    Timeout,
    ClockRegression,
    Backend(BackendError),
    SnapshotDrift,
    QueuePointer,
    EngineStopped,
    EventPending,
    CompletionStale,
    Lifecycle(LifecycleEvent),
    PublicationKey,
    PublicationCapacity,
    CompletionExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure {
    pub phase: Phase,
    pub unit: usize,
    pub reason: FailureReason,
}

/// Conservative side-effect accounting, set BEFORE fallible effects. Every
/// failure retains all assigned/old/reachable memory and all acquired controls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Retention {
    pub controls_may_be_owned: bool,
    pub requesters_may_be_quiesced: u16,
    pub old_queues_may_reference_completion: u16,
    pub new_roots_may_be_published: u16,
    pub composition_may_be_published: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Progress,
    Pending,
    Complete,
    Failed(Failure),
}

#[derive(Clone, Copy)]
struct UnitState {
    expected: RegisterObservation,
    head: u32,
    next_cell: usize,
    waiting_cell: usize,
    token: u64,
    generation: u64,
    receipt: Option<DrainReceipt>,
}

/// Owns protocol state, borrows an independently retained effects owner. Drop
/// performs no rollback, resume, unpin or hardware write. The deny-only outcome
/// keeps requesters silent; it is not permission to run ordinary Windows DMA.
pub struct Transaction<'a, B: Backend> {
    backend: &'a mut B,
    plan: Plan,
    states: [Option<UnitState>; MAX_OBSERVED_UNITS],
    epoch: u64,
    phase: Phase,
    cursor: usize,
    limits: Limits,
    remaining_steps: u32,
    deadline: u64,
    last_time: u64,
    failure: Option<Failure>,
    retention: Retention,
    mapping: Option<PublicationKey>,
}

impl<'a, B: Backend> Transaction<'a, B> {
    pub fn new(
        backend: &'a mut B,
        plan: Plan,
        epoch: u64,
        now: u64,
        limits: Limits,
    ) -> Result<Self, FailureReason> {
        if epoch == 0 || limits.max_steps == 0 || limits.timeout_ticks == 0 || plan.is_empty() {
            return Err(FailureReason::Limits);
        }
        let deadline = now.checked_add(limits.timeout_ticks).ok_or(FailureReason::Limits)?;
        let mut states = [None; MAX_OBSERVED_UNITS];
        for (index, unit) in plan.units().enumerate() {
            let head = unit
                .old_commands
                .validate_offset(unit.binding.observed_registers.command_head)
                .map_err(|_| FailureReason::QueuePointer)?;
            unit.old_commands
                .validate_offset(unit.binding.observed_registers.command_tail)
                .map_err(|_| FailureReason::QueuePointer)?;
            states[index] = Some(UnitState {
                expected: unit.binding.observed_registers,
                head,
                next_cell: 0,
                waiting_cell: 0,
                token: 0,
                generation: 0,
                receipt: None,
            });
        }
        Ok(Self {
            backend,
            plan,
            states,
            epoch,
            phase: Phase::Acquire,
            cursor: 0,
            limits,
            remaining_steps: limits.max_steps,
            deadline,
            last_time: now,
            failure: None,
            retention: Retention::default(),
            mapping: None,
        })
    }

    pub const fn phase(&self) -> Phase {
        self.phase
    }
    pub const fn retention(&self) -> Retention {
        self.retention
    }
    pub const fn failure(&self) -> Option<Failure> {
        self.failure
    }
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// The receiver must ALSO validate backend owner authority and current epoch.
    /// Takeover receipts intentionally have mapping_publication=false.
    pub fn receipt(&self, unit: usize) -> Option<DrainReceipt> {
        if self.phase != Phase::OwnedQuiesced {
            return None;
        }
        self.states.get(unit).and_then(Option::as_ref).and_then(|state| state.receipt)
    }

    pub fn mapping_receipt(&self, key: PublicationKey) -> Option<DrainReceipt> {
        self.plan.units().enumerate().find_map(|(index, _)| {
            self.receipt(index)
                .filter(|receipt| receipt.matches(key) && receipt.is_mapping_publication())
        })
    }

    /// Request a composition already staged by the backend. Validation errors
    /// before entering PublishMapping have no effects. A published generation
    /// alternates between two slots only after the preceding matching drain and
    /// renewed all-unit source-quiescence check. Completion cells are never reused.
    pub fn begin_publication(
        &mut self,
        key: PublicationKey,
        now: u64,
    ) -> Result<(), FailureReason> {
        if self.phase != Phase::OwnedQuiesced || key.epoch != self.epoch {
            return Err(FailureReason::PublicationKey);
        }
        let index = self
            .plan
            .units()
            .position(|unit| {
                crate::memory::iommu::physical::PhysicalUnit::from(unit.binding.identity)
                    == key.unit
            })
            .ok_or(FailureReason::PublicationKey)?;
        let state = self.states[index].as_ref().unwrap();
        if key.generation == 0 || state.generation.checked_add(1) != Some(key.generation) {
            return Err(FailureReason::PublicationKey);
        }
        if self.plan.unit(index).unwrap().publication.is_none() {
            return Err(FailureReason::PublicationCapacity);
        }
        if state.next_cell >= COMPLETION_CELLS {
            return Err(FailureReason::CompletionExhausted);
        }
        if now < self.last_time {
            return Err(FailureReason::ClockRegression);
        }
        let deadline = now.checked_add(self.limits.timeout_ticks).ok_or(FailureReason::Limits)?;
        self.phase = Phase::RevalidateMappingQuiescence;
        self.cursor = 0;
        self.mapping = Some(key);
        self.deadline = deadline;
        self.last_time = now;
        self.remaining_steps = self.limits.max_steps;
        Ok(())
    }

    /// Reset/power/tracking loss is terminal. No automatic restore of the old
    /// owner's roots, no reuse of completion cells, and no continuation in the
    /// same epoch is available. A separately admitted new owner is required.
    pub fn revoke(&mut self, event: LifecycleEvent) -> Failure {
        if let Some(failure) = self.failure {
            return failure;
        }
        self.fail(FailureReason::Lifecycle(event));
        self.failure.unwrap()
    }

    pub fn step(&mut self, now: u64) -> Step {
        if let Some(failure) = self.failure {
            return Step::Failed(failure);
        }
        if self.phase == Phase::OwnedQuiesced {
            return Step::Complete;
        }
        if now < self.last_time {
            return self.fail(FailureReason::ClockRegression);
        }
        self.last_time = now;
        if now >= self.deadline || self.remaining_steps == 0 {
            return self.fail(FailureReason::Timeout);
        }
        self.remaining_steps -= 1;
        match self.advance() {
            Ok(step) => step,
            Err(reason) => self.fail(reason),
        }
    }

    fn advance(&mut self) -> Result<Step, FailureReason> {
        let unit = *self.plan.unit(self.cursor).unwrap();
        let identity = unit.binding.identity;
        match self.phase {
            Phase::Acquire => {
                self.retention.controls_may_be_owned = true;
                self.backend.acquire(self.epoch, &self.plan)?;
                self.phase = Phase::RequestQuiescence;
            }
            Phase::RequestQuiescence => {
                self.retention.requesters_may_be_quiesced |= 1 << self.cursor;
                self.backend.request_quiescence(identity, self.epoch)?;
                self.next(Phase::AwaitQuiescence);
            }
            Phase::AwaitQuiescence => {
                if !self.backend.poll_quiescence(identity, self.epoch)? {
                    return Ok(Step::Pending);
                }
                self.next(Phase::VerifyBanks);
            }
            Phase::VerifyBanks => {
                self.backend.verify_and_publish_bank(&unit)?;
                self.backend.fence(identity, Fence::PublishMemoryBeforeMmio)?;
                self.next(Phase::Refresh);
            }
            Phase::Refresh => {
                let observed = self.observe(&unit, unit.old_commands)?;
                validate_running_profile(observed).map_err(|_| FailureReason::SnapshotDrift)?;
                self.next(Phase::PublishOldDrain);
            }
            Phase::PublishOldDrain => {
                if !self.submit_drain(&unit, true)? {
                    return Ok(Step::Pending);
                }
                self.next(Phase::AwaitOldDrain);
            }
            Phase::AwaitOldDrain => {
                if !self.poll_drain(&unit, true)? {
                    return Ok(Step::Pending);
                }
                self.next(Phase::StopEngines);
            }
            Phase::StopEngines => {
                self.observe(&unit, unit.old_commands)?;
                let control = preserved_control(self.state().expected) | 1;
                self.write(identity, Register::Control, control)?;
                self.state_mut().expected.control = control;
                self.next(Phase::AwaitStopped);
            }
            Phase::AwaitStopped => {
                let snapshot = self.observe(&unit, unit.old_commands)?;
                if snapshot.status & RUN != 0 {
                    return Ok(Step::Pending);
                }
                self.next(Phase::Install);
            }
            Phase::Install => {
                let snapshot = self.observe(&unit, unit.old_commands)?;
                if snapshot.status & RUN != 0 {
                    return Err(FailureReason::SnapshotDrift);
                }
                // Global barriers above ensure every old engine has drained and
                // stopped before the first new bank can become reachable.
                self.retention.new_roots_may_be_published |= 1 << self.cursor;
                let base = unit.binding.bank.base();
                for (register, value) in [
                    (Register::DeviceTable, (base + DEVICE_TABLE_OFFSET) | 511),
                    (Register::CommandBase, unit.commands.base_register_value()),
                    (Register::CommandHead, 0),
                    (Register::CommandTail, 0),
                    (Register::EventBase, (base + EVENT_OFFSET) | (8 << 56)),
                    (Register::EventHead, 0),
                    (Register::EventTail, 0),
                ] {
                    self.write(identity, register, value)?;
                }
                let control = preserved_control(self.state().expected) | ENABLES;
                {
                    let state = self.state_mut();
                    state.expected.device_table = (base + DEVICE_TABLE_OFFSET) | 511;
                    state.expected.command_buffer = unit.commands.base_register_value();
                    state.expected.command_head = 0;
                    state.expected.command_tail = 0;
                    state.expected.event_log = (base + EVENT_OFFSET) | (8 << 56);
                    state.expected.event_head = 0;
                    state.expected.event_tail = 0;
                    state.head = 0;
                }
                // Queue and event pointers are installed while Run=0. The
                // preinitialized, retained bank is visible before enable.
                self.backend.fence(identity, Fence::PublishMemoryBeforeMmio)?;
                self.write(identity, Register::Control, control)?;
                self.state_mut().expected.control = control;
                self.next(Phase::AwaitNewStart);
            }
            Phase::AwaitNewStart => {
                let snapshot = self.observe(&unit, unit.commands)?;
                if snapshot.status & RUN != RUN {
                    return Ok(Step::Pending);
                }
                // New ring has 255 usable entries; this emits only two.
                if !self.submit_drain(&unit, false)? {
                    return Err(FailureReason::QueuePointer);
                }
                self.next(Phase::AwaitNewDrain);
            }
            Phase::AwaitNewDrain => {
                if !self.poll_drain(&unit, false)? {
                    return Ok(Step::Pending);
                }
                let key =
                    PublicationKey { unit: identity.into(), epoch: self.epoch, generation: 2 };
                self.state_mut().receipt = Some(DrainReceipt::completed(key, false));
                self.next(Phase::OwnedQuiesced);
            }
            Phase::RevalidateMappingQuiescence => {
                if !self.backend.poll_quiescence(identity, self.epoch)? {
                    return Ok(Step::Pending);
                }
                self.cursor += 1;
                if self.cursor == self.plan.len {
                    let key = self.mapping.unwrap();
                    self.cursor = self
                        .plan
                        .units()
                        .position(|unit| {
                            crate::memory::iommu::physical::PhysicalUnit::from(
                                unit.binding.identity,
                            ) == key.unit
                        })
                        .unwrap();
                    self.phase = Phase::PublishMapping;
                }
            }
            Phase::PublishMapping => {
                // Preflight ring capacity and fresh unused cell before the
                // composition callback can mutate any hardware-visible table.
                if !self.can_submit(&unit, false)? {
                    return Ok(Step::Pending);
                }
                let key = self.mapping.unwrap();
                let space = unit.publication.unwrap();
                let slot_index = ((key.generation - 1) & 1) as usize;
                let previous_receipt = self.state().receipt;
                if key.generation > 1
                    && !previous_receipt.is_some_and(|receipt| {
                        receipt.is_mapping_publication()
                            && receipt
                                .matches(PublicationKey { generation: key.generation - 1, ..key })
                    })
                {
                    return Err(FailureReason::PublicationKey);
                }
                let slot = PublicationSlot {
                    destination: space.generations[slot_index],
                    previous: (key.generation > 1).then_some(space.generations[1 - slot_index]),
                    reuse_after: if key.generation > 2 { previous_receipt } else { None },
                };
                self.retention.composition_may_be_published |= 1 << self.cursor;
                self.backend.publish_composed(key, &unit, slot)?;
                self.backend.fence(identity, Fence::PublishMemoryBeforeMmio)?;
                if !self.submit_drain(&unit, false)? {
                    return Err(FailureReason::QueuePointer);
                }
                self.phase = Phase::AwaitMapping;
            }
            Phase::AwaitMapping => {
                if !self.poll_drain(&unit, false)? {
                    return Ok(Step::Pending);
                }
                let key = self.mapping.take().unwrap();
                let state = self.state_mut();
                state.generation = key.generation;
                state.receipt = Some(DrainReceipt::completed(key, true));
                self.phase = Phase::OwnedQuiesced;
            }
            Phase::OwnedQuiesced => return Ok(Step::Complete),
            Phase::Failed => unreachable!(),
        }
        Ok(if self.phase == Phase::OwnedQuiesced { Step::Complete } else { Step::Progress })
    }

    fn can_submit(&mut self, unit: &UnitPlan, old: bool) -> Result<bool, FailureReason> {
        let ring = if old { unit.old_commands } else { unit.commands };
        let snapshot = self.observe(unit, ring)?;
        if snapshot.status & RUN != RUN {
            return Err(FailureReason::EngineStopped);
        }
        let state = self.state();
        if state.next_cell >= COMPLETION_CELLS {
            return Err(FailureReason::CompletionExhausted);
        }
        let address = unit.completion_base + state.next_cell as u64 * 8;
        if self.backend.read_completion(unit.binding.identity, address)? != 0 {
            return Err(FailureReason::CompletionStale);
        }
        let used = distance(ring, snapshot.command_head as u32, snapshot.command_tail as u32) / 16;
        Ok(ring.usable_entries() - used as usize >= 2)
    }

    fn submit_drain(&mut self, unit: &UnitPlan, old: bool) -> Result<bool, FailureReason> {
        if !self.can_submit(unit, old)? {
            return Ok(false);
        }
        let ring = if old { unit.old_commands } else { unit.commands };
        let identity = unit.binding.identity;
        let state = self.state();
        let cell = state.next_cell;
        let token = cell as u64 + 1;
        let completion = HostCommand::completion_wait(
            self.plan.policy,
            unit.completion_base + cell as u64 * 8,
            token,
            CompletionOrdering::WaitBeforeSubsequent,
        )
        .map_err(|_| FailureReason::PublicationCapacity)?;
        let mut tail = state.expected.command_tail as u32;
        // INVALIDATE_IOMMU_ALL is optional, admitted by IASup. Exact opcode
        // 08h/all other bits zero: 48882-3.11 pp136-137, text and PNG checked.
        for words in [[8u64 << 60, 0], completion.words()] {
            self.backend.write_command(identity, ring.backing().base() + u64::from(tail), words)?;
            tail = (tail + 16) % ring.byte_len();
        }
        self.backend.fence(identity, Fence::PublishMemoryBeforeMmio)?;
        if old {
            self.retention.old_queues_may_reference_completion |= 1 << self.cursor;
        }
        // Mark the cell consumed before publication; Err can mean a posted tail
        // write took effect. There is no retry, zeroing, wrap or cell reuse.
        let state = self.state_mut();
        state.next_cell += 1;
        state.waiting_cell = cell;
        state.token = token;
        self.write(identity, Register::CommandTail, u64::from(tail))?;
        self.state_mut().expected.command_tail = u64::from(tail);
        Ok(true)
    }

    fn poll_drain(&mut self, unit: &UnitPlan, old: bool) -> Result<bool, FailureReason> {
        let ring = if old { unit.old_commands } else { unit.commands };
        let snapshot = self.observe(unit, ring)?;
        if snapshot.status & RUN != RUN {
            return Err(FailureReason::EngineStopped);
        }
        let address = unit.completion_base + self.state().waiting_cell as u64 * 8;
        let observed = self.backend.read_completion(unit.binding.identity, address)?;
        if observed == 0 {
            return Ok(false);
        }
        if observed != self.state().token {
            return Err(FailureReason::CompletionStale);
        }
        self.backend.fence(unit.binding.identity, Fence::AcquireCompletion)?;
        // A later hardware error/control loss wins over a matching cell.
        let after = self.observe(unit, ring)?;
        if after.status & RUN != RUN {
            return Err(FailureReason::EngineStopped);
        }
        Ok(true)
    }

    fn observe(
        &mut self,
        unit: &UnitPlan,
        ring: CommandRingGeometry,
    ) -> Result<RegisterObservation, FailureReason> {
        let observed = self.backend.observe(unit.binding.identity, self.epoch)?;
        let previous = self.state().expected;
        const BASE: u64 = 0x000f_ffff_ffff_f000;
        const BUFFER: u64 = BASE | (15 << 56);
        let mut ignored_control = (15 << 18) | (1 << 49) | (1 << 57);
        if previous.extended_features.unwrap_or(0) & (1 << 44) == 0 {
            ignored_control |= 1 << 41;
        }
        if (observed.device_table ^ previous.device_table) & (BASE | 511) != 0
            || (observed.command_buffer ^ previous.command_buffer) & BUFFER != 0
            || (observed.event_log ^ previous.event_log) & BUFFER != 0
            || (observed.control ^ previous.control) & !ignored_control != 0
            || (observed.exclusion_base ^ previous.exclusion_base) & (BASE | 3) != 0
            || (observed.exclusion_limit ^ previous.exclusion_limit) & BASE != 0
            || observed.extended_features != previous.extended_features
            || observed.extended_features2 != previous.extended_features2
            || observed.command_tail != previous.command_tail
            || observed.event_head != previous.event_head
        {
            return Err(FailureReason::SnapshotDrift);
        }
        // Defined optional run/overflow/active fields must remain zero for the
        // admitted basic profile. Unsupported reserved read fields are ignored.
        let features = previous.extended_features.unwrap_or(0);
        let mut optional_status = 0;
        for (supported, mask) in [
            (features & (1 << 1) != 0, 7 << 5),
            (features & (1 << 7) != 0, 7 << 8),
            (features >> 24 & 3 != 0, 3 << 11),
            (features >> 28 & 3 != 0, 3 << 15),
            (features & (1 << 40) != 0, 3 << 17),
        ] {
            if supported {
                optional_status |= mask;
            }
        }
        if observed.status & optional_status != 0 {
            return Err(FailureReason::SnapshotDrift);
        }
        if observed.status & 3 != 0 || observed.event_tail != previous.event_tail {
            return Err(FailureReason::EventPending);
        }
        let head =
            ring.validate_offset(observed.command_head).map_err(|_| FailureReason::QueuePointer)?;
        let tail =
            ring.validate_offset(observed.command_tail).map_err(|_| FailureReason::QueuePointer)?;
        if distance(ring, self.state().head, head) > distance(ring, self.state().head, tail) {
            return Err(FailureReason::QueuePointer);
        }
        self.state_mut().head = head;
        Ok(observed)
    }

    fn write(
        &mut self,
        identity: super::super::binding::UnitIdentity,
        register: Register,
        value: u64,
    ) -> Result<(), FailureReason> {
        self.backend.write_register(identity, register, value).map_err(FailureReason::Backend)
    }
    fn state(&self) -> &UnitState {
        self.states[self.cursor].as_ref().unwrap()
    }
    fn state_mut(&mut self) -> &mut UnitState {
        self.states[self.cursor].as_mut().unwrap()
    }
    fn next(&mut self, phase: Phase) {
        self.cursor += 1;
        if self.cursor == self.plan.len {
            self.cursor = 0;
            self.phase = phase;
        }
    }
    fn fail(&mut self, reason: FailureReason) -> Step {
        let failure = Failure { phase: self.phase, unit: self.cursor, reason };
        self.failure = Some(failure);
        self.phase = Phase::Failed;
        Step::Failed(failure)
    }
}

impl From<BackendError> for FailureReason {
    fn from(error: BackendError) -> Self {
        Self::Backend(error)
    }
}
fn distance(ring: CommandRingGeometry, from: u32, to: u32) -> u32 {
    (to + ring.byte_len() - from) % ring.byte_len()
}
fn preserved_control(registers: RegisterObservation) -> u64 {
    let mask = if registers.extended_features.unwrap_or(0) & (1 << 44) == 0 {
        CONTROL_KEEP & !(1 << 41)
    } else {
        CONTROL_KEEP
    };
    registers.control & mask
}
