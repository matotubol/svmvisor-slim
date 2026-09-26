use super::super::{Fence, Register};
use crate::{
    firmware::native::resident::iommu::{
        MAX_OBSERVED_UNITS, RegisterObservation,
        binding::UninstalledUnitPlan,
        resources::{COMMAND_OFFSET, COMPLETION_OFFSET, EVENT_OFFSET},
    },
    memory::{
        address::{AddressPolicy, PhysicalRange},
        iommu::{
            commands::{CompletionOrdering, HostCommand},
            queue::CommandRingGeometry,
        },
    },
};

const BASE: u64 = 0x000f_ffff_ffff_f000;
const CMD: u64 = 1 << 12;
const EVENT: u64 = 1 << 2;
const CMD_RUN: u64 = 1 << 4;
const EVENT_RUN: u64 = 1 << 3;
const KEEP: u64 = (127 << 5) | (1 << 23) | (1 << 41);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Limits,
    Address,
    UntranslatedTraffic,
    OldDeviceBypass,
    OldCommandBuffer,
    OldBufferAlias,
    Changed,
    EngineStopped,
    Event,
    Timeout,
    Completion,
    Access,
    Image,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub polls: u32,
}

/// Effects used by the native post-EBS BSP. RAM and MMIO ranges are admitted
/// against actual current mappings before construction; methods may fail after
/// a partial effect. There is no rollback, source restart or deallocation.
pub trait Access {
    fn observe(&mut self) -> Result<RegisterObservation, Error>;
    fn write_register(&mut self, register: Register, value: u64) -> Result<(), Error>;
    fn write_command(&mut self, address: u64, words: [u64; 2]) -> Result<(), Error>;
    fn read_completion(&mut self, address: u64) -> Result<u64, Error>;
    fn fence(&mut self, fence: Fence) -> Result<(), Error>;
}

/// Matching hardware completion for this exact table/ring, not permission to
/// release Windows or a claim that device producers have been quiesced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Published {
    device_table: u64,
    completion: u64,
    completion_address: u64,
    expected: RegisterObservation,
}
impl Published {
    pub const fn device_table(self) -> u64 {
        self.device_table
    }
    pub const fn completion(self) -> u64 {
        self.completion
    }

    /// Recheck earlier units after all units publish. This must precede any
    /// decision about guest release; a later unit's success cannot mask loss
    /// of an earlier unit's registers, engines or matching completion cell.
    pub fn revalidate(self, io: &mut impl Access) -> Result<(), Error> {
        wait_completion(
            io,
            &self.expected,
            self.completion_address,
            self.completion,
            Limits { polls: 1 },
            true,
        )
    }
}

/// Admit all old hardware backing before touching any unit. The general binder
/// excludes these extents from the new pool/control pages, but intentionally
/// does not establish independent old producers. Shared command/event memory
/// could otherwise let another engine supply the first engine's completion or
/// overwrite queued commands. This narrow boot profile rejects all old-buffer
/// overlap, including read-only device-table aliases.
pub fn validate_old_buffers<'a>(
    policy: AddressPolicy,
    units: impl IntoIterator<Item = &'a UninstalledUnitPlan>,
) -> Result<(), Error> {
    let mut extents: [Option<PhysicalRange>; MAX_OBSERVED_UNITS * 3] =
        [None; MAX_OBSERVED_UNITS * 3];
    let mut used = 0;
    for unit in units {
        let r = unit.observed_registers;
        let device = policy
            .validate(r.device_table & BASE, ((r.device_table & 511) + 1) * 4096, 4096)
            .map_err(|_| Error::Address)?;
        let commands = ring(policy, r.command_buffer)?;
        commands.validate_offset(r.command_head).map_err(|_| Error::OldCommandBuffer)?;
        commands.validate_offset(r.command_tail).map_err(|_| Error::OldCommandBuffer)?;
        let events =
            if r.event_log & BASE == 0 && r.control & EVENT == 0 && r.status & EVENT_RUN == 0 {
                None
            } else {
                let events = ring(policy, r.event_log)?;
                events.validate_offset(r.event_head).map_err(|_| Error::OldCommandBuffer)?;
                events.validate_offset(r.event_tail).map_err(|_| Error::OldCommandBuffer)?;
                Some(events.backing())
            };
        for extent in [Some(device), Some(commands.backing()), events].into_iter().flatten() {
            if used == extents.len() {
                return Err(Error::Limits);
            }
            if extents[..used]
                .iter()
                .flatten()
                .any(|old| extent.base() <= old.last_byte() && old.base() <= extent.last_byte())
            {
                return Err(Error::OldBufferAlias);
            }
            extents[used] = Some(extent);
            used += 1;
        }
    }
    if used == 0 {
        return Err(Error::Limits);
    }
    Ok(())
}

/// A bounded old-DTE profile with actual host translation, no EX, IOTLB,
/// SysMgt, guest translation, PASID or hardware page writes. Invalid V=0 DTEs
/// bypass; Mode=0 is conservatively excluded from this first drain profile.
/// The caller must read EVERY entry in the old size and retain old RAM until
/// publication completes. Out-of-size DeviceIDs fault (AMD p61).
pub fn validate_old_dte(policy: AddressPolicy, words: [u64; 4]) -> Result<(), Error> {
    if words[0] & 3 != 3
        || !(1..=4).contains(&((words[0] >> 9) & 7))
        || words[0] & !(BASE | (3 << 61) | (7 << 9) | 3) != 0
        || words[1] & !0xffff != 0
        || words[3] != 0
    {
        return Err(Error::OldDeviceBypass);
    }
    policy.validate(words[0] & BASE, 4096, 4096).map_err(|_| Error::Address)?;
    Ok(())
}

/// Establish host exclusion from trusted pre-guest construction. Unlike the
/// live-owner transaction, no preexisting CPU/DMA-denied bank assertion occurs.
/// The native caller checks all control denials, fresh old-DTE/no-bypass state,
/// no remote ATS, disjoint old buffers, and verifies the disconnected new bank
/// and image first.
///
/// The IOMMU MUST remain enabled: earlier untranslated traffic is outside the
/// p139 drain guarantee. Old command/event engines need not be running, but a
/// valid firmware command ring is required so a real old completion can precede
/// its stop. Empty/head-equals-tail is never substituted for that completion.
/// New DMA may continue throughout; the caller does NOT call this quiescence.
pub fn publish(
    io: &mut impl Access,
    policy: AddressPolicy,
    unit: &UninstalledUnitPlan,
    device_table: u64,
    limits: Limits,
) -> Result<Published, Error> {
    if limits.polls == 0 {
        return Err(Error::Limits);
    }
    // Command heads, event tails and status can progress after discovery.
    // Revalidate every software-controlled field, then use the fresh hardware
    // pointers. Progress remains queue metadata, never a completion proof.
    let initial = snapshot(io, &unit.observed_registers)?;
    if initial.control & 1 == 0 {
        return Err(Error::UntranslatedTraffic);
    }
    if initial.exclusion_base & 1 != 0 {
        return Err(Error::UntranslatedTraffic);
    }
    if device_table & 511 != 511
        || device_table & !(BASE | 511) != 0
        || policy.validate(device_table & BASE, 0x200000, 4096).is_err()
    {
        return Err(Error::Address);
    }
    let old = ring(policy, initial.command_buffer)?;
    let mut tail =
        old.validate_offset(initial.command_tail).map_err(|_| Error::OldCommandBuffer)?;
    old.validate_offset(initial.command_head).map_err(|_| Error::OldCommandBuffer)?;
    let new = CommandRingGeometry::new(policy, unit.bank.base() + COMMAND_OFFSET, 1)
        .map_err(|_| Error::Address)?;
    let completion = unit.bank.base() + COMPLETION_OFFSET;
    if io.read_completion(completion)? != 0 || io.read_completion(completion + 8)? != 0 {
        return Err(Error::Completion);
    }
    let mut expected = initial;
    // Start a stopped firmware ring only after native RW/WB admission of its
    // complete extent. Keep host translation continuously on.
    if expected.control & CMD == 0 {
        expected.control |= CMD;
        io.write_register(Register::Control, expected.control)?;
    }
    wait(io, &expected, limits, |r| r.status & CMD_RUN != 0)?;
    wait(io, &expected, limits, |r| {
        old.validate_offset(r.command_head).is_ok_and(|head| (tail + 16) % old.byte_len() != head)
    })?;
    let old_completion = HostCommand::completion_wait(
        policy,
        completion,
        1,
        CompletionOrdering::WaitBeforeSubsequent,
    )
    .map_err(|_| Error::Address)?;
    io.write_command(old.backing().base() + u64::from(tail), old_completion.words())?;
    tail = (tail + 16) % old.byte_len();
    io.fence(Fence::PublishMemoryBeforeMmio)?;
    expected.command_tail = u64::from(tail);
    io.write_register(Register::CommandTail, expected.command_tail)?;
    wait_completion(io, &expected, completion, 1, limits, false)?;
    // No old producer exists in this serialized pre-guest interval. The exact
    // completion, followed by stopped status, permits changing queue pointers.
    expected.control = (expected.control & KEEP) | 1;
    io.write_register(Register::Control, expected.control)?;
    wait(io, &expected, limits, |r| r.status & (CMD_RUN | EVENT_RUN) == 0)?;
    io.fence(Fence::PublishMemoryBeforeMmio)?;
    for (register, value) in [
        (Register::DeviceTable, device_table),
        (Register::CommandBase, new.base_register_value()),
        (Register::CommandHead, 0),
        (Register::CommandTail, 0),
        (Register::EventBase, (unit.bank.base() + EVENT_OFFSET) | (8 << 56)),
        (Register::EventHead, 0),
        (Register::EventTail, 0),
    ] {
        io.write_register(register, value)?;
    }
    expected.device_table = device_table;
    expected.command_buffer = new.base_register_value();
    expected.command_head = 0;
    expected.command_tail = 0;
    expected.event_log = (unit.bank.base() + EVENT_OFFSET) | (8 << 56);
    expected.event_head = 0;
    expected.event_tail = 0;
    io.fence(Fence::PublishMemoryBeforeMmio)?;
    expected.control |= CMD | EVENT;
    io.write_register(Register::Control, expected.control)?;
    wait(io, &expected, limits, |r| r.status & (CMD_RUN | EVENT_RUN) == (CMD_RUN | EVENT_RUN))?;

    // All 16-bit requesters have the same host policy, so initial exclusion
    // never resolves conflicting alias declarations by precedence. IASup is an
    // optimization only. The baseline path flushes every DTE, domain and IRTE.
    let all = initial.extended_features.unwrap_or(0) & (1 << 6) != 0;
    let total = if all { 1 } else { 3 * 65536 };
    let mut cursor = 0u32;
    let mut token = 1u64;
    tail = 0;
    while cursor < total {
        let count = (total - cursor).min(254);
        for _ in 0..count {
            let words = if all {
                [8u64 << 60, 0]
            } else if cursor < 65536 {
                HostCommand::invalidate_device_entry(cursor as u16).words()
            } else if cursor < 131072 {
                HostCommand::invalidate_domain(cursor as u16).words()
            } else {
                [(5u64 << 60) | u64::from(cursor as u16), 0]
            };
            io.write_command(new.backing().base() + u64::from(tail), words)?;
            tail = (tail + 16) % new.byte_len();
            cursor += 1;
        }
        let marker = HostCommand::completion_wait(
            policy,
            completion + 8,
            token,
            CompletionOrdering::WaitBeforeSubsequent,
        )
        .map_err(|_| Error::Address)?;
        io.write_command(new.backing().base() + u64::from(tail), marker.words())?;
        tail = (tail + 16) % new.byte_len();
        io.fence(Fence::PublishMemoryBeforeMmio)?;
        expected.command_tail = u64::from(tail);
        io.write_register(Register::CommandTail, expected.command_tail)?;
        wait_completion(io, &expected, completion + 8, token, limits, true)?;
        // f=1 + this exact completion makes every preceding batch unreachable.
        // Reuse the cell with a DISTINCT value; never clear it to accept stale 1.
        token += 1;
    }
    Ok(Published {
        device_table,
        completion: token - 1,
        completion_address: completion + 8,
        expected,
    })
}

fn ring(policy: AddressPolicy, raw: u64) -> Result<CommandRingGeometry, Error> {
    let code = ((raw >> 56) & 15) as u32;
    if code < 8 || raw & BASE == 0 || raw & !(BASE | (15 << 56)) != 0 {
        return Err(Error::OldCommandBuffer);
    }
    CommandRingGeometry::new(policy, raw & BASE, 1usize << (code - 8))
        .map_err(|_| Error::OldCommandBuffer)
}

fn snapshot(
    io: &mut impl Access,
    expected: &RegisterObservation,
) -> Result<RegisterObservation, Error> {
    let r = io.observe()?;
    if r.control != expected.control
        || r.device_table != expected.device_table
        || r.command_buffer != expected.command_buffer
        || r.command_tail != expected.command_tail
        || r.event_log != expected.event_log
        || r.event_head != expected.event_head
        || r.exclusion_base != expected.exclusion_base
        || r.exclusion_limit != expected.exclusion_limit
        || r.extended_features != expected.extended_features
        || r.extended_features2 != expected.extended_features2
    {
        return Err(Error::Changed);
    }
    Ok(r)
}

fn wait(
    io: &mut impl Access,
    expected: &RegisterObservation,
    limits: Limits,
    ready: impl Fn(&RegisterObservation) -> bool,
) -> Result<(), Error> {
    for _ in 0..limits.polls {
        let r = snapshot(io, expected)?;
        if ready(&r) {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(Error::Timeout)
}

fn wait_completion(
    io: &mut impl Access,
    expected: &RegisterObservation,
    address: u64,
    token: u64,
    limits: Limits,
    new: bool,
) -> Result<(), Error> {
    for _ in 0..limits.polls {
        let r = snapshot(io, expected)?;
        let run = if new { CMD_RUN | EVENT_RUN } else { CMD_RUN };
        if r.status & run != run {
            return Err(Error::EngineStopped);
        }
        if new && (r.status & 3 != 0 || r.event_tail != 0) {
            return Err(Error::Event);
        }
        let value = io.read_completion(address)?;
        if value == token {
            io.fence(Fence::AcquireCompletion)?;
            let after = snapshot(io, expected)?;
            if after.status & run != run {
                return Err(Error::EngineStopped);
            }
            if new && (after.status & 3 != 0 || after.event_tail != 0) {
                return Err(Error::Event);
            }
            return Ok(());
        }
        if value > token {
            return Err(Error::Completion);
        }
        core::hint::spin_loop();
    }
    Err(Error::Timeout)
}
