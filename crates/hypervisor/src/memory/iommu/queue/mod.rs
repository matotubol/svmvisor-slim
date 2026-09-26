//! Bounded command-buffer preparation over real, caller-owned storage.
//!
//! This producer stops before hardware publication. It never accesses MMIO,
//! dereferences a physical address, installs a queue, polls hardware or grants
//! reader/isolation authority. Ordinary borrowed storage must be disconnected
//! from every hardware consumer throughout its use here. Actual retention,
//! coherent visibility, DMA integrity, control ownership and submission need a
//! separately reviewed native owner; a caller-supplied extent cannot prove them.
//!
//! Head observations are numeric fetch progress only. Completion comparisons
//! are likewise injected numeric evidence, never invalidation/drain or authority
//! to reclaim memory. Completion cells and nonzero increasing values are never
//! reused during this producer's lifetime, even after an equal observation.
//!
//! Sources: 48882-3.11 physical pp122-125,215,252-253, text and PNG checked;
//! initialization pp120-121 and ordering pp138-139. See README.md.
#![forbid(unsafe_code)]

mod geometry;
mod storage;

pub use geometry::CommandRingGeometry;
pub use storage::{CommandPage, CompletionPage};

use super::commands::{CommandError, CommandOperands, HostCommand};
use crate::memory::address::{AddressError, AddressPolicy, PAGE_BYTES, PhysicalRange};

pub const COMMAND_BYTES: usize = 16;
pub const MIN_COMMAND_ENTRIES: usize = 256;
pub const MAX_COMMAND_ENTRIES: usize = 32_768;
pub const MAX_COMMAND_PAGES: usize = MAX_COMMAND_ENTRIES * COMMAND_BYTES / PAGE_BYTES;
pub const COMPLETION_CELLS: usize = PAGE_BYTES / core::mem::size_of::<u64>();

/// A disconnected producer. It borrows every assigned byte until dropped;
/// dropping it is not a hardware teardown protocol or permission to reclaim RAM.
#[derive(Debug)]
pub struct CommandBuffer<'a> {
    policy: AddressPolicy,
    geometry: CommandRingGeometry,
    pages: &'a mut [CommandPage],
    completion_backing: PhysicalRange,
    completion: &'a mut CompletionPage,
    head_offset: u32,
    tail_offset: u32,
    expected: [u64; COMPLETION_CELLS],
    last_completion_value: u64,
}

impl<'a> CommandBuffer<'a> {
    /// Validate and clear a new disconnected ring and completion page. There is
    /// no constructor for adopting or restarting a live ring. Neither storage
    /// may have an outstanding hardware reference, and both must remain
    /// disconnected throughout this borrow. Future hardware use requires a
    /// separate reviewed native owner, retained backing and publication protocol.
    ///
    /// `protected_extent` is the caller's numeric confinement boundary. Both
    /// complete storage spans must fit inside it and must not overlap. The
    /// extent is revalidated under `policy`; this does not establish its actual
    /// CPU/DMA protection, identity mapping, system-RAM type or allocation.
    /// Every returned error leaves all caller storage unchanged.
    pub fn prepare(
        policy: AddressPolicy,
        protected_extent: PhysicalRange,
        command_base: u64,
        pages: &'a mut [CommandPage],
        completion_base: u64,
        completion: &'a mut CompletionPage,
    ) -> Result<Self, QueueError> {
        let geometry = CommandRingGeometry::new(policy, command_base, pages.len())?;
        if protected_extent.len() & (PAGE_BYTES as u64 - 1) != 0 {
            return Err(QueueError::ProtectedLengthNotPageAligned);
        }
        let protected_extent = policy
            .validate(protected_extent.base(), protected_extent.len(), PAGE_BYTES as u64)
            .map_err(|error| QueueError::Address { backing: Backing::ProtectedExtent, error })?;
        let completion_backing = policy
            .validate(completion_base, PAGE_BYTES as u64, PAGE_BYTES as u64)
            .map_err(|error| QueueError::Address { backing: Backing::Completion, error })?;
        for (kind, range) in
            [(Backing::Commands, geometry.backing()), (Backing::Completion, completion_backing)]
        {
            if range.base() < protected_extent.base()
                || range.last_byte() > protected_extent.last_byte()
            {
                return Err(QueueError::OutsideProtectedExtent(kind));
            }
        }
        if geometry.backing().base() <= completion_backing.last_byte()
            && completion_backing.base() <= geometry.backing().last_byte()
        {
            return Err(QueueError::OverlappingBacking);
        }

        for page in pages.iter_mut() {
            page.bytes.fill(0);
        }
        completion.values.fill(0);
        Ok(Self {
            policy,
            geometry,
            pages,
            completion_backing,
            completion,
            head_offset: 0,
            tail_offset: 0,
            expected: [0; COMPLETION_CELLS],
            last_completion_value: 0,
        })
    }

    pub const fn geometry(&self) -> CommandRingGeometry {
        self.geometry
    }

    pub const fn completion_backing(&self) -> PhysicalRange {
        self.completion_backing
    }

    pub fn pages(&self) -> &[CommandPage] {
        self.pages
    }

    pub fn completion_page(&self) -> &CompletionPage {
        self.completion
    }

    pub const fn head_offset(&self) -> u32 {
        self.head_offset
    }

    /// Prepared byte offset only; never a tail value published to hardware.
    pub const fn tail_offset(&self) -> u32 {
        self.tail_offset
    }

    pub const fn available_entries(&self) -> usize {
        self.geometry.usable_entries()
            - self.geometry.distance(self.head_offset, self.tail_offset) as usize / COMMAND_BYTES
    }

    pub fn completion_cell_address(&self, cell: usize) -> Result<u64, QueueError> {
        if cell >= COMPLETION_CELLS {
            return Err(QueueError::InvalidCompletionCell(cell));
        }
        Ok(self.completion_backing.base() + cell as u64 * 8)
    }

    /// Check a caller-supplied raw head observation against previously observed
    /// head and prepared tail. A backward or beyond-tail move is rejected.
    /// Accepted progress makes command slots reusable in this offline model;
    /// it never frees a completion cell, table, DMA output or other resource.
    ///
    /// This does not establish the sample's origin, freshness or reset epoch.
    /// Hardware head advancement means fetched/validated, not executed (p252).
    pub fn observe_head(&mut self, raw: u64) -> Result<HeadProgress, QueueError> {
        let observed_offset = self.geometry.validate_offset(raw)?;
        let advance = self.geometry.distance(self.head_offset, observed_offset);
        if advance > self.geometry.distance(self.head_offset, self.tail_offset) {
            return Err(QueueError::HeadBeyondPreparedTail {
                previous: self.head_offset,
                observed: observed_offset,
                prepared_tail: self.tail_offset,
            });
        }
        let progress = HeadProgress {
            previous_offset: self.head_offset,
            observed_offset,
            fetched_commands: advance as usize / COMMAND_BYTES,
        };
        self.head_offset = observed_offset;
        Ok(progress)
    }

    /// Emit one bounded batch without publishing it. Command words are copied
    /// in explicit little-endian order. Empty batches and insufficient capacity
    /// are rejected before scanning commands. All command/address/freshness
    /// checks precede every storage and producer-state change.
    ///
    /// Completion destinations must name an aligned cell inside this borrowed
    /// completion page; arbitrary guest/system destinations are rejected even
    /// when inside the wider protected extent. Each cell can be used only once.
    /// Values must be strictly increasing across this producer's lifetime and
    /// must differ from the cell's initial zero. Exhaustion never wraps values.
    pub fn enqueue(&mut self, commands: &[HostCommand]) -> Result<PreparedBatch, QueueError> {
        if commands.is_empty() {
            return Err(QueueError::EmptyBatch);
        }
        let available = self.available_entries();
        if commands.len() > available {
            return Err(QueueError::InsufficientCapacity { requested: commands.len(), available });
        }
        let last_completion_value = self.check_commands(commands)?;
        let start_offset = self.tail_offset;
        let mut offset = start_offset;
        for command in commands {
            let words = command.words();
            let page = offset as usize / PAGE_BYTES;
            let byte = offset as usize % PAGE_BYTES;
            self.pages[page].bytes[byte..byte + 8].copy_from_slice(&words[0].to_le_bytes());
            self.pages[page].bytes[byte + 8..byte + COMMAND_BYTES]
                .copy_from_slice(&words[1].to_le_bytes());
            if let CommandOperands::CompletionWait { store_address, store_data, .. } =
                command.operands()
            {
                // Preflight admitted this whole cell and refused duplicates.
                let cell = ((store_address - self.completion_backing.base()) / 8) as usize;
                self.expected[cell] = store_data;
            }
            offset = self.geometry.next(offset);
        }
        self.last_completion_value = last_completion_value;
        self.tail_offset = offset;
        Ok(PreparedBatch { start_offset, tail_offset: offset, command_count: commands.len() })
    }

    /// Compare an injected numeric sample with the once-emitted cell value.
    /// Equality is not a fresh hardware observation, completion/drain proof or
    /// permission to recycle any resource. Even an equal sample changes no state.
    pub fn compare_completion(
        &self,
        cell: usize,
        observed_value: u64,
    ) -> Result<CompletionComparison, QueueError> {
        let address = self.completion_cell_address(cell)?;
        let expected_value = self.expected[cell];
        if expected_value == 0 {
            return Err(QueueError::UnusedCompletionCell(cell));
        }
        Ok(CompletionComparison { address, expected_value, observed_value })
    }

    fn check_commands(&self, commands: &[HostCommand]) -> Result<u64, QueueError> {
        let mut seen = [0u64; COMPLETION_CELLS / 64];
        let mut previous_value = self.last_completion_value;
        for (index, command) in commands.iter().enumerate() {
            // Reapply this buffer's policy, even to a command built under a
            // different/wider policy. Typed operands do not establish backing.
            HostCommand::decode(self.policy, command.words())
                .map_err(|error| QueueError::Command { index, error })?;
            if let CommandOperands::CompletionWait { store_address, store_data, .. } =
                command.operands()
            {
                let offset = store_address.checked_sub(self.completion_backing.base());
                let Some(offset) = offset.filter(|offset| *offset < PAGE_BYTES as u64) else {
                    return Err(QueueError::CompletionOutsideBacking { index, store_address });
                };
                // HostCommand's reapplied policy established eight-byte
                // alignment, so the final in-page offset names a whole cell.
                let cell = (offset / 8) as usize;
                let mask = 1u64 << (cell % 64);
                if self.expected[cell] != 0 || seen[cell / 64] & mask != 0 {
                    return Err(QueueError::CompletionCellAlreadyUsed { index, cell });
                }
                if store_data <= previous_value {
                    return Err(QueueError::CompletionValueNotIncreasing {
                        index,
                        previous: previous_value,
                        requested: store_data,
                    });
                }
                if store_data == self.completion.values[cell] {
                    return Err(QueueError::CompletionValueAlreadyPresent { index, cell });
                }
                seen[cell / 64] |= mask;
                previous_value = store_data;
            }
        }
        Ok(previous_value)
    }
}

/// Numeric facts about bytes emitted into disconnected storage, not a
/// submission receipt, publication action or hardware-accepted command batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedBatch {
    pub start_offset: u32,
    pub tail_offset: u32,
    pub command_count: usize,
}

/// Checked numeric pointer movement; this does not report command execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadProgress {
    pub previous_offset: u32,
    pub observed_offset: u32,
    pub fetched_commands: usize,
}

/// An ordinary numeric comparison with no authenticity/freshness guarantee.
/// It changes no producer state and cannot grant resource reclamation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletionComparison {
    pub address: u64,
    pub expected_value: u64,
    pub observed_value: u64,
}

impl CompletionComparison {
    pub const fn equal(self) -> bool {
        self.expected_value == self.observed_value
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backing {
    Commands,
    Completion,
    ProtectedExtent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    InvalidCommandPageCount(usize),
    Address { backing: Backing, error: AddressError },
    ProtectedLengthNotPageAligned,
    OutsideProtectedExtent(Backing),
    OverlappingBacking,
    InvalidPointerBits(u64),
    PointerOutsideRing(u64),
    HeadBeyondPreparedTail { previous: u32, observed: u32, prepared_tail: u32 },
    EmptyBatch,
    InsufficientCapacity { requested: usize, available: usize },
    Command { index: usize, error: CommandError },
    CompletionOutsideBacking { index: usize, store_address: u64 },
    InvalidCompletionCell(usize),
    UnusedCompletionCell(usize),
    CompletionCellAlreadyUsed { index: usize, cell: usize },
    CompletionValueNotIncreasing { index: usize, previous: u64, requested: u64 },
    CompletionValueAlreadyPresent { index: usize, cell: usize },
}

#[cfg(test)]
mod tests;
