use super::super::{RegisterObservation, binding::UnitIdentity};
use super::{DrainReceipt, Plan, PublicationKey, UnitPlan};
use crate::memory::address::PhysicalRange;

/// Exact destination selected by the transaction. Reuse is possible only when
/// the other slot became the sole active generation and its matching global
/// invalidation completed. The backend must replace ALL previous-generation
/// links, not merge old references into the new image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationSlot {
    pub(super) destination: PhysicalRange,
    pub(super) previous: Option<PhysicalRange>,
    pub(super) reuse_after: Option<DrainReceipt>,
}

impl PublicationSlot {
    pub const fn destination(self) -> PhysicalRange {
        self.destination
    }
    pub const fn previous(self) -> Option<PhysicalRange> {
        self.previous
    }
    pub const fn reuse_after(self) -> Option<DrainReceipt> {
        self.reuse_after
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Register {
    DeviceTable,
    CommandBase,
    EventBase,
    Control,
    CommandHead,
    CommandTail,
    EventHead,
    EventTail,
}

impl Register {
    pub const fn offset(self) -> u16 {
        match self {
            Self::DeviceTable => 0,
            Self::CommandBase => 8,
            Self::EventBase => 16,
            Self::Control => 24,
            Self::CommandHead => 0x2000,
            Self::CommandTail => 0x2008,
            Self::EventHead => 0x2010,
            Self::EventTail => 0x2018,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fence {
    PublishMemoryBeforeMmio,
    AcquireCompletion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendError {
    Unavailable,
    ControlLost,
    RetentionLost,
    Memory,
    Device,
    Composition,
}

/// Trusted effects boundary for the protocol. No native implementation exists.
/// Every call is bounded and nonblocking. A real implementation must own its
/// allocations independently of this Rust value: errors, Drop, reset and panic
/// NEVER unpin backing, release controls, restart a source or restore old roots.
/// Partial register/store effects are possible on Err and are retained.
pub trait Backend {
    /// Acquire the complete control/retention lease before any other effect.
    /// Revalidate the plan against fresh trusted routing, reservations, all-CPU
    /// denials and every alternate fabric/reset/SMM path. Retain the old device
    /// table, old logs/rings and their reachable structures as well as new banks.
    /// Establish that no earlier/queued/fetched command or other engine can
    /// write the newly assigned completion cells. Numeric zero, an epoch tag or
    /// stopping the old producer cannot establish that exclusivity by itself.
    /// Ownership must survive even a partially successful acquire returning Err.
    fn acquire(&mut self, epoch: u64, plan: &Plan) -> Result<(), BackendError>;
    /// Reverify initialized candidate bank words while disconnected; then make
    /// the full bank coherently visible. Borrowed ResourceStorage references
    /// must end before hardware writes completion or event memory.
    fn verify_and_publish_bank(&mut self, unit: &UnitPlan) -> Result<(), BackendError>;
    /// Stop all requester sources and previous software producers. Includes
    /// peer/bypass paths; CPU parking and merely clearing PCI BME do not suffice.
    fn request_quiescence(&mut self, unit: UnitIdentity, epoch: u64) -> Result<(), BackendError>;
    /// True means requesters remain silent, producers surrendered, and remote
    /// IOTLBs are disabled and empty with no outstanding ATS/PASID/PPR work.
    /// The protocol's global invalidation does not invalidate remote IOTLBs.
    fn poll_quiescence(&mut self, unit: UnitIdentity, epoch: u64) -> Result<bool, BackendError>;
    /// Fresh, serialized snapshot under the retained control lease. PCI route,
    /// identity/features, control coverage and epoch are revalidated by adapter.
    fn observe(
        &mut self,
        unit: UnitIdentity,
        epoch: u64,
    ) -> Result<RegisterObservation, BackendError>;
    /// Copy exactly one encoded 16-byte command into admitted retained RAM.
    fn write_command(
        &mut self,
        unit: UnitIdentity,
        address: u64,
        words: [u64; 2],
    ) -> Result<(), BackendError>;
    /// Coherent volatile completion read. Never a cached plain Rust reference
    /// to memory that an IOMMU may mutate. The adapter checks CPU mapping/cache.
    fn read_completion(&mut self, unit: UnitIdentity, address: u64) -> Result<u64, BackendError>;
    fn fence(&mut self, unit: UnitIdentity, fence: Fence) -> Result<(), BackendError>;
    /// Exactly one aligned 64-bit MMIO write with required device ordering.
    fn write_register(
        &mut self,
        unit: UnitIdentity,
        register: Register,
        value: u64,
    ) -> Result<(), BackendError>;
    /// Publish already validated, immutable composition generation into this
    /// unit's selected inactive PublicationSpace slot. Check every mapping and
    /// interrupt output against all host exclusions. Replace ALL links into
    /// `slot.previous()` with the new complete image; preserving even one old
    /// link forbids success. Retain BOTH slots through failure or drain. A slot
    /// reused after generation 2 carries the exact preceding drain receipt.
    /// Do not accept guest physical pointers as hardware pointers. Error may
    /// have changed tables; it permanently stops this transaction.
    fn publish_composed(
        &mut self,
        key: PublicationKey,
        unit: &UnitPlan,
        slot: PublicationSlot,
    ) -> Result<(), BackendError>;
}
