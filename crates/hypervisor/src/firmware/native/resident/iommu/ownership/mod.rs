//! Bounded physical-owner transaction with an injected, retained backend.
//!
//! `Transaction` is a live-old-owner transfer with an injected backend. The
//! separate `cold` path is wired to native BSP MMIO/volatile effects before
//! guest release; its first profile is deliberately narrow and holds guests
//! after successful protection. Numeric/offline results prove no hardware run.
#![forbid(unsafe_code)]

mod admission;
mod backend;
pub mod cold;
mod storage;
mod transaction;

pub use crate::memory::iommu::physical::{DrainReceipt, PublicationKey};
pub use admission::{
    AdmissionError, Coverage, CoverageKind, NativeBlocker, Plan, PublicationSpace, UnitPlan,
    native_blockers, require_native_admission,
};
pub use backend::{Backend, BackendError, Fence, PublicationSlot, Register};
pub use storage::{BankError, BankStorage, prepare_banks};
pub use transaction::{
    Failure, FailureReason, LifecycleEvent, Limits, Phase, Retention, Step, Transaction,
};

impl From<super::binding::UnitIdentity> for crate::memory::iommu::physical::PhysicalUnit {
    fn from(identity: super::binding::UnitIdentity) -> Self {
        Self {
            segment: identity.segment,
            device_id: identity.device_id,
            capability_offset: identity.capability_offset,
            mmio_base: identity.mmio_base,
        }
    }
}
