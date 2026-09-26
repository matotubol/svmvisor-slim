//! Resident host: the bridge ABI shared with DXE and the resident assembly
//! (`abi`), stopped-guest instruction fetch (`fetch`), terminal evidence
//! (`terminal`) and the per-CPU runtime linked into the resident payload
//! (`runtime`).

#[cfg(feature = "resident-runtime")]
pub use crate::host::resident::runtime::prepare;
pub use crate::{
    guest::continuation::NATIVE_BOOTSTRAP_ACK as BOOTSTRAP_ACK,
    host::resident::abi::{
        ArmRuntime, BridgeContext, CACHE_SHARED_BYTES, CACHE_SHARED_OFFSET, DIRECTORY_VERSION,
        Dispatch, Enter, IMAGE_LIMIT_OFFSET, IOMMU_COMPOSITION_BYTES, IOMMU_PRESENTATION_BYTES,
        IOMMU_RESOURCE_BYTES, IOMMU_RETAINED_BYTES, IOMMU_UNIT_STRIDE, IOMMU_WORKSPACE_BYTES,
        MAX_NATIVE_IOMMU_UNITS, MAX_RESIDENT_CPUS, NativeIommuResources, NativeIommuShared,
        PrepareRuntime, ResidentDirectory, SHARED_RETAINED_BYTES, STARTUP_PAGE_OFFSET,
        TAKEOVER_TAG, is_valid_pool_slot, native_iommu_resources, native_iommu_shared,
        pool_bytes_for_processors, pool_processor_count, retained_iommu_base,
        svmvisor_resident_callback, svmvisor_resident_guest_ack, svmvisor_resident_guest_after_ack,
        svmvisor_resident_guest_resume,
    },
};

mod abi;
pub mod configuration;
pub mod control;
pub mod fetch;
pub mod inventory;
pub mod iommu_runtime;
pub mod platform;
#[cfg(feature = "resident-runtime")]
mod runtime;
pub mod terminal;

#[cfg(all(target_os = "none", feature = "resident-runtime"))]
mod entry;
