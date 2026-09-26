//! Publication/completion correlation shared by the virtual device and an owner.
//!
//! A receipt describes execution by its producer's backend. An injected test
//! backend can produce synthetic receipts; neither this type nor numeric equality
//! grants native hardware authority. No native producer is installed. The actual
//! owner must separately retain controls, resources, DMA integrity and its epoch.
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysicalUnit {
    pub segment: u16,
    pub device_id: u16,
    pub capability_offset: u16,
    pub mmio_base: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationKey {
    pub unit: PhysicalUnit,
    pub epoch: u64,
    pub generation: u64,
}

/// Produced only after the owner's matching invalidations and private coherent
/// completion-store observation. Queue fetch progress cannot produce one.
/// Receivers must match the WHOLE key, require mapping publication, consume it
/// once, and revoke their owner epoch on reset/power/control-integrity loss.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrainReceipt {
    key: PublicationKey,
    mapping_publication: bool,
}

impl DrainReceipt {
    #[cfg(not(target_os = "none"))]
    pub(crate) const fn completed(key: PublicationKey, mapping_publication: bool) -> Self {
        Self { key, mapping_publication }
    }

    pub const fn key(self) -> PublicationKey {
        self.key
    }
    pub fn matches(self, key: PublicationKey) -> bool {
        self.key == key
    }
    pub const fn is_mapping_publication(self) -> bool {
        self.mapping_publication
    }
}
