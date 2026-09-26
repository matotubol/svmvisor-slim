//! Serialized pre-guest construction and physical publication.
//!
//! This is deliberately separate from `Plan`: initial protection is established
//! by the new roots and their matching hardware invalidations, not supplied as
//! a circular `dma_denied` assertion. Firmware and devices remain trusted until
//! publication completes. CPU rendezvous is serialization, never a DMA drain.
//! The first native profile requires old DMA to have passed through host
//! translation; disabled/bypass/ATS profiles need a platform source-stop and
//! fabric-drain implementation and are rejected before register writes.

mod image;
mod protocol;

pub use image::{IdentityImage, ImageError, prepare_identity, verify_identity};
pub use protocol::{
    Access, Error, Limits, Published, publish, validate_old_buffers, validate_old_dte,
};
