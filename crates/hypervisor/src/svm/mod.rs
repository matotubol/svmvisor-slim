//! AMD SVM control structures and bounded exit classification and emulation.
//!
//! Preparing a resume here does not itself enter a guest or establish hardware
//! readiness; the caller must satisfy the entry and state-ownership contracts.

pub mod cache_policy;
pub mod configuration;
pub mod control_msrs;
pub mod diagnostic_config;
pub mod dispatch;
pub mod events;
pub mod exit;
pub mod instructions;
pub mod mcax;
pub mod mmio;
pub mod pci;
pub mod permission_maps;
pub mod protection;
pub mod startup;
pub mod syscfg;
pub mod vmcb;
pub mod vmcr;
