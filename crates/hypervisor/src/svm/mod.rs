//! AMD SVM control structures and bounded exit classification and emulation.
//!
//! Preparing a resume here does not itself enter a guest or establish hardware
//! readiness; the caller must satisfy the entry and state-ownership contracts.

pub mod cache_policy;
pub mod diagnostic_config;
pub mod dispatch;
pub mod events;
pub mod exit;
pub mod mcax;
pub mod permission_maps;
pub mod startup;
pub mod syscfg;
pub mod vmcb;
pub mod vmcr;
