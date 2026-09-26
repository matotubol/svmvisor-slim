//! Bounded, inert four-level nested page tables: the resident `IdentityNpt`
//! (identity outside the excluded monitor pool and explicit control pages).
//!
//! AMD APM vol. 2 rev. 3.44 sections 5.3.5, 5.4 and 15.25: every present
//! entry has U/S=1 (15.25.5 treats every nested access as a user access),
//! parent entries permit writes/execution, leaf entries restrict them, and
//! 1-GByte/2-MByte leaves keep bits 29:13 / 20:13 and the bit-12 PAT zero.
//! NX requires supported NX and host EFER.NXE=1 (15.25.7). The caller supplies
//! evidence of host four-level long mode, because the nested walk uses the
//! paging mode the host had at VMRUN (15.25.3); GMET, SSS and encrypted modes
//! must be disabled. Initial PWT/PCD/PAT are zero, so the nested type is entry 0 of
//! the *host* PAT register at VMRUN (15.25.8, Table 15-19). Guest PAT writes
//! reach only the replicated guest copy (15.25.2), so the host PAT captured at
//! arm stays the nested PAT; index zero alone does not establish WB memory.
//! The cache owner stages replacement selectors with `retype_identity`, retaining
//! the identity domain, permanent zero holes and configuration permissions.
//! Control-page policies are immutable numeric plans, never hardware ownership
//! or reader authority. A fresh construction must receive the retained policy.
//! Allocation, actual copying to assigned physical addresses, ownership, PAT/
//! MTRR validation, guest state, TLB invalidation and enabling NPT are external.
//! No builder here may edit tables used by a running CPU.
//! `window` stages a one-page read-only/NX alias in separate inactive storage;
//! its result has additional lifetime/event/flush obligations and is never
//! admitted by the existing unchanged-mappings entry trial.

pub use crate::memory::npt::{
    cache::{
        CACHE_TABLE_COUNT, CacheMapping, CacheNptError, CacheTableStorage, identity_is_quarantined,
        retype_identity, retype_identity_policy, retype_identity_policy_with_denials,
        retype_identity_policy_with_guards,
    },
    denial::{ControlPageDenialError, ControlPageDenials, MAX_CONTROL_PAGE_RANGES},
    identity::{
        IdentityNpt, IdentityNptError, IdentityTranslation, MAX_IDENTITY_EXCLUSION_BYTES,
        identity_protection_range, restore_identity_write_range, set_identity_write_range,
    },
    table::{NptEvidence, TABLE_COUNT, TableStorage, TableView},
};

mod cache;
mod denial;
mod identity;
mod table;
pub mod table_guard;
