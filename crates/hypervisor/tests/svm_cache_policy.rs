//! Independent architectural regressions: APM2 physical pp286/616 and
//! PPR57896 physical p202 (including the register/table images).
use svmvisor_hypervisor::{
    arch::x86_64::msr::{MTRR_DEF_TYPE, SYS_CFG},
    svm::cache_policy::{CacheBank, CacheEffect, CacheError, FIXED_MSRS, TOP_MEM},
};

// Explicit representative firmware fixture, not a PAT value exported by the
// failing snapshot: WB, WT, UC-, UC, repeated in the upper four entries.
const FIRMWARE_PAT_FIXTURE: u64 = 0x0007_0406_0007_0406;
const DRAM_WB: u64 = 0x1e1e_1e1e_1e1e_1e1e;
const DRAM_WT: u64 = 0x1c1c_1c1c_1c1c_1c1c;

fn firmware() -> CacheBank {
    CacheBank {
        capability: 0x508,
        default: 0xc06,
        sys_cfg: 0x740000,
        top_mem: 0xc0000000,
        tom2: 0x10_0000_0000,
        fixed: [DRAM_WB; 11],
        ..CacheBank::EMPTY
    }
}

#[test]
fn windows_fixed_mtrr_update_can_disable_e_without_changing_physical_bank() {
    let physical = firmware();
    let original = physical;
    physical.validate().unwrap();
    // This is a synthetic restoration sequence around the observed SYS_CFG
    // write, not a claim that the snapshot exported all Windows operands.
    // APM2 p286: E=0 means UC regardless of FE/type; no CR0.CD prerequisite.
    let disabled = physical.prepare_write(MTRR_DEF_TYPE, 0x406, false).unwrap();
    assert_eq!(disabled.effect, CacheEffect::MemoryTypes);
    assert_eq!(disabled.bank.memory_type(0x1000), Ok(0));
    assert_eq!(disabled.bank.memory_type(0x200000), Ok(0));
    assert_eq!(disabled.bank.memory_type(0x1_0000_0000), Ok(0));
    let exposed = disabled.bank.prepare_write(SYS_CFG, 0x780000, false).unwrap();
    assert_eq!(exposed.effect, CacheEffect::MemoryTypes);
    assert!(exposed.visibility);
    assert_eq!(exposed.bank.routing_matches(&physical, 0x1000), Ok(false));
    assert_eq!(exposed.bank.routing_matches(&physical, 0x200000), Ok(true));
    assert_eq!(exposed.bank.read(0x250, exposed.visibility), Some(DRAM_WB));
    let changed = exposed.bank.prepare_write(0x250, DRAM_WT, true).unwrap();
    assert_eq!(changed.effect, CacheEffect::Registers);
    assert_eq!(changed.bank.memory_type(0x1000), Ok(0));
    let hidden = changed.bank.prepare_write(SYS_CFG, 0x740000, true).unwrap();
    assert_eq!(hidden.effect, CacheEffect::MemoryTypes);
    assert_eq!(hidden.bank.routing_matches(&physical, 0x1000), Ok(true));
    assert!(!hidden.visibility);
    assert_eq!(hidden.bank.read(0x250, false), Some(0x0404_0404_0404_0404));
    let restored = hidden.bank.prepare_write(MTRR_DEF_TYPE, 0xc06, false).unwrap();
    assert_eq!(restored.effect, CacheEffect::MemoryTypes);
    assert_eq!(restored.bank.memory_type(0x1000), Ok(4));
    assert_eq!(restored.bank.memory_type(0x80000), Ok(6));
    assert_eq!(restored.bank.memory_type(0x200000), Ok(6));
    assert_eq!(physical, original);
}

#[test]
fn sibling_threads_share_fixed_values_but_keep_independent_visibility() {
    let mut core = firmware();
    let mut visibility = [false, false];
    let expose = core.prepare_write(SYS_CFG, 0x7c0000, visibility[0]).unwrap();
    core = expose.bank;
    visibility[0] = expose.visibility;
    assert_eq!(core.read(SYS_CFG, visibility[0]), Some(0x7c0000));
    assert_eq!(core.read(SYS_CFG, visibility[1]), Some(0x740000));
    let change = core.prepare_write(0x250, DRAM_WT, visibility[0]).unwrap();
    core = change.bank;
    assert_eq!(core.read(0x250, visibility[0]), Some(DRAM_WT));
    assert_eq!(core.read(0x250, visibility[1]), Some(0x0404_0404_0404_0404));
    assert!(!visibility[1]);
}

#[test]
fn hidden_fixed_routing_bits_retain_attributes_and_reject_write_one() {
    // PPR p202 says hidden values are unchanged; the more specific per-field
    // AccessType on p127 is Read,Error-on-write-1 while SYS_CFG19=0.
    for stored in [0x00u8, 0x18] {
        let mut bank = firmware();
        bank.fixed[0] = u64::from_le_bytes([stored; 8]);
        for supplied in [0x00u8, 0x08, 0x10, 0x18] {
            let prepared = bank.prepare_write(0x250, u64::from_le_bytes([supplied; 8]), false);
            if supplied != 0 {
                assert_eq!(prepared, Err(CacheError::GeneralProtection));
                continue;
            }
            let change = prepared.unwrap();
            assert_eq!(change.bank.fixed[0], u64::from_le_bytes([stored; 8]));
            assert_eq!(change.bank.read(0x250, false), Some(0));
            assert_eq!(change.bank.read(0x250, true), Some(u64::from_le_bytes([stored; 8])));
        }
    }
}

#[test]
fn disabled_e_is_representable_using_firmware_pat_uncacheable_entry() {
    let physical = firmware();
    let logical = physical.prepare_write(MTRR_DEF_TYPE, 0x406, false).unwrap().bank;
    // Tables15-19/20 p616: nested UC or UC- over physical WB yields UC/CD
    // except guest WC, which remains WC, as with logical MTRR UC.
    for address in [0, 0xa0000, 0x200000, 0x1_0000_0000, 0xf_ffff_ffff] {
        let index = logical.nested_pat_index(&physical, address, FIRMWARE_PAT_FIXTURE).unwrap();
        assert!(matches!((FIRMWARE_PAT_FIXTURE >> (index * 8)) & 255, 0 | 7));
    }
    assert_eq!(physical.memory_type(0x200000), Ok(6));
}

#[test]
fn reserved_wb_mmio_routing_tuple_cannot_be_hidden_by_nested_pat() {
    let physical = firmware();
    let logical = physical.prepare_write(MTRR_DEF_TYPE, 0x406, false).unwrap().bank;
    // At TOM2 the fixture ceases routing to DRAM, but its default type is WB.
    // APM2 Table7-13 disallows the resulting RdMem=WrMem=0, MemType=WB tuple.
    assert_eq!(
        logical.nested_pat_index(&physical, physical.tom2, FIRMWARE_PAT_FIXTURE),
        Err(CacheError::UnsupportedControl)
    );
}

#[test]
fn unmodeled_routing_changes_refuse_even_with_e_disabled_and_leave_bank_unchanged() {
    let bank = firmware().prepare_write(MTRR_DEF_TYPE, 0x406, false).unwrap().bank;
    let original = bank;
    for (index, value, visibility) in [
        (SYS_CFG, 0x640000, false), // Disable TOP_MEM/IORR routing.
        (TOP_MEM, 0x80000000, false),
        (0xc0010016, 0x100000, false),
    ] {
        assert_eq!(
            bank.prepare_write(index, value, visibility),
            Err(CacheError::UnsupportedControl)
        );
        assert_eq!(bank, original);
    }
}

#[test]
fn visible_fixed_routing_changes_are_stored_while_disabled_then_guarded_on_restore() {
    let physical = firmware();
    let disabled = physical.prepare_write(MTRR_DEF_TYPE, 0x406, false).unwrap().bank;
    let window = disabled.prepare_write(SYS_CFG, 0x780000, false).unwrap();
    // Native19=1 allows changing shared hidden route fields even while18=0.
    let altered = window.bank.prepare_write(FIXED_MSRS[0], 0, true).unwrap();
    assert_eq!(altered.effect, CacheEffect::MemoryTypes);
    assert_eq!(altered.bank.fixed[0], 0);
    assert_eq!(altered.bank.read(FIXED_MSRS[0], true), Some(0));
    let restored = altered.bank.prepare_write(SYS_CFG, 0x740000, true).unwrap();
    assert_eq!(restored.effect, CacheEffect::MemoryTypes);
    // The changed destination stays inaccessible; other low DRAM can return.
    assert_eq!(restored.bank.routing_matches(&physical, 0), Ok(false));
    assert_eq!(restored.bank.routing_matches(&physical, 0x80000), Ok(true));
    assert_eq!(physical.fixed[0], DRAM_WB);
}

#[test]
fn already_mmio_pages_need_no_routing_guard_when_fixed_routing_is_disabled() {
    let mut physical = firmware();
    physical.fixed[2] = 0;
    let disabled = physical.prepare_write(MTRR_DEF_TYPE, 0x406, false).unwrap().bank;
    let window = disabled.prepare_write(SYS_CFG, 0x780000, false).unwrap();
    assert_eq!(window.bank.routing_matches(&physical, 0xa0000), Ok(true));
    assert!(window.bank.nested_pat_index(&physical, 0xa0000, FIRMWARE_PAT_FIXTURE).is_ok());
    assert_eq!(window.bank.routing_matches(&physical, 0), Ok(false));
    assert_eq!(
        window.bank.nested_pat_index(&physical, 0, FIRMWARE_PAT_FIXTURE),
        Err(CacheError::UnsupportedControl)
    );
}

#[test]
fn programming_window_does_not_relax_register_faults_or_fe_refusal() {
    let physical = firmware();
    // Even E=1 can store the18-disabled window; runtime must guard route
    // differences before testing the mapped tuple (MMIO+WB is reserved).
    let window = physical.prepare_write(SYS_CFG, 0x780000, false).unwrap().bank;
    assert_eq!(window.routing_matches(&physical, 0), Ok(false));
    assert_eq!(
        window.nested_pat_index(&physical, 0, FIRMWARE_PAT_FIXTURE),
        Err(CacheError::UnsupportedControl)
    );
    assert_eq!(
        window.prepare_write(FIXED_MSRS[0], 0x0707_0707_0707_0707, true),
        Err(CacheError::GeneralProtection)
    );
    assert_eq!(
        window.prepare_write(MTRR_DEF_TYPE, 0x806, true),
        Err(CacheError::UnsupportedControl)
    );
}

#[test]
fn physical_uc_cannot_be_widened_to_logical_wb_by_any_pat_entry() {
    let physical = CacheBank { default: 0xc00, ..firmware() };
    let logical = firmware();
    let original = physical;
    // Guest WB must remain UC under physical UC (Table15-20); no nested PAT
    // selector can produce the requested WB result at this non-fixed address.
    assert_eq!(
        logical.nested_pat_index(&physical, 0x200000, FIRMWARE_PAT_FIXTURE),
        Err(CacheError::UnsupportedControl)
    );
    assert_eq!(physical, original);
}
