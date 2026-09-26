use svmvisor_hypervisor::{
    arch::x86_64::msr::{MTRR_DEF_TYPE, SYS_CFG},
    svm::cache_policy::{CacheBank, CacheEffect, CacheError, FIXED_MSRS},
};
fn bank() -> CacheBank {
    CacheBank {
        capability: 0x508,
        default: 0xc06,
        sys_cfg: 0x740000,
        top_mem: 0xc0000000,
        tom2: 0x10_0000_0000,
        fixed: [0x1e1e_1e1e_1e1e_1e1e; 11],
        ..CacheBank::EMPTY
    }
}
#[test]
fn disabled_mtrrs_leave_the_original_bank_unchanged() {
    let physical = bank();
    let off = physical.prepare_write(MTRR_DEF_TYPE, 0x400, false).unwrap();
    assert_eq!(off.effect, CacheEffect::MemoryTypes);
    for address in [0, 0x100000, 0x1_0000_0000] {
        assert_eq!(off.bank.memory_type(address), Ok(0));
    }
    assert_eq!(physical.default, 0xc06);
}
#[test]
fn fixed_visibility_is_per_thread_and_preserves_hidden_attributes() {
    let value = bank();
    assert_eq!(value.read(FIXED_MSRS[0], false), Some(0x0606_0606_0606_0606));
    let hidden = value.prepare_write(FIXED_MSRS[0], 0x0404_0404_0404_0404, false).unwrap();
    assert_eq!(hidden.bank.fixed[0], 0x1c1c_1c1c_1c1c_1c1c);
    let visible = value.prepare_write(SYS_CFG, value.sys_cfg | 1 << 19, false).unwrap();
    assert!(visible.visibility);
    assert_eq!(visible.bank, value);
    assert_eq!(visible.effect, CacheEffect::Registers);
    assert_eq!(visible.bank.read(SYS_CFG, false), Some(value.sys_cfg));
}
#[test]
fn changed_enabled_bank_is_supported_without_replay_equality() {
    let value = bank();
    let off = value.prepare_write(MTRR_DEF_TYPE, 0x400, false).unwrap().bank;
    let base = off.prepare_write(0x200, 0x200000 | 4, false).unwrap();
    assert_eq!(base.effect, CacheEffect::Registers);
    let masked = base.bank.prepare_write(0x201, 0x0000_ffff_ffe0_0800, false).unwrap();
    let on = masked.bank.prepare_write(MTRR_DEF_TYPE, 0xc06, false).unwrap();
    assert_eq!(on.bank.memory_type(0x200000), Ok(4));
    assert_eq!(on.bank.memory_type(0x400000), Ok(6));
    assert_ne!(on.bank, value);
}
#[test]
fn enabling_a_malformed_range_refuses_without_mutation() {
    let mut value = bank();
    value.default = 0x400;
    value.variable[0] = (0x200000 | 6, 0x0000_ffff_ffd0_0800);
    let before = value;
    assert_eq!(value.prepare_write(MTRR_DEF_TYPE, 0xc06, false), Err(CacheError::MalformedRange));
    assert_eq!(before, value);
}
#[test]
fn fixed_precedence_and_variable_overlap_boundaries() {
    let mut value = bank();
    value.variable[0] = (6, 0x0000_ffff_ffc0_0800);
    value.variable[1] = (4, 0x0000_ffff_ffe0_0800);
    assert_eq!(value.memory_type(0x100000), Ok(4));
    assert_eq!(value.memory_type(0x200000), Ok(6));
    assert_eq!(value.memory_type(0), Ok(6));
    for (start, end) in [(0, 0x10000), (0x80000, 0x84000), (0xc0000, 0xc1000), (0x100000, 0x200000)]
    {
        assert_eq!(value.next_boundary(start, 1 << 40), Ok(end));
    }
    value.variable[1].0 = 5;
    assert_eq!(value.memory_type(0x100000), Err(CacheError::UndefinedOverlap));
    value.variable[1].0 = 0;
    assert_eq!(value.memory_type(0x100000), Ok(0));
}
#[test]
fn architectural_faults_remain_distinct_from_unsupported_controls() {
    let value = bank();
    assert_eq!(
        value.prepare_write(MTRR_DEF_TYPE, 0xc07, false),
        Err(CacheError::GeneralProtection)
    );
    assert_eq!(value.prepare_write(0x200, 7, false), Err(CacheError::GeneralProtection));
    assert_eq!(
        value.prepare_write(SYS_CFG, value.sys_cfg | 1 << 23, false),
        Err(CacheError::UnsupportedControl)
    );
    assert_eq!(value.prepare_write(0xc001001a, 0, false), Err(CacheError::UnsupportedControl));
}
#[test]
fn asymmetric_pat_composition_and_physical_uc_restriction() {
    let physical = bank();
    let off = physical.prepare_write(MTRR_DEF_TYPE, 0x400, false).unwrap().bank;
    let pat = 0x0007_0406_0007_0406;
    assert_eq!(off.nested_pat_index(&physical, 0x200000, pat), Ok(2));
    assert_eq!(physical.nested_pat_index(&physical, 0x200000, pat), Ok(0));
    let mut uc = physical;
    uc.default = 0xc00;
    assert_eq!(physical.nested_pat_index(&uc, 0x200000, pat), Err(CacheError::UnsupportedControl));
}
