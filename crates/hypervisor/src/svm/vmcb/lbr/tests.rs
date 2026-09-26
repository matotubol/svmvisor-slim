use super::*;
use crate::svm::permission_maps::Msrpm;

fn record_offsets() -> impl Iterator<Item = usize> {
    (0x670..=0x698).step_by(8).chain((0xa70..=0xb70).step_by(8))
}

fn seed_records(vmcb: &mut Vmcb) {
    for (index, offset) in record_offsets().enumerate() {
        let value = 0x8123_4567_0000_0000u64 | index as u64;
        vmcb.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}

#[test]
fn target_lbr_admission_preserves_records_and_invalidates_cached_groups() {
    let mut vmcb = Vmcb::new();
    seed_records(&mut vmcb);
    vmcb.set_clean_bits(0x03ff);
    let before = vmcb.bytes;
    assert!(vmcb.configure_native_lbr(0x8000_0022, 2, 7, 0x2106));
    assert!(vmcb.native_lbr_enabled());
    assert_eq!(vmcb.read_u32::<0x0c0>(), 0);
    for offset in record_offsets() {
        assert_eq!(&vmcb.bytes[offset..offset + 8], &before[offset..offset + 8]);
    }
}

#[test]
fn unsupported_or_preconfigured_lbr_refuses_without_changing_state() {
    for (maximum, svm, performance, sizes, controls) in [
        (0x8000_0021, 2, 7, 0x2106, 0),
        (0x8000_0022, 0, 7, 0x2106, 0),
        (0x8000_0022, 2, 5, 0x2106, 0),
        (0x8000_0022, 2, 7, 0x2006, 0),
        (0x8000_0022, 2, 7, 0x2086, 0),
        (0x8000_0022, 2, 7, 0x2206, 0),
        (0x8000_0022, 2, 7, 0x2106, 1),
        (0x8000_0022, 2, 7, 0x2106, 2),
        (0x8000_0022, 2, 7, 0x2106, 4),
    ] {
        let mut vmcb = Vmcb::new();
        seed_records(&mut vmcb);
        vmcb.write_u64::<0x0b8>(controls);
        let before = vmcb.bytes;
        assert!(!vmcb.configure_native_lbr(maximum, svm, performance, sizes));
        assert_eq!(vmcb.bytes, before);
    }
}

#[test]
fn init_and_sipi_retain_branch_records_controls_and_hardware_ownership() {
    let mut vmcb = Vmcb::new();
    vmcb.configure_native_boot_intercepts().unwrap();
    assert!(vmcb.configure_native_lbr(0x8000_0022, 2, 7, 0x2106));
    seed_records(&mut vmcb);
    let before = vmcb.bytes;
    vmcb.initialize_ap_after_init();
    vmcb.start_ap_from_sipi(8);
    assert!(vmcb.native_lbr_enabled());
    for offset in record_offsets() {
        assert_eq!(&vmcb.bytes[offset..offset + 8], &before[offset..offset + 8]);
    }
    assert_eq!(vmcb.read_u32::<0x0c0>(), 0);
}

#[test]
fn active_lbr_profile_requires_only_the_owned_control_bit() {
    let mut vmcb = Vmcb::new();
    for controls in [0, 2, 3, 4, 5, u64::MAX] {
        vmcb.write_u64::<0x0b8>(controls);
        assert!(!vmcb.native_lbr_enabled());
    }
    vmcb.write_u64::<0x0b8>(1);
    assert!(vmcb.native_lbr_enabled());
}

#[test]
fn guest_branch_record_msrs_keep_native_access_and_fault_semantics() {
    let map = Msrpm::native_boot();
    for (base, msr) in [0x1d9, 0x1db, 0x1dc, 0x1dd, 0x1de]
        .into_iter()
        .map(|msr| (0, msr))
        .chain([0x010e, 0x010f].map(|msr| (0x800, msr)))
        .chain((0x0300..=0x031f).map(|msr| (0x1000, msr)))
    {
        let byte = base + msr / 4;
        let bits = 3 << (2 * (msr % 4));
        assert_eq!(map.bytes()[byte] & bits, 0);
    }
}
