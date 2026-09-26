//! Cross-check observation accessors against architectural state-save offsets.

use crate::svm::vmcb::Vmcb;

#[test]
fn paging_context_uses_state_save_bytes_without_masking_raw_cr3() {
    let mut vmcb = Vmcb::new();
    vmcb.bytes[0x548..0x550].copy_from_slice(&0x20_000u64.to_le_bytes());
    vmcb.bytes[0x550..0x558].copy_from_slice(&0x1234_5007u64.to_le_bytes());
    vmcb.bytes[0x608..0x610].copy_from_slice(&0xffff_f800_006c_1840u64.to_le_bytes());
    assert_eq!(vmcb.guest_cr4(), 0x20_000);
    assert_eq!(vmcb.guest_cr3(), 0x1234_5007);
    assert_eq!(vmcb.guest_lstar(), 0xffff_f800_006c_1840);
}

#[test]
fn auxiliary_observation_reads_latest_vmsave_bytes() {
    let mut vmcb = Vmcb::new();
    for lstar in [0xffff_f800_006c_1840u64, 0xffff_f900_00bc_b200] {
        vmcb.bytes[0x608..0x610].copy_from_slice(&lstar.to_le_bytes());
        assert_eq!(vmcb.guest_lstar(), lstar);
    }
}
