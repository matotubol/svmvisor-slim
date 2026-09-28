use core::ptr;

use svmvisor_hypervisor::{
    arch::x86_64::{
        capabilities::{
            CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures, ValidatedCapabilities,
        },
        msr::{
            TARGET_PHYSICAL_BITS, TARGET_SIGNATURE, TSC_RATIO, TSC_RATIO_DEFINED, TSC_RATIO_UNITY,
        },
        registers::GuestRegisters,
    },
    memory::address::EncryptionState,
    svm::{
        control_msrs::{
            HsaveAddressPolicy, NativeSvmControlError, SVM_LOCK_KEY, SvmControlAdmissionError,
            VM_HSAVE_PA, VisibleSvmControls, handle_visible_svm_controls,
            handle_visible_svm_controls_with_nrip, owned_msr,
        },
        dispatch::{NativeEfer, NativeMsrOutcome},
        vmcb::Vmcb,
        vmcr::VisibleVmCr,
    },
};

fn policy(base: u64, mask: u64) -> HsaveAddressPolicy {
    HsaveAddressPolicy::admit_target(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, 1, base, mask).unwrap()
}

fn owner(vmcr: &VisibleVmCr) -> VisibleSvmControls {
    VisibleSvmControls::admit_firmware_zero_key(0x1234_5000, TSC_RATIO_UNITY, policy(0, 0), vmcr)
        .unwrap()
}

fn efer() -> NativeEfer {
    NativeEfer::admit_native_visible_svm(
        0x500,
        1 << 2,
        (1 << 11) | (1 << 20) | (1 << 29),
        1 << 20,
        None,
    )
    .unwrap()
}

fn capabilities(nrip: bool) -> ValidatedCapabilities {
    CapabilityEvidence {
        vendor: CpuVendor::Amd,
        svm: EvidenceFlag::Set,
        nested_paging: EvidenceFlag::Set,
        svm_revision: Some(1),
        asid_count: Some(16),
        physical_address_bits: Some(48),
        vm_cr_svmdis: EvidenceFlag::Clear,
        hypervisor_present: EvidenceFlag::Clear,
        encryption: EncryptionState::Unencrypted { encryption_bit: None },
        optional: OptionalFeatures { nrip_save: nrip, ..Default::default() },
    }
    .validate()
    .unwrap()
}

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: exclusively owned inert VMCB fixture, in-bounds offsets only.
    unsafe {
        ptr::write_unaligned(ptr::from_mut(vmcb).cast::<u8>().add(offset).cast(), value);
    }
}

fn stopped(index: u32, write: bool, input: u64) -> (Vmcb, GuestRegisters) {
    let mut vmcb = Vmcb::new();
    for (offset, value) in [
        (0x070, 0x7c),
        (0x078, u64::from(write)),
        (0x0c8, 0x4002),
        (0x410, 0x29b << 16),
        (0x4d0, 0x1500),
        (0x548, 0x20),
        (0x558, 0x8000_0011),
        (0x570, 2),
        (0x578, 0x4000),
        (0x5f8, 0xaaaa_bbbb_0000_0000 | u64::from(input as u32)),
    ] {
        put(&mut vmcb, offset, value);
    }
    let frame = GuestRegisters {
        rcx: 0xcccc_dddd_0000_0000 | u64::from(index),
        rdx: 0xeeee_ffff_0000_0000 | (input >> 32),
        rbx: 0xabcdef,
        ..GuestRegisters::default()
    };
    (vmcb, frame)
}

fn access(
    owner: &mut VisibleSvmControls,
    vmcr: &VisibleVmCr,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    write: bool,
    hardware: bool,
) -> Result<NativeMsrOutcome, NativeSvmControlError> {
    if hardware {
        handle_visible_svm_controls_with_nrip(
            owner,
            vmcr,
            &efer(),
            vmcb,
            frame,
            &capabilities(true),
            false,
        )
    } else {
        handle_visible_svm_controls(
            owner,
            vmcr,
            &efer(),
            vmcb,
            frame,
            if write { &[0x0f, 0x30] } else { &[0x0f, 0x32] },
            false,
        )
    }
}

#[test]
fn address_policy_requires_the_exact_cpu_and_immutable_smram_evidence() {
    use SvmControlAdmissionError as E;
    for (signature, bits, hwcr, base, mask, expected) in [
        (TARGET_SIGNATURE ^ 1, 48, 1, 0, 0, E::UnsupportedProcessor),
        (TARGET_SIGNATURE, 52, 1, 0, 0, E::UnsupportedProcessor),
        (TARGET_SIGNATURE, 48, 0, 0, 0, E::UnlockedSmram),
        (TARGET_SIGNATURE, 48, 1, 1, 0, E::ReservedSmramBits),
        (TARGET_SIGNATURE, 48, 1, 1 << 48, 0, E::ReservedSmramBits),
        (TARGET_SIGNATURE, 48, 1, 0, 1 << 16, E::ReservedSmramBits),
        (TARGET_SIGNATURE, 48, 1, 0, 1 << 48, E::ReservedSmramBits),
        (TARGET_SIGNATURE, 48, 1, 0xa0000, 0xffff_fffe_0003, E::OverlappingSmram),
    ] {
        assert_eq!(
            HsaveAddressPolicy::admit_target(signature, bits, hwcr, base, mask),
            Err(expected),
        );
    }
}

#[test]
fn address_policy_checks_every_alignment_and_high_bit_and_target_reserved_region() {
    let policy = policy(0, 0);
    for bit in (0..12).chain(48..64) {
        assert!(!policy.permits(1 << bit), "bit {bit}");
    }
    for value in [0, 0x1000, 0x1000_0000_0000, 0xfffc_ffff_f000] {
        assert!(policy.permits(value), "{value:#x}");
    }
    // These are physical byte addresses: PPR216's bounds name field bits 47:12.
    for value in [0xfffd_0000_0000, 0xfffd_0000_1000, 0xffff_ffff_f000, u64::MAX] {
        assert!(!policy.permits(value), "{value:#x}");
    }
}

#[test]
fn captured_hsave_is_readable_even_when_later_smram_configuration_blocks_rewriting_it() {
    let vmcr = VisibleVmCr::admit(8).unwrap();
    let protected = policy(0, 0xffff_fffe_0002);
    assert!(!protected.permits(0));
    let mut owner =
        VisibleSvmControls::admit_firmware_zero_key(0, TSC_RATIO_UNITY, protected, &vmcr).unwrap();
    let (mut vmcb, mut frame) = stopped(VM_HSAVE_PA, false, u64::MAX);
    assert_eq!(
        access(&mut owner, &vmcr, &mut vmcb, &mut frame, false, true),
        Ok(NativeMsrOutcome::Completed)
    );
    assert_eq!((vmcb.guest_rax(), frame.rdx), (0, 0));
    let (mut vmcb, mut frame) = stopped(VM_HSAVE_PA, true, 0);
    assert_eq!(
        access(&mut owner, &vmcr, &mut vmcb, &mut frame, true, true),
        Ok(NativeMsrOutcome::GeneralProtectionPrepared)
    );
    assert_eq!(owner.hsave_pa(), 0);
    for value in [1, 1 << 48, u64::MAX] {
        assert_eq!(
            VisibleSvmControls::admit_firmware_zero_key(value, TSC_RATIO_UNITY, protected, &vmcr),
            Err(SvmControlAdmissionError::InvalidInitialHsave)
        );
    }
}

#[test]
fn smram_checks_enabled_aseg_tseg_and_masked_aliases_without_inventing_ram_checks() {
    // A 256-KiB TSEG at 1 MiB, PPR213's example with the full 48-bit target mask.
    let protected = policy(0x10_0000, 0xffff_fffc_0003);
    for value in [0xa0000, 0xbf000, 0x10_0000, 0x13_f000] {
        assert!(!protected.permits(value), "{value:#x}");
    }
    for value in [0x9f000, 0xc0000, 0xff000, 0x14_0000, 0x1234_5678_9000] {
        assert!(protected.permits(value), "{value:#x}");
    }
    let disabled = policy(0x10_0000, 0xffff_fffc_0000);
    for value in [0xa0000, 0xbf000, 0x10_0000, 0x13_f000] {
        assert!(disabled.permits(value));
    }
    // Hardware defines a masked compare, not an assumption of one contiguous range.
    let aliases = policy(0x10_0000, 0xffff_fff6_0002);
    assert!(!aliases.permits(0x10_0000));
    assert!(!aliases.permits(0x18_0000));
    assert!(aliases.permits(0x12_0000));
}

#[test]
fn guest_hsave_roundtrips_preserve_inputs_and_zero_extend_reads() {
    for lock in [0, 8] {
        let vmcr = VisibleVmCr::admit(lock).unwrap();
        for hardware in [false, true] {
            let mut owner = owner(&vmcr);
            for value in [0x1234_5000, 0, 0x1234_5678_9000, 0xfffc_ffff_f000] {
                let (mut vmcb, mut frame) = stopped(VM_HSAVE_PA, true, value);
                let before = (frame, vmcb.guest_rax(), vmcb.guest_efer());
                assert_eq!(
                    access(&mut owner, &vmcr, &mut vmcb, &mut frame, true, hardware),
                    Ok(NativeMsrOutcome::Completed)
                );
                assert_eq!((frame, vmcb.guest_rax(), vmcb.guest_efer()), before);
                assert_eq!(owner.hsave_pa(), value);
                assert_eq!(vmcb.guest_rip(), 0x4002);
                let (mut vmcb, mut frame) = stopped(VM_HSAVE_PA, false, u64::MAX);
                let mut expected = frame;
                expected.rdx = value >> 32;
                assert_eq!(
                    access(&mut owner, &vmcr, &mut vmcb, &mut frame, false, hardware),
                    Ok(NativeMsrOutcome::Completed)
                );
                assert_eq!(vmcb.guest_rax(), u64::from(value as u32));
                assert_eq!(frame, expected);
                assert_eq!(vmcb.guest_rip(), 0x4002);
            }
        }
    }
}

#[test]
fn invalid_hsave_writes_fault_without_changing_the_previous_guest_value() {
    let vmcr = VisibleVmCr::admit(8).unwrap();
    let protected = policy(0x10_0000, 0xffff_fffc_0003);
    for hardware in [false, true] {
        let mut owner =
            VisibleSvmControls::admit_firmware_zero_key(0x4000, TSC_RATIO_UNITY, protected, &vmcr)
                .unwrap();
        for value in (0..12).chain(48..64).map(|bit| 1 << bit).chain([
            0xa0000,
            0xbf000,
            0x10_0000,
            0x13_f000,
            0xfffd_0000_0000,
            0xffff_ffff_f000,
        ]) {
            let (mut vmcb, mut frame) = stopped(VM_HSAVE_PA, true, value);
            let before = (owner, frame, vmcb.guest_rax(), vmcb.guest_efer());
            assert_eq!(
                access(&mut owner, &vmcr, &mut vmcb, &mut frame, true, hardware),
                Ok(NativeMsrOutcome::GeneralProtectionPrepared)
            );
            assert_eq!((owner, frame, vmcb.guest_rax(), vmcb.guest_efer()), before);
            assert_eq!(vmcb.event_injection(), 0x8000_0b0d);
            assert_eq!(vmcb.guest_rip(), 0x4000);
        }
    }
}

#[test]
fn svm_key_reads_zero_and_locked_zero_key_writes_never_unlock_or_change_state() {
    for lock in [0, 8] {
        let vmcr = VisibleVmCr::admit(lock).unwrap();
        for hardware in [false, true] {
            let mut owner = owner(&vmcr);
            let initial = owner;
            for value in [0, 0x1234_5678_abcd_ef00, u64::MAX, 0] {
                let (mut vmcb, mut frame) = stopped(SVM_LOCK_KEY, true, value);
                let before = (frame, vmcb.guest_rax());
                assert_eq!(
                    access(&mut owner, &vmcr, &mut vmcb, &mut frame, true, hardware),
                    Ok(NativeMsrOutcome::Completed)
                );
                assert_eq!((frame, vmcb.guest_rax()), before);
                assert_eq!(vmcr.logical(), lock);
                if lock != 0 || value == 0 {
                    assert_eq!(owner, initial);
                } else {
                    assert_ne!(owner, initial);
                }
                let (mut vmcb, mut frame) = stopped(SVM_LOCK_KEY, false, u64::MAX);
                assert_eq!(
                    access(&mut owner, &vmcr, &mut vmcb, &mut frame, false, hardware),
                    Ok(NativeMsrOutcome::Completed)
                );
                assert_eq!((vmcb.guest_rax(), frame.rdx), (0, 0));
            }
        }
    }
}

#[test]
fn failed_provenance_or_lifecycle_validation_is_transactional() {
    let vmcr = VisibleVmCr::admit(8).unwrap();
    for index in [VM_HSAVE_PA, SVM_LOCK_KEY, TSC_RATIO] {
        for hardware in [false, true] {
            for (offset, value) in [
                (0x070, 0x81),
                (0x078, 2),
                (0x0a8, 0x8000_0b0d),
                (0x088, 0x8000_0202),
                (0x4d0, 0x1501),
                (0x570, 0x102), // TF without LBR-owned DebugCtl.
            ] {
                let mut owner = owner(&vmcr);
                let (mut vmcb, mut frame) = stopped(index, true, 0x8888_0000);
                put(&mut vmcb, offset, value);
                let before = (owner, *vmcb.bytes(), frame);
                assert!(access(&mut owner, &vmcr, &mut vmcb, &mut frame, true, hardware).is_err());
                assert_eq!((owner, *vmcb.bytes(), frame), before);
            }
        }
    }
}

#[test]
fn nrip_requires_evidence_and_fetched_opcodes_must_match_the_msr_exit() {
    let vmcr = VisibleVmCr::admit(8).unwrap();
    let mut owner = owner(&vmcr);
    let (mut vmcb, mut frame) = stopped(VM_HSAVE_PA, true, 0x4000);
    let before = (owner, *vmcb.bytes(), frame);
    assert!(
        handle_visible_svm_controls_with_nrip(
            &mut owner,
            &vmcr,
            &efer(),
            &mut vmcb,
            &mut frame,
            &capabilities(false),
            false,
        )
        .is_err()
    );
    assert_eq!((owner, *vmcb.bytes(), frame), before);
    assert!(
        handle_visible_svm_controls(
            &mut owner,
            &vmcr,
            &efer(),
            &mut vmcb,
            &mut frame,
            &[0x0f, 0x32],
            false,
        )
        .is_err()
    );
    assert_eq!((owner, *vmcb.bytes(), frame), before);
    assert_eq!(
        access(&mut owner, &VisibleVmCr::admit(0).unwrap(), &mut vmcb, &mut frame, true, false),
        Err(NativeSvmControlError::BackingMismatch)
    );
    assert_eq!((owner, *vmcb.bytes(), frame), before);
}

#[test]
fn logical_svme_enable_does_not_block_legal_guest_hsave_setup() {
    let vmcr = VisibleVmCr::admit(8).unwrap();
    let mut owner = owner(&vmcr);
    let efer = NativeEfer::admit_native_visible_svm(
        0x1500,
        1 << 2,
        (1 << 11) | (1 << 20) | (1 << 29),
        1 << 20,
        None,
    )
    .unwrap();
    let (mut vmcb, mut frame) = stopped(VM_HSAVE_PA, true, 0x4000);
    assert_eq!(
        handle_visible_svm_controls_with_nrip(
            &mut owner,
            &vmcr,
            &efer,
            &mut vmcb,
            &mut frame,
            &capabilities(true),
            false,
        ),
        Ok(NativeMsrOutcome::Completed)
    );
    assert_eq!(owner.hsave_pa(), 0x4000);
    assert_eq!(efer.logical(), 0x1500);
    assert_eq!(vmcb.guest_efer(), 0x1500);
}

#[test]
fn fetched_unprivileged_access_faults_and_unknown_msr_is_never_emulated() {
    let vmcr = VisibleVmCr::admit(8).unwrap();
    let mut owner = owner(&vmcr);
    for index in [VM_HSAVE_PA, SVM_LOCK_KEY, TSC_RATIO] {
        for write in [false, true] {
            let (mut vmcb, mut frame) = stopped(index, write, 0x4000);
            // SAFETY: same inert exclusively owned fixture, one in-bounds CPL byte.
            unsafe { ptr::from_mut(&mut vmcb).cast::<u8>().add(0x4cb).write(3) };
            let before = (owner, frame, vmcb.guest_rax());
            assert_eq!(
                access(&mut owner, &vmcr, &mut vmcb, &mut frame, write, false),
                Ok(NativeMsrOutcome::GeneralProtectionPrepared)
            );
            assert_eq!((owner, frame, vmcb.guest_rax()), before);
            assert_eq!(vmcb.guest_rip(), 0x4000);
        }
    }
    let (mut vmcb, mut frame) = stopped(0xc001_0119, true, 0);
    let before = (owner, *vmcb.bytes(), frame);
    assert_eq!(
        access(&mut owner, &vmcr, &mut vmcb, &mut frame, true, false),
        Err(NativeSvmControlError::UnsupportedMsr { index: 0xc001_0119, write: true })
    );
    assert_eq!((owner, *vmcb.bytes(), frame), before);
}

#[test]
fn init_preserves_control_msrs_while_startup_reads_still_work() {
    let vmcr = VisibleVmCr::admit(0).unwrap();
    let mut owner = owner(&vmcr);
    let (mut vmcb, mut frame) = stopped(SVM_LOCK_KEY, true, 0x1234_5678_9000);
    access(&mut owner, &vmcr, &mut vmcb, &mut frame, true, false).unwrap();
    let ratio = 0x12_3456_789a;
    let (mut vmcb, mut frame) = stopped(TSC_RATIO, true, ratio);
    access(&mut owner, &vmcr, &mut vmcb, &mut frame, true, false).unwrap();
    let before = owner;
    let mut efer = efer();
    efer.enable_guest_startup();
    efer.reset_after_init().unwrap();
    for index in [VM_HSAVE_PA, SVM_LOCK_KEY, TSC_RATIO] {
        let (mut vmcb, mut frame) = stopped(index, false, u64::MAX);
        put(&mut vmcb, 0x4d0, 0x1000);
        put(&mut vmcb, 0x558, 0x11);
        put(&mut vmcb, 0x410, (0x49b << 16) | (0xffff << 32));
        assert_eq!(
            handle_visible_svm_controls(
                &mut owner,
                &vmcr,
                &efer,
                &mut vmcb,
                &mut frame,
                &[0x0f, 0x32],
                true,
            ),
            Ok(NativeMsrOutcome::Completed)
        );
        assert_eq!(owner, before);
        let expected = match index {
            VM_HSAVE_PA => 0x1234_5000,
            TSC_RATIO => ratio,
            _ => 0,
        };
        assert_eq!(vmcb.guest_rax(), u64::from(expected as u32));
        assert_eq!(frame.rdx, expected >> 32);
    }
}

#[test]
fn tsc_ratio_admission_preserves_every_legal_value_and_rejects_each_mbz_bit() {
    let vmcr = VisibleVmCr::admit(8).unwrap();
    for value in [0, 1, TSC_RATIO_UNITY, 0x12_3456_789a, TSC_RATIO_DEFINED] {
        let owner =
            VisibleSvmControls::admit_firmware_zero_key(0, value, policy(0, 0), &vmcr).unwrap();
        assert_eq!(owner.tsc_ratio(), value);
    }
    for bit in 40..64 {
        assert_eq!(
            VisibleSvmControls::admit_firmware_zero_key(0, 1 << bit, policy(0, 0), &vmcr),
            Err(SvmControlAdmissionError::InvalidInitialTscRatio),
        );
    }
    assert!(owned_msr(TSC_RATIO));
    assert!(owned_msr(VM_HSAVE_PA));
    assert!(owned_msr(SVM_LOCK_KEY));
    assert!(!owned_msr(TSC_RATIO - 1));
    assert!(!owned_msr(TSC_RATIO + 1));
}

#[test]
fn tsc_ratio_read_write_roundtrips_are_per_cpu_and_do_not_modify_other_state() {
    for lock in [0, 8] {
        let vmcr = VisibleVmCr::admit(lock).unwrap();
        for hardware in [false, true] {
            let mut current = owner(&vmcr);
            let other_cpu = owner(&vmcr);
            for value in
                [0, 1, TSC_RATIO_UNITY - 1, TSC_RATIO_UNITY, 0x12_3456_789a, TSC_RATIO_DEFINED]
            {
                let (mut vmcb, mut frame) = stopped(TSC_RATIO, true, value);
                let before = (
                    frame,
                    vmcb.guest_rax(),
                    vmcb.guest_efer(),
                    u64::from_le_bytes(vmcb.bytes()[0x570..0x578].try_into().unwrap()),
                );
                assert_eq!(
                    access(&mut current, &vmcr, &mut vmcb, &mut frame, true, hardware),
                    Ok(NativeMsrOutcome::Completed),
                );
                assert_eq!(
                    (
                        frame,
                        vmcb.guest_rax(),
                        vmcb.guest_efer(),
                        u64::from_le_bytes(vmcb.bytes()[0x570..0x578].try_into().unwrap())
                    ),
                    before
                );
                assert_eq!(current.tsc_ratio(), value);
                assert_eq!(other_cpu.tsc_ratio(), TSC_RATIO_UNITY);
                assert_eq!(current.hsave_pa(), other_cpu.hsave_pa());
                assert_eq!(vmcb.guest_rip(), 0x4002);
                let (mut vmcb, mut frame) = stopped(TSC_RATIO, false, u64::MAX);
                let mut expected = frame;
                expected.rdx = value >> 32;
                assert_eq!(
                    access(&mut current, &vmcr, &mut vmcb, &mut frame, false, hardware),
                    Ok(NativeMsrOutcome::Completed),
                );
                assert_eq!(vmcb.guest_rax(), u64::from(value as u32));
                assert_eq!(frame, expected);
                assert_eq!(vmcb.guest_rip(), 0x4002);
            }
        }
    }
}

#[test]
fn tsc_ratio_mbz_writes_fault_at_original_rip_without_mutating_guest_state() {
    let vmcr = VisibleVmCr::admit(8).unwrap();
    for hardware in [false, true] {
        let mut owner = owner(&vmcr);
        for value in (40..64).map(|bit| (1 << bit) | TSC_RATIO_UNITY).chain([u64::MAX]) {
            let (mut vmcb, mut frame) = stopped(TSC_RATIO, true, value);
            let before = (
                owner,
                frame,
                vmcb.guest_rax(),
                vmcb.guest_efer(),
                u64::from_le_bytes(vmcb.bytes()[0x570..0x578].try_into().unwrap()),
            );
            assert_eq!(
                access(&mut owner, &vmcr, &mut vmcb, &mut frame, true, hardware),
                Ok(NativeMsrOutcome::GeneralProtectionPrepared),
            );
            assert_eq!(
                (
                    owner,
                    frame,
                    vmcb.guest_rax(),
                    vmcb.guest_efer(),
                    u64::from_le_bytes(vmcb.bytes()[0x570..0x578].try_into().unwrap())
                ),
                before
            );
            assert_eq!(vmcb.event_injection(), 0x8000_0b0d);
            assert_eq!(vmcb.guest_rip(), 0x4000);
        }
    }
}

#[test]
fn tsc_ratio_rejects_bad_nrip_and_mismatched_fetched_opcode_transactionally() {
    let vmcr = VisibleVmCr::admit(8).unwrap();
    for write in [false, true] {
        for next in [0, 0x4000, 0x4001, 0x4010, 0x0000_8000_0000_0000] {
            let mut owner = owner(&vmcr);
            let (mut vmcb, mut frame) = stopped(TSC_RATIO, write, 0x4000);
            put(&mut vmcb, 0x0c8, next);
            let before = (owner, *vmcb.bytes(), frame);
            assert!(access(&mut owner, &vmcr, &mut vmcb, &mut frame, write, true).is_err());
            assert_eq!((owner, *vmcb.bytes(), frame), before);
        }
        let mut owner = owner(&vmcr);
        let (mut vmcb, mut frame) = stopped(TSC_RATIO, write, 0x4000);
        let before = (owner, *vmcb.bytes(), frame);
        assert!(access(&mut owner, &vmcr, &mut vmcb, &mut frame, !write, false).is_err());
        assert_eq!((owner, *vmcb.bytes(), frame), before);
        assert!(
            handle_visible_svm_controls_with_nrip(
                &mut owner,
                &vmcr,
                &efer(),
                &mut vmcb,
                &mut frame,
                &capabilities(false),
                false,
            )
            .is_err()
        );
        assert_eq!((owner, *vmcb.bytes(), frame), before);
    }
}

#[test]
fn logical_svme_does_not_gate_tsc_ratio_access_or_rescale_its_caller() {
    let vmcr = VisibleVmCr::admit(8).unwrap();
    for logical_efer in [0x500, 0x1500] {
        let mut owner = owner(&vmcr);
        let efer = NativeEfer::admit_native_visible_svm(
            logical_efer,
            1 << 2,
            (1 << 11) | (1 << 20) | (1 << 29),
            1 << 20,
            None,
        )
        .unwrap();
        for write in [true, false] {
            let (mut vmcb, mut frame) = stopped(TSC_RATIO, write, 0);
            // TSC_OFFSET remains unchanged too: TSC_RATIO affects a future nested
            // guest, not the conceptual native host executing this MSR access.
            put(&mut vmcb, 0x050, 0x1234_5678_9abc_def0);
            assert_eq!(
                handle_visible_svm_controls_with_nrip(
                    &mut owner,
                    &vmcr,
                    &efer,
                    &mut vmcb,
                    &mut frame,
                    &capabilities(true),
                    false,
                ),
                Ok(NativeMsrOutcome::Completed)
            );
            assert_eq!(owner.tsc_ratio(), 0);
            assert_eq!(efer.logical(), logical_efer);
            assert_eq!(vmcb.guest_efer(), 0x1500);
            assert_eq!(&vmcb.bytes()[0x050..0x058], &0x1234_5678_9abc_def0u64.to_le_bytes());
            if !write {
                assert_eq!((vmcb.guest_rax(), frame.rdx), (0, 0));
            }
        }
    }
}
