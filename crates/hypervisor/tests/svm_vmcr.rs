use core::ptr;

use svmvisor_hypervisor::{
    arch::x86_64::{
        capabilities::{
            CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures, ValidatedCapabilities,
        },
        registers::GuestRegisters,
    },
    memory::address::EncryptionState,
    svm::{
        dispatch::{NativeEfer, NativeMsrOutcome, NativeVmCrError},
        vmcb::Vmcb,
        vmcr::{VisibleVmCr, handle_visible_vmcr, handle_visible_vmcr_with_nrip},
    },
};

fn capabilities() -> ValidatedCapabilities {
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
        optional: OptionalFeatures { nrip_save: true, ..Default::default() },
    }
    .validate()
    .unwrap()
}

fn efer(svme: bool) -> NativeEfer {
    NativeEfer::admit_native_visible_svm(
        0x500 | if svme { 0x1000 } else { 0 },
        1 << 2,
        (1 << 11) | (1 << 20) | (1 << 29),
        1 << 20,
        None,
    )
    .unwrap()
}

fn stopped(write: bool, value: u64) -> (Vmcb, GuestRegisters) {
    let mut vmcb = Vmcb::new();
    for (offset, value) in [
        (0x070, 0x7c),
        (0x078, u64::from(write)),
        (0x0c8, 0x4002),
        (0x410, 0x29b << 16),
        (0x4d0, 0x1500),
        (0x548, 0x20),
        (0x550, 0x1000),
        (0x558, 0x8000_0011),
        (0x570, 2),
        (0x578, 0x4000),
        (0x5f8, value as u32 as u64),
    ] {
        put(&mut vmcb, offset, value);
    }
    (
        vmcb,
        GuestRegisters {
            rcx: 0xc001_0114,
            rdx: value >> 32,
            rbx: 0xabcdef,
            ..GuestRegisters::default()
        },
    )
}

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: these tests exclusively own inert VMCB storage; every offset is in bounds.
    unsafe {
        ptr::write_unaligned(ptr::from_mut(vmcb).cast::<u8>().add(offset).cast(), value);
    }
}

/// Firmware VM_CR values the owner admits: SVM enabled with LOCK clear, or with
/// LOCK set as PPR 57896 physical page 37 directs firmware to leave it.
const ADMITTED: [u64; 2] = [0, 8];

fn access(
    initial: u64,
    efer: &NativeEfer,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    write: bool,
    hardware: bool,
) -> Result<NativeMsrOutcome, NativeVmCrError> {
    let owner = VisibleVmCr::admit(initial).unwrap();
    if hardware {
        handle_visible_vmcr_with_nrip(&owner, efer, vmcb, frame, &capabilities(), false)
    } else {
        let instruction: &[u8] = if write { &[0x0f, 0x30] } else { &[0x0f, 0x32] };
        handle_visible_vmcr(&owner, efer, vmcb, frame, instruction, false)
    }
}

#[test]
fn admission_requires_pre_arm_control_state_and_reads_keep_svm_available() {
    for initial in ADMITTED {
        assert_eq!(VisibleVmCr::admit(initial).unwrap().logical(), initial);
    }
    for bit in (0..64).filter(|&bit| bit != 3) {
        for initial in ADMITTED {
            assert_eq!(
                VisibleVmCr::admit(initial | 1 << bit),
                Err(NativeVmCrError::UnsupportedInitialState)
            );
        }
    }
    for initial in ADMITTED {
        for hardware in [false, true] {
            for svme in [false, true] {
                let (mut vmcb, mut frame) = stopped(false, u64::MAX);
                assert_eq!(
                    access(initial, &efer(svme), &mut vmcb, &mut frame, false, hardware),
                    Ok(NativeMsrOutcome::Completed)
                );
                assert_eq!(vmcb.guest_rax(), initial);
                assert_eq!(frame.rdx, 0);
                assert_eq!(vmcb.guest_rip(), 0x4002);
                assert_eq!(vmcb.guest_efer(), 0x1500);
            }
        }
    }
}

#[test]
fn every_control_bit_obeys_fault_precedence_or_transactional_refusal() {
    for initial in ADMITTED {
        // PPR215: LOCK is target read-only, and SVMDIS too while LOCK is set.
        let ignored = if initial & 8 != 0 { 0x18 } else { 8 };
        for hardware in [false, true] {
            for svme in [false, true] {
                for value in (0..64).map(|bit| 1u64 << bit).chain([0, 0x18, 0x12, 0x22]) {
                    let (mut vmcb, mut frame) = stopped(true, value);
                    let before = (*vmcb.bytes(), frame);
                    let result =
                        access(initial, &efer(svme), &mut vmcb, &mut frame, true, hardware);
                    // APM physical645-646: MBZ and SVMDIS while logicalSVME=1 fault,
                    // regardless of LOCK. Other changes are unimplemented.
                    if value & !0x1f != 0 || (svme && value & 0x10 != 0) {
                        assert_eq!(result, Ok(NativeMsrOutcome::GeneralProtectionPrepared));
                        assert_eq!(vmcb.guest_rip(), 0x4000);
                        assert_eq!(vmcb.event_injection(), 0x8000_0b0d);
                    } else if value & !ignored != 0 {
                        assert_eq!(result, Err(NativeVmCrError::UnsupportedValue { value }));
                        assert_eq!(*vmcb.bytes(), before.0);
                    } else {
                        assert_eq!(result, Ok(NativeMsrOutcome::Completed));
                        assert_eq!(vmcb.guest_rip(), 0x4002);
                    }
                    assert_eq!(frame, before.1);
                    assert_eq!(vmcb.guest_rax(), value as u32 as u64);
                    assert_eq!(vmcb.guest_efer(), 0x1500);
                }
            }
        }
    }
}

#[test]
fn locked_firmware_state_ignores_svm_disable_and_reads_locked() {
    // PPR 57896 physical page 37: firmware enabling SVM leaves VM_CR = LOCK.
    for value in [0x10, 0x18] {
        let (mut vmcb, mut frame) = stopped(true, value);
        assert_eq!(
            access(8, &efer(false), &mut vmcb, &mut frame, true, false),
            Ok(NativeMsrOutcome::Completed)
        );
        assert_eq!(vmcb.guest_rip(), 0x4002);
    }
    let (mut vmcb, mut frame) = stopped(false, 0);
    assert_eq!(
        access(8, &efer(false), &mut vmcb, &mut frame, false, false),
        Ok(NativeMsrOutcome::Completed)
    );
    assert_eq!(vmcb.guest_rax(), 8);
}

#[test]
fn pending_event_or_stale_efer_cannot_mutate_vmcr_access() {
    for initial in ADMITTED {
        for hardware in [false, true] {
            for (offset, value) in [(0x0a8, 0x8000_0b0d), (0x088, 0x8000_0202), (0x4d0, 0x1501)] {
                let (mut vmcb, mut frame) = stopped(false, 0);
                put(&mut vmcb, offset, value);
                let before = (*vmcb.bytes(), frame);
                assert!(
                    access(initial, &efer(false), &mut vmcb, &mut frame, false, hardware).is_err()
                );
                assert_eq!((*vmcb.bytes(), frame), before);
            }
        }
    }
}

#[test]
fn guest_init_preserves_the_admitted_vmcr_without_host_reset() {
    // APM volume 2 physical page 645: INIT leaves LOCK unchanged.
    for initial in ADMITTED {
        let owner = VisibleVmCr::admit(initial).unwrap();
        let mut efer = efer(true);
        efer.enable_guest_startup();
        efer.reset_after_init().unwrap();
        let (mut vmcb, mut frame) = stopped(false, u64::MAX);
        put(&mut vmcb, 0x4d0, 0x1000);
        put(&mut vmcb, 0x558, 0x11);
        put(&mut vmcb, 0x410, (0x49b << 16) | (0xffff << 32));
        assert_eq!(
            handle_visible_vmcr(&owner, &efer, &mut vmcb, &mut frame, &[0x0f, 0x32], true),
            Ok(NativeMsrOutcome::Completed)
        );
        assert_eq!(vmcb.guest_rax(), initial);
        assert_eq!(frame.rdx, 0);
        assert_eq!(owner.logical(), initial);
        assert_eq!(efer.logical(), 0);
        assert_eq!(vmcb.guest_efer(), 0x1000);
    }
}
