//! Architectural retirement across the retained MSR owners. These are stopped
//! VMCB fixtures, not privileged execution or proof of target #DB delivery.
//! APM2 physical pages 455-456, 460, 470-472, 571-573 and 593-594.

use core::ptr;

use svmvisor_hypervisor::{
    arch::x86_64::{
        capabilities::{
            CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures, ValidatedCapabilities,
        },
        msr::{EFER, TARGET_PHYSICAL_BITS, TARGET_SIGNATURE, TSC_RATIO, TSC_RATIO_UNITY, VM_CR},
        registers::GuestRegisters,
    },
    memory::address::EncryptionState,
    svm::{
        control_msrs::{
            HsaveAddressPolicy, SVM_LOCK_KEY, VM_HSAVE_PA, VisibleSvmControls,
            handle_visible_svm_controls, handle_visible_svm_controls_with_nrip,
        },
        dispatch::{
            NativeEfer, NativeEferError, NativeMsrOutcome, handle_native_efer,
            handle_native_efer_with_nrip,
        },
        vmcb::Vmcb,
        vmcr::{VisibleVmCr, handle_visible_vmcr, handle_visible_vmcr_with_nrip},
    },
};

const RIP: u64 = 0xffff_f800_1234_5ffd;
const TF: u64 = 1 << 8;
const RF: u64 = 1 << 16;
const BS: u64 = 1 << 14;
const DEBUG_TRAP: u64 = 0x8000_0301;
const GENERAL_PROTECTION: u64 = 0x8000_0b0d;
// Preserve sticky BT/BD and the cleared BLD indication of an earlier bus lock.
const DR6: u64 = 0xffff_a7f0;
const MSRS: [u32; 5] = [EFER, VM_CR, VM_HSAVE_PA, SVM_LOCK_KEY, TSC_RATIO];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Owners {
    efer: NativeEfer,
    vmcr: VisibleVmCr,
    controls: VisibleSvmControls,
}

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

fn stopped(index: u32, write: bool, input: u64) -> (Owners, Vmcb, GuestRegisters) {
    let efer = NativeEfer::admit_native_visible_svm(
        0x500,
        1 << 2,
        (1 << 11) | (1 << 20) | (1 << 29),
        1 << 20,
        None,
    )
    .unwrap();
    let vmcr = VisibleVmCr::admit(8).unwrap();
    let policy =
        HsaveAddressPolicy::admit_target(TARGET_SIGNATURE, TARGET_PHYSICAL_BITS, 1, 0, 0).unwrap();
    let controls =
        VisibleSvmControls::admit_firmware_zero_key(0x1234_5000, TSC_RATIO_UNITY, policy, &vmcr)
            .unwrap();
    let mut vmcb = Vmcb::new();
    for (offset, value) in [
        (0x070, 0x7c),
        (0x078, u64::from(write)),
        (0x0c8, RIP + 2),
        (0x410, 0x29b << 16),
        (0x4d0, 0x1500),
        (0x548, 0x20),
        (0x558, 0x8000_0011),
        (0x560, 0x2400), // GD remains hardware-owned until #DB delivery.
        (0x568, DR6),
        (0x570, 0x202 | TF | RF),
        (0x578, RIP),
        (0x5f8, 0xaaaa_bbbb_0000_0000 | u64::from(input as u32)),
        (0x670, 1), // Saved DebugCtl.LBR, instruction stepping (BTF clear).
    ] {
        put(&mut vmcb, offset, value);
    }
    assert!(vmcb.configure_native_lbr(0x8000_0022, 1 << 1, 1 << 1, 16 << 4));
    let frame = GuestRegisters {
        rcx: 0xcccc_dddd_0000_0000 | u64::from(index),
        rdx: 0xeeee_ffff_0000_0000 | (input >> 32),
        rbx: 0xabcdef,
        r15: 0x12345678,
        ..GuestRegisters::default()
    };
    (Owners { efer, vmcr, controls }, vmcb, frame)
}

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: exclusively owned inert VMCB; every fixture offset is in bounds.
    unsafe { ptr::write_unaligned(ptr::from_mut(vmcb).cast::<u8>().add(offset).cast(), value) };
}

fn word(vmcb: &Vmcb, offset: usize) -> u64 {
    u64::from_le_bytes(vmcb.bytes()[offset..offset + 8].try_into().unwrap())
}

fn access(
    owners: &mut Owners,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
    hardware: bool,
) -> Result<NativeMsrOutcome, NativeEferError> {
    let bytes: &[u8] = if vmcb.exit_snapshot().info1 == 1 { &[0x0f, 0x30] } else { &[0x0f, 0x32] };
    match (frame.rcx as u32, hardware) {
        (EFER, false) => handle_native_efer(&mut owners.efer, vmcb, frame, bytes),
        (EFER, true) => {
            handle_native_efer_with_nrip(&mut owners.efer, vmcb, frame, &capabilities())
        }
        (VM_CR, false) => {
            handle_visible_vmcr(&owners.vmcr, &owners.efer, vmcb, frame, bytes, false)
        }
        (VM_CR, true) => handle_visible_vmcr_with_nrip(
            &owners.vmcr,
            &owners.efer,
            vmcb,
            frame,
            &capabilities(),
            false,
        ),
        (_, false) => handle_visible_svm_controls(
            &mut owners.controls,
            &owners.vmcr,
            &owners.efer,
            vmcb,
            frame,
            bytes,
            false,
        ),
        (_, true) => handle_visible_svm_controls_with_nrip(
            &mut owners.controls,
            &owners.vmcr,
            &owners.efer,
            vmcb,
            frame,
            &capabilities(),
            false,
        ),
    }
}

fn write_value(index: u32) -> u64 {
    match index {
        EFER => 0xd01,
        VM_CR => 8,
        VM_HSAVE_PA => 0x5678_9000,
        SVM_LOCK_KEY => u64::MAX, // Ignored while the captured zero key keeps LOCK set.
        TSC_RATIO => TSC_RATIO_UNITY + 1,
        _ => unreachable!(),
    }
}

fn read_value(index: u32) -> u64 {
    match index {
        EFER => 0x500,
        VM_CR => 8,
        VM_HSAVE_PA => 0x1234_5000,
        SVM_LOCK_KEY => 0,
        TSC_RATIO => TSC_RATIO_UNITY,
        _ => unreachable!(),
    }
}

#[test]
fn successful_msr_commits_before_one_single_step_trap_at_the_real_successor() {
    for index in MSRS {
        for hardware in [false, true] {
            for write in [false, true] {
                let input = if write { write_value(index) } else { u64::MAX };
                let (mut owners, mut vmcb, mut frame) = stopped(index, write, input);
                let length = if hardware { 7 } else { 2 };
                put(&mut vmcb, 0x0c8, RIP + length);
                let before_frame = frame;
                let before_rax = vmcb.guest_rax();
                assert_eq!(
                    access(&mut owners, &mut vmcb, &mut frame, hardware),
                    Ok(NativeMsrOutcome::DebugTrapPrepared),
                    "MSR {index:x}, hardware {hardware}, write {write}"
                );
                assert_eq!(vmcb.guest_rip(), RIP + length);
                assert_eq!(vmcb.event_injection(), DEBUG_TRAP);
                assert_eq!(word(&vmcb, 0x570), 0x202 | TF); // Keep TF for the saved #DB frame.
                assert_eq!(word(&vmcb, 0x568), DR6 | BS);
                assert_eq!((word(&vmcb, 0x560), word(&vmcb, 0x670)), (0x2400, 1));
                if write {
                    assert_eq!((frame, vmcb.guest_rax()), (before_frame, before_rax));
                    match index {
                        EFER => assert_eq!(owners.efer.logical(), input),
                        VM_HSAVE_PA => assert_eq!(owners.controls.hsave_pa(), input),
                        TSC_RATIO => assert_eq!(owners.controls.tsc_ratio(), input),
                        _ => {}
                    }
                } else {
                    let value = read_value(index);
                    assert_eq!((vmcb.guest_rax(), frame.rdx), (value as u32 as u64, value >> 32));
                    assert_eq!(frame, GuestRegisters { rdx: value >> 32, ..before_frame });
                }
            }
        }
    }
}

#[test]
fn branch_only_stepping_and_disabled_tf_do_not_invent_a_debug_trap() {
    for index in MSRS {
        for hardware in [false, true] {
            for flags in [0x202 | TF | RF, 0x202 | RF] {
                let (mut owners, mut vmcb, mut frame) = stopped(index, true, write_value(index));
                put(&mut vmcb, 0x570, flags);
                put(&mut vmcb, 0x670, 3); // BTF and LBR.
                if flags & TF == 0 {
                    put(&mut vmcb, 0x068, 1);
                }
                assert_eq!(
                    access(&mut owners, &mut vmcb, &mut frame, hardware),
                    Ok(NativeMsrOutcome::Completed)
                );
                assert_eq!((vmcb.guest_rip(), vmcb.event_injection()), (RIP + 2, 0));
                assert_eq!(word(&vmcb, 0x570), flags & !RF);
                assert_eq!(
                    (word(&vmcb, 0x568), word(&vmcb, 0x670), word(&vmcb, 0x068)),
                    (DR6, 3, 0)
                );
            }
        }
    }
}

#[test]
fn architectural_operand_fault_wins_over_tf_and_preserves_unretired_state() {
    for (index, input) in
        [(EFER, 1 << 63), (VM_CR, 1 << 63), (VM_HSAVE_PA, 1), (TSC_RATIO, 1 << 40)]
    {
        for hardware in [false, true] {
            let (mut owners, mut vmcb, mut frame) = stopped(index, true, input);
            put(&mut vmcb, 0x068, 1); // Unsupported retirement state cannot suppress a real fault.
            // Both opcode bytes are canonical, but a successful next RIP would not be.
            // Faults retain this instruction and must not need a retirement candidate.
            put(&mut vmcb, 0x578, 0x0000_7fff_ffff_fffe);
            put(&mut vmcb, 0x0c8, 0x0000_8000_0000_0000);
            let before = (owners, frame);
            let mut expected = *vmcb.bytes();
            expected[0x0a8..0x0b0].copy_from_slice(&GENERAL_PROTECTION.to_le_bytes());
            assert_eq!(
                access(&mut owners, &mut vmcb, &mut frame, hardware),
                Ok(NativeMsrOutcome::GeneralProtectionPrepared)
            );
            assert_eq!((owners, frame), before);
            assert_eq!(*vmcb.bytes(), expected);
        }
    }
}

#[test]
fn malformed_nrip_or_unowned_delivery_never_partially_retires_a_write() {
    for index in MSRS {
        for (offset, value) in [
            (0x0c8, 0),
            (0x0c8, RIP - 1),
            (0x0c8, RIP + 16),
            (0x0c8, 0x0000_8000_0000_0000),
            (0x0a8, GENERAL_PROTECTION),
            (0x088, 0x8000_0202),
            (0x0b8, 0), // Saved DebugCtl does not belong to the guest without LBR ownership.
            (0x068, 1), // STI/MOV SS shadow provenance cannot be distinguished here.
        ] {
            let (mut owners, mut vmcb, mut frame) = stopped(index, true, write_value(index));
            put(&mut vmcb, offset, value);
            let before = (owners, *vmcb.bytes(), frame);
            assert!(
                access(&mut owners, &mut vmcb, &mut frame, true).is_err(),
                "MSR {index:x}, offset {offset:x}"
            );
            assert_eq!((owners, *vmcb.bytes(), frame), before);
        }
    }
}

#[test]
fn retired_debug_trap_replays_without_repeating_the_msr_side_effect() {
    let (mut owners, mut vmcb, mut frame) = stopped(VM_HSAVE_PA, true, 0x5678_9000);
    assert_eq!(
        access(&mut owners, &mut vmcb, &mut frame, true),
        Ok(NativeMsrOutcome::DebugTrapPrepared)
    );
    let retired = (owners, frame, vmcb.guest_rip(), vmcb.guest_rax(), word(&vmcb, 0x568));
    let mut pending = true;
    for code in [0x63, 0x61, 0x63] {
        // Hardware clears EVENTINJ on exit; EXITINTINFO retains interrupted delivery.
        put(&mut vmcb, 0x070, code);
        put(&mut vmcb, 0x0a8, 0);
        put(&mut vmcb, 0x088, DEBUG_TRAP);
        vmcb.complete_event_delivery(&mut pending).unwrap();
        assert!(pending);
        assert_eq!(vmcb.event_injection(), DEBUG_TRAP);
        assert_eq!(
            (owners, frame, vmcb.guest_rip(), vmcb.guest_rax(), word(&vmcb, 0x568)),
            retired
        );
    }
    put(&mut vmcb, 0x0a8, 0);
    put(&mut vmcb, 0x088, 0);
    vmcb.complete_event_delivery(&mut pending).unwrap();
    assert!(!pending);
    assert_eq!(vmcb.event_injection(), 0);
    assert_eq!(owners.controls.hsave_pa(), 0x5678_9000);
}
