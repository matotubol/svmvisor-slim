use core::ptr;

use svmvisor_hypervisor::{
    arch::x86_64::capabilities::{
        CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures, ValidatedCapabilities,
    },
    memory::address::EncryptionState,
    svm::{
        dispatch::{NativeEfer, NativeEferError},
        events::ExternalInterruptError,
        instructions::{
            NativeSvmInstruction, NativeSvmInstructionError, NativeSvmInstructionOutcome,
            NativeSvmInstructions, handle_native_svm_instruction,
        },
        vmcb::Vmcb,
    },
};

const INSTRUCTIONS: [NativeSvmInstruction; 7] = [
    NativeSvmInstruction::Invlpga,
    NativeSvmInstruction::Vmrun,
    NativeSvmInstruction::Vmload,
    NativeSvmInstruction::Vmsave,
    NativeSvmInstruction::Stgi,
    NativeSvmInstruction::Clgi,
    NativeSvmInstruction::Skinit,
];

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
        // Fault delivery must not require NRIPS or decode assists.
        optional: OptionalFeatures::default(),
    }
    .validate()
    .unwrap()
}

fn instructions(skinit: bool, svm_lock: bool) -> NativeSvmInstructions {
    NativeSvmInstructions::admit_native(
        &capabilities(),
        (1 << 2) | if skinit { 1 << 12 } else { 0 },
        if svm_lock { 1 << 2 } else { 0 },
    )
    .unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Long,
    Compatibility,
    Protected32,
    Protected16,
    Real,
    Virtual8086,
}

const PROTECTED: [Mode; 4] =
    [Mode::Long, Mode::Compatibility, Mode::Protected32, Mode::Protected16];

fn stopped(
    instruction: NativeSvmInstruction,
    svme: bool,
    mode: Mode,
    cpl: u8,
) -> (NativeEfer, Vmcb) {
    let mut efer = NativeEfer::admit_native_visible_svm(
        0x500 | if svme { 0x1000 } else { 0 },
        1 << 2,
        (1 << 11) | (1 << 20) | (1 << 29),
        1 << 20,
        None,
    )
    .unwrap();
    efer.enable_guest_startup();
    let long = matches!(mode, Mode::Long | Mode::Compatibility);
    let mut vmcb = Vmcb::new();
    for (offset, value) in [
        (0x070, instruction.exit_code()),
        // Neither unused EXITINFO nor nRIP may gate instruction faults.
        (0x078, u64::MAX),
        (0x080, u64::MAX),
        (0x0c0, 0xffff_ffff),
        (0x0c8, 0),
        (
            0x410,
            (match mode {
                Mode::Long => 0x29b,
                Mode::Compatibility | Mode::Protected32 => 0x49b,
                _ => 0x9b,
            }) << 16,
        ),
        (0x4d0, if long { 0x1500 } else { 0x1100 }),
        (
            0x558,
            if matches!(mode, Mode::Real) {
                0x10
            } else if long {
                0x8000_0011
            } else {
                0x11
            },
        ),
        (0x570, 0x10302 | if matches!(mode, Mode::Virtual8086) { 1 << 17 } else { 0 }),
        (0x578, 0x4567),
        (0x5d8, 0xabcdef00),
        (0x5f8, 0x12345000),
        (0x640, 0x56789000),
    ] {
        put(&mut vmcb, offset, value);
    }
    // SAFETY: this test exclusively owns inert VMCB storage; CPL is one byte.
    unsafe { *ptr::from_mut(&mut vmcb).cast::<u8>().add(0x4cb) = cpl };
    (efer, vmcb)
}

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: tests exclusively own inert VMCB storage; every offset is in bounds.
    unsafe {
        ptr::write_unaligned(ptr::from_mut(vmcb).cast::<u8>().add(offset).cast(), value);
    }
}

fn assert_fault(
    vmcb: &Vmcb,
    before: &[u8; 4096],
    result: Result<NativeSvmInstructionOutcome, NativeSvmInstructionError>,
    expected: NativeSvmInstructionOutcome,
) {
    assert_eq!(result, Ok(expected));
    let mut expected_bytes = *before;
    let encoding: u64 = match expected {
        NativeSvmInstructionOutcome::InvalidOpcodePrepared => 0x8000_0306,
        NativeSvmInstructionOutcome::GeneralProtectionPrepared => 0x8000_0b0d,
    };
    expected_bytes[0x0a8..0x0b0].copy_from_slice(&encoding.to_le_bytes());
    // EVENTINJ is explicitly uncached (APM2 physical p590). All other bytes,
    // including CLEAN_BITS, RIP, RSP, RAX, EFER, flags and CR2, survive.
    assert_eq!(*vmcb.bytes(), expected_bytes);
}

#[test]
fn svme_clear_faults_before_privilege_in_all_protected_code_sizes() {
    let owner = instructions(true, true);
    for instruction in INSTRUCTIONS {
        if matches!(instruction, NativeSvmInstruction::Stgi | NativeSvmInstruction::Skinit) {
            continue;
        }
        for mode in PROTECTED {
            for cpl in 0..=3 {
                let (efer, mut vmcb) = stopped(instruction, false, mode, cpl);
                let before = *vmcb.bytes();
                let result = handle_native_svm_instruction(&owner, &efer, &mut vmcb);
                assert_fault(
                    &vmcb,
                    &before,
                    result,
                    NativeSvmInstructionOutcome::InvalidOpcodePrepared,
                );
            }
        }
    }
}

#[test]
fn stgi_and_skinit_use_the_independent_native_feature_gates() {
    for skinit in [false, true] {
        for svm_lock in [false, true] {
            let owner = instructions(skinit, svm_lock);
            for instruction in [NativeSvmInstruction::Stgi, NativeSvmInstruction::Skinit] {
                for mode in PROTECTED {
                    for svme in [false, true] {
                        for cpl in 0..=3 {
                            let (efer, mut vmcb) = stopped(instruction, svme, mode, cpl);
                            let before = *vmcb.bytes();
                            let result = handle_native_svm_instruction(&owner, &efer, &mut vmcb);
                            if !svme && !skinit && !svm_lock {
                                assert_fault(
                                    &vmcb,
                                    &before,
                                    result,
                                    NativeSvmInstructionOutcome::InvalidOpcodePrepared,
                                );
                            } else if cpl != 0 {
                                assert_fault(
                                    &vmcb,
                                    &before,
                                    result,
                                    NativeSvmInstructionOutcome::GeneralProtectionPrepared,
                                );
                            } else {
                                assert_eq!(
                                    result,
                                    Err(NativeSvmInstructionError::UnsupportedInstruction {
                                        instruction
                                    })
                                );
                                assert_eq!(*vmcb.bytes(), before);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn real_and_virtual8086_modes_fault_even_with_svme_and_both_features() {
    let owner = instructions(true, true);
    for instruction in INSTRUCTIONS {
        for mode in [Mode::Real, Mode::Virtual8086] {
            for svme in [false, true] {
                let (efer, mut vmcb) = stopped(instruction, svme, mode, 3);
                let before = *vmcb.bytes();
                let result = handle_native_svm_instruction(&owner, &efer, &mut vmcb);
                assert_fault(
                    &vmcb,
                    &before,
                    result,
                    NativeSvmInstructionOutcome::InvalidOpcodePrepared,
                );
            }
        }
    }
}

#[test]
fn enabled_instructions_fault_at_nonzero_cpl_but_legal_nested_execution_is_not_invented() {
    let owner = instructions(true, true);
    for instruction in INSTRUCTIONS {
        for mode in PROTECTED {
            for cpl in 0..=3 {
                let (efer, mut vmcb) = stopped(instruction, true, mode, cpl);
                let before = *vmcb.bytes();
                let result = handle_native_svm_instruction(&owner, &efer, &mut vmcb);
                if cpl == 0 {
                    assert_eq!(
                        result,
                        Err(NativeSvmInstructionError::UnsupportedInstruction { instruction })
                    );
                    assert_eq!(*vmcb.bytes(), before);
                } else {
                    assert_fault(
                        &vmcb,
                        &before,
                        result,
                        NativeSvmInstructionOutcome::GeneralProtectionPrepared,
                    );
                }
            }
        }
    }
}

#[test]
fn pending_events_and_unsupported_controls_are_preserved_for_both_faults() {
    for (offset, value, error) in [
        (0x0a8, 0x8000_030e, ExternalInterruptError::PendingInjection),
        (0x088, 0x8000_030e, ExternalInterruptError::NestedDeliveryUnsupported),
        (0x060, 1 << 8, ExternalInterruptError::PendingVirtualInterrupt),
        (0x060, 1 << 25, ExternalInterruptError::UnsupportedControl { control: 1 << 25 }),
        (0x090, 2, ExternalInterruptError::UnsupportedNestedControl { control: 2 }),
    ] {
        for (instruction, svme, cpl) in
            [(NativeSvmInstruction::Vmrun, false, 0), (NativeSvmInstruction::Stgi, true, 3)]
        {
            let (efer, mut vmcb) = stopped(instruction, svme, Mode::Long, cpl);
            put(&mut vmcb, offset, value);
            let before = *vmcb.bytes();
            assert_eq!(
                handle_native_svm_instruction(&instructions(true, true), &efer, &mut vmcb),
                Err(NativeSvmInstructionError::PendingState(error)),
            );
            assert_eq!(*vmcb.bytes(), before);
        }
    }
}

#[test]
fn inconsistent_backing_is_refused_before_an_architectural_fault() {
    for instruction in INSTRUCTIONS {
        for backing in [0, 0x500, 0x1501, 0x1d00] {
            let (efer, mut vmcb) = stopped(instruction, false, Mode::Long, 3);
            put(&mut vmcb, 0x4d0, backing);
            let before = *vmcb.bytes();
            assert_eq!(
                handle_native_svm_instruction(&instructions(true, true), &efer, &mut vmcb),
                Err(NativeSvmInstructionError::Efer(NativeEferError::BackingMismatch)),
            );
            assert_eq!(*vmcb.bytes(), before);
        }
    }
}

#[test]
fn admission_and_exit_identity_do_not_claim_the_local_abi_or_other_exits() {
    assert_eq!(
        NativeSvmInstructions::admit_native(&capabilities(), 1 << 12, 1 << 2),
        Err(NativeSvmInstructionError::SvmNotEnumerated),
    );
    for code in [0, 0x46, 0x4d, 0x79, 0x7c, 0x7f, 0x81, 0x87, u64::MAX] {
        let (efer, mut vmcb) = stopped(NativeSvmInstruction::Vmrun, false, Mode::Long, 0);
        put(&mut vmcb, 0x070, code);
        let before = *vmcb.bytes();
        assert_eq!(
            handle_native_svm_instruction(&instructions(true, true), &efer, &mut vmcb),
            Err(NativeSvmInstructionError::UnexpectedExit { code }),
        );
        assert_eq!(*vmcb.bytes(), before);
    }
}
