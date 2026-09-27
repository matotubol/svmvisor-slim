//! Inert stopped-state tests. No physical MSR, guest fetch or VMRUN executes.
use super::*;
use crate::{
    arch::x86_64::{
        capabilities::{
            CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures, ValidatedCapabilities,
        },
        msr::TARGET_SIGNATURE,
    },
    host::resident::runtime::INITIAL_STATE,
    memory::address::EncryptionState,
    svm::{
        control_msrs::{SMM_ADDR, SMM_BASE, SMM_MASK},
        mcax,
        target_msrs::{AVIC_DOORBELL, SECURE_AVIC, SMM_CTL, SMM_KEY, TargetMsrPolicy, VIRTUAL_TOM},
    },
};

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: exclusive inert fixture and in-bounds qword offsets only.
    unsafe {
        core::ptr::from_mut(vmcb).cast::<u8>().add(offset).cast::<u64>().write_unaligned(value)
    };
}

fn caps() -> ValidatedCapabilities {
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

fn stopped(
    index: u32,
    write: Option<u64>,
    startup: bool,
    nmi: u64,
) -> (State, Vmcb, GuestRegisters) {
    let mut state = INITIAL_STATE;
    state.capabilities = Some(caps());
    state.target_msrs = TargetMsrPolicy::admit(TARGET_SIGNATURE, Some(1 << 9), 1, 0, 0, 0);
    state.startup_owned = startup;
    state.routing_retries = 9;
    let mut vmcb = Vmcb::new();
    for (offset, value) in [
        (0x060, 6 | if startup { 1 << 24 } else { 0 }),
        (0x068, 1),
        (0x070, 0x7c),
        (0x078, u64::from(write.is_some())),
        (0x090, 1),
        (0x0c8, 0x4002),
        (0x410, 0x29b << 16),
        (0x4d0, 0x1500),
        (0x548, 0x20),
        (0x550, 0xfeed_0000), // Intentionally not a dereferenceable guest page table.
        (0x558, 0x8000_0011),
        (0x570, 0x10202),
        (0x578, 0x4000),
        (0x5f8, 0xaaaa_bbbb_0000_0000 | u64::from(write.unwrap_or(u64::MAX) as u32)),
        (0x640, 0xabcdef),
    ] {
        put(&mut vmcb, offset, value);
    }
    vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
    let control = vmcb.virtual_interrupt_control() | nmi;
    put(&mut vmcb, 0x060, control);
    let frame = GuestRegisters {
        rcx: 0xcccc_dddd_0000_0000 | u64::from(index),
        rdx: 0xeeee_ffff_0000_0000 | (write.unwrap_or(u64::MAX) >> 32),
        rbx: 3,
        rbp: 4,
        rsi: 5,
        rdi: 6,
        r8: 7,
        r9: 8,
        r10: 9,
        r11: 10,
        r12: 11,
        r13: 12,
        r14: 13,
        r15: 14,
    };
    (state, vmcb, frame)
}

#[test]
fn icr_operand_faults_precede_debug_and_continuation_requirements() {
    for startup in [false, true] {
        for nmi in [0, 1 << 11, 1 << 12, (1 << 11) | (1 << 12)] {
            // APM2 physical pp721,723 and PPR p179 agree these are reserved.
            // Message types 1/7 disagree between manuals and are not test oracles.
            for value in [1 << 20, 1 << 12, 1 << 13, 1 << 16, 1 << 17, 0x300] {
                for scenario in 0..4 {
                    let (mut state, mut vmcb, mut frame) =
                        stopped(0x830, Some(value), startup, nmi);
                    state.icr_value = 0x1234_0000_0040;
                    match scenario {
                        0 => put(&mut vmcb, 0x570, 0x10302), // TF on a faulting instruction.
                        1 => put(&mut vmcb, 0x0c8, 0),       // No usable continuation.
                        2 => state.capabilities = None,      // Faults need no nRIP capability.
                        _ => {
                            put(&mut vmcb, 0x570, 0x10302);
                            put(&mut vmcb, 0x0c8, u64::MAX);
                            state.capabilities = None;
                        }
                    }
                    let mut expected = *vmcb.bytes();
                    expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0b0du64.to_le_bytes());
                    let registers = frame;
                    // SAFETY: documented invalid operands must fault before guest fetch,
                    // mailbox access or a physical MSR operation in this inert fixture.
                    assert!(unsafe { handle_native_icr(&mut state, &mut vmcb, &mut frame) });
                    assert_eq!(*vmcb.bytes(), expected);
                    assert_eq!(frame, registers);
                    assert_eq!(state.icr_value, 0x1234_0000_0040);
                    assert!(state.pending_fault && !state.stopped_valid);
                    assert_eq!(state.routing_retries, 0);
                }
            }
        }
    }
}

#[test]
fn icr_faults_do_not_replace_pending_events_or_admit_invalid_boundaries() {
    for (offset, value) in [
        (0x070, 0x72),
        (0x078, 2),
        (0x4c8, 3 << 24),
        (0x090, 1 | (1 << 1)),
        (0x060, 1 << 11),
        (0x0a8, 0x8000_0051),
        (0x088, 0x8000_0051),
    ] {
        let (mut state, mut vmcb, mut frame) = stopped(0x830, Some(1 << 20), false, 0);
        put(&mut vmcb, offset, value);
        let before = (*vmcb.bytes(), frame, state.icr_value);
        // SAFETY: invalid boundaries are refused before any physical operation.
        assert!(!unsafe { handle_native_icr(&mut state, &mut vmcb, &mut frame) });
        assert_eq!((*vmcb.bytes(), frame, state.icr_value), before);
        assert!(state.stopped_valid && !state.pending_fault);
    }
}

#[test]
fn icr_success_keeps_unsupported_single_step_transactional() {
    let (mut state, mut vmcb, mut frame) = stopped(0x830, None, true, 0);
    state.icr_value = 0x1234_0000_0040;
    put(&mut vmcb, 0x570, 0x10302);
    let before = (*vmcb.bytes(), frame, state.icr_value);
    // SAFETY: this read has no physical access and TF prevents completion.
    assert!(!unsafe { handle_native_icr(&mut state, &mut vmcb, &mut frame) });
    assert_eq!((*vmcb.bytes(), frame, state.icr_value), before);
    assert!(state.stopped_valid && !state.pending_fault);
}

#[test]
fn documented_faults_preserve_full_guest_state_without_nrip_or_fetch() {
    for startup in [false, true] {
        for nmi in [0, 1 << 11, 1 << 12, (1 << 11) | (1 << 12)] {
            for (index, write) in [
                (SMM_CTL, None),
                (SMM_CTL, Some(u64::MAX)),
                (AVIC_DOORBELL, None),
                (VIRTUAL_TOM, None),
                (VIRTUAL_TOM, Some(0)),
                (SECURE_AVIC, None),
                (SECURE_AVIC, Some(u64::MAX)),
            ] {
                let (mut state, mut vmcb, mut frame) = stopped(index, write, startup, nmi);
                state.capabilities = None; // Faults do not need continuation capabilities.
                put(&mut vmcb, 0x0c8, u64::MAX);
                put(&mut vmcb, 0x570, 0x10302); // TF, RF and shadow must survive a fault.
                let mut expected = *vmcb.bytes();
                expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0b0du64.to_le_bytes());
                let registers = frame;
                let policy = state.target_msrs;
                assert_eq!(
                    unsafe { handle_target_msr(&mut state, &mut vmcb, &mut frame) },
                    Some(true)
                );
                assert_eq!(*vmcb.bytes(), expected);
                assert_eq!(frame, registers);
                assert_eq!(state.target_msrs, policy);
                assert!(state.pending_fault && !state.stopped_valid);
                assert_eq!(state.routing_retries, 0);
            }
        }
    }
}

#[test]
fn completed_target_accesses_retire_exact_length_and_preserve_unrelated_state() {
    for startup in [false, true] {
        for length in 2..=15 {
            for (index, write) in [
                (SMM_KEY, None),
                (SMM_KEY, Some(0)),
                (SMM_BASE, Some(0xffff_ffff)),
                (SMM_ADDR, Some(0x0000_ffff_fffe_0000)),
                (SMM_MASK, Some(0x0000_ffff_fffe_773f)),
            ] {
                let (mut state, mut vmcb, mut frame) =
                    stopped(index, write, startup, (1 << 11) | (1 << 12));
                put(&mut vmcb, 0x0c8, 0x4000 + length);
                let mut expected = *vmcb.bytes();
                let mut registers = frame;
                expected[0x578..0x580].copy_from_slice(&(0x4000 + length).to_le_bytes());
                expected[0x570..0x578].copy_from_slice(&0x202u64.to_le_bytes());
                expected[0x068..0x070].copy_from_slice(&0u64.to_le_bytes());
                if write.is_none() {
                    expected[0x5f8..0x600].copy_from_slice(&0u64.to_le_bytes());
                    registers.rdx = 0;
                }
                let policy = state.target_msrs;
                assert_eq!(
                    unsafe { handle_target_msr(&mut state, &mut vmcb, &mut frame) },
                    Some(true)
                );
                assert_eq!(*vmcb.bytes(), expected);
                assert_eq!(frame, registers);
                assert_eq!(state.target_msrs, policy);
                assert!(!state.pending_fault && !state.stopped_valid);
                assert_eq!(state.routing_retries, 0);
            }
        }
    }
}

#[test]
fn invalid_boundaries_and_unowned_contracts_are_transactional() {
    for (offset, value) in [
        (0x070, 0x72),
        (0x078, 2),
        (0x4c8, 3 << 24),
        (0x090, 1 | (1 << 1)),
        (0x060, 1 << 11),
        (0x060, (1 << 26) | (1 << 31)),
        (0x0a8, 0x8000_0051),
        (0x088, 0x8000_0051),
    ] {
        let (mut state, mut vmcb, mut frame) = stopped(SMM_CTL, None, false, 0);
        put(&mut vmcb, offset, value);
        assert_unhandled(&mut state, &mut vmcb, &mut frame);
    }
    for (index, write) in [
        (0xdead_beef, None),
        (AVIC_DOORBELL, Some(0)),
        (SMM_KEY, Some(1)),
        (SMM_BASE, Some(1 << 63)),
    ] {
        let (mut state, mut vmcb, mut frame) = stopped(index, write, false, 0);
        assert_unhandled(&mut state, &mut vmcb, &mut frame);
    }
    for cpuid in [None, Some(0)] {
        let (mut state, mut vmcb, mut frame) = stopped(SMM_CTL, None, false, 0);
        state.target_msrs = TargetMsrPolicy::admit(TARGET_SIGNATURE, cpuid, 1, 0, 0, 0);
        assert_unhandled(&mut state, &mut vmcb, &mut frame);
    }
    let (mut state, mut vmcb, mut frame) = stopped(SMM_CTL, None, false, 0);
    state.target_msrs = None;
    assert_unhandled(&mut state, &mut vmcb, &mut frame);
}

fn assert_unhandled(state: &mut State, vmcb: &mut Vmcb, frame: &mut GuestRegisters) {
    let before = (*vmcb.bytes(), *frame, state.target_msrs, state.routing_retries);
    assert_eq!(unsafe { handle_target_msr(state, vmcb, frame) }, None);
    assert_eq!((*vmcb.bytes(), *frame, state.target_msrs, state.routing_retries), before);
    assert!(!state.pending_fault && !state.stopped_valid);
}

#[test]
fn success_refuses_invalid_nrip_and_unowned_debug_completion_without_fetch() {
    for (offset, value) in [
        (0x0c8, 0),
        (0x0c8, 0x4001),
        (0x0c8, 0x4010),
        (0x0c8, 0x0000_8000_0000_0000),
        (0x570, 0x10302),
    ] {
        let (mut state, mut vmcb, mut frame) = stopped(SMM_KEY, None, false, 0);
        put(&mut vmcb, offset, value);
        let before = (*vmcb.bytes(), frame, state.target_msrs);
        assert_eq!(unsafe { handle_target_msr(&mut state, &mut vmcb, &mut frame) }, Some(false));
        assert_eq!((*vmcb.bytes(), frame, state.target_msrs), before);
        assert!(!state.pending_fault && state.stopped_valid);
        assert_eq!((state.stopped_info1, state.stopped_info2), (0xf104, u64::from(SMM_KEY)));
    }
}

#[test]
fn legacy_completion_requires_matching_opcode_and_nonwrapping_ip() {
    let (_, mut vmcb, _) = stopped(SMM_KEY, None, true, 0);
    put(&mut vmcb, 0x410, (0xffffu64 << 32) | (0x9b << 16));
    put(&mut vmcb, 0x4d0, 0x1000);
    put(&mut vmcb, 0x558, 0x10);
    let next = msr_continuation_from_instruction(&vmcb, MsrInstruction::Bytes(&[0x0f, 0x32]), true)
        .unwrap();
    assert_eq!(next.address(), 0x4002);
    assert!(
        msr_continuation_from_instruction(&vmcb, MsrInstruction::Bytes(&[0x0f, 0x30]), true)
            .is_none()
    );
    put(&mut vmcb, 0x578, 0xfffe);
    assert!(
        msr_continuation_from_instruction(&vmcb, MsrInstruction::Bytes(&[0x0f, 0x32]), true)
            .is_none()
    );
}

#[test]
fn mcax_discovery_bounds_reads_and_never_tests_absent_status_write_enable() {
    use mcax::Access;
    for index in [mcax::FIRST - 1, mcax::LAST + 1] {
        assert_eq!(
            plan_mcax_access(index, Some(1), |_| panic!("out-of-window metadata read")),
            None
        );
    }
    for index in [mcax::FIRST + 0x41, mcax::FIRST + 0x81, mcax::LAST] {
        let mut count = 0;
        assert_eq!(
            plan_mcax_access(index, Some(u64::MAX), |msr| {
                assert_eq!(msr, mcax::MCG_CAP);
                count += 1;
                8
            }),
            Some(Access::ReadZeroIgnoreWrite)
        );
        assert_eq!(count, 1);
    }
    for write in [None, Some(0), Some(u64::MAX)] {
        let mut reads = 0;
        assert_eq!(
            plan_mcax_access(mcax::FIRST + 0x71, write, |msr| {
                reads += 1;
                match msr {
                    mcax::MCG_CAP => 8,
                    0xc000_2075 => 0xffff_f000_ffff_ffff, // Nonzero IPID, zero HardwareID.
                    _ => panic!("unpopulated bank must not read HWCR or requested STATUS"),
                }
            }),
            Some(Access::ReadZeroIgnoreWrite)
        );
        assert_eq!(reads, 2);
    }
}

#[test]
fn mcax_status_fault_uses_live_hwcr_only_for_implemented_nonzero_writes() {
    use mcax::Access;
    for enabled in [false, true] {
        let mut reads = [0u32; 3];
        let mut count = 0;
        assert_eq!(
            plan_mcax_access(mcax::FIRST + 1, Some(1), |msr| {
                reads[count] = msr;
                count += 1;
                match msr {
                    mcax::MCG_CAP => 8,
                    0xc000_2005 => 0xb0 << 32,
                    HWCR => {
                        if enabled {
                            HWCR_MC_STATUS_WR_EN
                        } else {
                            0
                        }
                    }
                    _ => panic!("no requested STATUS access while planning"),
                }
            }),
            Some(if enabled { Access::Write(1) } else { Access::GeneralProtection })
        );
        assert_eq!(reads, [mcax::MCG_CAP, 0xc000_2005, HWCR]);
    }
    for (offset, write, expected) in
        [(1, None, Access::Read), (1, Some(0), Access::Write(0)), (8, Some(1), Access::Write(1))]
    {
        assert_eq!(
            plan_mcax_access(mcax::FIRST + offset, write, |msr| match msr {
                mcax::MCG_CAP => 8,
                0xc000_2005 => 0xb0 << 32,
                _ => panic!("this access does not need HWCR"),
            }),
            Some(expected)
        );
    }
    assert_eq!(
        plan_mcax_access(mcax::FIRST + 7, Some(1), |msr| match msr {
            mcax::MCG_CAP => 8,
            0xc000_2005 => 0xb0 << 32,
            _ => panic!("reserved access must not reach hardware or need HWCR"),
        }),
        None
    );
}

#[test]
fn fetch_contention_retries_without_retirement_and_other_failures_stop() {
    use crate::host::resident::terminal::FetchReadFailure;
    let (mut state, vmcb, _) = stopped(SMM_KEY, None, true, 0);
    let before = *vmcb.bytes();
    let busy = MsrContinuationError::Fetch(FetchReadFailure::MemoryControlBusy as u16);
    assert!(msr_continuation_failure(&mut state, &vmcb, SMM_KEY, busy));
    assert_eq!(state.routing_retries, 10);
    assert!(!state.stopped_valid && !state.pending_fault);
    state.routing_retries = 1024;
    assert!(!msr_continuation_failure(&mut state, &vmcb, SMM_KEY, busy));
    assert_eq!((state.stopped_info1, state.stopped_info2), (0xf107, 1025));
    assert_eq!(*vmcb.bytes(), before);

    let (mut state, vmcb, _) = stopped(SMM_KEY, None, true, 0);
    let before = *vmcb.bytes();
    let reason = FetchReadFailure::RamAdmission as u16;
    assert!(!msr_continuation_failure(
        &mut state,
        &vmcb,
        SMM_KEY,
        MsrContinuationError::Fetch(reason)
    ));
    assert_eq!((state.stopped_info1, state.stopped_info2), (0xf001, u64::from(reason)));
    assert_eq!(*vmcb.bytes(), before);
    assert!(!state.pending_fault);
}
