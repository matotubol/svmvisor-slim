use svmvisor_hypervisor::{
    arch::x86_64::{
        capabilities::{
            CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures, ValidatedCapabilities,
        },
        registers::GuestRegisters,
    },
    memory::address::{AddressError, EncryptionState},
    svm::{
        events::ExternalInterruptError,
        exit::ResumeError,
        mmio::{
            CommitError, DecodeError, Direction, LinearAccess, MmioError, PrepareError, prepare,
        },
        vmcb::Vmcb,
    },
};

const GPA: u64 = 0xfe00_0000;
const RIP: u64 = 0x4000;

fn caps(decode: bool, nrip: bool, encryption_bit: Option<u8>) -> ValidatedCapabilities {
    CapabilityEvidence {
        vendor: CpuVendor::Amd,
        svm: EvidenceFlag::Set,
        nested_paging: EvidenceFlag::Set,
        svm_revision: Some(1),
        asid_count: Some(16),
        physical_address_bits: Some(48),
        vm_cr_svmdis: EvidenceFlag::Clear,
        hypervisor_present: EvidenceFlag::Clear,
        encryption: EncryptionState::Unencrypted { encryption_bit },
        optional: OptionalFeatures {
            decode_assists: decode,
            nrip_save: nrip,
            ..Default::default()
        },
    }
    .validate()
    .unwrap()
}

fn bytes(vmcb: &mut Vmcb, offset: usize, bytes: &[u8]) {
    assert!(offset + bytes.len() <= 4096);
    // SAFETY: exclusive inert VMCB fixture; checked complete in-bounds span.
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            core::ptr::from_mut(vmcb).cast::<u8>().add(offset),
            bytes.len(),
        );
    }
}

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    bytes(vmcb, offset, &value.to_le_bytes());
}

fn field(vmcb: &Vmcb, offset: usize) -> u64 {
    u64::from_le_bytes(vmcb.bytes()[offset..offset + 8].try_into().unwrap())
}

fn fixture(instruction: &[u8], write: bool) -> (Vmcb, GuestRegisters) {
    let mut vmcb = Vmcb::new();
    for (offset, value) in [
        (0x068, 1),
        (0x070, 0x400),
        (0x078, (1 << 32) | 5 | if write { 2 } else { 0 }),
        (0x080, GPA),
        (0x090, 1),
        (0x0c8, u64::MAX),
        (0x410, 0x29b << 16),
        (0x4d0, 0x1500),
        (0x548, 0x20),
        (0x558, 0x8000_0011),
        (0x560, 0x400),
        (0x570, 0x1_0202),
        (0x578, RIP),
        (0x5d8, 0xdead_beef_0123_4564),
        (0x5f8, 0xdead_beef_0123_4560),
    ] {
        put(&mut vmcb, offset, value);
    }
    bytes(&mut vmcb, 0x0d0, &[instruction.len() as u8]);
    bytes(&mut vmcb, 0x0d1, instruction);
    (
        vmcb,
        GuestRegisters {
            rcx: 0xdead_beef_0123_4561,
            rdx: 0xdead_beef_0123_4562,
            rbx: 0xdead_beef_0123_4563,
            rbp: 0xdead_beef_0123_4565,
            rsi: 0xdead_beef_0123_4566,
            rdi: 0xdead_beef_0123_4567,
            r8: 0xdead_beef_0123_4568,
            r9: 0xdead_beef_0123_4569,
            r10: 0xdead_beef_0123_456a,
            r11: 0xdead_beef_0123_456b,
            r12: 0xdead_beef_0123_456c,
            r13: 0xdead_beef_0123_456d,
            r14: 0xdead_beef_0123_456e,
            r15: 0xdead_beef_0123_456f,
        },
    )
}

fn registers(v: &Vmcb, f: &GuestRegisters) -> [u64; 16] {
    [
        v.guest_rax(),
        f.rcx,
        f.rdx,
        f.rbx,
        v.guest_rsp(),
        f.rbp,
        f.rsi,
        f.rdi,
        f.r8,
        f.r9,
        f.r10,
        f.r11,
        f.r12,
        f.r13,
        f.r14,
        f.r15,
    ]
}

// Independent fixed addressing: [disp32=1000h], no base/index register.
fn instruction(width: u8, register: u8, write: bool, rex: bool) -> Vec<u8> {
    let mut code = Vec::new();
    if width == 2 {
        code.push(0x66);
    }
    if rex {
        code.push(0x40 | if width == 8 { 8 } else { 0 } | ((register >> 3) << 2));
    }
    code.push(if write { 0x88 } else { 0x8a } | u8::from(width != 1));
    code.extend_from_slice(&[(register & 7) << 3 | 4, 0x25, 0x00, 0x10, 0, 0]);
    code
}

fn assert_only_commit_fields_changed(before: &[u8; 4096], after: &Vmcb) {
    for (offset, old) in before.iter().copied().enumerate() {
        if (0x068..0x070).contains(&offset)
            || (0x570..0x580).contains(&offset)
            || (0x5d8..0x5e0).contains(&offset)
            || (0x5f8..0x600).contains(&offset)
        {
            continue;
        }
        assert_eq!(after.bytes()[offset], old, "unexpected VMCB change at {offset:x}");
    }
    assert_eq!(field(after, 0x068), 0);
    assert_eq!(field(after, 0x570), 0x202);
}

#[test]
fn every_gpr_lane_has_exact_read_merge_and_write_value_without_other_changes() {
    let caps = caps(true, false, None);
    let value = 0x8bad_f00d_fedc_ba98;
    for width in [1, 2, 4, 8] {
        for encoded in 0..16 {
            for write in [false, true] {
                let code = instruction(width, encoded, write, true);
                let (mut vmcb, mut frame) = fixture(&code, write);
                let before = *vmcb.bytes();
                let mut expected = registers(&vmcb, &frame);
                let mask = u64::MAX >> (64 - width * 8);
                let token = prepare(&mut vmcb, &mut frame, &caps, |_, span| {
                    assert_eq!(
                        span,
                        LinearAccess {
                            address: 0x1000,
                            bytes: width,
                            direction: if write { Direction::Write } else { Direction::Read }
                        }
                    );
                    Ok::<_, ()>(GPA)
                })
                .unwrap();
                assert_eq!(token.instruction_bytes(), code.len() as u8);
                assert_eq!(token.accumulator_operand(), encoded == 0);
                assert_eq!(token.access().guest_physical, GPA);
                if write {
                    assert_eq!(token.access().write_value, Some(expected[encoded as usize] & mask));
                    token.commit_write().unwrap();
                } else {
                    assert_eq!(token.access().write_value, None);
                    expected[encoded as usize] = if width >= 4 {
                        value & mask
                    } else {
                        expected[encoded as usize] & !mask | value & mask
                    };
                    token.commit_read(value).unwrap();
                }
                assert_eq!(
                    registers(&vmcb, &frame),
                    expected,
                    "width={width}, register={encoded}, write={write}"
                );
                assert_eq!(vmcb.guest_rip(), RIP + code.len() as u64);
                assert_only_commit_fields_changed(&before, &vmcb);
            }
        }
    }
}

#[test]
fn legacy_high_bytes_are_distinct_from_rex_low_bytes_and_ecam_accumulator() {
    for encoded in 4..8 {
        for write in [false, true] {
            let code = instruction(1, encoded, write, false);
            let (mut vmcb, mut frame) = fixture(&code, write);
            let mut expected = registers(&vmcb, &frame);
            let token =
                prepare(&mut vmcb, &mut frame, &caps(true, false, None), |_, _| Ok::<_, ()>(GPA))
                    .unwrap();
            assert!(!token.accumulator_operand());
            let target = usize::from(encoded - 4);
            if write {
                assert_eq!(token.access().write_value, Some((expected[target] >> 8) & 0xff));
                token.commit_write().unwrap();
            } else {
                expected[target] = (expected[target] & !0xff00) | 0xa700;
                token.commit_read(0x1a7).unwrap();
            }
            assert_eq!(registers(&vmcb, &frame), expected);
        }
    }
}

#[test]
fn exact_modrm_sib_rip_relative_and_address32_forms_use_stopped_registers() {
    let cases: &[(&[u8], u64)] = &[
        (&[0x8b, 0x00], 0x2000),                            // [rax]
        (&[0x8b, 0x44, 0x88, 0xe0], 0x20a0),                // [rax+rcx*4-32]
        (&[0x8b, 0x80, 0x00, 0xf0, 0xff, 0xff], 0x1000),    // [rax-4096]
        (&[0x43, 0x8b, 0x44, 0xa5, 0x10], 0x9210),          // [r13+r12*4+16]
        (&[0x41, 0x8b, 0x04, 0x25, 0, 0x30, 0, 0], 0x3000), // SIB base5 ignores REX.B
        (&[0x42, 0x8b, 0x04, 0x25, 0, 0x30, 0, 0], 0x3080), // REX.X makes index4 r12
        (&[0x41, 0x8b, 0x05, 0xf9, 0xff, 0xff, 0xff], RIP), // RIP ignores REX.B
        (&[0x67, 0x8b, 0x05, 0xf9, 0xff, 0xff, 0xff], RIP), // address32 EIP relative
        (&[0x67, 0x41, 0x8b, 0x04, 0x24], 0x80),            // address32 r12d as base
        (&[0x67, 0x8b, 0x04, 0x25, 0, 0xff, 0xff, 0xff], 0xffff_ff00),
        (&[0x8b, 0x04, 0x25, 0, 0xff, 0xff, 0xff], 0xffff_ffff_ffff_ff00),
        (&[0x66, 0x67, 0x48, 0x8b, 0x00], 0x2000), // REX.W wins over 66
    ];
    for &(code, address) in cases {
        let (mut vmcb, mut frame) = fixture(code, false);
        vmcb.set_guest_rax(0x2000);
        frame.rcx = 0x30;
        frame.r12 = 0x80;
        frame.r13 = 0x9000;
        put(&mut vmcb, 0x080, GPA + (address & 4095));
        let before = *vmcb.bytes();
        let before_frame = frame;
        let token = prepare(&mut vmcb, &mut frame, &caps(true, false, None), |_, span| {
            assert_eq!(span.address, address, "{code:x?}");
            Ok::<_, ()>(GPA + (address & 4095))
        })
        .unwrap();
        assert_eq!(token.instruction_bytes(), code.len() as u8);
        drop(token);
        assert_eq!(*vmcb.bytes(), before);
        assert_eq!(frame, before_frame);
    }
}

#[test]
fn moffs_width_address_size_and_prefix_orders_are_bounded() {
    for width in [1, 2, 4, 8] {
        for short in [false, true] {
            for write in [false, true] {
                let mut code = Vec::new();
                if short {
                    code.push(0x67);
                }
                if width == 2 {
                    code.push(0x66);
                }
                if width == 8 {
                    code.push(0x48);
                }
                code.push(if write { 0xa2 } else { 0xa0 } | u8::from(width != 1));
                code.extend_from_slice(&0x1234_1000u64.to_le_bytes()[..if short { 4 } else { 8 }]);
                let (mut vmcb, mut frame) = fixture(&code, write);
                let token = prepare(&mut vmcb, &mut frame, &caps(true, false, None), |_, span| {
                    assert_eq!((span.address, span.bytes), (0x1234_1000, width));
                    Ok::<_, ()>(GPA)
                })
                .unwrap();
                assert!(token.accumulator_operand());
                assert_eq!(token.instruction_bytes(), code.len() as u8);
            }
        }
    }
}

fn refusal(vmcb: &mut Vmcb, frame: &mut GuestRegisters, expected: MmioError) {
    let before = *vmcb.bytes();
    let before_frame = *frame;
    let result = prepare(vmcb, frame, &caps(true, false, None), |_, _| -> Result<u64, ()> {
        panic!("refused operand reached translation");
    });
    assert!(matches!(result, Err(PrepareError::Boundary(e)) if e == expected));
    assert_eq!(*vmcb.bytes(), before);
    assert_eq!(*frame, before_frame);
}

#[test]
fn unsupported_or_incomplete_instructions_never_reach_translation_or_change_state() {
    let cases: &[(&[u8], DecodeError)] = &[
        (&[0x8b], DecodeError::Truncated),
        (&[0x8b, 0x04], DecodeError::Truncated),
        (&[0x8b, 0x05, 0, 0, 0], DecodeError::Truncated),
        (&[0xa1, 0, 0, 0, 0, 0, 0, 0], DecodeError::Truncated),
        (&[0x8b, 0xc0], DecodeError::RegisterOnly),
        (&[0xc7, 0, 0, 0, 0, 0], DecodeError::UnsupportedOpcode(0xc7)),
        (&[0x0f, 0xb6, 0], DecodeError::UnsupportedOpcode(0x0f)),
        (&[0x87, 0], DecodeError::UnsupportedOpcode(0x87)),
        (&[0xa4], DecodeError::UnsupportedOpcode(0xa4)),
    ];
    for &(code, expected) in cases {
        let (mut vmcb, mut frame) = fixture(code, false);
        refusal(&mut vmcb, &mut frame, MmioError::Decode(expected));
    }
    for prefix in [0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0xf0, 0xf2, 0xf3] {
        let (mut vmcb, mut frame) = fixture(&[prefix, 0x8b, 0x00], false);
        refusal(&mut vmcb, &mut frame, MmioError::Decode(DecodeError::UnsupportedPrefix));
    }
    for code in [
        &[0x66, 0x66, 0x8b, 0][..],
        &[0x67, 0x67, 0x8b, 0],
        &[0x40, 0x48, 0x8b, 0],
        &[0x48, 0x66, 0x8b, 0],
    ] {
        let (mut vmcb, mut frame) = fixture(code, false);
        refusal(&mut vmcb, &mut frame, MmioError::Decode(DecodeError::UnsupportedPrefix));
    }
}

#[test]
fn only_exact_final_data_fault_and_supported_mode_can_prepare() {
    let cases = [
        (0x070, 0x72, MmioError::UnsupportedExit),
        (0x078, 1, MmioError::UnsupportedFault),
        (0x078, (1 << 33) | 3, MmioError::UnsupportedFault),
        (0x078, (1 << 32) | 3, MmioError::UnsupportedFault), // MOV read disagrees with RW
        (0x410, 0x49b << 16, MmioError::UnsupportedMode),
        (0x4d0, 0x1100, MmioError::UnsupportedMode),
        (0x548, 0, MmioError::UnsupportedMode),
        (0x548, 0x1020, MmioError::UnsupportedMode),
        (0x558, 0x11, MmioError::UnsupportedMode),
        (0x4d0, 0x10_1500, MmioError::UnsupportedMode),
        (0x570, 0x2_0202, MmioError::UnsupportedMode),
        (0x090, 0, MmioError::UnsupportedMode),
        (0x090, 3, MmioError::UnsupportedMode),
        (0x570, 0x302, MmioError::UnsupportedDebugState),
        (0x560, 0x401, MmioError::UnsupportedDebugState),
        (0x0a8, 1 << 31, MmioError::Pending(ExternalInterruptError::PendingInjection)),
        (0x088, 1 << 31, MmioError::Pending(ExternalInterruptError::NestedDeliveryUnsupported)),
    ];
    for (offset, value, expected) in cases {
        let (mut vmcb, mut frame) = fixture(&[0x8b, 0], false);
        put(&mut vmcb, offset, value);
        refusal(&mut vmcb, &mut frame, expected);
    }
    for bit in (3..32).chain(33..64) {
        let (mut vmcb, mut frame) = fixture(&[0x8b, 0], false);
        put(&mut vmcb, 0x078, (1 << 32) | (1 << bit));
        refusal(&mut vmcb, &mut frame, MmioError::UnsupportedFault);
    }
    let (mut vmcb, mut frame) = fixture(&[0x8b, 0], false);
    bytes(&mut vmcb, 0x4cb, &[3]);
    refusal(&mut vmcb, &mut frame, MmioError::UnsupportedMode);
}

#[test]
fn decode_assists_count_and_decoded_continuation_ignore_nrip_entirely() {
    for count in [0, 16, 0x81, 255] {
        let (mut vmcb, mut frame) = fixture(&[0x8b, 0], false);
        bytes(&mut vmcb, 0x0d0, &[count]);
        refusal(&mut vmcb, &mut frame, MmioError::InvalidInstructionBytes);
    }
    let (mut vmcb, mut frame) = fixture(&[0x8b, 0], false);
    bytes(&mut vmcb, 0x0d0, &[1]); // stale backing contains ModRM, but hardware count does not
    refusal(&mut vmcb, &mut frame, MmioError::Decode(DecodeError::Truncated));
    let (mut vmcb, mut frame) = fixture(&[0x8b, 0], false);
    let before = *vmcb.bytes();
    assert!(matches!(
        prepare(&mut vmcb, &mut frame, &caps(false, true, None), |_, _| Ok::<_, ()>(GPA)),
        Err(PrepareError::Boundary(MmioError::DecodeAssistsUnavailable))
    ));
    assert_eq!(*vmcb.bytes(), before);
    for nrips in [false, true] {
        for nrip in [0, RIP + 15, u64::MAX] {
            let code = instruction(4, 0, false, false);
            let (mut vmcb, mut frame) = fixture(&code, false);
            put(&mut vmcb, 0x0c8, nrip);
            bytes(&mut vmcb, 0x0d0, &[15]); // fetched trailing bytes are not instruction length
            let token =
                prepare(&mut vmcb, &mut frame, &caps(true, nrips, None), |_, _| Ok::<_, ()>(GPA))
                    .unwrap();
            assert_eq!(token.instruction_bytes(), code.len() as u8);
            token.commit_read(7).unwrap();
            assert_eq!(vmcb.guest_rip(), RIP + code.len() as u64);
        }
    }
    for (rip, expected) in [
        (0x8000_0000_0000, ResumeError::NonCanonicalRip),
        (0x7fff_ffff_fffe, ResumeError::NonCanonicalNrip),
        (u64::MAX, ResumeError::InvalidInstructionLength),
    ] {
        let (mut vmcb, mut frame) = fixture(&[0x8b, 0], false);
        put(&mut vmcb, 0x578, rip);
        refusal(&mut vmcb, &mut frame, MmioError::Continuation(expected));
    }
}

#[test]
fn address32_truncates_high_rip_and_last_aligned_qword_stays_in_one_page() {
    let (mut vmcb, mut frame) = fixture(&[0x67, 0x8b, 0x05, 0xf9, 0xff, 0xff, 0xff], false);
    put(&mut vmcb, 0x578, 0xffff_8001_0000_4000);
    let token = prepare(&mut vmcb, &mut frame, &caps(true, false, None), |_, span| {
        assert_eq!(span.address, 0x4000);
        Ok::<_, ()>(GPA)
    })
    .unwrap();
    token.commit_read(1).unwrap();
    assert_eq!(vmcb.guest_rip(), 0xffff_8001_0000_4007);

    let (mut vmcb, mut frame) = fixture(&[0x48, 0x8b, 0x00], false);
    vmcb.set_guest_rax(0x1ff8);
    put(&mut vmcb, 0x080, GPA + 4088);
    let token = prepare(&mut vmcb, &mut frame, &caps(true, false, None), |_, span| {
        assert_eq!(span, LinearAccess { address: 0x1ff8, bytes: 8, direction: Direction::Read });
        assert_eq!((span.address + u64::from(span.bytes) - 1) & 4095, 4095);
        Ok::<_, ()>(GPA + 4088)
    })
    .unwrap();
    token.commit_read(0xaabb_ccdd_eeff_0099).unwrap();
    assert_eq!(vmcb.guest_rax(), 0xaabb_ccdd_eeff_0099);
}

#[test]
fn complete_operand_bounds_and_current_translation_bind_the_reported_gpa() {
    for (linear, gpa, expected) in [
        (0x8000_0000_0000, GPA, MmioError::NoncanonicalOperand),
        (u64::MAX, GPA, MmioError::NoncanonicalOperand),
        (0x1fff, GPA + 4095, MmioError::UnalignedOperand),
        (0x1000, GPA + 4, MmioError::PageOffsetMismatch),
        (0x1000, GPA + 1, MmioError::PhysicalSpan(AddressError::Misaligned)),
        (0x1000, 1 << 48, MmioError::PhysicalSpan(AddressError::OutsidePhysicalWidth)),
    ] {
        let (mut vmcb, mut frame) = fixture(&[0x8b, 0], false);
        vmcb.set_guest_rax(linear);
        put(&mut vmcb, 0x080, gpa);
        refusal(&mut vmcb, &mut frame, expected);
    }
    for outcome in [Err("table changed"), Ok(GPA + 4096)] {
        let (mut vmcb, mut frame) = fixture(&instruction(8, 9, false, true), false);
        let before = *vmcb.bytes();
        let before_frame = frame;
        let result = prepare(&mut vmcb, &mut frame, &caps(true, false, None), |_, span| {
            assert_eq!(
                span,
                LinearAccess { address: 0x1000, bytes: 8, direction: Direction::Read }
            );
            outcome
        });
        assert!(
            matches!(result, Err(PrepareError::Translation("table changed")))
                || matches!(result, Err(PrepareError::Boundary(MmioError::OperandMismatch { reported: GPA, translated })) if translated == GPA + 4096)
        );
        assert_eq!(*vmcb.bytes(), before);
        assert_eq!(frame, before_frame);
    }
    let (mut vmcb, mut frame) = fixture(&instruction(8, 0, false, true), false);
    assert!(matches!(
        prepare(&mut vmcb, &mut frame, &caps(true, false, Some(31)), |_, _| -> Result<u64, ()> {
            panic!("encrypted GPA");
        }),
        Err(PrepareError::Boundary(MmioError::PhysicalSpan(AddressError::EncryptionBitEncoded)))
    ));
}

#[test]
fn wrong_commit_direction_and_dropped_tokens_preserve_all_guest_state() {
    for write in [false, true] {
        for wrong_commit in [false, true] {
            let (mut vmcb, mut frame) = fixture(&instruction(8, 4, write, true), write);
            let before = *vmcb.bytes();
            let before_frame = frame;
            let token =
                prepare(&mut vmcb, &mut frame, &caps(true, false, None), |_, _| Ok::<_, ()>(GPA))
                    .unwrap();
            if wrong_commit {
                assert_eq!(
                    if write { token.commit_read(9) } else { token.commit_write() },
                    Err(CommitError::WrongDirection)
                );
            } else {
                drop(token);
            }
            assert_eq!(*vmcb.bytes(), before);
            assert_eq!(frame, before_frame);
        }
    }
}
