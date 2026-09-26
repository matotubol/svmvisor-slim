use core::ptr;

use svmvisor_hypervisor::{
    arch::x86_64::capabilities::{
        CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures, ValidatedCapabilities,
    },
    memory::address::EncryptionState,
    svm::{
        instructions::{NativeSvmInstruction, NativeSvmInstructions},
        protection,
        vmcb::Vmcb,
    },
};

const OPCODES: [(u8, NativeSvmInstruction); 7] = [
    (0xd8, NativeSvmInstruction::Vmrun),
    (0xda, NativeSvmInstruction::Vmload),
    (0xdb, NativeSvmInstruction::Vmsave),
    (0xdc, NativeSvmInstruction::Stgi),
    (0xdd, NativeSvmInstruction::Clgi),
    (0xde, NativeSvmInstruction::Skinit),
    (0xdf, NativeSvmInstruction::Invlpga),
];

#[derive(Clone, Copy, Debug)]
enum Mode {
    Long64,
    Compatibility32,
    Compatibility16,
    Protected32,
    Protected16,
    Real,
    Virtual8086,
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
        optional: OptionalFeatures::default(),
    }
    .validate()
    .unwrap()
}

fn owner(skinit: bool, svm_lock: bool) -> NativeSvmInstructions {
    NativeSvmInstructions::admit_native(
        &capabilities(),
        (1 << 2) | if skinit { 1 << 12 } else { 0 },
        if svm_lock { 1 << 2 } else { 0 },
    )
    .unwrap()
}

fn stopped(mode: Mode, cpl: u8) -> Vmcb {
    let long = matches!(mode, Mode::Long64 | Mode::Compatibility32 | Mode::Compatibility16);
    let attributes = match mode {
        Mode::Long64 => 0x29b,
        Mode::Compatibility32 | Mode::Protected32 => 0x49b,
        _ => 0x9b,
    };
    let mut vmcb = Vmcb::new();
    for (offset, value) in [
        (0x070, 0x4d),
        (0x078, 0),
        // Undefined fields and next RIP cannot help classify a #GP opcode.
        (0x080, u64::MAX),
        (0x0c0, u64::MAX),
        (0x0c8, u64::MAX),
        (0x410, attributes << 16),
        (0x4d0, if long { 0x1500 } else { 0x1100 }),
        (0x558, if matches!(mode, Mode::Real) { 0x10 } else { 0x11 }),
        (0x570, 0x10302 | if matches!(mode, Mode::Virtual8086) { 1 << 17 } else { 0 }),
        (0x578, 0x4567),
        (0x5d8, 0xabcdef00),
        (0x5f8, u64::MAX),
        (0x640, 0x56789000),
    ] {
        put(&mut vmcb, offset, value);
    }
    // SAFETY: this test exclusively owns inert VMCB storage; CPL is one byte.
    unsafe { *ptr::from_mut(&mut vmcb).cast::<u8>().add(0x4cb) = cpl };
    vmcb
}

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: tests exclusively own inert VMCB storage; every offset is in bounds.
    unsafe {
        ptr::write_unaligned(ptr::from_mut(vmcb).cast::<u8>().add(offset).cast(), value);
    }
}

fn classify(
    owner: &NativeSvmInstructions,
    vmcb: &Vmcb,
    bytes: &[u8],
) -> Result<Option<NativeSvmInstruction>, usize> {
    protection::classify(owner, 0x500, vmcb, |index| bytes.get(index).copied().ok_or(index))
}

#[test]
fn svme_disabled_is_classified_at_every_cpl_and_protected_code_size() {
    let owner = owner(false, false);
    for mode in [
        Mode::Long64,
        Mode::Compatibility32,
        Mode::Compatibility16,
        Mode::Protected32,
        Mode::Protected16,
    ] {
        for cpl in 0..=3 {
            let vmcb = stopped(mode, cpl);
            let before = *vmcb.bytes();
            for (opcode, instruction) in OPCODES {
                let bytes = [0x0f, 0x01, opcode];
                assert_eq!(classify(&owner, &vmcb, &bytes), Ok(Some(instruction)));
                assert_eq!(*vmcb.bytes(), before);
            }
        }
    }
}

#[test]
fn independently_enabled_stgi_and_skinit_preserve_general_protection() {
    for skinit in [false, true] {
        for svm_lock in [false, true] {
            let owner = owner(skinit, svm_lock);
            for cpl in [0, 3] {
                let vmcb = stopped(Mode::Long64, cpl);
                for (opcode, instruction) in OPCODES {
                    let independent = (skinit || svm_lock)
                        && matches!(
                            instruction,
                            NativeSvmInstruction::Stgi | NativeSvmInstruction::Skinit
                        );
                    let expected = if independent { None } else { Some(instruction) };
                    assert_eq!(classify(&owner, &vmcb, &[0x0f, 0x01, opcode]), Ok(expected));
                }
            }
        }
    }
}

#[test]
fn unrelated_fault_contexts_never_fetch_instruction_bytes() {
    let owner = owner(false, false);
    for mode in [Mode::Real, Mode::Virtual8086] {
        assert_eq!(classify(&owner, &stopped(mode, 0), &[]), Ok(None));
    }
    let vmcb = stopped(Mode::Long64, 3);
    assert_eq!(protection::classify(&owner, 0x1500, &vmcb, |_| Err(())), Ok(None));
    for (offset, value) in [(0x070, 0x82), (0x078, 8), (0x088, 0x8000_0306)] {
        let mut vmcb = stopped(Mode::Long64, 3);
        put(&mut vmcb, offset, value);
        assert_eq!(classify(&owner, &vmcb, &[]), Ok(None));
    }
}

#[test]
fn complete_opcode_does_not_read_following_instruction_or_page() {
    let owner = owner(false, false);
    let vmcb = stopped(Mode::Long64, 3);
    let mut reads = 0;
    let result = protection::classify(&owner, 0x500, &vmcb, |index| {
        assert_eq!(index, reads);
        reads += 1;
        [0x0f, 0x01, 0xda].get(index).copied().ok_or(index)
    });
    assert_eq!(result, Ok(Some(NativeSvmInstruction::Vmload)));
    assert_eq!(reads, 3);
}

#[test]
fn fetch_failures_remain_distinct_from_other_opcodes() {
    let owner = owner(false, false);
    let vmcb = stopped(Mode::Long64, 3);
    for bytes in [&[][..], &[0x0f], &[0x0f, 0x01]] {
        assert_eq!(classify(&owner, &vmcb, bytes), Err(bytes.len()));
    }
    for bytes in [&[0x90][..], &[0x0f, 0x32], &[0x0f, 0x01, 0xd9], &[0x0f, 0x01, 0xd7]] {
        assert_eq!(classify(&owner, &vmcb, bytes), Ok(None));
    }
}

#[test]
fn legal_legacy_prefixes_and_long64_rex_preserve_opcode_identity() {
    let owner = owner(false, false);
    for mode in [Mode::Long64, Mode::Compatibility32, Mode::Protected16] {
        let vmcb = stopped(mode, 3);
        for prefixes in
            [&[][..], &[0x66], &[0x67], &[0x65], &[0x66, 0x67, 0x64], &[0x64, 0x67, 0x66]]
        {
            let mut bytes = prefixes.to_vec();
            bytes.extend_from_slice(&[0x0f, 0x01, 0xda]);
            assert_eq!(classify(&owner, &vmcb, &bytes), Ok(Some(NativeSvmInstruction::Vmload)));
        }
    }
    for rex in 0x40..=0x4f {
        let bytes = [0x66, 0x67, 0x64, rex, 0x0f, 0x01, 0xda];
        assert_eq!(
            classify(&owner, &stopped(Mode::Long64, 3), &bytes),
            Ok(Some(NativeSvmInstruction::Vmload))
        );
        assert_eq!(classify(&owner, &stopped(Mode::Compatibility32, 3), &bytes), Ok(None));
    }
}

#[test]
fn undefined_prefix_groups_and_unowned_mandatory_prefixes_preserve_gp() {
    let owner = owner(false, false);
    let vmcb = stopped(Mode::Long64, 3);
    for prefixes in [
        &[0xf0][..],
        &[0xf2],
        &[0xf3],
        &[0x66, 0x66],
        &[0x67, 0x67],
        &[0x64, 0x65],
        &[0x40, 0x48],
        &[0x48, 0x66],
    ] {
        let mut bytes = prefixes.to_vec();
        bytes.extend_from_slice(&[0x0f, 0x01, 0xda]);
        assert_eq!(classify(&owner, &vmcb, &bytes), Ok(None));
    }
}

#[test]
fn null_segments_can_repeat_up_to_fifteen_bytes_only_in_long64_without_uaie() {
    let owner = owner(false, false);
    let vmcb = stopped(Mode::Long64, 3);
    let mut bytes = [0x2e; 16];
    bytes[12..15].copy_from_slice(&[0x0f, 0x01, 0xda]);
    assert_eq!(classify(&owner, &vmcb, &bytes), Ok(Some(NativeSvmInstruction::Vmload)));
    assert_eq!(classify(&owner, &stopped(Mode::Compatibility32, 3), &bytes), Ok(None));
    assert_eq!(
        protection::classify(&owner, 0x10_0500, &vmcb, |index| Ok::<_, ()>(bytes[index])),
        Ok(None)
    );
    let bytes = [0x26, 0x36, 0x3e, 0x64, 0x2e, 0x0f, 0x01, 0xda];
    assert_eq!(classify(&owner, &vmcb, &bytes), Ok(Some(NativeSvmInstruction::Vmload)));
    for escape in [13, 14, 15] {
        let mut bytes = [0x2e; 18];
        bytes[escape..escape + 3].copy_from_slice(&[0x0f, 0x01, 0xda]);
        let mut reads = 0;
        assert_eq!(
            protection::classify(&owner, 0x500, &vmcb, |index| {
                assert!(index < 15);
                reads += 1;
                Ok::<_, ()>(bytes[index])
            }),
            Ok(None)
        );
        assert!(reads <= 15);
    }
}
