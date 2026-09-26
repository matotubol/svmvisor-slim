use core::ptr;
use std::collections::BTreeMap;

use svmvisor_hypervisor::{
    arch::x86_64::capabilities::{
        CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures, ValidatedCapabilities,
    },
    host::{
        paging::WalkError,
        resident::fetch::{self, FetchError},
    },
    memory::address::EncryptionState,
    svm::{
        instructions::{NativeSvmInstruction, NativeSvmInstructions},
        protection,
        vmcb::Vmcb,
    },
};

struct FetchFixture {
    vmcb: Vmcb,
    tables: BTreeMap<u64, u64>,
    bytes: BTreeMap<u64, u8>,
}

impl FetchFixture {
    fn new(cpl: u8) -> Self {
        let mut vmcb = Vmcb::new();
        for (offset, value) in [
            (0x070, 0x4d),
            (0x0c8, u64::MAX),
            (0x410, (0xffff_ffffu64 << 32) | (0x29b << 16)),
            (0x4d0, 0x1d00),
            (0x548, 0x20),
            (0x550, 0x1000),
            (0x558, 0x8000_0011),
            (0x578, 0x4ffe),
        ] {
            put(&mut vmcb, offset, value);
        }
        // SAFETY: this test exclusively owns inert VMCB storage; CPL is one byte.
        unsafe { *ptr::from_mut(&mut vmcb).cast::<u8>().add(0x4cb) = cpl };
        Self {
            vmcb,
            tables: BTreeMap::from([
                (0x1000, 0x2007),
                (0x2000, 0x3007),
                (0x3000, 0x4007),
                (0x4020, 0x9007),
                (0x4028, 0xb007),
            ]),
            bytes: BTreeMap::from([(0x9ffe, 0x0f), (0x9fff, 0x01), (0xb000, 0xda)]),
        }
    }

    fn fetch(&self, index: usize, pat: u64) -> Result<u8, FetchError> {
        fetch::general_protection_byte(&self.vmcb, 48, pat, index, |address, width| {
            self.read(address, width)
        })
    }

    fn read(&self, address: u64, width: usize) -> Option<u64> {
        match width {
            8 => self.tables.get(&address).copied(),
            1 => self.bytes.get(&address).copied().map(u64::from),
            _ => panic!("unbounded physical read width"),
        }
    }
}

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: tests exclusively own inert VMCB storage; every offset is in bounds.
    unsafe {
        ptr::write_unaligned(ptr::from_mut(vmcb).cast::<u8>().add(offset).cast(), value);
    }
}

fn owner() -> NativeSvmInstructions {
    let capabilities: ValidatedCapabilities = CapabilityEvidence {
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
    .unwrap();
    NativeSvmInstructions::admit_native(&capabilities, 1 << 2, 0).unwrap()
}

#[test]
fn long64_cpl_zero_and_three_walk_noncontiguous_pages_without_advancing_state() {
    for cpl in [0, 3] {
        let mut fixture = FetchFixture::new(cpl);
        // Long64 instruction fetch ignores the legacy CS base and limit.
        put(&mut fixture.vmcb, 0x410, 0x29b << 16);
        put(&mut fixture.vmcb, 0x418, 0xdead_beef);
        let before = *fixture.vmcb.bytes();
        let mut instruction_reads = Vec::new();
        let result = protection::classify(&owner(), 0xd00, &fixture.vmcb, |index| {
            fetch::general_protection_byte(&fixture.vmcb, 48, 6, index, |address, width| {
                if width == 1 {
                    instruction_reads.push(address);
                }
                fixture.read(address, width)
            })
        });
        assert_eq!(result, Ok(Some(NativeSvmInstruction::Vmload)));
        assert_eq!(instruction_reads, [0x9ffe, 0x9fff, 0xb000]);
        assert_eq!(*fixture.vmcb.bytes(), before);
    }
}

#[test]
fn opcode_in_final_three_bytes_does_not_fetch_the_unmapped_next_page() {
    let mut fixture = FetchFixture::new(3);
    put(&mut fixture.vmcb, 0x578, 0x4ffd);
    fixture.tables.remove(&0x4028);
    fixture.bytes = BTreeMap::from([(0x9ffd, 0x0f), (0x9ffe, 0x01), (0x9fff, 0xda)]);
    let mut reads = Vec::new();
    let result = protection::classify(&owner(), 0xd00, &fixture.vmcb, |index| {
        fetch::general_protection_byte(&fixture.vmcb, 48, 6, index, |address, width| {
            reads.push((address, width));
            fixture.read(address, width)
        })
    });
    assert_eq!(result, Ok(Some(NativeSvmInstruction::Vmload)));
    assert_eq!(reads.len(), 15);
    assert!(!reads.contains(&(0x4028, 8)));
}

#[test]
fn compatibility_code_uses_cs_base_and_inclusive_limit_for_both_default_sizes() {
    for attributes in [0x9b, 0x49b] {
        for cpl in [0, 3] {
            let mut fixture = FetchFixture::new(cpl);
            put(&mut fixture.vmcb, 0x410, (0x1000 << 32) | (attributes << 16));
            put(&mut fixture.vmcb, 0x418, 0x4000);
            put(&mut fixture.vmcb, 0x578, 0xffe);
            let before = *fixture.vmcb.bytes();
            assert_eq!(fixture.fetch(0, 6), Ok(0x0f));
            assert_eq!(fixture.fetch(1, 6), Ok(0x01));
            assert_eq!(fixture.fetch(2, 6), Ok(0xda));
            assert_eq!(
                fetch::general_protection_byte(&fixture.vmcb, 48, 6, 3, |_, _| {
                    panic!("read beyond CS limit")
                }),
                Err(FetchError::SegmentLimit)
            );
            assert_eq!(*fixture.vmcb.bytes(), before);
        }
    }
}

#[test]
fn unpaged_protected_fetch_uses_byte_addresses_without_a_page_walk() {
    for attributes in [0x9b, 0x49b] {
        for cpl in [0, 3] {
            let mut fixture = FetchFixture::new(cpl);
            put(&mut fixture.vmcb, 0x410, (0x1000 << 32) | (attributes << 16));
            put(&mut fixture.vmcb, 0x418, 0x9000);
            put(&mut fixture.vmcb, 0x578, 0xffe);
            put(&mut fixture.vmcb, 0x558, 0x11);
            put(&mut fixture.vmcb, 0x4d0, 0x1100);
            let bytes = [0x0f, 0x01, 0xda];
            let mut reads = Vec::new();
            for index in 0..3 {
                let result = fetch::general_protection_byte(
                    &fixture.vmcb,
                    48,
                    0,
                    index,
                    |address, width| {
                        reads.push((address, width));
                        bytes.get((address - 0x9ffe) as usize).copied().map(u64::from)
                    },
                );
                assert_eq!(result, Ok(bytes[index]));
            }
            assert_eq!(reads, [(0x9ffe, 1), (0x9fff, 1), (0xa000, 1)]);
        }
    }
}

#[test]
fn unpaged_cache_disabled_and_unproved_linear_wrap_never_read_memory() {
    for (base, cr0, expected) in [
        (0, 0x4000_0011, FetchError::UnsupportedCacheControl),
        (0xffff_f001, 0x11, FetchError::AddressOverflow),
    ] {
        let mut fixture = FetchFixture::new(0);
        put(&mut fixture.vmcb, 0x410, (0xffffu64 << 32) | (0x9b << 16));
        put(&mut fixture.vmcb, 0x418, base);
        put(&mut fixture.vmcb, 0x578, 0x1000);
        put(&mut fixture.vmcb, 0x558, cr0);
        put(&mut fixture.vmcb, 0x4d0, 0x1100);
        assert_eq!(
            fetch::general_protection_byte(&fixture.vmcb, 48, 6, 0, |_, _| panic!("unproved read")),
            Err(expected)
        );
    }
}

#[test]
fn legacy_paging_and_vm86_are_explicitly_unsupported_before_any_read() {
    for (cr0, efer, flags) in
        [(0x8000_0011, 0x1100, 2), (0x11, 0x1100, 0x2_0002), (0x10, 0x1100, 2)]
    {
        let mut fixture = FetchFixture::new(0);
        put(&mut fixture.vmcb, 0x410, (0xffffu64 << 32) | (0x9b << 16));
        put(&mut fixture.vmcb, 0x558, cr0);
        put(&mut fixture.vmcb, 0x4d0, efer);
        put(&mut fixture.vmcb, 0x570, flags);
        assert_eq!(
            fetch::general_protection_byte(&fixture.vmcb, 48, 6, 0, |_, _| panic!(
                "unsupported read"
            )),
            Err(FetchError::UnsupportedMode)
        );
    }
}

#[test]
fn aggregate_user_permissions_nx_and_smep_precede_instruction_memory_reads() {
    for (address, _) in FetchFixture::new(3).tables.iter().take(4) {
        for (cpl, bit, expected) in
            [(3, 4, FetchError::PrivilegeMismatch), (0, 1 << 63, FetchError::NotExecutable)]
        {
            let mut fixture = FetchFixture::new(cpl);
            let entry = fixture.tables.get_mut(address).unwrap();
            if bit == 4 {
                *entry &= !bit;
            } else {
                *entry |= bit;
            }
            assert_eq!(
                fetch::general_protection_byte(&fixture.vmcb, 48, 6, 0, |address, width| {
                    assert_eq!(width, 8, "permission check read instruction memory");
                    fixture.read(address, width)
                }),
                Err(expected)
            );
        }
    }
    let mut fixture = FetchFixture::new(0);
    put(&mut fixture.vmcb, 0x548, 0x10_0020);
    assert_eq!(fixture.fetch(0, 6), Err(FetchError::PrivilegeMismatch));
    *fixture.tables.get_mut(&0x1000).unwrap() &= !4;
    assert_eq!(fixture.fetch(0, 6), Ok(0x0f));
}

#[test]
fn cache_controls_are_checked_before_instruction_bytes() {
    let mut fixture = FetchFixture::new(3);
    for pat in [0, 2] {
        assert_eq!(fixture.fetch(0, pat), Err(FetchError::UnsupportedCacheControl));
    }
    *fixture.tables.get_mut(&0x4020).unwrap() |= 0x80;
    assert_eq!(fixture.fetch(0, 6), Err(FetchError::NonWriteBackInstruction));
    *fixture.tables.get_mut(&0x4020).unwrap() &= !0x80;
    *fixture.tables.get_mut(&0x2000).unwrap() |= 0x10;
    assert_eq!(fixture.fetch(0, 6), Err(FetchError::UnsupportedCacheControl));
    put(&mut fixture.vmcb, 0x558, 0xc000_0011);
    assert_eq!(fixture.fetch(0, 6), Err(FetchError::UnsupportedCacheControl));
}

#[test]
fn byte_limit_wrong_exit_and_noncanonical_address_refuse_before_memory_read() {
    let mut fixture = FetchFixture::new(3);
    put(&mut fixture.vmcb, 0x578, 0x4ff0);
    assert_eq!(fixture.fetch(14, 6), Ok(0x0f));
    for index in [15, 16, usize::MAX] {
        assert_eq!(
            fetch::general_protection_byte(&fixture.vmcb, 48, 6, index, |_, _| panic!(
                "bound read"
            )),
            Err(FetchError::AddressOverflow)
        );
    }
    put(&mut fixture.vmcb, 0x578, 0x0000_8000_0000_0000);
    assert_eq!(
        fetch::general_protection_byte(&fixture.vmcb, 48, 6, 0, |_, _| panic!("noncanonical read")),
        Err(FetchError::Walk(WalkError::NoncanonicalAddress))
    );
    put(&mut fixture.vmcb, 0x070, 0x82);
    assert_eq!(
        fetch::general_protection_byte(&fixture.vmcb, 48, 6, 0, |_, _| panic!("wrong exit read")),
        Err(FetchError::UnsupportedExit)
    );
}

#[test]
fn absent_or_nonbyte_instruction_memory_preserves_stopped_state() {
    let fixture = FetchFixture::new(3);
    let before = *fixture.vmcb.bytes();
    for value in [None, Some(0x100)] {
        assert_eq!(
            fetch::general_protection_byte(&fixture.vmcb, 48, 6, 2, |address, width| {
                if width == 1 { value } else { fixture.read(address, width) }
            }),
            Err(FetchError::UnreadableInstruction { address: 0xb000 })
        );
    }
    assert_eq!(*fixture.vmcb.bytes(), before);
}
