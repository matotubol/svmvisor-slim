use super::*;

use std::collections::BTreeMap;

const KERNEL_BASE: u64 = 0xffff_f800_0100_0000;
const CANDIDATE_ROOT: u64 = 0x1000;
const SYSTEM_ROOT: u64 = 0x3000;
const SYSTEM_OBJECT: u64 = KERNEL_BASE + 0x0180_0000;
const DEBUG_RVA: u32 = 0x1800;
const CODEVIEW_RVA: u32 = 0x2000;

struct ContextFixture {
    profile: KernelProfile,
    bytes: BTreeMap<u64, u8>,
    reads: usize,
}

impl ContextFixture {
    fn new() -> Self {
        let profile = KernelProfile::fixture();
        let identity = profile.identity();
        let mut header = [0u8; 512];
        header[..2].copy_from_slice(b"MZ");
        header[60..64].copy_from_slice(&0x80u32.to_le_bytes());
        header[0x80..0x84].copy_from_slice(b"PE\0\0");
        header[0x84..0x86].copy_from_slice(&identity.machine.to_le_bytes());
        header[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        header[0x88..0x8c].copy_from_slice(&identity.timestamp.to_le_bytes());
        header[0x94..0x96].copy_from_slice(&(OPTIONAL_BYTES as u16).to_le_bytes());
        let optional = &mut header[0x98..];
        optional[..2].copy_from_slice(&0x020bu16.to_le_bytes());
        optional[56..60].copy_from_slice(&identity.image_bytes.to_le_bytes());
        optional[60..64].copy_from_slice(&4096u32.to_le_bytes());
        optional[64..68].copy_from_slice(&identity.checksum.to_le_bytes());
        optional[108..112].copy_from_slice(&16u32.to_le_bytes());
        optional[160..164].copy_from_slice(&DEBUG_RVA.to_le_bytes());
        optional[164..168].copy_from_slice(&28u32.to_le_bytes());
        let section = &mut header[0x188..0x1b0];
        section[8..12].copy_from_slice(&(identity.image_bytes - 4096).to_le_bytes());
        section[12..16].copy_from_slice(&4096u32.to_le_bytes());
        section[36..40].copy_from_slice(&0x2000_0000u32.to_le_bytes());
        let mut debug = [0; 28];
        debug[12..16].copy_from_slice(&2u32.to_le_bytes());
        debug[16..20].copy_from_slice(&25u32.to_le_bytes());
        debug[20..24].copy_from_slice(&CODEVIEW_RVA.to_le_bytes());
        // An invalid file offset proves the mapped parser uses AddressOfRawData instead.
        debug[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut codeview = [0; 25];
        codeview[..4].copy_from_slice(b"RSDS");
        codeview[4..20].copy_from_slice(&identity.codeview_guid);
        codeview[20..24].copy_from_slice(&identity.codeview_age.to_le_bytes());
        let mut fixture = Self { profile, bytes: BTreeMap::new(), reads: 0 };
        let index = ((KERNEL_BASE >> 39) & 0x01ff) * 8;
        fixture.physical(CANDIDATE_ROOT + index, &0x2001u64.to_le_bytes());
        fixture.physical(SYSTEM_ROOT + index, &0x2001u64.to_le_bytes());
        let pdpt_index = ((KERNEL_BASE >> 30) & 0x01ff) * 8;
        fixture.physical(0x2000 + pdpt_index, &0x4000_0081u64.to_le_bytes());
        fixture.virtual_bytes(KERNEL_BASE, &header);
        fixture.virtual_bytes(KERNEL_BASE + u64::from(DEBUG_RVA), &debug);
        fixture.virtual_bytes(KERNEL_BASE + u64::from(CODEVIEW_RVA), &codeview);
        let layout = fixture.profile.process().layout();
        let head = fixture.head();
        let links = SYSTEM_OBJECT + u64::from(layout.active_links_offset);
        fixture.virtual_word(head, links);
        fixture.virtual_word(head + 8, links);
        fixture.virtual_word(links, head);
        fixture.virtual_word(links + 8, head);
        fixture.virtual_word(SYSTEM_OBJECT + u64::from(layout.pid_offset), 4);
        fixture.virtual_word(SYSTEM_OBJECT + u64::from(layout.directory_root_offset), SYSTEM_ROOT);
        fixture.virtual_word(SYSTEM_OBJECT + u64::from(layout.create_time_offset.unwrap()), 17);
        fixture.virtual_word(
            KERNEL_BASE + u64::from(fixture.profile.system_process_rva()),
            SYSTEM_OBJECT,
        );
        fixture
    }

    fn candidate(&self) -> ContextObservation {
        ContextObservation {
            config: PagingConfig::new(48, true, true).unwrap(),
            kernel_root_pa: CANDIDATE_ROOT,
            syscall_target_va: KERNEL_BASE + u64::from(self.profile.syscall_rvas()[0]),
        }
    }

    fn head(&self) -> u64 {
        KERNEL_BASE + u64::from(self.profile.list_head_rva())
    }

    fn physical(&mut self, address: u64, bytes: &[u8]) {
        for (index, byte) in bytes.iter().enumerate() {
            self.bytes.insert(address + index as u64, *byte);
        }
    }

    fn virtual_bytes(&mut self, address: u64, bytes: &[u8]) {
        self.physical(0x4000_0000 + (address & 0x3fff_ffff), bytes);
    }

    fn virtual_word(&mut self, address: u64, word: u64) {
        self.virtual_bytes(address, &word.to_le_bytes());
    }

    fn discover(&mut self, candidates: &[ContextObservation]) -> Result<ValidatedContext, String> {
        let profile = &self.profile;
        let bytes = &self.bytes;
        let reads = &mut self.reads;
        discover(profile, candidates, 4, &mut |address, output: &mut [u8]| {
            *reads += 1;
            for (index, byte) in output.iter_mut().enumerate() {
                *byte = bytes.get(&(address + index as u64)).copied().unwrap_or(0);
            }
            Ok(())
        })
    }
}

#[test]
fn validates_mapped_kernel_and_promotes_observed_system_root() {
    let mut fixture = ContextFixture::new();
    let context = fixture.discover(&[fixture.candidate()]).unwrap();
    assert_eq!(context.config(), fixture.candidate().config);
    assert_eq!(context.kernel_root_pa(), SYSTEM_ROOT);
    assert_eq!(context.list_head_va(), fixture.head());
    assert_eq!(context.kernel_base_va(), KERNEL_BASE);
    assert!(fixture.reads < 150);
}

#[test]
fn rejects_wrong_memory_identity_despite_matching_static_profile() {
    for address in [
        KERNEL_BASE,
        KERNEL_BASE + 0x84,
        KERNEL_BASE + 0x88,
        KERNEL_BASE + 0x98 + 56,
        KERNEL_BASE + 0x98 + 64,
        KERNEL_BASE + u64::from(CODEVIEW_RVA) + 4,
        KERNEL_BASE + u64::from(CODEVIEW_RVA) + 20,
    ] {
        let mut fixture = ContextFixture::new();
        let physical = 0x4000_0000 + (address & 0x3fff_ffff);
        *fixture.bytes.get_mut(&physical).unwrap() ^= 1;
        assert!(fixture.discover(&[fixture.candidate()]).is_err(), "address={address:x}");
    }
}

#[test]
fn refuses_symbol_pointer_list_and_system_root_disagreement() {
    for kind in 0..5 {
        let mut fixture = ContextFixture::new();
        let layout = fixture.profile.process().layout();
        match kind {
            0 => fixture.virtual_word(
                KERNEL_BASE + u64::from(fixture.profile.system_process_rva()),
                SYSTEM_OBJECT + 8,
            ),
            1 => fixture.virtual_word(SYSTEM_OBJECT + u64::from(layout.pid_offset), 5),
            2 => fixture.virtual_word(fixture.head() + 8, fixture.head()),
            3 => fixture.virtual_word(SYSTEM_OBJECT + u64::from(layout.directory_root_offset), 0),
            _ => fixture
                .virtual_word(SYSTEM_OBJECT + u64::from(layout.directory_root_offset), 0x5000),
        }
        assert!(fixture.discover(&[fixture.candidate()]).is_err(), "kind={kind}");
    }
}

#[test]
fn exact_anchor_and_candidate_limits_prevent_searches() {
    let mut fixture = ContextFixture::new();
    let mut candidate = fixture.candidate();
    candidate.syscall_target_va += 1;
    assert!(fixture.discover(&[candidate]).is_err());
    assert_eq!(fixture.reads, 0);
    candidate = fixture.candidate();
    assert!(fixture.discover(&[candidate; MAX_CANDIDATES + 1]).is_err());
    assert_eq!(fixture.reads, 0);
    candidate.kernel_root_pa = 0;
    assert!(fixture.discover(&[candidate]).is_err());
    assert_eq!(fixture.reads, 0);
}

#[test]
fn tries_only_supplied_roots_after_unmapped_candidate() {
    let mut fixture = ContextFixture::new();
    let valid = fixture.candidate();
    let unmapped = ContextObservation { kernel_root_pa: 0x5000, ..valid };
    assert_eq!(fixture.discover(&[unmapped, valid]).unwrap().kernel_root_pa(), SYSTEM_ROOT);
}

#[test]
fn backend_failure_stops_before_trying_another_candidate() {
    let fixture = ContextFixture::new();
    let candidate = fixture.candidate();
    let mut calls = 0;
    let error =
        discover(&fixture.profile, &[candidate, candidate], 4, &mut |_: u64, _: &mut [u8]| {
            calls += 1;
            Err(PagingError::PhysicalRead)
        })
        .unwrap_err();
    assert!(error.contains("stopped"));
    assert_eq!(calls, 1);
}

#[test]
fn rejects_unbounded_debug_metadata_before_following_it() {
    for (offset, value) in [(160, u32::MAX), (164, 28 * 65), (164, 29)] {
        let mut fixture = ContextFixture::new();
        fixture.virtual_bytes(KERNEL_BASE + 0x98 + offset, &value.to_le_bytes());
        assert!(fixture.discover(&[fixture.candidate()]).is_err());
        assert!(fixture.reads < 30);
    }
}

#[test]
fn rereads_kernel_identity_through_system_root() {
    let mut fixture = ContextFixture::new();
    let candidate = fixture.candidate();
    let index = ((KERNEL_BASE >> 39) & 0x01ff) * 8;
    fixture.physical(SYSTEM_ROOT + index, &0x4001u64.to_le_bytes());
    let pdpt_index = ((KERNEL_BASE >> 30) & 0x01ff) * 8;
    fixture.physical(0x4000 + pdpt_index, &0x8000_0081u64.to_le_bytes());
    assert!(fixture.discover(&[candidate]).is_err());
    assert!(fixture.reads > 20);
}

#[test]
fn kernel_identity_mutation_between_root_checks_never_publishes_context() {
    let fixture = ContextFixture::new();
    let candidate = fixture.candidate();
    let codeview = 0x4000_0000 + ((KERNEL_BASE + u64::from(CODEVIEW_RVA)) & 0x3fff_ffff);
    let mut observations = 0;
    let result = discover(&fixture.profile, &[candidate], 4, &mut |address, output: &mut [u8]| {
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = fixture.bytes.get(&(address + index as u64)).copied().unwrap_or(0);
        }
        if address == codeview {
            observations += 1;
            if observations == 2 {
                output[4] ^= 1;
            }
        }
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(observations, 2);
}

#[test]
fn rejects_duplicate_codeview_records_and_outside_record_extent() {
    for duplicate in [true, false] {
        let mut fixture = ContextFixture::new();
        if duplicate {
            fixture.virtual_bytes(KERNEL_BASE + 0x98 + 164, &56u32.to_le_bytes());
            let address = 0x4000_0000 + ((KERNEL_BASE + u64::from(DEBUG_RVA)) & 0x3fff_ffff);
            let entry: Vec<u8> = (0..28).map(|offset| fixture.bytes[&(address + offset)]).collect();
            fixture.virtual_bytes(KERNEL_BASE + u64::from(DEBUG_RVA) + 28, &entry);
        } else {
            let outside = fixture.profile.identity().image_bytes - 8;
            fixture.virtual_bytes(KERNEL_BASE + u64::from(DEBUG_RVA) + 20, &outside.to_le_bytes());
        }
        assert!(fixture.discover(&[fixture.candidate()]).is_err());
        assert!(fixture.reads < 30);
    }
}

#[test]
fn requires_anchor_inside_one_bounded_executable_section() {
    for (offset, value) in [(36, 0u32), (8, 4096), (8, u32::MAX)] {
        let mut fixture = ContextFixture::new();
        fixture.virtual_bytes(KERNEL_BASE + 0x188 + offset, &value.to_le_bytes());
        assert!(fixture.discover(&[fixture.candidate()]).is_err());
        assert!(fixture.reads < 30);
    }
}

#[test]
fn context_cr3_normalization_obeys_pcid_and_rejects_unsupported_modes() {
    let base = svmvisor_card_abi::context::ContextObservation {
        session: 1,
        boot: 7,
        exit_sequence: 10,
        cr3: 0x2018,
        cr4: 1 << 5,
        efer: 0xd01,
        lstar: 0xffff_f800_0010_0000,
        physical_bits: 48,
        cpu_slot: 3,
        page1gb: true,
    };
    assert_eq!(candidate(base).unwrap().kernel_root_pa, 0x2000);
    let mut pcid = base;
    pcid.cr4 |= 1 << 17;
    pcid.cr3 = 0x2fff;
    assert_eq!(candidate(pcid).unwrap().kernel_root_pa, 0x2000);
    for cr3 in [0, 0x2001, 1 << 48, 1 << 63] {
        assert!(candidate(svmvisor_card_abi::context::ContextObservation { cr3, ..base }).is_err());
    }
    for cr4 in [0, base.cr4 | (1 << 12), base.cr4 | (1 << 22)] {
        assert!(candidate(svmvisor_card_abi::context::ContextObservation { cr4, ..base }).is_err());
    }
    for efer in [0, 1 << 8, 1 << 10] {
        assert!(
            candidate(svmvisor_card_abi::context::ContextObservation { efer, ..base }).is_err()
        );
    }
    for lstar in [0, 0x1000, 0xffff_0000_0000_0000] {
        assert!(
            candidate(svmvisor_card_abi::context::ContextObservation { lstar, ..base }).is_err()
        );
    }
}
