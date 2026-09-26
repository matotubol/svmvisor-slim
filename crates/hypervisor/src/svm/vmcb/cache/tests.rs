use super::*;
use crate::{
    arch::x86_64::{
        capabilities::{CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures},
        descriptors::SegmentState,
    },
    memory::address::{AddressPolicy, EncryptionState},
    svm::vmcb::{EventIntercept, InstructionIntercept},
};

const CPU: u32 = 7;
const PA: u64 = 0x1234_5000;

fn clean(vmcb: &Vmcb) -> u32 {
    vmcb.read_u32::<0x0c0>()
}

// Synthetic ownership tests only: no privileged instruction is executed.
fn successful_entry(owner: &mut VmcbCacheOwner, vmcb: &mut Vmcb, cpu: u32, pa: u64) {
    owner.prepare_entry(vmcb, cpu, pa);
    vmcb.write_u64::<0x070>(0x7c);
    unsafe { owner.after_exit(vmcb, cpu, pa) };
}

fn policy() -> AddressPolicy {
    AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: None }).unwrap()
}

#[test]
fn first_entry_is_dirty_then_only_reviewed_groups_become_reusable() {
    let mut vmcb = Vmcb::new();
    let mut owner = VmcbCacheOwner::new();
    owner.configure(1 << 5);
    // Model a page returned by an allocator with stale clean bits.
    vmcb.set_clean_bits(u32::MAX);
    owner.prepare_entry(&mut vmcb, CPU, PA);
    assert_eq!(clean(&vmcb), 0);
    vmcb.write_u64::<0x070>(0x7c);
    unsafe { owner.after_exit(&mut vmcb, CPU, PA) };
    assert_eq!(clean(&vmcb), 0x03ff, "never claim unowned LBR/AVIC/CET or reserved groups");
    owner.prepare_entry(&mut vmcb, CPU, PA);
    assert_eq!(clean(&vmcb), 0x03ff);
}

#[test]
fn invalid_entry_shutdown_and_missing_entry_do_not_establish_cached_state() {
    for code in [u64::MAX, 0xffff_ffff, 0x7f] {
        let mut vmcb = Vmcb::new();
        let mut owner = VmcbCacheOwner::new();
        owner.configure(1 << 5);
        successful_entry(&mut owner, &mut vmcb, CPU, PA);
        owner.prepare_entry(&mut vmcb, CPU, PA);
        vmcb.write_u64::<0x070>(code);
        unsafe { owner.after_exit(&mut vmcb, CPU, PA) };
        assert_eq!(clean(&vmcb), 0, "exit {code:x}");
        owner.prepare_entry(&mut vmcb, CPU, PA);
        assert_eq!(clean(&vmcb), 0);
    }
    let mut vmcb = Vmcb::new();
    let mut owner = VmcbCacheOwner::new();
    owner.configure(1 << 5);
    vmcb.write_u64::<0x070>(0x7c);
    unsafe { owner.after_exit(&mut vmcb, CPU, PA) };
    assert_eq!(clean(&vmcb), 0);
    successful_entry(&mut owner, &mut vmcb, CPU, PA);
    vmcb.set_instruction_intercept(InstructionIntercept::Cpuid, true);
    unsafe { owner.after_exit(&mut vmcb, CPU, PA) };
    assert_eq!(clean(&vmcb), 0, "duplicate completion must not erase a new dirty group");
}

#[test]
fn migration_relocation_reuse_and_mismatched_returns_invalidate() {
    for (next_cpu, next_pa) in [(CPU + 1, PA), (CPU, PA + 4096)] {
        let mut vmcb = Vmcb::new();
        let mut owner = VmcbCacheOwner::new();
        owner.configure(1 << 5);
        successful_entry(&mut owner, &mut vmcb, CPU, PA);
        owner.prepare_entry(&mut vmcb, next_cpu, next_pa);
        assert_eq!(clean(&vmcb), 0);
        unsafe { owner.after_exit(&mut vmcb, next_cpu, next_pa) };
        assert_eq!(clean(&vmcb), 0x03ff);
        owner.prepare_entry(&mut vmcb, next_cpu, next_pa);
        unsafe { owner.after_exit(&mut vmcb, next_cpu + 1, next_pa) };
        assert_eq!(clean(&vmcb), 0);
    }
    let mut vmcb = Vmcb::new();
    let mut other = Vmcb::new();
    let mut owner = VmcbCacheOwner::new();
    owner.configure(1 << 5);
    successful_entry(&mut owner, &mut vmcb, CPU, PA);
    other.set_clean_bits(u32::MAX);
    owner.prepare_entry(&mut other, CPU, PA);
    assert_eq!(clean(&other), 0, "different storage cannot inherit the earlier page's proof");
    unsafe { owner.after_exit(&mut other, CPU, PA) };
    owner.invalidate(&mut other);
    assert_eq!(clean(&other), 0);
    owner.prepare_entry(&mut other, CPU, PA);
    assert_eq!(clean(&other), 0, "explicit logical-guest reuse is a first entry");
}

#[test]
fn unsupported_or_reconfigured_cpu_and_bad_addresses_stay_dirty() {
    let mut vmcb = Vmcb::new();
    let mut owner = VmcbCacheOwner::new();
    for features in [0, !(1 << 5)] {
        owner.configure(features);
        successful_entry(&mut owner, &mut vmcb, CPU, PA);
        assert_eq!(clean(&vmcb), 0);
    }
    owner.configure(1 << 5);
    successful_entry(&mut owner, &mut vmcb, CPU, PA);
    owner.configure(1 << 5);
    owner.prepare_entry(&mut vmcb, CPU, PA);
    assert_eq!(clean(&vmcb), 0);
    for pa in [0, PA + 1] {
        successful_entry(&mut owner, &mut vmcb, CPU, PA);
        owner.prepare_entry(&mut vmcb, CPU, pa);
        assert_eq!(clean(&vmcb), 0);
        unsafe { owner.after_exit(&mut vmcb, CPU, pa) };
        assert_eq!(clean(&vmcb), 0);
    }
}

#[test]
fn host_mutations_survive_final_entry_preparation_and_next_success_resets_dirty_groups() {
    let mut vmcb = Vmcb::new();
    let mut owner = VmcbCacheOwner::new();
    owner.configure(1 << 5);
    successful_entry(&mut owner, &mut vmcb, CPU, PA);
    vmcb.set_instruction_intercept(InstructionIntercept::Msr, true);
    vmcb.set_event_intercept(EventIntercept::Init, true);
    vmcb.set_nested_root(0x8000, &policy()).unwrap();
    vmcb.permission_maps_changed();
    let expected = 0x03ff & !((1 << 0) | (1 << 1) | (1 << 4));
    owner.prepare_entry(&mut vmcb, CPU, PA);
    assert_eq!(clean(&vmcb), expected);
    // Guest CR3 changed natively while running; hardware updates its cache.
    vmcb.bytes[0x550..0x558].copy_from_slice(&0x9000u64.to_le_bytes());
    unsafe { owner.after_exit(&mut vmcb, CPU, PA) };
    assert_eq!(clean(&vmcb), 0x03ff);
    assert_eq!(vmcb.guest_cr3(), 0x9000);
}

#[test]
fn every_cached_field_family_invalidates_its_architectural_group() {
    let mut vmcb = Vmcb::new();
    // Expected bit numbers are from APM2 p589 Figure15-4, independent of the classifier.
    let cases: &[(&str, fn(&mut Vmcb), u32)] = &[
        ("CR intercept", |v| v.write_u32::<0x000>(1), 0),
        ("exception intercept", |v| v.write_u32::<0x008>(1), 0),
        ("TSC offset", |v| v.write_u64::<0x050>(1), 0),
        ("PAUSE budget", |v| v.write_u16::<0x03e>(1), 0),
        ("IOPM", |v| v.write_u64::<0x040>(0x1000), 1),
        ("MSRPM", |v| v.write_u64::<0x048>(0x2000), 1),
        ("ASID", |v| v.write_u32::<0x058>(2), 2),
        ("virtual interrupts", |v| v.write_u64::<0x060>(3), 3),
        ("nested CR3", |v| v.write_u64::<0x0b0>(0x3000), 4),
        ("guest PAT", |v| v.write_u64::<0x668>(6), 4),
        ("EFER", |v| v.write_u64::<0x4d0>(0x1000), 5),
        ("CR4", |v| v.write_u64::<0x548>(0x20), 5),
        ("CR3", |v| v.write_u64::<0x550>(0x4000), 5),
        ("CR0", |v| v.write_u64::<0x558>(0x10), 5),
        ("DR7", |v| v.write_u64::<0x560>(0x400), 6),
        ("DR6", |v| v.write_u64::<0x568>(0xffff0ff0), 6),
        ("GDTR", |v| v.write_u64::<0x468>(0x5000), 7),
        ("IDTR", |v| v.write_u64::<0x488>(0x6000), 7),
        ("CS", |v| v.write_u16::<0x410>(8), 8),
        ("DS", |v| v.write_u16::<0x430>(16), 8),
        ("CR2", |v| v.write_u64::<0x640>(0x7000), 9),
    ];
    for &(name, mutate, bit) in cases {
        vmcb.set_clean_bits(0x03ff);
        mutate(&mut vmcb);
        assert_eq!(clean(&vmcb), 0x03ff & !(1 << bit), "{name}");
    }
    vmcb.set_clean_bits(0x03ff);
    vmcb.write_segment::<0x410>(SegmentState {
        selector: 8,
        attributes: 0x9b,
        limit: 0xffff,
        base: 0,
    });
    assert_eq!(clean(&vmcb), 0x03ff & !(1 << 8));
}

#[test]
fn public_asid_and_map_changes_dirty_groups_while_failed_setters_leave_cache_intact() {
    let capabilities = CapabilityEvidence {
        vendor: CpuVendor::Amd,
        svm: EvidenceFlag::Set,
        nested_paging: EvidenceFlag::Set,
        svm_revision: Some(1),
        asid_count: Some(8),
        physical_address_bits: Some(48),
        vm_cr_svmdis: EvidenceFlag::Clear,
        hypervisor_present: EvidenceFlag::Clear,
        encryption: EncryptionState::Unencrypted { encryption_bit: None },
        optional: OptionalFeatures::default(),
    }
    .validate()
    .unwrap();
    let mut vmcb = Vmcb::new();
    vmcb.set_clean_bits(0x03ff);
    vmcb.set_guest_asid(2, &capabilities).unwrap();
    assert_eq!(clean(&vmcb), 0x03ff & !(1 << 2));
    assert_eq!(vmcb.bytes[0x05c], 1);
    vmcb.set_clean_bits(0x03ff);
    vmcb.set_permission_maps(0x1000, 0x4000, &policy()).unwrap();
    assert_eq!(clean(&vmcb), 0x03ff & !(1 << 1));
    vmcb.set_clean_bits(0x03ff);
    let before = vmcb.bytes;
    assert!(vmcb.set_guest_asid(0, &capabilities).is_err());
    assert!(vmcb.set_permission_maps(0x1001, 0x4000, &policy()).is_err());
    assert!(vmcb.set_nested_root(0x1001, &policy()).is_err());
    assert_eq!(vmcb.bytes, before);
    // Mutating bits inside an existing bitmap must still invalidate group 1.
    vmcb.permission_maps_changed();
    assert_eq!(clean(&vmcb), 0x03ff & !(1 << 1));
}

#[test]
fn uncached_instruction_event_and_tlb_changes_keep_cached_groups() {
    let mut vmcb = Vmcb::new();
    vmcb.write_u64::<0x070>(0x7c);
    vmcb.set_clean_bits(0x03ff);
    vmcb.set_guest_rax(42);
    vmcb.write_u64::<0x578>(0x1000);
    vmcb.write_u64::<0x5d8>(0x2000);
    vmcb.complete_native_instruction_state();
    vmcb.queue_native_general_protection().unwrap();
    assert_eq!(vmcb.event_injection(), 0x8000_0b0d);
    assert_eq!(clean(&vmcb), 0x03ff);
    vmcb.clear_event_injection_after_exit().unwrap();
    vmcb.request_full_tlb_flush();
    assert_eq!(clean(&vmcb), 0x03ff);
    unsafe { vmcb.consume_tlb_flush_after_exit() };
    assert_eq!(vmcb.bytes[0x05c], 0);
    assert_eq!(clean(&vmcb), 0x03ff);
}

#[test]
fn vmload_auxiliary_state_is_separate_but_unknown_writes_and_init_are_cold() {
    let mut vmcb = Vmcb::new();
    vmcb.set_clean_bits(0x03ff);
    vmcb.write_u64::<0x608>(0xffff_8000_0000_1000); // LSTAR.
    vmcb.write_segment::<0x490>(SegmentState {
        selector: 0x40,
        attributes: 0x8b,
        limit: 0x67,
        base: 0x4000,
    });
    assert_eq!(clean(&vmcb), 0x03ff);
    vmcb.write_u64::<0x090>(1); // Nested feature controls not assigned a documented group.
    assert_eq!(clean(&vmcb), 0);
    vmcb.set_clean_bits(0x03ff);
    vmcb.initialize_ap_after_init();
    assert_eq!(clean(&vmcb), 0);
    vmcb.set_clean_bits(0x03ff);
    vmcb.start_ap_from_sipi(8);
    assert_eq!(clean(&vmcb), 0x03ff & !(1 << 8));
    assert_eq!(vmcb.guest_rip(), 0);
}
