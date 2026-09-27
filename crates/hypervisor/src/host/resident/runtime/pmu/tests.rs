use super::*;

use crate::{
    arch::x86_64::capabilities::{
        CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures, ValidatedCapabilities,
    },
    host::resident::runtime::INITIAL_STATE,
    memory::address::EncryptionState,
    svm::{
        dispatch::{self, NativeEfer, NativeMsrOutcome},
        pmu::PmuEvidence,
        startup::{NativeStartupCommand, NativeStartupEffect, NativeStartupTarget},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MockPmu {
    controls: [u64; 6],
    counters: [u64; 6],
    globals: [u64; 4],
    reads: usize,
    writes: usize,
}

impl MockPmu {
    fn new(controls: [u64; 6]) -> Self {
        Self {
            controls,
            counters: [1, 0x1234, 0x0000_ffff_ffff_fffe, 0xabcd, 7, 0x6789],
            globals: [0x1234, 0x35, 0x5678, 0xabcd],
            reads: 0,
            writes: 0,
        }
    }
}

impl PmuHardware for MockPmu {
    fn read(&mut self, msr: u32) -> u64 {
        assert!((0xc001_0200..=0xc001_020a).contains(&msr) && msr & 1 == 0);
        self.reads += 1;
        self.controls[((msr - 0xc001_0200) / 2) as usize]
    }

    fn write(&mut self, msr: u32, value: u64) {
        assert!((0xc001_0200..=0xc001_020a).contains(&msr) && msr & 1 == 0);
        self.writes += 1;
        self.controls[((msr - 0xc001_0200) / 2) as usize] = value;
    }
}

fn profile() -> PmuProfile {
    PmuProfile::admit(PmuEvidence {
        signature: 0x00b4_0f40,
        extended01_ecx: 1 << 23,
        extended21_eax: 1 << 12,
        extended22_eax: 1,
        extended22_ebx: 6,
    })
    .unwrap()
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

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: tests own an inert VMCB; every supplied qword offset is in bounds.
    unsafe { ptr::from_mut(vmcb).cast::<u8>().add(offset).cast::<u64>().write_unaligned(value) };
}

fn fixture(controls: [u64; 6]) -> (State, Vmcb, GuestRegisters, MockPmu) {
    let mut state = INITIAL_STATE;
    state.armed = true;
    state.capabilities = Some(caps());
    state.efer = Some(
        NativeEfer::admit_native_visible_svm(
            0x500,
            1 << 2,
            (1 << 11) | (1 << 20) | (1 << 29),
            1 << 20,
            None,
        )
        .unwrap(),
    );
    state.pmu = Some(PmuRuntime::new(profile()));
    let mut vmcb = Vmcb::new();
    for (offset, value) in [
        (0x060, 6),
        (0x068, 1),
        (0x070, 0x7c),
        (0x078, 1),
        (0x090, 1),
        (0x0c8, 0x4002),
        (0x410, 0x29b << 16),
        (0x4d0, 0x1500),
        (0x548, 0x20),
        (0x550, 0xfeed_0000),
        (0x558, 0x8000_0011),
        (0x570, 0x10202),
        (0x578, 0x4000),
    ] {
        put(&mut vmcb, offset, value);
    }
    vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
    let frame = GuestRegisters { rcx: 0xc001_0200, ..GuestRegisters::default() };
    let mut hardware = MockPmu::new(controls);
    assert!(initialize(&mut state, &vmcb, &mut hardware));
    (state, vmcb, frame, hardware)
}

fn operand(vmcb: &mut Vmcb, frame: &mut GuestRegisters, msr: u32, value: u64) {
    let next = vmcb.guest_rip() + 2;
    frame.rcx = 0xaaaa_bbbb_0000_0000 | u64::from(msr);
    frame.rdx = 0xcccc_dddd_0000_0000 | (value >> 32);
    put(vmcb, 0x5f8, 0xeeee_ffff_0000_0000 | u64::from(value as u32));
    put(vmcb, 0x078, 1);
    put(vmcb, 0x0c8, next);
}

#[test]
fn first_capture_preserves_firmware_state_and_cannot_be_repeated() {
    let controls = [0x43_00c0, 0x100_0043_00c0, 0xa00_0043_00c0, 0x300_0043_00c0, 0, 0];
    let (mut state, vmcb, _, mut hardware) = fixture(controls);
    assert_eq!(hardware.reads, 6);
    assert_eq!(hardware.controls[0], 0x100_0043_00c0);
    for index in 1..=3 {
        assert_eq!(hardware.controls[index] & (1 << 22), 0);
    }
    assert_eq!(
        state.pmu.as_ref().unwrap().owner.as_ref().unwrap().read(0xc001_0204),
        Some(controls[2])
    );
    let before = hardware;
    assert!(!initialize(&mut state, &vmcb, &mut hardware));
    assert_eq!(hardware, before);
    assert!(synchronize(&mut state, &vmcb, &mut hardware));
    assert_eq!(hardware, before);
    assert_eq!(hardware.counters, MockPmu::new(controls).counters);
    assert_eq!(hardware.globals, MockPmu::new(controls).globals);
}

#[test]
fn all_modern_selectors_and_legacy_aliases_share_readback_without_counter_access() {
    for index in 0..6 {
        for legacy in [false, true] {
            if legacy && index >= 4 {
                continue;
            }
            let (mut state, mut vmcb, mut frame, mut hardware) = fixture([0; 6]);
            let before = hardware;
            let msr = if legacy { 0xc001_0000 + index } else { 0xc001_0200 + 2 * index };
            let value = 0x300_0043_00c0 | if index == 2 { 1 << 43 } else { 0 };
            operand(&mut vmcb, &mut frame, msr, value);
            // SAFETY: inert stopped fixture takes the nRIP path; all hardware is mocked.
            assert_eq!(
                unsafe { handle_access(&mut state, &mut vmcb, &mut frame, &mut hardware) },
                Some(true)
            );
            assert_eq!(vmcb.guest_rip(), 0x4002);
            assert_eq!(hardware.controls[index as usize] & (1 << 22), 0);
            assert_eq!(hardware.reads, before.reads);
            assert_eq!((hardware.counters, hardware.globals), (before.counters, before.globals));

            frame.rcx = u64::from(0xc001_0200 + 2 * index);
            put(&mut vmcb, 0x078, 0);
            put(&mut vmcb, 0x0c8, 0x4004);
            let before = hardware;
            // SAFETY: same inert nRIP fixture, with all physical accesses mocked.
            assert_eq!(
                unsafe { handle_access(&mut state, &mut vmcb, &mut frame, &mut hardware) },
                Some(true)
            );
            assert_eq!(vmcb.guest_rax(), value & 0xffff_ffff);
            assert_eq!(frame.rdx, value >> 32);
            assert_eq!(hardware, before);
        }
    }
}

#[test]
fn repeated_guest_writes_reach_hardware_but_repeated_entry_refreshes_do_not() {
    let (mut state, mut vmcb, mut frame, mut hardware) = fixture([0; 6]);
    for _ in 0..2 {
        operand(&mut vmcb, &mut frame, 0xc001_0200, 0x43_00c0);
        let writes = hardware.writes;
        // SAFETY: the inert stopped fixture uses nRIP and a hardware trait double.
        assert_eq!(
            unsafe { handle_access(&mut state, &mut vmcb, &mut frame, &mut hardware) },
            Some(true)
        );
        assert_eq!(hardware.writes, writes + 1);
        let before = hardware;
        assert!(synchronize(&mut state, &vmcb, &mut hardware));
        assert_eq!(hardware, before);
    }
}

#[test]
fn invalid_boundaries_and_reserved_requests_do_not_mutate_selectors_or_guest() {
    for (offset, value) in [
        (0x070, 0x72),
        (0x078, 2),
        (0x4c8, 3 << 24),
        (0x060, 1 << 11),
        (0x0a8, 0x8000_0051),
        (0x088, 0x8000_0051),
        (0x570, 0x10302),
        (0x0c8, 0x4000),
        (0x4d0, 0x1501),
    ] {
        let (mut state, mut vmcb, mut frame, mut hardware) = fixture([0; 6]);
        operand(&mut vmcb, &mut frame, 0xc001_0200, 0x43_00c0);
        put(&mut vmcb, offset, value);
        let before = (state.pmu, *vmcb.bytes(), frame, hardware);
        // SAFETY: malformed inert nRIP fixtures are rejected before physical access.
        assert_eq!(
            unsafe { handle_access(&mut state, &mut vmcb, &mut frame, &mut hardware) },
            Some(false)
        );
        assert_eq!((state.pmu, *vmcb.bytes(), frame, hardware), before);
        assert!(state.stopped_valid);
    }
    for value in [1 << 63, 1 << 43, 1 << 31] {
        let (mut state, mut vmcb, mut frame, mut hardware) = fixture([0; 6]);
        operand(&mut vmcb, &mut frame, 0xc001_0200, value);
        let before = (state.pmu, *vmcb.bytes(), frame, hardware);
        // SAFETY: inert stopped fixture with a trait double for all hardware effects.
        assert_eq!(
            unsafe { handle_access(&mut state, &mut vmcb, &mut frame, &mut hardware) },
            Some(false)
        );
        assert_eq!((state.pmu, *vmcb.bytes(), frame, hardware), before);
        assert_eq!(vmcb.event_injection(), 0);
    }
}

#[test]
fn logical_efer_writes_in_both_decoders_resynchronize_and_faults_change_nothing() {
    for nrip in [false, true] {
        let controls = [0x200_0043_00c0, 0x100_0043_00c0, 0x300_0043_00c0, 0x43_00c0, 0, 0];
        let (mut state, mut vmcb, mut frame, mut hardware) = fixture(controls);
        let counters = hardware.counters;
        for (value, enabled) in
            [(0x1500, [true, false, true, true]), (0x500, [false, false, false, true])]
        {
            operand(&mut vmcb, &mut frame, 0xc000_0080, value);
            let owner = state.efer.as_mut().unwrap();
            let outcome = if nrip {
                dispatch::handle_native_efer_with_nrip(owner, &mut vmcb, &mut frame, &caps())
            } else {
                dispatch::handle_native_efer(owner, &mut vmcb, &mut frame, &[0x0f, 0x30])
            };
            assert_eq!(outcome, Ok(NativeMsrOutcome::Completed));
            assert!(synchronize(&mut state, &vmcb, &mut hardware));
            for (index, expected) in enabled.into_iter().enumerate() {
                assert_eq!(hardware.controls[index] & (1 << 22) != 0, expected);
            }
            assert_eq!(hardware.counters, counters);
        }
        operand(&mut vmcb, &mut frame, 0xc000_0080, 0x400);
        let before = (state.pmu, hardware);
        let owner = state.efer.as_mut().unwrap();
        let outcome = if nrip {
            dispatch::handle_native_efer_with_nrip(owner, &mut vmcb, &mut frame, &caps())
        } else {
            dispatch::handle_native_efer(owner, &mut vmcb, &mut frame, &[0x0f, 0x30])
        };
        assert_eq!(outcome, Ok(NativeMsrOutcome::GeneralProtectionPrepared));
        assert!(synchronize(&mut state, &vmcb, &mut hardware));
        assert_eq!((state.pmu, hardware), before);
    }
}

#[test]
fn committed_init_changes_filtering_without_resetting_counter_or_selector_state() {
    let controls = [0x200_0043_00c0; 6];
    let (mut state, mut vmcb, mut frame, mut hardware) = fixture(controls);
    operand(&mut vmcb, &mut frame, 0xc000_0080, 0x1500);
    assert_eq!(
        dispatch::handle_native_efer(
            state.efer.as_mut().unwrap(),
            &mut vmcb,
            &mut frame,
            &[0x0f, 0x30]
        ),
        Ok(NativeMsrOutcome::Completed)
    );
    assert!(synchronize(&mut state, &vmcb, &mut hardware));
    assert!(hardware.controls.iter().all(|value| value & (1 << 22) != 0));
    let owner = state.pmu.as_ref().unwrap().owner;
    let counters = hardware.counters;
    state.efer.as_mut().unwrap().enable_guest_startup();
    state.efer.as_mut().unwrap().reset_after_init().unwrap();
    assert_eq!(
        (NativeStartupTarget {
            vmcb: &mut vmcb,
            frame: &mut frame,
            state: &mut state.startup,
            signature: 0x00b4_0f40,
        })
        .apply(NativeStartupCommand::Init),
        Ok(NativeStartupEffect::Init)
    );
    assert!(synchronize(&mut state, &vmcb, &mut hardware));
    assert!(hardware.controls.iter().all(|value| value & (1 << 22) == 0));
    assert_eq!(state.pmu.as_ref().unwrap().owner, owner);
    assert_eq!(hardware.counters, counters);
}
