use super::*;
use crate::host::resident::runtime::{INITIAL_STATE, exit::check_exit_event};
use crate::memory::npt::{TABLE_COUNT, TableStorage};

fn put(vmcb: &mut Vmcb, offset: usize, value: u64, bytes: usize) {
    // Inert exclusive test fixture; never used by hardware.
    unsafe {
        ptr::copy_nonoverlapping(
            value.to_le_bytes().as_ptr(),
            ptr::from_mut(vmcb).cast::<u8>().add(offset),
            bytes,
        )
    };
}

fn guest() -> Vmcb {
    let mut vmcb = Vmcb::new();
    vmcb.configure_native_boot_intercepts().unwrap();
    vmcb.configure_native_nmi_virtualization(1 << 25).unwrap();
    assert!(vmcb.configure_native_lbr(0x8000_0022, 2, 7, 0x2106));
    for (offset, value, bytes) in [
        (0x090, 1, 8),
        (0x058, 1, 4),
        (0x550, 0x1000, 8),
        (0x0b0, 0x2000, 8),
        (0x4cb, 3, 1),
        (0x4d0, 1 << 10, 8),
        (0x413, 2, 1),
        (0x578, 0x400000, 8),
        (0x570, 0x202, 8),
        (0x640, 0xaaaa, 8),
    ] {
        put(&mut vmcb, offset, value, bytes);
    }
    vmcb
}

fn active(vmcb: &mut Vmcb) -> Active {
    let address = ptr::from_mut(vmcb) as u64;
    Active {
        ticket: unsafe { Ticket::arm(vmcb, (1 << 25) | (1 << 17) | 1) }.unwrap(),
        sequence: 19,
        cpu: 3,
        vmcb: address,
    }
}

fn raw(active: &Active) -> RawVmexitCapture {
    let mut raw: RawVmexitCapture = unsafe { core::mem::zeroed() };
    raw.entry_sequence = active.sequence;
    raw.exit_sequence = active.sequence;
    raw.entry_vmcb_pa = active.vmcb;
    raw.exit_vmcb_pa = active.vmcb;
    raw.context_vmcb_pa = active.vmcb;
    // This assembly field is intentionally undefined on non-MSR exits.
    raw.physical_apic_id = u64::MAX;
    raw
}

#[test]
fn native_entry_trial_syscall_boundary_preserves_transition_and_restoration_flush() {
    let mut vmcb = guest();
    let active = active(&mut vmcb);
    assert!(!interrupt::validate_entry(&vmcb));
    put(&mut vmcb, 0x070, 0x400, 8);
    put(&mut vmcb, 0x078, (1 << 32) | 0x11, 8);
    put(&mut vmcb, 0x080, 0x12345000, 8);
    put(&mut vmcb, 0x4cb, 0, 1);
    put(&mut vmcb, 0x578, 0xffff800000001000, 8);
    let frame = GuestRegisters { rcx: 0x400002, r11: 0x202, r10: 0xabcd, ..Default::default() };
    let mut state = INITIAL_STATE;
    let mut record = Record::default();
    let proof = FetchEvidence {
        nested_root: 0x2000,
        guest_physical_address: 0x12345000,
        user_executable: true,
    };
    assert!(witness(&active, &raw(&active), 3));
    assert_eq!(
        unsafe {
            complete_owned(&mut state, &mut vmcb, &frame, &mut record, active, true, Some(proof))
        },
        Ok(GATED)
    );
    assert_eq!(vmcb.guest_rip(), 0xffff800000001000);
    assert_eq!(word(&vmcb, 0x640), 0xaaaa);
    assert_eq!(vmcb.event_injection(), 0);
    assert_eq!(record.exit_registers, frame);
    assert_eq!(vmcb.bytes()[0x05c], 1, "restoration flush must survive old-entry consumption");
    assert!(interrupt::validate_entry(&vmcb) && minimal::valid(&vmcb));
    assert_eq!(word(&vmcb, 0x090), 1);
}

#[test]
fn native_entry_trial_reflection_waits_for_the_next_actual_delivery() {
    let mut vmcb = guest();
    let active = active(&mut vmcb);
    put(&mut vmcb, 0x070, 0x4e, 8);
    put(&mut vmcb, 0x078, 4, 8);
    put(&mut vmcb, 0x080, 0xbbbb, 8);
    let mut state = INITIAL_STATE;
    let mut record = Record::default();
    assert_eq!(
        unsafe {
            complete_owned(
                &mut state,
                &mut vmcb,
                &GuestRegisters::default(),
                &mut record,
                active,
                true,
                None,
            )
        },
        Ok(REFLECTED)
    );
    assert!(state.pending_fault);
    assert_eq!(word(&vmcb, 0x640), 0xbbbb);
    assert_eq!(vmcb.guest_rip(), 0x400000);
    assert_eq!(vmcb.event_injection(), (4 << 32) | 0x80000b0e);
    // Only a subsequent hardware exit establishes completion. The outer adapter
    // skips native completion on the trial exit that just queued this injection.
    put(&mut vmcb, 0x070, 0x81, 8);
    put(&mut vmcb, 0x0a8, 0, 8); // #VMEXIT clears EVENTINJ on that later exit.
    assert!(check_exit_event(&mut state, &mut vmcb));
    assert!(!state.pending_fault);
}

#[test]
fn native_entry_trial_timer_interrupt_is_not_injected_or_acknowledged() {
    let mut vmcb = guest();
    let active = active(&mut vmcb);
    put(&mut vmcb, 0x070, 0x60, 8);
    let before = (vmcb.guest_rip(), word(&vmcb, 0x640));
    let mut state = INITIAL_STATE;
    let mut record = Record::default();
    assert_eq!(
        unsafe {
            complete_owned(
                &mut state,
                &mut vmcb,
                &GuestRegisters::default(),
                &mut record,
                active,
                true,
                None,
            )
        },
        Ok(INTERRUPTED)
    );
    assert_eq!((vmcb.guest_rip(), word(&vmcb, 0x640)), before);
    assert_eq!(vmcb.event_injection(), 0);
    assert!(!state.pending_fault);
    assert!(interrupt::validate_entry(&vmcb));
}

#[test]
fn native_entry_trial_nmi_returns_to_the_canonical_acknowledgment_path() {
    let mut vmcb = guest();
    let active = active(&mut vmcb);
    put(&mut vmcb, 0x070, 0x61, 8);
    let mut state = INITIAL_STATE;
    let mut record = Record::default();
    let registers = GuestRegisters { r12: 0x1234, ..Default::default() };
    assert_eq!(
        unsafe {
            complete_owned(&mut state, &mut vmcb, &registers, &mut record, active, true, None)
        },
        Ok(INTERRUPTED)
    );
    assert_eq!(record.exit_registers, registers);
    assert_eq!(vmcb.guest_rip(), 0x400000);
    assert_eq!(vmcb.event_injection(), 0);
    assert!(!vmcb.virtual_nmi_pending() && !vmcb.virtual_nmi_masked());
    assert!(!state.pending_fault);
    assert!(interrupt::validate_entry(&vmcb));
    // Only the subsequent physical host handler may acknowledge the source;
    // the outer dispatcher then transfers its pending indication to V_NMI.
}

#[test]
fn native_entry_trial_refuses_late_event_and_preserves_pending_request() {
    let mut vmcb = guest();
    // The real final boundary sees outer-dispatch NMI injection in canonical state.
    vmcb.queue_native_nmi().unwrap();
    let before = *vmcb.bytes();
    assert!(unsafe { Ticket::arm(&mut vmcb, (1 << 25) | (1 << 17) | 1) }.is_err());
    assert_eq!(*vmcb.bytes(), before);
    assert!(vmcb.virtual_nmi_pending());
    assert_eq!(vmcb.event_injection(), 0);
}

#[test]
fn native_entry_trial_poisoned_terminal_fields_never_become_evidence() {
    for code in [u64::MAX, 0xffff_ffff, 0x7f] {
        let mut vmcb = guest();
        let active = active(&mut vmcb);
        put(&mut vmcb, 0x070, code, 8);
        for offset in [0x078, 0x080, 0x088, 0x578, 0x640] {
            put(&mut vmcb, offset, u64::MAX, 8);
        }
        let mut state = INITIAL_STATE;
        let mut record = Record::default();
        assert!(
            unsafe {
                complete_owned(
                    &mut state,
                    &mut vmcb,
                    &GuestRegisters::default(),
                    &mut record,
                    active,
                    true,
                    None,
                )
            }
            .is_err()
        );
        assert!(state.stopped_valid);
        assert_eq!(state.stopped_rip, 0);
        assert_eq!(record.exit, [code, 0, 0, 0, 0, 0]);
        assert_eq!(word(&vmcb, 0x090), 1);
        assert!(interrupt::validate_entry(&vmcb));
    }
}

#[test]
fn native_entry_trial_rejects_replay_wrong_cpu_and_wrong_physical_vmcb() {
    let mut vmcb = guest();
    let active = active(&mut vmcb);
    let good = raw(&active);
    assert!(witness(&active, &good, 3));
    assert!(!witness(&active, &good, 4));
    for field in [0, 1, 2, 3, 4] {
        let mut bad = good;
        match field {
            0 => bad.entry_sequence -= 1,
            1 => bad.exit_sequence -= 1,
            2 => bad.entry_vmcb_pa += 4096,
            3 => bad.exit_vmcb_pa += 4096,
            _ => bad.context_vmcb_pa += 4096,
        }
        assert!(!witness(&active, &bad, 3));
    }
    let mut state = INITIAL_STATE;
    assert!(
        unsafe {
            complete_owned(
                &mut state,
                &mut vmcb,
                &GuestRegisters::default(),
                &mut Record::default(),
                active,
                false,
                None,
            )
        }
        .is_err()
    );
    assert_eq!(word(&vmcb, 0x090), 1);
    assert!(interrupt::validate_entry(&vmcb));
}

#[test]
fn native_entry_trial_timer_requires_an_unmaskable_by_user_finite_count() {
    let mut vmcb = guest();
    let timer = Timer { lvt: 0xd0, count: 100, initial: 200, ppr: 0, svr: 0x1ff };
    assert!(timer.valid(&vmcb));
    for lvt in [0x10, 0x100d0, 0x400d0, 0x600d0, 0x10000d0] {
        assert!(!Timer { lvt, ..timer }.valid(&vmcb));
    }
    for count in [0, 201] {
        assert!(!Timer { count, ..timer }.valid(&vmcb));
    }
    assert!(!Timer { ppr: 0xd0, ..timer }.valid(&vmcb));
    assert!(!Timer { svr: 0xff, ..timer }.valid(&vmcb));
    for flags in [2, 0x302, 0x3202, 0x1202] {
        put(&mut vmcb, 0x570, flags, 8);
        assert!(!timer.valid(&vmcb));
    }
    put(&mut vmcb, 0x570, 0x202, 8);
    put(&mut vmcb, 0x068, 1, 8);
    assert!(!timer.valid(&vmcb));
}

fn npt() -> TableStorage {
    let mut table = TableStorage([[0; 4096]; TABLE_COUNT]);
    table.0[0][..8].copy_from_slice(&0x101007u64.to_le_bytes());
    // Map the second GiB; the private pool in first GiB remains absent.
    table.0[1][8..16].copy_from_slice(&0x40000087u64.to_le_bytes());
    table
}

#[test]
fn native_entry_trial_npt_proof_checks_all_levels_and_never_follows_external_links() {
    let root = 0x100000;
    let pool = (root, 0x100000);
    let mut table = npt();
    assert!(validate_npt(&table.0, root, pool));
    assert!(executable(&table.0, root, 0x45678900));
    assert!(!executable(&table.0, root, 0x100000));
    for entry in [0x101003, 0x8000000000101007, 0x200007, 0x100007] {
        table.0[0][..8].copy_from_slice(&u64::to_le_bytes(entry));
        assert!(!validate_npt(&table.0, root, pool));
    }
    let mut table = npt();
    table.0[1][8..16].copy_from_slice(&0x8000000040000087u64.to_le_bytes());
    assert!(!validate_npt(&table.0, root, pool));
    assert!(!executable(&table.0, root, 0x45678900));
    let mut table = npt();
    table.0[1][..8].copy_from_slice(&0x87u64.to_le_bytes());
    assert!(!validate_npt(&table.0, root, pool), "monitor pool must remain absent");
}

#[test]
fn native_entry_trial_preserves_cache_selectors_at_all_leaf_sizes() {
    for level in [1, 2, 3] {
        let mut table = npt();
        if level < 3 {
            table.0[1][8..16].copy_from_slice(&0x102007u64.to_le_bytes());
        }
        if level == 1 {
            table.0[2][..8].copy_from_slice(&0x103007u64.to_le_bytes());
        }
        let slot = if level == 3 { 8 } else { 0 };
        let index = 4 - level as usize;
        let leaf = 0x40000000 | 0x9f | if level > 1 { 0x1000 } else { 0 };
        table.0[index][slot..slot + 8].copy_from_slice(&u64::to_le_bytes(leaf));
        assert!(validate_npt(&table.0, 0x100000, (0x100000, 0x100000)));
        assert!(executable(&table.0, 0x100000, 0x40000123));
        // NX is an execute denial even with the same physical/PAT encoding.
        table.0[index][slot..slot + 8].copy_from_slice(&(leaf | (1u64 << 63)).to_le_bytes());
        assert!(!validate_npt(&table.0, 0x100000, (0x100000, 0x100000)));
        assert!(!executable(&table.0, 0x100000, 0x40000123));
    }
}

#[test]
fn native_entry_trial_keeps_cache_quarantine_nonexecutable() {
    let mut table = npt();
    let quarantined = 0x4000149eu64;
    table.0[1][8..16].copy_from_slice(&quarantined.to_le_bytes());
    assert!(validate_npt(&table.0, 0x100000, (0x100000, 0x100000)));
    assert!(!executable(&table.0, 0x100000, 0x40000123));
    table.0[1][8..16].copy_from_slice(&(quarantined & !(1 << 10)).to_le_bytes());
    assert!(!validate_npt(&table.0, 0x100000, (0x100000, 0x100000)));
}

#[test]
fn native_entry_trial_audits_cache_tables_beyond_the_old_eight_page_arena() {
    let mut tables = [[0u8; 4096]; 9];
    tables[0][..8].copy_from_slice(&0x108007u64.to_le_bytes());
    tables[8][8..16].copy_from_slice(&0x4000109fu64.to_le_bytes());
    assert!(validate_npt(&tables, 0x100000, (0x100000, 0x100000)));
    assert!(executable(&tables, 0x100000, 0x45678900));
    tables[8][8..16].copy_from_slice(&0x100007u64.to_le_bytes());
    assert!(!validate_npt(&tables, 0x100000, (0x100000, 0x100000)));
}
