use super::*;

const FEATURES: u32 = (1 << 17) | 1;
const FETCH: u64 = 1 | (1 << 4) | (1 << 32);

fn put(vmcb: &mut Vmcb, offset: usize, value: u64, size: usize) {
    vmcb.bytes[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
}

fn get(vmcb: &Vmcb, offset: usize) -> u64 {
    u64::from_le_bytes(vmcb.bytes[offset..offset + 8].try_into().unwrap())
}

fn canonical() -> Vmcb {
    let mut v = Vmcb::new();
    for (offset, value, size) in [
        (0x090, 1, 8),
        (0x058, 7, 4),
        (0x550, 0x1000, 8),
        (0x0b0, 0x2000, 8),
        (0x4cb, 3, 1),
        (0x4d0, 1 << 10, 8),
        (0x413, 2, 1),
        (0x578, 0x400000, 8),
        (0x5d8, 0x500000, 8),
        (0x640, 0xaaaa, 8),
        (0x0c0, u32::MAX as u64, 4),
        (0x00c, 0x90000000, 4),
        (0x010, 0x7f, 4),
    ] {
        put(&mut v, offset, value, size);
    }
    v
}

fn exit(v: &mut Vmcb, code: u64, info1: u64, info2: u64, cpl: u8) {
    put(v, 0x070, code, 8);
    put(v, 0x078, info1, 8);
    put(v, 0x080, info2, 8);
    put(v, 0x4cb, cpl.into(), 1);
}

fn issued(v: &mut Vmcb) -> Trial<'_> {
    let mut t = unsafe { Trial::begin(v, FEATURES) }.unwrap();
    // This is an inert synthetic-exit fixture; no hardware instruction is executed.
    unsafe { t.entry_pointer() }.unwrap();
    t
}

fn evidence() -> FetchEvidence {
    FetchEvidence { nested_root: 0x2000, guest_physical_address: 0x12345000, user_executable: true }
}

fn restored(v: &Vmcb) {
    assert_eq!(get(v, 0x090), 1);
    assert_eq!(&v.bytes[0x008..0x00c], &[0; 4]);
    assert_eq!(v.bytes[0x05c], 1);
    assert_eq!(&v.bytes[0x0c0..0x0c4], &[0; 4]);
}

#[test]
fn entry_trial_begin_refusal_is_byte_exact() {
    let mutations = [
        (0x4cb, 0, 1),
        (0x413, 0, 1),
        (0x4d0, 0, 8),
        (0x090, 0, 8),
        (0x090, 9, 8),
        (0x008, PF as u64, 4),
        (0x058, 0, 4),
        (0x060, 1, 8),
        (0x0a8, VALID | 0x202, 8),
        (0x088, VALID | 0x30e, 8),
    ];
    for (offset, value, size) in mutations {
        let mut v = canonical();
        put(&mut v, offset, value, size);
        let before = v.bytes;
        assert!(unsafe { Trial::begin(&mut v, FEATURES) }.is_err(), "offset {offset:x}");
        assert_eq!(v.bytes, before, "offset {offset:x}");
    }
    for features in [0, 1, 1 << 17] {
        let mut v = canonical();
        let before = v.bytes;
        assert!(unsafe { Trial::begin(&mut v, features) }.is_err());
        assert_eq!(v.bytes, before);
    }
}

#[test]
fn entry_trial_preserves_gp_interception_and_returns_delivery_fault_to_dispatch() {
    let mut v = canonical();
    put(&mut v, 0x008, 0x2000, 4);
    let t = issued(&mut v);
    assert_eq!(t.vmcb.read_u32::<EXCEPTIONS>(), 0x6000);
    exit(t.vmcb, 0x4d, 0x10, u64::MAX, 3);
    put(t.vmcb, 0x088, 0x8000_0306, 8);
    let saved = t.vmcb.bytes[0x400..].to_vec();
    assert_eq!(unsafe { t.finish(None) }, Ok(Outcome::GeneralProtectionIntercepted));
    assert_eq!(v.read_u32::<EXCEPTIONS>(), 0x2000);
    assert_eq!(get(&v, 0x090), 1);
    assert_eq!(get(&v, 0x0a8), 0);
    assert_eq!(get(&v, 0x088), 0x8000_0306);
    assert_eq!(&v.bytes[0x400..], saved);
}

#[test]
fn entry_trial_arming_changes_only_owned_controls_and_flush_metadata() {
    let mut v = canonical();
    let before = v.bytes;
    let t = issued(&mut v);
    assert_eq!(t.check_entry(), Ok(()));
    for (i, byte) in before.iter().enumerate() {
        if ![0x009, 0x090, 0x05c].contains(&i) && !(0x0c0..0x0c4).contains(&i) {
            assert_eq!(t.vmcb.bytes[i], *byte, "unexpected changed byte {i:x}");
        }
    }
    assert_eq!(get(t.vmcb, 0x090), 9);
    assert_eq!(t.vmcb.read_u32::<EXCEPTIONS>(), PF);
    drop(t);
    restored(&v);
}

#[test]
fn entry_trial_supervisor_fetch_preserves_post_exit_state_and_ignores_erratum_us() {
    for extra in [0, 1 << 2] {
        let mut v = canonical();
        let t = issued(&mut v);
        exit(t.vmcb, 0x400, FETCH | extra, 0x12345000, 0);
        for (offset, value) in [
            (0x578, 0xffff800000123000),
            (0x5d8, 0x87654321),
            (0x5f8, 0xfedcba98),
            (0x640, 0xaaaa),
            (0x570, 0x246),
        ] {
            put(t.vmcb, offset, value, 8);
        }
        let post_exit = t.vmcb.bytes;
        assert_eq!(unsafe { t.finish(Some(evidence())) }, Ok(Outcome::SupervisorFetchGated));
        restored(&v);
        assert_eq!(&v.bytes[0x400..], &post_exit[0x400..]);
        assert_eq!(v.event_injection(), 0);
    }
}

#[test]
fn entry_trial_real_pf_reflects_cr2_and_exact_error_without_advancing_rip() {
    for error in [4, 5] {
        let mut v = canonical();
        let t = issued(&mut v);
        exit(t.vmcb, 0x4e, error, 0xbbbb, 3);
        let old_rip = t.vmcb.guest_rip();
        assert_eq!(unsafe { t.finish(None) }, Ok(Outcome::PageFaultReflected));
        restored(&v);
        assert_eq!(get(&v, CR2), 0xbbbb);
        assert_eq!(v.guest_rip(), old_rip);
        assert_eq!(v.event_injection(), VALID | (3 << 8) | (1 << 11) | 14 | (error << 32));
    }
}

#[test]
fn entry_trial_rejects_wrong_pf_access_without_fault_mutation() {
    for (error, cpl) in [(0, 3), (6, 3), (0x14, 3), (0x44, 3), (4, 0)] {
        let mut v = canonical();
        let t = issued(&mut v);
        exit(t.vmcb, 0x4e, error, 0xbbbb, cpl);
        assert_eq!(unsafe { t.finish(None) }, Err(Error::UnsupportedExit));
        restored(&v);
        assert_eq!(get(&v, CR2), 0xaaaa);
        assert_eq!(v.event_injection(), 0);
    }
}

#[test]
fn entry_trial_poisoned_invalid_and_shutdown_restore_without_reflection() {
    for (code, expected) in [
        (u64::MAX, Error::InvalidEntry),
        (0xffff_ffff, Error::InvalidEntry),
        (0x7f, Error::Shutdown),
    ] {
        let mut v = canonical();
        let t = issued(&mut v);
        exit(t.vmcb, code, u64::MAX, u64::MAX, 0xff);
        for offset in [0x088, 0x0a8, 0x578, CR2] {
            put(t.vmcb, offset, u64::MAX, 8);
        }
        assert_eq!(unsafe { t.finish(None) }, Err(expected));
        restored(&v);
        for offset in [0x088, 0x0a8, 0x578, CR2] {
            assert_eq!(get(&v, offset), u64::MAX);
        }
    }
}

#[test]
fn entry_trial_late_event_guard_and_nested_delivery_refuse_without_clobbering() {
    for offset in [0x088, 0x0a8] {
        let mut v = canonical();
        let mut t = issued(&mut v);
        let event = VALID | (3 << 8) | (1 << 11) | 14;
        put(t.vmcb, offset, event, 8);
        assert_eq!(t.check_entry(), Err(Error::PendingEvent));
        assert_eq!(unsafe { t.entry_pointer() }.err(), Some(Error::EntryAlreadyIssued));
        exit(t.vmcb, 0x4e, 4, 0xbbbb, 3);
        assert_eq!(unsafe { t.finish(None) }, Err(Error::PendingEvent));
        restored(&v);
        assert_eq!(get(&v, offset), event);
        assert_eq!(get(&v, CR2), 0xaaaa);
    }
}

#[test]
fn entry_trial_wrong_fetch_kind_or_cpl_is_rejected() {
    for (info, cpl) in [
        (FETCH & !1, 0),
        (FETCH | 2, 0),
        (FETCH | 8, 0),
        (FETCH & !(1 << 4), 0),
        (FETCH & !(1 << 32), 0),
        (FETCH | (1 << 33), 0),
        (FETCH, 3),
        (FETCH, 1),
        (FETCH | (1 << 6), 0),
    ] {
        let mut v = canonical();
        let t = issued(&mut v);
        exit(t.vmcb, 0x400, info, 0x12345000, cpl);
        assert_eq!(
            unsafe { t.finish(Some(evidence())) },
            Err(Error::UnsupportedExit),
            "info {info:x}, CPL {cpl}"
        );
        restored(&v);
        assert_eq!(get(&v, CR2), 0xaaaa);
    }
}

#[test]
fn entry_trial_fetch_requires_matching_independent_evidence() {
    let p = evidence();
    for proof in [
        None,
        Some(FetchEvidence { nested_root: 0x3000, ..p }),
        Some(FetchEvidence { guest_physical_address: 0x12345008, ..p }),
        Some(FetchEvidence { user_executable: false, ..p }),
    ] {
        let mut v = canonical();
        let t = issued(&mut v);
        exit(t.vmcb, 0x400, FETCH, 0x12345000, 0);
        assert_eq!(unsafe { t.finish(proof) }, Err(Error::FetchEvidence));
        restored(&v);
    }
}

#[test]
fn entry_trial_control_drift_refuses_and_drop_does_not_hide_unowned_changes() {
    for (offset, value, size) in
        [(0x550, 0x9000, 8), (0x0b0, 0x9000, 8), (0x058, 8, 4), (0x00c, 1, 4), (0x014, 1, 4)]
    {
        let mut v = canonical();
        let t = issued(&mut v);
        put(t.vmcb, offset, value, size);
        assert_eq!(t.check_entry(), Err(Error::ControlDrift));
        exit(t.vmcb, 0x400, FETCH, 0x12345000, 0);
        assert_eq!(unsafe { t.finish(Some(evidence())) }, Err(Error::ControlDrift));
        restored(&v);
        assert_eq!(&v.bytes[offset..offset + size], &value.to_le_bytes()[..size]);
    }
    let mut v = canonical();
    let t = issued(&mut v);
    put(t.vmcb, NESTED_CONTROL, 9 | (1 << 6), 8);
    put(t.vmcb, EXCEPTIONS, (PF | 1) as u64, 4);
    drop(t);
    assert_eq!(get(&v, NESTED_CONTROL), 1 | (1 << 6));
    assert_eq!(v.read_u32::<EXCEPTIONS>(), 1);
    assert_eq!(v.bytes[0x05c], 1);
}

#[test]
fn entry_trial_unknown_exit_and_lost_flush_guard_never_authorize_entry() {
    let mut v = canonical();
    let t = issued(&mut v);
    t.vmcb.bytes[0x05c] = 0;
    assert_eq!(t.check_entry(), Err(Error::ControlDrift));
    exit(t.vmcb, 0x72, 0, 0, 3);
    assert_eq!(unsafe { t.finish(None) }, Err(Error::UnsupportedExit));
    restored(&v);
}

#[test]
fn entry_trial_finish_without_pointer_and_duplicate_pointer_are_refused() {
    let mut v = canonical();
    let t = unsafe { Trial::begin(&mut v, FEATURES) }.unwrap();
    assert_eq!(unsafe { t.finish(None) }, Err(Error::EntryNotIssued));
    restored(&v);
    let mut v = canonical();
    let mut t = issued(&mut v);
    assert_eq!(unsafe { t.entry_pointer() }.err(), Some(Error::EntryAlreadyIssued));
    drop(t);
    restored(&v);
}

#[test]
fn entry_trial_event_before_pointer_is_refused_by_final_guard() {
    let mut v = canonical();
    let mut t = unsafe { Trial::begin(&mut v, FEATURES) }.unwrap();
    put(t.vmcb, 0x0a8, VALID | 0x202, 8);
    assert_eq!(unsafe { t.entry_pointer() }.err(), Some(Error::PendingEvent));
    drop(t);
    restored(&v);
    assert_eq!(v.event_injection(), VALID | 0x202);
}
