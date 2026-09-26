use super::*;

use svmvisor_card_abi::batch::{BatchRange, BindingEvidence, MAX_RANGES};

use crate::{
    arch::x86_64::capabilities::{CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures},
    host::resident::runtime::INITIAL_STATE,
    memory::address::EncryptionState,
};

fn put(vmcb: &mut Vmcb, offset: usize, value: u64) {
    // SAFETY: these fixtures exclusively own an inert VMCB and use in-bounds fields.
    unsafe {
        ptr::from_mut(vmcb).cast::<u8>().add(offset).cast::<u64>().write_unaligned(value);
    }
}

fn probe(nrip: bool) -> (State, Vmcb, GuestRegisters) {
    let mut state = INITIAL_STATE;
    state.capabilities = Some(
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
            optional: OptionalFeatures { nrip_save: nrip, ..Default::default() },
        }
        .validate()
        .unwrap(),
    );
    let mut vmcb = Vmcb::new();
    for (offset, value) in [
        (0x070, 0x81u64),
        (0x0c8, 0x2003),
        (0x410, 0x2fb << 16),
        (0x4c8, 3 << 24),
        (0x4d0, 0x1500),
        (0x548, 0x20),
        (0x558, 0x8000_0001),
        (0x570, 2),
        (0x578, 0x2000),
        (0x5f8, protocol::MAGIC),
    ] {
        // SAFETY: exclusively owned inert VMCB with complete in-bounds field writes.
        unsafe {
            ptr::from_mut(&mut vmcb).cast::<u8>().add(offset).cast::<u64>().write_unaligned(value);
        }
    }
    (state, vmcb, GuestRegisters { rcx: protocol::PROBE, ..Default::default() })
}

fn hello(session: u64, sequence: u64) -> BatchRequest {
    BatchRequest {
        operation: Operation::Hello,
        session,
        boot: 0,
        sequence,
        token: 0,
        count: 0,
        ranges: [BatchRange::EMPTY; MAX_RANGES],
        binding: BindingEvidence::EMPTY,
    }
}

fn registers(session: u64) -> GuestRegisters {
    GuestRegisters {
        rdx: 0x1000,
        r8: 0x3000,
        r9: MAX_RESPONSE_BYTES as u64,
        r10: session,
        ..GuestRegisters::default()
    }
}

#[test]
fn decoded_probe_preserves_abi_without_guest_memory_or_session() {
    let (mut state, mut vmcb, mut frame) = probe(true);
    // SAFETY: the NRIPS Probe path completes over inert state with no memory adapter,
    // privileged operation or LOCAL access. No real guest execution is claimed.
    assert!(unsafe { handle(&mut state, &mut vmcb, &mut frame) });
    assert_eq!(vmcb.guest_rax(), protocol::COMPLETE);
    assert_eq!(frame.rdx, protocol::VERSION);
    assert_eq!(vmcb.guest_rip(), 0x2003);
    assert_eq!(frame.rcx, protocol::PROBE);
    assert_eq!(frame.r10, 0);
    assert!(!state.pending_fault);
}

#[test]
fn decoded_invalid_operation_finishes_without_physical_reader_capture() {
    let (mut state, mut vmcb, mut frame) = probe(true);
    frame.rcx = u64::MAX;
    frame.rdx = 0x1234;
    // SAFETY: this is the only test that reaches the empty static channel. The VMCB's
    // absent NPT would fail LocalMemory construction; decoded refusal needs neither
    // that adapter nor privileged work, and only completes these inert guest bytes.
    assert!(unsafe { handle(&mut state, &mut vmcb, &mut frame) });
    assert_eq!(vmcb.guest_rax(), protocol::INVALID);
    assert_eq!(frame.rdx, 0);
    assert_eq!(vmcb.guest_rip(), 0x2003);
    assert!(!state.pending_fault);
}

#[test]
fn probe_without_nrips_requires_readable_instruction_evidence() {
    let (mut state, mut vmcb, mut frame) = probe(false);
    // SAFETY: the inert VMCB has no nested root, so byte-fetch admission fails before
    // privileged work. Refusal only queues a guest exception in these owned bytes.
    assert!(unsafe { handle(&mut state, &mut vmcb, &mut frame) });
    assert_eq!(vmcb.guest_rax(), protocol::MAGIC);
    assert_eq!(vmcb.guest_rip(), 0x2000);
    assert!(state.pending_fault);
}

#[test]
fn unsupported_privilege_faults_before_debug_continuation_or_memory_admission() {
    for cpl in 0..3 {
        for flags in [2, 2 | (1 << 8), 2 | (1 << 16), 2 | (1 << 8) | (1 << 16)] {
            for nrip in [None, Some(0), Some(u64::MAX), Some(0x2003)] {
                let (mut state, mut vmcb, mut frame) = probe(nrip.is_some());
                if nrip.is_none() {
                    state.capabilities = None;
                }
                state.exits = 41;
                state.routing_retries = 7;
                frame = GuestRegisters {
                    rbx: 1,
                    rcx: frame.rcx,
                    rdx: 3,
                    rsi: 4,
                    rdi: 5,
                    rbp: 6,
                    r8: 7,
                    r9: 8,
                    r10: 9,
                    r11: 10,
                    r12: 11,
                    r13: 12,
                    r14: 13,
                    r15: 14,
                };
                put(&mut vmcb, 0x4c8, cpl << 24);
                put(&mut vmcb, 0x0c8, nrip.unwrap_or(u64::MAX));
                put(&mut vmcb, 0x570, flags);
                put(&mut vmcb, 0x0c0, 0xffff);
                put(&mut vmcb, 0x5d8, 0x7654_3000);
                put(&mut vmcb, 0x640, 0x7654_1000);
                let registers = frame;
                let mut expected = *vmcb.bytes();
                expected[0x0a8..0x0b0].copy_from_slice(&0x8000_0306u64.to_le_bytes());
                // EVENTINJ is uncached; privilege faults preserve clean bits.
                // SAFETY: privilege rejection uses only inert VMCB state. Poisoned/no
                // continuation and no NPT root must not reach a memory adapter or LOCAL.
                assert!(unsafe { handle(&mut state, &mut vmcb, &mut frame) });
                assert_eq!(*vmcb.bytes(), expected);
                assert_eq!(frame, registers);
                assert!(state.pending_fault);
                assert!(!state.stopped_valid);
                assert_eq!((state.exits, state.routing_retries), (41, 7));
            }
        }
    }
}

#[test]
fn unsupported_privilege_keeps_pending_delivery_before_retry() {
    for cpl in 0..3 {
        for event in [0x8000_0051, 0x8000_0202, 0x0000_0030_8000_0b0d] {
            for pending_fault in [false, true] {
                let (mut state, mut vmcb, mut frame) = probe(false);
                state.pending_fault = pending_fault;
                put(&mut vmcb, 0x4c8, cpl << 24);
                put(&mut vmcb, 0x570, 2 | (1 << 8) | (1 << 16));
                put(&mut vmcb, 0x088, event);
                put(&mut vmcb, 0x0a8, event);
                let before = *vmcb.bytes();
                let registers = frame;
                // SAFETY: pending delivery returns before any guest or host access.
                assert!(unsafe { handle(&mut state, &mut vmcb, &mut frame) });
                assert_eq!(*vmcb.bytes(), before);
                assert_eq!(frame, registers);
                assert_eq!(state.pending_fault, pending_fault);
                assert!(!state.stopped_valid);
            }
        }
    }
}

#[test]
fn unsupported_privilege_refuses_conflicting_fault_state_without_mutation() {
    for (offset, value) in
        [(0x070, 0x80), (0x088, 0x8000_0051), (0x060, 1 << 8), (0x060, 1 << 63), (0x090, 2)]
    {
        let (mut state, mut vmcb, mut frame) = probe(false);
        put(&mut vmcb, 0x4c8, 0);
        put(&mut vmcb, offset, value);
        let before = *vmcb.bytes();
        let registers = frame;
        // SAFETY: malformed inert event/control fixtures refuse before fault commit.
        assert!(!unsafe { handle(&mut state, &mut vmcb, &mut frame) });
        assert_eq!(*vmcb.bytes(), before);
        assert_eq!(frame, registers);
        assert!(!state.pending_fault && !state.stopped_valid);
    }
}

#[test]
fn buffers_exclude_overlap_overflow_and_kernel_addresses() {
    let mut registers = GuestRegisters {
        rdx: 0x1000,
        r8: 0x3000,
        r9: MAX_RESPONSE_BYTES as u64,
        r10: 1,
        ..GuestRegisters::default()
    };
    assert!(LocalBuffers::from_registers(&registers).is_some());
    for invalid in [0, 0x1000, 0x10ff, (1 << 47) - 1, u64::MAX] {
        registers.r8 = invalid;
        assert!(LocalBuffers::from_registers(&registers).is_none());
    }
}

#[test]
fn ownership_requires_nonzero_session_and_same_address_space() {
    let mut channel = LocalChannel::new();
    assert!(!channel.owns(0, 0));
    channel.owner = 0x1000;
    channel.session = 9;
    assert!(channel.owns(0x1000, 9));
    assert!(!channel.owns(0x2000, 9));
    assert!(!channel.owns(0x1000, 10));
    channel.clear();
    assert!(!channel.owns(0x1000, 9));
}

#[test]
fn pending_request_cannot_be_stolen_and_idle_hello_invalidates_old_owner() {
    let mut channel = LocalChannel::new();
    channel.boot = 17;
    let config = PagingConfig::new(48, true, true).unwrap();
    channel.begin(hello(9, 1), 0x2000, &registers(9), config).unwrap();
    assert_eq!(channel.begin(hello(10, 1), 0x4000, &registers(10), config), Err(protocol::BUSY));
    assert!(channel.owns(0x2000, 9));
    channel.engine.reset_response();
    channel.buffers = None;
    channel.begin(hello(10, 1), 0x4000, &registers(10), config).unwrap();
    assert!(!channel.owns(0x2000, 9));
    assert!(channel.owns(0x4000, 10));
}

#[test]
fn session_mismatch_and_new_owner_nonhello_leave_channel_unchanged() {
    let mut channel = LocalChannel::new();
    channel.boot = 17;
    let config = PagingConfig::new(48, true, true).unwrap();
    assert_eq!(channel.begin(hello(9, 1), 0x2000, &registers(10), config), Err(protocol::OWNER));
    assert_eq!(channel.session, 0);
    let mut request = hello(9, 1);
    request.operation = Operation::Physical;
    assert_eq!(channel.begin(request, 0x2000, &registers(9), config), Err(protocol::OWNER));
    assert!(channel.buffers.is_none());
}

#[test]
fn abandoned_operation_expires_without_reusing_session() {
    let mut channel = LocalChannel::new();
    channel.boot = 17;
    let config = PagingConfig::new(48, true, true).unwrap();
    channel.begin(hello(9, 1), 0x2000, &registers(9), config).unwrap();
    channel.last_progress = 31;
    channel.expire(30 + MAX_IDLE_EXITS);
    assert!(channel.buffers.is_some());
    channel.expire(31 + MAX_IDLE_EXITS);
    assert!(channel.buffers.is_none());
    assert_eq!(channel.session, 0);
    assert_eq!(channel.boot, 17);
    assert!(channel.engine.response().is_none());
    channel.begin(hello(10, 1), 0x4000, &registers(10), config).unwrap();
    assert!(channel.owns(0x4000, 10));
}

#[test]
fn memory_free_abort_preserves_owner_until_matching_cancellation() {
    let mut channel = LocalChannel::new();
    channel.boot = 17;
    let config = PagingConfig::new(48, true, true).unwrap();
    let mut frame = registers(9);
    channel.begin(hello(9, 1), 0x2000, &frame, config).unwrap();
    channel.steps = 3;
    frame.rcx = protocol::ABORT;
    // Abort does not need any still-mapped request/output buffer.
    frame.rdx = 0;
    frame.r8 = 0;
    frame.r9 = 0;
    for (root, session) in [(0x4000, 9), (0x2000, 10), (0x2000, 0)] {
        frame.r10 = session;
        assert_eq!(channel.handle_without_memory(root, &frame), Some((protocol::OWNER, 0)));
        assert!(channel.owns(0x2000, 9));
        assert!(channel.buffers.is_some());
        assert_eq!(channel.steps, 3);
    }
    frame.r10 = 9;
    assert_eq!(channel.handle_without_memory(0x2000, &frame), Some((protocol::COMPLETE, 0)));
    assert_eq!(channel.boot, 17);
    assert_eq!(channel.steps, 0);
    assert!(channel.buffers.is_none());
    assert!(channel.engine.response().is_none());
    assert!(!channel.owns(0x2000, 9));
    assert_eq!(channel.context_buffers(0x2000, &registers(9)), Err(protocol::OWNER));
}

#[test]
fn memory_free_metadata_refusals_preserve_pending_request() {
    let mut channel = LocalChannel::new();
    channel.boot = 17;
    let config = PagingConfig::new(48, true, true).unwrap();
    let mut frame = registers(9);
    frame.rcx = protocol::SUBMIT;
    assert_eq!(channel.handle_without_memory(0x2000, &frame), None);
    frame.r9 = 0;
    assert_eq!(channel.handle_without_memory(0x2000, &frame), Some((protocol::INVALID, 0)));
    frame.r9 = MAX_RESPONSE_BYTES as u64;
    channel.begin(hello(9, 1), 0x2000, &frame, config).unwrap();
    assert_eq!(channel.handle_without_memory(0x4000, &frame), Some((protocol::BUSY, 0)));
    frame.rcx = protocol::STEP;
    assert_eq!(channel.handle_without_memory(0x2000, &frame), None);
    assert_eq!(channel.handle_without_memory(0x4000, &frame), Some((protocol::OWNER, 0)));
    frame.r8 += 0x1000;
    assert_eq!(channel.handle_without_memory(0x2000, &frame), Some((protocol::INVALID, 0)));
    frame.r8 -= 0x1000;
    frame.rcx = protocol::CONTEXT;
    assert_eq!(channel.handle_without_memory(0x2000, &frame), Some((protocol::BUSY, 0)));
    assert_eq!(channel.handle_without_memory(0x4000, &frame), Some((protocol::OWNER, 0)));
    assert!(channel.owns(0x2000, 9));
    assert_eq!(channel.buffers, LocalBuffers::from_registers(&frame));
    assert_eq!(channel.steps, 0);
    assert_eq!(channel.boot, 17);
    channel.engine.reset_response();
    channel.buffers = None;
    assert_eq!(channel.handle_without_memory(0x2000, &frame), None);
    frame.r9 = 0;
    assert_eq!(channel.handle_without_memory(0x2000, &frame), Some((protocol::INVALID, 0)));
    frame.rcx = protocol::STEP;
    assert_eq!(channel.handle_without_memory(0x2000, &frame), Some((protocol::INVALID, 0)));
}

#[test]
fn context_requires_idle_owner_and_validated_disjoint_buffers() {
    let mut channel = LocalChannel::new();
    let mut registers = registers(9);
    assert_eq!(channel.context_buffers(0x2000, &registers), Err(protocol::OWNER));
    channel.owner = 0x2000;
    channel.session = 9;
    channel.boot = 17;
    assert!(channel.context_buffers(0x2000, &registers).is_ok());
    assert_eq!(channel.context_buffers(0x4000, &registers), Err(protocol::OWNER));
    registers.r10 = 10;
    assert_eq!(channel.context_buffers(0x2000, &registers), Err(protocol::OWNER));
    registers.r10 = 9;
    registers.r8 = registers.rdx;
    assert_eq!(channel.context_buffers(0x2000, &registers), Err(protocol::INVALID));
    registers.r8 = 0x3000;
    channel.buffers = LocalBuffers::from_registers(&registers);
    assert_eq!(channel.context_buffers(0x2000, &registers), Err(protocol::BUSY));
}

#[test]
fn committed_init_reset_discards_owner_pending_batch_and_generation() {
    let mut channel = LocalChannel::new();
    channel.boot = 17;
    let config = PagingConfig::new(48, true, true).unwrap();
    channel.begin(hello(9, 1), 0x2000, &registers(9), config).unwrap();
    channel.last_progress = 31;
    channel.reset();
    assert_eq!(channel.boot, 0);
    assert_eq!(channel.last_progress, 0);
    assert!(channel.buffers.is_none());
    assert!(channel.engine.response().is_none());
    assert!(!channel.owns(0x2000, 9));
    assert_eq!(channel.context_buffers(0x2000, &registers(9)), Err(protocol::OWNER));
}

#[test]
fn completion_preserves_nonresult_registers_and_advances_validated_instruction() {
    let mut vmcb = Vmcb::new();
    vmcb.set_guest_rax(protocol::MAGIC);
    let mut frame = registers(9);
    frame.rcx = protocol::STEP;
    frame.rbx = 0x7654;
    frame.r11 = 0x3344;
    frame.r15 = 0x9988;
    let mut expected = frame;
    expected.rdx = 68;
    let next =
        crate::svm::exit::ExitSnapshot { code: 0x81, info1: 0, info2: 0, rip: 0x2000, nrip: 0 }
            .resume_candidate_from_instruction(&[0x0f, 0x01, 0xd9])
            .unwrap();
    complete(&mut vmcb, &mut frame, next, (protocol::COMPLETE, 68));
    assert_eq!(frame, expected);
    assert_eq!(vmcb.guest_rax(), protocol::COMPLETE);
    assert_eq!(vmcb.guest_rip(), 0x2003);
}
