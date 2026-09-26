//! CPU-local VMMCALL batches. Buffers are translated anew at every call; only owned bytes
//! survive guest reentry. The session is correlation, not an authorization credential.

use core::{arch::x86_64::_rdtsc, ptr};

use svmvisor_card_abi::{
    batch::{BatchRequest, MAX_RESPONSE_BYTES, Operation, REQUEST_BYTES},
    context::ContextObservation,
    local as protocol,
};

use crate::{
    arch::x86_64::{capabilities::page1gb_supported, registers::GuestRegisters},
    host::resident::runtime::{State, service::LocalMemory},
    reader::{batch::BatchEngine, paging::PagingConfig},
    svm::{exit::ResumeCandidate, vmcb::Vmcb},
};

const MAX_STEPS: u32 = 64;
const MAX_IDLE_EXITS: u64 = 1_000_000;

// Each relocated resident image belongs to one CPU. Only its stopped dispatcher reads/writes
// this storage; the returning NMI handler does not access local requests.
static mut LOCAL: LocalChannel = LocalChannel::new();

struct LocalChannel {
    engine: BatchEngine,
    boot: u64,
    owner: u64,
    session: u64,
    buffers: Option<LocalBuffers>,
    steps: u32,
    last_progress: u64,
}

impl LocalChannel {
    const fn new() -> Self {
        Self {
            engine: BatchEngine::new(),
            boot: 0,
            owner: 0,
            session: 0,
            buffers: None,
            steps: 0,
            last_progress: 0,
        }
    }

    fn owns(&self, root: u64, session: u64) -> bool {
        self.owner == root && self.session == session && session != 0
    }

    fn clear(&mut self) {
        self.engine.clear();
        self.owner = 0;
        self.session = 0;
        self.buffers = None;
        self.steps = 0;
    }

    fn reset(&mut self) {
        self.clear();
        self.boot = 0;
        self.last_progress = 0;
    }

    fn expire(&mut self, exits: u64) {
        if self.buffers.is_some() && exits.saturating_sub(self.last_progress) >= MAX_IDLE_EXITS {
            self.clear();
        }
    }

    fn submit(
        &mut self,
        memory: &mut LocalMemory,
        root: u64,
        registers: &GuestRegisters,
        config: PagingConfig,
    ) -> (u64, u64) {
        if self.buffers.is_some() {
            return (protocol::BUSY, 0);
        }
        let Some(buffers) = LocalBuffers::from_registers(registers) else {
            return (protocol::INVALID, 0);
        };
        let mut bytes = [0; REQUEST_BYTES];
        if memory.read_user(buffers.request, &mut bytes).is_err() {
            return (protocol::MEMORY, 0);
        }
        let Ok(request) = BatchRequest::decode(&bytes) else {
            return (protocol::INVALID, 0);
        };
        if let Err(status) = self.begin(request, root, registers, config) {
            return (status, 0);
        }
        self.advance(memory)
    }

    fn begin(
        &mut self,
        request: BatchRequest,
        root: u64,
        registers: &GuestRegisters,
        config: PagingConfig,
    ) -> Result<(), u64> {
        if self.buffers.is_some() {
            return Err(protocol::BUSY);
        }
        let buffers = LocalBuffers::from_registers(registers).ok_or(protocol::INVALID)?;
        if request.session != registers.r10 {
            return Err(protocol::OWNER);
        }
        if request.operation == Operation::Hello {
            if !self.owns(root, request.session) {
                self.clear();
                self.owner = root;
                self.session = request.session;
            }
        } else if !self.owns(root, request.session) {
            return Err(protocol::OWNER);
        }
        if self.engine.begin(request, self.boot, config).is_err() {
            return Err(protocol::INVALID);
        }
        self.buffers = Some(buffers);
        self.steps = 0;
        Ok(())
    }

    fn step(
        &mut self,
        memory: &mut LocalMemory,
        root: u64,
        registers: &GuestRegisters,
    ) -> (u64, u64) {
        if !self.owns(root, registers.r10) {
            return (protocol::OWNER, 0);
        }
        if self.buffers.is_none() || self.buffers != LocalBuffers::from_registers(registers) {
            return (protocol::INVALID, 0);
        }
        self.advance(memory)
    }

    fn context(
        &mut self,
        memory: &mut LocalMemory,
        root: u64,
        registers: &GuestRegisters,
        vmcb: &Vmcb,
        state: &State,
    ) -> (u64, u64) {
        let buffers = match self.context_buffers(root, registers) {
            Ok(buffers) => buffers,
            Err(status) => return (status, 0),
        };
        // The audited world switch VMSAVEs the guest before restoring host auxiliary state.
        // CR3 belongs to this user-mode exit; it is only a candidate for kernel-image discovery.
        let observation = ContextObservation {
            session: self.session,
            boot: self.boot,
            exit_sequence: state.exits,
            cr3: vmcb.guest_cr3(),
            cr4: vmcb.guest_cr4(),
            efer: vmcb.guest_efer(),
            lstar: vmcb.guest_lstar(),
            physical_bits: memory.width(),
            cpu_slot: state.slot as u32,
            page1gb: page1gb_supported(),
        };
        let bytes = observation.encode();
        if memory.write_user(buffers.response, &bytes).is_err() {
            self.clear();
            return (protocol::MEMORY, 0);
        }
        (protocol::COMPLETE, bytes.len() as u64)
    }

    fn context_buffers(&self, root: u64, registers: &GuestRegisters) -> Result<LocalBuffers, u64> {
        if !self.owns(root, registers.r10) {
            return Err(protocol::OWNER);
        }
        if self.buffers.is_some() {
            return Err(protocol::BUSY);
        }
        LocalBuffers::from_registers(registers).ok_or(protocol::INVALID)
    }

    fn advance(&mut self, memory: &mut LocalMemory) -> (u64, u64) {
        if self.steps == MAX_STEPS {
            self.clear();
            return (protocol::INVALID, 0);
        }
        self.steps += 1;
        self.engine.advance(&mut |address, bytes| memory.read_physical(address, bytes));
        let Some(response) = self.engine.response() else {
            return (protocol::PENDING, 0);
        };
        let Some(buffers) = self.buffers else {
            return (protocol::INVALID, 0);
        };
        let length = response.len() as u64;
        if memory.write_user(buffers.response, response).is_err() {
            self.clear();
            return (protocol::MEMORY, 0);
        }
        self.engine.reset_response();
        self.buffers = None;
        (protocol::COMPLETE, length)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LocalBuffers {
    request: u64,
    response: u64,
    capacity: u64,
}

impl LocalBuffers {
    fn from_registers(registers: &GuestRegisters) -> Option<Self> {
        let result =
            Self { request: registers.rdx, response: registers.r8, capacity: registers.r9 };
        if result.capacity != MAX_RESPONSE_BYTES as u64 || registers.r10 == 0 {
            return None;
        }
        let request_end = result.request.checked_add(REQUEST_BYTES as u64)?;
        let response_end = result.response.checked_add(result.capacity)?;
        if result.request == 0
            || result.response == 0
            || request_end > 1 << 47
            || response_end > 1 << 47
            || (result.request < response_end && result.response < request_end)
        {
            return None;
        }
        Some(result)
    }
}

/// Discard all local sessions and generation correlation after a committed guest INIT.
/// # Safety
/// Only this CPU's stopped dispatcher may access its relocated LOCAL storage.
pub(super) unsafe fn reset() {
    // SAFETY: caller retains exclusive stopped-CPU ownership of this relocated channel.
    unsafe { &mut *ptr::addr_of_mut!(LOCAL) }.reset();
}

/// # Safety
/// The acknowledged CPU owns its stopped guest, private mappings, and register frame. No
/// startup/route guard or scratch alias is held. Only this CPU can access its relocated LOCAL.
#[unsafe(export_name = "svmvisor_local_read_service")]
#[inline(never)]
pub(super) unsafe fn handle(
    state: &mut State,
    vmcb: &mut Vmcb,
    registers: &mut GuestRegisters,
) -> bool {
    if vmcb.event_injection() != 0 {
        return true;
    }
    // A caller using TF needs architectural single-step delivery that this API does not own.
    // Refuse with a guest exception rather than silently discarding the debug trap.
    if vmcb.guest_rflags() & (1 << 8) != 0 {
        return reject(state, vmcb);
    }
    let next = state
        .capabilities
        .as_ref()
        .and_then(|caps| vmcb.exit_snapshot().resume_candidate(caps).ok());
    // NRIPS can complete Probe without reading memory or capturing PAT/MTRRs. The byte-fetch
    // fallback constructs the adapter once, then shares it with a memory-using operation.
    let mut memory = None;
    let next = next.or_else(|| {
        // SAFETY: caller established exclusive stopped-CPU and private-root ownership.
        let reader = memory.insert(unsafe { LocalMemory::new(state, vmcb) }).as_mut().ok()?;
        let mut instruction = [0; 3];
        reader.read_user(vmcb.guest_rip(), &mut instruction).ok()?;
        vmcb.exit_snapshot().resume_candidate_from_instruction(&instruction).ok()
    });
    let Some(next) = next else {
        return reject(state, vmcb);
    };
    if !valid_mode(vmcb) {
        complete(vmcb, registers, next, (protocol::INVALID, 0));
        return true;
    }
    if registers.rcx == protocol::PROBE {
        complete(vmcb, registers, next, (protocol::COMPLETE, protocol::VERSION));
        return true;
    }
    // SAFETY: same stopped owner; preserve fresh capture for every memory-using call.
    let Ok(memory) = memory.get_or_insert_with(|| unsafe { LocalMemory::new(state, vmcb) }) else {
        complete(vmcb, registers, next, (protocol::MEMORY, 0));
        return true;
    };
    let Ok(config) = PagingConfig::new(memory.width(), vmcb.guest_efer() & (1 << 11) != 0, true)
    else {
        complete(vmcb, registers, next, (protocol::UNAVAILABLE, 0));
        return true;
    };
    // SAFETY: this CPU is the sole reader/writer of its relocated storage, with guest stopped.
    let channel = unsafe { &mut *ptr::addr_of_mut!(LOCAL) };
    if channel.boot == 0 {
        // SAFETY: RDTSC is supported by the admitted AMD64 runtime; this is correlation only.
        channel.boot = unsafe { _rdtsc() }.max(1);
    }
    let root = vmcb.guest_cr3() & 0x000f_ffff_ffff_f000;
    channel.expire(state.exits);
    let result = match registers.rcx {
        protocol::SUBMIT => channel.submit(memory, root, registers, config),
        protocol::STEP => channel.step(memory, root, registers),
        protocol::CONTEXT => channel.context(memory, root, registers, vmcb, state),
        protocol::ABORT if channel.owns(root, registers.r10) => {
            channel.clear();
            (protocol::COMPLETE, 0)
        }
        protocol::ABORT => (protocol::OWNER, 0),
        _ => (protocol::INVALID, 0),
    };
    if matches!(result.0, protocol::PENDING | protocol::COMPLETE) {
        channel.last_progress = state.exits;
    }
    complete(vmcb, registers, next, result);
    true
}

fn valid_mode(vmcb: &Vmcb) -> bool {
    let cr4 = vmcb.guest_cr4();
    vmcb.guest_cpl() == 3
        && vmcb.guest_in_64_bit_code()
        && vmcb.guest_cr0() & ((1 << 31) | 1) == ((1 << 31) | 1)
        && cr4 & (1 << 5) != 0
        && cr4 & (1 << 12) == 0
}

fn complete(
    vmcb: &mut Vmcb,
    registers: &mut GuestRegisters,
    next: ResumeCandidate,
    result: (u64, u64),
) {
    registers.rdx = result.1;
    vmcb.commit_emulated_instruction(result.0, next);
    vmcb.complete_native_instruction_state();
}

fn reject(state: &mut State, vmcb: &mut Vmcb) -> bool {
    if vmcb.queue_native_general_protection().is_ok() {
        state.pending_fault = true;
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use svmvisor_card_abi::batch::{BatchRange, BindingEvidence, MAX_RANGES};

    use crate::{
        arch::x86_64::capabilities::{
            CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures,
        },
        host::resident::runtime::INITIAL_STATE,
        memory::address::EncryptionState,
    };

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
                ptr::from_mut(&mut vmcb)
                    .cast::<u8>()
                    .add(offset)
                    .cast::<u64>()
                    .write_unaligned(value);
            }
        }
        (state, vmcb, GuestRegisters { rcx: protocol::PROBE, ..Default::default() })
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
    fn probe_without_nrips_requires_readable_instruction_evidence() {
        let (mut state, mut vmcb, mut frame) = probe(false);
        // SAFETY: the inert VMCB has no nested root, so byte-fetch admission fails before
        // privileged work. Refusal only queues a guest exception in these owned bytes.
        assert!(unsafe { handle(&mut state, &mut vmcb, &mut frame) });
        assert_eq!(vmcb.guest_rax(), protocol::MAGIC);
        assert_eq!(vmcb.guest_rip(), 0x2000);
        assert!(state.pending_fault);
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
        assert_eq!(
            channel.begin(hello(10, 1), 0x4000, &registers(10), config),
            Err(protocol::BUSY)
        );
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
        assert_eq!(
            channel.begin(hello(9, 1), 0x2000, &registers(10), config),
            Err(protocol::OWNER)
        );
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
}
