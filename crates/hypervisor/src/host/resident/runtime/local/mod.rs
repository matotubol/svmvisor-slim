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

#[cfg(test)]
mod tests;

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
    page_1g: Option<bool>,
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
            page_1g: None,
        }
    }

    fn owns(&self, root: u64, session: u64) -> bool {
        self.owner == root && self.session == session && session != 0
    }

    fn page_1g(&mut self, query: impl FnOnce() -> bool) -> bool {
        // Each relocated channel stays on one CPU. This hardware feature survives session
        // changes; guest EFER and address-space observations are still captured per submit.
        *self.page_1g.get_or_insert_with(query)
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
        self.page_1g = None;
    }

    fn expire(&mut self, exits: u64) {
        if self.buffers.is_some() && exits.saturating_sub(self.last_progress) >= MAX_IDLE_EXITS {
            self.clear();
        }
    }

    /// Complete control-only calls and reject malformed ownership/buffer metadata before
    /// capturing a physical reader. NRIPS callers require no guest-memory access for these
    /// outcomes; callers without NRIPS still owe instruction-byte evidence before this point.
    fn handle_without_memory(
        &mut self,
        root: u64,
        registers: &GuestRegisters,
    ) -> Option<(u64, u64)> {
        let status = match registers.rcx {
            protocol::CAPABILITIES if !self.owns(root, registers.r10) => protocol::OWNER,
            protocol::CAPABILITIES if self.buffers.is_some() => protocol::BUSY,
            protocol::CAPABILITIES => return Some((protocol::COMPLETE, protocol::CAP_DIAGNOSTIC)),
            protocol::ABORT if self.owns(root, registers.r10) => {
                self.clear();
                protocol::COMPLETE
            }
            protocol::ABORT => protocol::OWNER,
            protocol::SUBMIT if self.buffers.is_some() => protocol::BUSY,
            protocol::SUBMIT if LocalBuffers::from_registers(registers).is_none() => {
                protocol::INVALID
            }
            protocol::STEP if !self.owns(root, registers.r10) => protocol::OWNER,
            protocol::STEP
                if self.buffers.is_none()
                    || self.buffers != LocalBuffers::from_registers(registers) =>
            {
                protocol::INVALID
            }
            protocol::CONTEXT => match self.context_buffers(root, registers) {
                Ok(_) => return None,
                Err(status) => status,
            },
            protocol::SUBMIT | protocol::STEP => return None,
            _ => protocol::INVALID,
        };
        Some((status, 0))
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
            page1gb: self.page_1g(page1gb_supported),
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
        self.engine.advance_bounded(&mut |address, bytes| memory.read_physical(address, bytes));
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
    // This ABI admits only user-mode callers. An unclaimed VMMCALL raises #UD in
    // every privilege level (APM2 physical page 593; APM3 physical page 536).
    // Fault before the API's TF/continuation checks: no instruction has completed,
    // so neither NRIPS nor a guest-memory fetch is needed and all operands survive.
    if vmcb.guest_cpl() != 3 {
        if vmcb.queue_vmmcall_invalid_opcode().is_err() {
            return false;
        }
        state.pending_fault = true;
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
    // NRIPS can complete Probe, Abort and metadata refusals without reading memory or
    // capturing PAT/MTRRs. The byte-fetch fallback constructs the adapter once, then shares
    // it with a memory-using operation.
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
    // SAFETY: this CPU exclusively owns its relocated channel with the guest stopped.
    let channel = unsafe { &mut *ptr::addr_of_mut!(LOCAL) };
    let root = vmcb.guest_cr3() & 0x000f_ffff_ffff_f000;
    channel.expire(state.exits);
    if let Some(result) = channel.handle_without_memory(root, registers) {
        if result.0 == protocol::COMPLETE {
            channel.last_progress = state.exits;
        }
        complete(vmcb, registers, next, result);
        return true;
    }
    // SAFETY: same stopped owner; preserve fresh capture for every memory-using call.
    let Ok(memory) = memory.get_or_insert_with(|| unsafe { LocalMemory::new(state, vmcb) }) else {
        complete(vmcb, registers, next, (protocol::MEMORY, 0));
        return true;
    };
    if channel.boot == 0 {
        // SAFETY: RDTSC is supported by the admitted AMD64 runtime; this is correlation only.
        channel.boot = unsafe { _rdtsc() }.max(1);
    }
    let result = match registers.rcx {
        protocol::SUBMIT => {
            let Ok(config) = PagingConfig::new(
                memory.width(),
                vmcb.guest_efer() & (1 << 11) != 0,
                channel.page_1g(page1gb_supported),
            ) else {
                complete(vmcb, registers, next, (protocol::UNAVAILABLE, 0));
                return true;
            };
            channel.submit(memory, root, registers, config)
        }
        protocol::STEP => channel.step(memory, root, registers),
        protocol::CONTEXT => channel.context(memory, root, registers, vmcb, state),
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
