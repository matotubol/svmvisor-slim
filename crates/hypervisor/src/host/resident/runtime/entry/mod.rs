//! Explicit one-shot native GMET experiment. Default resident builds omit this module.
//!
//! All translations stay canonical. The same-CPU physical LAPIC count timer
//! bounds a fault-free user loop; INTR is handed back without acknowledgment.
//! Native assembly preserves all external GPRs and commits entry/exit provenance.

use core::{arch::x86_64::__cpuid_count, ptr, sync::atomic::Ordering};
use svmvisor_card_abi::entry::{
    ARM, ENTERED, FAILED, GATED, INTERRUPTED, MAGIC, QUERY, REFLECTED, REFUSED, REQUESTED, VERSION,
};

use crate::{
    arch::x86_64::{apic, registers::GuestRegisters},
    host::resident::runtime::{
        ASSIGNED_APIC_ID, CONTEXT, FRAME, NPT, POOL, RawVmexitCapture, State, VMCB, diagnostics,
        interrupt, minimal,
        msr::read_msr,
        startup::mailboxes,
        stop::{stop, terminal_requested},
        svmvisor_resident_nmi_pending, svmvisor_resident_raw_vmexit,
    },
    memory::{
        address::{ADDRESS_MASK, PAGE_BYTES, PAT_LARGE, PRESENT, PS},
        npt::{CACHE_TABLE_COUNT, identity_is_quarantined},
    },
    svm::vmcb::{
        Vmcb,
        trial::{FetchEvidence, Outcome, Ticket},
    },
};

const _: () = assert!(CACHE_TABLE_COUNT <= u64::BITS as usize);

static mut CHANNEL: Channel = Channel::new();

/// Host-private full register evidence. Written by the stopped owner only.
/// This is corroborating monitor evidence, not an independent entry witness.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Record {
    status: u64,
    nonce: u64,
    cpu: u64,
    vmcb: u64,
    sequence: u64,
    root: u64,
    nested_root: u64,
    timer: [u64; 4],
    entry: [u64; 4],
    exit: [u64; 6],
    entry_registers: GuestRegisters,
    exit_registers: GuestRegisters,
}

struct Active {
    ticket: Ticket,
    sequence: u64,
    cpu: u32,
    vmcb: u64,
}

struct Channel {
    used: bool,
    pending: bool,
    active: Option<Active>,
    record: Record,
}

impl Channel {
    const fn new() -> Self {
        Self {
            used: false,
            pending: false,
            active: None,
            // All-zero integer-only record is the idle representation.
            record: unsafe { core::mem::zeroed() },
        }
    }
}

#[derive(Clone, Copy)]
struct Timer {
    lvt: u64,
    count: u64,
    initial: u64,
    ppr: u64,
    svr: u64,
}

impl Timer {
    fn valid(self, vmcb: &Vmcb) -> bool {
        let vector = self.lvt & 0xff;
        // Only enabled count-mode LAPIC timers. A zero or expired count is
        // refused even if IRR might already contain the vector. No guessed tick rate.
        self.lvt & !((1 << 17) | 0xff) == 0
            && vector >= 0x20
            && vector & 0xf0 > self.ppr & 0xf0
            && self.count != 0
            && self.count <= self.initial
            && self.initial <= u32::MAX as u64
            && self.svr & (1 << 8) != 0
            && vmcb.guest_rflags() & ((1 << 9) | (1 << 8) | (3 << 12)) == 1 << 9
            && word(vmcb, 0x068) == 0
    }
}

/// Called only for the acknowledged, stopped guest after startup servicing.
/// # Safety
/// Exclusive same-CPU native dispatcher; this image's private channel is owned.
#[unsafe(export_name = "svmvisor_entry_trial_request")]
#[inline(never)]
pub(super) unsafe fn request(
    state: &mut State,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
) -> Option<bool> {
    if vmcb.guest_rax() != MAGIC {
        return None;
    }
    let next = state
        .capabilities
        .as_ref()
        .and_then(|caps| vmcb.exit_snapshot().resume_candidate(caps).ok());
    let Some(next) = next else {
        return Some(stop(state, 0x81, vmcb.guest_rip(), 0xf301, 0));
    };
    if vmcb.guest_cpl() != 3
        || !vmcb.guest_in_64_bit_code()
        || vmcb.guest_rflags() & (1 << 8) != 0
        || vmcb.event_injection() != 0
        || state.pending_fault
    {
        return Some(stop(state, 0x81, vmcb.guest_rip(), 0xf301, 1));
    }
    let channel = unsafe { &mut *ptr::addr_of_mut!(CHANNEL) };
    let root = vmcb.guest_cr3();
    let nonce = frame.rdx;
    let mut result = 1;
    if frame.r8 == VERSION && nonce != 0 {
        match frame.rcx {
            ARM if !channel.used => {
                channel.used = true;
                channel.pending = true;
                channel.record.nonce = nonce;
                channel.record.root = root;
                channel.record.status = REQUESTED;
                result = 0;
            }
            QUERY if channel.record.nonce == nonce && channel.record.root == root => {
                result = 0;
                frame.r8 = channel.record.exit[0];
                frame.r9 = channel.record.exit[1];
                frame.r10 = channel.record.exit[2];
                frame.r11 = channel.record.exit[3];
                frame.r12 = channel.record.sequence;
            }
            _ => {}
        }
    }
    frame.rdx = channel.record.status;
    vmcb.commit_emulated_instruction(result, next);
    vmcb.complete_native_instruction_state();
    Some(true)
}

/// Final trial-state operation before returning to the audited VMRUN loop.
/// # Safety
/// Owning CPU with IF/GIF clear, after outer late-NMI routing. No later producer
/// or callback may mutate guest/control state, frame, NPT, LAPIC timer, or startup
/// state. Only the CPU-local cache owner's final CLEAN_BITS bookkeeping follows;
/// it can require fresh loads but cannot change the state admitted by this trial.
#[unsafe(export_name = "svmvisor_entry_trial_final")]
#[inline(never)]
pub(super) unsafe fn final_entry(state: &mut State, vmcb: &mut Vmcb) -> bool {
    let channel = unsafe { &mut *ptr::addr_of_mut!(CHANNEL) };
    if !channel.pending {
        return true;
    }
    channel.pending = false;
    let context = unsafe { &*ptr::addr_of!(CONTEXT) };
    let address = ptr::addr_of!(VMCB) as u64;
    let cpu = __cpuid_count(1, 0).ebx >> 24;
    let raw = unsafe { ptr::read_volatile(ptr::addr_of!(svmvisor_resident_raw_vmexit)) };
    let features = __cpuid_count(0x8000_000a, 0).edx;
    // Refuse before reading LAPIC registers unless native x2APIC is still active.
    let apic_base = unsafe { read_msr(apic::APIC_BASE) };
    let identity = cpu == unsafe { ASSIGNED_APIC_ID }
        && context.guest_vmcb_pa == address
        && context.guest_vmcb_va == address
        && context.guest_frame_va == ptr::addr_of!(FRAME) as u64
        && apic_base == state.host_apic_base
        && apic_base & apic::APIC_BASE_X2APIC == apic::APIC_BASE_X2APIC;
    let ready = identity
        && state.armed
        && state.startup_owned
        && !state.pending_fault
        && !unsafe { terminal_requested(state) }
        && unsafe { mailboxes(state.count) }[state.slot].peek().is_none()
        && svmvisor_resident_nmi_pending.load(Ordering::Acquire) == 0
        && interrupt::validate_entry(vmcb)
        && minimal::valid(vmcb)
        && vmcb.guest_cr3() == channel.record.root
        && vmcb.nested_root() == ptr::addr_of!(NPT) as u64
        && raw.entry_sequence == raw.exit_sequence
        && raw.exit_vmcb_pa == address
        && raw.entry_sequence != u64::MAX;
    let ready = ready
        && validate_npt(unsafe { &(*ptr::addr_of!(NPT)).0 }, vmcb.nested_root(), unsafe { POOL });
    let timer = if ready {
        Some(Timer {
            lvt: unsafe { read_msr(apic::msr(apic::LVT_TIMER)) },
            count: unsafe { read_msr(0x839) },
            initial: unsafe { read_msr(apic::msr(apic::TIMER_INITIAL_COUNT)) },
            ppr: unsafe { read_msr(0x80a) },
            svr: unsafe { read_msr(apic::msr(apic::SVR)) },
        })
    } else {
        None
    };
    let valid = timer.is_some_and(|timer| timer.valid(vmcb));
    if !valid {
        channel.record.status = REFUSED;
        vmcb.set_guest_rax(1);
        unsafe { (*ptr::addr_of_mut!(FRAME)).rdx = REFUSED };
        return true;
    }
    let timer = timer.unwrap();
    // The private NPT has no software writer while this CPU executes its guest.
    // Hardware A/D changes preserve every proved effective permission/address.
    unsafe { (*ptr::addr_of_mut!(FRAME)).rdx = ENTERED };
    let ticket = match unsafe { Ticket::arm(vmcb, features) } {
        Ok(ticket) => ticket,
        Err(_) => {
            channel.record.status = REFUSED;
            vmcb.set_guest_rax(1);
            unsafe { (*ptr::addr_of_mut!(FRAME)).rdx = REFUSED };
            return true;
        }
    };
    channel.record.status = ENTERED;
    channel.record.cpu = cpu as u64;
    channel.record.vmcb = address;
    channel.record.sequence = raw.entry_sequence + 1;
    channel.record.nested_root = vmcb.nested_root();
    channel.record.timer = [timer.lvt, timer.count, timer.initial, timer.ppr];
    channel.record.entry =
        [vmcb.guest_rip(), vmcb.guest_rax(), vmcb.guest_rsp(), word(vmcb, 0x640)];
    channel.record.entry_registers = unsafe { ptr::read(ptr::addr_of!(FRAME)) };
    channel.active = Some(Active { ticket, sequence: raw.entry_sequence + 1, cpu, vmcb: address });
    true
}

/// Complete before native validators, flush consumption, event completion,
/// startup, terminal work or diagnostic callbacks can interpret/mutate the exit.
/// # Safety
/// Actual assembly return to this image's exclusive stopped dispatcher.
#[unsafe(export_name = "svmvisor_entry_trial_complete")]
#[inline(never)]
pub(super) unsafe fn complete(state: &mut State, vmcb: &mut Vmcb) -> Result<bool, ()> {
    let channel = unsafe { &mut *ptr::addr_of_mut!(CHANNEL) };
    let Some(active) = channel.active.take() else { return Ok(false) };
    let raw = unsafe { ptr::read_volatile(ptr::addr_of!(svmvisor_resident_raw_vmexit)) };
    let cpu = __cpuid_count(1, 0).ebx >> 24;
    let context = unsafe { &*ptr::addr_of!(CONTEXT) };
    let identity = witness(&active, &raw, cpu)
        && context.guest_vmcb_pa == active.vmcb
        && context.guest_vmcb_va == active.vmcb
        && context.guest_frame_va == ptr::addr_of!(FRAME) as u64;
    let evidence = if word(vmcb, 0x070) == 0x400 {
        let address = vmcb.exit_snapshot().info2;
        Some(FetchEvidence {
            nested_root: vmcb.nested_root(),
            guest_physical_address: address,
            user_executable: executable(
                unsafe { &(*ptr::addr_of!(NPT)).0 },
                vmcb.nested_root(),
                address,
            ),
        })
    } else {
        None
    };
    let status = unsafe {
        complete_owned(
            state,
            vmcb,
            &*ptr::addr_of!(FRAME),
            &mut channel.record,
            active,
            identity,
            evidence,
        )
    }?;
    let code = word(vmcb, 0x070);
    // Result survives all later exits and is available through QUERY even when
    // transport is unavailable. Emit a correlated bounded record when present.
    unsafe {
        diagnostics::record(
            10,
            false,
            [
                status,
                channel.record.nonce,
                cpu as u64,
                channel.record.sequence,
                channel.record.exit[1],
                channel.record.exit[2],
            ],
            0,
        )
    };
    if state.startup_owned && unsafe { mailboxes(state.count) }[state.slot].peek().is_some() {
        stop(state, code, vmcb.guest_rip(), 0xf304, status);
        return Err(());
    }
    Ok(true)
}

/// Consume an assembly-proven entry, preserving all guest register effects.
/// # Safety
/// `identity` and `evidence` are actual stable same-CPU observations, never
/// caller-supplied guest assertions. The exclusive stopped VMCB owns `active`.
unsafe fn complete_owned(
    state: &mut State,
    vmcb: &mut Vmcb,
    frame: &GuestRegisters,
    record: &mut Record,
    active: Active,
    identity: bool,
    evidence: Option<FetchEvidence>,
) -> Result<u64, ()> {
    let code = word(vmcb, 0x070);
    // Never publish poisoned saved-state fields as architectural evidence.
    let usable = !matches!(code, u64::MAX | 0xffff_ffff | 0x7f);
    record.status = FAILED;
    record.exit[0] = code;
    if usable {
        let exit = vmcb.exit_snapshot();
        record.exit = [code, exit.rip, exit.info1, exit.info2, vmcb.guest_rax(), word(vmcb, 0x640)];
        record.exit_registers = *frame;
    }
    if !identity {
        let _ = active.ticket.cancel(vmcb);
        stop(state, code, 0, 0xf302, 0);
        return Err(());
    }
    // Consume the old entry request before restoration issues its new flush.
    unsafe { vmcb.consume_tlb_flush_after_exit() };
    let result = unsafe { active.ticket.finish(vmcb, evidence) };
    let status = match result {
        Ok(Outcome::SupervisorFetchGated) => GATED,
        Ok(Outcome::PageFaultReflected) => {
            state.pending_fault = true;
            REFLECTED
        }
        Ok(Outcome::InterruptPending) => INTERRUPTED,
        Err(error) => {
            stop(state, code, if usable { vmcb.guest_rip() } else { 0 }, 0xf303, error as u64);
            return Err(());
        }
    };
    record.status = status;
    Ok(status)
}

fn witness(active: &Active, raw: &RawVmexitCapture, cpu: u32) -> bool {
    cpu == active.cpu
        && raw.entry_sequence == active.sequence
        && raw.exit_sequence == active.sequence
        && raw.entry_vmcb_pa == active.vmcb
        && raw.exit_vmcb_pa == active.vmcb
        && raw.context_vmcb_pa == active.vmcb
}

fn word(vmcb: &Vmcb, offset: usize) -> u64 {
    u64::from_le_bytes(vmcb.bytes()[offset..offset + 8].try_into().unwrap())
}

/// Audit the complete reachable private identity tree. The cache owner may
/// select any admitted PAT index or retain a marked nonpresent leaf; this
/// permission proof neither retypes memory nor makes a quarantine accessible.
fn validate_npt(storage: &[[u8; PAGE_BYTES]], root: u64, pool: (u64, u64)) -> bool {
    if root & (PAGE_BYTES as u64 - 1) != 0
        || storage.is_empty()
        || storage.len() > CACHE_TABLE_COUNT
        || pool.1 == 0
        || pool.0.checked_add(pool.1).is_none()
    {
        return false;
    }
    if root < pool.0
        || root
            .checked_add((storage.len() * PAGE_BYTES) as u64)
            .is_none_or(|end| end > pool.0 + pool.1)
    {
        return false;
    }
    audit_table(storage, root, pool, 0, 4, 0, &mut 0)
}

fn audit_table(
    storage: &[[u8; PAGE_BYTES]],
    root: u64,
    pool: (u64, u64),
    table: usize,
    level: u32,
    base: u64,
    seen: &mut u64,
) -> bool {
    if *seen & (1u64 << table) != 0 {
        return false;
    }
    *seen |= 1u64 << table;
    let span = 1u64 << (12 + 9 * (level - 1));
    for index in 0..512 {
        let entry = table_word(storage, table, index);
        if entry == 0 {
            continue;
        }
        let address = base + index as u64 * span;
        let leaf = level == 1 || (level < 4 && entry & PS != 0);
        // Cache retyping retains identity and permissions in its marked holes.
        // Reuse its decoder to establish provenance rather than treating an
        // arbitrary nonpresent entry as a cache quarantine.
        if entry & PRESENT == 0 {
            if !leaf || identity_is_quarantined(storage, root, address) != Ok(true) {
                return false;
            }
            let next = leaf_address(entry, level);
            if next != address || overlaps_pool(address, span, pool) {
                return false;
            }
            continue;
        }
        if entry & 5 != 5 {
            return false;
        }
        if leaf {
            // PTE bit7 is PAT, while PDE/PDPE bit7 is PS and bit12 is PAT.
            // Cache selectors do not alter effective execute permission.
            if entry & !(ADDRESS_MASK | 0xff) != 0
                || leaf_address(entry, level) != address
                || overlaps_pool(address, span, pool)
            {
                return false;
            }
        } else {
            if entry & !(ADDRESS_MASK | 0x67) != 0 {
                return false;
            }
            let Some(table) = table_index(root, entry & ADDRESS_MASK, storage.len()) else {
                return false;
            };
            if !audit_table(storage, root, pool, table, level - 1, address, seen) {
                return false;
            }
        }
    }
    true
}

fn overlaps_pool(address: u64, span: u64, pool: (u64, u64)) -> bool {
    address < pool.0 + pool.1 && pool.0 < address + span
}

fn leaf_address(entry: u64, level: u32) -> u64 {
    entry & ADDRESS_MASK & if level == 1 { u64::MAX } else { !PAT_LARGE }
}

fn executable(storage: &[[u8; PAGE_BYTES]], root: u64, address: u64) -> bool {
    if address >= 1 << 48 || storage.is_empty() || storage.len() > CACHE_TABLE_COUNT {
        return false;
    }
    let mut table = 0;
    for level in (1..=4).rev() {
        let shift = 12 + 9 * (level - 1);
        let entry = table_word(storage, table, ((address >> shift) & 511) as usize);
        if entry & 5 != 5 {
            return false;
        }
        let leaf = level == 1 || (level < 4 && entry & PS != 0);
        if leaf {
            return entry & !(ADDRESS_MASK | 0xff) == 0
                && leaf_address(entry, level) == address & !((1 << shift) - 1);
        }
        if entry & !(ADDRESS_MASK | 0x67) != 0 {
            return false;
        }
        let Some(index) = table_index(root, entry & ADDRESS_MASK, storage.len()) else {
            return false;
        };
        table = index;
    }
    false
}

fn table_word(storage: &[[u8; PAGE_BYTES]], table: usize, index: usize) -> u64 {
    let offset = index * 8;
    u64::from_le_bytes(storage[table][offset..offset + 8].try_into().unwrap())
}

fn table_index(root: u64, next: u64, table_count: usize) -> Option<usize> {
    let offset = next.checked_sub(root)?;
    if offset & (PAGE_BYTES as u64 - 1) != 0 || offset / PAGE_BYTES as u64 >= table_count as u64 {
        return None;
    }
    Some((offset / PAGE_BYTES as u64) as usize)
}

#[cfg(test)]
mod tests;
