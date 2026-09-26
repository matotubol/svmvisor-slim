//! Core-shared logical MTRRs with permanently unchanged physical host MTRRs.
//! Every type transition parks all guests before retiring ASIDs and flushing
//! caches. Each CPU stages and installs only its own nested tables.

use crate::{
    arch::x86_64::{
        msr::{HWCR, HWCR_INVD_WBINVD, PAT},
        registers::GuestRegisters,
    },
    host::resident::{
        CACHE_SHARED_OFFSET,
        runtime::{
            NPT, State,
            guest_reader::fetch_instruction,
            image_base,
            msr::{read_msr, write_msr},
            startup::{acknowledge_init, notify_native_startup},
            stop::{stop, terminal_requested},
        },
    },
    memory::npt::{CacheMapping, CacheNptError, CacheTableStorage, retype_identity_policy},
    svm::{
        cache_policy::{CacheBank, CacheEffect, CacheError, SharedCache},
        dispatch,
        exit::MsrInstruction,
        vmcb::Vmcb,
    },
};
use core::{
    arch::{asm, x86_64::__cpuid_count},
    ptr,
    sync::atomic::Ordering,
};

static mut STAGING: CacheTableStorage =
    CacheTableStorage([[0; 4096]; crate::memory::npt::CACHE_TABLE_COUNT]);
static mut LOCAL: Local = Local { ready: false, visibility: false, host_pat: 0, last_asid: 0 };
struct Local {
    ready: bool,
    visibility: bool,
    host_pat: u64,
    last_asid: u32,
}
const WAIT: u32 = 100_000_000;

unsafe fn shared() -> &'static SharedCache {
    unsafe { &*((image_base() + CACHE_SHARED_OFFSET) as *const SharedCache) }
}
fn mask(count: usize) -> u32 {
    u32::MAX >> (32 - count)
}

/// Before the first guest entry, under the identity-mapped firmware root.
/// Shared backing has been initialized and every MSRPM already owns cache MSRs.
pub(super) unsafe fn capture(pool: u64, slot: usize, ids: &[u32]) -> bool {
    if ids.is_empty() || ids.len() > 32 || slot >= ids.len() {
        return false;
    }
    let top = __cpuid_count(0x8000_0000, 0).eax;
    if top < 0x8000_001e || __cpuid_count(0x8000_0001, 0).ecx & (1 << 22) == 0 {
        return false;
    }
    let topology = __cpuid_count(0x8000_001e, 0);
    let width = __cpuid_count(0x8000_0008, 0);
    let shift = (width.ecx >> 12) & 15;
    let threads = ((topology.ebx >> 8) & 255) + 1;
    if shift == 0 || threads > 2 || topology.eax != ids[slot] || topology.ebx >> 16 != 0 {
        return false;
    }
    let key = ((topology.eax >> shift) as u64) << 32 | (topology.ebx & 255) as u64;
    let Ok((bank, visibility)) = CacheBank::capture(
        __cpuid_count(1, 0).eax,
        width.eax as u8,
        |index| unsafe { read_msr(index) },
        |index, value| unsafe { write_msr(index, value) },
    ) else {
        return false;
    };
    if bank.default & (1 << 11) == 0 {
        return false;
    }
    if unsafe { read_msr(HWCR) } & HWCR_INVD_WBINVD == 0 {
        return false;
    }
    let host_pat = unsafe { read_msr(PAT) };
    if host_pat & 255 != 6
        || !(0..8).all(|i| matches!((host_pat >> (i * 8)) & 255, 0 | 1 | 4 | 5 | 6 | 7))
        || !(0..8).any(|i| matches!((host_pat >> (i * 8)) & 255, 0 | 7))
    {
        return false;
    }
    // No guest has run on this CPU. Establish the correctly composed initial
    // types as well: nested PAT0=WB alone is not transparent for physical WC.
    if unsafe {
        retype_identity_policy(
            &(*ptr::addr_of!(NPT)).0,
            &mut (*ptr::addr_of_mut!(STAGING)).0,
            ptr::addr_of!(NPT) as u64,
            |start, end| select_type(&bank, &bank, host_pat, start, end),
        )
    }
    .is_err()
    {
        return false;
    }
    unsafe {
        ptr::copy_nonoverlapping(ptr::addr_of!(STAGING), ptr::addr_of_mut!(NPT), 1);
    }
    let memory = unsafe { &*((pool + CACHE_SHARED_OFFSET) as *const SharedCache) };
    let mut lease = None;
    for _ in 0..WAIT {
        lease = memory.state.try_lock();
        if lease.is_some() {
            break;
        }
        core::hint::spin_loop();
    }
    let Some(mut owner) = lease else {
        return false;
    };
    if owner.captured & (1 << slot) != 0 {
        return false;
    }
    owner.physical[slot] = bank;
    owner.logical[slot] = bank;
    owner.core_keys[slot] = key;
    owner.threads[slot] = threads;
    owner.core[slot] = slot;
    owner.captured |= 1 << slot;
    if owner.captured == mask(ids.len()) {
        for cpu in 0..ids.len() {
            let mut first = cpu;
            let mut found = 0;
            for peer in 0..ids.len() {
                if owner.core_keys[peer] == owner.core_keys[cpu] {
                    first = first.min(peer);
                    found += 1;
                    if owner.physical[peer] != owner.physical[cpu]
                        || owner.threads[peer] != owner.threads[cpu]
                    {
                        owner.captured &= !(1 << slot);
                        return false;
                    }
                }
            }
            if found != owner.threads[cpu] {
                owner.captured &= !(1 << slot);
                return false;
            }
            owner.core[cpu] = first;
        }
    }
    unsafe {
        LOCAL = Local { ready: true, visibility, host_pat, last_asid: 0 };
    }
    true
}

/// Called exactly once for a successful VMRUN return, before any cache owner
/// changes the ASID. A staged ASID remains unused until this observation.
pub(super) unsafe fn after_exit(vmcb: &Vmcb) {
    if !matches!(vmcb.exit_snapshot().code, u64::MAX | 0xffff_ffff) {
        unsafe {
            LOCAL.last_asid = vmcb.guest_asid();
        }
    }
}

/// Bootstrap VMMCALL proves arm, VM_CR.R_INIT, private IDT and a completed
/// first VMRUN on this CPU before any other CPU may send a cache notification.
pub(super) unsafe fn ready(state: &State) {
    unsafe { shared() }.ready.fetch_or(1 << state.slot, Ordering::AcqRel);
}

fn refuse(state: &mut State, vmcb: &Vmcb, detail: u64) -> bool {
    stop(state, vmcb.exit_snapshot().code, vmcb.guest_rip(), 0xf400, detail)
}

/// Join an outstanding global transaction. Hooks run before instruction
/// dispatch, before guest reentry, and in AwaitSipi's stopped polling loop.
pub(super) unsafe fn service(state: &mut State, vmcb: &mut Vmcb) -> bool {
    let memory = unsafe { shared() };
    if memory.phase.load(Ordering::Acquire) == 0 {
        return true;
    }
    if !unsafe { LOCAL.ready } {
        return refuse(state, vmcb, 1);
    }
    let bit = 1 << state.slot;
    let all = mask(state.count);
    // Drain notifications before publishing parked. Never open GIF while any
    // phase relies on this CPU being quiescent; SMI could alter physical MTRRs.
    if unsafe { acknowledge_init() }.is_none() {
        return refuse(state, vmcb, 2);
    }
    let mut joined = None;
    for _ in 0..WAIT {
        match memory.try_join(state.slot) {
            None => core::hint::spin_loop(),
            Some(None) => return true,
            Some(Some(generation)) => {
                joined = Some(generation);
                break;
            }
        }
    }
    let Some(generation) = joined else {
        return refuse(state, vmcb, 6);
    };
    let mut prepared = false;
    let mut retired = false;
    let mut flushed = false;
    let mut applied = false;
    let mut departed = false;
    for spin in 0..WAIT {
        if spin & 1023 == 0 {
            if unsafe { terminal_requested(state) } {
                return false;
            }
        }
        let phase = memory.phase.load(Ordering::Acquire);
        if phase == 0 || memory.generation.load(Ordering::Acquire) != generation {
            return true;
        }
        if phase == 1 && memory.parked.load(Ordering::Acquire) == all && !prepared {
            let Some(owner) = memory.state.try_lock() else {
                continue;
            };
            let core = owner.core[state.slot];
            let logical =
                if core == owner.changed_core { owner.requested } else { owner.logical[core] };
            let physical = owner.physical[state.slot];
            drop(owner);
            let host_pat = unsafe { LOCAL.host_pat };
            let observed = CacheBank::capture(
                __cpuid_count(1, 0).eax,
                __cpuid_count(0x8000_0008, 0).eax as u8,
                |index| unsafe { read_msr(index) },
                |index, value| unsafe { write_msr(index, value) },
            );
            if observed.is_err()
                || observed.is_ok_and(|(bank, _)| bank != physical)
                || unsafe { read_msr(PAT) } != host_pat
            {
                return refuse(state, vmcb, 3);
            }
            let result = unsafe {
                retype_identity_policy(
                    &(*ptr::addr_of!(NPT)).0,
                    &mut (*ptr::addr_of_mut!(STAGING)).0,
                    ptr::addr_of!(NPT) as u64,
                    |start, end| select_type(&logical, &physical, host_pat, start, end),
                )
            };
            if result.is_err() {
                return refuse(state, vmcb, 4);
            }
            prepared = true;
            memory.prepared.fetch_or(bit, Ordering::AcqRel);
        }
        if phase == 1 && memory.prepared.load(Ordering::Acquire) == all {
            memory.phase.compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire).ok();
        }
        if phase == 2 && !retired {
            // Retire the live guest ASID before WBINVD. A second transaction
            // before VMRUN keeps the already-unused staged ASID. Every next
            // VMRUN performs a full flush, making the alternate reusable.
            let last = unsafe { LOCAL.last_asid };
            if vmcb.guest_asid() == last {
                let Some(caps) = state.capabilities.as_ref() else {
                    return refuse(state, vmcb, 5);
                };
                if vmcb.set_guest_asid(if last == 1 { 2 } else { 1 }, caps).is_err() {
                    return refuse(state, vmcb, 5);
                }
            }
            vmcb.request_full_tlb_flush();
            retired = true;
            memory.retired.fetch_or(bit, Ordering::AcqRel);
        }
        // All old ASIDs are retired on every stopped processor before any
        // processor invalidates cache lines (APM2 physical pp293-294,591).
        if phase == 2 && memory.retired.load(Ordering::Acquire) == all && !flushed {
            unsafe {
                asm!("wbinvd", options(nostack));
            }
            flushed = true;
            memory.flushed.fetch_or(bit, Ordering::AcqRel);
        }
        if phase == 2 && memory.flushed.load(Ordering::Acquire) == all {
            memory.phase.compare_exchange(2, 3, Ordering::AcqRel, Ordering::Acquire).ok();
        }
        if phase == 3 && !applied {
            unsafe {
                ptr::copy_nonoverlapping(ptr::addr_of!(STAGING), ptr::addr_of_mut!(NPT), 1);
            }
            vmcb.request_full_tlb_flush();
            applied = true;
            memory.applied.fetch_or(bit, Ordering::AcqRel);
        }
        if phase == 3 && memory.applied.load(Ordering::Acquire) == all {
            if let Some(mut owner) = memory.state.try_lock() {
                if memory.phase.load(Ordering::Acquire) == 3 {
                    let core = owner.changed_core;
                    owner.logical[core] = owner.requested;
                    memory.phase.store(4, Ordering::Release);
                }
            }
        }
        if phase == 4 && !departed {
            departed = true;
            memory.departed.fetch_or(bit, Ordering::AcqRel);
        }
        if phase == 4 && memory.departed.load(Ordering::Acquire) == all {
            if let Some(_owner) = memory.state.try_lock() {
                if memory.phase.load(Ordering::Acquire) == 4 {
                    memory.generation.fetch_add(1, Ordering::AcqRel);
                    memory.phase.store(0, Ordering::Release);
                }
            }
        }
        core::hint::spin_loop();
    }
    refuse(state, vmcb, 6)
}

fn select_type(
    logical: &CacheBank,
    physical: &CacheBank,
    host_pat: u64,
    start: u64,
    end: u64,
) -> Result<Option<CacheMapping>, CacheNptError> {
    let convert = |_| CacheNptError::MemoryType;
    let mapping = |address| {
        if !logical.routing_matches(physical, address).map_err(convert)? {
            return Ok(CacheMapping::Quarantine);
        }
        logical
            .nested_pat_index(physical, address, host_pat)
            .map(CacheMapping::Pat)
            .map_err(convert)
    };
    let first = mapping(start)?;
    let mut position = start;
    while position < end {
        if mapping(position)? != first {
            return Ok(None);
        }
        position = logical
            .next_boundary(position, end)
            .map_err(convert)?
            .min(physical.next_boundary(position, end).map_err(convert)?);
    }
    Ok(Some(first))
}

pub(super) unsafe fn handle(
    state: &mut State,
    vmcb: &mut Vmcb,
    frame: &mut GuestRegisters,
) -> bool {
    if !unsafe { LOCAL.ready } {
        return refuse(state, vmcb, 10);
    }
    if !unsafe { service(state, vmcb) } {
        return false;
    }
    let exit = vmcb.exit_snapshot();
    let caps = state
        .capabilities
        .filter(|c| c.optional_features().nrip_save && vmcb.guest_in_64_bit_code());
    let bytes;
    let instruction = if let Some(caps) = caps.as_ref() {
        match dispatch::hardware_msr_instruction(vmcb, caps) {
            Ok(value) => value,
            Err(_) => return refuse(state, vmcb, 11),
        }
    } else {
        bytes = match unsafe { fetch_instruction(vmcb, state.startup_owned, state.count) } {
            Ok(bytes) => bytes,
            Err(_) => return refuse(state, vmcb, 12),
        };
        MsrInstruction::Bytes(&bytes)
    };
    if dispatch::validate_native_msr_boundary(vmcb, instruction, state.startup_owned).is_err()
        || vmcb.guest_rflags() & (1 << 8) != 0
        || (!state.startup_owned && !vmcb.guest_in_64_bit_code())
        || (state.startup_owned
            && !dispatch::native_startup_instruction_mode(vmcb, instruction.length()))
    {
        return refuse(state, vmcb, 13);
    }
    let Ok(next) = instruction.continuation(exit) else {
        return refuse(state, vmcb, 14);
    };
    if vmcb.bytes()[0x4cb] != 0 {
        if vmcb.queue_validated_msr_general_protection(instruction).is_err() {
            return refuse(state, vmcb, 16);
        }
        state.pending_fault = true;
        return true;
    }
    let index = frame.rcx as u32;
    let value = (vmcb.guest_rax() as u32 as u64) | ((frame.rdx as u32 as u64) << 32);
    let memory = unsafe { shared() };
    for spin in 0..WAIT {
        if spin & 1023 == 0 && unsafe { terminal_requested(state) } {
            return false;
        }
        if memory.phase.load(Ordering::Acquire) != 0 {
            if !unsafe { service(state, vmcb) } {
                return false;
            }
            continue;
        }
        let Some(mut owner) = memory.state.try_lock() else {
            core::hint::spin_loop();
            continue;
        };
        if memory.phase.load(Ordering::Acquire) != 0 {
            continue;
        }
        if owner.captured != mask(state.count) {
            drop(owner);
            core::hint::spin_loop();
            continue;
        }
        let core = owner.core[state.slot];
        let visibility = unsafe { LOCAL.visibility };
        if exit.info1 == 0 {
            let Some(value) = owner.logical[core].read(index, visibility) else {
                return refuse(state, vmcb, 15);
            };
            drop(owner);
            frame.rdx = value >> 32;
            vmcb.commit_emulated_instruction(value as u32 as u64, next);
            vmcb.complete_native_instruction_state();
            return true;
        }
        let change = match owner.logical[core].prepare_write(index, value, visibility) {
            Ok(change) => change,
            Err(CacheError::GeneralProtection) => {
                drop(owner);
                if vmcb.queue_validated_msr_general_protection(instruction).is_err() {
                    return refuse(state, vmcb, 16);
                }
                state.pending_fault = true;
                return true;
            }
            Err(_) => return refuse(state, vmcb, 17),
        };
        if change.effect == CacheEffect::MemoryTypes {
            if memory.ready.load(Ordering::Acquire) != mask(state.count) {
                drop(owner);
                core::hint::spin_loop();
                continue;
            }
            owner.owner_slot = state.slot;
            owner.changed_core = core;
            owner.requested = change.bank;
            memory.parked.store(0, Ordering::Relaxed);
            memory.prepared.store(0, Ordering::Relaxed);
            memory.retired.store(0, Ordering::Relaxed);
            memory.flushed.store(0, Ordering::Relaxed);
            memory.applied.store(0, Ordering::Relaxed);
            memory.departed.store(0, Ordering::Relaxed);
            memory.phase.store(1, Ordering::Release);
            drop(owner);
            unsafe {
                notify_native_startup();
            }
            if !unsafe { service(state, vmcb) } {
                return false;
            }
        } else {
            owner.logical[core] = change.bank;
            drop(owner);
        }
        unsafe {
            LOCAL.visibility = change.visibility;
        }
        vmcb.request_full_tlb_flush();
        vmcb.request_rap_clear_after_cache_msr_write(index);
        vmcb.commit_emulated_instruction(vmcb.guest_rax(), next);
        vmcb.complete_native_instruction_state();
        return true;
    }
    refuse(state, vmcb, 18)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::msr::{MTRR_DEF_TYPE, SYS_CFG};

    const PAT_FIXTURE: u64 = 0x0007_0406_0007_0406;

    fn physical() -> CacheBank {
        let mut bank = CacheBank {
            capability: 0x508,
            default: 0xc00,
            sys_cfg: 0x740000,
            top_mem: 0xc0000000,
            tom2: 0x10_0000_0000,
            fixed: [0x1e1e_1e1e_1e1e_1e1e; 11],
            ..CacheBank::EMPTY
        };
        bank.fixed[2] = 0; // Conventional low MMIO span remains MMIO.
        bank
    }

    #[test]
    fn syscfg_programming_window_guards_routing_before_pat_composition() {
        let physical = physical();
        for default in [0x400, 0xc00] {
            let logical = physical.prepare_write(MTRR_DEF_TYPE, default, false).unwrap().bank;
            let window = logical.prepare_write(SYS_CFG, 0x780000, false).unwrap().bank;
            assert_eq!(
                select_type(&window, &physical, PAT_FIXTURE, 0, 0x1000),
                Ok(Some(CacheMapping::Quarantine))
            );
            assert!(matches!(
                select_type(&window, &physical, PAT_FIXTURE, 0xa0000, 0xa1000),
                Ok(Some(CacheMapping::Pat(_)))
            ));
            // Never quarantine the representable upper part of a large leaf.
            assert_eq!(select_type(&window, &physical, PAT_FIXTURE, 0, 0x200000), Ok(None));
            let restored = window.prepare_write(SYS_CFG, 0x740000, true).unwrap().bank;
            assert!(matches!(
                select_type(&restored, &physical, PAT_FIXTURE, 0, 0x1000),
                Ok(Some(CacheMapping::Pat(_)))
            ));
        }
    }

    #[test]
    fn route_matching_undefined_types_still_refuse() {
        let mut physical = physical();
        physical.fixed[2] = 0x0606_0606_0606_0606;
        assert_eq!(
            select_type(&physical, &physical, PAT_FIXTURE, 0xa0000, 0xa1000),
            Err(CacheNptError::MemoryType)
        );
    }
}
