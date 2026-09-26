//! Image preparation and arm: the private host root, descriptors and directory
//! (`prepare`), CPU capability admission and the one-time arm of this CPU.

use core::{
    arch::{asm, x86_64::__cpuid_count},
    ptr,
};

use svmvisor_card_abi::endpoint::TerminalEndpoint;

use crate::{
    arch::x86_64::{
        capabilities::{
            CapabilityEvidence, CpuVendor, EvidenceFlag, OptionalFeatures, ValidatedCapabilities,
        },
        encryption::NativeEncryptionPlan,
        msr::{MMIO_CFG_BASE_ADDR, TARGET_SIGNATURE, VM_CR, VM_CR_R_INIT, VM_CR_SVMDIS},
    },
    boot::memory::{MAX_DESCRIPTORS, MemoryDescriptor, ValidatedMemoryMap},
    guest::continuation::NativeBootstrapAck,
    host::{
        descriptors::HostDescriptorRequest,
        resident::{
            CACHE_SHARED_BYTES, CACHE_SHARED_OFFSET, DIRECTORY_VERSION, ResidentDirectory,
            runtime::{
                ASSIGNED_APIC_ID, AUX, CONTEXT, FAULT_STACK, FRAME, GDT_TSS, GDTR, HOST_EXTRA,
                HSAVE, IDT, IDTR, IOPM, MSRPM, NMI_STACK, NPT, PHYSICAL_BITS, POOL, RAM, RAM_COUNT,
                STACK, STATE, TABLES, VMCB, data_start, diagnostics, image_base, image_bss_end,
                interrupt::CapturedInterrupts,
                msr::{read_msr, write_msr},
                svmvisor_resident_enter, svmvisor_resident_fault_offsets, svmvisor_resident_nmi,
                svmvisor_resident_sx, text_end,
            },
        },
    },
    svm::{
        dispatch::NativeEfer,
        permission_maps::{MsrAccess, Msrpm, Permission},
        startup::{NativeDestinationMode, NativeIcr, NativeStartupMailbox, try_lock_routes},
    },
};

/// # Safety
/// Call once in a legal loaded raw runtime allocation under live native CPL0
/// identity mappings. Caller has validated the entire 1MiB backing RW/X/WB,
/// original stack and this exact linked package. No CPU control is changed.
/// `output` is disjoint writable caller storage. Firmware owns allocation.
/// Every dense pool slot holds a relocated copy of this same package; the
/// private root maps the retained shared startup and cache-policy backing before arm.
pub unsafe extern "win64" fn prepare(
    base: u64,
    output: *mut ResidentDirectory,
    pool_base: u64,
    pool_bytes: u64,
    cpu_slot: u64,
    apic_id: u64,
) -> u64 {
    let start = image_base();
    let text_limit = ptr::addr_of!(text_end) as u64;
    let data = ptr::addr_of!(data_start) as u64;
    let end = ptr::addr_of!(image_bss_end) as u64;
    if output.is_null()
        || !super::is_valid_pool_slot(base, pool_base, pool_bytes, cpu_slot, apic_id)
        || base != start
        || base < 0x100000
        || base & 4095 != 0
        || base + 0x100000 > 0x40000000
        || base >> 21 != (base + 0xfffff) >> 21
        || text_limit <= base
        || text_limit > data
        || data > end
        || end > base + super::IMAGE_LIMIT_OFFSET
        || (text_limit | data | end) & 4095 != 0
    {
        return 1;
    }
    let state = unsafe { &mut *ptr::addr_of_mut!(STATE) };
    if state.prepared {
        return 2;
    }
    let root = ptr::addr_of_mut!(TABLES) as u64;
    let stack = ptr::addr_of_mut!(STACK) as u64;
    let fault_stack = ptr::addr_of_mut!(FAULT_STACK) as u64;
    let nmi_stack = ptr::addr_of_mut!(NMI_STACK) as u64;
    let gdt = ptr::addr_of_mut!(GDT_TSS) as u64;
    let idt = ptr::addr_of_mut!(IDT) as u64;
    let stack_top = stack + 17 * 4096;
    let fault_top = fault_stack + 5 * 4096;
    let nmi_top = nmi_stack + 2 * 4096;
    let fault_offsets = ptr::addr_of!(svmvisor_resident_fault_offsets);
    let mut handlers = core::array::from_fn(|vector| {
        (fault_offsets as u64).wrapping_add(unsafe { (*fault_offsets)[vector] } as i64 as u64)
    });
    handlers[30] = svmvisor_resident_sx as *const () as u64;
    // Vector 2: the returning host NMI gate (irq.S) on IST2, replacing the
    // terminal fault stub. Host-window NMIs are requeued through EVENTINJ.
    handlers[2] = svmvisor_resident_nmi as *const () as u64;
    let request = HostDescriptorRequest {
        gdt_base: gdt,
        tss_base: gdt + 128,
        idt_base: idt,
        rsp0: stack_top,
        ist1: fault_top,
        ist2: nmi_top,
        handlers,
    };
    let Ok(descriptors) = request.validate_terminal_ist() else {
        return 3;
    };
    unsafe {
        ptr::copy_nonoverlapping(
            descriptors.gdt().as_ptr(),
            gdt as *mut u8,
            descriptors.gdt().len(),
        );
        ptr::copy_nonoverlapping(
            descriptors.tss().as_ptr(),
            (gdt + 128) as *mut u8,
            descriptors.tss().len(),
        );
        ptr::copy_nonoverlapping(descriptors.idt().as_ptr(), idt as *mut u8, 4096);
        let gdtr = &mut *ptr::addr_of_mut!(GDTR);
        gdtr[..2].copy_from_slice(&descriptors.gdtr().limit.to_le_bytes());
        gdtr[2..].copy_from_slice(&gdt.to_le_bytes());
        let idtr = &mut *ptr::addr_of_mut!(IDTR);
        idtr[..2].copy_from_slice(&4095u16.to_le_bytes());
        idtr[2..].copy_from_slice(&idt.to_le_bytes());
    }
    let tables = unsafe { &mut (*ptr::addr_of_mut!(TABLES)).0 };
    tables[0][0] = (root + 4096) | 3;
    tables[1][0] = (root + 8192) | 3;
    tables[2][((base >> 21) & 511) as usize] = (root + 12288) | 3;
    for page in (base..end).step_by(4096) {
        if [stack, stack_top, fault_stack, fault_top, nmi_stack, nmi_top].contains(&page) {
            continue;
        }
        let flags = if page < text_limit {
            1
        } else if page < data {
            1 | (1 << 63)
        } else {
            3 | (1 << 63)
        };
        tables[3][((page >> 12) & 511) as usize] = page | flags;
    }
    // Every private root maps one shared RW/NX page through a fixed local
    // alias. Its physical backing remains inside the excluded monitor pool.
    let shared_alias = base + super::STARTUP_PAGE_OFFSET;
    tables[3][((shared_alias >> 12) & 511) as usize] =
        (pool_base + super::STARTUP_PAGE_OFFSET) | 3 | (1 << 63);
    // All slots share the BSP-owned policy backing. Local aliases remain
    // supervisor RW/NX and are disjoint from linked data and diagnostic aliases.
    for offset in (0..CACHE_SHARED_BYTES).step_by(4096) {
        let alias = base + CACHE_SHARED_OFFSET + offset;
        tables[3][((alias >> 12) & 511) as usize] =
            (pool_base + CACHE_SHARED_OFFSET + offset) | 3 | (1 << 63);
    }
    let vmcb = unsafe { &mut *ptr::addr_of_mut!(VMCB) };
    if vmcb.configure_native_boot_intercepts().is_err() {
        return 4;
    }
    unsafe {
        ptr::write(ptr::addr_of_mut!(MSRPM), Msrpm::native_boot());
    }
    let context = unsafe { &mut *ptr::addr_of_mut!(CONTEXT) };
    context.host_stack_top = stack_top;
    context.host_cr3 = root;
    context.guest_vmcb_pa = ptr::addr_of_mut!(VMCB) as u64;
    context.guest_vmcb_va = context.guest_vmcb_pa;
    context.host_extra_pa = ptr::addr_of_mut!(HOST_EXTRA) as u64;
    context.guest_frame_va = ptr::addr_of_mut!(FRAME) as u64;
    context.hsave_pa = ptr::addr_of_mut!(HSAVE) as u64;
    context.host_gdtr_va = ptr::addr_of_mut!(GDTR) as u64;
    context.host_idtr_va = ptr::addr_of_mut!(IDTR) as u64;
    context.owner_context = ptr::addr_of_mut!(STATE) as u64;
    let directory = ResidentDirectory {
        version: DIRECTORY_VERSION,
        arena_base: base,
        arena_bytes: 0x100000,
        context: ptr::addr_of_mut!(CONTEXT) as u64,
        vmcb: context.guest_vmcb_pa,
        auxiliary: ptr::addr_of_mut!(AUX) as u64,
        registers: context.guest_frame_va,
        npt: ptr::addr_of_mut!(NPT) as u64,
        arm: arm as *const () as u64,
        enter: svmvisor_resident_enter as *const () as u64,
        text_end: text_limit,
        data_start: data,
        memory_end: end,
        pool_base,
        pool_bytes,
        cpu_slot,
        apic_id,
        reserved: [0; 3],
    };
    unsafe {
        ptr::write(output, directory);
        POOL = (pool_base, pool_bytes);
        ASSIGNED_APIC_ID = apic_id as u32;
    }
    state.prepared = true;
    0
}

/// # Safety
/// Owning CPU, IF=0, native capture/memory admission complete, never-entered
/// exclusively stopped VMCB/frame/NPT already prepared in this owned image.
/// Callback sites identify the audited immutable callback until its guest RET.
/// `map` and `ids` are disjoint valid immutable caller arrays for this call;
/// IDs bind the complete retained pool to admitted native processors. x2APIC
/// must already be enabled on every CPU.
/// A nonnull `initial_icr` is aligned, readable and immutable for this call,
/// revalidated by DXE under the current mapping; its value is copied only.
/// The optional terminal endpoint has the same copied-input lifetime and its
/// complete 56-byte aligned mapping has been validated by the DXE caller.
///
/// Returns 0 when armed, otherwise the refused step: 1 runtime state or CPU
/// identity, 2 CPU capabilities, 3 EFER, 4 bootstrap ACK sites, 5 VMCB
/// controls, 6 memory map, 7 CPU inventory, 8 native x2APIC admission,
/// 9 startup ownership and its commit, 10 terminal endpoint, 13 VM_CR outside
/// the visible profile (11 and 12 keep their historical meanings).
/// Refusals occur before physical VM_CR INIT redirection is committed.
unsafe extern "win64" fn arm(
    efer: u64,
    resume: u64,
    ack: u64,
    after: u64,
    map: *const MemoryDescriptor,
    count: usize,
    ids: *const u32,
    id_count: usize,
    startup_owned: bool,
    initial_icr: *const u64,
    terminal_endpoint: *const TerminalEndpoint,
) -> u64 {
    let state = unsafe { &mut *ptr::addr_of_mut!(STATE) };
    if !state.prepared
        || state.armed
        || (!startup_owned && !initial_icr.is_null())
        || __cpuid_count(1, 0).ebx >> 24 != unsafe { ASSIGNED_APIC_ID }
    {
        return 1;
    }
    let Some(caps) = (unsafe { capabilities() }) else {
        return 2;
    };
    if caps.asid_count() < 3 {
        return 2;
    }
    // The visible VM_CR owner uses the target PPR's read-only LOCK semantics.
    if __cpuid_count(1, 0).eax != TARGET_SIGNATURE {
        return 2;
    }
    let endpoint = if terminal_endpoint.is_null() {
        None
    } else {
        // Caller validated this immutable input mapping for this arm invocation.
        // PPR57896 applies only to Family1Ah Model44h B0, signature00B40F40h.
        if !startup_owned
            || terminal_endpoint as usize & 7 != 0
            || __cpuid_count(1, 0).eax != TARGET_SIGNATURE
        {
            return 10;
        }
        let value = unsafe { terminal_endpoint.read() };
        if !value.valid() || unsafe { read_msr(MMIO_CFG_BASE_ADDR) } != value.mmio_config_msr {
            return 10;
        }
        Some(value)
    };
    if ids.is_null()
        || !(ids as usize).is_multiple_of(core::mem::align_of::<u32>())
        || id_count == 0
        || id_count > 32
        || id_count as u64 != unsafe { POOL.1 } / 0x100000
    {
        return 7;
    }
    let ids = unsafe { core::slice::from_raw_parts(ids, id_count) };
    let assigned_id = unsafe { ASSIGNED_APIC_ID };
    let Ok(icr_owner) = NativeIcr::admit(assigned_id, ids) else {
        return 7;
    };
    // SAFETY: arm owns the same native CPU/LAPIC with IF=0 and validated inventory;
    // initial_icr is the admitted immutable caller input; the retained pool owns both pages.
    let interrupts =
        match unsafe { CapturedInterrupts::capture(&caps, ids, assigned_id, initial_icr) } {
            Ok(interrupts) => interrupts,
            Err(error) => return error.code(),
        };
    let vmcb = unsafe { &mut *ptr::addr_of_mut!(VMCB) };
    let frame = unsafe { &*ptr::addr_of!(FRAME) };
    if let Some(endpoint) = endpoint {
        let slot = ids.iter().position(|&id| id == assigned_id).unwrap();
        if !unsafe { diagnostics::prepare(endpoint, slot, id_count) } {
            return 10;
        }
        let io = unsafe { &mut *ptr::addr_of_mut!(IOPM) };
        if io.set_range(0, 65536, Permission::Allow).is_err()
            || io.set_range(0xcf8, 8, Permission::Intercept).is_err()
            || unsafe { &mut *ptr::addr_of_mut!(MSRPM) }
                .set(MMIO_CFG_BASE_ADDR, MsrAccess::Write, Permission::Intercept)
                .is_err()
        {
            return 10;
        }
        vmcb.set_instruction_intercept(crate::svm::vmcb::InstructionIntercept::Ioio, true);
    }
    // Capture only enumerated same-CPU features, before the first guest entry.
    // Guest FXSR and INVLPG execute directly; VMRUN/VMEXIT owns EFER switching.
    let extended = __cpuid_count(0x8000_0001, 0);
    let extended21 = if __cpuid_count(0x8000_0000, 0).eax >= 0x8000_0021 {
        Some(__cpuid_count(0x8000_0021, 0).eax)
    } else {
        None
    };
    let admit_efer = NativeEfer::admit_native_visible_svm;
    let Ok(mut owner) =
        admit_efer(efer, extended.ecx, extended.edx, __cpuid_count(0x8000_0008, 0).ebx, extended21)
    else {
        return 3;
    };
    let vmcr = {
        // Native CPUID is not evidence against an already active SVM owner.
        // The visible EFER emulator permits later guest SVME changes, but takeover
        // still requires the original pre-monitor EFER.SVME to be clear.
        if efer & crate::arch::x86_64::msr::EFER_SVME != 0 {
            return 3;
        }
        if !super::minimal::valid(vmcb) {
            return 5;
        }
        let Ok(owner) = crate::svm::vmcr::VisibleVmCr::admit(unsafe { read_msr(VM_CR) }) else {
            return 13;
        };
        owner
    };
    let Ok(ack_owner) = NativeBootstrapAck::new(vmcb, frame, resume, ack, after) else {
        return 4;
    };
    let policy = caps.address_policy();
    if map.is_null()
        || !(map as usize).is_multiple_of(core::mem::align_of::<MemoryDescriptor>())
        || count == 0
        || count > MAX_DESCRIPTORS
    {
        return 6;
    }
    let descriptors = unsafe { core::slice::from_raw_parts(map, count) };
    if ValidatedMemoryMap::new(descriptors, policy.physical_bits()).is_err() {
        return 6;
    }
    // Preserve physical LAPIC delivery; intercept only the ICR for INIT/SIPI routing.
    unsafe {
        interrupts.configure_msrpm(&mut *ptr::addr_of_mut!(MSRPM));
    }
    if vmcb
        .set_permission_maps(ptr::addr_of!(IOPM) as u64, ptr::addr_of!(MSRPM) as u64, &policy)
        .is_err()
        || vmcb.set_guest_asid(1, &caps).is_err()
        || vmcb.set_nested_root(ptr::addr_of!(NPT) as u64, &policy).is_err()
        || vmcb.enable_native_nested_paging(&policy).is_err()
    {
        return 5;
    }
    if !startup_owned || id_count < 2 {
        return 9;
    }
    let shared = unsafe {
        core::slice::from_raw_parts(
            (POOL.0 + super::STARTUP_PAGE_OFFSET) as *const NativeStartupMailbox,
            id_count,
        )
    };
    if shared.iter().zip(ids).any(|(mailbox, &id)| mailbox.identity() != id) {
        return 9;
    }
    owner.enable_guest_startup();
    // Software startup commands retain the existing target-owned mailbox.
    // Ordinary fixed IPIs retain their physical destination and LAPIC state.
    let slot = ids.iter().position(|&id| id == assigned_id).unwrap();
    if !unsafe { super::cache::capture(POOL.0, slot, ids) } {
        return 14;
    }
    let Ok(routes) = try_lock_routes(shared) else {
        return 9;
    };
    let Ok(commit) = routes.prepare_destination_mode(slot, NativeDestinationMode::X2Apic) else {
        return 9;
    };
    unsafe {
        let original = read_msr(VM_CR);
        write_msr(VM_CR, original | VM_CR_R_INIT);
        if read_msr(VM_CR) != original | VM_CR_R_INIT {
            write_msr(VM_CR, original);
            return 9;
        }
    }
    commit.commit_destination_mode();
    unsafe {
        ptr::copy_nonoverlapping(map, ptr::addr_of_mut!(RAM).cast(), count);
        RAM_COUNT = count;
        PHYSICAL_BITS = policy.physical_bits();
    }
    state.ack = Some(ack_owner);
    state.efer = Some(owner);
    state.vmcr = Some(vmcr);
    state.icr = Some(icr_owner);
    state.icr_value = interrupts.icr_value();
    state.host_apic_base = interrupts.host_apic_base();
    state.startup_owned = startup_owned;
    state.slot = ids.iter().position(|&id| id == assigned_id).unwrap();
    state.count = id_count;
    state.terminal_endpoint = endpoint;
    // PAUSE filtering is optional; unsupported CPUs retain direct PAUSE.
    vmcb.configure_native_pause_filter(__cpuid_count(0x8000_000a, 0).edx);
    vmcb.set_event_intercept(crate::svm::vmcb::EventIntercept::Init, true);
    state.capabilities = Some(caps);
    state.armed = true;
    0
}

const _: crate::host::resident::ArmRuntime = arm;

/// Capability gating precedes every SVM-related MSR access in the caller.
/// Here VM_CR is read only after enumerated native AMD SVM. The shared native
/// encryption plan gates control reads and refuses unsupported enabled modes.
unsafe fn capabilities() -> Option<ValidatedCapabilities> {
    let basic = __cpuid_count(0, 0);
    let ext = __cpuid_count(0x80000000, 0);
    if basic.ebx != 0x68747541
        || basic.edx != 0x69746e65
        || basic.ecx != 0x444d4163
        || basic.eax < 1
        || ext.eax < 0x8000000a
    {
        return None;
    }
    let one = __cpuid_count(1, 0);
    let extone = __cpuid_count(0x80000001, 0);
    let svm = __cpuid_count(0x8000000a, 0);
    if one.ecx >> 31 != 0
        || extone.ecx & 4 == 0
        || extone.edx & ((1 << 20) | (1 << 26)) != ((1 << 20) | (1 << 26))
        || svm.edx & 1 != 1
        || svm.eax != 1
    {
        return None;
    }
    let width = __cpuid_count(0x80000008, 0).eax as u8;
    let encryption_leaf = if ext.eax >= 0x8000001f {
        let leaf = __cpuid_count(0x8000001f, 0);
        Some([leaf.eax, leaf.ebx, leaf.ecx, leaf.edx])
    } else {
        None
    };
    let plan = NativeEncryptionPlan::new(one.eax, width, encryption_leaf).ok()?;
    let encryption = plan
        .validate(
            plan.sys_cfg_msr().map(|msr| unsafe { read_msr(msr) }),
            plan.sev_status_msr().map(|msr| unsafe { read_msr(msr) }),
        )
        .ok()?;
    let low: u32;
    let high: u32;
    unsafe {
        asm!("rdmsr",in("ecx")VM_CR,out("eax")low,out("edx")high,options(nostack));
    }
    if u64::from(low) & VM_CR_SVMDIS != 0 || high != 0 {
        return None;
    }
    CapabilityEvidence {
        vendor: CpuVendor::Amd,
        svm: EvidenceFlag::Set,
        nested_paging: EvidenceFlag::Set,
        svm_revision: Some(svm.eax as u8),
        asid_count: Some(svm.ebx),
        physical_address_bits: Some(width),
        vm_cr_svmdis: EvidenceFlag::Clear,
        hypervisor_present: EvidenceFlag::Clear,
        encryption,
        optional: OptionalFeatures { nrip_save: svm.edx & 8 != 0, ..Default::default() },
    }
    .validate()
    .ok()
}
