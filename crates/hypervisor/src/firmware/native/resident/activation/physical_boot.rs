//! Physical AP bootstrap. Caller has returned successfully from EBS.
//! PI1.10 II-13.4.1 makes same-group notification ordering insufficient.
//! The Windows boot interposer owns this startup sequence.
use core::sync::atomic::AtomicU32;

use svmvisor_hypervisor::firmware::diagnostics::resident_boot::{
    AdmissionFailure, ApFailureObservation,
};
use svmvisor_hypervisor::{
    arch::x86_64::msr::{MTRR_DEF_TYPE, VM_CR_R_INIT},
    host::descriptors::HostDescriptorRequest,
    memory::mtrrs::{CAP_FIX, DEF_TYPE_E, DEF_TYPE_FE},
};
use uefi_raw::table::boot::AllocateType;

use super::*;
use resident::bootstrap_paging::BootstrapPaging;

const BOOT_BYTES: usize = 128 * 1024;
const AP_FAILURE_OFFSET: u64 = 120;
const _: () =
    assert!(AP_FAILURE_OFFSET as usize + core::mem::size_of::<ApFailureObservation>() <= 256);
const X2APIC_BASE_EXPECTED: u64 = apic::APIC_BASE_DEFAULT_ADDRESS | apic::APIC_BASE_X2APIC;

// One blocking MP observer at a time. No card access from this context.
static mut ADMISSION_CONTEXT: Option<AdmissionFailure> = None;
static ADMISSION_ACTIVE: AtomicBool = AtomicBool::new(false);
static mut BOOT: [Bootstrap; abi::MAX_RESIDENT_CPUS] =
    [const { Bootstrap([0; BOOT_BYTES]) }; abi::MAX_RESIDENT_CPUS];
static STARTED: AtomicBool = AtomicBool::new(false);
static mut LOW: u64 = 0;
static mut BOOT_CFG: Option<PagingConfig> = None;
static mut AP_TABLES: BootstrapPaging = BootstrapPaging::empty();
static mut BSP: usize = 0;

static mut BSP_INITIAL_ICR: u64 = 0;

static BSP_INITIAL_ICR_READY: AtomicBool = AtomicBool::new(false);
#[unsafe(no_mangle)]
static mut svmvisor_ap_boots: [u64; abi::MAX_RESIDENT_CPUS] = [0; abi::MAX_RESIDENT_CPUS];
#[unsafe(no_mangle)]
static mut svmvisor_ap_count: u32 = 0;
#[unsafe(no_mangle)]
static svmvisor_ap_discovery_failed: AtomicU32 = AtomicU32::new(0);
static AP_COMPLETED: AtomicU32 = AtomicU32::new(0);
static AP_FAILED: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" {
    static svmvisor_ap_trampoline: u8;
    static svmvisor_ap_trampoline_end: u8;
    static svmvisor_ap_protected_target: u8;
    static svmvisor_ap_protected: u8;
    static svmvisor_ap_root: u8;
    static svmvisor_ap_long_target: u8;
    static svmvisor_ap_gdt: u8;
    static svmvisor_ap_gdt_base: u8;
    static svmvisor_ap_wait: u8;
    static svmvisor_ap_wait_end: u8;
    static svmvisor_ap_wait_fault: u8;
    fn svmvisor_ap_entry64();
}

pub(super) struct LowAllocation<'a> {
    bs: &'a BootServices,
    base: u64,
    retained: bool,
}

impl LowAllocation<'_> {
    pub(super) fn retain(&mut self) {
        self.retained = true;
    }
}

impl Drop for LowAllocation<'_> {
    fn drop(&mut self) {
        if !self.retained {
            let status = unsafe { (self.bs.free_pages)(self.base, 1) };
            if status != Status::SUCCESS {}
        }
    }
}

#[repr(C, align(4096))]
struct Bootstrap([u8; BOOT_BYTES]);

pub(super) fn admission_clear() {
    ADMISSION_ACTIVE.store(false, Ordering::Release);
    unsafe {
        ADMISSION_CONTEXT = None;
    }
}

pub(super) fn admission_begin(operation: u32, processor: u32, apic_id: u32) {
    let mut value = AdmissionFailure::new(operation, 0, 0, 0, 0, 0);
    value.processor = processor;
    value.apic_id = apic_id;
    unsafe {
        ADMISSION_CONTEXT = Some(value);
    }
    ADMISSION_ACTIVE.store(true, Ordering::Release);
}

pub(super) fn admission_cpu_id(apic_id: u32) {
    if !ADMISSION_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    unsafe {
        if let Some(value) = &mut *ptr::addr_of_mut!(ADMISSION_CONTEXT) {
            value.apic_id = apic_id;
        }
    }
}

pub(super) fn admission_walk(
    error: paging::WalkError,
    cfg: PagingConfig,
    address: u64,
    last: Option<(u64, u64)>,
) {
    use paging::WalkError::*;
    let (reason, level) = match error {
        UnsupportedPhysicalWidth => (1, 0),
        FiveLevelUnsupported => (2, 0),
        NoncanonicalAddress => (3, 0),
        InvalidCr3 => (4, 0),
        UnreadableTable { level, .. } => (5, level),
        NotPresent { level } => (6, level),
        ReservedEntry { level } => (7, level),
        UnsupportedEntryBits { level } => (8, level),
        OneGiBUnsupported => (9, 0),
        IncompleteWalk => (10, 0),
    };
    let (item, observed) = match error {
        UnreadableTable { address, .. } => (address, 0),
        InvalidCr3 => (3, cfg.cr3),
        UnsupportedPhysicalWidth => (0x80000008, cfg.physical_bits as u64),
        FiveLevelUnsupported => (4, 1 << 12),
        NoncanonicalAddress => (address, address),
        _ => last.unwrap_or((cfg.cr3, 0)),
    };
    admission_hint(400 + reason + u32::from(level) * 16, item, observed, address);
}

pub(super) fn admission_hint(predicate: u32, item: u64, observed: u64, expected: u64) {
    if !ADMISSION_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    unsafe {
        if let Some(value) = &mut *ptr::addr_of_mut!(ADMISSION_CONTEXT) {
            if value.predicate == 0 {
                value.predicate = predicate;
                value.item = item;
                value.observed = observed;
                value.expected = expected;
            }
        }
    }
}

/// Serialized BSP preparation stages 16/17, before CPU/MAP are retained: end
/// the recorder armed by `admission_begin`, carry `code` and the slot into the
/// preparation record under `reason` (33-36) and publish the full record now,
/// while the caller's collected map still backs the transport validation.
/// # Safety
/// Same BSP-only pre-loader context as `admission_refused`; `map` is current.
pub(super) unsafe fn slot_admission_refused(
    reason: u32,
    count: usize,
    code: u64,
    processor: Cpu,
    map: &[MemoryDescriptor],
) -> Status {
    let value = admission_end(code);

    unsafe {
        card_boot::slot_admission_failure(value, count as u32, reason, processor, map);
    }

    unsupported(code)
}

/// All allocation and complete static-bootstrap construction happens before
/// publication. Runtime image owns BOOT, AP_TABLES and AP completion flags until reset.
/// The low LoaderCode page is consumed before successful activation returns;
/// no permanent OS reservation is inferred from that type.
pub(super) unsafe fn prepare(
    bs: &BootServices,
    bsp: usize,
    count: usize,
    cfg: PagingConfig,
) -> Result<LowAllocation<'_>, Status> {
    preparation_step(25, count as u64);
    if !(2..=abi::MAX_RESIDENT_CPUS).contains(&count) {
        return Err(Status::UNSUPPORTED);
    }
    let vm_cr = unsafe { rdmsr(VM_CR) };
    preparation_step(27, vm_cr);
    if vm_cr & VM_CR_R_INIT != 0 {
        return Err(Status::UNSUPPORTED);
    }
    let apic_base = unsafe { rdmsr(apic::APIC_BASE) };
    preparation_step(28, apic_base);
    if !x2apic_base_valid(apic_base) {
        return Err(Status::UNSUPPORTED);
    }
    // APM2 16.9/Table16-5: x2APIC is the only admitted host and guest bus.
    let cpuid1_ecx = __cpuid_count(1, 0).ecx;
    preparation_step(26, u64::from(cpuid1_ecx));
    if cpuid1_ecx & (1 << 21) == 0 {
        return Err(Status::UNSUPPORTED);
    }
    preparation_step(21, 0xfffff);
    let mut low = 0xfffff;
    let status = unsafe {
        (bs.allocate_pages)(AllocateType::MAX_ADDRESS, MemoryType::LOADER_CODE, 1, &mut low)
    };
    if status != Status::SUCCESS {
        preparation_failure(1, status.0 as u64, low);
        return Err(status);
    }
    preparation_step(21, low);
    let allocation = LowAllocation { bs, base: low, retained: false };
    if low == 0 || low >= 0x100000 || low & 4095 != 0 {
        return Err(Status::UNSUPPORTED);
    }
    unsafe {
        LOW = low;
    }
    preparation_step(22, 0);
    let mut map = unsafe { memory::collect(bs) }.map_err(preparation_map_failure)?;
    let mt = unsafe { mtrrs(cfg.physical_bits) }.map_err(unsupported)?;
    preparation_step(23, low);
    unsafe { validate(map.descriptors(), cfg, &mt, rdmsr(PAT), count) }.map_err(unsupported)?;
    map.release()?;
    preparation_step(24, low);
    let length = ptr::addr_of!(svmvisor_ap_trampoline_end) as usize
        - ptr::addr_of!(svmvisor_ap_trampoline) as usize;
    if length == 0 || length >= 4096 {
        return Err(Status::LOAD_ERROR);
    }
    unsafe {
        ptr::write_bytes(low as *mut u8, 0, 4096);
        ptr::copy_nonoverlapping(ptr::addr_of!(svmvisor_ap_trampoline), low as *mut u8, length);
    }
    let offset = |p: *const u8| p as usize - ptr::addr_of!(svmvisor_ap_trampoline) as usize;
    for (field, value) in [
        (
            ptr::addr_of!(svmvisor_ap_protected_target),
            low + offset(ptr::addr_of!(svmvisor_ap_protected)) as u64,
        ),
        (ptr::addr_of!(svmvisor_ap_gdt_base), low + offset(ptr::addr_of!(svmvisor_ap_gdt)) as u64),
        (ptr::addr_of!(svmvisor_ap_root), ptr::addr_of!(AP_TABLES) as u64),
        (ptr::addr_of!(svmvisor_ap_long_target), svmvisor_ap_entry64 as *const () as u64),
    ] {
        if value > u32::MAX as u64 || offset(field) + 4 > length {
            return Err(Status::UNSUPPORTED);
        }
        unsafe {
            ((low + offset(field) as u64) as *mut u32).write_unaligned(value as u32);
        }
    }
    for slot in 0..count {
        let base = boot_address(slot);
        let wait = ptr::addr_of!(svmvisor_ap_wait) as usize;
        let wait_bytes = ptr::addr_of!(svmvisor_ap_wait_end) as usize - wait;
        let fault_offset = ptr::addr_of!(svmvisor_ap_wait_fault) as usize - wait;
        if wait_bytes == 0 || wait_bytes > 4096 - 256 || fault_offset >= wait_bytes {
            return Err(Status::LOAD_ERROR);
        }
        let descriptors = HostDescriptorRequest {
            gdt_base: base + 4096,
            tss_base: base + 4160,
            idt_base: base + 8192,
            rsp0: base + BOOT_BYTES as u64,
            ist1: base + 32768,
            // The AP bootstrap IDT keeps every gate on IST0 except #DF (IST1),
            // so no gate selects IST2; this validated-but-unused pointer only
            // satisfies the descriptor builder (NMI stays on IST0 here, with
            // interrupts off during the trampoline).
            ist2: base + 36864,
            handlers: [base + 256 + fault_offset as u64; 256],
        }
        .validate()
        .map_err(|_| Status::UNSUPPORTED)?;
        unsafe {
            (base as *mut u64).write(base + BOOT_BYTES as u64);
            ((base + 8) as *mut u16).write_unaligned(39);
            ((base + 10) as *mut u64).write_unaligned(base + 4096);
            ((base + 24) as *mut u16).write_unaligned(4095);
            ((base + 26) as *mut u64).write_unaligned(base + 8192);
            ((base + 48) as *mut u32).write(1u32 << slot);
            ((base + 56) as *mut u64).write(ptr::addr_of!(AP_COMPLETED) as u64);
            ((base + 64) as *mut u64).write(ptr::addr_of!(AP_FAILED) as u64);
            ((base + 80) as *mut u64).write(base + 256);
            ((base + 88) as *mut u32).write(0);
            ((base + 96) as *mut u64).write(0);
            // Assembly claims its identity before touching a stack. BSP then
            // releases exactly one CPU into the shared capture owner at a time.
            ((base + 104) as *mut u32).write(0);
            ((base + 108) as *mut u32).write(0);
            // Numeric guest-accessible witness pointer, copied before release.
            // The callback revalidates its mapping; copied code has no fixup.
            ((base + 112) as *mut u64).write(ptr::addr_of!(GUEST_ACK) as u64);
            ((base + AP_FAILURE_OFFSET) as *mut ApFailureObservation).write(ApFailureObservation {
                reason: 0,
                reserved: 0,
                observation: 0,
            });
            ptr::copy_nonoverlapping(wait as *const u8, (base + 256) as *mut u8, wait_bytes);
            ptr::copy_nonoverlapping(descriptors.gdt().as_ptr(), (base + 4096) as *mut u8, 40);
            ptr::copy_nonoverlapping(descriptors.tss().as_ptr(), (base + 4160) as *mut u8, 104);
            ptr::copy_nonoverlapping(descriptors.idt().as_ptr(), (base + 8192) as *mut u8, 4096);
        }
    }
    unsafe {
        BOOT_CFG = Some(cfg);
        BSP = bsp;
    }
    Ok(allocation)
}

/// Validate complete shared bootstrap closure before any physical INIT. The
/// low page uses architectural fixed-MTRR bytes; variable-only Mtrrs rejects it.
pub(super) unsafe fn validate(
    map: &[MemoryDescriptor],
    cfg: PagingConfig,
    mt: &Mtrrs,
    pat: u64,
    count: usize,
) -> Result<(), u64> {
    validate_x2apic()?;
    for slot in 0..count {
        unsafe {
            mapped(map, cfg, mt, pat, boot_address(slot), BOOT_BYTES as u64, true, false)?;
        }
    }
    let low = unsafe { LOW };
    if !ram_span(map, low, 4096) {
        admission_hint(130, low, 4096, 1);
        return Err(30);
    }
    let enabled = DEF_TYPE_E | DEF_TYPE_FE;
    if mt.default & enabled != enabled {
        admission_hint(131, MTRR_DEF_TYPE as u64, mt.default, enabled);
        return Err(30);
    }
    let capability = unsafe { rdmsr(MTRR_CAP) };
    if capability & CAP_FIX == 0 {
        admission_hint(132, MTRR_CAP as u64, capability, CAP_FIX);
        return Err(30);
    }
    let (msr, shift) = Mtrrs::fixed_range_register(low).ok_or_else(|| {
        admission_hint(133, low, low, 0x100000);
        30u64
    })?;
    let fixed = unsafe { rdmsr(msr) };
    if (fixed >> shift) & 255 != 6 {
        admission_hint(134, msr as u64, fixed, shift as u64 | (6u64 << 32));
        return Err(30);
    }
    if pat & 255 != 6 {
        admission_hint(135, PAT as u64, pat, 6);
        return Err(30);
    }
    let mut last = None;
    let translation = paging::translate(cfg, low, |address| {
        if !ram_span(map, address, 8) || !mt.page_is_wb(address & !4095) {
            admission_hint(
                108,
                address,
                u64::from(ram_span(map, address, 8))
                    | u64::from(mt.page_is_wb(address & !4095)) << 1,
                3,
            );
            return None;
        }
        let entry = unsafe { ptr::read_volatile(address as *const u64) };
        last = Some((address, entry));
        if entry & 0x18 != 0 {
            admission_hint(109, address, entry, 0x18);
            None
        } else {
            Some(entry)
        }
    })
    .map_err(|error| {
        admission_walk(error, cfg, low, last);
        30u64
    })?;
    if translation.physical_address != low
        || !translation.writable
        || !translation.executable
        || (pat >> (translation.pat_index * 8)) & 255 != 6
    {
        let (predicate, observed, expected) = if translation.physical_address != low {
            (110, translation.physical_address, low)
        } else if !translation.writable {
            (111, 0, 1)
        } else if !translation.executable {
            (112, 0, 1)
        } else {
            (114, pat, translation.pat_index as u64)
        };
        admission_hint(predicate, low, observed, expected);
        return Err(30);
    }
    Ok(())
}

/// Recheck the current CPU's enabled x2APIC. x2APIC performs no MMIO access,
/// so no LAPIC page mapping or cache type participates.
pub(super) fn validate_x2apic() -> Result<(), u64> {
    let base = unsafe { rdmsr(apic::APIC_BASE) };
    if !x2apic_base_valid(base) {
        admission_hint(139, apic::APIC_BASE as u64, base, X2APIC_BASE_EXPECTED);
        return Err(39);
    }
    Ok(())
}

pub(super) unsafe fn admit_processors(bs: &BootServices) -> Result<(), Status> {
    admission_begin(1, unsafe { BSP } as u32, unsafe { CPU_IDS[BSP] });
    unsafe { build_owned_root() }.map_err(|code| admission_refused(admission_end(code)))?;
    admission_clear();
    let inventory =
        unsafe { resident::processors::inspect_with(bs, admission_observer) }.map_err(|error| {
            admission_clear();

            let resident::processors::Error::Admission(value) = error;
            admission_refused(value)
        })?;
    if inventory.processors().len() != unsafe { CPU_COUNT }
        || inventory.bsp_number() != unsafe { BSP }
        || inventory
            .processors()
            .iter()
            .enumerate()
            .any(|(slot, p)| p.identity.apic_id != unsafe { CPU_IDS[slot] })
    {
        let (observed, expected, item) = if inventory.processors().len() != unsafe { CPU_COUNT } {
            (inventory.processors().len() as u64, unsafe { CPU_COUNT } as u64, 0)
        } else if inventory.bsp_number() != unsafe { BSP } {
            (inventory.bsp_number() as u64, unsafe { BSP } as u64, 1)
        } else {
            let (slot, p) = inventory
                .processors()
                .iter()
                .enumerate()
                .find(|(s, p)| p.identity.apic_id != unsafe { CPU_IDS[*s] })
                .unwrap();
            (p.identity.apic_id as u64, unsafe { CPU_IDS[slot] } as u64, 2 + slot as u64)
        };
        let mut failure = AdmissionFailure::new(5, 1, item, observed, expected, 0);
        if item >= 2 {
            failure.processor = (item - 2) as u32;
            failure.apic_id = observed as u32;
        } else {
            failure.processor = unsafe { BSP } as u32;
            failure.apic_id = unsafe { CPU_IDS[BSP] };
        }
        return Err(admission_refused(failure));
    }
    Ok(())
}

/// Caller exclusively owns BSP after successful EBS return, still using the
/// admitted root/image, IF=0. The BSP's original root remains its guest-owned
/// continuation; AP guests use the independent retained bootstrap root. No
/// original firmware paging structures are needed by APs after startup. The
/// low LoaderCode page is consumed before success. No firmware calls or allocation remain. Failures
/// retain both runtime and bootstrap resources. This diagnostic has bounded
/// poll/settle iterations, not a calibrated physical startup timing claim.
pub(super) unsafe extern "efiapi" fn start() -> u64 {
    let flags: u64;
    unsafe {
        asm!("pushfq; pop {}", out(reg) flags, options(preserves_flags));
    }
    if flags & 0x200 != 0 || STARTED.load(Ordering::Acquire) || !READY.load(Ordering::Acquire) {
        return 32;
    }
    // Firmware/consumer page tables may have changed since MP observation.
    // Recheck before publishing a target or issuing the physical startup IPI.
    let preflight = (|| -> Result<(), u64> {
        let processor = unsafe { cpu() }?;
        let cfg = unsafe { config(processor) }?;
        let mt = unsafe { mtrrs(processor.physical_bits) }?;
        let map = unsafe {
            core::slice::from_raw_parts(ptr::addr_of!(MAP).cast::<MemoryDescriptor>(), MAP_COUNT)
        };
        if !x2apic_base_valid(unsafe { rdmsr(apic::APIC_BASE) }) {
            return Err(39);
        }
        let pat = unsafe { rdmsr(PAT) };
        unsafe {
            validate_current_closure(map, cfg, &mt, pat, CPU_COUNT)?;
            validate_owned_root(map, &mt, pat)?;
        }
        Ok(())
    })();
    if let Err(code) = preflight {
        return code;
    }
    if STARTED.swap(true, Ordering::AcqRel) {
        return 32;
    }

    {
        // Capture before any physical command. Restoring hardware ICR low
        // would send another IPI; arm seeds its existing guest readback
        // overlay from this retained value instead (APM2 16.5).
        let initial = unsafe { rdmsr(apic::ICR_MSR) };
        unsafe { BSP_INITIAL_ICR = initial };
        BSP_INITIAL_ICR_READY.store(true, Ordering::Release);
    }
    if !x2apic_base_valid(unsafe { rdmsr(apic::APIC_BASE) }) {
        return 31;
    }
    // PI inspect_with requires total=enabled, every CPU healthy, and a complete
    // returned observation. No subset or disabled processor can be broadcast to.
    let count = unsafe { CPU_COUNT };
    unsafe { asm!("mfence", options(nostack, preserves_flags)) };
    // APM2 16.5/Table16-4 pp643-644 permits all-excluding-self for both
    // edge INIT and SIPI. No APIC physical-ID width participates in shorthand
    // matching, including the PPR57896 APIC410 reset-to-four-bit interval.
    if let Err(code) = unsafe { send_startup(0x000c_4500) } {
        AP_FAILED.store(u32::MAX, Ordering::Release);
        return code;
    }
    for _ in 0..10000 {
        core::hint::spin_loop();
    }
    // Send the STARTUP IPI twice with a delay between, as the MP init protocol
    // recommends (APM2 rev3.44 14.1.3): the second covers an AP that had not
    // reached wait-for-SIPI when the first arrived. A duplicate SIPI to an AP
    // that already left wait-for-SIPI is dropped by hardware, so the trampoline
    // (physical.S) never re-enters for it; the `lock btsl $0, 104(%r12)` slot
    // claim there is a safety net that faults cleanly (jc .Lap_discovery_failed)
    // should a genuine re-entry ever occur, so it does not corrupt state.
    // No calibrated time base exists here (no TSC-frequency helper), so these
    // remain raw spin counts, not a measured startup deadline.
    for _ in 0..2 {
        if let Err(code) = unsafe { send_startup(0x000c_0600 | (LOW >> 12) as u32) } {
            AP_FAILED.store(u32::MAX, Ordering::Release);
            return code;
        }
        for _ in 0..10000 {
            core::hint::spin_loop();
        }
    }
    // All firmware CPUs must first reach the owned release wait. A slot claim
    // is a CPU rendezvous only: it is explicitly NOT evidence of DMA silence.
    // The complete enabled/healthy inventory was admitted before broadcast;
    // hotplug or any undiscovered processor remains outside this boot profile.
    for slot in 0..count {
        if slot == unsafe { BSP } {
            continue;
        }
        let claimed = unsafe { &*((boot_address(slot) + 104) as *const AtomicU32) };
        let mut parked = false;
        for _ in 0..20_000_000 {
            if svmvisor_ap_discovery_failed.load(Ordering::Acquire) != 0
                || AP_FAILED.load(Ordering::Acquire) != 0
            {
                return 45;
            }
            if claimed.load(Ordering::Acquire) == 1 {
                parked = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !parked {
            return 34;
        }
    }
    match unsafe { super::iommu_takeover::take_over() } {
        Ok(()) => super::iommu_takeover::PROTECTED_GUEST_CONTRACT_PENDING,
        Err(reason) => reason,
    }
}

/// The existing guest continuation is retained for the eventual complete
/// virtual-IOMMU profile. Physical protection alone cannot call it: this boot
/// profile holds AP releases and the BSP until that separate contract exists.
#[allow(dead_code)]
unsafe fn release_guests(count: usize) -> u64 {
    for slot in 0..count {
        if slot == unsafe { BSP } {
            continue;
        }
        let release = unsafe { &*((boot_address(slot) + 108) as *const AtomicU32) };

        unsafe { card_boot::stage(3, slot as u32, 0) };
        release.store(1, Ordering::Release);
        let mut done = false;
        for _ in 0..20_000_000 {
            if svmvisor_ap_discovery_failed.load(Ordering::Acquire) != 0 {
                // No slot is authoritative for an unknown/duplicate identity.
                AP_FAILED.store(u32::MAX, Ordering::Release);
                return 45;
            }
            let failed = AP_FAILED.load(Ordering::Acquire);
            if failed != 0 {
                // AP owns its BOOT record until locked failure publication.
                // The acquire above orders these final volatile field reads.
                // Only the serially released AP is authoritative for this batch.

                if failed == 1u32 << slot {
                    let sample = unsafe {
                        ((boot_address(slot) + AP_FAILURE_OFFSET) as *const ApFailureObservation)
                            .read_volatile()
                    };
                    unsafe { card_boot::ap_failure(slot as u32, count as u32, sample) };
                }
                return 33;
            }
            if AP_COMPLETED.load(Ordering::Acquire) & (1u32 << slot) != 0 {
                // The copied guest continuation stores CR3 before its locked
                // completion publication; this acquire precedes the read.
                let observed = unsafe { ((boot_address(slot) + 96) as *const u64).read_volatile() };

                if observed != ptr::addr_of!(AP_TABLES) as u64 {
                    AP_FAILED.fetch_or(1u32 << slot, Ordering::AcqRel);
                    return 44;
                }
                done = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !done {
            AP_FAILED.fetch_or(1u32 << slot, Ordering::AcqRel);
            return 34;
        }
    }
    unsafe {
        card_boot::stage(4, BSP as u32, 0);
        abi::svmvisor_resident_callback(ptr::null_mut(), COOKIE as *mut c_void);
    }
    // A normal refusal also returns from the callback. Only the immutable
    // post-VMMCALL guest epilogue publishes this bit after NativeBootstrapAck.
    if GUEST_ACK.load(Ordering::Acquire) & (1u32 << unsafe { BSP }) == 0 {
        return 35;
    }
    AP_COMPLETED.fetch_or(1u32 << unsafe { BSP }, Ordering::Release);
    0
}

/// BSP-only saved pre-bootstrap ICR, copied by arm while the admitted DXE
/// mapping is still live. This numeric field is never a runtime virtual pointer.
/// # Safety
/// Called from the serialized native callback after start's successful-EBS
/// preflight. The caller revalidates this field's current readable mapping.

pub(super) unsafe fn initial_icr(slot: usize) -> Result<*const u64, u64> {
    if slot != unsafe { BSP } {
        return Ok(ptr::null());
    }
    if !BSP_INITIAL_ICR_READY.load(Ordering::Acquire) {
        return Err(46);
    }
    Ok(ptr::addr_of!(BSP_INITIAL_ICR))
}

/// Inventory is immutable before any activation callback executes.
pub(super) unsafe fn is_bsp(slot: usize) -> bool {
    slot == unsafe { BSP }
}

pub(super) unsafe fn bsp_slot() -> usize {
    unsafe { BSP }
}

/// Returning MP reader: complete AP-local controls, capability, cache and all
/// retained resource mappings are admitted before the first physical INIT.
/// Firmware can still change AP state afterward; capture revalidates locally.
fn admission_observer() -> Result<resident::processors::Identity, resident::processors::Error> {
    admission_begin(3, u32::MAX, u32::MAX);
    let result = (|| -> Result<(), u64> {
        let processor = unsafe { cpu() }?;
        unsafe {
            if let Some(value) = &mut *ptr::addr_of_mut!(ADMISSION_CONTEXT) {
                value.apic_id = processor.apic_id;
                value.processor = CPU_IDS[..CPU_COUNT]
                    .iter()
                    .position(|&id| id == processor.apic_id)
                    .map_or(u32::MAX, |v| v as u32);
            }
        }
        let current = unsafe { config(processor) }?;
        let vm_cr = unsafe { rdmsr(VM_CR) };
        if vm_cr & VM_CR_R_INIT != 0 {
            admission_hint(38, VM_CR as u64, vm_cr, 0);
            return Err(38);
        }
        let apic_base = unsafe { rdmsr(apic::APIC_BASE) };
        if !x2apic_base_valid(apic_base) {
            admission_hint(138, apic::APIC_BASE as u64, apic_base, X2APIC_BASE_EXPECTED);
            return Err(38);
        }
        let mt = unsafe { mtrrs(processor.physical_bits) }?;
        let pat = unsafe { rdmsr(PAT) };

        let map = unsafe {
            core::slice::from_raw_parts(ptr::addr_of!(MAP).cast::<MemoryDescriptor>(), MAP_COUNT)
        };
        let cfg = unsafe { BOOT_CFG }.ok_or_else(|| {
            admission_hint(140, 0, 0, 1);
            38u64
        })?;
        if current.nxe != cfg.nxe || current.physical_bits != cfg.physical_bits {
            admission_hint(
                238,
                0,
                (current.physical_bits as u64) << 1 | u64::from(current.nxe),
                (cfg.physical_bits as u64) << 1 | u64::from(cfg.nxe),
            );
            return Err(38);
        }
        let count = unsafe { CPU_COUNT };
        unsafe {
            validate_current_closure(map, current, &mt, pat, count)?;
            validate_owned_root(map, &mt, pat)?;
        }
        let prepared = unsafe { directories() };
        for (slot, d) in prepared.iter().enumerate() {
            unsafe {
                mapped(map, current, &mt, pat, d.arena_base, d.arena_bytes, true, true)?;
                host_closure(prepared, slot, map, processor, &mt, pat)?;
            }
        }
        // This is allocation/bootstrap admission, not the final cache bank.
        // F7 CpuDxe synchronizes BSP/AP MTRRs in its EBS callbacks. Capture the
        // authoritative bank only after original EBS succeeds and all APs are
        // under our bootstrap owner, before any guest entry.
        Ok(())
    })();
    result.map_err(|code| resident::processors::Error::Admission(admission_end(code)))?;
    let identity = resident::processors::capture_identity().map_err(|error| match error {
        resident::processors::Error::Admission(mut value) => {
            if let Some(context) = unsafe { ADMISSION_CONTEXT } {
                value.apic_id = context.apic_id;
                value.processor = context.processor;
            }
            resident::processors::Error::Admission(value)
        }
    });
    admission_clear();
    identity
}

/// Before MP admission/publication only: the complete callback lives in the
/// retained DXE image, and all raw per-CPU entries/tables live in the pool.
/// No firmware paging page is copied or linked into the owned root. APM2
/// 5.3.3/5.4; UEFI2.11 7.2/Table7.10 and 8.4.1 runtime image fixups.
unsafe fn build_owned_root() -> Result<(), u64> {
    let cfg = unsafe { BOOT_CFG }.ok_or_else(|| {
        admission_hint(140, 0, 0, 1);
        43u64
    })?;
    let mt = unsafe { mtrrs(cfg.physical_bits) }?;
    let pat = unsafe { rdmsr(PAT) };
    let map = unsafe {
        core::slice::from_raw_parts(ptr::addr_of!(MAP).cast::<MemoryDescriptor>(), MAP_COUNT)
    };
    let (image, bytes) = unsafe { IMAGE };
    let tables = unsafe { &mut *ptr::addr_of_mut!(AP_TABLES) };
    tables.initialize(ptr::addr_of!(AP_TABLES) as u64).map_err(|error| {
        admission_hint(141, ptr::addr_of!(AP_TABLES) as u64, error as u64, 0);
        43u64
    })?;
    let count = unsafe { CPU_COUNT };
    for (base, length, raw) in
        core::iter::once((image, bytes, false)).chain((0..count).map(|slot| {
            let d = unsafe { DIRECTORIES[slot] };
            (d.arena_base, d.arena_bytes, true)
        }))
    {
        let end = base.checked_add(length).ok_or_else(|| {
            admission_hint(142, base, length, u64::MAX - base);
            43u64
        })?;
        if base & 4095 != 0 || length == 0 || length > 16 * 1024 * 1024 || end > 1 << 40 {
            admission_hint(142, base, length, 16 * 1024 * 1024);
            return Err(43);
        }
        // Validate current firmware accesses before reading/copying leaf policy.
        let mut cursor = base;
        while cursor < end {
            let chunk = (end - cursor).min(2 * 1024 * 1024);
            unsafe {
                mapped(map, cfg, &mt, pat, cursor, chunk, raw, raw)?;
            }
            cursor += chunk;
        }
        let mut page = base;
        while page < end {
            let mut last = None;
            let t = paging::translate(cfg, page, |address| {
                // The preceding mapped() proves this exact table-fetch closure.
                let entry = unsafe { ptr::read_volatile(address as *const u64) };
                last = Some((address, entry));
                Some(entry)
            })
            .map_err(|error| {
                admission_walk(error, cfg, page, last);
                43u64
            })?;
            let wait_page = (0..count).any(|slot| page == boot_address(slot));
            tables.map_page(page, t.writable, t.executable || wait_page).map_err(|error| {
                admission_hint(143, page, error as u64, 0);
                43u64
            })?;
            page += 4096;
        }
    }
    tables.map_page(unsafe { LOW }, true, true).map_err(|error| {
        admission_hint(144, unsafe { LOW }, error as u64, 0);
        43u64
    })?;
    for slot in 0..count {
        unsafe {
            ((boot_address(slot) + 72) as *mut u32).write(CPU_IDS[slot]);
            // A BSP or unknown identity never receives an AP stack/record.
            svmvisor_ap_boots[slot] = if slot == BSP { 0 } else { boot_address(slot) };
        }
    }
    unsafe { svmvisor_ap_count = count as u32 };
    Ok(())
}

/// Both MP admission and pre-INIT rechecks prove the independent root's actual
/// callback closure. Original firmware configuration remains BOOT_CFG; APs
/// capture this root with NXE explicitly enabled by physical.S.
unsafe fn validate_owned_root(map: &[MemoryDescriptor], mt: &Mtrrs, pat: u64) -> Result<(), u64> {
    let mut cfg = unsafe { BOOT_CFG }.ok_or_else(|| {
        admission_hint(140, 0, 0, 1);
        43u64
    })?;
    cfg.cr3 = ptr::addr_of!(AP_TABLES) as u64;
    cfg.nxe = true;
    let count = unsafe { CPU_COUNT };
    unsafe {
        validate(map, cfg, mt, pat, count)?;
    }
    let (image, bytes) = unsafe { IMAGE };
    let mut cursor = image;
    while cursor < image + bytes {
        let chunk = (image + bytes - cursor).min(2 * 1024 * 1024);
        unsafe {
            mapped(map, cfg, mt, pat, cursor, chunk, false, false)?;
        }
        cursor += chunk;
    }
    for slot in 0..count {
        let d = unsafe { DIRECTORIES[slot] };
        unsafe {
            mapped(map, cfg, mt, pat, d.arena_base, d.arena_bytes, true, true)?;
        }
        let mut last = None;
        let t = paging::translate(cfg, boot_address(slot), |address| unsafe {
            let entry = (&*ptr::addr_of!(AP_TABLES)).read(address);
            if let Some(value) = entry {
                last = Some((address, value));
            }
            entry
        })
        .map_err(|error| {
            admission_walk(error, cfg, boot_address(slot), last);
            43u64
        })?;
        if !t.executable || !t.writable || t.user {
            admission_hint(
                150,
                boot_address(slot),
                u64::from(t.writable) | u64::from(t.executable) << 1 | u64::from(t.user) << 2,
                3,
            );
            return Err(43);
        }
    }
    Ok(())
}

/// Firmware MP callbacks and a normal loader may select different roots. Prove
/// the current identity closure instead of treating the installation CR3 value
/// as a permanent lease. All checks precede physical INIT.
unsafe fn validate_current_closure(
    map: &[MemoryDescriptor],
    cfg: PagingConfig,
    mt: &Mtrrs,
    pat: u64,
    count: usize,
) -> Result<(), u64> {
    unsafe {
        validate(map, cfg, mt, pat, count)?;
    }
    let (image, bytes) = unsafe { IMAGE };
    let mut cursor = image;
    while cursor < image + bytes {
        let chunk = (image + bytes - cursor).min(2 * 1024 * 1024);
        unsafe {
            mapped(map, cfg, mt, pat, cursor, chunk, false, false)?;
        }
        cursor += chunk;
    }
    // The image walk above makes AP_TABLES safe to read through this current
    // root. Its saved leaf permissions describe every original callback page;
    // only the copied AP wait page needs execution solely under the owned root.
    let mut owned = cfg;
    owned.cr3 = ptr::addr_of!(AP_TABLES) as u64;
    owned.nxe = true;
    let mut page = image;
    while page < image + bytes {
        let mut last = None;
        let expected = paging::translate(owned, page, |address| unsafe {
            let entry = (&*ptr::addr_of!(AP_TABLES)).read(address);
            if let Some(value) = entry {
                last = Some((address, value));
            }
            entry
        })
        .map_err(|error| {
            admission_walk(error, owned, page, last);
            43u64
        })?;
        let wait_page = (0..count).any(|slot| page == boot_address(slot));
        unsafe {
            mapped(
                map,
                cfg,
                mt,
                pat,
                page,
                4096,
                expected.writable,
                expected.executable && !wait_page,
            )?;
        }
        page += 4096;
    }
    for slot in 0..count {
        let d = unsafe { DIRECTORIES[slot] };
        unsafe {
            mapped(map, cfg, mt, pat, d.arena_base, d.arena_bytes, true, true)?;
        }
    }
    Ok(())
}

/// BSP-only before resident capture, IF=0 and admitted x2APIC. APM2 16.5/16.13:
/// all-excluding-self ignores the destination, so preserve the ICR high half.
/// x2APIC has no software-polled delivery status to wait for.
unsafe fn send_startup(command: u32) -> Result<(), u64> {
    unsafe {
        let high = rdmsr(apic::ICR_MSR) & !0xffff_ffff;
        wrmsr(apic::ICR_MSR, high | u64::from(command));
    }
    Ok(())
}

fn admission_end(code: u64) -> AdmissionFailure {
    ADMISSION_ACTIVE.store(false, Ordering::Release);
    let mut value = unsafe { ptr::addr_of_mut!(ADMISSION_CONTEXT).replace(None) }
        .unwrap_or(AdmissionFailure::new(3, 0, 0, 0, 0, 0));
    if value.predicate == 0 {
        value.predicate = code as u32;
    }
    value.status = code;
    value
}

fn admission_refused(value: AdmissionFailure) -> Status {
    card_boot::admission_failure(value, unsafe { CPU_COUNT } as u32);
    Status::UNSUPPORTED
}

fn boot_address(slot: usize) -> u64 {
    unsafe { ptr::addr_of_mut!(BOOT).cast::<Bootstrap>().add(slot) as u64 }
}

// APM2 16.3.1/Figure16-2 and 16.10: enabled x2APIC at the fixed base. ABA
// extends through bit51, not only bit31.
fn x2apic_base_valid(base: u64) -> bool {
    base & !(apic::APIC_BASE_ADDRESS | apic::APIC_BASE_X2APIC | apic::APIC_BASE_BSP) == 0
        && base & apic::APIC_BASE_ADDRESS == apic::APIC_BASE_DEFAULT_ADDRESS
        && base & apic::APIC_BASE_X2APIC == apic::APIC_BASE_X2APIC
}
