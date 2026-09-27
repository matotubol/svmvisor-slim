//! Executable per-CPU resident host. UEFI allocation/capture stays in DXE.
//! This image has one guest, no migration and no host FP/SIMD use. All linked
//! code (including panic/compiler builtins) needs the no-FP instruction audit.

use core::sync::atomic::{AtomicU32, AtomicU64};

use svmvisor_card_abi::endpoint::TerminalEndpoint;

#[cfg(test)]
use crate::host::resident::runtime::linked_symbols::*;
// Child files still name `fetch`, `terminal`, the pool offsets and `is_valid_pool_slot`
// as `super::..` inside function bodies that moved here unchanged.
use crate::{
    arch::x86_64::{capabilities::ValidatedCapabilities, registers::GuestRegisters},
    boot::memory::{MAX_DESCRIPTORS, MemoryDescriptor},
    guest::continuation::NativeBootstrapAck,
    host::resident::{
        BridgeContext, IMAGE_LIMIT_OFFSET, STARTUP_PAGE_OFFSET, fetch, is_valid_pool_slot,
        runtime::exit::dispatch, terminal,
    },
    memory::{
        address::PAGE_BYTES,
        npt::{CACHE_TABLE_COUNT, CacheTableStorage},
    },
    svm::{
        control_msrs::VisibleSvmControls,
        dispatch::NativeEfer,
        instructions::NativeSvmInstructions,
        permission_maps::{Iopm, Msrpm},
        startup::{NativeIcr, NativeStartupState},
        target_msrs::TargetMsrPolicy,
        vmcb::{Vmcb, VmcbCacheOwner},
    },
};

pub use crate::host::resident::runtime::arm::prepare;

/// Runtime image address, kept opaque to constant propagation. Shared arena offsets
/// lie outside the linked image and must be added at runtime, never encoded as ELF
/// relocations into unrelated linker storage.
#[inline(never)]
fn image_base() -> u64 {
    let mut base = core::ptr::addr_of!(image_start) as u64;
    // SAFETY: the empty assembly preserves the address and all machine state. The
    // read/write register operand prevents folding later arena offsets into the
    // image_start relocation even when the whole payload uses one codegen unit.
    unsafe {
        core::arch::asm!("/* {base} */", base = inout(reg) base,
            options(nomem, nostack, preserves_flags));
    }
    base
}

mod arm;
mod cache;
mod configuration;
mod diagnostics;
#[cfg(feature = "native-entry-trial")]
mod entry;
mod exit;
mod guest_reader;
mod interrupt;
mod local;
mod maintenance;
mod minimal;
mod msr;
mod pmu;
mod service;
mod startup;
mod stop;
#[cfg(test)]
mod tests;

const INITIAL_STATE: State = State {
    prepared: false,
    armed: false,
    capabilities: None,
    vmcb_cache: VmcbCacheOwner::new(),
    ack: None,
    efer: None,
    pmu: None,
    vmcr: None,
    svm_controls: None,
    target_msrs: None,
    svm_instructions: None,
    icr: None,
    icr_value: 0,
    host_apic_base: 0,
    startup_owned: false,
    startup: NativeStartupState::Running,
    guest_started: false,
    pause_filter_supported: false,
    slot: 0,
    count: 0,
    pending_fault: false,
    exits: 0,
    stopped: 0,
    stopped_rip: 0,
    stopped_info1: 0,
    stopped_info2: 0,
    routing_retries: 0,
    terminal_endpoint: None,
    stopped_valid: false,
};

#[unsafe(no_mangle)]
static svmvisor_resident_init_acks: AtomicU64 = AtomicU64::new(0);

/// Set to 1 by the host NMI gate (vector 2, nmi.S) when a physical NMI is
/// taken in a host GIF window, and cleared after transfer to V_NMI. This CPU is
/// the only writer (its own NMI) and reader (its own dispatcher).
#[unsafe(no_mangle)]
static svmvisor_resident_nmi_pending: AtomicU32 = AtomicU32::new(0);

/// Same-CPU acknowledgment witness, separate from the coalescing pending bit.
/// A physical NMI intercept leaves the source pending; only the returning host
/// gate advances this counter after taking it (APM2 physical p598).
#[unsafe(no_mangle)]
static svmvisor_resident_nmi_acks: AtomicU64 = AtomicU64::new(0);

#[unsafe(no_mangle)]
static mut svmvisor_resident_raw_vmexit: RawVmexitCapture = unsafe { core::mem::zeroed() };
// CPU-local circular history; no PCI traffic, heap, guest reads or global lock.
// Updated only on the ordinary stopped-guest stack, before dispatcher mutation.
static mut EXIT_HISTORY: [[u64; 6]; 5] = [[0; 6]; 5];
static mut EXIT_HISTORY_NEXT: usize = 0;
static mut EXIT_HISTORY_COUNT: usize = 0;

static mut TABLES: HostTables = HostTables([[0; 512]; 4]);
static mut NPT: CacheTableStorage = CacheTableStorage([[0; PAGE_BYTES]; CACHE_TABLE_COUNT]);
static mut VMCB: Vmcb = Vmcb::new();
static mut AUX: Vmcb = Vmcb::new();
static mut HOST_EXTRA: Vmcb = Vmcb::new();
static mut HSAVE: Pages<1> = Pages([[0; 4096]; 1]);
static mut STACK: Pages<18> = Pages([[0; 4096]; 18]);
static mut FAULT_STACK: Pages<6> = Pages([[0; 4096]; 6]);
// Dedicated IST2 stack for the returning host NMI gate: one usable page
// between two guard pages, like FAULT_STACK.
static mut NMI_STACK: Pages<3> = Pages([[0; 4096]; 3]);
static mut GDT_TSS: Pages<1> = Pages([[0; 4096]; 1]);
static mut IDT: Pages<1> = Pages([[0; 4096]; 1]);
static mut GDTR: [u8; 10] = [0; 10];
static mut IDTR: [u8; 10] = [0; 10];
static mut FRAME: GuestRegisters = GuestRegisters {
    rcx: 0,
    rdx: 0,
    rbx: 0,
    rbp: 0,
    rsi: 0,
    rdi: 0,
    r8: 0,
    r9: 0,
    r10: 0,
    r11: 0,
    r12: 0,
    r13: 0,
    r14: 0,
    r15: 0,
};
static mut IOPM: Iopm = Iopm::new();
static mut MSRPM: Msrpm = Msrpm::new();
static mut CONTEXT: BridgeContext = BridgeContext {
    host_stack_top: 0,
    host_cr3: 0,
    guest_vmcb_pa: 0,
    guest_vmcb_va: 0,
    host_extra_pa: 0,
    guest_frame_va: 0,
    hsave_pa: 0,
    host_gdtr_va: 0,
    host_idtr_va: 0,
    host_tr_selector: 24,
    host_data_selector: 16,
    host_code_selector: 8,
    dispatch,
    owner_context: 0,
    reserved: 0,
};

static mut STATE: State = INITIAL_STATE;
static mut RAM: [MemoryDescriptor; MAX_DESCRIPTORS] =
    [MemoryDescriptor { memory_type: 0, physical_start: 0, page_count: 0, attributes: 0 };
        MAX_DESCRIPTORS];
static mut RAM_COUNT: usize = 0;
static mut PHYSICAL_BITS: u8 = 0;
static mut POOL: (u64, u64) = (0, 0);
static mut ASSIGNED_APIC_ID: u32 = u32::MAX;

// Defined by crates/hypervisor/payload.ld, runtime.S, nmi.S and fault.S.
#[cfg(not(test))]
unsafe extern "C" {
    static image_start: u8;
    static text_end: u8;
    static data_start: u8;
    static image_bss_end: u8;
    static svmvisor_resident_fault_offsets: [i32; 256];
    fn svmvisor_resident_sx();
    fn svmvisor_resident_nmi();
}

#[cfg(not(test))]
unsafe extern "win64" {
    fn svmvisor_resident_enter(context: *mut BridgeContext) -> !;
}

/// Host unit tests link this module without the payload linker script and
/// resident assembly. These inert stand-ins only satisfy references from code
/// the tests never execute; no test may reach them.
#[cfg(test)]
#[allow(non_upper_case_globals)]
mod linked_symbols {
    use crate::host::resident::BridgeContext;

    pub(super) static image_start: u8 = 0;
    pub(super) static text_end: u8 = 0;
    pub(super) static data_start: u8 = 0;
    pub(super) static image_bss_end: u8 = 0;
    pub(super) static svmvisor_resident_fault_offsets: [i32; 256] = [0; 256];
    pub(super) unsafe extern "C" fn svmvisor_resident_sx() {
        unreachable!("host unit tests never take #SX")
    }
    pub(super) unsafe extern "C" fn svmvisor_resident_nmi() {
        unreachable!("host unit tests never take a host NMI")
    }
    pub(super) unsafe extern "win64" fn svmvisor_resident_enter(_: *mut BridgeContext) -> ! {
        unreachable!("host unit tests never enter the resident runtime")
    }
}

struct State {
    prepared: bool,
    armed: bool,
    capabilities: Option<ValidatedCapabilities>,
    /// Same-CPU, same-VMCB reuse evidence established only by the audited entry path.
    vmcb_cache: VmcbCacheOwner,
    ack: Option<NativeBootstrapAck>,
    efer: Option<NativeEfer>,
    /// Guest selector state and physical filtering on this nonmigrating CPU.
    pmu: Option<pmu::PmuRuntime>,
    vmcr: Option<crate::svm::vmcr::VisibleVmCr>,
    svm_controls: Option<VisibleSvmControls>,
    /// Documented non-SNP target register contracts captured on this CPU.
    target_msrs: Option<TargetMsrPolicy>,
    svm_instructions: Option<NativeSvmInstructions>,
    icr: Option<NativeIcr>,
    /// Last guest ICR value, separate from the host's private startup notifications.
    icr_value: u64,
    /// Physical APIC_BASE captured at arm. The host keeps this interface; the
    /// terminal notification rechecks it. Never a guest-visible value.
    host_apic_base: u64,
    startup_owned: bool,
    startup: NativeStartupState,
    /// Initial all-AP startup milestone; quiet progress, never ICR passthrough.
    guest_started: bool,
    /// Same-CPU PAUSE filtering admission; only maintenance work needs this exit.
    pause_filter_supported: bool,
    slot: usize,
    count: usize,
    /// Delivery obligation for a queued fault or any recovered interrupted event.
    /// Completion transfers it to replay, or retires it once EXITINTINFO is clear.
    pending_fault: bool,
    exits: u64,
    stopped: u64,
    stopped_rip: u64,
    stopped_info1: u64,
    stopped_info2: u64,
    routing_retries: u16,
    terminal_endpoint: Option<TerminalEndpoint>,
    stopped_valid: bool,
}

/// Single-writer host-private provenance, written by runtime.S. The entry half
/// is recorded before loading guest GPRs; the exit half before VMSAVE/VMLOAD or
/// Rust dispatch. The exit sequence commits last. It is retained unchanged
/// through a stop and overwritten only by the next world switch, never by SMM
/// acknowledgment or instruction emulation in this runtime.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct RawVmexitCapture {
    entry_sequence: u64,
    exit_sequence: u64,
    entry_vmcb_pa: u64,
    entry_rip: u64,
    exit_vmcb_pa: u64,
    exit_rip: u64,
    nrip: u64,
    code: u64,
    guest_cr0: u64,
    guest_cr3: u64,
    guest_rax: u64,
    guest_rdx: u64,
    mtrr_def_type: u64,
    sys_cfg: u64,
    host_cr0: u64,
    physical_apic_id: u64,
    guest_rcx: u64,
    entry_cr0: u64,
    context_vmcb_pa: u64,
    physical_cache_valid: u64,
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<RawVmexitCapture>() == 160);
    assert!(align_of::<RawVmexitCapture>() == 8);
    assert!(offset_of!(RawVmexitCapture, entry_sequence) == 0);
    assert!(offset_of!(RawVmexitCapture, exit_sequence) == 8);
    assert!(offset_of!(RawVmexitCapture, entry_vmcb_pa) == 16);
    assert!(offset_of!(RawVmexitCapture, entry_rip) == 24);
    assert!(offset_of!(RawVmexitCapture, exit_vmcb_pa) == 32);
    assert!(offset_of!(RawVmexitCapture, exit_rip) == 40);
    assert!(offset_of!(RawVmexitCapture, nrip) == 48);
    assert!(offset_of!(RawVmexitCapture, code) == 56);
    assert!(offset_of!(RawVmexitCapture, guest_cr0) == 64);
    assert!(offset_of!(RawVmexitCapture, guest_cr3) == 72);
    assert!(offset_of!(RawVmexitCapture, guest_rax) == 80);
    assert!(offset_of!(RawVmexitCapture, guest_rdx) == 88);
    assert!(offset_of!(RawVmexitCapture, mtrr_def_type) == 96);
    assert!(offset_of!(RawVmexitCapture, sys_cfg) == 104);
    assert!(offset_of!(RawVmexitCapture, host_cr0) == 112);
    assert!(offset_of!(RawVmexitCapture, physical_apic_id) == 120);
    assert!(offset_of!(RawVmexitCapture, guest_rcx) == 128);
    assert!(offset_of!(RawVmexitCapture, entry_cr0) == 136);
    assert!(offset_of!(RawVmexitCapture, context_vmcb_pa) == 144);
    assert!(offset_of!(RawVmexitCapture, physical_cache_valid) == 152);
};

#[repr(C, align(4096))]
struct Pages<const N: usize>([[u8; 4096]; N]);

#[repr(C, align(4096))]
struct HostTables([[u64; 512]; 4]);
