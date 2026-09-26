//! Native callback and resident assembly seam, AMD APM2 rev3.44 15.5/15.7.
//!
//! Pointer fields are inert ABI operands, not admission or allocation evidence.
//! The callback object stays in the original DXE image; runtime.S and its entire
//! dispatch call graph must reside in independently retained monitor memory.

use svmvisor_card_abi::endpoint::TerminalEndpoint;

/// Shared retained-resource profile; incompatible with previous pool layouts.
pub const DIRECTORY_VERSION: u64 = 17;
/// Image bound below the shared cache-policy aliases.
pub const IMAGE_LIMIT_OFFSET: u64 = 0xf0000;
/// One shared cache-policy backing in slot zero, aliased into every host root.
pub const CACHE_SHARED_OFFSET: u64 = 0xf0000;
pub const CACHE_SHARED_BYTES: u64 = 0x8000;
/// Shared startup mailboxes and terminal control, excluded from guest memory.
pub const STARTUP_PAGE_OFFSET: u64 = 0xfe000;
pub const MAX_RESIDENT_CPUS: usize = 32;
/// One immutable firmware observation after the private image slots. The whole
/// assigned extent is retained and CPU-excluded, including unused capacity.
pub const IOMMU_RETAINED_BYTES: u64 = 0x10000;
/// Uninstalled candidate device table, root, command/event/completion backing.
pub const IOMMU_RESOURCE_BYTES: u64 = 0x210000;
/// Native capacity, checked against the complete fresh inventory before ownership.
pub const MAX_NATIVE_IOMMU_UNITS: usize = 4;
/// Each generation holds a full device table plus 256 translation/interrupt pages.
/// Arbitrary guest compositions must pass a separate capacity check; this is not
/// a promise that every possible Windows mapping fits.
pub const IOMMU_COMPOSITION_BYTES: u64 = 0x300000;
pub const IOMMU_UNIT_STRIDE: u64 = IOMMU_RESOURCE_BYTES + 2 * IOMMU_COMPOSITION_BYTES;
/// Common scalar guest PCI/IVRS presentation; shared by every processor.
pub const IOMMU_PRESENTATION_BYTES: u64 = 0x12000;
/// One serialized source capture and mapping workspace, not one copy per CPU.
/// Its source-page protection and physical publication are separate obligations.
pub const IOMMU_WORKSPACE_BYTES: u64 = 0x1200000;
pub const SHARED_RETAINED_BYTES: u64 = IOMMU_RETAINED_BYTES
    + MAX_NATIVE_IOMMU_UNITS as u64 * IOMMU_UNIT_STRIDE
    + IOMMU_PRESENTATION_BYTES
    + IOMMU_WORKSPACE_BYTES;

const _: () = {
    assert!(IMAGE_LIMIT_OFFSET <= CACHE_SHARED_OFFSET);
    assert!(CACHE_SHARED_OFFSET & 4095 == 0);
    assert!(CACHE_SHARED_BYTES & 4095 == 0);
    assert!(CACHE_SHARED_OFFSET + CACHE_SHARED_BYTES <= 0xfb000);
    assert!(CACHE_SHARED_OFFSET + CACHE_SHARED_BYTES <= STARTUP_PAGE_OFFSET);
    assert!(
        MAX_RESIDENT_CPUS as u64 * 0x100000 + SHARED_RETAINED_BYTES
            <= crate::memory::npt::MAX_IDENTITY_EXCLUSION_BYTES
    );
};

/// Typed takeover evidence: tag A1h in bits 63:56, bit 55 set when the
/// observed value has bits above 31, the reason in bits 54:48, the register
/// in bits 47:32 and the observed value's low 32 bits in bits 31:0. Reasons
/// 1-4 are retired xAPIC-era MMIO register refusals (the register field is
/// the MMIO offset); DXE and the snapshot decoder keep them for older images.
pub const TAKEOVER_TAG: u64 = 0xa1;
unsafe extern "efiapi" {
    pub fn svmvisor_resident_callback(
        event: *mut core::ffi::c_void,
        context: *mut core::ffi::c_void,
    );
}

unsafe extern "C" {
    pub static svmvisor_resident_guest_resume: u8;
    pub static svmvisor_resident_guest_ack: u8;
    pub static svmvisor_resident_guest_after_ack: u8;
}

/// One physical CPU and one guest. All fields and referenced storage remain
/// resident, host-accessible and exclusively owned until reset. Descriptor
/// pointers identify packed ten-byte GDTR/IDTR images; selectors are GDT CPL0.
/// The host TSS descriptor must be available before the one-time LTR.
///
/// # Entry safety contract
/// Native CPL0 long64, IF=0, admitted AMD SVM enabled and guest auxiliary state
/// already captured/composed into guest_vmcb. The guest/native root is retained
/// in that VMCB; host_cr3 is a different, privately owned root. Current and new
/// host roots map the complete runtime transition instructions and context.
/// Every host pointer remains mapped after switching CR3. Host stack is aligned,
/// bounded, disjoint from guest stack/backing, and large enough for dispatch.
/// VMCB/HSAVE/auxiliary pages are distinct aligned WB physical operands; their
/// virtual aliases and the 112-byte GuestRegisters frame are prevalidated.
///
/// Guest x87/MMX/SIMD and XCR0 remain live on this CPU. The complete persistent
/// host call graph must contain no x87/MMX/SIMD, XSAVE/XRSTOR, XSETBV, debug
/// register mutation outside the successful target-owned INIT reset, or migration.
/// Compiler target settings alone are not
/// proof: linked-image instruction audit is mandatory. DR0–3 and clock MSRs
/// remain guest-owned. The audited INIT commit clears live DR0-3 and resets
/// VMCB DR6/7; ordinary exits and private notifications leave them untouched.
/// Clock MSRs are untouched by host. Admit disabled hardware breakpoints
/// and debug recording. All guest GPRs are captured before host scratch use.
/// The dispatcher may update only validated stopped guest state and keeps
/// IF clear throughout and GIF clear except the opt-in redirected-INIT window.
/// VM_CR.R_INIT and a private #SX(error1) gate own that notification. Guest
/// Physical interrupts and CR8/TPR remain native; host code never opens an INTR window.
/// Host descriptors remain stable. No firmware calls,
/// allocation, unwinding, unbounded work, or resumable synchronous transport.
/// The optional terminal exporter runs only after guards drop and every admitted
/// CPU irreversibly acknowledges the shared stop request with IF/GIF clear.
/// False dispatch is terminal; no post-entry native restoration is provided.
#[repr(C, align(16))]
pub struct BridgeContext {
    pub host_stack_top: u64,
    pub host_cr3: u64,
    pub guest_vmcb_pa: u64,
    pub guest_vmcb_va: u64,
    pub host_extra_pa: u64,
    pub guest_frame_va: u64,
    pub hsave_pa: u64,
    pub host_gdtr_va: u64,
    pub host_idtr_va: u64,
    pub host_tr_selector: u64,
    pub host_data_selector: u64,
    pub host_code_selector: u64,
    pub dispatch: Dispatch,
    pub owner_context: u64,
    /// Reserved ABI slot; zero. IRQ capture uses its own assembly mailbox.
    pub reserved: u64,
}

const _: () = {
    assert!(core::mem::size_of::<BridgeContext>() == 128);
    assert!(core::mem::align_of::<BridgeContext>() == 16);
    assert!(core::mem::offset_of!(BridgeContext, host_stack_top) == 0);
    assert!(core::mem::offset_of!(BridgeContext, host_cr3) == 8);
    assert!(core::mem::offset_of!(BridgeContext, guest_vmcb_pa) == 16);
    assert!(core::mem::offset_of!(BridgeContext, guest_vmcb_va) == 24);
    assert!(core::mem::offset_of!(BridgeContext, host_extra_pa) == 32);
    assert!(core::mem::offset_of!(BridgeContext, guest_frame_va) == 40);
    assert!(core::mem::offset_of!(BridgeContext, hsave_pa) == 48);
    assert!(core::mem::offset_of!(BridgeContext, host_gdtr_va) == 56);
    assert!(core::mem::offset_of!(BridgeContext, host_idtr_va) == 64);
    assert!(core::mem::offset_of!(BridgeContext, host_tr_selector) == 72);
    assert!(core::mem::offset_of!(BridgeContext, host_data_selector) == 80);
    assert!(core::mem::offset_of!(BridgeContext, host_code_selector) == 88);
    assert!(core::mem::offset_of!(BridgeContext, dispatch) == 96);
    assert!(core::mem::offset_of!(BridgeContext, owner_context) == 104);
    assert!(core::mem::offset_of!(BridgeContext, reserved) == 112);
};

/// Numeric directory returned by the separately loaded raw runtime. It owns no
/// references into firmware. All storage addresses identify aligned, disjoint
/// objects within the declared arena; the delivery adapter verifies containment
/// and actual mappings before use. Function addresses are linked runtime code.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ResidentDirectory {
    pub version: u64,
    pub arena_base: u64,
    pub arena_bytes: u64,
    pub context: u64,
    pub vmcb: u64,
    pub auxiliary: u64,
    pub registers: u64,
    pub npt: u64,
    pub arm: u64,
    pub enter: u64,
    pub text_end: u64,
    pub data_start: u64,
    pub memory_end: u64,
    pub pool_base: u64,
    pub pool_bytes: u64,
    pub cpu_slot: u64,
    pub apic_id: u64,
    pub reserved: [u64; 3],
}

const _: () = {
    assert!(core::mem::size_of::<ResidentDirectory>() == 160);
    assert!(core::mem::offset_of!(ResidentDirectory, context) == 24);
    assert!(core::mem::offset_of!(ResidentDirectory, arm) == 64);
    assert!(core::mem::offset_of!(ResidentDirectory, pool_base) == 104);
    assert!(core::mem::offset_of!(ResidentDirectory, reserved) == 136);
};

/// Nonreturning resident entry uses the Windows x64 ABI, also when linked into
/// an ELF payload. The dispatcher uses that same ABI and returns AL=1 to resume.
/// No borrowed reference may alias guest writes or survive guest execution.
pub type Dispatch = unsafe extern "win64" fn(*mut BridgeContext) -> bool;

pub type Enter = unsafe extern "win64" fn(*mut BridgeContext) -> !;

pub type PrepareRuntime =
    unsafe extern "win64" fn(u64, *mut ResidentDirectory, u64, u64, u64, u64) -> u64;

/// The optional penultimate pointer supplies the BSP's canonical ICR before physical
/// bootstrap overwrites its readable command. Null selects current native ICR.
/// A nonnull operand is allowed only for startup ownership and identifies an
/// aligned immutable u64 in the caller's validated current mapping for this
/// call. The callee copies the value before guest entry and retains no pointer.
/// The x2APIC ICR carries the destination in bits63:32 and the command in bits31:0.
/// The final optional pointer identifies one aligned immutable TerminalEndpoint
/// in the caller's validated current mapping for this call. It is copied before
/// entry; no pointer is retained. Null disables production terminal export.
///
/// Arm returns 0 or a refusal code (`runtime::arm` lists them). A typed
/// refusal carries tag `TAKEOVER_TAG` in bits 63:56, which DXE preserves
/// (BSP stage 84h record, AP BOOT record reason 83h) instead of its generic
/// arm failure. Historical takeover codes remain decodable by the launcher.
pub type ArmRuntime = unsafe extern "win64" fn(
    u64,
    u64,
    u64,
    u64,
    *const crate::boot::memory::MemoryDescriptor,
    usize,
    *const u32,
    usize,
    bool,
    *const u64,
    *const TerminalEndpoint,
) -> u64;

/// Numeric extent for dense 1MiB images plus shared observation and resources.
pub const fn pool_bytes_for_processors(count: usize) -> Option<u64> {
    if count == 0 || count > MAX_RESIDENT_CPUS {
        return None;
    }
    Some(count as u64 * 0x100000 + SHARED_RETAINED_BYTES)
}

/// Decode only the current exact pool shape; the tail is never a CPU slot.
pub const fn pool_processor_count(bytes: u64) -> Option<usize> {
    if bytes < 0x100000 + SHARED_RETAINED_BYTES {
        return None;
    }
    let images = bytes - SHARED_RETAINED_BYTES;
    if images & 0xfffff != 0 || images / 0x100000 > MAX_RESIDENT_CPUS as u64 {
        return None;
    }
    Some((images / 0x100000) as usize)
}

/// Address of the common observation within a numerically valid pool.
pub fn retained_iommu_base(pool_base: u64, pool_bytes: u64) -> Option<u64> {
    let count = pool_processor_count(pool_bytes)?;
    if pool_base < 0x200000
        || pool_base & 0x1fffff != 0
        || pool_base.checked_add(pool_bytes)? > 0x40000000
    {
        return None;
    }
    Some(pool_base + count as u64 * 0x100000)
}

/// Fixed native backing addresses. These numeric assignments do not grant a
/// storage borrow, admission, DMA integrity or permission to publish hardware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeIommuResources {
    pub bank: u64,
    pub generations: [u64; 2],
}

/// Common retained state. Both extents are disjoint from hardware-consumed
/// unit banks and belong to the complete pool covered by the exclusion policy.
/// Numeric layout does not establish that the physical policy is installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeIommuShared {
    pub presentation: u64,
    pub workspace: u64,
}

pub fn native_iommu_shared(pool_base: u64, pool_bytes: u64) -> Option<NativeIommuShared> {
    let retained = retained_iommu_base(pool_base, pool_bytes)?;
    let presentation =
        retained + IOMMU_RETAINED_BYTES + MAX_NATIVE_IOMMU_UNITS as u64 * IOMMU_UNIT_STRIDE;
    Some(NativeIommuShared { presentation, workspace: presentation + IOMMU_PRESENTATION_BYTES })
}

/// Each physical unit needs its own slot; callers must reject a larger fresh
/// inventory, never truncate it. All slots, including unused ones, are retained
/// and CPU-excluded as part of the complete pool.
pub fn native_iommu_resources(
    pool_base: u64,
    pool_bytes: u64,
    unit: usize,
) -> Option<NativeIommuResources> {
    if unit >= MAX_NATIVE_IOMMU_UNITS {
        return None;
    }
    let retained = retained_iommu_base(pool_base, pool_bytes)?;
    let bank = retained + IOMMU_RETAINED_BYTES + unit as u64 * IOMMU_UNIT_STRIDE;
    let first = bank + IOMMU_RESOURCE_BYTES;
    Some(NativeIommuResources { bank, generations: [first, first + IOMMU_COMPOSITION_BYTES] })
}

/// One 1MiB image per dense slot followed by the retained shared tail.
/// Every pool is 2MiB aligned below1GiB, including the one-CPU test profile.
/// APIC IDs remain limited to the physical bootstrap inventory (0..=254).
/// Numeric layout checks are not allocation, caching or CPU ownership proof.
pub fn is_valid_pool_slot(
    base: u64,
    pool_base: u64,
    pool_bytes: u64,
    slot: u64,
    apic_id: u64,
) -> bool {
    let Some(count) = pool_processor_count(pool_bytes) else {
        return false;
    };
    retained_iommu_base(pool_base, pool_bytes).is_some()
        && slot < count as u64
        && apic_id <= 254
        && base == pool_base + slot * 0x100000
        && base >> 21 == (base + 0xfffff) >> 21
}
