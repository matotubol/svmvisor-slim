//! The serialized installer's pre-EBS acquisition adapter. It never changes
//! PCI routing, IOMMU registers, mappings or memory attributes.
use core::{
    arch::x86_64::__cpuid_count,
    ptr,
    sync::atomic::{AtomicU32, Ordering},
};
use svmvisor_card_abi::endpoint::{self, TerminalEndpoint};
use svmvisor_hypervisor::{
    arch::x86_64::msr::{MMIO_CFG_BASE_ADDR, TARGET_PHYSICAL_BITS, TARGET_SIGNATURE},
    boot::memory::MemoryDescriptor,
    firmware::native::resident::{
        iommu::{
            self, MemoryKind, ReadError, ReadOnlyAccess, Scratch,
            resources::{CompositionStorage, ResourceHeader, ResourceStorage},
            retained::{CaptureMetadata, RetainedHeader, RetainedObservation},
        },
        launch::Mtrrs,
    },
    host::{
        paging::{self, PagingConfig},
        resident::{
            IOMMU_COMPOSITION_BYTES, IOMMU_PRESENTATION_BYTES, IOMMU_RETAINED_BYTES,
            IOMMU_UNIT_STRIDE, IOMMU_WORKSPACE_BYTES, MAX_NATIVE_IOMMU_UNITS,
            SHARED_RETAINED_BYTES, configuration::RouteExpectation, native_iommu_resources,
            native_iommu_shared,
        },
    },
    memory::address::AddressPolicy,
};
use uefi_raw::{Status, table::system::SystemTable};

// Scratch is boot-only and never borrowed by the retained observation. The
// complete report is acquired directly into the separately retained pool tail.
static mut SCRATCH: Scratch = Scratch::EMPTY;
static SUMMARY: AtomicU32 = AtomicU32::new(0x0200_0020);

pub(super) fn summary() -> u32 {
    SUMMARY.load(Ordering::Acquire)
}

/// Admit the complete shared allocation, preserving mapped()'s 2MiB bound.
/// # Safety
/// The caller supplies the owned, numerically validated pool tail and current
/// native paging/cache/descriptor evidence under the serialized boot contract.
pub(super) unsafe fn mapped_backing(
    map: &[MemoryDescriptor],
    config: PagingConfig,
    mtrrs: &Mtrrs,
    pat: u64,
    retained: u64,
    write: bool,
) -> Result<(), u64> {
    let end = retained.checked_add(SHARED_RETAINED_BYTES).ok_or(24u64)?;
    let mut cursor = retained;
    while cursor < end {
        let bytes = (end - cursor).min(0x200000);
        unsafe {
            super::mapping::mapped(map, config, mtrrs, pat, cursor, bytes, write, false)?;
        }
        cursor += bytes;
    }
    Ok(())
}

/// # Safety
/// The entire resource extent is exclusive, uninstalled, retained RW/WB RAM,
/// already admitted by mapped_backing; no hardware or concurrent reader can
/// access it. No typed borrow survives this call or an unpublished arena drop.
pub(super) unsafe fn prepare_resources(
    pool_base: u64,
    pool_bytes: u64,
    policy: AddressPolicy,
) -> Result<(), Status> {
    // Exact ABI shape and the whole allocation are checked before any mutation.
    policy.validate(pool_base, pool_bytes, 4096).map_err(|_| Status::UNSUPPORTED)?;
    for unit in 0..MAX_NATIVE_IOMMU_UNITS {
        native_iommu_resources(pool_base, pool_bytes, unit).ok_or(Status::UNSUPPORTED)?;
    }
    let shared = native_iommu_shared(pool_base, pool_bytes).ok_or(Status::UNSUPPORTED)?;
    for unit in 0..MAX_NATIVE_IOMMU_UNITS {
        let layout = native_iommu_resources(pool_base, pool_bytes, unit).unwrap();
        // Every slot is initialized, including capacity not used by discovery.
        // All fields are integer words; no multi-MiB stack object is formed.
        unsafe { ptr::write_bytes(layout.bank as *mut u8, 0, IOMMU_UNIT_STRIDE as usize) };
        let bank = unsafe { &mut *(layout.bank as *mut ResourceStorage) };
        bank.prepare(policy, layout.bank).map_err(|_| Status::UNSUPPORTED)?;
        bank.verify(policy, layout.bank).map_err(|_| Status::UNSUPPORTED)?;
        for address in layout.generations {
            policy
                .validate(address, IOMMU_COMPOSITION_BYTES, 4096)
                .map_err(|_| Status::UNSUPPORTED)?;
            if !unsafe { &*(address as *const CompositionStorage) }.is_empty() {
                return Err(Status::UNSUPPORTED);
            }
        }
    }
    // Scalar storage is initialized before any typed presentation/capture view.
    // Copy no multi-MiB aggregate through the firmware stack.
    unsafe {
        ptr::write_bytes(shared.presentation as *mut u8, 0, IOMMU_PRESENTATION_BYTES as usize);
        ptr::write_bytes(shared.workspace as *mut u8, 0, IOMMU_WORKSPACE_BYTES as usize);
        svmvisor_hypervisor::host::resident::iommu_runtime::initialize_workspace(
            shared.workspace
                as *mut svmvisor_hypervisor::host::resident::iommu_runtime::NativeWorkspace,
        );
    }
    Ok(())
}

/// Copy only all-integer metadata after native mapping admission. Rechecking
/// this header grants no DMA-integrity, freshness or resource ownership.
/// # Safety
/// Full retained backing is currently readable; no CPU writer is active.
pub(super) unsafe fn validate_resource_header(
    pool_base: u64,
    pool_bytes: u64,
    policy: AddressPolicy,
) -> Result<(), u64> {
    for unit in 0..MAX_NATIVE_IOMMU_UNITS {
        let layout = native_iommu_resources(pool_base, pool_bytes, unit).ok_or(24u64)?;
        let header = unsafe { (layout.bank as *const ResourceHeader).read() };
        header.validate(policy, layout.bank).map_err(|_| 24u64)?;
    }
    Ok(())
}

/// # Safety
/// Called once by serialized BSP install before EBS, with current map/root,
/// PAT/MTRRs and unencrypted native identity/coherency admission. No firmware
/// call, allocation, paging/cache transition or concurrent descriptor/table
/// mutation may occur during this observation. Firmware guarantees that RAM
/// paging structures themselves are directly accessible through identity
/// aliases, as required by the existing activation mapping walker.
/// `destination` names the aligned, exclusive whole IOMMU_RETAINED_BYTES tail
/// already admitted RW/WB under this native root, inside the owned pool. It is
/// disjoint from all input/scratch/package memory and has no active readers.
/// No pointer escapes if later preparation drops the unpublished allocation.
pub(super) unsafe fn capture(
    system_table: *const SystemTable,
    map: &[MemoryDescriptor],
    config: PagingConfig,
    mtrrs: &Mtrrs,
    pat: u64,
    policy: AddressPolicy,
    expected: RouteExpectation,
    cpu_count: usize,
    destination: u64,
) -> Result<(), Status> {
    const _: () = assert!(iommu::retained::RETAINED_BYTES as u64 <= IOMMU_RETAINED_BYTES);
    let metadata = unsafe { current_metadata(expected, policy.physical_bits(), cpu_count) }
        .ok_or(Status::UNSUPPORTED)?;
    policy.validate(destination, IOMMU_RETAINED_BYTES, 4096).map_err(|_| Status::UNSUPPORTED)?;
    let mut access = NativeAccess {
        map,
        config,
        mtrrs,
        pat,
        policy,
        target: true,
        route: metadata.configuration_route,
    };
    let destination = destination as *mut RetainedObservation;
    // Zero unused assigned capacity too, then install valid typed enum/Option
    // initializers without constructing a report-sized stack temporary.
    unsafe {
        ptr::write_bytes(destination.cast::<u8>(), 0, IOMMU_RETAINED_BYTES as usize);
        ptr::copy_nonoverlapping(RetainedObservation::empty_template(), destination, 1);
    }
    let observation = unsafe { &mut *destination };
    let scratch = unsafe { &mut *ptr::addr_of_mut!(SCRATCH) };
    observation
        .capture_once(metadata, &mut access, policy, system_table as u64, scratch)
        .map_err(|_| Status::UNSUPPORTED)?;
    if unsafe { current_metadata(expected, policy.physical_bits(), cpu_count) } != Some(metadata) {
        return Err(Status::UNSUPPORTED);
    }
    let summary = observation.header().validate(metadata).map_err(|_| Status::UNSUPPORTED)?;
    // Concrete F7 power-off/reset ports are selected by these MMIO words.
    // Exact 16-bit native reads enforce the current UC mapping and route. Denial of
    // these observed paths does not establish a complete chipset allowlist.
    let route = expected
        .admit(TARGET_SIGNATURE, policy.physical_bits(), metadata.configuration_route, cpu_count)
        .ok_or(Status::UNSUPPORTED)?;
    let (raw360, raw368) = access.platform_io_observation().map_err(|_| Status::UNSUPPORTED)?;
    let platform = svmvisor_hypervisor::host::resident::platform::PlatformIo::from_observed(
        route, cpu_count, raw360, raw368,
    )
    .ok_or(Status::UNSUPPORTED)?;
    let pool = destination as u64 - cpu_count as u64 * 0x100000;
    unsafe {
        ((pool
            + svmvisor_hypervisor::host::resident::STARTUP_PAGE_OFFSET
            + svmvisor_hypervisor::host::resident::platform::PLATFORM_IO_OFFSET)
            as *mut svmvisor_hypervisor::host::resident::platform::PlatformIo)
            .write(platform);
    }
    SUMMARY.store(summary, Ordering::Release);
    Ok(())
}

/// Retain the candidate's exact scalar config/firmware state. Preparation can
/// record a refusal (for example contradictory IVRS); it never publishes guest
/// firmware or invents the missing native publication owner.
/// # Safety
/// Serialized firmware phase; the complete initialized pool is retained RW/WB
/// under the current root. No guest, CPU peer or device may mutate this storage.
pub(super) unsafe fn prepare_presentation(
    pool_base: u64,
    pool_bytes: u64,
    policy: AddressPolicy,
    expected: RouteExpectation,
    count: usize,
) -> Result<(), Status> {
    use svmvisor_hypervisor::{
        host::resident as abi, memory::iommu::virtualized::presentation::Storage,
    };
    const _: () = assert!(core::mem::size_of::<Storage>() as u64 <= abi::IOMMU_PRESENTATION_BYTES);
    let shared = abi::native_iommu_shared(pool_base, pool_bytes).ok_or(Status::UNSUPPORTED)?;
    let retained = abi::retained_iommu_base(pool_base, pool_bytes).ok_or(Status::UNSUPPORTED)?;
    let metadata = unsafe { current_metadata(expected, policy.physical_bits(), count) }
        .ok_or(Status::UNSUPPORTED)?;
    let route = expected
        .admit(TARGET_SIGNATURE, policy.physical_bits(), metadata.configuration_route, count)
        .ok_or(Status::UNSUPPORTED)?;
    let observation = unsafe { &*(retained as *const RetainedObservation) };
    let report = observation.report(metadata).map_err(|_| Status::UNSUPPORTED)?;
    let storage = unsafe { &mut *(shared.presentation as *mut Storage) };
    let _ = iommu::presentation::prepare(storage, report, route);
    if storage.is_active() {
        return Err(Status::UNSUPPORTED);
    }
    Ok(())
}

/// Check only the scalar header after current native mapping admission. The
/// enum-rich historical payload remains opaque during callback and runtime.
/// This proves no freshness, successful discovery or DMA integrity.
/// # Safety
/// Header backing is aligned/readable, retained and no CPU writer is active.
pub(super) unsafe fn validate_retained_header(
    address: u64,
    expected: RouteExpectation,
    physical_bits: u8,
    cpu_count: usize,
) -> Result<(), u64> {
    let metadata = unsafe { current_metadata(expected, physical_bits, cpu_count) }.ok_or(24u64)?;
    let header = unsafe { (address as *const RetainedHeader).read() };
    header.validate(metadata).map_err(|_| 24u64)?;
    Ok(())
}

unsafe fn current_metadata(
    expected: RouteExpectation,
    physical_bits: u8,
    cpu_count: usize,
) -> Option<CaptureMetadata> {
    let signature = __cpuid_count(1, 0).eax;
    if signature != TARGET_SIGNATURE || physical_bits != TARGET_PHYSICAL_BITS {
        return None;
    }
    let raw = unsafe { super::capture::rdmsr(MMIO_CFG_BASE_ADDR) };
    let route = expected.admit(signature, physical_bits, raw, cpu_count)?;
    Some(CaptureMetadata {
        configuration_route: route.raw(),
        signature,
        physical_bits,
        cpu_count: cpu_count as u8,
    })
}

pub(super) struct NativeAccess<'a> {
    map: &'a [MemoryDescriptor],
    config: PagingConfig,
    mtrrs: &'a Mtrrs,
    pat: u64,
    policy: AddressPolicy,
    target: bool,
    route: u64,
}

impl NativeAccess<'_> {
    /// Exactly the three word loads observed in F7; do not widen these into
    /// accesses to neighboring MMIO registers with unknown side effects.
    pub(super) fn platform_io_observation(&self) -> Result<(u64, u64), ReadError> {
        use svmvisor_hypervisor::host::resident::platform::FCH_CONTROL_PAGE;
        let ecam = self.route & 0x0000_ffff_fff0_0000;
        let ecam_bytes = (1u64 << 20) << ((self.route >> 2) & 15);
        if !self.target
            || unsafe { super::capture::rdmsr(MMIO_CFG_BASE_ADDR) } != self.route
            || (FCH_CONTROL_PAGE < ecam + ecam_bytes && ecam < FCH_CONTROL_PAGE + 4096)
        {
            return Err(ReadError::Mapping);
        }
        let addresses =
            [FCH_CONTROL_PAGE + 0x360, FCH_CONTROL_PAGE + 0x362, FCH_CONTROL_PAGE + 0x368];
        for address in addresses {
            self.policy.validate(address, 2, 2).map_err(|_| ReadError::Address)?;
            self.validate(MemoryKind::Mmio, address, 2)?;
        }
        let read = || addresses.map(|address| unsafe { ptr::read_volatile(address as *const u16) });
        let words = read();
        if words != read() || unsafe { super::capture::rdmsr(MMIO_CFG_BASE_ADDR) } != self.route {
            return Err(ReadError::Mapping);
        }
        Ok((u64::from(words[0]) | (u64::from(words[1]) << 16), u64::from(words[2])))
    }

    pub(super) fn validate(
        &self,
        kind: MemoryKind,
        address: u64,
        bytes: u64,
    ) -> Result<(), ReadError> {
        self.validate_access(kind, address, bytes, false)
    }

    pub(super) fn validate_write(
        &self,
        kind: MemoryKind,
        address: u64,
        bytes: u64,
    ) -> Result<(), ReadError> {
        self.validate_access(kind, address, bytes, true)
    }

    fn validate_access(
        &self,
        kind: MemoryKind,
        address: u64,
        bytes: u64,
        write: bool,
    ) -> Result<(), ReadError> {
        iommu::descriptor_span(self.map, self.policy, kind, address, bytes)?;
        if write
            && self.map.iter().any(|d| {
                d.physical_start < address + bytes
                    && address < d.physical_start + d.page_count * 4096
                    && d.attributes & (0x1000 | 0x20000) != 0
            })
        {
            return Err(ReadError::ReadProtected);
        }
        iommu::root_cache_preflight(self.policy, self.config, self.mtrrs.physical_bits, self.pat)?;
        let end = address.checked_add(bytes).ok_or(ReadError::Address)?;
        let mut page = address & !4095;
        while page < end {
            let mut level = 4;
            let translated = paging::translate(self.config, page, |entry_address| {
                if iommu::descriptor_span(
                    self.map,
                    self.policy,
                    MemoryKind::PageTable,
                    entry_address,
                    8,
                )
                .is_err()
                    || !self.mtrrs.page_is_wb(entry_address & !4095)
                {
                    return None;
                }
                // The capture contract independently supplies the direct
                // identity alias for RAM page-table access; the walker then
                // verifies each requested target's actual current mapping.
                let entry = unsafe { ptr::read_volatile(entry_address as *const u64) };
                let leaf = level == 1 || (level < 4 && entry & 0x80 != 0);
                level -= 1;
                if !leaf && entry & 0x18 != 0 { None } else { Some(entry) }
            })
            .map_err(|_| ReadError::Mapping)?;
            if translated.physical_address != page
                || translated.user
                || (write && !translated.writable)
            {
                return Err(ReadError::Mapping);
            }
            let pat_type = ((self.pat >> (translated.pat_index * 8)) & 255) as u8;
            let admitted = if kind == MemoryKind::Mmio {
                self.mtrrs.page_is_uc(page, pat_type)
            } else {
                pat_type == 6 && self.mtrrs.page_is_wb(page)
            };
            if !admitted {
                return Err(ReadError::CacheType);
            }
            page = page.checked_add(4096).ok_or(ReadError::Address)?;
        }
        Ok(())
    }

    fn read_ram(&self, kind: MemoryKind, address: u64, out: &mut [u8]) -> Result<(), ReadError> {
        self.validate(kind, address, out.len() as u64)?;
        for (offset, byte) in out.iter_mut().enumerate() {
            *byte = unsafe { ptr::read_volatile((address + offset as u64) as *const u8) };
        }
        Ok(())
    }
}

impl<'a> NativeAccess<'a> {
    /// # Safety
    /// Serialized native BSP, current stable page tables/cache registers and
    /// trusted pre-guest memory; same identity/coherency contract as capture.
    pub(super) unsafe fn new(
        map: &'a [MemoryDescriptor],
        config: PagingConfig,
        mtrrs: &'a Mtrrs,
        pat: u64,
        policy: AddressPolicy,
        expected: RouteExpectation,
        count: usize,
    ) -> Result<Self, ReadError> {
        let metadata = unsafe { current_metadata(expected, policy.physical_bits(), count) }
            .ok_or(ReadError::Mapping)?;
        Ok(Self {
            map,
            config,
            mtrrs,
            pat,
            policy,
            target: true,
            route: metadata.configuration_route,
        })
    }
}

impl ReadOnlyAccess for NativeAccess<'_> {
    fn read_firmware(&mut self, address: u64, out: &mut [u8]) -> Result<(), ReadError> {
        self.read_ram(MemoryKind::Firmware, address, out)
    }
    fn read_acpi(&mut self, address: u64, out: &mut [u8]) -> Result<(), ReadError> {
        // Reclaim/NVS is admitted only here; mapping::ram_span is unchanged.
        self.read_ram(MemoryKind::Acpi, address, out)
    }
    fn read_pci_u32(
        &mut self,
        segment: u16,
        requester: u16,
        address: u64,
    ) -> Result<u32, ReadError> {
        if !self.target || segment != 0 {
            return Err(ReadError::Unsupported);
        }
        self.policy.validate(address, 4, 4).map_err(|_| ReadError::Address)?;
        let page = address & !4095;
        // PPR57896 p210, target-gated read only: require MCFG's selected
        // requester page to agree with enabled processor ECAM routing.
        let route = unsafe { super::capture::rdmsr(MMIO_CFG_BASE_ADDR) };
        if TerminalEndpoint::config_page_from_msr(route, u32::from(requester)) != Some(page) {
            return Err(ReadError::Unsupported);
        }
        if self.route != route {
            return Err(ReadError::Mapping);
        }
        self.validate(MemoryKind::Mmio, address, 4)?;
        // PPR57896 pp40-41 requires EAX and a naturally aligned DWORD.
        Ok(unsafe { endpoint::read_config_dword(page, (address & 4095) as u16) })
    }
    fn read_mmio_u64(&mut self, address: u64) -> Result<u64, ReadError> {
        let route = self.route;
        if !self.target || unsafe { super::capture::rdmsr(MMIO_CFG_BASE_ADDR) } != route {
            return Err(ReadError::Mapping);
        }
        let ecam = route & 0x0000_ffff_fff0_0000;
        let ecam_bytes = (1u64 << 20) << ((route >> 2) & 15);
        if (address >= ecam && address < ecam + ecam_bytes)
            || !svmvisor_hypervisor::host::resident::platform::outside_control_page(address, 8)
        {
            return Err(ReadError::MemoryType);
        }
        self.policy.validate(address, 8, 8).map_err(|_| ReadError::Address)?;
        self.validate(MemoryKind::Mmio, address, 8)?;
        Ok(unsafe { ptr::read_volatile(address as *const u64) })
    }
}
