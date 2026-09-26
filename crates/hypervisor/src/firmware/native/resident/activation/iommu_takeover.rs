//! Physical BSP publication after successful EBS and the AP parking rendezvous.
//! Firmware/SMM and devices are trusted during construction. No guest executes
//! until physical completion and a separately implemented guest contract admit
//! release. EBS, AP parking and BME state are never called DMA quiescence.
use super::{
    capture::{config, cpu, mtrrs, rdmsr},
    iommu::NativeAccess,
};
use core::{
    arch::asm,
    ptr,
    sync::atomic::{AtomicBool, Ordering, compiler_fence},
};
use svmvisor_hypervisor::{
    arch::x86_64::msr::{MMIO_CFG_BASE_ADDR, PAT, TARGET_SIGNATURE},
    boot::memory::MemoryDescriptor,
    firmware::native::resident::iommu::{
        self, MemoryKind, ReadOnlyAccess, RegisterObservation,
        binding::{self, UninstalledUnitPlan, UnitAssignment, UnitIdentity},
        control::manifest_from_report,
        ownership::{
            Fence, Register,
            cold::{self, Access, Error},
        },
        resources::{COMMAND_OFFSET, COMPLETION_OFFSET, CompositionStorage, ResourceStorage},
        retained::{CaptureMetadata, RetainedObservation},
    },
    host::resident::{
        self as abi,
        configuration::RouteExpectation,
        control::{CONTROL_MANIFEST_OFFSET, ControlManifest},
    },
    memory::{address::AddressPolicy, iommu::tables::DteInterruptPolicy},
};

static ATTEMPTED: AtomicBool = AtomicBool::new(false);
// Boot-only scratch; copied from valid typed retained storage under the trusted
// pre-guest contract. No firmware reference survives a guest release.
static mut FRESH: iommu::Report = iommu::Report::EMPTY;
const BASE: u64 = 0x000f_ffff_ffff_f000;
const POLLS: u32 = 100_000;

/// First installed profile intentionally holds all guests: Windows virtual
/// registers, table-write tracking, interrupts and firmware are not connected.
/// This code is returned only AFTER actual matching physical completion. It is
/// distinct from admission refusals and never makes EBS return success.
pub(super) const PROTECTED_GUEST_CONTRACT_PENDING: u64 = 95;

/// # Safety
/// Called once by the BSP after EBS with IF=0, every AP parked before callback,
/// validated native roots and independently retained pool. Trusted firmware has
/// surrendered software producers; SMM remains in the trusted platform boundary.
/// Failures retain all allocations and enter the existing terminal EBS path.
pub(super) unsafe fn take_over() -> Result<(), u64> {
    if ATTEMPTED.swap(true, Ordering::AcqRel) {
        return Err(80);
    }
    let processor = unsafe { cpu() }?;
    let cfg = unsafe { config(processor) }?;
    let mt = unsafe { mtrrs(processor.physical_bits) }?;
    let pat = unsafe { rdmsr(PAT) };
    let count = unsafe { super::CPU_COUNT };
    let directory = unsafe { super::DIRECTORIES[super::physical_boot::bsp_slot()] };
    let policy =
        AddressPolicy::new(processor.physical_bits, processor.encryption).map_err(|_| 80u64)?;
    let pool =
        policy.validate(directory.pool_base, directory.pool_bytes, 4096).map_err(|_| 80u64)?;
    let retained = abi::retained_iommu_base(pool.base(), pool.len()).ok_or(80u64)?;
    let map = unsafe {
        core::slice::from_raw_parts(
            ptr::addr_of!(super::MAP).cast::<MemoryDescriptor>(),
            super::MAP_COUNT,
        )
    };
    let startup = pool.base() + abi::STARTUP_PAGE_OFFSET;
    let route_expectation = unsafe {
        ((startup + abi::configuration::ROUTE_EXPECTATION_OFFSET) as *const RouteExpectation).read()
    };
    let route = unsafe { rdmsr(MMIO_CFG_BASE_ADDR) };
    let mut access =
        unsafe { NativeAccess::new(map, cfg, &mt, pat, policy, route_expectation, count) }
            .map_err(|_| 80u64)?;
    let platform = unsafe {
        ((startup + abi::platform::PLATFORM_IO_OFFSET) as *const abi::platform::PlatformIo).read()
    };
    let configuration = route_expectation
        .admit(TARGET_SIGNATURE, policy.physical_bits(), route, count)
        .ok_or(92u64)?;
    let (raw360, raw368) = access.platform_io_observation().map_err(|_| 92u64)?;
    if !platform.validate(configuration, count) || !platform.matches_observation(raw360, raw368) {
        return Err(92);
    }
    unsafe { super::iommu::mapped_backing(map, cfg, &mt, pat, retained, true) }?;
    access.validate(MemoryKind::Firmware, startup, 4096).map_err(|_| 80u64)?;
    let manifest =
        unsafe { ((startup + CONTROL_MANIFEST_OFFSET) as *const ControlManifest).read() };
    if !manifest.is_complete() {
        return Err(81);
    }
    let denied = unsafe { super::control_policy::read(pool.base(), pool.len(), policy, count) }?;
    let metadata = CaptureMetadata {
        configuration_route: route,
        signature: TARGET_SIGNATURE,
        physical_bits: processor.physical_bits,
        cpu_count: count as u8,
    };
    let retained_observation = unsafe { &*(retained as *const RetainedObservation) };
    let original = retained_observation.report(metadata).map_err(|_| 81u64)?;
    let fresh = unsafe { &mut *ptr::addr_of_mut!(FRESH) };
    // Report owns only values. This is safe only in the trusted construction
    // phase, never a read of enum-rich memory after an untrusted writer runs.
    unsafe { ptr::copy_nonoverlapping(original, fresh, 1) };
    iommu::refresh_hardware(&mut access, policy, fresh);
    let live_manifest =
        manifest_from_report(fresh, policy, TARGET_SIGNATURE, route, count).map_err(|_| 81u64)?;
    if !live_manifest.is_complete() || live_manifest != manifest {
        return Err(81);
    }
    let units = fresh.tables.ivrs.units();
    if units.is_empty() || units.len() > abi::MAX_NATIVE_IOMMU_UNITS {
        return Err(82);
    }
    let assignments: [UnitAssignment<'_>; abi::MAX_NATIVE_IOMMU_UNITS] =
        core::array::from_fn(|slot| {
            let index = slot.min(units.len() - 1);
            let layout = abi::native_iommu_resources(pool.base(), pool.len(), index).unwrap();
            UnitAssignment {
                identity: UnitIdentity::from_unit(units[index]),
                extent: policy.validate(layout.bank, abi::IOMMU_RESOURCE_BYTES, 4096).unwrap(),
                storage: unsafe { &*(layout.bank as *const ResourceStorage) },
            }
        });
    let plan =
        binding::bind(policy, fresh, pool, &assignments[..units.len()]).map_err(|_| 82u64)?;
    // End every typed bank borrow before an old queue may store a completion.
    drop(assignments);

    let inert = policy.validate(0, 4096, 4096).map_err(|_| 80u64)?;
    let mut excluded = [inert; 34];
    excluded[0] = pool;
    let mut excluded_len = 1;
    for &(base, end) in denied.ranges() {
        excluded[excluded_len] = policy.validate(base, end - base, 4096).map_err(|_| 81u64)?;
        excluded_len += 1;
    }
    excluded[..excluded_len].sort_unstable_by_key(|range| range.base());

    // Complete every admission/read/image check for ALL units before the first
    // physical effect. Partial multi-unit failure never releases a guest.
    let mut roots = [0u64; abi::MAX_NATIVE_IOMMU_UNITS];
    for (index, unit) in plan.units().enumerate() {
        let r = unit.observed_registers;
        if r.control & 1 == 0 {
            return Err(83);
        }
        // AMD p206: actual physical ATS support, not merely DTE I. No native
        // requester ATS stop/IOTLB drain exists yet, so capable units are not
        // admitted by this first profile even if their current I bits are zero.
        if unit.observed_pci.capability_header & (1 << 24) != 0 {
            return Err(90);
        }
        if r.control & (1 << 10) == 0 {
            return Err(91);
        }
        let old_table = policy
            .validate(r.device_table & BASE, ((r.device_table & 511) + 1) * 4096, 4096)
            .map_err(|_| 84u64)?;
        access
            .validate(MemoryKind::PageTable, old_table.base(), old_table.len())
            .map_err(|_| 84u64)?;
        // No-ATS capability above and I=0 in every DTE both matter. This refuses
        // all bypass DTEs instead of choosing a requester alias.
        for offset in (0..old_table.len()).step_by(32) {
            let address = old_table.base() + offset;
            let words = core::array::from_fn(|i| unsafe {
                ptr::read_volatile((address + i as u64 * 8) as *const u64)
            });
            cold::validate_old_dte(policy, words).map_err(|_| 85u64)?;
        }
        let code = (r.command_buffer >> 56) & 15;
        if code < 8 || r.command_buffer & BASE == 0 {
            return Err(86);
        }
        access
            .validate_write(MemoryKind::PageTable, r.command_buffer & BASE, 16u64 << code)
            .map_err(|_| 86u64)?;
        access
            .validate_write(
                MemoryKind::Mmio,
                unit.control_aperture.base(),
                unit.control_aperture.len(),
            )
            .map_err(|_| 87u64)?;
        let layout = abi::native_iommu_resources(pool.base(), pool.len(), index).ok_or(82u64)?;
        let storage = unsafe { &mut *(layout.generations[0] as *mut CompositionStorage) };
        let unit_policy = AddressPolicy::new(unit.iommu_physical_bits, processor.encryption)
            .map_err(|_| 88u64)?;
        let image = cold::prepare_identity(
            storage,
            unit_policy,
            layout.generations[0],
            map,
            &excluded[..excluded_len],
            DteInterruptPolicy::AbortControlled,
        )
        .map_err(|_| 88u64)?;
        cold::verify_identity(
            storage,
            unit_policy,
            layout.generations[0],
            map,
            &excluded[..excluded_len],
            DteInterruptPolicy::AbortControlled,
        )
        .map_err(|_| 88u64)?;
        roots[index] = image.device_table;
    }
    // Distinct physical engines must not consume or update aliased old RAM.
    // Check the complete set before any unit's queue can receive a command.
    cold::validate_old_buffers(policy, plan.units()).map_err(|_| 86u64)?;
    // Fences publish normal coherent RAM before any root/tail MMIO store.
    compiler_fence(Ordering::Release);
    unsafe { asm!("mfence", options(nostack, preserves_flags)) };
    let mut completed = [None; abi::MAX_NATIVE_IOMMU_UNITS];
    for (index, unit) in plan.units().enumerate() {
        let mut effects = NativeEffects { access: &mut access, unit, policy };
        completed[index] = Some(
            cold::publish(&mut effects, policy, unit, roots[index], cold::Limits { polls: POLLS })
                .map_err(|_| 89u64)?,
        );
    }
    for (index, unit) in plan.units().enumerate() {
        let mut effects = NativeEffects { access: &mut access, unit, policy };
        completed[index].ok_or(89u64)?.revalidate(&mut effects).map_err(|_| 89u64)?;
    }
    let (raw360, raw368) = access.platform_io_observation().map_err(|_| 92u64)?;
    if !platform.matches_observation(raw360, raw368) {
        return Err(92);
    }
    Ok(())
}

struct NativeEffects<'a, 'b> {
    access: &'a mut NativeAccess<'b>,
    unit: &'a UninstalledUnitPlan,
    policy: AddressPolicy,
}

impl Access for NativeEffects<'_, '_> {
    fn observe(&mut self) -> Result<RegisterObservation, Error> {
        let u = self.unit;
        let id = u.identity;
        // Current route is checked by every NativeAccess read. Reconfirm decode
        // and feature identity so a relocated aperture cannot receive writes.
        for (offset, expected) in [
            (0, u.observed_pci.vendor_device),
            (id.capability_offset, u.observed_pci.capability_header),
            (id.capability_offset + 4, u.observed_pci.base_low),
            (id.capability_offset + 8, u.observed_pci.base_high),
        ] {
            let value = self
                .access
                .read_pci_u32(
                    id.segment,
                    id.device_id,
                    u.configuration_page.base() + u64::from(offset),
                )
                .map_err(|_| Error::Access)?;
            if value != expected {
                return Err(Error::Changed);
            }
        }
        let mut read =
            |offset| self.access.read_mmio_u64(id.mmio_base + offset).map_err(|_| Error::Access);
        Ok(RegisterObservation {
            device_table: read(0)?,
            command_buffer: read(8)?,
            event_log: read(16)?,
            control: read(24)?,
            exclusion_base: read(32)?,
            exclusion_limit: read(40)?,
            extended_features: if u.observed_registers.extended_features.is_some() {
                Some(read(0x30)?)
            } else {
                None
            },
            extended_features2: if u.observed_registers.extended_features2.is_some() {
                Some(read(0x1a0)?)
            } else {
                None
            },
            command_head: read(0x2000)?,
            command_tail: read(0x2008)?,
            event_head: read(0x2010)?,
            event_tail: read(0x2018)?,
            status: read(0x2020)?,
        })
    }
    fn write_register(&mut self, register: Register, value: u64) -> Result<(), Error> {
        // Read back the configuration route/decode immediately before effects.
        self.observe()?;
        let address = self.unit.identity.mmio_base + u64::from(register.offset());
        unsafe {
            ptr::write_volatile(address as *mut u64, value);
            asm!("mfence", options(nostack, preserves_flags));
        }
        Ok(())
    }
    fn write_command(&mut self, address: u64, words: [u64; 2]) -> Result<(), Error> {
        self.policy.validate(address, 16, 16).map_err(|_| Error::Address)?;
        let old = self.unit.observed_registers.command_buffer;
        let old_bytes = 16u64 << ((old >> 56) & 15);
        let new_base = self.unit.bank.base() + COMMAND_OFFSET;
        if !inside(address, 16, old & BASE, old_bytes) && !inside(address, 16, new_base, 4096) {
            return Err(Error::Address);
        }
        unsafe {
            ptr::write_volatile(address as *mut u64, words[0]);
            ptr::write_volatile((address + 8) as *mut u64, words[1]);
        }
        Ok(())
    }
    fn read_completion(&mut self, address: u64) -> Result<u64, Error> {
        if !inside(address, 8, self.unit.bank.base() + COMPLETION_OFFSET, 16) || address & 7 != 0 {
            return Err(Error::Address);
        }
        Ok(unsafe { ptr::read_volatile(address as *const u64) })
    }
    fn fence(&mut self, fence: Fence) -> Result<(), Error> {
        match fence {
            Fence::PublishMemoryBeforeMmio => {
                compiler_fence(Ordering::Release);
                unsafe { asm!("mfence", options(nostack, preserves_flags)) };
            }
            Fence::AcquireCompletion => {
                unsafe { asm!("lfence", options(nostack, preserves_flags)) };
                compiler_fence(Ordering::Acquire);
            }
        }
        Ok(())
    }
}

fn inside(address: u64, bytes: u64, base: u64, length: u64) -> bool {
    address >= base
        && address
            .checked_add(bytes)
            .is_some_and(|end| base.checked_add(length).is_some_and(|last| end <= last))
}
