//! Serialized BSP installation: payload delivery, per-slot preparation, admission and
//! publication of the resident pool before READY.
use core::{arch::x86_64::__cpuid_count, ptr, sync::atomic::Ordering};

use svmvisor_card_abi::package::Package;

use svmvisor_hypervisor::firmware::native::{
    admission::memory,
    resident::{
        self, allocation,
        launch::{directory_valid, pool_valid},
    },
};
use svmvisor_hypervisor::{
    arch::x86_64::capabilities::EvidenceFlag,
    memory::npt::{CacheTableStorage, NptEvidence},
};
use svmvisor_hypervisor::{
    arch::x86_64::msr::{MMIO_CFG_BASE_ADDR, PAT, TARGET_PHYSICAL_BITS, TARGET_SIGNATURE},
    boot::memory::ValidatedMemoryMap,
    host::resident::{
        self as abi, ResidentDirectory,
        configuration::{ROUTE_EXPECTATION_OFFSET, RouteExpectation},
    },
    memory::address::AddressPolicy,
};
use uefi_raw::{
    Handle, Status,
    protocol::loaded_image::LoadedImageProtocol,
    table::{
        boot::{BootServices, MemoryType},
        system::SystemTable,
    },
};

use super::{
    CPU, CPU_COUNT, CPU_IDS, DIRECTORIES, IMAGE, INSTALLED, MAP, MAP_COUNT, PACKAGE, READY,
    RESIDENT_ENTRY_OFFSET,
    capture::{config, cpu, mtrrs, rdmsr},
    closure::host_closure,
    mapping::mapped,
    preparation::{preparation_failure, preparation_map_failure, preparation_step},
    unsupported,
};

use super::{boot_handoff, card_boot, preparation::identity_npt_error_code};

use super::{
    physical_boot,
    physical_boot::admission_hint,
    preparation::{address_error_code, resident_memory_error_code},
};

/// Install retained payload and the selected event, diagnostic seam or EBS interposer once.
/// # Safety
/// These are the live runtime-driver entry arguments. Firmware provides trusted
/// x64 identity mappings, coherent page tables, a flat hidden-segment profile,
/// no debugger/NMI/SMM interference during capture, and this single BSP owns
/// the eventual resident interval. No physical launch is implied by the test
/// profile: AMD routing/encryption profiles outside this admission are refused.
pub(crate) unsafe fn install(image: Handle, table: *mut SystemTable) -> Status {
    if table.is_null() || INSTALLED.swap(true, Ordering::AcqRel) {
        return Status::UNSUPPORTED;
    }
    let boot_services = unsafe { (*table).boot_services };
    if boot_services.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let card = match unsafe { card_boot::Prepared::new(image, &*boot_services) } {
        Ok(value) => value,
        Err(status) => return status,
    };

    let handoff = match {
        preparation_step(1, boot_services as u64);
        unsafe { boot_handoff::Prepared::new(boot_services) }
    } {
        Ok(value) => value,
        Err(status) => {
            if let Some(card) = card {
                card.complete(status, false);
            }
            return status;
        }
    };
    let result = unsafe { install_inner(image, &*boot_services, table) };

    if result.is_ok() && READY.load(Ordering::Acquire) {
        unsafe { handoff.commit(boot_services) };
        unsafe { card_boot::stage(1, 0, 0) };
    }

    if let Some(card) = card {
        card.complete(
            result.as_ref().err().copied().unwrap_or(Status::PROTOCOL_ERROR),
            result.is_ok() && READY.load(Ordering::Acquire),
        );
    }
    match result {
        Ok(()) => Status::SUCCESS,
        Err(status) => status,
    }
}

unsafe fn install_inner(
    image: Handle,
    boot_services: &BootServices,
    table: *const SystemTable,
) -> Result<(), Status> {
    preparation_step(2, 0);
    let processor = unsafe { cpu() }.map_err(unsupported)?;

    preparation_step(3, 0);
    let inventory =
        unsafe { resident::processors::inspect(boot_services) }.map_err(|_| Status::UNSUPPORTED)?;
    let count = inventory.processors().len();

    // Capture one common route before any CPU can enter the guest. Every arm
    // revalidates its own live register against this retained expectation.
    // PPR57896 p210 applies only to this exact target; gate RDMSR first.
    let signature = __cpuid_count(1, 0).eax;
    if signature != TARGET_SIGNATURE || processor.physical_bits != TARGET_PHYSICAL_BITS {
        return Err(Status::UNSUPPORTED);
    }
    let expected_route = RouteExpectation::new(
        signature,
        processor.physical_bits,
        unsafe { rdmsr(MMIO_CFG_BASE_ADDR) },
        count,
    )
    .ok_or(Status::UNSUPPORTED)?;

    let bsp = inventory.bsp_number();
    let common = inventory.processors()[bsp].identity;
    if common.apic_id != processor.apic_id {
        return Err(Status::UNSUPPORTED);
    }
    for p in inventory.processors() {
        let mut identity = p.identity;
        // Identity fields are CPU-local; all common requirements must agree.
        // Keep the current physical bootstrap inventory bound.
        identity.apic_id = common.apic_id;
        if identity != common || p.identity.apic_id > 254 {
            return Err(Status::UNSUPPORTED);
        }
    }

    preparation_step(4, 0);
    let mut loaded = ptr::null_mut();
    let status =
        unsafe { (boot_services.handle_protocol)(image, &LoadedImageProtocol::GUID, &mut loaded) };
    if status != Status::SUCCESS {
        return Err(status);
    }
    if loaded.is_null() || loaded as usize % core::mem::align_of::<LoadedImageProtocol>() != 0 {
        return Err(Status::LOAD_ERROR);
    }
    let loaded = unsafe { &*loaded.cast::<LoadedImageProtocol>() };
    let image_base = loaded.image_base as u64;
    if loaded.image_code_type != MemoryType::RUNTIME_SERVICES_CODE
        || loaded.image_data_type != MemoryType::RUNTIME_SERVICES_DATA
        || image_base == 0
        || image_base & 4095 != 0
        || loaded.image_size == 0
        || loaded.image_size > 16 * 1024 * 1024
        || image_base.checked_add(loaded.image_size).is_none()
    {
        return Err(Status::UNSUPPORTED);
    }
    unsafe {
        IMAGE = (image_base, loaded.image_size);
    }

    preparation_step(5, image_base);
    let package = Package::parse(PACKAGE, RESIDENT_ENTRY_OFFSET).map_err(|_| Status::LOAD_ERROR)?;

    preparation_step(6, 0);
    let mut arena =
        unsafe { allocation::allocate_for_processors(boot_services, count) }.map_err(|error| {
            let (reason, status, address) = error.diagnostic();
            preparation_failure(reason, status, address);
            Status::OUT_OF_RESOURCES
        })?;

    preparation_step(7, arena.base());
    let cfg = unsafe { config(processor) }.map_err(unsupported)?;

    preparation_step(8, arena.base());
    let mt = unsafe { mtrrs(processor.physical_bits) }.map_err(unsupported)?;
    let pat = unsafe { rdmsr(PAT) };
    let policy = AddressPolicy::new(processor.physical_bits, processor.encryption)
        .map_err(|_| Status::UNSUPPORTED)?;
    {
        preparation_step(9, 0);
        let mut map = unsafe { memory::collect(boot_services) }
            .map_err(|error| preparation_map_failure(error))?;

        preparation_step(10, arena.base());
        arena.validate_map(policy, map.descriptors()).map_err(|_| Status::UNSUPPORTED)?;

        for slot in 0..count {
            preparation_step(11, arena.slot_base(slot).unwrap_or(0));
            unsafe {
                mapped(
                    map.descriptors(),
                    cfg,
                    &mt,
                    pat,
                    arena.slot_base(slot).ok_or(Status::LOAD_ERROR)?,
                    0x100000,
                    true,
                    true,
                )
            }
            .map_err(unsupported)?;

            preparation_step(12, arena.slot_base(slot).unwrap_or(0));
            unsafe { arena.initialize_slot(&package, slot) }.map_err(|_| Status::LOAD_ERROR)?;
        }
        let retained = abi::retained_iommu_base(arena.base(), arena.bytes() as u64)
            .ok_or(Status::LOAD_ERROR)?;
        unsafe { super::iommu::mapped_backing(map.descriptors(), cfg, &mt, pat, retained, true) }
            .map_err(unsupported)?;
        // Capture directly into admitted lifetime backing after image copies.
        // Partial/failed discovery is retained as information, never authority.
        // No accessor survives failure: the arena still owns rollback here.
        unsafe {
            super::iommu::capture(
                table,
                map.descriptors(),
                cfg,
                &mt,
                pat,
                policy,
                expected_route,
                count,
                retained,
            )
        }?;
        unsafe { super::iommu::prepare_resources(arena.base(), arena.bytes() as u64, policy) }?;
        unsafe {
            super::iommu::prepare_presentation(
                arena.base(),
                arena.bytes() as u64,
                policy,
                expected_route,
                count,
            )
        }?;
        unsafe {
            super::control_policy::publish(retained, arena.base(), policy, expected_route, count)
        }?;
        map.release()?;
    }
    let mut directories = [ResidentDirectory::default(); abi::MAX_RESIDENT_CPUS];

    let mut physical_storage = {
        preparation_step(13, 0);
        unsafe { physical_boot::prepare(boot_services, bsp, count, cfg)? }
    };

    for (slot, directory) in directories.iter_mut().enumerate().take(count) {
        let base = arena.slot_base(slot).ok_or(Status::LOAD_ERROR)?;
        preparation_step(14, base);
        let prepare: abi::PrepareRuntime =
            unsafe { core::mem::transmute(base as usize + RESIDENT_ENTRY_OFFSET) };
        let prepared = unsafe {
            prepare(
                base,
                directory,
                arena.base(),
                arena.bytes() as u64,
                slot as u64,
                inventory.processors()[slot].identity.apic_id as u64,
            )
        };
        if prepared != 0
            || !directory_valid(directory, base)
            || base + RESIDENT_ENTRY_OFFSET as u64 >= directory.text_end
        {
            return Err(Status::LOAD_ERROR);
        }
    }
    if !pool_valid(&directories[..count]) {
        return Err(Status::LOAD_ERROR);
    }

    {
        use svmvisor_hypervisor::svm::cache_policy::SharedCache;
        const _: () = {
            assert!(core::mem::size_of::<SharedCache>() <= abi::CACHE_SHARED_BYTES as usize);
            assert!(4096 % core::mem::align_of::<SharedCache>() == 0);
        };
        // Only the serialized installer initializes the common backing, after
        // image copies and before admission or activation of any resident CPU.
        let shared = (arena.base() + abi::CACHE_SHARED_OFFSET) as *mut SharedCache;
        unsafe {
            ptr::write_bytes(shared.cast::<u8>(), 0, abi::CACHE_SHARED_BYTES as usize);
            shared.write(SharedCache::new());
        }
    }

    {
        // Separate fixed block follows all 32 mailboxes; initialize before any
        // AP can enter. It is not a guest-writable acknowledgement buffer.
        let terminal_control =
            (arena.base() + abi::STARTUP_PAGE_OFFSET + abi::terminal::CONTROL_OFFSET)
                as *mut abi::terminal::TerminalControl;
        unsafe {
            terminal_control.write(abi::terminal::TerminalControl::new());
        }
    }

    {
        // The same page is aliased by every private host root and excluded by
        // every guest NPT. No firmware pointer or mutable guest copy is kept.
        let destination = (arena.base() + abi::STARTUP_PAGE_OFFSET + ROUTE_EXPECTATION_OFFSET)
            as *mut RouteExpectation;
        unsafe { destination.write(expected_route) };
    }

    {
        use svmvisor_hypervisor::svm::startup::NativeStartupMailbox;
        const _: () = assert!(
            core::mem::size_of::<NativeStartupMailbox>() * abi::MAX_RESIDENT_CPUS
                <= abi::terminal::CONTROL_OFFSET as usize
        );
        let shared = (arena.base() + abi::STARTUP_PAGE_OFFSET) as *mut NativeStartupMailbox;
        for slot in 0..count {
            // The admitted pool is exclusively DXE-owned before activation.
            // Constructors publish Assigned slots; the target later marks ready.
            unsafe {
                shared.add(slot).write(NativeStartupMailbox::new(
                    inventory.processors()[slot].identity.apic_id,
                ));
            }
        }
    }

    {
        preparation_step(15, 0);
        let mut map = unsafe { memory::collect(boot_services) }.map_err(preparation_map_failure)?;
        arena.validate_map(policy, map.descriptors()).map_err(|_| Status::UNSUPPORTED)?;
        ValidatedMemoryMap::new(map.descriptors(), processor.physical_bits.min(40))
            .map_err(|_| Status::UNSUPPORTED)?;
        // The admission-hint recorder is armed around each slot's closure and
        // NPT work (operations 9/10) so a refusal names its predicate and code
        // on the card without any test feature; see `slot_admission_refused`.
        for (slot, d) in directories.iter().enumerate().take(count) {
            preparation_step(16, d.arena_base);
            physical_boot::admission_begin(9, slot as u32, d.apic_id as u32);
            unsafe {
                host_closure(&directories[..count], slot, map.descriptors(), processor, &mt, pat)
            }
            .map_err(|code| unsafe {
                physical_boot::slot_admission_refused(33, count, code, processor, map.descriptors())
            })?;
            let pool = policy.validate(d.pool_base, d.pool_bytes, 4096).map_err(|error| {
                let code = address_error_code(error);
                admission_hint(635, d.pool_base, d.pool_bytes, code);
                unsafe {
                    physical_boot::slot_admission_refused(
                        34,
                        count,
                        code,
                        processor,
                        map.descriptors(),
                    )
                }
            })?;
            physical_boot::admission_clear();
            preparation_step(17, d.arena_base);
            physical_boot::admission_begin(10, slot as u32, d.apic_id as u32);
            let denied =
                unsafe { super::control_policy::read(d.pool_base, d.pool_bytes, policy, count) }
                    .map_err(unsupported)?;
            let mut _npt = resident::memory::prepare_identity_npt_with_denials(
                unsafe { &mut (*(d.npt as *mut CacheTableStorage)).0 },
                d.npt,
                policy,
                pool,
                map.descriptors(),
                NptEvidence {
                    nx_supported: EvidenceFlag::Set,
                    host_nxe: EvidenceFlag::Set,
                    host_four_level: EvidenceFlag::Set,
                },
                EvidenceFlag::Set,
                pat,
                &denied,
            )
            .map_err(|error| {
                let code = resident_memory_error_code(error);
                admission_hint(636, d.npt, d.pool_base, code);
                unsafe {
                    physical_boot::slot_admission_refused(
                        35,
                        count,
                        code,
                        processor,
                        map.descriptors(),
                    )
                }
            })?;

            unsafe {
                super::configuration::protect(
                    &mut _npt,
                    expected_route,
                    processor.physical_bits,
                    count,
                )
            }
            .map_err(|error| {
                let code = identity_npt_error_code(error);
                admission_hint(637, d.npt, d.pool_base, code);
                unsafe {
                    physical_boot::slot_admission_refused(
                        36,
                        count,
                        code,
                        processor,
                        map.descriptors(),
                    )
                }
            })?;
            physical_boot::admission_clear();
        }
        preparation_step(18, 0);
        unsafe { physical_boot::validate(map.descriptors(), cfg, &mt, pat, count) }
            .map_err(unsupported)?;
        unsafe {
            ptr::copy_nonoverlapping(
                map.descriptors().as_ptr(),
                ptr::addr_of_mut!(MAP).cast(),
                map.descriptors().len(),
            );
            MAP_COUNT = map.descriptors().len();
            DIRECTORIES = directories;
            CPU_COUNT = count;
            CPU = Some(processor);
            for (slot, p) in inventory.processors().iter().enumerate() {
                CPU_IDS[slot] = p.identity.apic_id;
            }
        }
        map.release()?;
        preparation_step(19, 0);
        unsafe {
            physical_boot::admit_processors(boot_services)?;
        }
        preparation_step(20, arena.base());
        arena.publish().map_err(|_| Status::DEVICE_ERROR)?;
        physical_storage.retain();
        READY.store(true, Ordering::Release);
        return Ok(());
    }
}
