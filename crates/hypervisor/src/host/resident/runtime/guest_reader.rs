//! Stopped-guest memory copies through the temporary scratch alias, for instruction fetch,
//! target reads and admitted caller output buffers, with their MTRR admission.

use core::{
    arch::{asm, x86_64::__cpuid_count},
    mem::MaybeUninit,
    ptr, slice,
};

use crate::{
    arch::x86_64::msr::{
        MTRR_CAP, PAT, SYS_CFG, SYS_CFG_DEFINED, SYS_CFG_ENCRYPTION, SYS_CFG_MTRR_FIX_DRAM_EN,
        SYS_CFG_MTRR_FIX_DRAM_MOD_EN,
    },
    boot::memory::ValidatedMemoryMap,
    host::paging::{self, PagingConfig},
    host::resident::{
        runtime::{
            NPT, PHYSICAL_BITS, POOL, RAM, RAM_COUNT, TABLES, image_base,
            msr::{read_msr, write_msr},
            startup::mailboxes,
        },
        terminal,
    },
    memory::address::{EncryptionState, NX, PAGE_BYTES, PRESENT, WRITE},
    svm::{startup::try_lock_routes, vmcb::Vmcb},
};

/// Temporary RAM alias used by instruction reads and the bounded reader.
/// Owns one stopped CPU; each read removes its alias before returning.
pub(super) struct GuestReader {
    map: ValidatedMemoryMap<'static>,
    monitor: crate::memory::address::PhysicalRange,
    mt: crate::memory::mtrrs::Mtrrs,
    pub(super) width: u8,
    pub(super) guest_pat: u64,
    startup_owned: bool,
    pub(super) failure: Option<terminal::FetchReadFailure>,
    count: usize,
    nested: PagingConfig,
    tables: &'static [[u8; PAGE_BYTES]],
}

impl GuestReader {
    pub(super) unsafe fn new(
        vmcb: &Vmcb,
        startup_owned: bool,
        count: usize,
    ) -> Result<Self, terminal::FetchReadFailure> {
        use crate::memory::address::AddressPolicy;
        use terminal::FetchReadFailure as R;
        let root = ptr::addr_of!(NPT) as u64;
        if vmcb.nested_root() != root {
            return Err(R::RamAdmission);
        }
        let width = unsafe { PHYSICAL_BITS };
        let nested = PagingConfig {
            cr3: root,
            physical_bits: width,
            la57: false,
            nxe: true,
            pcid: false,
            page1gb: true,
        };
        // SAFETY: the stopped owner cannot replace this private NPT while a reader is live.
        let tables = unsafe { &(*ptr::addr_of!(NPT)).0 };
        let map = unsafe { core::slice::from_raw_parts(ptr::addr_of!(RAM).cast(), RAM_COUNT) };
        let map = ValidatedMemoryMap::new(map, width).map_err(|_| R::MemoryMap)?;
        let policy =
            AddressPolicy::new(width, EncryptionState::Unencrypted { encryption_bit: None })
                .map_err(|_| R::AddressPolicy)?;
        let (pool_base, pool_bytes) = unsafe { POOL };
        let monitor = policy.validate(pool_base, pool_bytes, 4096).map_err(|_| R::MonitorRange)?;
        let host_pat = unsafe { read_msr(PAT) };
        if host_pat & 255 != 6 {
            return Err(R::HostPat);
        }
        let mt = unsafe { native_mtrrs(width) }.ok_or(R::MtrrCapture)?;
        let guest_pat = u64::from_le_bytes(vmcb.bytes()[0x668..0x670].try_into().unwrap());
        Ok(Self {
            map,
            monitor,
            mt,
            width,
            guest_pat,
            startup_owned,
            failure: None,
            count,
            nested,
            tables,
        })
    }

    /// Same stopped/private-root WB RAM admission as fetch_instruction.
    pub(super) unsafe fn read(&mut self, address: u64, bytes: usize) -> Option<u64> {
        use terminal::FetchReadFailure as R;
        if !matches!(bytes, 1 | 8)
            || (address & 4095) + bytes as u64 > 4096
            || (bytes == 8 && address & 7 != 0)
        {
            self.failure = Some(R::ReadShape);
            return None;
        }
        // SAFETY: the caller owns the stopped CPU and private root; with_page admits the full
        // source page and retains the temporary alias through this single volatile access.
        unsafe {
            self.with_page(address, false, |pointer| {
                if bytes == 1 {
                    ptr::read_volatile(pointer) as u64
                } else {
                    ptr::read_volatile(pointer.cast::<u64>())
                }
            })
        }
    }

    /// Copy one nonempty page fragment from independently identified host physical RAM.
    /// The opt-in caller establishes the GPA-to-HPA relation; this method never assumes identity.
    /// Low memory is refused, avoiding the fixed-MTRR routing-control path entirely.
    /// All admission precedes the alias and every byte is staged until the alias is removed.
    ///
    /// # Safety
    /// Retain exclusive stopped-CPU ownership, the admitted private host root and clear GIF/IF
    /// until return. Source RAM, cache controls and routing must remain valid through the read.
    /// The output must be monitor-owned storage, disjoint from the source and scratch mapping.
    pub(super) unsafe fn copy(
        &mut self,
        hpa: u64,
        output: &mut [u8],
    ) -> Result<(), terminal::FetchReadFailure> {
        use terminal::FetchReadFailure as R;
        self.failure = None;
        if output.is_empty()
            || output.len() > PAGE_BYTES
            || (hpa as usize & (PAGE_BYTES - 1)) + output.len() > PAGE_BYTES
        {
            self.failure = Some(R::ReadShape);
            return Err(R::ReadShape);
        }
        if hpa < 0x0010_0000 {
            self.failure = Some(R::RamAdmission);
            return Err(R::RamAdmission);
        }
        let mut scratch = [MaybeUninit::<u8>::uninit(); PAGE_BYTES];
        // SAFETY: with_page admits the complete RAM page, retains the read-only alias while
        // the exact fragment is read, then invalidates it before committing initialized output.
        let result = unsafe {
            self.with_page(hpa, false, |pointer| {
                read_fragment(pointer, &mut scratch[..output.len()]);
            })
        };
        if result.is_none() {
            // Every with_page refusal supplies the exact existing admission failure.
            return Err(self.failure.unwrap_or(R::RamAdmission));
        }
        // SAFETY: a successful with_page invoked read_fragment, which initialized exactly this
        // prefix. The alias has been removed; the remaining scratch bytes are never observed.
        let initialized = unsafe { slice::from_raw_parts(scratch.as_ptr().cast(), output.len()) };
        output.copy_from_slice(initialized);
        Ok(())
    }

    /// Copy to an independently validated writable caller buffer, never to a requested target.
    ///
    /// # Safety
    /// The caller retains stopped-CPU ownership, validates the destination's user/write
    /// permissions and nested identity mapping, and must ensure its lifetime for this copy.
    /// Rewalking does not establish lifetime; the client must retain its output allocation.
    /// Source is monitor-owned and disjoint from the destination and scratch mapping.
    pub(super) unsafe fn copy_to(
        &mut self,
        hpa: u64,
        source: &[u8],
    ) -> Result<(), terminal::FetchReadFailure> {
        use terminal::FetchReadFailure as R;
        self.failure = None;
        if source.is_empty()
            || source.len() > PAGE_BYTES
            || (hpa as usize & (PAGE_BYTES - 1)) + source.len() > PAGE_BYTES
        {
            return Err(R::ReadShape);
        }
        if hpa < 0x0010_0000 {
            return Err(R::RamAdmission);
        }
        // SAFETY: caller established destination ownership/permissions; with_page independently
        // admits physical RAM, WB caching and monitor exclusion before the temporary RW alias.
        unsafe {
            self.with_page(hpa, true, |pointer| {
                write_fragment(pointer.cast_mut(), source);
            })
        }
        .ok_or_else(|| self.failure.unwrap_or(R::RamAdmission))
    }

    pub(super) fn permits_output(&self, hpa: u64, length: usize) -> bool {
        let page = hpa & !(PAGE_BYTES as u64 - 1);
        hpa >= 0x0010_0000
            && length != 0
            && length <= PAGE_BYTES
            && (hpa as usize & (PAGE_BYTES - 1)) + length <= PAGE_BYTES
            && self.map.permit_guest_write(page, PAGE_BYTES, self.monitor).is_ok()
            && self.mt.page_is_wb(page)
            && nested_fragment(self.nested, self.tables, page, PAGE_BYTES, true)
    }

    /// # Safety
    /// The caller retains stopped-CPU/private-root ownership through return. The closure must
    /// bound every source access to the admitted page and must not return or retain its pointer.
    unsafe fn with_page<T>(
        &mut self,
        address: u64,
        writable: bool,
        read: impl FnOnce(*const u8) -> T,
    ) -> Option<T> {
        use terminal::FetchReadFailure as R;
        let physical = address & !(PAGE_BYTES as u64 - 1);
        let admission = if writable {
            self.map.permit_guest_write(physical, PAGE_BYTES, self.monitor)
        } else {
            self.map.permit_guest_ram(physical, PAGE_BYTES, self.monitor)
        };
        if admission.is_err() {
            self.failure = Some(R::RamAdmission);
            return None;
        }
        // A host scratch alias bypasses hardware NPT. Apply its admission here for every
        // instruction byte, guest page-table read, and buffer copy before touching backing.
        // PAT0 is admitted host WB; physical WB below proves the same type for the alias.
        if !nested_fragment(self.nested, self.tables, physical, PAGE_BYTES, writable) {
            self.failure = Some(R::RamAdmission);
            return None;
        }
        // Serialize core-shared SYS_CFG18 with every low-RAM sample and access.
        // Fetch completes before the APIC operation takes this same route gate.
        let _memory_controls = if self.startup_owned && physical < 0x100000 {
            match try_lock_routes(unsafe { mailboxes(self.count) }) {
                Ok(guard) => Some(guard),
                Err(_) => {
                    self.failure = Some(R::MemoryControlBusy);
                    return None;
                }
            }
        } else {
            None
        };
        let wb = if self.startup_owned && physical < 0x100000 {
            use crate::memory::mtrrs::{CAP_FIX, DEF_TYPE_DEFINED, DEF_TYPE_E, DEF_TYPE_FE};
            if self.mt.default & !DEF_TYPE_DEFINED != 0
                || self.mt.default & (DEF_TYPE_E | DEF_TYPE_FE) != DEF_TYPE_E | DEF_TYPE_FE
                || unsafe { read_msr(MTRR_CAP) } & CAP_FIX == 0
            {
                self.failure = Some(R::FixedMtrrControl);
                return None;
            }
            let Some((index, shift)) = crate::memory::mtrrs::Mtrrs::fixed_range_register(physical)
            else {
                self.failure = Some(R::FixedMtrrRange);
                return None;
            };
            if crate::memory::mtrrs::Tom2Default::supported_profile(
                __cpuid_count(1, 0).eax,
                self.width,
            ) {
                unsafe { native_fixed_page_is_wb(index, shift) }
            } else {
                (unsafe { read_msr(index) } >> shift) & 255 == 6
            }
        } else {
            self.mt.page_is_wb(physical)
        };
        if !wb {
            self.failure = Some(R::PhysicalMemoryNotWb);
            return None;
        }
        let window = image_base() + 0xff000;
        let slot = unsafe {
            ptr::addr_of_mut!((*ptr::addr_of_mut!(TABLES)).0[3][((window >> 12) & 511) as usize])
        };
        // The final page has no backing object and starts absent. Never replace
        // an unexpected retained mapping or leave an alias across guest entry.
        if unsafe { ptr::read_volatile(slot) } != 0 {
            self.failure = Some(R::ScratchAliasOccupied);
            return None;
        }
        // SAFETY: this stopped CPU exclusively owns the absent scratch PTE in its active
        // private root. RAM, monitor exclusion and effective WB were admitted above.
        unsafe {
            ptr::write_volatile(slot, physical | PRESENT | NX | if writable { WRITE } else { 0 });
            asm!("invlpg [{}]",in(reg)window,options(nostack,preserves_flags));
        }
        let alias = ScratchAlias { slot, window };
        let pointer = (window + (address & (PAGE_BYTES as u64 - 1))) as *const u8;
        let value = read(pointer);
        drop(alias);
        Some(value)
    }
}

/// Initialize exactly the requested prefix using aligned volatile RAM loads. Head and tail
/// bytes keep word accesses inside the fragment. This remains a best-effort observation.
///
/// # Safety
/// The source spans output.len() readable WB RAM bytes, disjoint from output, and remains
/// mapped throughout this call. The caller owns admission and removal of the temporary alias.
unsafe fn read_fragment(source: *const u8, output: &mut [MaybeUninit<u8>]) {
    let head = source.align_offset(8).min(output.len());
    let mut offset = 0;
    while offset < head {
        // SAFETY: the head stays within the admitted fragment and initializes one output byte.
        output[offset].write(unsafe { ptr::read_volatile(source.add(offset)) });
        offset += 1;
    }
    while output.len() - offset >= 8 {
        // SAFETY: the head aligned the source; a complete word remains in both ranges. The
        // staging buffer may be unaligned, so the initialized word uses an unaligned store.
        unsafe {
            let value = ptr::read_volatile(source.add(offset).cast::<u64>());
            ptr::write_unaligned(output.as_mut_ptr().add(offset).cast::<u64>(), value);
        }
        offset += 8;
    }
    while offset < output.len() {
        // SAFETY: tail loads never extend beyond the requested range.
        output[offset].write(unsafe { ptr::read_volatile(source.add(offset)) });
        offset += 1;
    }
}

/// Publish exactly the supplied fragment with aligned volatile RAM stores.
///
/// # Safety
/// The destination spans source.len() writable WB RAM bytes, disjoint from source, and remains
/// mapped throughout this call. The caller owns its permissions, lifetime and alias removal.
unsafe fn write_fragment(destination: *mut u8, source: &[u8]) {
    let head = destination.align_offset(8).min(source.len());
    let mut offset = 0;
    while offset < head {
        // SAFETY: each head byte stays within the writable destination and initialized source.
        unsafe { ptr::write_volatile(destination.add(offset), source[offset]) };
        offset += 1;
    }
    while source.len() - offset >= 8 {
        // SAFETY: the head aligned the destination; a complete word remains in both ranges.
        // Monitor-owned source bytes may be unaligned and have no concurrent writer.
        unsafe {
            let value = ptr::read_unaligned(source.as_ptr().add(offset).cast::<u64>());
            ptr::write_volatile(destination.add(offset).cast::<u64>(), value);
        }
        offset += 8;
    }
    while offset < source.len() {
        // SAFETY: each tail byte stays inside the supplied fragment.
        unsafe { ptr::write_volatile(destination.add(offset), source[offset]) };
        offset += 1;
    }
}

/// Conservative software-alias admission against the owning CPU's installed NPT.
/// Host PAT0 must have been admitted as WB. Requiring executable mappings also preserves
/// the existing service policy; no permission or cache-type translation is emulated here.
pub(super) fn nested_fragment(
    config: PagingConfig,
    tables: &[[u8; PAGE_BYTES]],
    gpa: u64,
    length: usize,
    writable: bool,
) -> bool {
    let translation = paging::translate(config, gpa, |entry_address| {
        let offset = usize::try_from(entry_address.checked_sub(config.cr3)?).ok()?;
        let page = tables.get(offset / PAGE_BYTES)?;
        let offset = offset % PAGE_BYTES;
        let entry = page.get(offset..offset.checked_add(8)?)?;
        Some(u64::from_le_bytes(entry.try_into().ok()?))
    });
    translation.is_ok_and(|translation| {
        translation.physical_address == gpa
            && translation.remaining_bytes >= length as u64
            && translation.user
            && translation.executable
            && translation.pat_index == 0
            && (!writable || translation.writable)
    })
}

/// Confined to one stopped access; no reference to guest memory survives alias invalidation.
struct ScratchAlias {
    slot: *mut u64,
    window: u64,
}

impl Drop for ScratchAlias {
    fn drop(&mut self) {
        // SAFETY: only with_page constructs this guard after admitting the exclusive active
        // scratch PTE. The guard is dropped before the reader can return or resume the guest.
        unsafe {
            ptr::write_volatile(self.slot, 0);
            asm!("invlpg [{}]",in(reg)self.window,options(nostack,preserves_flags));
        }
    }
}

/// Read only one qualified physical page through the final, otherwise absent
/// arena PTE. The alias is supervisor RO/NX and is removed before returning.
/// Physical source pages are admitted RAM, effective WB and outside the monitor.
/// Single CPU, stopped guest and GIF/IF clear make the temporary PTE exclusive.
pub(super) unsafe fn fetch_instruction(
    vmcb: &Vmcb,
    startup_owned: bool,
    count: usize,
) -> Result<[u8; 2], u16> {
    let mut reader =
        unsafe { GuestReader::new(vmcb, startup_owned, count) }.map_err(|e| e as u16)?;
    let result = if startup_owned {
        super::fetch::startup_instruction(
            vmcb,
            reader.width,
            reader.guest_pat,
            |address, bytes| unsafe { reader.read(address, bytes) },
        )
    } else {
        super::fetch::instruction(vmcb, reader.width, reader.guest_pat, |address, bytes| unsafe {
            reader.read(address, bytes)
        })
    };
    result.map_err(|error| {
        reader.failure.map_or_else(|| terminal::fetch_failure_code(error), |e| e as u16)
    })
}

/// Enumerated architectural MTRRs, captured boundedly on the owning CPU.
/// Shared by diagnostic UC admission and stopped instruction reading.
pub(super) unsafe fn native_mtrrs(width: u8) -> Option<crate::memory::mtrrs::Mtrrs> {
    crate::memory::mtrrs::Mtrrs::read(width, __cpuid_count(1, 0).eax, |index| unsafe {
        read_msr(index)
    })
    .ok()
}

/// PPR57896 p202/43, APM2 7.9.1: bit19 is thread-private visibility;
/// bit18 is core-shared routing. Caller holds the shared route gate through
/// this sample and the eventual low RAM read. Fixed writes retain the native
/// trusted OS rendezvous contract. All executing monitor storage is >=1MiB.
unsafe fn native_fixed_page_is_wb(index: u32, shift: u8) -> bool {
    use crate::memory::mtrrs::Mtrrs;
    let original = unsafe { read_msr(SYS_CFG) };
    if original & !SYS_CFG_DEFINED != 0
        || original & SYS_CFG_ENCRYPTION != 0
        || original & SYS_CFG_MTRR_FIX_DRAM_EN == 0
    {
        return false;
    }
    let visible = original | SYS_CFG_MTRR_FIX_DRAM_MOD_EN;
    if visible != original {
        unsafe {
            write_msr(SYS_CFG, visible);
        }
    }
    let matched = unsafe { read_msr(SYS_CFG) } == visible;
    let byte = if matched { (unsafe { read_msr(index) } >> shift) as u8 } else { 0 };
    if visible != original {
        unsafe {
            write_msr(SYS_CFG, original);
        }
    }
    let restored = unsafe { read_msr(SYS_CFG) } == original;
    matched && restored && Mtrrs::native_fixed_page_is_wb(visible, byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        boot::memory::MemoryDescriptor,
        memory::{
            address::AddressPolicy,
            mtrrs::{DEF_TYPE_E, MAX_VARIABLE, Mtrrs},
        },
    };

    const NESTED_ROOT: u64 = 0x0020_0000;
    const NESTED_CONFIG: PagingConfig = PagingConfig {
        cr3: NESTED_ROOT,
        physical_bits: 48,
        la57: false,
        nxe: true,
        pcid: false,
        page1gb: true,
    };
    static NESTED_TABLES: [[u8; PAGE_BYTES]; 2] = {
        let mut tables = [[0; PAGE_BYTES]; 2];
        let root = (NESTED_ROOT + PAGE_BYTES as u64 | 7).to_le_bytes();
        let leaf = 0x87u64.to_le_bytes();
        let mut byte = 0;
        while byte < 8 {
            tables[0][byte] = root[byte];
            tables[1][byte] = leaf[byte];
            byte += 1;
        }
        tables
    };
    const RAM_START: u64 = 0x0020_0000;
    const MONITOR_START: u64 = RAM_START + PAGE_BYTES as u64;
    static DESCRIPTORS: [MemoryDescriptor; 4] = [
        MemoryDescriptor {
            memory_type: 7,
            physical_start: RAM_START,
            page_count: 2,
            attributes: 8,
        },
        MemoryDescriptor {
            memory_type: 11,
            physical_start: RAM_START + 2 * PAGE_BYTES as u64,
            page_count: 1,
            attributes: 8,
        },
        MemoryDescriptor {
            memory_type: 7,
            physical_start: RAM_START + 3 * PAGE_BYTES as u64,
            page_count: 1,
            attributes: 0,
        },
        MemoryDescriptor {
            memory_type: 7,
            physical_start: RAM_START + 4 * PAGE_BYTES as u64,
            page_count: 1,
            attributes: 0x2008,
        },
    ];

    fn reader(default: u64) -> GuestReader {
        let policy =
            AddressPolicy::new(48, EncryptionState::Unencrypted { encryption_bit: None }).unwrap();
        GuestReader {
            map: ValidatedMemoryMap::new(&DESCRIPTORS, 48).unwrap(),
            monitor: policy.validate(MONITOR_START, PAGE_BYTES as u64, PAGE_BYTES as u64).unwrap(),
            mt: Mtrrs {
                default,
                count: 0,
                variable: [(0, 0); MAX_VARIABLE],
                physical_bits: 48,
                tom2_default: None,
            },
            width: 48,
            guest_pat: 6,
            startup_owned: false,
            failure: None,
            count: 1,
            nested: NESTED_CONFIG,
            tables: &NESTED_TABLES,
        }
    }

    #[test]
    fn fragment_copies_preserve_bytes_and_guards_at_every_word_alignment() {
        let mut source = [0u8; PAGE_BYTES + 16];
        for (index, byte) in source.iter_mut().enumerate() {
            *byte = index.wrapping_mul(37).wrapping_add(index / 251) as u8;
        }
        for source_offset in 0..8 {
            for destination_offset in 0..8 {
                for length in [0, 1, 7, 8, 9, 15, 16, 17, 63, 64, 65, 255, 256, 257, PAGE_BYTES] {
                    let bytes = &source[source_offset..source_offset + length];
                    let start = 8 + destination_offset;
                    let mut scratch = [MaybeUninit::new(0xa5); PAGE_BYTES + 24];
                    // SAFETY: the separate source and destination span exactly length bytes;
                    // these ordinary test allocations require no privileged mapping work.
                    unsafe {
                        read_fragment(bytes.as_ptr(), &mut scratch[start..start + length]);
                    }
                    // SAFETY: guards were initialized above and the complete copied range was
                    // initialized by read_fragment. No uninitialized bytes are exposed here.
                    let initialized = unsafe {
                        slice::from_raw_parts(scratch.as_ptr().cast::<u8>(), scratch.len())
                    };
                    assert_eq!(&initialized[start..start + length], bytes);
                    assert!(initialized[..start].iter().all(|&byte| byte == 0xa5));
                    assert!(initialized[start + length..].iter().all(|&byte| byte == 0xa5));

                    let mut destination = [0xa5; PAGE_BYTES + 24];
                    // SAFETY: the exact writable test range is disjoint from the source.
                    unsafe {
                        write_fragment(destination.as_mut_ptr().add(start), bytes);
                    }
                    assert_eq!(&destination[start..start + length], bytes);
                    assert!(destination[..start].iter().all(|&byte| byte == 0xa5));
                    assert!(destination[start + length..].iter().all(|&byte| byte == 0xa5));
                }
            }
        }
    }

    #[test]
    fn fragment_reads_initialize_uninitialized_staging_before_publication() {
        let source = [0x72u8; 31];
        let mut scratch = [MaybeUninit::<u8>::uninit(); 31];
        // SAFETY: source and output are separate valid allocations for this complete fragment.
        unsafe { read_fragment(source.as_ptr(), &mut scratch) };
        // SAFETY: read_fragment initialized every byte, including both partial-word ends.
        let initialized = unsafe { slice::from_raw_parts(scratch.as_ptr().cast::<u8>(), 31) };
        assert_eq!(initialized, source);
    }

    #[test]
    fn nested_admission_rejects_quarantine_holes_types_and_permissions() {
        let mut tables = NESTED_TABLES;
        assert!(nested_fragment(NESTED_CONFIG, &tables, RAM_START, PAGE_BYTES, true));
        for leaf in [0, (0x87 & !1) | (1 << 10), 0x8f, 0x83, 0x87 | NX, 0x4000_0087] {
            tables[1][..8].copy_from_slice(&leaf.to_le_bytes());
            assert!(!nested_fragment(NESTED_CONFIG, &tables, RAM_START, PAGE_BYTES, false));
        }
        for level in 0..2 {
            tables = NESTED_TABLES;
            tables[level][0] &= !2;
            assert!(nested_fragment(NESTED_CONFIG, &tables, RAM_START, PAGE_BYTES, false));
            assert!(!nested_fragment(NESTED_CONFIG, &tables, RAM_START, PAGE_BYTES, true));
            tables[level][0] &= !1;
            assert!(!nested_fragment(NESTED_CONFIG, &tables, RAM_START, PAGE_BYTES, false));
        }
    }

    #[test]
    fn every_scratch_access_refuses_denied_npt_before_privileged_work() {
        let mut reader = reader(DEF_TYPE_E | 6);
        reader.tables = &[];
        assert!(!reader.permits_output(RAM_START, 8));
        // SAFETY: RAM and physical WB pass, but owned-NPT admission fails before any
        // privileged instruction or alias is reached. No guest execution is modeled.
        unsafe {
            assert!(reader.read(RAM_START, 1).is_none());
            assert!(reader.read(RAM_START, 8).is_none());
            let mut output = [0xa5; 8];
            assert!(reader.copy(RAM_START, &mut output).is_err());
            assert_eq!(output, [0xa5; 8]);
            assert!(reader.copy_to(RAM_START, &[0x55; 8]).is_err());
        }
        assert!(reader.failure == Some(terminal::FetchReadFailure::RamAdmission));
    }

    #[test]
    fn denied_startup_fetch_refuses_before_low_memory_control_sampling() {
        static LOW_RAM: [MemoryDescriptor; 1] = [MemoryDescriptor {
            memory_type: 7,
            physical_start: 0x8000,
            page_count: 1,
            attributes: 8,
        }];
        let mut reader = reader(DEF_TYPE_E | 6);
        reader.map = ValidatedMemoryMap::new(&LOW_RAM, 48).unwrap();
        reader.startup_owned = true;
        reader.tables = &[];
        // SAFETY: denied NPT precedes low-RAM route locking, MSR reads and scratch aliasing.
        assert!(unsafe { reader.read(0x8000, 1) }.is_none());
        assert!(reader.failure == Some(terminal::FetchReadFailure::RamAdmission));
    }

    #[test]
    fn copy_refuses_bad_shapes_before_mapping_or_output_mutation() {
        for (address, length) in [
            (RAM_START, 0),
            (RAM_START, PAGE_BYTES + 1),
            (RAM_START + PAGE_BYTES as u64 - 1, 2),
            (u64::MAX, 2),
        ] {
            let mut reader = reader(DEF_TYPE_E | 6);
            let mut output = [0xa5; PAGE_BYTES + 1];
            // SAFETY: each shape is refused before any privileged or source-memory operation.
            let result = unsafe { reader.copy(address, &mut output[..length]) };
            assert!(result == Err(terminal::FetchReadFailure::ReadShape));
            assert!(output.iter().all(|&byte| byte == 0xa5));
        }
    }

    #[test]
    fn copy_refuses_low_monitor_mmio_missing_wb_and_protected_ram() {
        for address in [
            0x000f_f000,
            MONITOR_START,
            RAM_START + 2 * PAGE_BYTES as u64,
            RAM_START + 3 * PAGE_BYTES as u64,
            RAM_START + 4 * PAGE_BYTES as u64,
            RAM_START + 5 * PAGE_BYTES as u64,
            1 << 48,
        ] {
            let mut reader = reader(DEF_TYPE_E | 6);
            let mut output = [0xa5; 8];
            // SAFETY: each range fails metadata admission before scratch mapping or hardware.
            let result = unsafe { reader.copy(address, &mut output) };
            assert!(result == Err(terminal::FetchReadFailure::RamAdmission));
            assert_eq!(output, [0xa5; 8]);
        }
    }

    #[test]
    fn copy_requires_effective_wb_after_ram_metadata_admission() {
        for default in [0, 6, DEF_TYPE_E, DEF_TYPE_E | 4] {
            let mut reader = reader(default);
            let mut output = [0xa5; 8];
            // SAFETY: these captured MTRR profiles fail before any scratch mapping or hardware.
            let result = unsafe { reader.copy(RAM_START + 1, &mut output) };
            assert!(result == Err(terminal::FetchReadFailure::PhysicalMemoryNotWb));
            assert_eq!(output, [0xa5; 8]);
        }
    }

    #[test]
    fn output_refuses_protected_ranges_and_bad_shapes_before_mapping() {
        let mut reader = reader(DEF_TYPE_E | 6);
        for (address, length) in [
            (RAM_START, 0),
            (RAM_START, PAGE_BYTES + 1),
            (RAM_START + PAGE_BYTES as u64 - 1, 2),
            (0x000f_f000, 8),
            (MONITOR_START, 8),
            (RAM_START + 2 * PAGE_BYTES as u64, 8),
            (RAM_START + 4 * PAGE_BYTES as u64, 8),
        ] {
            assert!(!reader.permits_output(address, length));
            let bytes = [0x55; PAGE_BYTES + 1];
            // SAFETY: these cases are all refused before privileged mapping or memory access.
            assert!(unsafe { reader.copy_to(address, &bytes[..length]) }.is_err());
        }
        assert!(reader.permits_output(RAM_START, 8));
    }
}
