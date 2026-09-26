//! Native table-source primitives. These install real readable NPT guards and
//! use the existing retained scratch alias to copy protected sources. They do
//! not assert a DMA drain, run an unimplemented arbitrary-instruction step, or
//! release the cold-boot hold. Every tracked write currently requires the owner
//! to keep all guests stopped until that write/publication protocol exists.

use crate::{
    host::resident::runtime::{NPT, State, cache, guest_reader::GuestReader},
    memory::{
        address::{AddressPolicy, PAGE_BYTES},
        iommu::{
            image::ProtectedRange,
            virtualized::{
                compose::HostMap,
                device::{GuestMemory, MemoryError},
                snapshot::{CapturePage, SnapshotPage},
            },
        },
        npt::{
            CacheNptError,
            table_guard::{
                MAX_TABLE_SOURCE_PAGES, TableWriteDenials, verify_identity_table_guards,
                verify_identity_tables,
            },
        },
    },
    svm::vmcb::Vmcb,
};
use core::ptr;

static mut SOURCES: [u64; MAX_TABLE_SOURCE_PAGES] = [0; MAX_TABLE_SOURCE_PAGES];
static mut SOURCE_COUNT: usize = 0;
static mut SOURCE_GENERATION: u64 = 0;

/// This CPU's retained monotonic source guards. Cache rebuilding takes the same
/// immutable policy and cannot silently restore table writes.
pub(super) unsafe fn local_guards(
    policy: AddressPolicy,
) -> Result<TableWriteDenials<'static>, CacheNptError> {
    // SAFETY: only this stopped CPU mutates its local image; no borrow crosses
    // guest entry or a source-policy replacement.
    let pages = unsafe { core::slice::from_raw_parts(ptr::addr_of!(SOURCES).cast(), SOURCE_COUNT) };
    TableWriteDenials::new(policy, pages)
}

/// # Safety
/// Called by the stopped owner on EACH vCPU during the global source barrier;
/// none may resume until every CPU has installed the same generation. Physical
/// source writes must separately be excluded before any source capture. Caller
/// also excludes concurrent cache staging on this CPU.
pub(super) unsafe fn install_sources(
    state: &State,
    vmcb: &mut Vmcb,
    generation: u64,
    pages: &[u64],
) -> Result<(), CacheNptError> {
    let policy = state.capabilities.as_ref().ok_or(CacheNptError::Storage)?.address_policy();
    let guards = TableWriteDenials::new(policy, pages)?;
    let old = unsafe { local_guards(policy)? };
    if generation < unsafe { SOURCE_GENERATION }
        || old.pages().iter().any(|page| !guards.covers_page(*page))
        || (generation == unsafe { SOURCE_GENERATION } && old.pages() != pages)
        || vmcb.nested_root() != ptr::addr_of!(NPT) as u64
    {
        return Err(CacheNptError::Entry);
    }
    unsafe {
        cache::install_source_guards(vmcb, policy, guards)?;
    }
    // Commit metadata only AFTER the actual NPT and full-flush request exist.
    unsafe {
        ptr::copy_nonoverlapping(pages.as_ptr(), ptr::addr_of_mut!(SOURCES).cast(), pages.len());
        SOURCE_COUNT = pages.len();
        SOURCE_GENERATION = generation;
    }
    Ok(())
}

/// # Safety
/// Same stopped CPU and retained source barrier as install_sources, with actual
/// all-unit DMA write exclusion plus matching physical invalidation/drain already
/// complete. The destination is exclusive monitor-owned scratch. This routine
/// checks current NPT bytes; it never turns a callback boolean into protection.
pub(super) unsafe fn copy_source(
    state: &State,
    vmcb: &Vmcb,
    source: CapturePage,
    output: &mut [u8; PAGE_BYTES],
) -> Result<(), MemoryError> {
    let policy = state.capabilities.as_ref().ok_or(MemoryError::Unavailable)?.address_policy();
    let guards = unsafe { local_guards(policy) }.map_err(|_| MemoryError::Unavailable)?;
    // Current native NPT is identity-only and its builder rejects aliases.
    // A future nonidentity native guest map requires a matching scratch adapter.
    if source.guest_page != source.host_page || !guards.covers_page(source.host_page) {
        return Err(MemoryError::Range);
    }
    unsafe { verify_identity_tables(&(*ptr::addr_of!(NPT)).0, ptr::addr_of!(NPT) as u64, guards) }
        .map_err(|_| MemoryError::StaleCapture)?;
    let mut reader = unsafe { GuestReader::new(vmcb, state.startup_owned, state.count) }
        .map_err(|_| MemoryError::Unavailable)?;
    unsafe { reader.copy(source.host_page, output) }.map_err(|_| MemoryError::Unavailable)
}

pub(super) unsafe fn tracked_write(
    vmcb: &Vmcb,
    policy: AddressPolicy,
) -> Result<bool, CacheNptError> {
    let exit = vmcb.exit_snapshot();
    if exit.code != 0x400 || exit.info1 & 2 == 0 {
        return Ok(false);
    }
    let guards = unsafe { local_guards(policy)? };
    Ok(guards.covers_page(exit.info2 & !4095))
}

/// Validate retained source policy against this CPU's actual installed NPT at
/// the final entry boundary. This cannot stand in for peer TLB acknowledgements
/// or any physical source-DMA exclusion.
pub(super) unsafe fn verify_sources(
    vmcb: &Vmcb,
    policy: AddressPolicy,
) -> Result<(), CacheNptError> {
    let root = ptr::addr_of!(NPT) as u64;
    if vmcb.nested_root() != root {
        return Err(CacheNptError::Storage);
    }
    let guards = unsafe { local_guards(policy)? };
    unsafe { verify_identity_table_guards(&(*ptr::addr_of!(NPT)).0, root, guards) }
}

/// Retained native output adapter. Event/completion stores use guest GPA policy
/// and actual current NPT admission; no guest pointer is used as a host pointer.
/// Baseline output records are at most 16 bytes and aligned to avoid page splits.
pub(super) struct NativeGuestMemory<'a> {
    reader: GuestReader,
    host: &'a HostMap<'a>,
    sources: &'a [SnapshotPage],
    retained_sources: &'a [u64],
    protected: &'a [ProtectedRange],
}

impl<'a> NativeGuestMemory<'a> {
    /// # Safety
    /// Exclusive stopped CPU/private root, valid RAM/cache/routing state and
    /// retained writable guest output allocations through all adapter calls.
    pub(super) unsafe fn new(
        state: &State,
        vmcb: &Vmcb,
        host: &'a HostMap<'a>,
        sources: &'a [SnapshotPage],
        retained_sources: &'a [u64],
        protected: &'a [ProtectedRange],
    ) -> Result<Self, MemoryError> {
        let reader = unsafe { GuestReader::new(vmcb, state.startup_owned, state.count) }
            .map_err(|_| MemoryError::Unavailable)?;
        Ok(Self { reader, host, sources, retained_sources, protected })
    }
}

impl GuestMemory for NativeGuestMemory<'_> {
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if !matches!(bytes.len(), 8 | 16) || address & (bytes.len() as u64 - 1) != 0 {
            return Err(MemoryError::Range);
        }
        let end = address.checked_add(bytes.len() as u64).ok_or(MemoryError::Range)?;
        let map = self
            .host
            .ranges()
            .iter()
            .find(|map| map.guest_base <= address && end <= map.guest_base + map.len)
            .ok_or(MemoryError::Range)?;
        if !map.permissions.allows_write() {
            return Err(MemoryError::ReadOnly);
        }
        let host = map.host_base + address - map.guest_base;
        let host_end = host + bytes.len() as u64;
        if self
            .sources
            .iter()
            .any(|page| host < page.source_host_page() + 4096 && page.source_host_page() < host_end)
            || self.retained_sources.iter().any(|page| host < *page + 4096 && *page < host_end)
            || self
                .protected
                .iter()
                .chain(self.host.protected().iter())
                .any(|p| host < p.base + p.len && p.base < host_end)
            || !self.reader.permits_output(host, bytes.len())
        {
            return Err(MemoryError::ReadOnly);
        }
        // SAFETY: construction retains stopped-CPU ownership; entire destination
        // was checked above and copy_to repeats RAM/cache/NPT admission before
        // it installs its temporary RW alias, removing it before returning.
        unsafe { self.reader.copy_to(host, bytes) }.map_err(|_| MemoryError::Unavailable)
    }
}
