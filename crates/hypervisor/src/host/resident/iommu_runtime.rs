//! One retained workspace shared by every native unit and every vCPU. Typed
//! cells are initialized in place: no 18MiB stack value or zeroed-enum reference.
//! The lock serializes software ownership only; it cannot stop CPU/DMA writers.

use crate::memory::iommu::{
    image::{MappingRange, ProtectedRange},
    physical::PhysicalUnit,
    tables::{PageCoherency, Permissions},
    virtualized::{
        compose::GuestHostRange,
        device::Device,
        snapshot::{CapturePage, Dependency, MAX_SNAPSHOT_PAGES, SnapshotPage},
    },
};
use core::{
    mem::{MaybeUninit, size_of},
    ptr,
    sync::atomic::{AtomicU32, Ordering},
};

const MAGIC: u64 = u64::from_le_bytes(*b"VIOMMU17");
pub const WORKSPACE_BYTES: usize = 0x1200000;
const N: usize = MAX_SNAPSHOT_PAGES;

/// Every bit pattern of each uninitialized payload cell is valid. Only
/// initialize_workspace followed by lock acquisition exposes typed references.
#[repr(C, align(4096))]
pub struct NativeWorkspace {
    magic: u64,
    lock: AtomicU32,
    units: u32,
    source_generation: u64,
    source_count: usize,
    sources: [u64; N],
    devices: [MaybeUninit<Device>; 4],
    pages: [MaybeUninit<SnapshotPage>; N],
    requests: [MaybeUninit<CapturePage>; N],
    dependencies: [MaybeUninit<Dependency>; N],
    mappings: [MaybeUninit<MappingRange>; N],
    host: [MaybeUninit<GuestHostRange>; N],
    protected: [MaybeUninit<ProtectedRange>; N],
}

const _: () = assert!(size_of::<NativeWorkspace>() <= WORKSPACE_BYTES);

/// # Safety
/// `workspace` is aligned, exclusive, writable/WB retained backing of at least
/// WORKSPACE_BYTES. No CPU or hardware consumer can access it during this call.
/// Construction runs either under actual CPU/DMA exclusion or the explicitly
/// trusted preguest firmware/SMM/device construction phase. Runtime use requires
/// actual exclusions independently; initialization does not establish them.
pub unsafe fn initialize_workspace(workspace: *mut NativeWorkspace) {
    // SAFETY: all uninitialized fields admit arbitrary bits; no typed payload
    // reference is created until its individual value has been initialized.
    unsafe {
        ptr::write_bytes(workspace.cast::<u8>(), 0, size_of::<NativeWorkspace>());
    }
    let empty_mapping = MappingRange {
        io_base: 0,
        system_base: 0,
        len: 0,
        permissions: Permissions::None,
        coherency: PageCoherency::Inherit,
    };
    let empty_host =
        GuestHostRange { guest_base: 0, host_base: 0, len: 0, permissions: Permissions::None };
    for index in 0..N {
        // SAFETY: each in-bounds destination is uniquely owned and each write
        // initializes one cell, with at most one page-sized temporary.
        unsafe {
            ptr::addr_of_mut!((*workspace).pages)
                .cast::<SnapshotPage>()
                .add(index)
                .write(SnapshotPage::EMPTY);
            ptr::addr_of_mut!((*workspace).requests)
                .cast::<CapturePage>()
                .add(index)
                .write(CapturePage::EMPTY);
            ptr::addr_of_mut!((*workspace).dependencies)
                .cast::<Dependency>()
                .add(index)
                .write(Dependency::EMPTY);
            ptr::addr_of_mut!((*workspace).mappings)
                .cast::<MappingRange>()
                .add(index)
                .write(empty_mapping);
            ptr::addr_of_mut!((*workspace).host)
                .cast::<GuestHostRange>()
                .add(index)
                .write(empty_host);
            ptr::addr_of_mut!((*workspace).protected)
                .cast::<ProtectedRange>()
                .add(index)
                .write(ProtectedRange { base: 0, len: 0 });
        }
    }
    // Publish only after every workspace payload has its valid Rust value.
    unsafe {
        ptr::addr_of_mut!((*workspace).magic).write(MAGIC);
    }
}

pub struct WorkspaceGuard {
    workspace: *mut NativeWorkspace,
}

/// # Safety
/// The pointer names this initialized retained shared allocation, writable in
/// this CPU's private root, excluded from guests and devices for its lifetime.
/// No access other than through a held guard may mutate the payload.
pub unsafe fn try_lock_workspace(workspace: *mut NativeWorkspace) -> Option<WorkspaceGuard> {
    if workspace.is_null() || workspace as usize & 4095 != 0 {
        return None;
    }
    // SAFETY: caller supplies initialized retained backing; header is immutable.
    if unsafe { ptr::addr_of!((*workspace).magic).read() } != MAGIC {
        return None;
    }
    let lock = unsafe { &*ptr::addr_of!((*workspace).lock) };
    lock.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).ok()?;
    Some(WorkspaceGuard { workspace })
}

pub struct WorkspaceParts<'a> {
    pub pages: &'a mut [SnapshotPage],
    pub requests: &'a mut [CapturePage],
    pub dependencies: &'a mut [Dependency],
    pub mappings: &'a mut [MappingRange],
    pub host: &'a mut [GuestHostRange],
    pub protected: &'a mut [ProtectedRange],
}

impl WorkspaceGuard {
    pub fn parts(&mut self) -> WorkspaceParts<'_> {
        let workspace = self.workspace;
        // SAFETY: initialization established every element, the held global
        // lock is exclusive, fields are disjoint and references borrow the guard.
        unsafe {
            WorkspaceParts {
                pages: core::slice::from_raw_parts_mut(
                    ptr::addr_of_mut!((*workspace).pages).cast(),
                    N,
                ),
                requests: core::slice::from_raw_parts_mut(
                    ptr::addr_of_mut!((*workspace).requests).cast(),
                    N,
                ),
                dependencies: core::slice::from_raw_parts_mut(
                    ptr::addr_of_mut!((*workspace).dependencies).cast(),
                    N,
                ),
                mappings: core::slice::from_raw_parts_mut(
                    ptr::addr_of_mut!((*workspace).mappings).cast(),
                    N,
                ),
                host: core::slice::from_raw_parts_mut(
                    ptr::addr_of_mut!((*workspace).host).cast(),
                    N,
                ),
                protected: core::slice::from_raw_parts_mut(
                    ptr::addr_of_mut!((*workspace).protected).cast(),
                    N,
                ),
            }
        }
    }

    pub fn bind_unit(&mut self, slot: usize, unit: PhysicalUnit, epoch: u64) -> bool {
        if slot >= 4 || epoch == 0 {
            return false;
        }
        // SAFETY: the guard exclusively owns payload and the checked unit cell.
        unsafe {
            if (*self.workspace).units & (1 << slot) != 0 {
                return false;
            }
            (*self.workspace).devices[slot].write(Device::new(unit, epoch));
            (*self.workspace).units |= 1 << slot;
        }
        true
    }

    pub fn device(&mut self, slot: usize) -> Option<&mut Device> {
        if slot >= 4 {
            return None;
        }
        // SAFETY: initialized bit is set only after writing the Device; the
        // returned reference cannot survive this exclusive guard borrow.
        unsafe {
            if (*self.workspace).units & (1 << slot) == 0 {
                return None;
            }
            Some((*self.workspace).devices[slot].assume_init_mut())
        }
    }

    /// Retain a monotonic union of all source HPAs for the owner epoch. Removed
    /// guest links do not immediately release source protection or backing.
    pub fn retain_sources(&mut self, pages: &[SnapshotPage]) -> Result<u64, ()> {
        // SAFETY: the lock exclusively owns these disjoint payload fields. Do
        // not create &mut NativeWorkspace: other CPUs can still inspect its
        // separate atomic lock field while failing to acquire this guard.
        let (sources, count, generation) = unsafe {
            (
                &mut *ptr::addr_of_mut!((*self.workspace).sources),
                &mut *ptr::addr_of_mut!((*self.workspace).source_count),
                &mut *ptr::addr_of_mut!((*self.workspace).source_generation),
            )
        };
        if pages.len() > N {
            return Err(());
        }
        let additional = pages
            .iter()
            .enumerate()
            .filter(|(index, page)| {
                !sources[..*count].contains(&page.source_host_page())
                    && !pages[..*index]
                        .iter()
                        .any(|prior| prior.source_host_page() == page.source_host_page())
            })
            .count();
        if *count + additional > N {
            return Err(());
        }
        if additional == 0 {
            return Ok(*generation);
        }
        let next = generation.checked_add(1).ok_or(())?;
        for page in pages {
            let host = page.source_host_page();
            if !sources[..*count].contains(&host) {
                sources[*count] = host;
                *count += 1;
            }
        }
        sources[..*count].sort_unstable();
        *generation = next;
        Ok(next)
    }

    pub fn sources(&self) -> (u64, &[u64]) {
        // SAFETY: the guard excludes payload mutation by every other CPU.
        let workspace = unsafe { &*self.workspace };
        (workspace.source_generation, &workspace.sources[..workspace.source_count])
    }
}

impl Drop for WorkspaceGuard {
    fn drop(&mut self) {
        // SAFETY: backing is retained beyond the guard; every payload borrow
        // ended before the guard can drop.
        unsafe { &*ptr::addr_of!((*self.workspace).lock) }.store(0, Ordering::Release);
    }
}
