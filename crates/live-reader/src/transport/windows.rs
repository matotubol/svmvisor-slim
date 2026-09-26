//! Windows allocation, affinity and the narrow user-mode VMMCALL ABI.

use std::{arch::asm, cell::Cell, ffi::c_void, marker::PhantomData, ptr, rc::Rc, time::Instant};

use svmvisor_card_abi::{
    batch::{MAX_RESPONSE_BYTES, REQUEST_BYTES},
    local,
};

use crate::transport::{Exchange, complete, context_complete};

const PAGE_BYTES: usize = 4096;
const ALLOCATION_BYTES: usize = 3 * PAGE_BYTES;

#[link(name = "kernel32")]
unsafe extern "system" {
    #[cfg(not(test))]
    fn GetCurrentThread() -> *mut c_void;
    fn GetCurrentThreadId() -> u32;
    fn SetThreadGroupAffinity(
        thread: *mut c_void,
        affinity: *const GroupAffinity,
        previous: *mut GroupAffinity,
    ) -> i32;
    #[cfg(not(test))]
    fn VirtualAlloc(address: *mut c_void, bytes: usize, kind: u32, protect: u32) -> *mut c_void;
    fn VirtualFree(address: *mut c_void, bytes: usize, kind: u32) -> i32;
    #[cfg(not(test))]
    fn VirtualLock(address: *mut c_void, bytes: usize) -> i32;
    fn VirtualUnlock(address: *mut c_void, bytes: usize) -> i32;
}

pub(crate) struct NativeTransport {
    memory: *mut u8,
    previous: GroupAffinity,
    thread: *mut c_void,
    thread_id: u32,
    session: u64,
    hypercalls: Cell<u64>,
    // Affinity and pseudohandle belong to the constructing thread.
    owner: PhantomData<Rc<()>>,
}

impl NativeTransport {
    #[cfg(test)]
    pub(crate) fn new(_: u16) -> Result<Self, String> {
        Err("live VMMCALL is disabled in test builds".into())
    }

    #[cfg(not(test))]
    pub(crate) fn new(cpu: u16) -> Result<Self, String> {
        if cpu >= 32 {
            return Err("local CPU must be 0..31 in processor group zero".into());
        }
        let mut previous = GroupAffinity { mask: 0, group: 0, reserved: [0; 3] };
        let affinity = GroupAffinity { mask: 1usize << cpu, group: 0, reserved: [0; 3] };
        // SAFETY: valid writable structure, current-thread handle and bounded processor mask.
        let thread = unsafe { GetCurrentThread() };
        // SAFETY: all FFI pointers remain valid for the synchronous call.
        if unsafe { SetThreadGroupAffinity(thread, &affinity, &mut previous) } == 0 {
            return Err(format!(
                "pin local reader to group0 CPU{cpu}: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: the OS allocates a private page-aligned read/write region.
        let memory =
            unsafe { VirtualAlloc(ptr::null_mut(), ALLOCATION_BYTES, 0x3000, 4) }.cast::<u8>();
        if memory.is_null() {
            // SAFETY: restore the affinity returned by the successful call above.
            unsafe {
                SetThreadGroupAffinity(thread, &previous, ptr::null_mut());
            }
            return Err("allocate local batch buffers failed".into());
        }
        // SAFETY: this thread owns the complete newly allocated writable range.
        unsafe {
            ptr::write_bytes(memory, 0, ALLOCATION_BYTES);
        }
        // SAFETY: valid allocation; lock reduces paging but does not prove mapping lifetime.
        if unsafe { VirtualLock(memory.cast(), ALLOCATION_BYTES) } == 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: allocation and saved affinity belong to this construction attempt.
            unsafe {
                VirtualFree(memory.cast(), 0, 0x8000);
                SetThreadGroupAffinity(thread, &previous, ptr::null_mut());
            }
            return Err(format!("lock local batch buffers: {error}"));
        }
        // SAFETY: thread query has no pointer arguments or side effects.
        let thread_id = unsafe { GetCurrentThreadId() };
        let transport = Self {
            memory,
            previous,
            thread,
            thread_id,
            session: 0,
            hypercalls: Cell::new(0),
            owner: PhantomData,
        };
        // SAFETY: caller's explicit runtime-v2 acknowledgement permits this first VMMCALL.
        // A legacy runtime may stop: this is version negotiation, not safe absence detection.
        let (status, version) = unsafe { transport.call(local::PROBE) };
        if status != local::COMPLETE || version != local::VERSION {
            return Err(format!(
                "local runtime unavailable or wrong ABI: status={status} version={version}"
            ));
        }
        Ok(transport)
    }

    unsafe fn call(&self, operation: u64) -> (u64, u64) {
        let mut status = local::MAGIC;
        let mut length = self.memory as u64;
        self.hypercalls.set(self.hypercalls.get().saturating_add(1));
        // SAFETY: redesigned runtime ABI preserves every register except RAX/RDX. Buffers
        // are private, page-aligned and locked; memory effects prevent compiler reordering.
        unsafe {
            asm!("vmmcall", inout("rax") status, in("rcx") operation,
                inout("rdx") length, in("r8") self.memory.add(PAGE_BYTES),
                in("r9") MAX_RESPONSE_BYTES as u64, in("r10") self.session,
                options(nostack, preserves_flags));
        }
        (status, length)
    }
}

impl Exchange for NativeTransport {
    fn hypercalls(&self) -> Option<u64> {
        Some(self.hypercalls.get())
    }

    fn context(&mut self, session: u64, deadline: Instant) -> Result<Vec<u8>, String> {
        // SAFETY: pure query; buffers and affinity belong to this exact thread.
        if unsafe { GetCurrentThreadId() } != self.thread_id || self.session != session {
            return Err("local context session or thread changed".into());
        }
        // SAFETY: this transport owns the complete response allocation.
        unsafe { ptr::write_bytes(self.memory.add(PAGE_BYTES), 0, MAX_RESPONSE_BYTES) };
        context_complete(deadline, |operation| {
            // SAFETY: established local ABI, same pinned caller and retained buffers.
            unsafe { self.call(operation) }
        })?;
        // SAFETY: fixed context length is smaller than the retained response allocation.
        Ok(unsafe {
            std::slice::from_raw_parts(
                self.memory.add(PAGE_BYTES),
                svmvisor_card_abi::context::RESPONSE_BYTES,
            )
        }
        .to_vec())
    }

    fn exchange(
        &mut self,
        request: &[u8; REQUEST_BYTES],
        deadline: Instant,
    ) -> Result<Vec<u8>, String> {
        // SAFETY: pure query of current thread identity.
        if unsafe { GetCurrentThreadId() } != self.thread_id {
            return Err("local session changed thread".into());
        }
        let mut session = [0; 8];
        session.copy_from_slice(&request[8..16]);
        self.session = u64::from_le_bytes(session);
        // SAFETY: allocations are disjoint, writable and larger than each bounded copy.
        unsafe {
            ptr::copy_nonoverlapping(request.as_ptr(), self.memory, REQUEST_BYTES);
            ptr::write_bytes(self.memory.add(PAGE_BYTES), 0, MAX_RESPONSE_BYTES);
        }
        let length = complete(deadline, |operation| {
            // SAFETY: same pinned thread, immutable request and live locked response storage.
            unsafe { self.call(operation) }
        })?;
        if length > MAX_RESPONSE_BYTES {
            return Err("local response exceeds buffer capacity".into());
        }
        // SAFETY: runtime returned a bounded length within the still-owned allocation.
        Ok(unsafe { std::slice::from_raw_parts(self.memory.add(PAGE_BYTES), length) }.to_vec())
    }
}

impl Drop for NativeTransport {
    fn drop(&mut self) {
        if self.session != 0 {
            // SAFETY: release this session's idle binding before unlocking its owned buffers.
            unsafe {
                self.call(local::ABORT);
            }
        }
        // SAFETY: owner is !Send; allocation and affinity remain owned by the current thread.
        unsafe {
            VirtualUnlock(self.memory.cast(), ALLOCATION_BYTES);
            VirtualFree(self.memory.cast(), 0, 0x8000);
            SetThreadGroupAffinity(self.thread, &self.previous, ptr::null_mut());
        }
    }
}

#[repr(C)]
struct GroupAffinity {
    mask: usize,
    group: u16,
    reserved: [u16; 3],
}

const _: () = {
    assert!(size_of::<GroupAffinity>() == 16);
    assert!(align_of::<GroupAffinity>() == 8);
    assert!(std::mem::offset_of!(GroupAffinity, mask) == 0);
    assert!(std::mem::offset_of!(GroupAffinity, group) == 8);
    assert!(std::mem::offset_of!(GroupAffinity, reserved) == 10);
};
