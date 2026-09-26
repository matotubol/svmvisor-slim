//! Pinned, prepared Windows invocation. All operating-system preparation precedes ARM.

use std::{arch::global_asm, ffi::c_void, ptr};

use svmvisor_card_abi::entry;

use crate::entry::Record;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentThread() -> *mut c_void;
    fn GetCurrentProcess() -> *mut c_void;
    fn GetProcessGroupAffinity(process: *mut c_void, count: *mut u16, groups: *mut u16) -> i32;
    fn GetProcessAffinityMask(
        process: *mut c_void,
        process_mask: *mut usize,
        system_mask: *mut usize,
    ) -> i32;
    fn SetThreadGroupAffinity(
        thread: *mut c_void,
        affinity: *const Affinity,
        previous: *mut Affinity,
    ) -> i32;
    fn GetCurrentProcessorNumberEx(processor: *mut Processor);
    fn GetModuleHandleA(name: *const u8) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *const c_void;
    fn VirtualLock(address: *mut c_void, bytes: usize) -> i32;
    fn VirtualUnlock(address: *mut c_void, bytes: usize) -> i32;
}

#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(algorithm: *mut c_void, buffer: *mut u8, bytes: u32, flags: u32) -> i32;
}

unsafe extern "system" {
    fn svmvisor_trial_client(record: *mut Record, nonce: u64, syscall: *const c_void, live: u64);
    static svmvisor_trial_client_end: u8;
}

global_asm!(include_str!("native.S"), magic = const entry::MAGIC,
    version = const entry::VERSION, arm = const entry::ARM, query = const entry::QUERY,
    mock = const cfg!(test) as u8);

#[repr(C)]
#[derive(Default)]
struct Affinity {
    mask: usize,
    group: u16,
    reserved: [u16; 3],
}

#[repr(C)]
#[derive(Default)]
struct Processor {
    group: u16,
    number: u8,
    reserved: u8,
}

struct Preparation {
    previous: Affinity,
    locks: Vec<(*const c_void, usize)>,
}

impl Preparation {
    fn lock(&mut self, address: *const c_void, bytes: usize) -> Result<(), String> {
        // SAFETY: caller supplies committed code/stack or owned buffer memory.
        if unsafe { VirtualLock(address.cast_mut(), bytes) } == 0 {
            return Err(format!("lock trial memory: {}", std::io::Error::last_os_error()));
        }
        self.locks.push((address, bytes));
        Ok(())
    }
}

impl Drop for Preparation {
    fn drop(&mut self) {
        // SAFETY: all recorded ranges and the saved affinity belong to this thread.
        unsafe {
            for &(address, bytes) in self.locks.iter().rev() {
                VirtualUnlock(address.cast_mut(), bytes);
            }
            SetThreadGroupAffinity(GetCurrentThread(), &self.previous, ptr::null_mut());
        }
    }
}

pub(super) fn run(cpu: u16) -> Result<(u64, Box<Record>), String> {
    if cfg!(test) {
        return Err("live trials disabled in test builds".into());
    }
    let mut record = Box::<Record>::default();
    let mut previous = Affinity::default();
    let (mut allowed, mut system) = (0usize, 0usize);
    let (mut count, mut group) = (1u16, 0u16);
    // The supported runtime topology is group zero. Do not interpret another
    // group's process mask as a group-zero allowance.
    if unsafe { GetProcessGroupAffinity(GetCurrentProcess(), &mut count, &mut group) } == 0
        || count != 1
        || group != 0
    {
        return Err("trial requires a process confined to processor group zero".into());
    }
    // SAFETY: valid output buffers and process pseudohandle. Group zero only.
    if unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut allowed, &mut system) } == 0
        || cpu >= 32
        || allowed & (1usize << cpu) == 0
    {
        return Err("CPU must be allowed by process affinity and in group zero, 0..31".into());
    }
    let affinity = Affinity { mask: 1usize << cpu, ..Affinity::default() };
    // SAFETY: synchronous call with initialized, live affinity structures.
    if unsafe { SetThreadGroupAffinity(GetCurrentThread(), &affinity, &mut previous) } == 0 {
        return Err(format!("pin trial CPU: {}", std::io::Error::last_os_error()));
    }
    let mut preparation = Preparation { previous, locks: Vec::with_capacity(4) };
    let mut current = Processor::default();
    let mut nonce = 0u64;
    // SAFETY: valid writable outputs; system RNG with a null provider handle.
    unsafe {
        GetCurrentProcessorNumberEx(&mut current);
        if BCryptGenRandom(ptr::null_mut(), (&mut nonce as *mut u64).cast(), 8, 2) < 0 || nonce == 0
        {
            return Err("could not generate a nonzero nonce".into());
        }
    }
    if current.group != 0 || current.number as u16 != cpu {
        return Err("selected CPU was not reached".into());
    }
    // SAFETY: NUL-terminated static names; ntdll remains loaded throughout process life.
    let module = unsafe { GetModuleHandleA(c"ntdll.dll".as_ptr().cast()) };
    if module.is_null() {
        return Err("ntdll is not loaded".into());
    }
    let syscall = unsafe { GetProcAddress(module, c"NtYieldExecution".as_ptr().cast()) };
    if syscall.is_null() {
        return Err("NtYieldExecution is unavailable".into());
    }
    preparation.lock((&*record as *const Record).cast(), size_of::<Record>())?;
    let code = svmvisor_trial_client as *const () as usize;
    let end = ptr::addr_of!(svmvisor_trial_client_end) as usize;
    preparation.lock(code as *const c_void, end.checked_sub(code).ok_or("invalid code range")?)?;
    preparation.lock(syscall, 64)?;
    // SAFETY: mode zero calls the resolved function and touches the exact wrapper frame,
    // without issuing VMMCALL. The boxed output and code addresses remain fixed.
    unsafe {
        svmvisor_trial_client(&mut *record, nonce, syscall, 0);
    }
    // Include the return-address slot touched by CALL below the shadow space.
    preparation.lock((record.stack - 8) as *const c_void, 80)?;
    // SAFETY: explicit CLI acknowledgement, same pinned thread, prepared buffers/code/stack.
    // The assembly owns the entire ARM -> syscall -> QUERY interval, including R12.
    unsafe {
        svmvisor_trial_client(&mut *record, nonce, syscall, 1);
    }
    drop(preparation);
    Ok((nonce, record))
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "system" fn syscall() -> u32 {
        0x4000_0024
    }

    #[test]
    fn assembly_captures_query_clobbers_and_skips_syscall_on_refusal() {
        for nonce in [1, 2] {
            let mut record = Box::<Record>::default();
            // Test assembly substitutes register responses, never VMMCALL.
            unsafe {
                svmvisor_trial_client(&mut *record, nonce, syscall as *const c_void, 1);
            }
            assert_eq!(record.arm_rax, nonce - 1);
            assert_eq!(record.syscall_called, u64::from(nonce == 1));
            if nonce == 1 {
                assert_eq!(record.syscall_status, 0x4000_0024);
            }
            assert_eq!((record.query_rax, record.status, record.exit_code), (0, 3, 0x400));
            assert_eq!(
                (record.rip, record.info1, record.info2, record.sequence),
                (0x1234, 0x1_0000_0011, 0x5678, 9)
            );
        }
    }
}
