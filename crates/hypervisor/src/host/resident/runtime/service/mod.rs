//! Caller-buffer admission and physical copies for local VMMCALL batches.
//! Physical admission does not establish Windows object identity or coherent contents.

use core::ptr;

use svmvisor_card_abi::batch::MAX_RESPONSE_BYTES;

use crate::{
    host::{
        paging::{self, PagingConfig},
        resident::runtime::{NPT, State, guest_reader::GuestReader},
    },
    memory::address::PAGE_BYTES,
    reader::paging::PagingError,
    svm::vmcb::Vmcb,
};

#[cfg(test)]
mod tests;

/// Stack-scoped adapter for one stopped caller. Retains values, never guest pointers.
pub(super) struct LocalMemory {
    reader: GuestReader,
    guest: PagingConfig,
}

impl LocalMemory {
    /// # Safety
    /// The caller owns this CPU's stopped guest, private root, NPT and scratch window with
    /// GIF/IF clear for the entire adapter lifetime. Guest buffers stay allocated through return.
    pub(super) unsafe fn new(state: &State, vmcb: &Vmcb) -> Result<Self, ()> {
        let cr4 = u64::from_le_bytes(vmcb.bytes()[0x548..0x550].try_into().unwrap());
        if vmcb.guest_cpl() != 3
            || !vmcb.guest_in_64_bit_code()
            || vmcb.guest_cr0() & 0xe000_0001 != 0x8000_0001
            || cr4 & (1 << 5) == 0
            || cr4 & ((1 << 12) | (1 << 22)) != 0
            || vmcb.guest_efer() & 0x500 != 0x500
        {
            return Err(());
        }
        let root = ptr::addr_of!(NPT) as u64;
        if vmcb.nested_root() != root {
            return Err(());
        }
        // SAFETY: owning stopped CPU retains its private NPT and scratch root through return.
        let reader =
            unsafe { GuestReader::new(vmcb, state.startup_owned, state.count) }.map_err(|_| ())?;
        let guest = PagingConfig {
            cr3: vmcb.guest_cr3(),
            physical_bits: reader.width,
            la57: false,
            nxe: vmcb.guest_efer() & (1 << 11) != 0,
            pcid: cr4 & (1 << 17) != 0,
            page1gb: true,
        };
        Ok(Self { reader, guest })
    }

    pub(super) fn width(&self) -> u8 {
        self.reader.width
    }

    pub(super) fn read_physical(&mut self, gpa: u64, output: &mut [u8]) -> Result<(), PagingError> {
        if output.is_empty()
            || output.len() > PAGE_BYTES
            || (gpa as usize & (PAGE_BYTES - 1)) + output.len() > PAGE_BYTES
        {
            return Err(PagingError::PhysicalRead);
        }
        // SAFETY: adapter retains stopped ownership. copy admits the entire backing page
        // against the same owned NPT (identity/permissions/cache type), RAM, physical WB and
        // monitor exclusion before creating its alias, and removes the alias before return.
        // A second fragment walk here would repeat a subset of that immutable-NPT proof.
        unsafe { self.reader.copy(gpa, output) }.map_err(|_| PagingError::PhysicalRead)
    }

    pub(super) fn read_user(&mut self, va: u64, output: &mut [u8]) -> Result<(), ()> {
        if !user_range(va, output.len()) {
            return Err(());
        }
        let mut offset = 0;
        while offset < output.len() {
            let address = va + offset as u64;
            let length =
                (PAGE_BYTES - (address as usize & (PAGE_BYTES - 1))).min(output.len() - offset);
            let physical = self.user_address(address, false)?;
            self.read_physical(physical, &mut output[offset..offset + length]).map_err(|_| ())?;
            offset += length;
        }
        Ok(())
    }

    /// Preflight every output page, then rewalk before writing each page. A concurrent caller
    /// unmap can still produce a partial buffer; only a successful hypercall publishes a result.
    pub(super) fn write_user(&mut self, va: u64, source: &[u8]) -> Result<(), ()> {
        write_output(
            self,
            va,
            source,
            |memory, address| memory.user_address(address, true),
            // permits_output includes the full-page writable identity-NPT proof. copy_to
            // independently repeats admission at the actual write after the caller rewalk.
            |memory, physical, length| memory.reader.permits_output(physical, length),
            |memory, physical, bytes| {
                // SAFETY: current caller's complete range was admitted; this page was rewalked as
                // writable user memory. Client retains allocations until return. copy_to rechecks
                // RAM/WB/monitor exclusion and removes the RW alias before the next operation.
                unsafe { memory.reader.copy_to(physical, bytes) }.map_err(|_| ())
            },
        )
    }

    fn user_address(&mut self, va: u64, writable: bool) -> Result<u64, ()> {
        let pat = self.reader.guest_pat;
        user_translation(self.guest, pat, va, writable, &mut |address| {
            let mut bytes = [0u8; 8];
            self.read_physical(address, &mut bytes).ok()?;
            Some(u64::from_le_bytes(bytes))
        })
    }
}

/// Complete admission precedes any write; each rewalk must still match its admitted page.
/// This detects some mapping changes, but does not pin memory past the last translation check.
fn write_output<Memory>(
    memory: &mut Memory,
    va: u64,
    source: &[u8],
    mut translate: impl FnMut(&mut Memory, u64) -> Result<u64, ()>,
    mut admit: impl FnMut(&mut Memory, u64, usize) -> bool,
    mut write: impl FnMut(&mut Memory, u64, &[u8]) -> Result<(), ()>,
) -> Result<(), ()> {
    if !user_range(va, source.len()) {
        return Err(());
    }
    let mut pages = [(0u64, 0usize); 3];
    let mut count = 0;
    let mut offset = 0;
    while offset < source.len() {
        if count == pages.len() {
            return Err(());
        }
        let address = va + offset as u64;
        let length =
            (PAGE_BYTES - (address as usize & (PAGE_BYTES - 1))).min(source.len() - offset);
        let physical = translate(memory, address)?;
        if !admit(memory, physical, length)
            || pages[..count].iter().any(|&(other, _)| other >> 12 == physical >> 12)
        {
            return Err(());
        }
        pages[count] = (physical, length);
        count += 1;
        offset += length;
    }
    offset = 0;
    for &(physical, length) in &pages[..count] {
        if translate(memory, va + offset as u64)? != physical {
            return Err(());
        }
        write(memory, physical, &source[offset..offset + length])?;
        offset += length;
    }
    Ok(())
}

fn user_range(va: u64, length: usize) -> bool {
    va != 0
        && length != 0
        && length <= MAX_RESPONSE_BYTES
        && va.checked_add(length as u64 - 1).is_some_and(|last| last < 1 << 47)
}

/// Four-level caller walk, preserving accumulated U/S and R/W checks. PKE is refused at entry.
/// Guest software bits are ignored; each table and leaf must select WB in the stopped PAT.
fn user_translation(
    config: PagingConfig,
    pat: u64,
    va: u64,
    writable: bool,
    read: &mut impl FnMut(u64) -> Option<u64>,
) -> Result<u64, ()> {
    if !user_range(va, 1) {
        return Err(());
    }
    let mut level = 4;
    let mut table_pat = if config.pcid { 0 } else { (config.cr3 >> 3) & 3 };
    let translation = paging::translate(config, va, |address| {
        if (pat >> (table_pat * 8)) & 255 != 6 {
            return None;
        }
        let entry = read(address)?;
        let leaf = level == 1 || (level < 4 && entry & (1 << 7) != 0);
        level -= 1;
        if !leaf {
            table_pat = (entry >> 3) & 3;
        }
        Some(entry & !0x7ff0_0000_0000_0000)
    })
    .map_err(|_| ())?;
    if !translation.user
        || (writable && !translation.writable)
        || (pat >> (translation.pat_index * 8)) & 255 != 6
    {
        return Err(());
    }
    Ok(translation.physical_address)
}
