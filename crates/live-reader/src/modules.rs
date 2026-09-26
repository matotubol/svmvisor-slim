//! The loaded-module list of a 64-bit process, walked through the runtime like any other memory.
//!
//! The loader keeps the list in user memory: `PEB.Ldr` points at `PEB_LDR_DATA`, whose
//! `InLoadOrderModuleList` links one `LDR_DATA_TABLE_ENTRY` per module, the executable first.
//! The PEB address comes from the process's kernel object; every byte comes from the runtime. The list is
//! the loader's own bookkeeping, so a module unlinked from it, or mapped without the loader, is
//! not listed.

use crate::error::{Error, ErrorKind, Result};

// x64 layouts, unchanged since Windows 7.
const PEB_LDR: u64 = 0x18;
const LDR_LOAD_ORDER: u64 = 0x10;
const ENTRY_DLL_BASE: usize = 0x30;
const ENTRY_SIZE_OF_IMAGE: usize = 0x40;
const ENTRY_BASE_NAME_LENGTH: usize = 0x58;
const ENTRY_BASE_NAME_BUFFER: usize = 0x60;
const ENTRY_BYTES: usize = 0x68;

/// More entries than any real process loads; a longer walk means the list changed under it.
const MAX_MODULES: usize = 4096;
/// `UNICODE_STRING.Length` is in bytes; module names are far shorter than this.
const MAX_NAME_BYTES: u16 = 1024;

/// A loaded image (the executable or a DLL) in the target's address space.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Module {
    /// The file name, such as `client.dll`.
    pub name: String,
    pub base: u64,
    pub size: u32,
}

impl Module {
    /// The virtual address `offset` bytes into the image, if that is inside it.
    pub fn address(&self, offset: u64) -> Option<u64> {
        (offset < u64::from(self.size)).then(|| self.base + offset)
    }

    /// The offset of `address` from the image base, if the address is inside the image.
    pub fn offset(&self, address: u64) -> Option<u64> {
        address.checked_sub(self.base).filter(|&offset| offset < u64::from(self.size))
    }

    /// True when `length` bytes from `offset` all lie inside the image.
    pub fn contains(&self, offset: u64, length: usize) -> bool {
        offset.checked_add(length as u64).is_some_and(|end| end <= u64::from(self.size))
    }
}

type Read<'a> = dyn FnMut(u64, &mut [u8]) -> Result<()> + 'a;

/// Every module in load order. `read` fills a buffer from a target virtual address.
pub(crate) fn list(peb: u64, read: &mut Read<'_>) -> Result<Vec<Module>> {
    let mut modules = Vec::new();
    walk(peb, read, |entry, read| {
        modules.push(Module { name: name(entry, read)?, base: entry.base, size: entry.size });
        Ok(false)
    })?;
    Ok(modules)
}

/// The first module in load order, which is the executable.
pub(crate) fn first(peb: u64, read: &mut Read<'_>) -> Result<Option<Module>> {
    let mut found = None;
    walk(peb, read, |entry, read| {
        found = Some(Module { name: name(entry, read)?, base: entry.base, size: entry.size });
        Ok(true)
    })?;
    Ok(found)
}

/// The first module whose file name matches `wanted`, ignoring ASCII case.
pub(crate) fn find(peb: u64, wanted: &str, read: &mut Read<'_>) -> Result<Option<Module>> {
    let wanted_bytes = wanted.encode_utf16().count() * 2;
    let mut found = None;
    walk(peb, read, |entry, read| {
        // Compare lengths first so only candidate names cost a read.
        if usize::from(entry.name_bytes) != wanted_bytes {
            return Ok(false);
        }
        let name = name(entry, read)?;
        if !name.eq_ignore_ascii_case(wanted) {
            return Ok(false);
        }
        found = Some(Module { name, base: entry.base, size: entry.size });
        Ok(true)
    })?;
    Ok(found)
}

struct Entry {
    base: u64,
    size: u32,
    name_bytes: u16,
    name_buffer: u64,
}

/// Calls `visit` for each entry until it returns true or the list ends.
fn walk(
    peb: u64,
    read: &mut Read<'_>,
    mut visit: impl FnMut(&Entry, &mut Read<'_>) -> Result<bool>,
) -> Result<()> {
    let ldr = u64_at(read, peb + PEB_LDR)?;
    if ldr == 0 {
        return Err(Error::new(ErrorKind::Unreadable, "the process loader has not started yet"));
    }
    let head = ldr + LDR_LOAD_ORDER;
    let mut link = u64_at(read, head)?;
    for _ in 0..MAX_MODULES {
        if link == head {
            return Ok(());
        }
        let mut bytes = [0; ENTRY_BYTES];
        read(link, &mut bytes)?;
        let field = |offset: usize| u64::from_le_bytes(bytes[offset..][..8].try_into().unwrap());
        let entry = Entry {
            base: field(ENTRY_DLL_BASE),
            size: u32::from_le_bytes(bytes[ENTRY_SIZE_OF_IMAGE..][..4].try_into().unwrap()),
            name_bytes: u16::from_le_bytes([
                bytes[ENTRY_BASE_NAME_LENGTH],
                bytes[ENTRY_BASE_NAME_LENGTH + 1],
            ]),
            name_buffer: field(ENTRY_BASE_NAME_BUFFER),
        };
        if visit(&entry, read)? {
            return Ok(());
        }
        link = field(0);
    }
    Err(changed())
}

fn name(entry: &Entry, read: &mut Read<'_>) -> Result<String> {
    if !entry.name_bytes.is_multiple_of(2) || entry.name_bytes > MAX_NAME_BYTES {
        return Err(changed());
    }
    let mut bytes = vec![0; usize::from(entry.name_bytes)];
    read(entry.name_buffer, &mut bytes)?;
    let units: Vec<u16> =
        bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    Ok(String::from_utf16_lossy(&units))
}

fn u64_at(read: &mut Read<'_>, address: u64) -> Result<u64> {
    let mut bytes = [0; 8];
    read(address, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn changed() -> Error {
    Error::new(ErrorKind::Unreadable, "the module list changed while it was read; try again")
}

/// Loader structures for a fake address space, shared with the crate's API tests.
#[cfg(test)]
pub(crate) mod fixture {
    use super::*;

    /// `(address, bytes)` writes that lay out a PEB at `peb`, its loader data and `modules`,
    /// with entries and names placed from `peb + 0x1000` on.
    pub(crate) fn layout(peb: u64, modules: &[(&str, u64, u32)]) -> Vec<(u64, Vec<u8>)> {
        let ldr = peb + 0x100;
        let head = ldr + LDR_LOAD_ORDER;
        let entry = |index: usize| peb + 0x1000 + index as u64 * 0x100;
        let next = |index: usize| if index + 1 == modules.len() { head } else { entry(index + 1) };
        let mut writes = vec![
            (peb + PEB_LDR, ldr.to_le_bytes().to_vec()),
            (head, if modules.is_empty() { head } else { entry(0) }.to_le_bytes().to_vec()),
        ];
        for (index, &(name, base, size)) in modules.iter().enumerate() {
            let at = entry(index);
            let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            writes.extend([
                (at, next(index).to_le_bytes().to_vec()),
                (at + ENTRY_DLL_BASE as u64, base.to_le_bytes().to_vec()),
                (at + ENTRY_SIZE_OF_IMAGE as u64, size.to_le_bytes().to_vec()),
                (at + ENTRY_BASE_NAME_LENGTH as u64, (name.len() as u16).to_le_bytes().to_vec()),
                (at + ENTRY_BASE_NAME_BUFFER as u64, (at + 0x80).to_le_bytes().to_vec()),
                (at + 0x80, name),
            ]);
        }
        writes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const PEB: u64 = 0x1000;

    /// A sparse fake address space holding a PEB, loader data and the given modules.
    fn memory(modules: &[(&str, u64, u32)]) -> BTreeMap<u64, u8> {
        let mut memory = BTreeMap::new();
        for (address, bytes) in fixture::layout(PEB, modules) {
            for (offset, byte) in bytes.into_iter().enumerate() {
                memory.insert(address + offset as u64, byte);
            }
        }
        memory
    }

    fn reader(memory: &BTreeMap<u64, u8>) -> impl FnMut(u64, &mut [u8]) -> Result<()> + '_ {
        |address, buffer| {
            for (offset, byte) in buffer.iter_mut().enumerate() {
                // Entry fields the fixture leaves out read as zero, like padding.
                *byte = memory.get(&(address + offset as u64)).copied().unwrap_or(0);
            }
            Ok(())
        }
    }

    #[test]
    fn lists_modules_in_load_order_and_finds_them_by_name() {
        let memory = memory(&[
            ("malware.exe", 0x7ff6_0000_0000, 0x5000),
            ("ntdll.dll", 0x7ffb_0000_0000, 0x1f_0000),
            ("client.dll", 0x7ffa_1000_0000, 0x200_0000),
        ]);
        let modules = list(PEB, &mut reader(&memory)).unwrap();
        let names: Vec<_> = modules.iter().map(|module| module.name.as_str()).collect();
        assert_eq!(names, ["malware.exe", "ntdll.dll", "client.dll"]);
        assert_eq!(first(PEB, &mut reader(&memory)).unwrap().unwrap(), modules[0]);
        let client = find(PEB, "CLIENT.dll", &mut reader(&memory)).unwrap().unwrap();
        assert_eq!((client.base, client.size), (0x7ffa_1000_0000, 0x200_0000));
        assert_eq!(find(PEB, "server.dll", &mut reader(&memory)).unwrap(), None);
    }

    #[test]
    fn only_names_of_the_wanted_length_are_read() {
        let memory = memory(&[("a.dll", 0x1_0000, 1), ("client.dll", 0x2_0000, 2)]);
        let mut reads = Vec::new();
        let mut inner = reader(&memory);
        find(PEB, "client.dll", &mut |address, buffer| {
            reads.push(address);
            inner(address, buffer)
        })
        .unwrap()
        .unwrap();
        // Ldr, head link, first entry, second entry, second name: not the first name.
        assert_eq!(reads.len(), 5);
    }

    #[test]
    fn a_list_that_never_returns_to_its_head_is_reported_as_changed() {
        let mut memory = memory(&[("a.dll", 0x1_0000, 1)]);
        // Point the only entry at itself.
        let entry = PEB + 0x1000;
        for (offset, byte) in entry.to_le_bytes().into_iter().enumerate() {
            memory.insert(entry + offset as u64, byte);
        }
        let error = list(PEB, &mut reader(&memory)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unreadable);
    }

    #[test]
    fn module_offsets_stay_inside_the_image() {
        let module = Module { name: "a.dll".into(), base: 0x1_0000, size: 0x1000 };
        assert_eq!(module.address(0xfff), Some(0x1_0fff));
        assert_eq!(module.address(0x1000), None);
        assert_eq!(module.offset(0x1_0010), Some(0x10));
        assert_eq!(module.offset(0xffff), None);
        assert_eq!(module.offset(0x1_1000), None);
        assert!(module.contains(0xff0, 0x10));
        assert!(!module.contains(0xff0, 0x11));
        assert!(!module.contains(u64::MAX, 1));
    }
}
