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

type Read<'a> = dyn FnMut(u64, &mut [u8]) -> Result<()> + 'a;
type ReadBatch<'a> = dyn FnMut(&mut [(u64, &mut [u8])]) -> Result<()> + 'a;

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
        self.base.checked_add(offset).filter(|_| offset < u64::from(self.size))
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

struct Entry {
    next: u64,
    base: u64,
    size: u32,
    name_bytes: u16,
    name_buffer: u64,
}

impl Entry {
    fn from_bytes(bytes: &[u8; ENTRY_BYTES]) -> Self {
        let field = |offset: usize| u64::from_le_bytes(bytes[offset..][..8].try_into().unwrap());
        Self {
            next: field(0),
            base: field(ENTRY_DLL_BASE),
            size: u32::from_le_bytes(bytes[ENTRY_SIZE_OF_IMAGE..][..4].try_into().unwrap()),
            name_bytes: u16::from_le_bytes([
                bytes[ENTRY_BASE_NAME_LENGTH],
                bytes[ENTRY_BASE_NAME_LENGTH + 1],
            ]),
            name_buffer: field(ENTRY_BASE_NAME_BUFFER),
        }
    }
}

/// Every module in load order, batching each name with the following loader entry.
pub(crate) fn list(peb: u64, read: &mut ReadBatch<'_>) -> Result<Vec<Module>> {
    let (head, link) = start(peb, &mut |address, bytes| read(&mut [(address, bytes)]))?;
    let mut modules = Vec::new();
    if link == head {
        return Ok(modules);
    }
    let mut bytes = [0; ENTRY_BYTES];
    read(&mut [(link, &mut bytes)])?;
    for index in 0..MAX_MODULES {
        let entry = Entry::from_bytes(&bytes);
        let mut name_bytes = name_buffer(&entry)?;
        let last = entry.next == head;
        if !last && index + 1 == MAX_MODULES {
            return Err(changed());
        }
        // Only the current name and the next complete entry are read. No memory between them
        // is sampled, and a failed batch cannot publish a partial module list.
        match (name_bytes.is_empty(), last) {
            (false, false) => {
                read(&mut [(entry.name_buffer, &mut name_bytes), (entry.next, &mut bytes)])?;
            }
            (false, true) => read(&mut [(entry.name_buffer, &mut name_bytes)])?,
            (true, false) => read(&mut [(entry.next, &mut bytes)])?,
            (true, true) => {}
        }
        modules.push(Module { name: decode_name(&name_bytes), base: entry.base, size: entry.size });
        if last {
            return Ok(modules);
        }
    }
    Err(changed())
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

/// Calls `visit` for each entry until it returns true or the list ends.
fn walk(
    peb: u64,
    read: &mut Read<'_>,
    mut visit: impl FnMut(&Entry, &mut Read<'_>) -> Result<bool>,
) -> Result<()> {
    let (head, mut link) = start(peb, read)?;
    for _ in 0..MAX_MODULES {
        if link == head {
            return Ok(());
        }
        let mut bytes = [0; ENTRY_BYTES];
        read(link, &mut bytes)?;
        let entry = Entry::from_bytes(&bytes);
        if visit(&entry, read)? {
            return Ok(());
        }
        link = entry.next;
    }
    Err(changed())
}

fn start(peb: u64, read: &mut Read<'_>) -> Result<(u64, u64)> {
    let ldr = u64_at(read, peb.checked_add(PEB_LDR).ok_or_else(changed)?)?;
    if ldr == 0 {
        return Err(Error::new(ErrorKind::Unreadable, "the process loader has not started yet"));
    }
    let head = ldr.checked_add(LDR_LOAD_ORDER).ok_or_else(changed)?;
    Ok((head, u64_at(read, head)?))
}

fn name(entry: &Entry, read: &mut Read<'_>) -> Result<String> {
    let mut bytes = name_buffer(entry)?;
    read(entry.name_buffer, &mut bytes)?;
    Ok(decode_name(&bytes))
}

fn name_buffer(entry: &Entry) -> Result<Vec<u8>> {
    if !entry.name_bytes.is_multiple_of(2) || entry.name_bytes > MAX_NAME_BYTES {
        return Err(changed());
    }
    Ok(vec![0; usize::from(entry.name_bytes)])
}

fn decode_name(bytes: &[u8]) -> String {
    let units: Vec<u16> =
        bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    String::from_utf16_lossy(&units)
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

    fn batch_reader(
        memory: &BTreeMap<u64, u8>,
    ) -> impl FnMut(&mut [(u64, &mut [u8])]) -> Result<()> + '_ {
        |reads| {
            for (address, bytes) in reads {
                reader(memory)(*address, bytes)?;
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
        let modules = list(PEB, &mut batch_reader(&memory)).unwrap();
        let names: Vec<_> = modules.iter().map(|module| module.name.as_str()).collect();
        assert_eq!(names, ["malware.exe", "ntdll.dll", "client.dll"]);
        assert_eq!(first(PEB, &mut reader(&memory)).unwrap().unwrap(), modules[0]);
        let client = find(PEB, "CLIENT.dll", &mut reader(&memory)).unwrap().unwrap();
        assert_eq!((client.base, client.size), (0x7ffa_1000_0000, 0x200_0000));
        assert_eq!(find(PEB, "server.dll", &mut reader(&memory)).unwrap(), None);
    }

    #[test]
    fn full_list_batches_exact_names_with_the_next_entry() {
        let memory =
            memory(&[("a.dll", 0x1_0000, 1), ("b.dll", 0x2_0000, 2), ("c.dll", 0x3_0000, 3)]);
        let mut requests: Vec<Vec<(u64, usize)>> = Vec::new();
        let modules = list(PEB, &mut |reads| {
            requests.push(reads.iter().map(|(address, bytes)| (*address, bytes.len())).collect());
            batch_reader(&memory)(reads)
        })
        .unwrap();
        let expected: Vec<Vec<(u64, usize)>> = vec![
            vec![(PEB + PEB_LDR, 8)],
            vec![(PEB + 0x100 + LDR_LOAD_ORDER, 8)],
            vec![(PEB + 0x1000, ENTRY_BYTES)],
            vec![(PEB + 0x1080, 10), (PEB + 0x1100, ENTRY_BYTES)],
            vec![(PEB + 0x1180, 10), (PEB + 0x1200, ENTRY_BYTES)],
            vec![(PEB + 0x1280, 10)],
        ];
        assert_eq!(requests, expected);
        assert_eq!(requests.len(), modules.len() + 3);
    }

    #[test]
    fn empty_lists_and_names_do_not_add_requests() {
        for (source, expected_requests) in [(vec![], 2), (vec![("", 0x1_0000, 1)], 3)] {
            let memory = memory(&source);
            let mut requests = 0;
            let modules = list(PEB, &mut |reads| {
                requests += 1;
                assert!(reads.iter().all(|(_, bytes)| !bytes.is_empty()));
                batch_reader(&memory)(reads)
            })
            .unwrap();
            assert_eq!(modules.len(), source.len());
            assert_eq!(requests, expected_requests);
        }
    }

    #[test]
    fn malformed_pipelined_names_stop_before_another_request() {
        for length in [1u16, MAX_NAME_BYTES + 2] {
            let mut memory = memory(&[("a.dll", 0x1_0000, 1), ("b.dll", 0x2_0000, 2)]);
            for (offset, byte) in length.to_le_bytes().into_iter().enumerate() {
                memory.insert(PEB + 0x1100 + ENTRY_BASE_NAME_LENGTH as u64 + offset as u64, byte);
            }
            let mut requests = 0;
            let error = list(PEB, &mut |reads| {
                requests += 1;
                batch_reader(&memory)(reads)
            })
            .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Unreadable);
            assert_eq!(requests, 4);
        }
    }

    #[test]
    fn a_failed_name_or_next_entry_discards_the_whole_list() {
        let memory =
            memory(&[("a.dll", 0x1_0000, 1), ("b.dll", 0x2_0000, 2), ("c.dll", 0x3_0000, 3)]);
        for failed_range in 0..2 {
            let mut requests = 0;
            let error = list(PEB, &mut |reads| {
                requests += 1;
                for (index, (address, bytes)) in reads.iter_mut().enumerate() {
                    if requests == 5 && index == failed_range {
                        return Err(Error::new(ErrorKind::Unreadable, "pipeline read failed"));
                    }
                    reader(&memory)(*address, bytes)?;
                }
                Ok(())
            })
            .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Unreadable);
            assert_eq!(requests, 5);
        }
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
        let error = list(PEB, &mut batch_reader(&memory)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unreadable);
    }

    #[test]
    fn a_complete_list_can_reach_the_module_limit() {
        let memory = memory(&vec![("", 0x1_0000, 1); MAX_MODULES]);
        assert_eq!(list(PEB, &mut batch_reader(&memory)).unwrap().len(), MAX_MODULES);
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
        let overflowing = Module { base: u64::MAX, ..module };
        assert_eq!(overflowing.address(1), None);
    }

    #[test]
    fn overflowing_loader_pointers_never_issue_a_wrapped_read() {
        let error = list(u64::MAX, &mut |_| panic!("invalid PEB must not be read")).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unreadable);
        let mut addresses = Vec::new();
        let error = list(PEB, &mut |reads| {
            assert_eq!(reads.len(), 1);
            addresses.push(reads[0].0);
            reads[0].1.copy_from_slice(&u64::MAX.to_le_bytes());
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unreadable);
        assert_eq!(addresses, [PEB + PEB_LDR]);
    }
}
