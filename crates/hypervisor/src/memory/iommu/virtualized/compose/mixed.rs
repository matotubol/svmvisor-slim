//! Native-capacity output builder: default 1GiB, 2MiB and 4KiB AMD leaves.
//! Every range and exact required page count is checked before storage changes.
//! Numeric image construction never publishes hardware or grants a source lease.
//! Layout: 48882-3.11 physical pp80,82,85 (text and PNG checked).

use crate::memory::{
    address::AddressPolicy,
    iommu::{
        image::{MAX_MAPPING_RANGES, MAX_PROTECTED_RANGES, MappingRange, ProtectedRange},
        tables::{PageCoherency, Permissions},
    },
};

pub const MAX_PAGES: usize = 256;
const PAGE: u64 = 4096;
const LIMIT: u64 = 1 << 48;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Address,
    Capacity { required: usize, available: usize },
    Ranges,
    ProtectedOutput,
    BackingOutput,
    Contents,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image {
    pub root: u64,
    pub used_pages: usize,
}

/// `tables` is disconnected exclusive storage, normally a slice of the native
/// 256-page translation/interrupt arena. Its WHOLE assigned extent is excluded
/// from every output, including unused capacity. The caller also supplies the
/// complete generation's DTE and interrupt backing in `protected`.
pub fn build(
    policy: AddressPolicy,
    backing: u64,
    tables: &mut [[u64; 512]],
    mappings: &[MappingRange],
    protected: &[ProtectedRange],
) -> Result<Image, Error> {
    let used = prepare(policy, backing, tables.len(), mappings, protected)?;
    for table in tables.iter_mut() {
        table.fill(0);
    }
    let mut next = 1;
    visit(backing, mappings, 0, 4, 0, &mut next, tables.len(), &mut |page, index, word| {
        tables[page][index] = word;
        Ok(())
    })?;
    debug_assert_eq!(next, used);
    Ok(Image { root: backing, used_pages: used })
}

/// Independently regenerate expected words from immutable input and compare
/// every used and unused cell. This does not borrow hardware-visible storage
/// mutably and catches stale links in a reused generation.
pub fn verify(
    policy: AddressPolicy,
    backing: u64,
    tables: &[[u64; 512]],
    mappings: &[MappingRange],
    protected: &[ProtectedRange],
) -> Result<Image, Error> {
    let used = prepare(policy, backing, tables.len(), mappings, protected)?;
    let mut next = 1;
    visit(backing, mappings, 0, 4, 0, &mut next, tables.len(), &mut |page, index, word| {
        if tables[page][index] == word { Ok(()) } else { Err(Error::Contents) }
    })?;
    if tables[used..].iter().flatten().any(|word| *word != 0) {
        return Err(Error::Contents);
    }
    Ok(Image { root: backing, used_pages: used })
}

fn prepare(
    policy: AddressPolicy,
    backing: u64,
    capacity: usize,
    mappings: &[MappingRange],
    protected: &[ProtectedRange],
) -> Result<usize, Error> {
    if capacity == 0 || capacity > MAX_PAGES {
        return Err(Error::Capacity { required: 1, available: capacity });
    }
    policy.validate(backing, capacity as u64 * PAGE, PAGE).map_err(|_| Error::Address)?;
    if mappings.len() > MAX_MAPPING_RANGES || protected.len() > MAX_PROTECTED_RANGES {
        return Err(Error::Ranges);
    }
    let mut end = 0;
    for range in protected {
        policy.validate(range.base, range.len, PAGE).map_err(|_| Error::Address)?;
        if range.len & (PAGE - 1) != 0 || range.base < end {
            return Err(Error::Ranges);
        }
        end = range.base + range.len;
    }
    end = 0;
    for map in mappings {
        if map.len == 0
            || map.len & (PAGE - 1) != 0
            || map.io_base & (PAGE - 1) != 0
            || map.io_base < end
            || map.io_base.checked_add(map.len).is_none_or(|e| e > LIMIT)
        {
            return Err(Error::Ranges);
        }
        policy.validate(map.system_base, map.len, PAGE).map_err(|_| Error::Address)?;
        let host_end = map.system_base + map.len;
        if map.system_base < backing + capacity as u64 * PAGE && backing < host_end {
            return Err(Error::BackingOutput);
        }
        if protected.iter().any(|p| map.system_base < p.base + p.len && p.base < host_end) {
            return Err(Error::ProtectedOutput);
        }
        end = map.io_base + map.len;
    }
    let mut used = 1;
    visit(backing, mappings, 0, 4, 0, &mut used, capacity, &mut |_, _, _| Ok(()))?;
    Ok(used)
}

fn visit(
    backing: u64,
    mappings: &[MappingRange],
    base: u64,
    level: u8,
    page: usize,
    used: &mut usize,
    capacity: usize,
    write: &mut impl FnMut(usize, usize, u64) -> Result<(), Error>,
) -> Result<(), Error> {
    let bytes = 1u64 << (12 + 9 * (level - 1));
    for index in 0..512 {
        let io = base + index as u64 * bytes;
        let start = mappings.partition_point(|m| m.io_base + m.len <= io);
        let map = mappings.get(start).filter(|m| m.io_base < io + bytes);
        let Some(map) = map else {
            write(page, index, 0)?;
            continue;
        };
        let full = map.io_base <= io && map.io_base + map.len >= io + bytes;
        let host = if full { map.system_base + io - map.io_base } else { 0 };
        if full && map.permissions == Permissions::None {
            write(page, index, 0)?;
        } else if full && level <= 3 && host & (bytes - 1) == 0 {
            let rights = ((map.permissions.allows_read() as u64) << 61)
                | ((map.permissions.allows_write() as u64) << 62);
            let coherent = if map.coherency == PageCoherency::ForceCoherent { 1 << 60 } else { 0 };
            write(page, index, host | rights | coherent | 1)?;
        } else {
            if level == 1 {
                return Err(Error::Ranges);
            }
            if *used == capacity {
                return Err(Error::Capacity { required: *used + 1, available: capacity });
            }
            let child = *used;
            *used += 1;
            let address = backing + child as u64 * PAGE;
            write(page, index, address | (3 << 61) | (u64::from(level - 1) << 9) | 1)?;
            visit(backing, mappings, io, level - 1, child, used, capacity, write)?;
        }
    }
    Ok(())
}

/// Read-only independent walker for native publication verification. It accepts
/// only this output format and checks every pointer against the retained arena.
pub fn walk(
    tables: &[[u64; 512]],
    image: Image,
    io: u64,
) -> Result<Option<(u64, Permissions)>, Error> {
    if io >= LIMIT
        || tables.is_empty()
        || image.used_pages == 0
        || image.used_pages > tables.len()
        || image.root & (PAGE - 1) != 0
    {
        return Err(Error::Address);
    }
    let mut page = 0;
    let mut read = true;
    let mut write = true;
    for level in (1..=4).rev() {
        let shift = 12 + 9 * (level - 1);
        let index = ((io >> shift) & 511) as usize;
        let word = tables[page][index];
        if word == 0 {
            return Ok(None);
        }
        if word & 1 == 0 {
            return Err(Error::Contents);
        }
        read &= word & (1 << 61) != 0;
        write &= word & (1 << 62) != 0;
        let next = (word >> 9) & 7;
        let address = word & ADDRESS;
        if next == 0 {
            let mask = (1 << shift) - 1;
            if level == 4 || word & !(ADDRESS | (7 << 60) | 1) != 0 || address & mask != 0 {
                return Err(Error::Contents);
            }
            return Ok(Some((address | (io & mask), super::super::permissions(read, write))));
        }
        if next != level - 1 || word & !(ADDRESS | (3 << 61) | (7 << 9) | 1) != 0 {
            return Err(Error::Contents);
        }
        let offset = address.checked_sub(image.root).ok_or(Error::Contents)?;
        page = (offset / PAGE) as usize;
        if page == 0 || page >= image.used_pages {
            return Err(Error::Contents);
        }
    }
    Err(Error::Contents)
}
