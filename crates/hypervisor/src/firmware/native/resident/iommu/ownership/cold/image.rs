//! Mixed 1GiB/2MiB/4KiB native host image. AMD 48882-3.11 pp63,73-75,80-85
//! (text and PNG): NextLevel=0 chooses the level's default leaf size. This does
//! not use x86 PS, skip levels, or set AMD's variable-size NextLevel=7 encoding.
use crate::{
    boot::memory::{MemoryDescriptor, ValidatedMemoryMap},
    firmware::native::resident::iommu::resources::{
        COMPOSITION_TABLE_OFFSET, COMPOSITION_TABLE_PAGES, CompositionStorage,
    },
    host::resident::IOMMU_COMPOSITION_BYTES,
    memory::{
        address::{AddressPolicy, PhysicalRange},
        iommu::tables::{
            CompleteHostDeviceEntry, DteInterruptPolicy, HostDeviceEntry, Permissions,
        },
    },
};

const RW: u64 = 3 << 61;
const FC: u64 = 1 << 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityImage {
    pub device_table: u64,
    pub root: u64,
    pub used_pages: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageError {
    Address,
    MemoryMap,
    Exclusions,
    Capacity,
    Contents,
    InterruptPolicy,
}

/// Only normal firmware/loader/conventional RAM with WB capability is mapped;
/// MMIO, reserved memory, ACPI reclaim/NVS and holes remain absent. Every output
/// is identity-mapped and explicitly excludes the full monitor pool and control
/// ranges. This common requester policy says nothing about Windows domains.
pub fn prepare_identity(
    storage: &mut CompositionStorage,
    policy: AddressPolicy,
    base: u64,
    map: &[MemoryDescriptor],
    excluded: &[PhysicalRange],
    interrupts: DteInterruptPolicy,
) -> Result<IdentityImage, ImageError> {
    let input = Input::new(policy, base, map, excluded, interrupts)?;
    // Size the same deterministic tree before touching any output.
    let mut count = 1;
    visit(&input, 0, 4, &mut count, &mut |_, _, _| Ok(()))?;
    storage.clear();
    let mut used = 1;
    visit(&input, 0, 4, &mut used, &mut |page, index, word| {
        storage.tables_mut()[page][index] = word;
        Ok(())
    })?;
    for page in storage.device_table_mut() {
        for entry in page.chunks_exact_mut(4) {
            entry.copy_from_slice(&input.dte);
        }
    }
    Ok(IdentityImage { device_table: base | 511, root: input.root, used_pages: used })
}

/// Recompute and compare the entire disconnected generation, including unused
/// pages. No mutable borrow may exist once hardware can access the image.
pub fn verify_identity(
    storage: &CompositionStorage,
    policy: AddressPolicy,
    base: u64,
    map: &[MemoryDescriptor],
    excluded: &[PhysicalRange],
    interrupts: DteInterruptPolicy,
) -> Result<IdentityImage, ImageError> {
    let input = Input::new(policy, base, map, excluded, interrupts)?;
    let mut used = 1;
    visit(&input, 0, 4, &mut used, &mut |page, index, word| {
        if storage.tables()[page][index] == word { Ok(()) } else { Err(ImageError::Contents) }
    })?;
    if storage.tables()[used..].iter().flatten().any(|word| *word != 0)
        || storage
            .device_table()
            .iter()
            .any(|page| page.chunks_exact(4).any(|entry| entry != input.dte))
    {
        return Err(ImageError::Contents);
    }
    Ok(IdentityImage { device_table: base | 511, root: input.root, used_pages: used })
}

struct Input<'a> {
    root: u64,
    map: &'a [MemoryDescriptor],
    excluded: &'a [PhysicalRange],
    dte: [u64; 4],
}

impl<'a> Input<'a> {
    fn new(
        policy: AddressPolicy,
        base: u64,
        map: &'a [MemoryDescriptor],
        excluded: &'a [PhysicalRange],
        interrupts: DteInterruptPolicy,
    ) -> Result<Self, ImageError> {
        let extent = policy
            .validate(base, IOMMU_COMPOSITION_BYTES, 4096)
            .map_err(|_| ImageError::Address)?;
        ValidatedMemoryMap::new(map, policy.physical_bits().min(48))
            .map_err(|_| ImageError::MemoryMap)?;
        if excluded.is_empty() || excluded.len() > 128 {
            return Err(ImageError::Exclusions);
        }
        for (i, range) in excluded.iter().enumerate() {
            policy.validate(range.base(), range.len(), 4096).map_err(|_| ImageError::Exclusions)?;
            if range.len() & 4095 != 0 || (i > 0 && excluded[i - 1].last_byte() >= range.base()) {
                return Err(ImageError::Exclusions);
            }
        }
        if !excluded
            .iter()
            .any(|range| range.base() <= base && range.last_byte() >= extent.last_byte())
        {
            return Err(ImageError::Exclusions);
        }
        let root = base + COMPOSITION_TABLE_OFFSET;
        let translation = HostDeviceEntry::new(policy, root, 0, Permissions::ReadWrite)
            .map_err(|_| ImageError::Address)?;
        // A remap root shared by every requester would itself require a source
        // policy; native cold construction currently selects controlled aborts.
        if interrupts != DteInterruptPolicy::AbortControlled {
            return Err(ImageError::InterruptPolicy);
        }
        let dte = CompleteHostDeviceEntry::new(policy, translation, interrupts)
            .map_err(|_| ImageError::InterruptPolicy)?
            .words();
        Ok(Self { root, map, excluded, dte })
    }

    fn classify(&self, base: u64, bytes: u64) -> u8 {
        let end = base + bytes;
        let p = self.excluded.partition_point(|r| r.last_byte() < base);
        let excluded = self.excluded.get(p).filter(|r| r.base() < end);
        if excluded.is_some_and(|r| r.base() <= base && r.last_byte() >= end - 1) {
            return 0;
        }
        let first = self.map.partition_point(|d| d.physical_start + d.page_count * 4096 <= base);
        let mut cursor = base;
        let mut any = false;
        let mut full = excluded.is_none();
        for d in &self.map[first..] {
            if d.physical_start >= end {
                break;
            }
            let limit = (d.physical_start + d.page_count * 4096).min(end);
            let admitted = (1..=7).contains(&d.memory_type)
                && d.attributes & 8 != 0
                && d.attributes & (0x1000 | 0x2000 | 0x20000) == 0;
            any |= admitted;
            full &= d.physical_start <= cursor && admitted;
            cursor = limit;
        }
        if !any {
            0
        } else if full && cursor == end {
            2
        } else {
            1
        }
    }
}

fn visit(
    input: &Input<'_>,
    base: u64,
    level: u8,
    used: &mut usize,
    emit: &mut impl FnMut(usize, usize, u64) -> Result<(), ImageError>,
) -> Result<(), ImageError> {
    let page = *used - 1;
    let bytes = 1u64 << (12 + 9 * (level - 1));
    for index in 0..512 {
        let address = base + index as u64 * bytes;
        let class = input.classify(address, bytes);
        let word = if class == 0 {
            0
        } else if class == 2 && level <= 3 {
            address | RW | FC | 1
        } else {
            if level == 1 {
                return Err(ImageError::Exclusions);
            }
            if *used == COMPOSITION_TABLE_PAGES {
                return Err(ImageError::Capacity);
            }
            let child = *used;
            *used += 1;
            visit(input, address, level - 1, used, emit)?;
            (input.root + child as u64 * 4096) | RW | (u64::from(level - 1) << 9) | 1
        };
        emit(page, index, word)?;
    }
    Ok(())
}
