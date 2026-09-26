//! Private-root mapping of the retained observation and mutable resources. CPU
//! memory lifetime support, not current hardware evidence or DMA protection.
#![forbid(unsafe_code)]

use super::{
    IMAGE_LIMIT_OFFSET, IOMMU_RETAINED_BYTES, SHARED_RETAINED_BYTES, is_valid_pool_slot,
    retained_iommu_base,
};

pub const HOST_TABLE_PAGES: usize = 6;
pub const HOST_TABLE_BYTES: u64 = HOST_TABLE_PAGES as u64 * 4096;

/// Add supervisor/NX identity aliases for the complete shared allocation. The
/// observation is read-only; per-unit hardware banks and both composition
/// generations are writable. AMD APM2 physical pp206-207,211,215-216 define
/// 4KiB/2MiB leaf permissions. Complete interior 2MiB resource spans use large
/// leaves; only the observation boundary and final partial span require PTs.
///
/// All checks precede mutation. Numeric shape is not allocation or cache
/// admission; the firmware closure walker independently checks the actual root.
pub fn map_retained_backing(
    tables: &mut [[u64; 512]; HOST_TABLE_PAGES],
    root: u64,
    base: u64,
    pool_base: u64,
    pool_bytes: u64,
) -> bool {
    let Some(relative) = base.checked_sub(pool_base) else { return false };
    if relative & 0xfffff != 0
        || !is_valid_pool_slot(base, pool_base, pool_bytes, relative / 0x100000, 0)
        || root & 4095 != 0
        || root < base
        || root.checked_add(HOST_TABLE_BYTES).is_none_or(|end| end > base + IMAGE_LIMIT_OFFSET)
    {
        return false;
    }
    let Some(retained) = retained_iommu_base(pool_base, pool_bytes) else { return false };
    let end = retained + SHARED_RETAINED_BYTES;
    let first_directory = ((retained >> 21) & 511) as usize;
    let last_directory = (((end - 1) >> 21) & 511) as usize;
    if last_directory <= first_directory
        || tables[0][0] != (root + 4096) | 3
        || tables[1][0] != (root + 8192) | 3
    {
        return false;
    }
    let local_directory = ((base >> 21) & 511) as usize;
    if tables[2][local_directory] != (root + 12288) | 3
        || tables[4..].iter().flatten().any(|word| *word != 0)
    {
        return false;
    }
    let leaf_for = |directory| {
        if directory == local_directory {
            3
        } else if directory == first_directory || first_directory == local_directory {
            4
        } else {
            5
        }
    };
    for directory in first_directory..=last_directory {
        if directory != local_directory && tables[2][directory] != 0 {
            return false;
        }
    }
    for directory in [first_directory, last_directory] {
        let start = (directory as u64 * 0x200000).max(retained);
        let limit = ((directory as u64 + 1) * 0x200000).min(end);
        let leaf = leaf_for(directory);
        for page in (start..limit).step_by(4096) {
            if tables[leaf][((page >> 12) & 511) as usize] != 0 {
                return false;
            }
        }
    }
    for directory in first_directory..=last_directory {
        if directory != first_directory && directory != last_directory {
            tables[2][directory] = (directory as u64 * 0x200000) | 0x83 | (1 << 63);
            continue;
        }
        let leaf = leaf_for(directory);
        tables[2][directory] = (root + leaf as u64 * 4096) | 3;
        let start = (directory as u64 * 0x200000).max(retained);
        let limit = ((directory as u64 + 1) * 0x200000).min(end);
        for page in (start..limit).step_by(4096) {
            let write = if page >= retained + IOMMU_RETAINED_BYTES { 2 } else { 0 };
            tables[leaf][((page >> 12) & 511) as usize] = page | 1 | write | (1 << 63);
        }
    }
    true
}
