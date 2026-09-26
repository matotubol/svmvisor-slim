//! Guest AMD formats for the 48-bit, four-level, no-optional-feature profile.
//! Sources: 48882-3.11 physical pp63-75,79-85,91-92; layout PNGs checked.

use super::snapshot::{Dependencies, DependencyError, Snapshot, SnapshotError, TableRole};
use super::{ADDRESS, GUEST_LIMIT, PAGE, guest_span, intersect, permissions};
use crate::memory::iommu::tables::{PageCoherency, Permissions};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranslationMode {
    Bypass,
    Unavailable,
    Paging { root: u64, levels: u8 },
    Identity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptMode {
    Pass,
    Abort,
    Remap { root: u64, entries: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceEntry {
    pub mode: TranslationMode,
    pub permissions: Permissions,
    pub domain: u16,
    pub allow_exclusion: bool,
    pub suppress_all: bool,
    pub suppress_first: bool,
    pub interrupt: InterruptMode,
    pub ignore_interrupt_faults: bool,
    /// LINT1,LINT0,NMI,ExtInt,INIT bits packed in architectural word-2 positions.
    pub interrupt_pass: u64,
    pub sys_mgt: u8,
    pub io_ctl: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Reserved { word: u8, bits: u64 },
    UnsupportedMode(u8),
    InvalidInterruptControl,
    InvalidInterruptLength,
    AddressWidth,
    MisalignedLeaf,
    InvalidLevel,
    InvalidLargePage,
}

impl DeviceEntry {
    /// Recheck public decoded values before arithmetic or indexed access. These
    /// values are useful to policy adapters but are not unforgeable capabilities.
    pub fn validate(self) -> Result<(), DecodeError> {
        if let TranslationMode::Paging { root, levels } = self.mode {
            if !(1..=4).contains(&levels) {
                return Err(DecodeError::InvalidLevel);
            }
            if !guest_span(root, PAGE, PAGE) {
                return Err(DecodeError::AddressWidth);
            }
        }
        if let InterruptMode::Remap { root, entries } = self.interrupt {
            if !entries.is_power_of_two() || entries > 2048 {
                return Err(DecodeError::InvalidInterruptLength);
            }
            if !guest_span(root, u64::from(entries) * 4, 128) {
                return Err(DecodeError::AddressWidth);
            }
        }
        Ok(())
    }

    pub fn decode(words: [u64; 4]) -> Result<Self, DecodeError> {
        let [a, b, c, d] = words;
        let valid = a & 1 != 0;
        let tv = a & 2 != 0;
        let iv = c & 1 != 0;
        // V and IV independently gate their architectural halves. Inactive
        // payload is ignored, not incorrectly rejected by the host codec.
        if valid {
            let allowed_a = 3 | ADDRESS | (7 << 9) | (3 << 61);
            reject(a & !allowed_a, 0)?;
            let allowed_b = 0xffff | (0x3fe_u64 << 32); // SE..SysMgt, no ATS I.
            reject(b & !allowed_b, 1)?;
            if (b >> 35) & 3 == 3 {
                return Err(DecodeError::Reserved { word: 1, bits: 3 << 35 });
            }
        }
        let interrupt = if !iv {
            InterruptMode::Pass
        } else {
            // Basic interrupt root bits [51:6], pass bits, IG and length are
            // architectural; optional HPTMode/GuestPagingMode are absent.
            let allowed_c = 0xf70f_ffff_ffff_ffff;
            reject(c & !allowed_c, 2)?;
            reject(d, 3)?;
            let len = ((c >> 1) & 15) as u8;
            if len > 11 {
                return Err(DecodeError::InvalidInterruptLength);
            }
            match (c >> 60) & 3 {
                0 => InterruptMode::Abort,
                1 => InterruptMode::Pass,
                2 => {
                    let root = c & 0x000f_ffff_ffff_ffc0;
                    if root & 127 != 0 || !guest_span(root, (1u64 << len) * 4, 128) {
                        return Err(DecodeError::AddressWidth);
                    }
                    InterruptMode::Remap { root, entries: 1u16 << len }
                }
                _ => return Err(DecodeError::InvalidInterruptControl),
            }
        };
        let mode = if !valid {
            TranslationMode::Bypass
        } else if !tv {
            TranslationMode::Unavailable
        } else {
            let levels = ((a >> 9) & 7) as u8;
            match levels {
                0 => TranslationMode::Identity,
                1..=4 => {
                    let root = a & ADDRESS;
                    if !guest_span(root, PAGE, PAGE) {
                        return Err(DecodeError::AddressWidth);
                    }
                    TranslationMode::Paging { root, levels }
                }
                _ => return Err(DecodeError::UnsupportedMode(levels)),
            }
        };
        Ok(Self {
            mode,
            permissions: if valid { from_word(a) } else { Permissions::ReadWrite },
            domain: if valid { b as u16 } else { 0 },
            allow_exclusion: valid && b & (1 << 39) != 0,
            suppress_all: valid && b & (1 << 34) != 0,
            suppress_first: valid && b & (1 << 33) != 0,
            interrupt,
            ignore_interrupt_faults: iv && c & (1 << 5) != 0,
            interrupt_pass: if iv { c & 0xc700_0000_0000_0000 } else { 0xc700_0000_0000_0000 },
            sys_mgt: if valid { ((b >> 40) & 3) as u8 } else { 1 },
            io_ctl: if valid { ((b >> 35) & 3) as u8 } else { 1 },
        })
    }

    pub fn read(
        snapshot: &Snapshot<'_>,
        table_base: u64,
        table_len: u64,
        device: u16,
        dependencies: &mut Dependencies<'_>,
    ) -> Result<Self, WalkError> {
        if !guest_span(table_base, table_len, PAGE)
            || table_len & (PAGE - 1) != 0
            || u64::from(device) * 32 + 32 > table_len
        {
            return Err(WalkError::DeviceOutsideTable);
        }
        let address = table_base + u64::from(device) * 32;
        dependencies.record(snapshot, address, TableRole::Device).map_err(WalkError::Dependency)?;
        let mut words = [0; 4];
        for (i, word) in words.iter_mut().enumerate() {
            *word = snapshot.read_u64(address + i as u64 * 8).map_err(WalkError::Snapshot)?;
        }
        Self::decode(words).map_err(WalkError::Decode)
    }
}

fn reject(bits: u64, word: u8) -> Result<(), DecodeError> {
    if bits == 0 { Ok(()) } else { Err(DecodeError::Reserved { word, bits }) }
}

pub(crate) fn from_word(word: u64) -> Permissions {
    permissions(word & (1 << 61) != 0, word & (1 << 62) != 0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PageEntry {
    Absent,
    Directory { address: u64, next: u8, permissions: Permissions },
    Leaf { address: u64, size: u64, permissions: Permissions, coherency: PageCoherency },
}

pub(crate) fn decode_page(level: u8, word: u64) -> Result<PageEntry, DecodeError> {
    if !(1..=4).contains(&level) {
        return Err(DecodeError::InvalidLevel);
    }
    if word & 1 == 0 {
        return Ok(PageEntry::Absent);
    }
    let next = ((word >> 9) & 7) as u8;
    let address = word & ADDRESS;
    let permissions = from_word(word);
    if next != 0 && next != 7 {
        reject(word & (0x1ff << 52), 0)?;
        if next >= level {
            return Err(DecodeError::InvalidLevel);
        }
        if !guest_span(address, PAGE, PAGE) {
            return Err(DecodeError::AddressWidth);
        }
        return Ok(PageEntry::Directory { address, next, permissions });
    }
    reject(word & (0x7f << 52), 0)?;
    let default_shift = 12 + 9 * (level - 1);
    let shift = if next == 0 {
        default_shift
    } else {
        let first_zero = (address >> 12).trailing_ones() as u8 + 12;
        let shift = first_zero + 1;
        if shift <= default_shift || shift >= default_shift + 9 {
            return Err(DecodeError::InvalidLargePage);
        }
        shift
    };
    let size = 1u64 << shift;
    if next == 0 && address & (size - 1) != 0 {
        return Err(DecodeError::MisalignedLeaf);
    }
    let base = address & !(size - 1);
    if !guest_span(base, size, size) {
        return Err(DecodeError::AddressWidth);
    }
    Ok(PageEntry::Leaf {
        address: base,
        size,
        permissions,
        coherency: if word & (1 << 60) != 0 {
            PageCoherency::ForceCoherent
        } else {
            PageCoherency::Inherit
        },
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exclusion {
    pub base: u64,
    pub limit: u64,
    pub allow_all: bool,
}

impl Exclusion {
    pub const fn valid(self) -> bool {
        self.base & (PAGE - 1) == 0
            && self.limit & (PAGE - 1) == PAGE - 1
            && self.base <= self.limit
            && self.limit < GUEST_LIMIT
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Translation {
    pub guest_address: u64,
    pub permissions: Permissions,
    pub coherency: PageCoherency,
    pub page_size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalkError {
    Decode(DecodeError),
    Snapshot(SnapshotError),
    Dependency(DependencyError),
    DeviceOutsideTable,
    AddressWidth,
    TranslationUnavailable,
    SkippedAddressBits,
    NotPresent,
    InvalidExclusion,
}

pub fn walk(
    snapshot: &Snapshot<'_>,
    device: DeviceEntry,
    enabled: bool,
    exclusion: Option<Exclusion>,
    io: u64,
    dependencies: &mut Dependencies<'_>,
) -> Result<Translation, WalkError> {
    device.validate().map_err(WalkError::Decode)?;
    if exclusion.is_some_and(|range| !range.valid()) {
        return Err(WalkError::InvalidExclusion);
    }
    if io >= GUEST_LIMIT {
        return Err(WalkError::AddressWidth);
    }
    let excluded = exclusion.is_some_and(|range| {
        (range.allow_all || device.allow_exclusion) && range.base <= io && io <= range.limit
    });
    if !enabled || excluded || device.mode == TranslationMode::Bypass {
        return Ok(Translation {
            guest_address: io,
            permissions: Permissions::ReadWrite,
            coherency: PageCoherency::Inherit,
            page_size: PAGE,
        });
    }
    let (mut table, mut level) = match device.mode {
        TranslationMode::Unavailable => return Err(WalkError::TranslationUnavailable),
        TranslationMode::Identity => {
            return Ok(Translation {
                guest_address: io,
                permissions: device.permissions,
                coherency: PageCoherency::Inherit,
                page_size: PAGE,
            });
        }
        TranslationMode::Paging { root, levels } => (root, levels),
        TranslationMode::Bypass => unreachable!(),
    };
    if io >> (12 + 9 * level) != 0 {
        return Err(WalkError::SkippedAddressBits);
    }
    let mut effective = device.permissions;
    for _ in 0..4 {
        let shift = 12 + 9 * (level - 1);
        let address = table + ((io >> shift) & 511) * 8;
        dependencies
            .record(snapshot, address, TableRole::Translation)
            .map_err(WalkError::Dependency)?;
        match decode_page(level, snapshot.read_u64(address).map_err(WalkError::Snapshot)?)
            .map_err(WalkError::Decode)?
        {
            PageEntry::Absent => return Err(WalkError::NotPresent),
            PageEntry::Directory { address, next, permissions } => {
                let mask = ((1u64 << shift) - 1) & !((1u64 << (12 + 9 * next)) - 1);
                if io & mask != 0 {
                    return Err(WalkError::SkippedAddressBits);
                }
                effective = intersect(effective, permissions);
                table = address;
                level = next;
            }
            PageEntry::Leaf { address, size, permissions, coherency } => {
                return Ok(Translation {
                    guest_address: address | (io & (size - 1)),
                    permissions: intersect(effective, permissions),
                    coherency,
                    page_size: size,
                });
            }
        }
    }
    Err(WalkError::Decode(DecodeError::InvalidLevel))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptDelivery {
    Fixed,
    Arbitrated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterruptEntry {
    pub enabled: bool,
    pub suppress_fault: bool,
    pub delivery: InterruptDelivery,
    pub logical: bool,
    pub request_eoi: bool,
    pub destination: u8,
    pub vector: u8,
}

impl InterruptEntry {
    pub fn decode(word: u32) -> Result<Self, DecodeError> {
        // Reserved fields are checked for enabled entries. Disabled entries
        // still carry SupIOPF; all other fields are unused by the abort action.
        if word & 1 != 0 {
            reject(u64::from(word & 0xff00_0080), 0)?;
            if word & 0x1c > 4 {
                return Err(DecodeError::InvalidInterruptControl);
            }
        }
        Ok(Self {
            enabled: word & 1 != 0,
            suppress_fault: word & 2 != 0,
            delivery: if word & 4 != 0 {
                InterruptDelivery::Arbitrated
            } else {
                InterruptDelivery::Fixed
            },
            logical: word & 0x40 != 0,
            request_eoi: word & 0x20 != 0,
            destination: (word >> 8) as u8,
            vector: (word >> 16) as u8,
        })
    }

    pub fn read(
        snapshot: &Snapshot<'_>,
        device: DeviceEntry,
        msi_data: u16,
        dependencies: &mut Dependencies<'_>,
    ) -> Result<Self, WalkError> {
        device.validate().map_err(WalkError::Decode)?;
        let InterruptMode::Remap { root, entries } = device.interrupt else {
            return Err(WalkError::TranslationUnavailable);
        };
        let index = msi_data & 0x7ff;
        if index >= entries {
            return Err(WalkError::DeviceOutsideTable);
        }
        let address = root + u64::from(index) * 4;
        dependencies
            .record(snapshot, address, TableRole::Interrupt)
            .map_err(WalkError::Dependency)?;
        Self::decode(snapshot.read_u32(address).map_err(WalkError::Snapshot)?)
            .map_err(WalkError::Decode)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterruptMessage {
    pub delivery: InterruptDelivery,
    pub logical: bool,
    pub request_eoi: bool,
    pub destination: u8,
    pub vector: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptAction {
    /// Target fields are guest APIC identities. A physical interrupt policy must
    /// translate them; these are never authority to program native APIC delivery.
    Deliver(InterruptMessage),
    Abort {
        report: bool,
    },
}

/// Evaluate basic fixed/arbitrated interrupt remapping, retaining destination
/// mode, delivery mode and RqEoi. Guest GA/SMI/legacy special messages are outside
/// this function and are not silently treated as ordinary fixed interrupts.
pub fn remap_interrupt(
    snapshot: &Snapshot<'_>,
    device: DeviceEntry,
    enabled: bool,
    table_index: u16,
    incoming: InterruptMessage,
    dependencies: &mut Dependencies<'_>,
) -> Result<InterruptAction, WalkError> {
    device.validate().map_err(WalkError::Decode)?;
    if !enabled || device.interrupt == InterruptMode::Pass {
        return Ok(InterruptAction::Deliver(incoming));
    }
    if device.interrupt == InterruptMode::Abort {
        return Ok(InterruptAction::Abort { report: !device.ignore_interrupt_faults });
    }
    if table_index >= 2048 {
        return Err(WalkError::DeviceOutsideTable);
    }
    let entry = InterruptEntry::read(snapshot, device, table_index, dependencies)?;
    if !entry.enabled {
        return Ok(InterruptAction::Abort {
            report: !(device.ignore_interrupt_faults || entry.suppress_fault),
        });
    }
    Ok(InterruptAction::Deliver(InterruptMessage {
        delivery: entry.delivery,
        logical: entry.logical,
        request_eoi: entry.request_eoi,
        destination: entry.destination,
        vector: entry.vector,
    }))
}
