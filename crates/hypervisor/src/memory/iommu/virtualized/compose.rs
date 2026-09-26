//! Build a complete bounded DVA -> GPA -> HPA composition from private copied
//! guest tables. All admitted leaves are enumerated; this is not fault-driven
//! learning. Hardware does not retry or queue DMA faults to discover mappings.

use super::guest::{self, DeviceEntry, Exclusion, PageEntry, TranslationMode, WalkError};
use super::snapshot::{
    Dependencies, DependencyError, Snapshot, SnapshotError, TableRole, TrackedSnapshot,
};
use super::{GUEST_LIMIT, PAGE, guest_span, intersect, permissions};
use crate::memory::address::{AddressError, AddressPolicy};
use crate::memory::iommu::image::{self, MappingRange, ProtectedRange};
use crate::memory::iommu::tables::{PageCoherency, Permissions};

pub mod mixed;

pub const MAX_HOST_RANGES: usize = 4096;
pub const MAX_ENTRY_VISITS: usize = 1_048_576;
pub const MAX_COMPOSITION_STEPS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestHostRange {
    pub guest_base: u64,
    pub host_base: u64,
    pub len: u64,
    pub permissions: Permissions,
}

/// Numeric, immutable guest-RAM policy. This is not an admission capability.
pub struct HostMap<'a> {
    ranges: &'a [GuestHostRange],
    protected: &'a [ProtectedRange],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComposeError {
    InvalidGuestRange,
    HostAddress(AddressError),
    UnsortedRanges,
    Capacity,
    WorkLimit,
    Snapshot(SnapshotError),
    SnapshotOutsideRam(u64),
    SnapshotAliasMismatch(u64),
    Dependency(DependencyError),
    Guest(WalkError),
    InvalidExclusion,
    Image(image::BuildError),
}

impl<'a> HostMap<'a> {
    pub fn new(
        policy: AddressPolicy,
        ranges: &'a [GuestHostRange],
        protected: &'a [ProtectedRange],
    ) -> Result<Self, ComposeError> {
        if ranges.len() > MAX_HOST_RANGES || protected.len() > image::MAX_PROTECTED_RANGES {
            return Err(ComposeError::Capacity);
        }
        let mut end = 0;
        for range in ranges {
            if !guest_span(range.guest_base, range.len, PAGE) || range.len & (PAGE - 1) != 0 {
                return Err(ComposeError::InvalidGuestRange);
            }
            if range.guest_base < end {
                return Err(ComposeError::UnsortedRanges);
            }
            policy.validate(range.host_base, range.len, PAGE).map_err(ComposeError::HostAddress)?;
            end = range.guest_base + range.len;
        }
        end = 0;
        for range in protected {
            if range.len & (PAGE - 1) != 0 {
                return Err(ComposeError::InvalidGuestRange);
            }
            policy.validate(range.base, range.len, PAGE).map_err(ComposeError::HostAddress)?;
            if range.base < end {
                return Err(ComposeError::UnsortedRanges);
            }
            end = range.base + range.len;
        }
        Ok(Self { ranges, protected })
    }

    pub const fn ranges(&self) -> &[GuestHostRange] {
        self.ranges
    }
    pub const fn protected(&self) -> &[ProtectedRange] {
        self.protected
    }

    fn check_snapshot(&self, snapshot: &Snapshot<'_>) -> Result<(), ComposeError> {
        for page in snapshot.pages() {
            let i = self.ranges.partition_point(|r| r.guest_base + r.len <= page.guest_page());
            let range = self
                .ranges
                .get(i)
                .filter(|r| r.guest_base <= page.guest_page() && r.permissions.allows_read())
                .ok_or(ComposeError::SnapshotOutsideRam(page.guest_page()))?;
            let host = range.host_base + page.guest_page() - range.guest_base;
            if host != page.source_host_page() {
                return Err(ComposeError::SnapshotAliasMismatch(page.guest_page()));
            }
            if self.protected.iter().any(|r| host < r.base + r.len && r.base < host + PAGE) {
                return Err(ComposeError::SnapshotOutsideRam(page.guest_page()));
            }
        }
        Ok(())
    }
}

/// All mappings are 4KiB aligned, sorted and nonoverlapping, ready for the host
/// image builder. Protected outputs are holes. Every captured guest table page
/// loses DMA write permission through every physical alias, including bypass.
/// These slices describe one immutable composition, never an installed domain.
/// Publication must revalidate the source capture's epoch and liveness under
/// its control lease. This inert value does not retain or substitute that lease.
pub struct Composed<'a> {
    ranges: &'a [MappingRange],
}

impl Composed<'_> {
    pub const fn ranges(&self) -> &[MappingRange] {
        self.ranges
    }

    pub fn build_image<'a>(
        &self,
        policy: AddressPolicy,
        backing: u64,
        storage: &'a mut [image::TablePage],
        protected: &[ProtectedRange],
    ) -> Result<image::HostPageTableImage<'a>, ComposeError> {
        image::build(policy, backing, storage, self.ranges, protected).map_err(ComposeError::Image)
    }
}

/// Enumerate the complete selected guest domain into scratch storage. No output
/// image exists on error, though scratch and dependency metadata may be changed.
/// A maximum entry count bounds malicious repeated/cyclic page-table links;
/// decreasing levels already make actual cycles impossible within one walk.
pub fn compose<'a>(
    tracked: &TrackedSnapshot<'_>,
    device: DeviceEntry,
    enabled: bool,
    exclusion: Option<Exclusion>,
    host: &HostMap<'_>,
    output: &'a mut [MappingRange],
    dependencies: &mut Dependencies<'_>,
) -> Result<Composed<'a>, ComposeError> {
    device.validate().map_err(|error| ComposeError::Guest(WalkError::Decode(error)))?;
    if output.len() > image::MAX_MAPPING_RANGES {
        return Err(ComposeError::Capacity);
    }
    let snapshot = tracked.snapshot().map_err(ComposeError::Snapshot)?;
    host.check_snapshot(snapshot)?;
    if let Some(range) = exclusion {
        if !range.valid() {
            return Err(ComposeError::InvalidExclusion);
        }
    }
    let effective_exclusion = exclusion.filter(|range| range.allow_all || device.allow_exclusion);
    let mut build = Builder {
        snapshot,
        host,
        output,
        len: 0,
        visits: 0,
        steps: 0,
        dependencies,
        exclusion: effective_exclusion,
    };
    if !enabled || device.mode == TranslationMode::Bypass {
        build.exclusion = None;
        build.emit(0, 0, GUEST_LIMIT, Permissions::ReadWrite, PageCoherency::Inherit)?;
    } else {
        match device.mode {
            TranslationMode::Paging { root, levels } => {
                build.table(root, levels, 0, device.permissions)?
            }
            TranslationMode::Identity => {
                build.emit(0, 0, GUEST_LIMIT, device.permissions, PageCoherency::Inherit)?
            }
            TranslationMode::Unavailable => (),
            TranslationMode::Bypass => unreachable!(),
        }
        if let Some(range) = effective_exclusion {
            build.exclusion = None;
            build.emit(
                range.base,
                range.base,
                range.limit - range.base + 1,
                Permissions::ReadWrite,
                PageCoherency::Inherit,
            )?;
        }
    }
    let len = build.len;
    let ranges = &mut output[..len];
    ranges.sort_unstable_by_key(|range| range.io_base);
    let mut used = 0;
    for index in 0..len {
        let range = ranges[index];
        if used != 0 {
            let prior = &mut ranges[used - 1];
            if prior.io_base + prior.len == range.io_base
                && prior.system_base + prior.len == range.system_base
                && prior.permissions == range.permissions
                && prior.coherency == range.coherency
            {
                prior.len += range.len;
                continue;
            }
        }
        ranges[used] = range;
        used += 1;
    }
    Ok(Composed { ranges: &output[..used] })
}

struct Builder<'a, 'b, 'c, 'd, 'e, 'f, 'g> {
    snapshot: &'a Snapshot<'b>,
    host: &'c HostMap<'d>,
    output: &'e mut [MappingRange],
    len: usize,
    visits: usize,
    steps: usize,
    dependencies: &'f mut Dependencies<'g>,
    exclusion: Option<Exclusion>,
}

impl Builder<'_, '_, '_, '_, '_, '_, '_> {
    fn charge(&mut self) -> Result<(), ComposeError> {
        self.steps += 1;
        if self.steps > MAX_COMPOSITION_STEPS { Err(ComposeError::WorkLimit) } else { Ok(()) }
    }

    fn table(
        &mut self,
        table: u64,
        level: u8,
        prefix: u64,
        effective: Permissions,
    ) -> Result<(), ComposeError> {
        self.dependencies
            .record(self.snapshot, table, TableRole::Translation)
            .map_err(ComposeError::Dependency)?;
        let shift = 12 + 9 * (level - 1);
        for index in 0..512 {
            self.charge()?;
            self.visits += 1;
            if self.visits > MAX_ENTRY_VISITS {
                return Err(ComposeError::WorkLimit);
            }
            let raw = self.snapshot.read_u64(table + index * 8).map_err(ComposeError::Snapshot)?;
            let io = prefix | (index << shift);
            match guest::decode_page(level, raw)
                .map_err(|error| ComposeError::Guest(WalkError::Decode(error)))?
            {
                PageEntry::Absent => (),
                PageEntry::Directory { address, next, permissions } => {
                    self.table(address, next, io, intersect(effective, permissions))?
                }
                PageEntry::Leaf { address, size, permissions, coherency } => self.emit(
                    io,
                    address | (io & (size - 1)),
                    1 << shift,
                    intersect(effective, permissions),
                    coherency,
                )?,
            }
        }
        Ok(())
    }

    fn emit(
        &mut self,
        io: u64,
        guest: u64,
        len: u64,
        access: Permissions,
        coherent: PageCoherency,
    ) -> Result<(), ComposeError> {
        // Apply virtual exclusion as a second identity range after enumeration.
        if let Some(ex) = self.exclusion {
            let first = io.max(ex.base);
            let end = (io + len).min(ex.limit + 1);
            if first < end {
                if first > io {
                    self.emit_ram(io, guest, first - io, access, coherent)?;
                }
                if end < io + len {
                    self.emit_ram(end, guest + end - io, io + len - end, access, coherent)?;
                }
                return Ok(());
            }
        }
        self.emit_ram(io, guest, len, access, coherent)
    }

    fn emit_ram(
        &mut self,
        io: u64,
        guest: u64,
        len: u64,
        access: Permissions,
        coherent: PageCoherency,
    ) -> Result<(), ComposeError> {
        for map in self.host.ranges {
            self.charge()?;
            let first = guest.max(map.guest_base);
            let end = (guest + len).min(map.guest_base + map.len);
            if first >= end {
                continue;
            }
            let effective = intersect(access, map.permissions);
            let mut cursor = map.host_base + first - map.guest_base;
            let host_end = cursor + end - first;
            let mut io_cursor = io + first - guest;
            while cursor < host_end {
                let mut next = host_end;
                let mut denied = false;
                let mut table = false;
                for protected in self.host.protected {
                    self.charge()?;
                    split(cursor, protected.base, protected.len, &mut next, &mut denied);
                }
                for page in self.snapshot.pages() {
                    self.charge()?;
                    split(cursor, page.source_host_page(), PAGE, &mut next, &mut table);
                }
                let length = next - cursor;
                if !denied {
                    let permissions =
                        permissions(effective.allows_read(), effective.allows_write() && !table);
                    if permissions != Permissions::None {
                        self.push(MappingRange {
                            io_base: io_cursor,
                            system_base: cursor,
                            len: length,
                            permissions,
                            coherency: coherent,
                        })?;
                    }
                }
                cursor = next;
                io_cursor += length;
            }
        }
        Ok(())
    }

    fn push(&mut self, range: MappingRange) -> Result<(), ComposeError> {
        if self.len != 0 {
            let prior = &mut self.output[self.len - 1];
            if prior.io_base + prior.len == range.io_base
                && prior.system_base + prior.len == range.system_base
                && prior.permissions == range.permissions
                && prior.coherency == range.coherency
            {
                prior.len += range.len;
                return Ok(());
            }
        }
        if self.len == self.output.len() {
            return Err(ComposeError::Capacity);
        }
        self.output[self.len] = range;
        self.len += 1;
        Ok(())
    }
}

fn split(cursor: u64, base: u64, len: u64, next: &mut u64, inside: &mut bool) {
    if cursor >= base && cursor < base + len {
        *inside = true;
        *next = (*next).min(base + len);
    } else if base > cursor {
        *next = (*next).min(base);
    }
}
