//! Immutable copied input and dependency tracking. These types deliberately
//! confer no live-capture authority. CPU interception and device quiescence must
//! precede capture in a future native integration; NPT cannot observe DMA writes.

use super::{PAGE, guest_span};

pub const MAX_SNAPSHOT_PAGES: usize = 4096;
pub const MAX_CAPTURE_ENTRY_VISITS: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct SnapshotPage {
    guest: u64,
    source_host: u64,
    bytes: [u8; PAGE as usize],
}

impl SnapshotPage {
    /// Empty workspace cell, not a captured page. A capture only exposes its
    /// initialized prefix and never constructs Snapshot from unused cells.
    pub const EMPTY: Self = Self { guest: 0, source_host: 0, bytes: [0; PAGE as usize] };

    /// Copy bytes into private Rust-owned storage. `source_host` is a numeric
    /// alias identity, not an address this module dereferences or admits.
    pub fn copy(guest: u64, source_host: u64, bytes: &[u8]) -> Result<Self, SnapshotError> {
        if !guest_span(guest, PAGE, PAGE)
            || source_host & (PAGE - 1) != 0
            || source_host.checked_add(PAGE).is_none()
            || bytes.len() != PAGE as usize
        {
            return Err(SnapshotError::InvalidPage);
        }
        let mut copied = [0; PAGE as usize];
        copied.copy_from_slice(bytes);
        Ok(Self { guest, source_host, bytes: copied })
    }

    pub const fn guest_page(&self) -> u64 {
        self.guest
    }
    pub const fn source_host_page(&self) -> u64 {
        self.source_host
    }

    pub const fn bytes(&self) -> &[u8; PAGE as usize] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    InvalidPage,
    TooManyPages,
    UnsortedPages,
    InconsistentAlias,
    MissingPage(u64),
    UnalignedWord,
    Stale,
}

#[derive(Debug)]
pub struct Snapshot<'a> {
    pages: &'a [SnapshotPage],
}

impl<'a> Snapshot<'a> {
    pub fn new(pages: &'a [SnapshotPage]) -> Result<Self, SnapshotError> {
        if pages.len() > MAX_SNAPSHOT_PAGES {
            return Err(SnapshotError::TooManyPages);
        }
        for (i, page) in pages.iter().enumerate() {
            if i != 0 && pages[i - 1].guest >= page.guest {
                return Err(SnapshotError::UnsortedPages);
            }
            // Aliases are admitted only when they describe identical copied
            // contents. This is bounded by MAX_SNAPSHOT_PAGES, not guest data.
            if pages[..i]
                .iter()
                .any(|prior| prior.source_host == page.source_host && prior.bytes != page.bytes)
            {
                return Err(SnapshotError::InconsistentAlias);
            }
        }
        Ok(Self { pages })
    }

    pub const fn pages(&self) -> &[SnapshotPage] {
        self.pages
    }

    pub fn page(&self, address: u64) -> Result<&SnapshotPage, SnapshotError> {
        let base = address & !(PAGE - 1);
        self.pages
            .binary_search_by_key(&base, |page| page.guest)
            .map(|i| &self.pages[i])
            .map_err(|_| SnapshotError::MissingPage(base))
    }

    pub fn read_u64(&self, address: u64) -> Result<u64, SnapshotError> {
        if address & 7 != 0 {
            return Err(SnapshotError::UnalignedWord);
        }
        let page = self.page(address)?;
        let offset = (address & (PAGE - 1)) as usize;
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&page.bytes[offset..offset + 8]);
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn read_u32(&self, address: u64) -> Result<u32, SnapshotError> {
        if address & 3 != 0 {
            return Err(SnapshotError::UnalignedWord);
        }
        let page = self.page(address)?;
        let offset = (address & (PAGE - 1)) as usize;
        let mut bytes = [0; 4];
        bytes.copy_from_slice(&page.bytes[offset..offset + 4]);
        Ok(u32::from_le_bytes(bytes))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableRole {
    Device,
    Translation,
    Interrupt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Writer {
    Cpu,
    Dma,
    Monitor,
}

/// An immutable-copy tracker. A single observed mutation permanently invalidates
/// this copy, including writes through a different GPA to the same host page.
/// Replacement requires a new copy and new tracker; invalidation commands do not
/// magically repair the captured bytes. Every DTE/IRTE write is relevant, even
/// old V=IV=0 or RemapEn=0 writes which need no guest invalidation command.
#[derive(Debug)]
pub struct TrackedSnapshot<'a> {
    snapshot: Snapshot<'a>,
    stale: bool,
}

impl<'a> TrackedSnapshot<'a> {
    pub fn new(pages: &'a [SnapshotPage]) -> Result<Self, SnapshotError> {
        Ok(Self { snapshot: Snapshot::new(pages)?, stale: false })
    }

    pub fn snapshot(&self) -> Result<&Snapshot<'a>, SnapshotError> {
        if self.stale { Err(SnapshotError::Stale) } else { Ok(&self.snapshot) }
    }

    pub fn observe_write(
        &mut self,
        host: u64,
        len: u64,
        _writer: Writer,
    ) -> Result<bool, SnapshotError> {
        let end = host.checked_add(len).filter(|_| len != 0).ok_or(SnapshotError::InvalidPage)?;
        let affected = self
            .snapshot
            .pages
            .iter()
            .any(|page| host < page.source_host + PAGE && page.source_host < end);
        self.stale |= affected;
        Ok(affected)
    }

    pub const fn is_stale(&self) -> bool {
        self.stale
    }
}

/// A bounded manifest of exactly which copied pages were consulted. Repeated
/// page reads merge roles; the entire immutable capture is also DMA-write
/// excluded by the composer to cover subsequently discovered table links.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dependency {
    pub guest_page: u64,
    pub source_host_page: u64,
    pub roles: u8,
}

impl Dependency {
    pub const EMPTY: Self = Self { guest_page: 0, source_host_page: 0, roles: 0 };
}

pub struct Dependencies<'a> {
    entries: &'a mut [Dependency],
    len: usize,
}

impl<'a> Dependencies<'a> {
    pub fn new(entries: &'a mut [Dependency]) -> Self {
        Self { entries, len: 0 }
    }
    pub fn entries(&self) -> &[Dependency] {
        &self.entries[..self.len]
    }
    pub fn record(
        &mut self,
        snapshot: &Snapshot<'_>,
        address: u64,
        role: TableRole,
    ) -> Result<(), DependencyError> {
        let page = snapshot.page(address).map_err(DependencyError::Snapshot)?;
        let bit = match role {
            TableRole::Device => 1,
            TableRole::Translation => 2,
            TableRole::Interrupt => 4,
        };
        if let Some(entry) =
            self.entries[..self.len].iter_mut().find(|entry| entry.guest_page == page.guest)
        {
            entry.roles |= bit;
            return Ok(());
        }
        if self.len == self.entries.len() {
            return Err(DependencyError::Capacity);
        }
        self.entries[self.len] =
            Dependency { guest_page: page.guest, source_host_page: page.source_host, roles: bit };
        self.len += 1;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencyError {
    Snapshot(SnapshotError),
    Capacity,
}

/// A page whose bytes are still needed. `levels` is a bit set because a guest
/// may use the same physical page at several decreasing page-table levels.
/// Every such interpretation must be traversed; a simple visited-page set would
/// incorrectly miss child tables in this case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CapturePage {
    pub guest_page: u64,
    pub host_page: u64,
    pub roles: u8,
    levels: u8,
    visited: u8,
    copied: bool,
}

impl CapturePage {
    pub const EMPTY: Self =
        Self { guest_page: 0, host_page: 0, roles: 0, levels: 0, visited: 0, copied: false };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureError {
    Capacity,
    WorkLimit,
    Address,
    SourceOutsideRam(u64),
    ProtectedSource(u64),
    WrongPage,
    Incomplete,
    Decode(super::guest::DecodeError),
    Snapshot(SnapshotError),
}

/// Bounded closure discovery over copied DTE/PDE/PTE/IRTE pages. This is NOT a
/// capture lease. The native owner must close CPU and DMA writes before calling
/// `supply`, and keep them closed until publication; comparing two samples does
/// not establish coherent memory. In particular, newly linked pages require
/// protection before copying, while every device-table page is requested even
/// if every old entry is V=IV=0. A missing protection backend cannot use this
/// object to justify guest resume.
pub struct Capture<'a, 'h> {
    pages: &'a mut [SnapshotPage],
    requests: &'a mut [CapturePage],
    host: &'h super::compose::HostMap<'h>,
    len: usize,
    failed: bool,
    visits: usize,
}

impl<'a, 'h> Capture<'a, 'h> {
    pub fn new(
        pages: &'a mut [SnapshotPage],
        requests: &'a mut [CapturePage],
        host: &'h super::compose::HostMap<'h>,
        device_base: u64,
        device_bytes: u64,
    ) -> Result<Self, CaptureError> {
        if pages.is_empty() || pages.len() > MAX_SNAPSHOT_PAGES || pages.len() != requests.len() {
            return Err(CaptureError::Capacity);
        }
        if !guest_span(device_base, device_bytes, PAGE)
            || device_bytes & (PAGE - 1) != 0
            || device_bytes > 512 * PAGE
        {
            return Err(CaptureError::Address);
        }
        let mut capture = Self { pages, requests, host, len: 0, failed: false, visits: 0 };
        for page in (device_base..device_base + device_bytes).step_by(PAGE as usize) {
            capture.request(page, 1, 0)?;
        }
        Ok(capture)
    }

    pub fn requests(&self) -> &[CapturePage] {
        &self.requests[..self.len]
    }

    pub fn next_page(&self) -> Option<CapturePage> {
        if self.failed {
            return None;
        }
        self.requests[..self.len].iter().find(|page| !page.copied).copied()
    }

    /// Supply exact bytes AFTER native CPU+DMA exclusion is effective. The
    /// numeric page identity is checked again; the API makes no boolean claim
    /// that the caller installed those protections.
    pub fn supply(&mut self, page: CapturePage, bytes: &[u8]) -> Result<(), CaptureError> {
        let result = self.supply_inner(page, bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn supply_inner(&mut self, page: CapturePage, bytes: &[u8]) -> Result<(), CaptureError> {
        if self.failed {
            return Err(CaptureError::Incomplete);
        }
        let index = self.requests[..self.len]
            .iter()
            .position(|request| {
                !request.copied
                    && request.guest_page == page.guest_page
                    && request.host_page == page.host_page
            })
            .ok_or(CaptureError::WrongPage)?;
        self.pages[index] = SnapshotPage::copy(page.guest_page, page.host_page, bytes)
            .map_err(CaptureError::Snapshot)?;
        // A physical alias must come from the same protected sample. Reject
        // contradictory copied values even before the final Snapshot check.
        if (0..self.len).any(|prior| {
            prior != index
                && self.requests[prior].copied
                && self.requests[prior].host_page == page.host_page
                && self.pages[prior].bytes != self.pages[index].bytes
        }) {
            return Err(CaptureError::Snapshot(SnapshotError::InconsistentAlias));
        }
        self.requests[index].copied = true;
        loop {
            let pending = (0..self.len).find(|&i| {
                let p = self.requests[i];
                p.copied && ((p.roles & 1 != 0 && p.visited & 1 == 0) || p.levels & !p.visited != 0)
            });
            let Some(index) = pending else {
                break;
            };
            self.discover(index)?;
        }
        Ok(())
    }

    fn request(&mut self, guest: u64, roles: u8, level: u8) -> Result<(), CaptureError> {
        if !guest_span(guest, PAGE, PAGE) {
            return Err(CaptureError::Address);
        }
        if let Some(page) = self.requests[..self.len].iter_mut().find(|p| p.guest_page == guest) {
            page.roles |= roles;
            page.levels |= if level == 0 { 0 } else { 1 << level };
            return Ok(());
        }
        if self.len == self.requests.len() {
            return Err(CaptureError::Capacity);
        }
        let map = self
            .host
            .ranges()
            .iter()
            .find(|map| {
                map.guest_base <= guest
                    && guest + PAGE <= map.guest_base + map.len
                    && map.permissions.allows_read()
            })
            .ok_or(CaptureError::SourceOutsideRam(guest))?;
        let host = map.host_base + guest - map.guest_base;
        if self.host.protected().iter().any(|p| host < p.base + p.len && p.base < host + PAGE) {
            return Err(CaptureError::ProtectedSource(guest));
        }
        self.requests[self.len] = CapturePage {
            guest_page: guest,
            host_page: host,
            roles,
            levels: if level == 0 { 0 } else { 1 << level },
            visited: 0,
            copied: false,
        };
        self.len += 1;
        Ok(())
    }

    fn discover(&mut self, index: usize) -> Result<(), CaptureError> {
        use super::guest::{DeviceEntry, InterruptMode, PageEntry, TranslationMode, decode_page};
        let page = self.requests[index];
        if page.roles & 1 != 0 && page.visited & 1 == 0 {
            self.requests[index].visited |= 1;
            for offset in (0..PAGE as usize).step_by(32) {
                self.charge()?;
                let mut words = [0; 4];
                for (word, value) in words.iter_mut().enumerate() {
                    let start = offset + word * 8;
                    *value = u64::from_le_bytes(
                        self.pages[index].bytes[start..start + 8].try_into().unwrap(),
                    );
                }
                let entry = DeviceEntry::decode(words).map_err(CaptureError::Decode)?;
                if let TranslationMode::Paging { root, levels } = entry.mode {
                    self.request(root, 2, levels)?;
                }
                if let InterruptMode::Remap { root, entries } = entry.interrupt {
                    let last = (root + u64::from(entries) * 4 - 1) & !(PAGE - 1);
                    for base in (root & !(PAGE - 1)..=last).step_by(PAGE as usize) {
                        self.request(base, 4, 0)?;
                    }
                }
            }
        }
        for level in 1..=4 {
            let bit = 1 << level;
            if page.levels & bit == 0 || page.visited & bit != 0 {
                continue;
            }
            self.requests[index].visited |= bit;
            for offset in (0..PAGE as usize).step_by(8) {
                self.charge()?;
                let word = u64::from_le_bytes(
                    self.pages[index].bytes[offset..offset + 8].try_into().unwrap(),
                );
                if let PageEntry::Directory { address, next, .. } =
                    decode_page(level, word).map_err(CaptureError::Decode)?
                {
                    self.request(address, 2, next)?;
                }
            }
        }
        Ok(())
    }

    pub fn finish(self) -> Result<TrackedSnapshot<'a>, CaptureError> {
        if self.failed || self.requests[..self.len].iter().any(|page| !page.copied) {
            return Err(CaptureError::Incomplete);
        }
        self.pages[..self.len].sort_unstable_by_key(|page| page.guest);
        TrackedSnapshot::new(&self.pages[..self.len]).map_err(CaptureError::Snapshot)
    }

    fn charge(&mut self) -> Result<(), CaptureError> {
        self.visits += 1;
        if self.visits > MAX_CAPTURE_ENTRY_VISITS { Err(CaptureError::WorkLimit) } else { Ok(()) }
    }
}
