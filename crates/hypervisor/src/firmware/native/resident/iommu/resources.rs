//! Retained, disconnected hardware banks and composed mapping generations.
//! A bank is not a unit inventory,
//! a Windows device policy, DMA integrity evidence, or an ownership token.
//! Preparation selects no unit and performs no MMIO, submission or enablement.
//! Header publication describes initialized memory only; takeover must revalidate
//! actual contents and acquire all hardware/control paths independently.
//!
//! Layout: 48882-3.11 physical pp214-216 (text and PNG checked). Device tables
//! need 4KiB alignment; 512 pages cover every 16-bit DeviceID. Minimum command
//! and event buffers contain 256 16-byte entries, with ComLen/EventLen=8.
#![forbid(unsafe_code)]

use crate::{
    host::resident::{IOMMU_COMPOSITION_BYTES, IOMMU_RESOURCE_BYTES},
    memory::{
        address::{AddressError, AddressPolicy},
        iommu::{
            device_table::{self, DeviceTablePage},
            image::{self, ProtectedRange, TablePage},
            queue::{CommandBuffer, CommandPage, CompletionPage},
            tables::{CompleteHostDeviceEntry, DteInterruptPolicy, HostDeviceEntry, Permissions},
        },
    },
};

pub const DEVICE_TABLE_OFFSET: u64 = 0x1000;
pub const ROOT_OFFSET: u64 = 0x201000;
pub const COMMAND_OFFSET: u64 = 0x202000;
pub const EVENT_OFFSET: u64 = 0x203000;
pub const COMPLETION_OFFSET: u64 = 0x204000;
const PADDING_OFFSET: u64 = 0x205000;
const MAGIC: u64 = u64::from_le_bytes(*b"IOUNINST");
const VERSION: u64 = 1;

pub const COMPOSITION_TABLE_OFFSET: u64 = 0x200000;
pub const COMPOSITION_TABLE_PAGES: usize = 256;

/// One native publication destination. Raw integer pages deliberately permit
/// building/validating a mixed-page cold image without borrowing live hardware
/// memory as Rust references. All mutable/immutable borrows must end before
/// publication. Both generations remain retained on every success/error path.
///
/// This storage supplies capacity, not a ready image or DMA authority. A 4KiB
/// only mapper cannot cover ordinary machine RAM within 256 pages; every mapper
/// must check its exact required capacity before publication.
#[repr(C, align(4096))]
pub struct CompositionStorage {
    device_table: [[u64; 512]; device_table::TABLE_PAGES],
    tables: [[u64; 512]; COMPOSITION_TABLE_PAGES],
}

impl CompositionStorage {
    pub const fn device_table(&self) -> &[[u64; 512]; device_table::TABLE_PAGES] {
        &self.device_table
    }

    pub fn device_table_mut(&mut self) -> &mut [[u64; 512]; device_table::TABLE_PAGES] {
        &mut self.device_table
    }

    pub const fn tables(&self) -> &[[u64; 512]; COMPOSITION_TABLE_PAGES] {
        &self.tables
    }

    pub fn tables_mut(&mut self) -> &mut [[u64; 512]; COMPOSITION_TABLE_PAGES] {
        &mut self.tables
    }

    /// Only disconnected, exclusively borrowed backing may be cleared.
    pub fn clear(&mut self) {
        for page in self.device_table.iter_mut().chain(self.tables.iter_mut()) {
            page.fill(0);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.device_table.iter().chain(self.tables.iter()).flatten().all(|word| *word == 0)
    }
}

const _: () = {
    assert!(core::mem::size_of::<CompositionStorage>() as u64 == IOMMU_COMPOSITION_BYTES);
    assert!(core::mem::offset_of!(CompositionStorage, device_table) == 0);
    assert!(core::mem::offset_of!(CompositionStorage, tables) as u64 == COMPOSITION_TABLE_OFFSET);
};

/// Integer-only cross-image metadata. These values must equal the independently
/// derived layout; never follow addresses supplied by an unvalidated header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ResourceHeader {
    magic: u64,
    version: u64,
    bytes: u64,
    base: u64,
    device_table: u64,
    translation_root: u64,
    command_buffer: u64,
    event_log: u64,
    completion: u64,
    reserved: [u64; 7],
}

impl ResourceHeader {
    const EMPTY: Self = Self {
        magic: 0,
        version: 0,
        bytes: 0,
        base: 0,
        device_table: 0,
        translation_root: 0,
        command_buffer: 0,
        event_log: 0,
        completion: 0,
        reserved: [0; 7],
    };

    pub fn validate(self, policy: AddressPolicy, base: u64) -> Result<(), ResourceError> {
        let expected = Self::expected(policy, base)?;
        if self != expected {
            return Err(ResourceError::Header);
        }
        Ok(())
    }

    fn expected(policy: AddressPolicy, base: u64) -> Result<Self, ResourceError> {
        policy.validate(base, IOMMU_RESOURCE_BYTES, 4096).map_err(ResourceError::Address)?;
        Ok(Self {
            magic: MAGIC,
            version: VERSION,
            bytes: IOMMU_RESOURCE_BYTES,
            base,
            device_table: (base + DEVICE_TABLE_OFFSET) | 0x1ff,
            translation_root: base + ROOT_OFFSET,
            command_buffer: (base + COMMAND_OFFSET) | (8 << 56),
            event_log: (base + EVENT_OFFSET) | (8 << 56),
            completion: base + COMPLETION_OFFSET,
            reserved: [0; 7],
        })
    }
}

/// All fields contain only raw integer words; every bit pattern is valid Rust.
/// The native adapter initializes in place after complete RW/WB admission. Never
/// construct this multi-MiB object on the firmware stack or use it while hardware
/// can access it. Native instances remain in distinct slots in the retained pool.
#[repr(C, align(4096))]
pub struct ResourceStorage {
    header: ResourceHeader,
    header_padding: [u64; (4096 - core::mem::size_of::<ResourceHeader>()) / 8],
    device_table: [DeviceTablePage; device_table::TABLE_PAGES],
    root: TablePage,
    commands: [CommandPage; 1],
    event: [u64; 512],
    completion: CompletionPage,
    padding: [u64; (IOMMU_RESOURCE_BYTES - PADDING_OFFSET) as usize / 8],
}

const _: () = {
    assert!(core::mem::size_of::<ResourceHeader>() == 128);
    assert!(core::mem::align_of::<ResourceHeader>() == 8);
    assert!(core::mem::size_of::<ResourceStorage>() as u64 == IOMMU_RESOURCE_BYTES);
    assert!(core::mem::offset_of!(ResourceStorage, header) == 0);
    assert!(core::mem::offset_of!(ResourceStorage, device_table) as u64 == DEVICE_TABLE_OFFSET);
    assert!(core::mem::offset_of!(ResourceStorage, root) as u64 == ROOT_OFFSET);
    assert!(core::mem::offset_of!(ResourceStorage, commands) as u64 == COMMAND_OFFSET);
    assert!(core::mem::offset_of!(ResourceStorage, event) as u64 == EVENT_OFFSET);
    assert!(core::mem::offset_of!(ResourceStorage, completion) as u64 == COMPLETION_OFFSET);
    assert!(core::mem::offset_of!(ResourceStorage, padding) as u64 == PADDING_OFFSET);
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceError {
    Address(AddressError),
    Header,
    AlreadyPrepared,
    Build,
    Contents,
}

impl ResourceStorage {
    pub fn header(&self) -> ResourceHeader {
        self.header
    }

    /// Check the nonmutating admission conditions for disconnected preparation.
    /// A multi-bank caller can reject all header/address errors before touching
    /// any bank. This provides no hardware ownership or DMA-integrity evidence.
    pub fn preflight_prepare(&self, policy: AddressPolicy, base: u64) -> Result<(), ResourceError> {
        ResourceHeader::expected(policy, base)?;
        if self.header != ResourceHeader::EMPTY {
            return Err(ResourceError::AlreadyPrepared);
        }
        Ok(())
    }

    /// Prepare exclusive, disconnected backing once. Numeric preflight errors
    /// leave it unchanged; later failures leave the publication header empty.
    /// No references to scratch, firmware tables, or this mutable borrow escape.
    pub fn prepare(&mut self, policy: AddressPolicy, base: u64) -> Result<(), ResourceError> {
        self.preflight_prepare(policy, base)?;
        let header = ResourceHeader::expected(policy, base)?;
        let root = image::build(
            policy,
            header.translation_root,
            core::slice::from_mut(&mut self.root),
            &[],
            &[ProtectedRange { base, len: IOMMU_RESOURCE_BYTES }],
        )
        .map_err(|_| ResourceError::Build)?;
        let translation = HostDeviceEntry::new(policy, root.root_address(), 0, Permissions::None)
            .map_err(|_| ResourceError::Build)?;
        let default =
            CompleteHostDeviceEntry::new(policy, translation, DteInterruptPolicy::AbortControlled)
                .map_err(|_| ResourceError::Build)?;
        let table = device_table::build(
            policy,
            base + DEVICE_TABLE_OFFSET,
            &mut self.device_table,
            default,
            &[],
        )
        .map_err(|_| ResourceError::Build)?;
        if table.base_register_value() != header.device_table {
            return Err(ResourceError::Build);
        }
        self.header_padding.fill(0);
        self.event.fill(0);
        self.padding.fill(0);
        // Command/completion initialization is supplied by the bounded offline
        // producer. Its borrow ends here; no queue writer is retained.
        self.prepare_queue(policy, base)?;
        self.verify_contents(header)?;
        self.header = header;
        Ok(())
    }

    /// Bounded raw-word verification for disconnected memory. This detects local
    /// corruption only; it supplies no authenticity, freshness or device drain.
    pub fn verify(&self, policy: AddressPolicy, base: u64) -> Result<(), ResourceError> {
        self.header.validate(policy, base)?;
        self.verify_contents(self.header)
    }

    fn verify_contents(&self, header: ResourceHeader) -> Result<(), ResourceError> {
        // Independent expected words: V=TV=1, Mode=4, no IR/IW, DomainID0,
        // IV=1 with controlled aborts and no interrupt passthrough.
        let expected = [header.translation_root | 0x803, 0, 1, 0];
        if self
            .device_table
            .iter()
            .any(|page| page.words().chunks_exact(4).any(|words| words != expected))
            || self.root.words().iter().any(|word| *word != 0)
            || self
                .header_padding
                .iter()
                .chain(self.event.iter())
                .chain(self.padding.iter())
                .any(|word| *word != 0)
            || !self.queue_is_empty()
        {
            return Err(ResourceError::Contents);
        }
        Ok(())
    }

    fn prepare_queue(&mut self, policy: AddressPolicy, base: u64) -> Result<(), ResourceError> {
        let extent =
            policy.validate(base, IOMMU_RESOURCE_BYTES, 4096).map_err(ResourceError::Address)?;
        let queue = CommandBuffer::prepare(
            policy,
            extent,
            base + COMMAND_OFFSET,
            &mut self.commands,
            base + COMPLETION_OFFSET,
            &mut self.completion,
        )
        .map_err(|_| ResourceError::Build)?;
        // Construction checks geometry and initializes both pages; no commands
        // or completion markers are enqueued and no tail is published.
        drop(queue);
        Ok(())
    }

    fn queue_is_empty(&self) -> bool {
        self.commands.iter().all(|page| page.bytes().iter().all(|byte| *byte == 0))
            && self.completion.values().iter().all(|word| *word == 0)
    }
}
