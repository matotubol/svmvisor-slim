//! Offline AMD IOMMU host-command formats; these values are never submitted.
//!
//! The profile contains device-entry invalidation, one 4 KiB host page or an
//! entire domain, standard remote IOTLB invalidation, and completion wait with
//! an explicit numeric store. Guest/PASID, enhanced ATS, interrupt and PPR
//! commands are excluded. Decoding
//! rejects every reserved, unsupported and noncanonical ignored field.
//!
//! This module does not allocate a command buffer, access hardware, wait for a
//! completion, or claim that invalidation, draining or DMA isolation occurred.
//! A completion destination is just a checked number: a future owner must
//! separately constrain it to retained, protected system-memory backing. The
//! caller-supplied AddressPolicy supplies no ownership or platform evidence.
//!
//! Sources (physical pages, text and PNG checked): 48882-3.11 pp123-128;
//! four-level DVA width p82; ordering requirements pp138-139. See README.md.

#![forbid(unsafe_code)]

use crate::memory::address::{AddressError, AddressPolicy, PAGE_BYTES};

const OPCODE_SHIFT: u32 = 60;
const OPCODE_MASK: u64 = 0xf000_0000_0000_0000;
const COMPLETION_WAIT: u64 = 1 << OPCODE_SHIFT;
const INVALIDATE_DEVTAB_ENTRY: u64 = 2 << OPCODE_SHIFT;
const INVALIDATE_IOMMU_PAGES: u64 = 3 << OPCODE_SHIFT;
const INVALIDATE_IOTLB_PAGES: u64 = 4 << OPCODE_SHIFT;
const IOTLB_ROUTE_MASK: u64 = 0x0000_ffff_ff00_ffff;
const ENTIRE_IOTLB: u64 = 0x7fff_ffff_ffff_f001;
const DEVICE_ID_MASK: u64 = 0xffff;
const DOMAIN_ID_SHIFT: u32 = 32;
const DOMAIN_ID_MASK: u64 = 0x0000_ffff_0000_0000;
const PAGE_ADDRESS_MASK: u64 = 0xffff_ffff_ffff_f000;
const PAGE_SIZE: u64 = 1 << 0;
const PAGE_DIRECTORIES: u64 = 1 << 1;
const IO_ADDRESS_BITS: u32 = 48;
// Exact command sentinel from p126, not a system physical or four-level DVA.
const ENTIRE_DOMAIN: u64 = 0x7fff_ffff_ffff_f000 | PAGE_DIRECTORIES | PAGE_SIZE;
const STORE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_fff8;
const STORE: u64 = 1 << 0;
const FLUSH_QUEUE: u64 = 1 << 2;
const STORE_BYTES: u64 = 8;

/// An inert command whose operands fit this restricted numeric profile.
/// Only `words()` serializes it; its Rust layout is not a command-buffer ABI.
/// There is no default, arbitrary-opcode constructor or submission operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostCommand {
    operands: CommandOperands,
}

impl HostCommand {
    /// Encode opcode 02h for one numeric DeviceID, including zero if supplied.
    /// This does not invalidate cached translations for its domain (p125).
    pub const fn invalidate_device_entry(device_id: u16) -> Self {
        Self { operands: CommandOperands::InvalidateDeviceEntry { device_id } }
    }

    /// Encode opcode 03h with S=GN=PASID=0 for an aligned 4 KiB DVA.
    /// This address is an unsigned four-level I/O address, not a system physical
    /// address or x86 canonical address. Its entire page must fit in 48 bits.
    /// The caller must establish that no larger mapping needs invalidation.
    pub fn invalidate_page_4k(
        domain_id: u16,
        io_address: u64,
        directories: PageDirectoryInvalidation,
    ) -> Result<Self, CommandError> {
        validate_io_page(io_address)?;
        Ok(Self {
            operands: CommandOperands::InvalidatePage4k { domain_id, io_address, directories },
        })
    }

    /// Encode the p126 whole-domain form: GN=PASID=0, PDE=S=1 and
    /// Address[63:12]=7_FFFF_FFFF_FFFFh. This sentinel is not a real address.
    /// It does not issue the optional INVALIDATE_IOMMU_ALL opcode.
    pub const fn invalidate_domain(domain_id: u16) -> Self {
        Self { operands: CommandOperands::InvalidateDomain { domain_id } }
    }

    /// Standard ATS invalidation (Type=GN=PASID=0), AMD pp128-130.
    /// QueueID and Maxpend are device-specific numeric fields, NOT discovered
    /// capabilities. The physical owner must establish their values, complete
    /// requester coverage and IotlbSup before submitting this command.
    pub fn invalidate_iotlb_page_4k(
        target: IotlbTarget,
        io_address: u64,
    ) -> Result<Self, CommandError> {
        validate_io_page(io_address)?;
        Ok(Self { operands: CommandOperands::InvalidateIotlbPage4k { target, io_address } })
    }

    /// Invalidate the entire device IOTLB using the exact p130 sentinel.
    /// This does not disable ATS or stop new translation requests. Invalidate
    /// affected IOMMU tables/domains FIRST, and observe a subsequent matching
    /// completion. Reset or timeout must fail the enclosing ownership protocol.
    pub const fn invalidate_iotlb_all(target: IotlbTarget) -> Self {
        Self { operands: CommandOperands::InvalidateIotlbAll { target } }
    }

    /// Encode opcode 01h with s=1, i=0 and an explicit f choice (pp124-125).
    /// Validate all eight destination bytes, their alignment, physical width
    /// and encryption-bit exclusion. No memory is read or written. Numeric
    /// address zero and any u64 data are allowed; neither identifies protected
    /// system memory or proves that a command has completed.
    pub fn completion_wait(
        policy: AddressPolicy,
        store_address: u64,
        store_data: u64,
        ordering: CompletionOrdering,
    ) -> Result<Self, CommandError> {
        policy
            .validate(store_address, STORE_BYTES, STORE_BYTES)
            .map_err(CommandError::StoreAddress)?;
        Ok(Self {
            operands: CommandOperands::CompletionWait { store_address, store_data, ordering },
        })
    }

    /// Decode exactly two 64-bit words, with bits 63:0 first. This accepts only
    /// this module's profile, not arbitrary commands from another owner. The
    /// supplied policy is reapplied to completion stores; DVA operands do not
    /// use physical-width or encryption-bit policy. No bits are normalized away.
    pub fn decode(policy: AddressPolicy, words: [u64; 2]) -> Result<Self, CommandError> {
        match words[0] & OPCODE_MASK {
            INVALIDATE_DEVTAB_ENTRY => {
                validate_bits(words, [OPCODE_MASK | DEVICE_ID_MASK, 0])?;
                Ok(Self::invalidate_device_entry((words[0] & DEVICE_ID_MASK) as u16))
            }
            INVALIDATE_IOMMU_PAGES => {
                validate_bits(
                    words,
                    [
                        OPCODE_MASK | DOMAIN_ID_MASK,
                        PAGE_ADDRESS_MASK | PAGE_DIRECTORIES | PAGE_SIZE,
                    ],
                )?;
                let domain_id = ((words[0] & DOMAIN_ID_MASK) >> DOMAIN_ID_SHIFT) as u16;
                if words[1] & PAGE_SIZE != 0 {
                    if words[1] != ENTIRE_DOMAIN {
                        return Err(CommandError::UnsupportedPageRange);
                    }
                    return Ok(Self::invalidate_domain(domain_id));
                }
                let directories = if words[1] & PAGE_DIRECTORIES == 0 {
                    PageDirectoryInvalidation::TranslationsOnly
                } else {
                    PageDirectoryInvalidation::IncludeDirectories
                };
                Self::invalidate_page_4k(domain_id, words[1] & PAGE_ADDRESS_MASK, directories)
            }
            INVALIDATE_IOTLB_PAGES => {
                validate_bits(
                    words,
                    [OPCODE_MASK | IOTLB_ROUTE_MASK, PAGE_ADDRESS_MASK | PAGE_SIZE],
                )?;
                let target = IotlbTarget {
                    device_id: words[0] as u16,
                    queue_id: (words[0] >> 32) as u16,
                    max_pending: (words[0] >> 24) as u8,
                };
                if words[1] & PAGE_SIZE != 0 {
                    if words[1] != ENTIRE_IOTLB {
                        return Err(CommandError::UnsupportedPageRange);
                    }
                    Ok(Self::invalidate_iotlb_all(target))
                } else {
                    Self::invalidate_iotlb_page_4k(target, words[1])
                }
            }
            COMPLETION_WAIT => {
                validate_bits(
                    words,
                    [OPCODE_MASK | STORE_ADDRESS_MASK | FLUSH_QUEUE | STORE, u64::MAX],
                )?;
                if words[0] & STORE == 0 {
                    return Err(CommandError::CompletionStoreDisabled);
                }
                let ordering = if words[0] & FLUSH_QUEUE == 0 {
                    CompletionOrdering::AllowIndependentSubsequent
                } else {
                    CompletionOrdering::WaitBeforeSubsequent
                };
                Self::completion_wait(policy, words[0] & STORE_ADDRESS_MASK, words[1], ordering)
            }
            _ => Err(CommandError::UnsupportedOpcode((words[0] >> OPCODE_SHIFT) as u8)),
        }
    }

    /// Typed numeric operands, with no runtime authority or completion state.
    pub const fn operands(self) -> CommandOperands {
        self.operands
    }

    /// Command bits 63:0 followed by 127:64 (Figure 43, p123). Each word has
    /// little-endian byte order if serialized. Returning them performs no store
    /// to a command buffer and says nothing about hardware consumption.
    pub const fn words(self) -> [u64; 2] {
        match self.operands {
            CommandOperands::InvalidateDeviceEntry { device_id } => {
                [INVALIDATE_DEVTAB_ENTRY | device_id as u64, 0]
            }
            CommandOperands::InvalidatePage4k { domain_id, io_address, directories } => {
                let pde = match directories {
                    PageDirectoryInvalidation::TranslationsOnly => 0,
                    PageDirectoryInvalidation::IncludeDirectories => PAGE_DIRECTORIES,
                };
                [INVALIDATE_IOMMU_PAGES | ((domain_id as u64) << DOMAIN_ID_SHIFT), io_address | pde]
            }
            CommandOperands::InvalidateDomain { domain_id } => {
                [INVALIDATE_IOMMU_PAGES | ((domain_id as u64) << DOMAIN_ID_SHIFT), ENTIRE_DOMAIN]
            }
            CommandOperands::InvalidateIotlbPage4k { target, io_address } => {
                [INVALIDATE_IOTLB_PAGES | target.bits(), io_address]
            }
            CommandOperands::InvalidateIotlbAll { target } => {
                [INVALIDATE_IOTLB_PAGES | target.bits(), ENTIRE_IOTLB]
            }
            CommandOperands::CompletionWait { store_address, store_data, ordering } => {
                let flush = match ordering {
                    CompletionOrdering::AllowIndependentSubsequent => 0,
                    CompletionOrdering::WaitBeforeSubsequent => FLUSH_QUEUE,
                };
                [COMPLETION_WAIT | store_address | flush | STORE, store_data]
            }
        }
    }
}

/// Operand view only. Constructing this enum does not construct a HostCommand;
/// only the named HostCommand constructors validate and serialize operands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandOperands {
    InvalidateDeviceEntry { device_id: u16 },
    InvalidatePage4k { domain_id: u16, io_address: u64, directories: PageDirectoryInvalidation },
    InvalidateDomain { domain_id: u16 },
    InvalidateIotlbPage4k { target: IotlbTarget, io_address: u64 },
    InvalidateIotlbAll { target: IotlbTarget },
    CompletionWait { store_address: u64, store_data: u64, ordering: CompletionOrdering },
}

/// Literal fields from AMD Table 37, not physical requester admission. In
/// particular, functions sharing a peripheral invalidation queue must use the
/// same QueueID; using each function's DeviceID by default is not sufficient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IotlbTarget {
    pub device_id: u16,
    pub queue_id: u16,
    pub max_pending: u8,
}

impl IotlbTarget {
    const fn bits(self) -> u64 {
        self.device_id as u64 | ((self.max_pending as u64) << 24) | ((self.queue_id as u64) << 32)
    }
}

/// Opcode 03h PDE field (p127). A 4 KiB range does not ensure invalidation of a
/// directory entry covering a larger range; whole-domain invalidation sets PDE=1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageDirectoryInvalidation {
    TranslationsOnly,
    IncludeDirectories,
}

/// Opcode 01h f field (p124), not a software fence or observed drain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionOrdering {
    /// f=0: subsequent independent commands may begin before completion.
    AllowIndependentSubsequent,
    /// f=1: subsequent commands wait until this command finishes.
    WaitBeforeSubsequent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandError {
    StoreAddress(AddressError),
    IoAddressOverflow,
    IoAddressMisaligned,
    IoAddressOutsideWidth,
    UnsupportedOpcode(u8),
    /// A reserved, unsupported or canonicalized-away field is nonzero.
    /// `word` is its zero-based 64-bit word index.
    UnsupportedBits {
        word: u8,
        bits: u64,
    },
    /// S=1 accepts only the exact whole-domain address with PDE=1.
    UnsupportedPageRange,
    /// Interrupt-only and unobservable no-store forms are outside this profile.
    CompletionStoreDisabled,
}

fn validate_io_page(io_address: u64) -> Result<(), CommandError> {
    let last =
        io_address.checked_add(PAGE_BYTES as u64 - 1).ok_or(CommandError::IoAddressOverflow)?;
    if io_address & (PAGE_BYTES as u64 - 1) != 0 {
        return Err(CommandError::IoAddressMisaligned);
    }
    if last >> IO_ADDRESS_BITS != 0 {
        return Err(CommandError::IoAddressOutsideWidth);
    }
    Ok(())
}

fn validate_bits(words: [u64; 2], allowed: [u64; 2]) -> Result<(), CommandError> {
    for (index, (word, mask)) in words.into_iter().zip(allowed).enumerate() {
        let bits = word & !mask;
        if bits != 0 {
            return Err(CommandError::UnsupportedBits { word: index as u8, bits });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
