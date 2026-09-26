//! Bounded current-boot validation from observed roots and exact profiled syscall anchors.
//!
//! Observations are candidates, including a caller root when it maps the full kernel. Success
//! relates sampled kernel identity and process metadata; it does not pin pages or prove lifetime.

use std::fmt;

use svmvisor_hypervisor::{
    memory::address::{PAGE_BYTES, is_canonical_48},
    reader::{
        paging::{PagingConfig, PagingError},
        process::{self, ProcessError, ProcessRequest},
        read::{self, ReadError},
    },
};

use crate::profile::KernelProfile;

const MAX_CANDIDATES: usize = 4;
const MAX_ANCHORS: usize = 4;
const MAX_PHYSICAL_READS: usize = 120_000;
const MAX_PE_OFFSET: u32 = 4096;
const OPTIONAL_BYTES: usize = 240;
const MAX_DEBUG_ENTRIES: u32 = 64;
const MAX_CODEVIEW_BYTES: u32 = 1024;

/// A sampled root is untrusted until it maps the independently verified kernel and System.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ContextObservation {
    pub config: PagingConfig,
    pub kernel_root_pa: u64,
    pub syscall_target_va: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ValidatedContext {
    config: PagingConfig,
    kernel_root_pa: u64,
    list_head_va: u64,
    kernel_base_va: u64,
}

impl ValidatedContext {
    pub(crate) fn config(self) -> PagingConfig {
        self.config
    }

    pub(crate) fn kernel_root_pa(self) -> u64 {
        self.kernel_root_pa
    }

    pub(crate) fn list_head_va(self) -> u64 {
        self.list_head_va
    }

    pub(crate) fn kernel_base_va(self) -> u64 {
        self.kernel_base_va
    }
}

/// Normalize the runtime's register observation into a candidate root and syscall target.
pub(crate) fn candidate(
    observation: svmvisor_card_abi::context::ContextObservation,
) -> Result<ContextObservation, String> {
    let config = PagingConfig::new(
        observation.physical_bits,
        observation.efer & (1 << 11) != 0,
        observation.page1gb,
    )
    .map_err(|_| "unsupported context physical width")?;
    if observation.cr4 & (1 << 5) == 0
        || observation.cr4 & ((1 << 12) | (1 << 22)) != 0
        || observation.efer & 0x500 != 0x500
    {
        return Err("unsupported context paging mode".into());
    }
    let physical_mask = (1u64 << observation.physical_bits) - 1;
    let address_mask = physical_mask & !0xfff;
    let low_mask = if observation.cr4 & (1 << 17) != 0 { 0xfff } else { 0x18 };
    if observation.cr3 & !(address_mask | low_mask) != 0 {
        return Err("context CR3 contains unsupported bits".into());
    }
    let root = observation.cr3 & address_mask;
    if root == 0 || observation.lstar < 0xffff_8000_0000_0000 || !is_canonical_48(observation.lstar)
    {
        return Err("context root or syscall target is invalid".into());
    }
    Ok(ContextObservation { config, kernel_root_pa: root, syscall_target_va: observation.lstar })
}

struct ContextReader<'a, F> {
    config: PagingConfig,
    root: u64,
    read: &'a mut F,
}

impl<F: FnMut(u64, &mut [u8]) -> Result<(), PagingError>> ContextReader<'_, F> {
    fn exact(&mut self, address: u64, output: &mut [u8]) -> Result<(), ContextError> {
        let report = read::read_virtual(self.config, self.root, address, output, self.read);
        if let Some(error) = report.error {
            return Err(ContextError::Read(error));
        }
        if report.bytes_read != output.len() {
            return Err(ContextError::Invalid("incomplete virtual read"));
        }
        Ok(())
    }

    fn word(&mut self, address: u64) -> Result<u64, ContextError> {
        let mut bytes = [0; 8];
        self.exact(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn identity(
        &mut self,
        base: u64,
        anchor: u32,
        profile: &KernelProfile,
    ) -> Result<(), ContextError> {
        let expected = profile.identity();
        let mut dos = [0; 64];
        self.exact(base, &mut dos)?;
        let offset = word32(&dos, 60);
        if dos[..2] != *b"MZ" || !(64..=MAX_PE_OFFSET).contains(&offset) {
            return Err(ContextError::Invalid("invalid mapped DOS header"));
        }
        let mut nt = [0; 24 + OPTIONAL_BYTES];
        self.exact(image_address(base, offset, nt.len(), expected.image_bytes)?, &mut nt)?;
        let optional = &nt[24..];
        let headers_bytes = word32(optional, 60);
        let section_end = u64::from(offset) + nt.len() as u64 + u64::from(word16(&nt, 6)) * 40;
        if nt[..4] != *b"PE\0\0"
            || word16(&nt, 4) != expected.machine
            || !(1..=96).contains(&word16(&nt, 6))
            || word32(&nt, 8) != expected.timestamp
            || usize::from(word16(&nt, 20)) != OPTIONAL_BYTES
            || word16(optional, 0) != 0x020b
            || word32(optional, 56) != expected.image_bytes
            || word32(optional, 64) != expected.checksum
            || word32(optional, 108) != 16
            || headers_bytes > expected.image_bytes
            || section_end > u64::from(headers_bytes)
        {
            return Err(ContextError::Invalid("mapped PE identity mismatch"));
        }
        let section_address = base + u64::from(offset) + nt.len() as u64;
        let mut anchor_section = false;
        for index in 0..word16(&nt, 6) {
            let mut section = [0; 40];
            self.exact(section_address + u64::from(index) * 40, &mut section)?;
            let size = word32(&section, 8);
            let rva = word32(&section, 12);
            let end = u64::from(rva) + u64::from(size);
            if end > u64::from(expected.image_bytes) || (size != 0 && rva < headers_bytes) {
                return Err(ContextError::Invalid("mapped section exceeds image extent"));
            }
            if anchor >= rva && u64::from(anchor) < end {
                if anchor_section || word32(&section, 36) & 0x2000_0000 == 0 {
                    return Err(ContextError::Invalid("syscall anchor is not uniquely executable"));
                }
                anchor_section = true;
            }
        }
        if !anchor_section {
            return Err(ContextError::Invalid(
                "syscall anchor is outside mapped executable sections",
            ));
        }
        let debug_rva = word32(optional, 160);
        let debug_bytes = word32(optional, 164);
        if debug_bytes == 0 || debug_bytes % 28 != 0 || debug_bytes / 28 > MAX_DEBUG_ENTRIES {
            return Err(ContextError::Invalid("invalid mapped debug directory size"));
        }
        let debug_address =
            image_address(base, debug_rva, debug_bytes as usize, expected.image_bytes)?;
        let mut found = false;
        for index in 0..debug_bytes / 28 {
            let mut entry = [0; 28];
            self.exact(debug_address + u64::from(index) * 28, &mut entry)?;
            if word32(&entry, 12) != 2 {
                continue;
            }
            let length = word32(&entry, 16);
            if found || !(25..=MAX_CODEVIEW_BYTES).contains(&length) {
                return Err(ContextError::Invalid("ambiguous or invalid mapped CodeView record"));
            }
            let address =
                image_address(base, word32(&entry, 20), length as usize, expected.image_bytes)?;
            let mut record = [0; MAX_CODEVIEW_BYTES as usize];
            self.exact(address, &mut record[..length as usize])?;
            if record[..4] != *b"RSDS"
                || record[4..20] != expected.codeview_guid
                || word32(&record, 20) != expected.codeview_age
                || !record[24..length as usize].contains(&0)
            {
                return Err(ContextError::Invalid("mapped kernel CodeView identity mismatch"));
            }
            found = true;
        }
        if !found {
            return Err(ContextError::Invalid("mapped kernel has no CodeView identity"));
        }
        Ok(())
    }
}

#[derive(Debug)]
enum ContextError {
    Invalid(&'static str),
    Read(ReadError),
    Process(&'static str, ProcessError),
}

impl ContextError {
    fn backend_failed(&self) -> bool {
        matches!(
            self,
            Self::Read(ReadError::Paging(PagingError::PhysicalRead))
                | Self::Process(
                    _,
                    ProcessError::Read(ReadError::Paging(PagingError::PhysicalRead))
                )
        )
    }
}

impl fmt::Display for ContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Read(error) => write!(formatter, "kernel read failed: {error:?}"),
            Self::Process(stage, error) => write!(formatter, "System {stage} failed: {error:?}"),
        }
    }
}

/// Try only observed roots and exact profiled entry RVAs, with one shared physical-read budget.
/// A physical callback failure ends discovery immediately; it is never retried with another root.
pub(crate) fn discover(
    profile: &KernelProfile,
    candidates: &[ContextObservation],
    max_nodes: usize,
    read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), PagingError>,
) -> Result<ValidatedContext, String> {
    if candidates.is_empty()
        || candidates.len() > MAX_CANDIDATES
        || profile.syscall_rvas().is_empty()
        || profile.syscall_rvas().len() > MAX_ANCHORS
        || max_nodes == 0
        || max_nodes > process::MAX_PROCESS_NODES
    {
        return Err("invalid bounded context discovery inputs".into());
    }
    let mut calls = 0;
    let mut last_error = String::from("no aligned kernel base from profiled syscall anchors");
    for candidate in candidates {
        for &anchor in profile.syscall_rvas() {
            let calls_before = calls;
            let mut bounded = |address, output: &mut [u8]| {
                if calls >= MAX_PHYSICAL_READS {
                    return Err(PagingError::PhysicalRead);
                }
                calls += 1;
                read(address, output)
            };
            match validate(profile, *candidate, anchor, max_nodes, &mut bounded) {
                Ok(context) => return Ok(context),
                Err(error) if error.backend_failed() => {
                    return Err(format!(
                        "context discovery stopped after {calls} physical reads: {error}"
                    ));
                }
                Err(error) => {
                    if calls > calls_before || calls == 0 {
                        last_error = error.to_string();
                    }
                }
            }
        }
    }
    Err(format!("no validated current-boot kernel context: {last_error}"))
}

fn validate(
    profile: &KernelProfile,
    candidate: ContextObservation,
    anchor: u32,
    max_nodes: usize,
    read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), PagingError>,
) -> Result<ValidatedContext, ContextError> {
    let image_bytes = profile.identity().image_bytes;
    let base = candidate
        .syscall_target_va
        .checked_sub(u64::from(anchor))
        .ok_or(ContextError::Invalid("syscall anchor underflow"))?;
    if anchor >= image_bytes
        || base & (PAGE_BYTES as u64 - 1) != 0
        || !kernel_pointer(base, u64::from(image_bytes))
        || !valid_root(candidate.config, candidate.kernel_root_pa)
    {
        return Err(ContextError::Invalid("invalid candidate root or kernel extent"));
    }
    let head = image_address(base, profile.list_head_rva(), 16, image_bytes)?;
    let system_address = image_address(base, profile.system_process_rva(), 8, image_bytes)?;
    if head & 7 != 0 || system_address & 7 != 0 {
        return Err(ContextError::Invalid("unaligned kernel globals"));
    }
    let mut image =
        ContextReader { config: candidate.config, root: candidate.kernel_root_pa, read };
    image.identity(base, anchor, profile)?;
    let system = image.word(system_address)?;
    if !kernel_pointer(system, u64::from(profile.process().layout().eprocess_bytes))
        || system & 7 != 0
    {
        return Err(ContextError::Invalid("invalid initial System process pointer"));
    }
    let mut sentinel = [0; 16];
    image.exact(head, &mut sentinel)?;
    let request = ProcessRequest {
        kernel_root_pa: candidate.kernel_root_pa,
        list_head_va: head,
        pid: 4,
        max_nodes,
    };
    let observed = process::find(candidate.config, profile.process(), request, image.read)
        .map_err(|error| ContextError::Process("list traversal", error))?
        .ok_or(ContextError::Invalid("System PID absent from process sentinel"))?;
    if observed.eprocess_va != system || !valid_root(candidate.config, observed.kernel_root_pa) {
        return Err(ContextError::Invalid("initial System and process list disagree"));
    }
    process::revalidate(
        candidate.config,
        profile.process(),
        candidate.kernel_root_pa,
        observed,
        image.read,
    )
    .map_err(|error| ContextError::Process("candidate-root revalidation", error))?;

    // Rewalk all required kernel evidence through the observed System root. Neither a plausible
    // EPROCESS field nor a root which maps only the syscall shadow establishes the final context.
    image.root = observed.kernel_root_pa;
    image.identity(base, anchor, profile)?;
    if image.word(system_address)? != system {
        return Err(ContextError::Invalid("initial System pointer changed across roots"));
    }
    let mut repeated_sentinel = [0; 16];
    image.exact(head, &mut repeated_sentinel)?;
    if repeated_sentinel != sentinel {
        return Err(ContextError::Invalid("process sentinel changed across validation"));
    }
    process::revalidate(
        candidate.config,
        profile.process(),
        observed.kernel_root_pa,
        observed,
        image.read,
    )
    .map_err(|error| ContextError::Process("System-root revalidation", error))?;
    Ok(ValidatedContext {
        config: candidate.config,
        kernel_root_pa: observed.kernel_root_pa,
        list_head_va: head,
        kernel_base_va: base,
    })
}

fn image_address(
    base: u64,
    rva: u32,
    length: usize,
    image_bytes: u32,
) -> Result<u64, ContextError> {
    if length == 0
        || u64::from(rva).checked_add(length as u64).is_none_or(|end| end > u64::from(image_bytes))
    {
        return Err(ContextError::Invalid("mapped image range outside verified image extent"));
    }
    base.checked_add(u64::from(rva)).ok_or(ContextError::Invalid("mapped image address overflow"))
}

fn valid_root(config: PagingConfig, root: u64) -> bool {
    root != 0 && root & (PAGE_BYTES as u64 - 1) == 0 && root >> config.physical_bits() == 0
}

fn kernel_pointer(address: u64, length: u64) -> bool {
    length != 0
        && address >> 48 == 0xffff
        && is_canonical_48(address)
        && address.checked_add(length - 1).is_some_and(is_canonical_48)
}

fn word16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn word32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

#[cfg(test)]
mod tests;
