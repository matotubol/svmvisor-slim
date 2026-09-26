//! Bounded process-list inspection of supplied Windows memory images.
//! Layout evidence and the list head must come from the caller's verified image profile.
//! This module supplies no Windows offsets and cannot establish list authenticity.

use crate::memory::address::{PAGE_BYTES, is_canonical_48};

use super::{
    paging::PagingConfig,
    read::{self, ReadError, VirtualRead},
};

pub const MAX_PROCESS_NODES: usize = 4096;
pub const MAX_EPROCESS_BYTES: u32 = 16 * PAGE_BYTES as u32;
const WORD_BYTES: u32 = size_of::<u64>() as u32;
const LINK_BYTES: u32 = 2 * WORD_BYTES;
const MAX_FIELD_BYTES: u32 = 64;

/// Structurally checked offsets; construction does not verify their Windows build provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessProfile {
    layout: ProcessLayoutEvidence,
}

impl ProcessProfile {
    pub fn new(layout: ProcessLayoutEvidence) -> Result<Self, ProcessError> {
        if layout.eprocess_bytes == 0
            || layout.eprocess_bytes > MAX_EPROCESS_BYTES
            || layout.eprocess_bytes % WORD_BYTES != 0
            || u64::from(layout.dtb_low_bits_mask) & !(PAGE_BYTES as u64 - 1) != 0
        {
            return Err(ProcessError::InvalidProfile);
        }
        let fields = [
            (layout.active_links_offset, LINK_BYTES),
            (layout.pid_offset, WORD_BYTES),
            (layout.directory_root_offset, WORD_BYTES),
            (
                layout.create_time_offset.unwrap_or(0),
                if layout.create_time_offset.is_some() { WORD_BYTES } else { 0 },
            ),
        ];
        for (index, &(offset, length)) in fields.iter().enumerate() {
            if length == 0 {
                continue;
            }
            if offset % WORD_BYTES != 0
                || offset.checked_add(length).is_none_or(|end| end > layout.eprocess_bytes)
            {
                return Err(ProcessError::InvalidProfile);
            }
            for &(other_offset, other_length) in &fields[..index] {
                if other_length != 0
                    && offset < other_offset + other_length
                    && other_offset < offset + length
                {
                    return Err(ProcessError::OverlappingFields);
                }
            }
        }
        Ok(Self { layout })
    }

    pub const fn layout(self) -> ProcessLayoutEvidence {
        self.layout
    }

    /// Worst-case physical callbacks for one revalidation, including four-level walks.
    /// Neighbor words are aligned and each fits a page. No translation is cached.
    pub(crate) fn revalidation_calls(self, object: u64) -> Option<usize> {
        let layout = self.layout;
        let pages = |offset: u32, length: u32| {
            let start = object.checked_add(u64::from(offset))?;
            let end = start.checked_add(u64::from(length) - 1)?;
            Some((end / PAGE_BYTES as u64 - start / PAGE_BYTES as u64 + 1) as usize)
        };
        validate_pointer(object, layout.eprocess_bytes).ok()?;
        let range = identity_range(layout);
        let mut count = match range {
            Some((start, end)) => pages(start, end - start)?,
            None => {
                pages(layout.active_links_offset, LINK_BYTES)?
                    + pages(layout.pid_offset, WORD_BYTES)?
            }
        };
        if let Some(offset) = layout.create_time_offset {
            if range.is_none_or(|(start, end)| offset < start || offset + WORD_BYTES > end) {
                count += pages(offset, WORD_BYTES)?;
            }
        }
        count += pages(layout.directory_root_offset, WORD_BYTES)? + 2;
        Some(count * 5)
    }
}

/// Caller-supplied, independently verified x64 EPROCESS field locations.
/// All scalar fields are eight-byte little-endian values; active links are Flink then Blink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessLayoutEvidence {
    pub eprocess_bytes: u32,
    pub active_links_offset: u32,
    pub pid_offset: u32,
    pub create_time_offset: Option<u32>,
    /// Absolute offset from EPROCESS, including any embedded KPROCESS displacement.
    pub directory_root_offset: u32,
    /// Only these low DTB bits may be set and stripped. Zero requires an aligned stored root.
    /// The mask must fit bits 11:0; no high metadata or encryption bits are stripped.
    pub dtb_low_bits_mask: u16,
}

/// Explicit lookup inputs; the head is the sentinel LIST_ENTRY itself, not a pointer variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessRequest {
    /// Root used to translate the supplied kernel list and EPROCESS fields.
    pub kernel_root_pa: u64,
    pub list_head_va: u64,
    pub pid: u64,
    pub max_nodes: usize,
}

/// Observed image values, not a live process handle or proof that this PID remains current.
/// The fields are sampled separately. Their relationship is meaningful only for the same stable
/// image used for lookup; neither the object address nor creation time pins identity or lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessObservation {
    pub pid: u64,
    pub eprocess_va: u64,
    pub create_time: Option<u64>,
    /// Observed target process root, normalized using the profile's explicit low-bit mask.
    pub kernel_root_pa: u64,
}

/// One list entry as the walk sampled it: an object address and its PID, nothing more.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessNode {
    pub eprocess_va: u64,
    pub pid: u64,
}

/// Inputs for a complete process-list traversal without a PID filter.
#[derive(Clone, Copy, Debug)]
pub struct ProcessListRequest {
    pub kernel_root_pa: u64,
    pub list_head_va: u64,
    pub max_nodes: usize,
}

/// Caller-owned scratch for one EPROCESS range, including its PID and both active links.
/// Bytes are overwritten for every node and are not a coherent snapshot of live memory.
pub struct ProcessFields<'a> {
    pub offset: u32,
    pub bytes: &'a mut [u8],
}

struct ImageReader<'a, F> {
    config: PagingConfig,
    root_pa: u64,
    read: &'a mut F,
}

impl<F: VirtualRead> ImageReader<'_, F> {
    fn read_node_fields(
        &mut self,
        layout: ProcessLayoutEvidence,
        eprocess_va: u64,
        fields: &mut ProcessFields<'_>,
    ) -> Result<(u64, u64, u64, bool), ProcessError> {
        let report = self.read.read_virtual(
            self.config,
            self.root_pa,
            eprocess_va + u64::from(fields.offset),
            fields.bytes,
        );
        let required_end =
            (layout.pid_offset + WORD_BYTES).max(layout.active_links_offset + LINK_BYTES);
        if report.bytes_read < (required_end - fields.offset) as usize {
            return Err(report
                .error
                .map(ProcessError::Read)
                .unwrap_or(ProcessError::IncompleteRead));
        }
        // A failed later page must not erase the already-read PID and links. Metadata is
        // withheld in that case; no second read or translation cache repairs the observation.
        let word = |offset: u32| {
            let index = (offset - fields.offset) as usize;
            read_u64(&fields.bytes[index..index + WORD_BYTES as usize])
        };
        let forward = word(layout.active_links_offset);
        let backward = word(layout.active_links_offset + WORD_BYTES);
        validate_pointer(forward, LINK_BYTES)?;
        validate_pointer(backward, LINK_BYTES)?;
        Ok((
            word(layout.pid_offset),
            forward,
            backward,
            report.error.is_none() && report.bytes_read == fields.bytes.len(),
        ))
    }

    fn read_identity_links(
        &mut self,
        layout: ProcessLayoutEvidence,
        eprocess_va: u64,
    ) -> Result<(u64, Option<u64>, u64, u64), ProcessError> {
        let Some((start, end)) = identity_range(layout) else {
            let (forward, backward) =
                self.read_links(eprocess_va + u64::from(layout.active_links_offset))?;
            let pid = self.read_word(eprocess_va + u64::from(layout.pid_offset))?;
            let create_time = match layout.create_time_offset {
                Some(offset) => Some(self.read_word(eprocess_va + u64::from(offset))?),
                None => None,
            };
            return Ok((pid, create_time, forward, backward));
        };

        // Every field lies inside the checked object extent. Only this bounded local range is
        // coalesced; read_exact still translates each touched page afresh.
        let mut bytes = [0; MAX_FIELD_BYTES as usize];
        self.read_exact(eprocess_va + u64::from(start), &mut bytes[..(end - start) as usize])?;
        let word = |offset: u32| {
            let index = (offset - start) as usize;
            read_u64(&bytes[index..index + WORD_BYTES as usize])
        };
        let pid = word(layout.pid_offset);
        let forward = word(layout.active_links_offset);
        let backward = word(layout.active_links_offset + WORD_BYTES);
        validate_pointer(forward, LINK_BYTES)?;
        validate_pointer(backward, LINK_BYTES)?;
        let create_time = match layout.create_time_offset {
            Some(offset) if offset >= start && offset + WORD_BYTES <= end => Some(word(offset)),
            Some(offset) => Some(self.read_word(eprocess_va + u64::from(offset))?),
            None => None,
        };
        Ok((pid, create_time, forward, backward))
    }

    fn read_links(&mut self, va: u64) -> Result<(u64, u64), ProcessError> {
        validate_pointer(va, LINK_BYTES)?;
        let mut bytes = [0; LINK_BYTES as usize];
        self.read_exact(va, &mut bytes)?;
        let forward = read_u64(&bytes[..WORD_BYTES as usize]);
        let backward = read_u64(&bytes[WORD_BYTES as usize..]);
        validate_pointer(forward, LINK_BYTES)?;
        validate_pointer(backward, LINK_BYTES)?;
        Ok((forward, backward))
    }

    fn read_word(&mut self, va: u64) -> Result<u64, ProcessError> {
        let mut bytes = [0; WORD_BYTES as usize];
        self.read_exact(va, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_exact(&mut self, va: u64, bytes: &mut [u8]) -> Result<(), ProcessError> {
        let report = self.read.read_virtual(self.config, self.root_pa, va, bytes);
        if let Some(error) = report.error {
            return Err(error.into());
        }
        if report.bytes_read != bytes.len() {
            return Err(ProcessError::IncompleteRead);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessError {
    InvalidProfile,
    OverlappingFields,
    InvalidNodeLimit,
    InvalidPointer,
    CorruptLinks,
    NodeLimit,
    DuplicatePid,
    IdentityChanged,
    DirectoryRootChanged,
    InvalidDirectoryRoot,
    IncompleteRead,
    Read(ReadError),
}

impl From<ReadError> for ProcessError {
    fn from(error: ReadError) -> Self {
        Self::Read(error)
    }
}

/// Inspect the complete circular list before returning a matching observation or `None`.
///
/// Checks every node's backlink against its predecessor and the head's backlink against the
/// final node. Broken lists and cycles terminate with an error; no partial match escapes.
/// Duplicate matching PIDs also fail. This does not detect deliberately hidden processes.
/// The immutable, consistent image and correct profile remain caller obligations.
/// Checks compare separately sampled values; they do not detect every source mutation. PID,
/// root, and optional creation time may come from different objects if the source changes, and
/// a successful result does not establish that they ever coexisted. No identity revalidation or
/// retry occurs. A later read through an observed root requires the same stable image to relate
/// its bytes to this observation; PID, object address, and root reuse are not prevented.
///
/// At most `max_nodes` nodes (capped at `MAX_PROCESS_NODES`) are read. Nearby PID and link
/// fields share one virtual read of at most 64 bytes; distant fields need two reads.
/// The matching PID needs at most two additional reads. Head links need one read.
/// Every range can cross at most two mapped pages. There are
/// no retries, allocations, process modifications, or live-memory acquisition operations.
pub fn find(
    config: PagingConfig,
    profile: ProcessProfile,
    request: ProcessRequest,
    read: &mut impl VirtualRead,
) -> Result<Option<ProcessObservation>, ProcessError> {
    if request.max_nodes == 0 || request.max_nodes > MAX_PROCESS_NODES {
        return Err(ProcessError::InvalidNodeLimit);
    }
    let mut image = ImageReader { config, root_pa: request.kernel_root_pa, read };
    let layout = profile.layout;
    let mut found = None;
    walk(
        &mut image,
        layout,
        request.list_head_va,
        request.max_nodes,
        None,
        &mut |image, ProcessNode { eprocess_va, pid }, _| {
            if pid != request.pid {
                return Ok(());
            }
            if found.is_some() {
                return Err(ProcessError::DuplicatePid);
            }
            let raw_root =
                image.read_word(eprocess_va + u64::from(layout.directory_root_offset))?;
            let kernel_root_pa = normalize_root(config, layout.dtb_low_bits_mask, raw_root)?;
            let create_time = match layout.create_time_offset {
                Some(offset) => Some(image.read_word(eprocess_va + u64::from(offset))?),
                None => None,
            };
            found = Some(ProcessObservation { pid, eprocess_va, create_time, kernel_root_pa });
            Ok(())
        },
    )?;
    Ok(found)
}

/// Inspect the complete circular list and copy every node into `nodes`, in list order,
/// returning how many were copied. The link checks, bounds and caveats are those of `find`;
/// `nodes.len()` (at most `MAX_PROCESS_NODES`) is the node limit. Duplicate PIDs are copied as
/// found. Nearby PID and links share one virtual read; distant fields need two.
pub fn list(
    config: PagingConfig,
    profile: ProcessProfile,
    kernel_root_pa: u64,
    list_head_va: u64,
    nodes: &mut [ProcessNode],
    read: &mut impl VirtualRead,
) -> Result<usize, ProcessError> {
    if nodes.is_empty() || nodes.len() > MAX_PROCESS_NODES {
        return Err(ProcessError::InvalidNodeLimit);
    }
    let mut image = ImageReader { config, root_pa: kernel_root_pa, read };
    let mut count = 0;
    walk(&mut image, profile.layout, list_head_va, nodes.len(), None, &mut |_, node, _| {
        nodes[count] = node;
        count += 1;
        Ok(())
    })?;
    Ok(count)
}

/// Walk the complete list while sampling extra EPROCESS fields with its PID and links.
/// The range must fit the object and include the PID and both links. Each touched page is
/// translated afresh. If a later page fails after the PID and links were read, the visitor
/// receives `None` for the extra fields and traversal continues. Earlier failures stop it.
///
/// Visitors run before the final list check. Callers must discard accumulated results if
/// this function returns an error; follow-up reads can be deferred until the walk succeeds.
/// Bounds, backlink checks and live-memory caveats are otherwise those of `list`.
pub fn visit_fields(
    config: PagingConfig,
    profile: ProcessProfile,
    request: ProcessListRequest,
    fields: &mut ProcessFields<'_>,
    read: &mut impl VirtualRead,
    visit: &mut impl FnMut(ProcessNode, Option<&[u8]>) -> Result<(), ProcessError>,
) -> Result<(), ProcessError> {
    if request.max_nodes == 0 || request.max_nodes > MAX_PROCESS_NODES {
        return Err(ProcessError::InvalidNodeLimit);
    }
    let layout = profile.layout;
    let end = u64::from(fields.offset) + fields.bytes.len() as u64;
    if fields.bytes.is_empty()
        || fields.bytes.len() > read::MAX_READ_BYTES
        || end > u64::from(layout.eprocess_bytes)
        || fields.offset > layout.pid_offset.min(layout.active_links_offset)
        || end
            < u64::from(
                (layout.pid_offset + WORD_BYTES).max(layout.active_links_offset + LINK_BYTES),
            )
    {
        return Err(ProcessError::InvalidProfile);
    }
    let mut image = ImageReader { config, root_pa: request.kernel_root_pa, read };
    walk(
        &mut image,
        layout,
        request.list_head_va,
        request.max_nodes,
        Some(fields),
        &mut |_, node, bytes| visit(node, bytes),
    )
}

/// Visit every node of the circular list with its object address and PID, then check that the
/// head's backlink names the last node. Any visitor error stops the walk.
fn walk<'a, F: VirtualRead>(
    image: &mut ImageReader<'a, F>,
    layout: ProcessLayoutEvidence,
    list_head_va: u64,
    max_nodes: usize,
    mut fields: Option<&mut ProcessFields<'_>>,
    visit: &mut impl FnMut(
        &mut ImageReader<'a, F>,
        ProcessNode,
        Option<&[u8]>,
    ) -> Result<(), ProcessError>,
) -> Result<(), ProcessError> {
    validate_pointer(list_head_va, LINK_BYTES)?;
    let (mut current, last) = image.read_links(list_head_va)?;
    let mut previous = list_head_va;
    for _ in 0..max_nodes {
        if current == list_head_va {
            return finish(previous, last);
        }
        let eprocess_va = current
            .checked_sub(u64::from(layout.active_links_offset))
            .ok_or(ProcessError::InvalidPointer)?;
        validate_pointer(eprocess_va, layout.eprocess_bytes)?;
        let (pid, next, backward, complete) = if let Some(fields) = fields.as_deref_mut() {
            image.read_node_fields(layout, eprocess_va, fields)?
        } else {
            let (pid, _, next, backward) = image.read_identity_links(
                ProcessLayoutEvidence { create_time_offset: None, ..layout },
                eprocess_va,
            )?;
            (pid, next, backward, false)
        };
        if backward != previous || next == current {
            return Err(ProcessError::CorruptLinks);
        }
        let bytes = fields.as_ref().filter(|_| complete).map(|fields| &*fields.bytes);
        visit(image, ProcessNode { eprocess_va, pid }, bytes)?;
        previous = current;
        current = next;
    }
    if current == list_head_va {
        return finish(previous, last);
    }
    Err(ProcessError::NodeLimit)
}

/// Reobserve a previously discovered object without traversing the process list.
///
/// `kernel_root_pa` translates kernel metadata; it is independent of the target root retained
/// in `expected`. PID, optional creation time, and normalized target root must still match.
/// The target's freshly sampled links must be non-self links with reciprocal neighbor pointers.
/// Neighbors may change between calls. A sentinel is read only if it is a current neighbor;
/// neither the sentinel nor unrelated objects are otherwise inspected. This does not repeat
/// `find`'s whole-list or duplicate-PID checks and cannot detect a detached, internally valid ring.
///
/// Each call uses fresh translations and retains no VA-to-PA cache. Nearby identity/link fields
/// may share one read of at most 64 bytes; other reads are at most 16 bytes. Each range crosses
/// at most two pages. All fields and both reciprocal checks must complete before a result escapes.
/// The physical callback must fill each complete slice before returning success.
///
/// These are best-effort mutation checks on separately sampled data, not an OS object reference,
/// page pin, lifetime guarantee, or coherent snapshot. Mutation and reuse between callbacks can
/// escape detection, including a change followed by restoration. Callers needing creation-time
/// identity must supply a profile and observation that contain it.
pub fn revalidate(
    config: PagingConfig,
    profile: ProcessProfile,
    kernel_root_pa: u64,
    expected: ProcessObservation,
    read: &mut impl VirtualRead,
) -> Result<ProcessObservation, ProcessError> {
    let layout = profile.layout;
    validate_pointer(expected.eprocess_va, layout.eprocess_bytes)?;
    if layout.create_time_offset.is_some() != expected.create_time.is_some() {
        return Err(ProcessError::IdentityChanged);
    }
    let mut image = ImageReader { config, root_pa: kernel_root_pa, read };
    let (pid, create_time, forward, backward) =
        image.read_identity_links(layout, expected.eprocess_va)?;
    if pid != expected.pid || create_time != expected.create_time {
        return Err(ProcessError::IdentityChanged);
    }
    let links_va = expected.eprocess_va + u64::from(layout.active_links_offset);
    if forward == links_va || backward == links_va {
        return Err(ProcessError::CorruptLinks);
    }
    let raw_root =
        image.read_word(expected.eprocess_va + u64::from(layout.directory_root_offset))?;
    let observed_root = normalize_root(config, layout.dtb_low_bits_mask, raw_root)?;
    if observed_root != expected.kernel_root_pa {
        return Err(ProcessError::DirectoryRootChanged);
    }
    if image.read_word(forward + u64::from(WORD_BYTES))? != links_va
        || image.read_word(backward)? != links_va
    {
        return Err(ProcessError::CorruptLinks);
    }
    Ok(ProcessObservation {
        pid,
        eprocess_va: expected.eprocess_va,
        create_time,
        kernel_root_pa: observed_root,
    })
}

fn finish(previous: u64, last: u64) -> Result<(), ProcessError> {
    if previous != last {
        return Err(ProcessError::CorruptLinks);
    }
    Ok(())
}

fn identity_range(layout: ProcessLayoutEvidence) -> Option<(u32, u32)> {
    let mut start = layout.pid_offset.min(layout.active_links_offset);
    let mut end = (layout.pid_offset + WORD_BYTES).max(layout.active_links_offset + LINK_BYTES);
    if end - start > MAX_FIELD_BYTES {
        return None;
    }
    if let Some(offset) = layout.create_time_offset {
        if end.max(offset + WORD_BYTES) - start.min(offset) <= MAX_FIELD_BYTES {
            start = start.min(offset);
            end = end.max(offset + WORD_BYTES);
        }
    }
    Some((start, end))
}

fn normalize_root(
    config: PagingConfig,
    low_bits_mask: u16,
    raw_root: u64,
) -> Result<u64, ProcessError> {
    let root_pa = raw_root & !u64::from(low_bits_mask);
    if root_pa & (PAGE_BYTES as u64 - 1) != 0 || root_pa >> config.physical_bits() != 0 {
        return Err(ProcessError::InvalidDirectoryRoot);
    }
    Ok(root_pa)
}

fn validate_pointer(va: u64, length: u32) -> Result<(), ProcessError> {
    let last = va.checked_add(u64::from(length) - 1).ok_or(ProcessError::InvalidPointer)?;
    if va == 0 || va % u64::from(WORD_BYTES) != 0 || !is_canonical_48(va) || !is_canonical_48(last)
    {
        return Err(ProcessError::InvalidPointer);
    }
    Ok(())
}

fn read_u64(bytes: &[u8]) -> u64 {
    let mut word = [0; WORD_BYTES as usize];
    word.copy_from_slice(bytes);
    u64::from_le_bytes(word)
}
