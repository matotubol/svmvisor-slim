//! The kernel's own process list and the EPROCESS fields read from it, all through the runtime.
//! Windows is never asked: no Toolhelp snapshot and no process handle.

use svmvisor_hypervisor::reader::{
    paging::{PagingConfig, PagingError},
    process::{self, ProcessFields, ProcessListRequest},
    read::{self, ReadError, ReadReport, VirtualRead, VirtualReader},
};

use crate::{
    bridge::{Failure, ReadBridge},
    profile::{DetailOffsets, IMAGE_NAME_BYTES, KernelProfile},
};

/// Longest full image path read for a name, in UTF-16 bytes. Longer paths use `ImageFileName`.
const MAX_PATH_BYTES: usize = 4096;
/// `UNICODE_STRING` as its pointer to `OBJECT_NAME_INFORMATION` sees it: x64, 16 bytes.
const STRING_BYTES: usize = 16;

/// A user-mode process in the kernel's process list, as listed by
/// [`Svm::list_processes`](crate::Svm::list_processes).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProcessEntry {
    pub pid: u32,
    /// The executable file name, such as `game.exe`.
    pub name: String,
    /// Kernel creation time (100 ns units since 1601). With the PID it names one process, so
    /// [`attach`](crate::Svm::attach) refuses a PID that was reused since the listing.
    pub created: u64,
}

/// Kernel-held metadata sampled once from one EPROCESS.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Details {
    pub created: u64,
    image_name: [u8; IMAGE_NAME_BYTES],
    /// Zero for processes without a user-mode loader, such as System.
    pub peb: u64,
    /// A 32-bit process keeps a separate 32-bit module list.
    pub wow64: bool,
    /// `OBJECT_NAME_INFORMATION` holding the full image path, when the kernel recorded one.
    audit_name: u64,
}

impl Details {
    /// Reads every field with one virtual read; they lie within 0x160 bytes of each other.
    pub(crate) fn read(
        config: PagingConfig,
        profile: &KernelProfile,
        kernel_root_pa: u64,
        eprocess_va: u64,
        memory: &mut impl VirtualRead,
    ) -> Result<Self, String> {
        let (start, end) = Self::range(profile.details());
        let mut bytes = vec![0; (end - start) as usize];
        read_exact(config, kernel_root_pa, eprocess_va + u64::from(start), &mut bytes, memory)
            .map_err(|error| format!("read EPROCESS fields: {error}"))?;
        Ok(Self::decode(profile.details(), start, &bytes))
    }

    fn range(offsets: DetailOffsets) -> (u32, u32) {
        let fields = [
            (offsets.create_time, 8),
            (offsets.image_name, IMAGE_NAME_BYTES as u32),
            (offsets.peb, 8),
            (offsets.wow64, 8),
            (offsets.audit_name, 8),
        ];
        let start = fields.iter().map(|&(offset, _)| offset).min().unwrap_or(0);
        let end = fields.iter().map(|&(offset, length)| offset + length).max().unwrap_or(0);
        (start, end)
    }

    /// The caller supplies the complete, profile-checked field range.
    fn decode(offsets: DetailOffsets, start: u32, bytes: &[u8]) -> Self {
        let at = |offset: u32| (offset - start) as usize;
        let word = |offset: u32| u64::from_le_bytes(bytes[at(offset)..][..8].try_into().unwrap());
        let mut image_name = [0; IMAGE_NAME_BYTES];
        image_name.copy_from_slice(&bytes[at(offsets.image_name)..][..IMAGE_NAME_BYTES]);
        Self {
            created: word(offsets.create_time),
            image_name,
            peb: word(offsets.peb),
            wow64: word(offsets.wow64) != 0,
            audit_name: word(offsets.audit_name),
        }
    }

    /// The file name of the full image path the kernel recorded at creation, or else
    /// `ImageFileName`, which keeps at most the first 14 bytes of the name.
    fn name(
        &self,
        config: PagingConfig,
        profile: &KernelProfile,
        kernel_root_pa: u64,
        memory: &mut impl VirtualRead,
    ) -> String {
        self.full_name(config, profile, kernel_root_pa, memory).unwrap_or_else(|| {
            let length = self.image_name.iter().position(|&byte| byte == 0);
            self.image_name[..length.unwrap_or(IMAGE_NAME_BYTES)]
                .iter()
                .map(|&byte| char::from(byte))
                .collect()
        })
    }

    fn full_name(
        &self,
        config: PagingConfig,
        profile: &KernelProfile,
        kernel_root_pa: u64,
        memory: &mut impl VirtualRead,
    ) -> Option<String> {
        if self.audit_name == 0 {
            return None;
        }
        let offsets = profile.details();
        let string = self.audit_name.checked_add(u64::from(offsets.name))?;
        let mut header = [0; STRING_BYTES];
        read_exact(config, kernel_root_pa, string, &mut header, memory).ok()?;
        let length = usize::from(u16::from_le_bytes(
            header[offsets.name_length as usize..][..2].try_into().unwrap(),
        ));
        let buffer =
            u64::from_le_bytes(header[offsets.name_buffer as usize..][..8].try_into().unwrap());
        if length == 0 || length % 2 != 0 || length > MAX_PATH_BYTES || buffer == 0 {
            return None;
        }
        let mut path = vec![0; length];
        read_exact(config, kernel_root_pa, buffer, &mut path, memory).ok()?;
        let units: Vec<u16> =
            path.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        let name = units.rsplit(|&unit| unit == u16::from(b'\\')).next()?;
        (!name.is_empty()).then(|| String::from_utf16_lossy(name))
    }
}

/// Every process in the list that has a PEB, sorted by name then PID. Unreadable metadata
/// is skipped if its PID and links were read; broken list links fail the complete listing.
pub(crate) fn list(
    config: PagingConfig,
    profile: &KernelProfile,
    kernel_root_pa: u64,
    list_head_va: u64,
    max_nodes: usize,
    bridge: &mut ReadBridge,
) -> Result<Vec<ProcessEntry>, String> {
    let mut backend_error = None;
    let offsets = profile.details();
    let layout = profile.process().layout();
    let (start, end) = Details::range(offsets);
    let start = start.min(layout.pid_offset).min(layout.active_links_offset);
    let end = end.max(layout.pid_offset + 8).max(layout.active_links_offset + 16);
    let mut bytes = vec![0; (end - start) as usize];
    let mut sampled = Vec::new();
    let walked = process::visit_fields(
        config,
        profile.process(),
        ProcessListRequest { kernel_root_pa, list_head_va, max_nodes },
        &mut ProcessFields { offset: start, bytes: &mut bytes },
        &mut memory(bridge, &mut backend_error),
        &mut |node, bytes| {
            let Ok(pid) = u32::try_from(node.pid) else { return Ok(()) };
            let Some(bytes) = bytes else { return Ok(()) };
            if pid == 0 {
                return Ok(());
            }
            let details = Details::decode(offsets, start, bytes);
            if details.peb != 0 {
                sampled.push((pid, details));
            }
            Ok(())
        },
    );
    walked.map_err(|error| {
        format!("process list walk failed: {error:?}; backend={backend_error:?}")
    })?;
    if bridge.failed() {
        return Err(format!("read process metadata: backend={backend_error:?}"));
    }
    // Keep path-pointer reads out of the list walk. All links must pass before names are
    // resolved, and the EPROCESS fields above are retained rather than reread.
    let mut processes = Vec::with_capacity(sampled.len());
    for (pid, details) in sampled {
        let name =
            details.name(config, profile, kernel_root_pa, &mut memory(bridge, &mut backend_error));
        if bridge.failed() {
            return Err(format!("read process {pid} name: backend={backend_error:?}"));
        }
        processes.push(ProcessEntry { pid, name, created: details.created });
    }
    processes.sort_by_cached_key(|process| (process.name.to_ascii_lowercase(), process.pid));
    Ok(processes)
}

/// Translate inside the resident, retaining completed pages if a later page is unavailable.
/// Physical backend failures still poison the bridge and retain their transport reason.
pub(crate) fn memory<'a>(
    bridge: &'a mut ReadBridge,
    backend_error: &'a mut Option<String>,
) -> impl VirtualRead + 'a {
    VirtualReader(move |config: PagingConfig, root: u64, va: u64, bytes: &mut [u8]| {
        if let Err(error) = read::validate_range(va, bytes.len()) {
            return ReadReport { bytes_read: 0, error: Some(error) };
        }
        let mut bytes_read = 0;
        while bytes_read < bytes.len() {
            let address = va + bytes_read as u64;
            let length = (4096 - (address as usize & 4095)).min(bytes.len() - bytes_read);
            if let Err(failure) = bridge.read_virtual(
                config,
                root,
                address,
                &mut bytes[bytes_read..bytes_read + length],
            ) {
                let error = if failure == Failure::Unreadable {
                    ReadError::Translation
                } else {
                    *backend_error = Some(failure.to_string());
                    ReadError::Paging(PagingError::PhysicalRead)
                };
                return ReadReport { bytes_read, error: Some(error) };
            }
            bytes_read += length;
        }
        ReadReport { bytes_read, error: None }
    })
}

fn read_exact(
    config: PagingConfig,
    root_pa: u64,
    va: u64,
    bytes: &mut [u8],
    memory: &mut impl VirtualRead,
) -> Result<(), String> {
    let report = memory.read_virtual(config, root_pa, va, bytes);
    match report.error {
        Some(error) => Err(format!("{error:?}")),
        None if report.bytes_read != bytes.len() => Err("incomplete read".into()),
        None => Ok(()),
    }
}
