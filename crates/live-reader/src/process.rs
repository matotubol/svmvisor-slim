//! The kernel's own process list and the EPROCESS fields read from it, all through the runtime.
//! Windows is never asked: no Toolhelp snapshot and no process handle.

use svmvisor_hypervisor::reader::{
    paging::{PagingConfig, PagingError},
    process::{self, ProcessNode},
    read,
};

use crate::{
    bridge::ReadBridge,
    profile::{IMAGE_NAME_BYTES, KernelProfile},
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
        physical: &mut impl FnMut(u64, &mut [u8]) -> Result<(), PagingError>,
    ) -> Result<Self, String> {
        let offsets = profile.details();
        let fields = [
            (offsets.create_time, 8),
            (offsets.image_name, IMAGE_NAME_BYTES as u32),
            (offsets.peb, 8),
            (offsets.wow64, 8),
            (offsets.audit_name, 8),
        ];
        let start = fields.iter().map(|&(offset, _)| offset).min().unwrap_or(0);
        let end = fields.iter().map(|&(offset, length)| offset + length).max().unwrap_or(0);
        let mut bytes = vec![0; (end - start) as usize];
        read_exact(config, kernel_root_pa, eprocess_va + u64::from(start), &mut bytes, physical)
            .map_err(|error| format!("read EPROCESS fields: {error}"))?;
        let at = |offset: u32| (offset - start) as usize;
        let word = |offset: u32| u64::from_le_bytes(bytes[at(offset)..][..8].try_into().unwrap());
        let mut image_name = [0; IMAGE_NAME_BYTES];
        image_name.copy_from_slice(&bytes[at(offsets.image_name)..][..IMAGE_NAME_BYTES]);
        Ok(Self {
            created: word(offsets.create_time),
            image_name,
            peb: word(offsets.peb),
            wow64: word(offsets.wow64) != 0,
            audit_name: word(offsets.audit_name),
        })
    }

    /// The file name of the full image path the kernel recorded at creation, or else
    /// `ImageFileName`, which keeps at most the first 14 bytes of the name.
    fn name(
        &self,
        config: PagingConfig,
        profile: &KernelProfile,
        kernel_root_pa: u64,
        physical: &mut impl FnMut(u64, &mut [u8]) -> Result<(), PagingError>,
    ) -> String {
        self.full_name(config, profile, kernel_root_pa, physical).unwrap_or_else(|| {
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
        physical: &mut impl FnMut(u64, &mut [u8]) -> Result<(), PagingError>,
    ) -> Option<String> {
        if self.audit_name == 0 {
            return None;
        }
        let offsets = profile.details();
        let string = self.audit_name.checked_add(u64::from(offsets.name))?;
        let mut header = [0; STRING_BYTES];
        read_exact(config, kernel_root_pa, string, &mut header, physical).ok()?;
        let length = usize::from(u16::from_le_bytes(
            header[offsets.name_length as usize..][..2].try_into().unwrap(),
        ));
        let buffer =
            u64::from_le_bytes(header[offsets.name_buffer as usize..][..8].try_into().unwrap());
        if length == 0 || length % 2 != 0 || length > MAX_PATH_BYTES || buffer == 0 {
            return None;
        }
        let mut path = vec![0; length];
        read_exact(config, kernel_root_pa, buffer, &mut path, physical).ok()?;
        let units: Vec<u16> =
            path.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        let name = units.rsplit(|&unit| unit == u16::from(b'\\')).next()?;
        (!name.is_empty()).then(|| String::from_utf16_lossy(name))
    }
}

/// Every process in the list that has a PEB, sorted by name then PID. A process that exits
/// while it is read is left out.
pub(crate) fn list(
    config: PagingConfig,
    profile: &KernelProfile,
    kernel_root_pa: u64,
    list_head_va: u64,
    max_nodes: usize,
    bridge: &mut ReadBridge,
) -> Result<Vec<ProcessEntry>, String> {
    let mut backend_error = None;
    let mut nodes = vec![ProcessNode::default(); max_nodes];
    let walked = process::list(
        config,
        profile.process(),
        kernel_root_pa,
        list_head_va,
        &mut nodes,
        &mut physical(bridge, &mut backend_error),
    );
    let count = walked.map_err(|error| {
        format!("process list walk failed: {error:?}; backend={backend_error:?}")
    })?;
    let mut processes = Vec::new();
    for node in &nodes[..count] {
        let Ok(pid) = u32::try_from(node.pid) else { continue };
        if pid == 0 {
            continue;
        }
        let details = Details::read(
            config,
            profile,
            kernel_root_pa,
            node.eprocess_va,
            &mut physical(bridge, &mut backend_error),
        );
        let Ok(details) = details else {
            if bridge.failed() {
                return Err(format!("read process {pid}: backend={backend_error:?}"));
            }
            continue;
        };
        if details.peb == 0 {
            continue;
        }
        let name = details.name(
            config,
            profile,
            kernel_root_pa,
            &mut physical(bridge, &mut backend_error),
        );
        if bridge.failed() {
            return Err(format!("read process {pid} name: backend={backend_error:?}"));
        }
        processes.push(ProcessEntry { pid, name, created: details.created });
    }
    processes.sort_by_key(|process| (process.name.to_ascii_lowercase(), process.pid));
    Ok(processes)
}

/// Physical reads through the runtime, keeping the transport's reason for a failed read.
pub(crate) fn physical<'a>(
    bridge: &'a mut ReadBridge,
    backend_error: &'a mut Option<String>,
) -> impl FnMut(u64, &mut [u8]) -> Result<(), PagingError> + 'a {
    move |pa, bytes| {
        bridge.read(pa, bytes).map_err(|error| {
            *backend_error = Some(error);
            PagingError::PhysicalRead
        })
    }
}

fn read_exact(
    config: PagingConfig,
    root_pa: u64,
    va: u64,
    bytes: &mut [u8],
    physical: &mut impl FnMut(u64, &mut [u8]) -> Result<(), PagingError>,
) -> Result<(), String> {
    let report = read::read_virtual(config, root_pa, va, bytes, physical);
    match report.error {
        Some(error) => Err(format!("{error:?}")),
        None if report.bytes_read != bytes.len() => Err("incomplete read".into()),
        None => Ok(()),
    }
}
