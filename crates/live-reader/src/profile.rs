//! Bind supplied kernel/PDB files to the recorded static layout evidence.

use std::{fs::File, io::Read, path::Path};

use serde_json::Value;
use sha2::{Digest, Sha256};
use svmvisor_hypervisor::reader::process::{ProcessLayoutEvidence, ProcessProfile};

const EVIDENCE: &str = include_str!("../../hypervisor/profiles/ntoskrnl-26100.9457.json");
const HASH_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct KernelProfile {
    process: ProcessProfile,
    identity: KernelIdentity,
    syscall_rvas: [u32; 2],
    list_head_rva: u32,
    system_process_rva: u32,
    details: DetailOffsets,
}

impl KernelProfile {
    pub(crate) fn process(&self) -> ProcessProfile {
        self.process
    }

    pub(crate) fn identity(&self) -> &KernelIdentity {
        &self.identity
    }

    pub(crate) fn syscall_rvas(&self) -> &[u32] {
        &self.syscall_rvas
    }

    pub(crate) fn list_head_rva(&self) -> u32 {
        self.list_head_rva
    }

    pub(crate) fn system_process_rva(&self) -> u32 {
        self.system_process_rva
    }

    pub(crate) fn details(&self) -> DetailOffsets {
        self.details
    }

    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        parse_kernel(&serde_json::from_str(EVIDENCE).unwrap()).unwrap()
    }
}

/// EPROCESS fields read when a process is listed or opened, and the path structures behind
/// its full image name. The resident never checks them.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DetailOffsets {
    pub create_time: u32,
    /// `ImageFileName`, [`IMAGE_NAME_BYTES`] long.
    pub image_name: u32,
    pub peb: u32,
    pub wow64: u32,
    /// `SeAuditProcessCreationInfo.ImageFileName`, a pointer to `OBJECT_NAME_INFORMATION`.
    pub audit_name: u32,
    /// `OBJECT_NAME_INFORMATION.Name`, a `UNICODE_STRING`.
    pub name: u32,
    /// `UNICODE_STRING.Length` (bytes, `u16`) and `.Buffer` (pointer).
    pub name_length: u32,
    pub name_buffer: u32,
}

/// `ImageFileName` is a fixed array that need not end in a zero.
pub(crate) const IMAGE_NAME_BYTES: usize = 15;

#[derive(Clone, Debug)]
pub(crate) struct KernelIdentity {
    pub machine: u16,
    pub timestamp: u32,
    pub image_bytes: u32,
    pub checksum: u32,
    pub codeview_guid: [u8; 16],
    pub codeview_age: u32,
}

/// Exact file hashes bind the offsets to these supplied files, not to the memory capture.
/// The caller must separately establish that the capture used this kernel and layout.
pub fn load(kernel: &Path, pdb: &Path) -> Result<ProcessProfile, String> {
    Ok(load_kernel(kernel, pdb)?.process())
}

pub(crate) fn load_kernel(kernel: &Path, pdb: &Path) -> Result<KernelProfile, String> {
    let evidence: Value = serde_json::from_str(EVIDENCE)
        .map_err(|error| format!("recorded kernel evidence is malformed: {error}"))?;
    // The recorded symbols establish a field location, not a tagged storage encoding.
    // Require an already aligned stored root; do not infer which low bits are meaningful.
    let profile = parse_kernel(&evidence)?;
    verify_file(kernel, &evidence["image"], "kernel")?;
    verify_file(pdb, &evidence["pdb"], "PDB")?;
    Ok(profile)
}

fn parse_kernel(evidence: &Value) -> Result<KernelProfile, String> {
    let process = parse(evidence, 0)?;
    let image = &evidence["image"];
    let identity = KernelIdentity {
        machine: u16::try_from(number(&image["machine"])?).map_err(|_| "invalid PE machine")?,
        timestamp: number(&image["timestamp"])?,
        image_bytes: number(&image["image_bytes"])?,
        checksum: number(&image["checksum"])?,
        codeview_guid: guid_bytes(image["codeview"]["guid"].as_str().ok_or("missing GUID")?)?,
        codeview_age: number(&image["codeview"]["age"])?,
    };
    let symbol = |name: &str, length: u32| -> Result<u32, String> {
        let rva = number(&evidence["symbols"][name]["rva"])?;
        if rva == 0 || rva.checked_add(length).is_none_or(|end| end > identity.image_bytes) {
            return Err(format!("recorded {name} exceeds kernel image"));
        }
        Ok(rva)
    };
    let syscall_rvas = [symbol("KiSystemCall64", 1)?, symbol("KiSystemCall64Shadow", 1)?];
    let list_head_rva = symbol("PsActiveProcessHead", 16)?;
    let system_process_rva = symbol("PsInitialSystemProcess", 8)?;
    let details = parse_details(evidence)?;
    Ok(KernelProfile {
        process,
        identity,
        syscall_rvas,
        list_head_rva,
        system_process_rva,
        details,
    })
}

fn parse_details(evidence: &Value) -> Result<DetailOffsets, String> {
    let field = |group: &str, name: &str, key: &str, within: &str, length: u32, align: u32| {
        let offset = number(&evidence[group][name][key])?;
        let bytes = number(&evidence["types"][within]["bytes"])?;
        if offset % align != 0 || offset.checked_add(length).is_none_or(|end| end > bytes) {
            return Err(format!("recorded {name} does not fit {within}"));
        }
        Ok::<_, String>(offset)
    };
    let eprocess = |name: &str, key: &str, length: u32, align: u32| {
        field("fields", name, key, "_EPROCESS", length, align)
    };
    if number(&evidence["fields"]["ImageFileName"]["bytes"])? != IMAGE_NAME_BYTES as u32 {
        return Err("recorded ImageFileName is not 15 bytes".into());
    }
    let strings = "_UNICODE_STRING";
    if number(&evidence["types"][strings]["bytes"])? != 16 {
        return Err("recorded UNICODE_STRING is not the x64 layout".into());
    }
    Ok(DetailOffsets {
        create_time: eprocess("CreateTime", "offset", 8, 8)?,
        image_name: eprocess("ImageFileName", "offset", IMAGE_NAME_BYTES as u32, 1)?,
        peb: eprocess("Peb", "offset", 8, 8)?,
        wow64: eprocess("WoW64Process", "offset", 8, 8)?,
        audit_name: eprocess("SeAuditProcessCreationInfo.ImageFileName", "eprocess_offset", 8, 8)?,
        name: field("name_fields", "Name", "offset", "_OBJECT_NAME_INFORMATION", 16, 8)?,
        name_length: field("string_fields", "Length", "offset", strings, 2, 2)?,
        name_buffer: field("string_fields", "Buffer", "offset", strings, 8, 8)?,
    })
}

fn guid_bytes(text: &str) -> Result<[u8; 16], String> {
    if text.len() != 36 || [8, 13, 18, 23].iter().any(|&index| text.as_bytes()[index] != b'-') {
        return Err("recorded evidence has an invalid GUID".into());
    }
    let digits: Vec<u8> = text.bytes().filter(|&byte| byte != b'-').collect();
    if digits.len() != 32 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err("recorded evidence has an invalid GUID".into());
    }
    let mut bytes = [0; 16];
    for (out, pair) in bytes.iter_mut().zip(digits.chunks_exact(2)) {
        let digit = |byte: u8| {
            if byte.is_ascii_digit() { byte - b'0' } else { byte.to_ascii_lowercase() - b'a' + 10 }
        };
        *out = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    bytes[..4].reverse();
    bytes[4..6].reverse();
    bytes[6..8].reverse();
    Ok(bytes)
}

fn parse(evidence: &Value, dtb_low_bits_mask: u16) -> Result<ProcessProfile, String> {
    if number(&evidence["schema_version"])? != 1
        || number(&evidence["image"]["machine"])? != 0x8664
        || evidence["image"]["codeview"]["guid"].as_str().is_none()
        || evidence["image"]["codeview"]["guid"] != evidence["pdb"]["guid"]
        || number(&evidence["image"]["codeview"]["age"])? != number(&evidence["pdb"]["dbi_age"])?
        || number(&evidence["types"]["_LIST_ENTRY"]["bytes"])? != 16
        || number(&evidence["list_fields"]["Flink"]["offset"])? != 0
        || number(&evidence["list_fields"]["Blink"]["offset"])? != 8
    {
        return Err("recorded kernel evidence has inconsistent identity or x64 list layout".into());
    }
    let fields = &evidence["fields"];
    let pcb_offset = number(&fields["Pcb"]["offset"])?;
    let relative_root = number(&fields["Pcb.DirectoryTableBase"]["offset"])?;
    let directory_root_offset = number(&fields["Pcb.DirectoryTableBase"]["eprocess_offset"])?;
    let kprocess_bytes = number(&evidence["types"]["_KPROCESS"]["bytes"])?;
    let eprocess_bytes = number(&evidence["types"]["_EPROCESS"]["bytes"])?;
    if pcb_offset.checked_add(relative_root) != Some(directory_root_offset)
        || relative_root.checked_add(8).is_none_or(|end| end > kprocess_bytes)
        || pcb_offset.checked_add(kprocess_bytes).is_none_or(|end| end > eprocess_bytes)
    {
        return Err("recorded KPROCESS root field does not fit its enclosing EPROCESS".into());
    }
    let layout = ProcessLayoutEvidence {
        eprocess_bytes,
        active_links_offset: number(&fields["ActiveProcessLinks"]["offset"])?,
        pid_offset: number(&fields["UniqueProcessId"]["offset"])?,
        create_time_offset: Some(number(&fields["CreateTime"]["offset"])?),
        directory_root_offset,
        dtb_low_bits_mask,
    };
    ProcessProfile::new(layout)
        .map_err(|error| format!("recorded process layout is invalid: {error:?}"))
}

fn number(value: &Value) -> Result<u32, String> {
    value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "recorded evidence is missing a bounded unsigned integer".into())
}

fn verify_file(path: &Path, identity: &Value, label: &str) -> Result<(), String> {
    let expected_bytes = u64::from(number(&identity["file_bytes"])?);
    let expected_hash = identity["sha256"]
        .as_str()
        .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("recorded evidence has an invalid SHA-256 digest")?;
    let mut file =
        File::open(path).map_err(|error| format!("open {label} {}: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| format!("inspect {label}: {error}"))?;
    if !metadata.is_file() || metadata.len() != expected_bytes {
        return Err(format!("{label} file size does not match the recorded kernel profile"));
    }
    let mut hasher = Sha256::new();
    let mut bytes = [0; HASH_BUFFER_BYTES];
    let mut remaining = expected_bytes;
    while remaining != 0 {
        let length = remaining.min(bytes.len() as u64) as usize;
        file.read_exact(&mut bytes[..length]).map_err(|error| format!("read {label}: {error}"))?;
        hasher.update(&bytes[..length]);
        remaining -= length as u64;
    }
    if file.read(&mut bytes[..1]).map_err(|error| format!("finish {label} read: {error}"))? != 0 {
        return Err(format!("{label} changed length during profile verification"));
    }
    let actual_hash: String = hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect();
    if actual_hash != expected_hash.to_ascii_lowercase() {
        return Err(format!("{label} SHA-256 does not match the recorded kernel profile"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    #[test]
    fn recorded_evidence_constructs_the_validated_profile() {
        let evidence: Value = serde_json::from_str(EVIDENCE).unwrap();
        assert!(parse(&evidence, 0).is_ok());
        assert!(parse(&evidence, 0x1000).is_err());
        let kernel = parse_kernel(&evidence).unwrap();
        assert_eq!(kernel.syscall_rvas(), &[0x006c_1840, 0x00bc_b200]);
        assert_eq!(kernel.identity().codeview_age, 1);
        let details = kernel.details();
        assert_eq!(
            [details.create_time, details.image_name, details.peb, details.wow64],
            [0x1f8, 0x338, 0x2e0, 0x310]
        );
        assert_eq!(
            [details.audit_name, details.name, details.name_length, details.name_buffer],
            [0x350, 0, 0, 8]
        );
        assert_eq!(
            kernel.identity().codeview_guid,
            [
                0xb0, 0xbf, 0x9e, 0xc2, 0x78, 0x6b, 0xc0, 0xb3, 0x20, 0xdc, 0xa6, 0x6d, 0x99, 0x71,
                0x3f, 0x9e,
            ]
        );
    }

    #[test]
    fn invalid_guid_and_unbounded_anchors_are_rejected() {
        for text in ["", "C29EBFB0-6B78-B3C0-20DC-A66D99713F9Z", "C29EBFB06B78B3C020DCA66D99713F9E"]
        {
            assert!(guid_bytes(text).is_err());
        }
        let evidence: Value = serde_json::from_str(EVIDENCE).unwrap();
        for symbol in [
            "KiSystemCall64",
            "KiSystemCall64Shadow",
            "PsActiveProcessHead",
            "PsInitialSystemProcess",
        ] {
            for rva in [0, u32::MAX, number(&evidence["image"]["image_bytes"]).unwrap()] {
                let mut invalid = evidence.clone();
                invalid["symbols"][symbol]["rva"] = Value::from(rva);
                assert!(parse_kernel(&invalid).is_err());
            }
        }
    }

    #[test]
    fn malformed_static_evidence_cannot_construct_a_profile() {
        let evidence: Value = serde_json::from_str(EVIDENCE).unwrap();
        for pointer in [
            "/fields/UniqueProcessId/offset",
            "/fields/ActiveProcessLinks/offset",
            "/types/_EPROCESS/bytes",
            "/fields/Pcb.DirectoryTableBase/eprocess_offset",
            "/list_fields/Blink/offset",
            "/pdb/dbi_age",
        ] {
            let mut malformed = evidence.clone();
            *malformed.pointer_mut(pointer).unwrap() = Value::from(u32::MAX);
            assert!(parse(&malformed, 0).is_err(), "accepted {pointer}");
        }
        for (pointer, value) in [
            ("/fields/Peb/offset", 0x2e4),
            ("/fields/WoW64Process/offset", 2112),
            ("/fields/ImageFileName/offset", 2100),
            ("/fields/ImageFileName/bytes", 16),
            ("/fields/SeAuditProcessCreationInfo.ImageFileName/eprocess_offset", 2108),
            ("/string_fields/Buffer/offset", 12),
            ("/types/_UNICODE_STRING/bytes", 12),
        ] {
            let mut malformed = evidence.clone();
            *malformed.pointer_mut(pointer).unwrap() = Value::from(value);
            assert!(parse_kernel(&malformed).is_err(), "accepted {pointer}");
        }
        let mut overlap = evidence.clone();
        overlap["fields"]["UniqueProcessId"]["offset"] =
            overlap["fields"]["ActiveProcessLinks"]["offset"].clone();
        assert!(parse(&overlap, 0).is_err());
    }

    #[test]
    fn file_verification_checks_both_exact_length_and_streamed_digest() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let bytes = std::fs::read(&path).unwrap();
        let hash: String =
            Sha256::digest(&bytes).iter().map(|byte| format!("{byte:02x}")).collect();
        let mut identity = json!({ "file_bytes": bytes.len(), "sha256": hash });
        assert!(verify_file(&path, &identity, "fixture").is_ok());
        identity["sha256"] = Value::String("0".repeat(64));
        assert!(verify_file(&path, &identity, "fixture").unwrap_err().contains("SHA-256"));
        identity["file_bytes"] = Value::from(bytes.len() + 1);
        assert!(verify_file(&path, &identity, "fixture").unwrap_err().contains("size"));
    }
}
