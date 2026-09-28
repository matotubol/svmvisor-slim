//! Bind supplied kernel/PDB files to the recorded static layout evidence.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use serde_json::Value;
use sha2::{Digest, Sha256};
use svmvisor_hypervisor::reader::process::{ProcessLayoutEvidence, ProcessProfile};

use crate::config::Config;

const EVIDENCE: &str = include_str!("../../hypervisor/profiles/ntoskrnl-26100.9457.json");
const HASH_BUFFER_BYTES: usize = 64 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 1024 * 1024;
const MAX_PE_OFFSET: u32 = 4096;
const OPTIONAL_BYTES: usize = 240;
const MAX_DEBUG_ENTRIES: u32 = 64;
const MAX_CODEVIEW_BYTES: u32 = 1024;

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

/// Select explicit local evidence, or keep the embedded profile when none was requested.
/// This performs only local file reads; live kernel validation remains part of discovery.
pub(crate) fn load_config(config: &Config) -> Result<KernelProfile, String> {
    match &config.profile {
        Some(path) => {
            let evidence = read_evidence(path)?;
            load_evidence(&config.kernel, &config.pdb, &evidence)
        }
        None => load_kernel(&config.kernel, &config.pdb),
    }
}

pub(crate) fn load_kernel(kernel: &Path, pdb: &Path) -> Result<KernelProfile, String> {
    let evidence: Value = serde_json::from_str(EVIDENCE)
        .map_err(|error| format!("recorded kernel evidence is malformed: {error}"))?;
    load_evidence(kernel, pdb, &evidence)
}

fn read_evidence(path: &Path) -> Result<Value, String> {
    let file =
        File::open(path).map_err(|error| format!("open profile {}: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| format!("inspect profile: {error}"))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_EVIDENCE_BYTES {
        return Err("profile must be a nonempty regular file of at most 1 MiB".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_EVIDENCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read profile: {error}"))?;
    if bytes.len() as u64 != metadata.len() {
        return Err("profile changed length during reading".into());
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("profile JSON is malformed: {error}"))
}

fn load_evidence(kernel: &Path, pdb: &Path, evidence: &Value) -> Result<KernelProfile, String> {
    // The recorded symbols establish a field location, not a tagged storage encoding.
    // Require an already aligned stored root; do not infer which low bits are meaningful.
    let profile = parse_kernel(evidence)?;
    let mut image = verify_file(kernel, &evidence["image"], "kernel")?;
    verify_image(&mut image, &profile)?;
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
        || number(&evidence["pdb"]["info_age"])? < number(&evidence["pdb"]["dbi_age"])?
        || evidence["pdb"]["private_symbols_stripped"].as_bool() != Some(true)
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

/// Check the supplied PE itself, so editable evidence cannot merely claim a different identity.
/// These file reads use raw section offsets; current-boot validation reads the mapped image.
fn verify_image(file: &mut File, profile: &KernelProfile) -> Result<(), String> {
    let expected = profile.identity();
    let mut dos = [0; 64];
    read_at(file, 0, &mut dos)?;
    let offset = read_u32(&dos, 60);
    if dos[..2] != *b"MZ" || !(64..=MAX_PE_OFFSET).contains(&offset) {
        return Err("invalid kernel DOS header".into());
    }
    let mut nt = [0; 24 + OPTIONAL_BYTES];
    read_at(file, u64::from(offset), &mut nt)?;
    let optional = &nt[24..];
    let count = read_u16(&nt, 6);
    let headers_bytes = read_u32(optional, 60);
    let sections_offset = u64::from(offset) + nt.len() as u64;
    if nt[..4] != *b"PE\0\0"
        || read_u16(&nt, 4) != expected.machine
        || !(1..=96).contains(&count)
        || read_u32(&nt, 8) != expected.timestamp
        || usize::from(read_u16(&nt, 20)) != OPTIONAL_BYTES
        || read_u16(optional, 0) != 0x020b
        || read_u32(optional, 56) != expected.image_bytes
        || read_u32(optional, 64) != expected.checksum
        || read_u32(optional, 108) != 16
        || headers_bytes > expected.image_bytes
        || sections_offset + u64::from(count) * 40 > u64::from(headers_bytes)
    {
        return Err("kernel PE identity does not match the recorded profile".into());
    }
    let mut sections = vec![0; usize::from(count) * 40];
    read_at(file, sections_offset, &mut sections)?;
    let mut anchors = [false; 2];
    for section in sections.chunks_exact(40) {
        let rva = read_u32(section, 12);
        let length = read_u32(section, 8);
        let end = u64::from(rva) + u64::from(length);
        if end > u64::from(expected.image_bytes) || (length != 0 && rva < headers_bytes) {
            return Err("kernel section exceeds the recorded image extent".into());
        }
        for (index, &anchor) in profile.syscall_rvas().iter().enumerate() {
            if anchor >= rva && u64::from(anchor) < end {
                if anchors[index] || read_u32(section, 36) & 0x2000_0000 == 0 {
                    return Err("kernel syscall anchor is not uniquely executable".into());
                }
                anchors[index] = true;
            }
        }
    }
    if anchors.contains(&false) {
        return Err("kernel syscall anchor is outside executable sections".into());
    }
    let debug_rva = read_u32(optional, 160);
    let debug_bytes = read_u32(optional, 164);
    if debug_bytes == 0
        || debug_bytes % 28 != 0
        || debug_bytes / 28 > MAX_DEBUG_ENTRIES
        || debug_rva.checked_add(debug_bytes).is_none_or(|end| end > expected.image_bytes)
    {
        return Err("invalid kernel debug directory size".into());
    }
    let debug_offset = image_offset(&sections, headers_bytes, debug_rva, debug_bytes)?;
    let mut found = false;
    for index in 0..debug_bytes / 28 {
        let mut entry = [0; 28];
        read_at(file, debug_offset + u64::from(index) * 28, &mut entry)?;
        if read_u32(&entry, 12) != 2 {
            continue;
        }
        let length = read_u32(&entry, 16);
        if found || !(25..=MAX_CODEVIEW_BYTES).contains(&length) {
            return Err("ambiguous or invalid kernel CodeView record".into());
        }
        let record_rva = read_u32(&entry, 20);
        if record_rva.checked_add(length).is_none_or(|end| end > expected.image_bytes) {
            return Err("kernel CodeView record exceeds image extent".into());
        }
        let record_offset = image_offset(&sections, headers_bytes, record_rva, length)?;
        if record_offset != u64::from(read_u32(&entry, 24)) {
            return Err("kernel CodeView file and image locations disagree".into());
        }
        let mut record = [0; MAX_CODEVIEW_BYTES as usize];
        read_at(file, record_offset, &mut record[..length as usize])?;
        if record[..4] != *b"RSDS"
            || record[4..20] != expected.codeview_guid
            || read_u32(&record, 20) != expected.codeview_age
            || !record[24..length as usize].contains(&0)
        {
            return Err("kernel CodeView identity does not match the recorded profile".into());
        }
        found = true;
    }
    if !found {
        return Err("kernel has no CodeView identity".into());
    }
    Ok(())
}

fn image_offset(sections: &[u8], headers_bytes: u32, rva: u32, length: u32) -> Result<u64, String> {
    let mut found =
        (u64::from(rva) + u64::from(length) <= u64::from(headers_bytes)).then_some(u64::from(rva));
    for section in sections.chunks_exact(40) {
        let Some(delta) = rva.checked_sub(read_u32(section, 12)) else { continue };
        if u64::from(delta) + u64::from(length) <= u64::from(read_u32(section, 16)) {
            if found.is_some() {
                return Err("kernel debug data has ambiguous section mappings".into());
            }
            found = Some(u64::from(read_u32(section, 20)) + u64::from(delta));
        }
    }
    found.ok_or_else(|| "kernel debug data is outside initialized image bytes".into())
}

fn read_at(file: &mut File, offset: u64, bytes: &mut [u8]) -> Result<(), String> {
    file.seek(SeekFrom::Start(offset)).map_err(|error| format!("seek kernel PE: {error}"))?;
    file.read_exact(bytes).map_err(|error| format!("read kernel PE: {error}"))
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

fn verify_file(path: &Path, identity: &Value, label: &str) -> Result<File, String> {
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
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        env, fs,
        path::PathBuf,
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde_json::json;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct ProfileFiles {
        directory: PathBuf,
        evidence: Value,
        image: Vec<u8>,
    }

    impl ProfileFiles {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let directory =
                env::temp_dir().join(format!("svmvisor-profile-{}-{sequence}", process::id()));
            fs::create_dir(&directory).unwrap();
            let mut evidence: Value = serde_json::from_str(EVIDENCE).unwrap();
            evidence["image"]["codeview"]["guid"] = json!("00112233-4455-6677-8899-AABBCCDDEEFF");
            evidence["pdb"]["guid"] = evidence["image"]["codeview"]["guid"].clone();
            evidence["fields"]["CreateTime"]["offset"] = json!(0x2a0);
            let identity = parse_kernel(&evidence).unwrap().identity;
            let mut image = vec![0; 1024];
            image[..2].copy_from_slice(b"MZ");
            image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
            image[0x80..0x84].copy_from_slice(b"PE\0\0");
            image[0x84..0x86].copy_from_slice(&identity.machine.to_le_bytes());
            image[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
            image[0x88..0x8c].copy_from_slice(&identity.timestamp.to_le_bytes());
            image[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
            image[0x98..0x9a].copy_from_slice(&0x020bu16.to_le_bytes());
            for (offset, value) in [
                (0xd0, identity.image_bytes),
                (0xd4, 0x200),
                (0xd8, identity.checksum),
                (0x104, 16),
                (0x138, 0x1000),
                (0x13c, 28),
                (0x190, identity.image_bytes - 0x1000),
                (0x194, 0x1000),
                (0x198, 0x200),
                (0x19c, 0x200),
                (0x1ac, 0x2000_0000),
                (0x20c, 2),
                (0x210, 25),
                (0x214, 0x1040),
                (0x218, 0x240),
            ] {
                image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            image[0x240..0x244].copy_from_slice(b"RSDS");
            image[0x244..0x254].copy_from_slice(&identity.codeview_guid);
            image[0x254..0x258].copy_from_slice(&identity.codeview_age.to_le_bytes());
            Self { directory, evidence, image }
        }

        fn save(&mut self) -> Config {
            let kernel = self.directory.join("kernel.exe");
            let pdb = self.directory.join("kernel.pdb");
            let profile = self.directory.join("profile.json");
            let pdb_bytes = b"caller-owned PDB fixture";
            for (label, bytes) in [("image", self.image.as_slice()), ("pdb", pdb_bytes.as_slice())]
            {
                self.evidence[label]["file_bytes"] = json!(bytes.len());
                let hash: String =
                    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect();
                self.evidence[label]["sha256"] = json!(hash);
            }
            fs::write(&kernel, &self.image).unwrap();
            fs::write(&pdb, pdb_bytes).unwrap();
            fs::write(&profile, serde_json::to_vec(&self.evidence).unwrap()).unwrap();
            Config::new(kernel, pdb).profile(profile)
        }
    }

    impl Drop for ProfileFiles {
        fn drop(&mut self) {
            for name in ["kernel.exe", "kernel.pdb", "profile.json"] {
                let _ = fs::remove_file(self.directory.join(name));
            }
            let _ = fs::remove_dir(&self.directory);
        }
    }

    #[test]
    fn external_profile_selects_its_verified_identity_and_offsets() {
        let mut files = ProfileFiles::new();
        let config = files.save();
        let profile = load_config(&config).unwrap();
        assert_eq!(profile.process().layout().create_time_offset, Some(0x2a0));
        assert_ne!(
            profile.identity().codeview_guid,
            KernelProfile::fixture().identity().codeview_guid
        );
        assert!(load_config(&Config::new(&config.kernel, &config.pdb)).is_err());
    }

    #[test]
    fn external_profile_cannot_claim_another_pe_identity_with_valid_hashes() {
        for offset in [0x84, 0x88, 0xd0, 0xd8, 0x244, 0x254] {
            let mut files = ProfileFiles::new();
            files.image[offset] ^= 1;
            let config = files.save();
            let error = load_config(&config).unwrap_err();
            assert!(error.contains("identity"), "offset {offset:x}: {error}");
        }
    }

    #[test]
    fn external_profile_preserves_hash_schema_and_layout_checks() {
        let mut files = ProfileFiles::new();
        let config = files.save();
        fs::write(&config.pdb, b"same-size wrong fixture!").unwrap();
        assert!(load_config(&config).unwrap_err().contains("SHA-256"));
        for pointer in ["/schema_version", "/pdb/dbi_age", "/fields/ActiveProcessLinks/offset"] {
            let mut files = ProfileFiles::new();
            *files.evidence.pointer_mut(pointer).unwrap() = json!(u32::MAX);
            assert!(load_config(&files.save()).is_err(), "accepted {pointer}");
        }
    }

    #[test]
    fn external_profile_rejects_malformed_and_oversized_evidence_without_fallback() {
        let mut files = ProfileFiles::new();
        let config = files.save();
        let path = config.profile.as_ref().unwrap();
        fs::write(path, b"{invalid JSON}").unwrap();
        assert!(load_config(&config).unwrap_err().contains("JSON"));
        let oversized = File::create(path).unwrap();
        oversized.set_len(MAX_EVIDENCE_BYTES + 1).unwrap();
        drop(oversized);
        assert!(load_config(&config).unwrap_err().contains("1 MiB"));
        fs::remove_file(path).unwrap();
        assert!(load_config(&config).unwrap_err().contains("open profile"));
    }

    #[test]
    fn external_profile_rejects_ambiguous_codeview_and_nonexecutable_anchors() {
        let mut files = ProfileFiles::new();
        files.image[0x13c..0x140].copy_from_slice(&56u32.to_le_bytes());
        files.image.copy_within(0x200..0x21c, 0x21c);
        assert!(load_config(&files.save()).unwrap_err().contains("ambiguous"));
        let mut files = ProfileFiles::new();
        files.image[0x1ac..0x1b0].fill(0);
        assert!(load_config(&files.save()).unwrap_err().contains("executable"));
        for offset in [0x138, 0x214] {
            let mut files = ProfileFiles::new();
            files.image[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(load_config(&files.save()).is_err());
        }
    }

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
