//! Sparse capture display and a binary-plus-manifest export with preserved region offsets.

use std::{
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use svmvisor_live_reader::capture::{
    CaptureData, CaptureObservation, MAX_CAPTURE_BYTES, MAX_CAPTURE_SPANS,
};

/// The console view stays small even when the binary export contains a larger capture.
const MAX_DISPLAY_BYTES: usize = 64 * 1024;
const ZERO_BYTES: [u8; 4096] = [0; 4096];

/// Writes a new directory containing `memory.bin` and its authoritative `manifest.json`.
/// Region bytes occupy consecutive file ranges; each span retains its offset within its region.
/// Unreadable spans occupy zero placeholders that must never be interpreted as captured bytes.
/// A final manifest appears only after the data and temporary manifest have been flushed.
/// On failure the incomplete directory is retained for inspection; existing paths are refused.
pub fn export(observation: &CaptureObservation, directory: &Path) -> io::Result<()> {
    let total = validate(observation)?;
    fs::create_dir(directory)?;
    let mut output =
        OpenOptions::new().write(true).create_new(true).open(directory.join("memory.bin"))?;
    let mut hash = Sha256::new();
    for span in &observation.spans {
        match &span.data {
            CaptureData::Bytes { bytes, .. } => {
                output.write_all(bytes)?;
                hash.update(bytes);
            }
            CaptureData::Unreadable => {
                let mut remaining = span.length;
                while remaining != 0 {
                    let length = remaining.min(ZERO_BYTES.len());
                    output.write_all(&ZERO_BYTES[..length])?;
                    hash.update(&ZERO_BYTES[..length]);
                    remaining -= length;
                }
            }
        }
    }
    output.sync_all()?;
    let data_sha256 = hex(&hash.finalize());
    let manifest = manifest(observation, total, &data_sha256);
    let pending = directory.join("manifest.pending.json");
    let mut output = OpenOptions::new().write(true).create_new(true).open(&pending)?;
    serde_json::to_writer_pretty(&mut output, &manifest)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    drop(output);
    fs::rename(pending, directory.join("manifest.json"))
}

/// Formats up to 64 KiB, with `??` and `?` for unavailable hex and ASCII bytes.
pub fn dump(observation: &CaptureObservation) -> io::Result<String> {
    let total = validate(observation)?;
    if total > MAX_DISPLAY_BYTES {
        return Err(invalid("capture is too large for display; use binary export"));
    }
    let mut text = String::with_capacity(total.saturating_mul(6));
    for span in &observation.spans {
        for offset in (0..span.length).step_by(16) {
            let length = (span.length - offset).min(16);
            let address = span.address + offset as u64;
            // Formatting into a String cannot fail.
            write!(text, "  {address:016X}  ").unwrap();
            let bytes = match &span.data {
                CaptureData::Bytes { bytes, .. } => Some(&bytes[offset..offset + length]),
                CaptureData::Unreadable => None,
            };
            for index in 0..16 {
                match (index < length, bytes) {
                    (true, Some(bytes)) => {
                        // Formatting into a String cannot fail.
                        write!(text, "{:02X} ", bytes[index]).unwrap();
                    }
                    (true, None) => text.push_str("?? "),
                    (false, _) => text.push_str("   "),
                }
            }
            text.push(' ');
            for index in 0..length {
                text.push(match bytes {
                    Some(bytes) if bytes[index].is_ascii_graphic() || bytes[index] == b' ' => {
                        bytes[index] as char
                    }
                    Some(_) => '.',
                    None => '?',
                });
            }
            text.push('\n');
        }
    }
    Ok(text)
}

fn manifest(observation: &CaptureObservation, total: usize, data_sha256: &str) -> Value {
    let mut file_offset = 0usize;
    let regions: Vec<_> = observation
        .regions
        .iter()
        .enumerate()
        .map(|(index, region)| {
            let result = json!({
                "index": index,
                "address": format!("0x{:016x}", region.address),
                "length": region.length,
                "file_offset": file_offset,
            });
            file_offset += region.length;
            result
        })
        .collect();
    let mut file_offset = 0usize;
    let spans: Vec<_> = observation
        .spans
        .iter()
        .map(|span| {
            let (status, sha256) = match &span.data {
                CaptureData::Bytes { sha256, .. } => ("read", Some(hex(sha256))),
                CaptureData::Unreadable => ("unreadable", None),
            };
            let result = json!({
                "region": span.region,
                "region_offset": span.offset,
                "address": format!("0x{:016x}", span.address),
                "length": span.length,
                "file_offset": file_offset,
                "started_ns": span.started.as_nanos().to_string(),
                "elapsed_ns": span.elapsed.as_nanos().to_string(),
                "status": status,
                "sha256": sha256,
            });
            file_offset += span.length;
            result
        })
        .collect();
    json!({
        "format": "svmvisor.capture.v1",
        "semantics": "Live observations, not an atomic snapshot. Each span validates process identity independently.",
        "hole_policy": "Unreadable spans contain zero placeholders in memory.bin. Only spans with status=read are captured evidence; placeholders are unusable as memory contents.",
        "data_file": "memory.bin",
        "data_length": total,
        "data_sha256": data_sha256,
        "data_hash_scope": "Exact stored bytes including zero placeholders; valid memory hashes are attached only to read spans.",
        "pid": observation.pid,
        "created_windows_100ns": observation.created.to_string(),
        "started_unix_ms": observation.started_unix_ms,
        "elapsed_ns": observation.elapsed.as_nanos().to_string(),
        "calls": observation.calls,
        "hypercalls": observation.hypercalls,
        "regions": regions,
        "spans": spans,
    })
}

/// Public observation records can be constructed by callers. Refuse malformed ones before I/O.
fn validate(observation: &CaptureObservation) -> io::Result<usize> {
    if observation.regions.is_empty()
        || observation.regions.len() > MAX_CAPTURE_SPANS
        || observation.spans.is_empty()
        || observation.spans.len() > MAX_CAPTURE_SPANS
    {
        return Err(invalid("invalid capture region or span count"));
    }
    let mut total = 0usize;
    let mut spans = observation.spans.iter();
    for (index, region) in observation.regions.iter().enumerate() {
        total = total
            .checked_add(region.length)
            .filter(|&total| total <= MAX_CAPTURE_BYTES)
            .ok_or_else(|| invalid("capture exceeds the export byte limit"))?;
        if region.length == 0 || region.address.checked_add(region.length as u64 - 1).is_none() {
            return Err(invalid("invalid capture region"));
        }
        let mut offset = 0usize;
        while offset < region.length {
            let span = spans.next().ok_or_else(|| invalid("capture has unreported gaps"))?;
            if span.region != index
                || span.offset != offset
                || span.length == 0
                || span.address != region.address + offset as u64
                || span.length > region.length - offset
            {
                return Err(invalid("capture spans do not exactly cover their regions"));
            }
            if let CaptureData::Bytes { bytes, sha256 } = &span.data {
                if bytes.len() != span.length {
                    return Err(invalid("capture span length mismatch"));
                }
                let actual: [u8; 32] = Sha256::digest(bytes).into();
                if &actual != sha256 {
                    return Err(invalid("capture span SHA-256 mismatch"));
                }
            }
            offset += span.length;
        }
    }
    if spans.next().is_some() {
        return Err(invalid("capture has extra spans"));
    }
    Ok(total)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use svmvisor_live_reader::capture::{CaptureRegion, CaptureSpan};

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    fn observation() -> CaptureObservation {
        let data = |bytes: Vec<u8>| {
            let sha256 = Sha256::digest(&bytes).into();
            CaptureData::Bytes { bytes, sha256 }
        };
        CaptureObservation {
            pid: 42,
            created: 1234,
            started_unix_ms: 123,
            elapsed: Duration::from_millis(3),
            calls: 3,
            hypercalls: Some(9),
            regions: vec![CaptureRegion { address: 0x1ffe, length: 6 }],
            spans: vec![
                CaptureSpan {
                    region: 0,
                    offset: 0,
                    address: 0x1ffe,
                    length: 2,
                    started: Duration::ZERO,
                    elapsed: Duration::ZERO,
                    data: data(vec![0, 0]),
                },
                CaptureSpan {
                    region: 0,
                    offset: 2,
                    address: 0x2000,
                    length: 2,
                    started: Duration::ZERO,
                    elapsed: Duration::ZERO,
                    data: CaptureData::Unreadable,
                },
                CaptureSpan {
                    region: 0,
                    offset: 4,
                    address: 0x2002,
                    length: 2,
                    started: Duration::ZERO,
                    elapsed: Duration::ZERO,
                    data: data(b"OK".to_vec()),
                },
            ],
        }
    }

    fn directory() -> PathBuf {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/capture-tests");
        fs::create_dir_all(&root).unwrap();
        root.join(format!(
            "svmvisor-capture-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn export_preserves_holes_offsets_hashes_and_large_creation_identity() {
        let mut observation = observation();
        observation.created = u64::MAX;
        let directory = directory();
        export(&observation, &directory).unwrap();
        assert_eq!(fs::read(directory.join("memory.bin")).unwrap(), b"\0\0\0\0OK");
        let manifest: Value =
            serde_json::from_slice(&fs::read(directory.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["spans"][0]["status"], "read");
        assert_eq!(manifest["spans"][1]["status"], "unreadable");
        assert_eq!(manifest["spans"][1]["sha256"], Value::Null);
        assert_eq!(manifest["spans"][2]["file_offset"], 4);
        assert_eq!(manifest["spans"][2]["address"], "0x0000000000002002");
        assert_eq!(manifest["created_windows_100ns"], u64::MAX.to_string());
        assert_eq!(manifest["data_sha256"], hex(&Sha256::digest(b"\0\0\0\0OK")));
        assert!(!directory.join("manifest.pending.json").exists());
        assert_eq!(
            export(&observation, &directory).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        fs::remove_file(directory.join("memory.bin")).unwrap();
        fs::remove_file(directory.join("manifest.json")).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn display_does_not_turn_missing_bytes_into_zero_evidence() {
        let text = dump(&observation()).unwrap();
        assert!(text.contains("0000000000001FFE  00 00 "));
        assert!(text.contains("0000000000002000  ?? ?? "));
        assert!(text.contains("0000000000002002  4F 4B "));
        assert!(text.lines().nth(1).unwrap().ends_with("??"));
    }

    #[test]
    fn full_and_short_display_rows_keep_hex_and_ascii_columns() {
        let mut observation = observation();
        let bytes: Vec<u8> = (0..18).map(|index| b'A' + index).collect();
        let sha256 = Sha256::digest(&bytes).into();
        observation.regions = vec![CaptureRegion { address: 0x1000, length: bytes.len() }];
        observation.spans = vec![CaptureSpan {
            region: 0,
            offset: 0,
            address: 0x1000,
            length: bytes.len(),
            started: Duration::ZERO,
            elapsed: Duration::ZERO,
            data: CaptureData::Bytes { bytes, sha256 },
        }];
        assert_eq!(
            dump(&observation).unwrap(),
            "  0000000000001000  41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50  ABCDEFGHIJKLMNOP\n\
             \x20 0000000000001010  51 52                                            QR\n"
        );
        observation.spans[0].data = CaptureData::Unreadable;
        let text = dump(&observation).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.lines().next().unwrap().ends_with("????????????????"));
        assert_eq!(text.lines().nth(1).unwrap().len(), 71);
    }

    #[test]
    fn separate_regions_keep_explicit_file_to_virtual_address_mapping() {
        let mut observation = observation();
        observation.regions.push(CaptureRegion { address: 0x7000_0000, length: 1 });
        observation.spans.push(CaptureSpan {
            region: 1,
            offset: 0,
            address: 0x7000_0000,
            length: 1,
            started: Duration::ZERO,
            elapsed: Duration::ZERO,
            data: CaptureData::Unreadable,
        });
        assert_eq!(validate(&observation).unwrap(), 7);
        let manifest = manifest(&observation, 7, "hash");
        assert_eq!(manifest["regions"][1]["file_offset"], 6);
        assert_eq!(manifest["regions"][1]["address"], "0x0000000070000000");
        assert_eq!(manifest["spans"][3]["region"], 1);
        assert_eq!(manifest["spans"][3]["file_offset"], 6);
        assert_eq!(manifest["spans"][3]["region_offset"], 0);
    }

    #[test]
    fn display_and_export_refuse_unbounded_or_uncovered_records() {
        let mut observation = observation();
        observation.regions[0].length = MAX_CAPTURE_BYTES + 1;
        assert!(validate(&observation).is_err());
        observation.regions[0].length = MAX_DISPLAY_BYTES + 1;
        observation.spans = vec![CaptureSpan {
            region: 0,
            offset: 0,
            address: 0x1ffe,
            length: MAX_DISPLAY_BYTES + 1,
            started: Duration::ZERO,
            elapsed: Duration::ZERO,
            data: CaptureData::Unreadable,
        }];
        assert!(dump(&observation).is_err());
        observation.spans.clear();
        assert!(validate(&observation).is_err());
    }

    #[test]
    fn malformed_capture_is_refused_before_creating_output() {
        let mut observation = observation();
        observation.spans[2].offset = 3;
        let directory = directory();
        assert_eq!(
            export(&observation, &directory).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(!directory.exists());
        observation.spans[2].offset = 4;
        observation.spans[0].data = CaptureData::Bytes { bytes: vec![1, 2], sha256: [0; 32] };
        assert!(export(&observation, &directory).is_err());
        assert!(!directory.exists());
    }
}
