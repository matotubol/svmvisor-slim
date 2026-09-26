//! Strict command-line context and bounded offline process reads.

use std::{collections::BTreeMap, fs::OpenOptions, io::Write, path::PathBuf, process::ExitCode};

use svmvisor_hypervisor::memory::address::{PAGE_BYTES, is_canonical_48};
use svmvisor_hypervisor::reader::{
    paging::{PagingConfig, PagingError},
    process::{self, MAX_PROCESS_NODES, ProcessProfile, ProcessRequest},
    read::{self, MAX_READ_BYTES},
};
use svmvisor_live_reader::profile;

use crate::capture::image::CaptureImage;

const MAX_HEX_BYTES: usize = 256;
const USAGE: &str =
    "usage: cargo xtask capture --input <file> --format <raw|full-dump|bitmap-kernel>
  [--physical-base <PA> (required for raw, forbidden for dump formats)]
  --kernel <ntoskrnl.exe> --pdb <ntkrnlmp.pdb>
  --kernel-root <PML4-PA> --list-head <sentinel-VA> --physical-bits <32..52>
  --nxe <true|false> --page-1g <true|false> --max-nodes <1..4096>
  --pid <PID> --address <VA> --length <1..65536> (--output <new-file> | --hex)

Numbers are unsigned decimal or 0x-prefixed hexadecimal. Hex output is limited to 256 bytes.
Raw means one contiguous physical range. Full-dump accepts traditional AMD64 full dumps
(type 1); bitmap-kernel accepts AMD64 bitmap kernel dumps (type 6). Other variants are unsupported.
Context must be independently established for this capture: aligned PML4 physical root,
runtime PsActiveProcessHead sentinel VA (not its RVA or a pointer variable), and paging flags.
Only the built-in symbol-verified kernel/PDB profile is accepted. Matching external binaries
does not prove the capture belongs to them. Capture consistency remains caller-owned.
The capture is read-only; output must not exist. Partial reads write only the completed prefix.
Exit codes: 0 complete, 1 inspection/profile/I/O error, 2 arguments, 3 PID absent, 4 partial read.";

#[derive(Debug)]
struct CaptureOptions {
    input: PathBuf,
    format: CaptureFormat,
    kernel: PathBuf,
    pdb: PathBuf,
    config: PagingConfig,
    request: ProcessRequest,
    va: u64,
    length: usize,
    output: Option<PathBuf>,
}

impl CaptureOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut values = BTreeMap::new();
        let mut hex = false;
        let mut rest = args.iter();
        while let Some(arg) = rest.next() {
            if arg == "--hex" {
                if hex {
                    return Err("duplicate --hex".into());
                }
                hex = true;
                continue;
            }
            if !matches!(
                arg.as_str(),
                "--input"
                    | "--format"
                    | "--physical-base"
                    | "--kernel"
                    | "--pdb"
                    | "--kernel-root"
                    | "--list-head"
                    | "--physical-bits"
                    | "--nxe"
                    | "--page-1g"
                    | "--max-nodes"
                    | "--pid"
                    | "--address"
                    | "--length"
                    | "--output"
            ) {
                return Err(format!("unknown argument {arg}"));
            }
            let value = rest.next().ok_or_else(|| format!("{arg} needs a value"))?;
            if value.is_empty() || value.starts_with("--") {
                return Err(format!("{arg} needs a value"));
            }
            if values.insert(arg.as_str(), value.as_str()).is_some() {
                return Err(format!("duplicate {arg}"));
            }
        }
        let required = |key| values.get(key).copied().ok_or_else(|| format!("{key} is required"));
        let number = |key| parse_number(required(key)?).map_err(|error| format!("{key}: {error}"));
        let format = match required("--format")? {
            "raw" => CaptureFormat::Raw { physical_base: number("--physical-base")? },
            "full-dump" if !values.contains_key("--physical-base") => CaptureFormat::FullDump,
            "full-dump" => return Err("--physical-base is forbidden for full-dump".into()),
            "bitmap-kernel" if !values.contains_key("--physical-base") => {
                CaptureFormat::BitmapKernel
            }
            "bitmap-kernel" => return Err("--physical-base is forbidden for bitmap-kernel".into()),
            _ => return Err("--format must be raw, full-dump or bitmap-kernel".into()),
        };
        let physical_bits = u8::try_from(number("--physical-bits")?)
            .map_err(|_| "--physical-bits must be 32..52")?;
        let config = PagingConfig::new(
            physical_bits,
            parse_bool(required("--nxe")?)?,
            parse_bool(required("--page-1g")?)?,
        )
        .map_err(|_| "--physical-bits must be 32..52")?;
        let max_nodes = number("--max-nodes")?;
        if max_nodes == 0 || max_nodes > MAX_PROCESS_NODES as u64 {
            return Err(format!("--max-nodes must be 1..{MAX_PROCESS_NODES}"));
        }
        let length = number("--length")?;
        if length == 0 || length > MAX_READ_BYTES as u64 {
            return Err(format!("--length must be 1..{MAX_READ_BYTES}"));
        }
        let va = number("--address")?;
        let last = va.checked_add(length - 1).ok_or("virtual range overflows")?;
        if !is_canonical_48(va) || !is_canonical_48(last) {
            return Err("virtual range is not canonical for four-level paging".into());
        }
        let root_pa = number("--kernel-root")?;
        if root_pa & (PAGE_BYTES as u64 - 1) != 0 || root_pa >> physical_bits != 0 {
            return Err("--kernel-root must be an aligned PML4 PA within physical width".into());
        }
        let list_head_va = number("--list-head")?;
        if list_head_va == 0
            || list_head_va & 7 != 0
            || !is_canonical_48(list_head_va)
            || list_head_va.checked_add(15).is_none_or(|last| !is_canonical_48(last))
        {
            return Err("--list-head must be a nonzero aligned canonical sentinel VA".into());
        }
        let output = values.get("--output").map(PathBuf::from);
        if hex == output.is_some() {
            return Err("choose exactly one of --output or --hex".into());
        }
        if hex && length > MAX_HEX_BYTES as u64 {
            return Err(format!("--hex supports at most {MAX_HEX_BYTES} bytes"));
        }
        Ok(Self {
            input: PathBuf::from(required("--input")?),
            format,
            kernel: PathBuf::from(required("--kernel")?),
            pdb: PathBuf::from(required("--pdb")?),
            config,
            request: ProcessRequest {
                kernel_root_pa: root_pa,
                list_head_va,
                pid: number("--pid")?,
                max_nodes: max_nodes as usize,
            },
            va,
            length: length as usize,
            output,
        })
    }
}

#[derive(Debug)]
enum CaptureFormat {
    Raw { physical_base: u64 },
    FullDump,
    BitmapKernel,
}

pub(crate) fn command(args: &[String]) -> ExitCode {
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let options = match CaptureOptions::parse(args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("error: {error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result =
        profile::load(&options.kernel, &options.pdb).and_then(|profile| execute(&options, profile));
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute(options: &CaptureOptions, profile: ProcessProfile) -> Result<u8, String> {
    let mut image = match options.format {
        CaptureFormat::Raw { physical_base } => {
            CaptureImage::open_raw(&options.input, physical_base)
        }
        CaptureFormat::FullDump => CaptureImage::open_full_dump(&options.input),
        CaptureFormat::BitmapKernel => CaptureImage::open_bitmap_kernel_dump(&options.input),
    }
    .map_err(|error| error.to_string())?;
    if image.max_physical_address() >> options.config.physical_bits() != 0 {
        return Err("capture physical range exceeds declared physical width".into());
    }
    if let Some(metadata) = image.dump_metadata() {
        eprintln!(
            "dump_context=unverified source=header type={} major={} minor={} directory_table_base={:#x} ps_active_process_head={:#x} ps_loaded_module_list={:#x} runs={:?} pages={} bitmap_pages={:?}",
            metadata.dump_type,
            metadata.major_version,
            metadata.minor_version,
            metadata.directory_table_base,
            metadata.ps_active_process_head,
            metadata.ps_loaded_module_list,
            metadata.run_count,
            metadata.page_count,
            metadata.bitmap_pages,
        );
        eprintln!(
            "inspection_context=caller kernel_root_pa={:#x} list_head_va={:#x}; header metadata does not authenticate the kernel profile",
            options.request.kernel_root_pa, options.request.list_head_va,
        );
    }
    let mut backend_error = None;
    let mut read = |pa, bytes: &mut [u8]| {
        image.read(pa, bytes).map_err(|error| {
            backend_error = Some(error.to_string());
            PagingError::PhysicalRead
        })
    };
    let observation = process::find(options.config, profile, options.request, &mut read);
    let observation = match observation {
        Ok(Some(observation)) => observation,
        Ok(None) => {
            eprintln!("status=pid-absent pid={}", options.request.pid);
            return Ok(3);
        }
        Err(error) => {
            return Err(format!("process lookup failed: {error:?}; backend={backend_error:?}"));
        }
    };
    let mut bytes = vec![0; options.length];
    let report = read::read_virtual(
        options.config,
        observation.kernel_root_pa,
        options.va,
        &mut bytes,
        &mut read,
    );
    bytes.truncate(report.bytes_read);
    if let Some(path) = &options.output {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| format!("cannot create new output {}: {error}", path.display()))?;
        output
            .write_all(&bytes)
            .and_then(|()| output.flush())
            .map_err(|error| format!("output write failed (file may contain a prefix): {error}"))?;
    } else {
        for chunk in bytes.chunks(16) {
            println!(
                "{}",
                chunk.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" ")
            );
        }
    }
    eprintln!(
        "status={} pid={} eprocess_va={:#x} create_time={:?} root_pa={:#x} requested={} bytes_read={} error={:?} backend={:?}",
        if report.error.is_some() { "partial" } else { "complete" },
        observation.pid,
        observation.eprocess_va,
        observation.create_time,
        observation.kernel_root_pa,
        options.length,
        report.bytes_read,
        report.error,
        backend_error,
    );
    Ok(if report.error.is_some() { 4 } else { 0 })
}

pub(super) fn parse_number(value: &str) -> Result<u64, String> {
    let (digits, radix) = match value.strip_prefix("0x") {
        Some(digits) => (digits, 16),
        None => (value, 10),
    };
    if digits.is_empty()
        || !digits.bytes().all(|byte| match radix {
            16 => byte.is_ascii_hexdigit(),
            _ => byte.is_ascii_digit(),
        })
    {
        return Err("expected unsigned decimal or 0x-prefixed hexadecimal".into());
    }
    u64::from_str_radix(digits, radix).map_err(|_| "integer exceeds u64".into())
}

pub(super) fn parse_bool(value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err("paging flags must be true or false".into()),
    }
}

#[cfg(test)]
mod tests;
