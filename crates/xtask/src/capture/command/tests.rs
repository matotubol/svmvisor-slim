use super::*;

use std::{
    env, fs,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use svmvisor_hypervisor::reader::process::ProcessLayoutEvidence;

use crate::capture::image::{bitmap_dump_fixture, full_dump_fixture};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct CommandFixture {
    directory: PathBuf,
    options: CaptureOptions,
    profile: ProcessProfile,
}

impl CommandFixture {
    fn new() -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let directory = env::temp_dir()
            .join(format!("svmvisor-capture-command-{}-{sequence}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let input = directory.join("image.raw");
        let output = directory.join("result.bin");
        let mut bytes = vec![0; 0xc000];
        for (pa, word) in [
            (0x1000, 0x2001u64),
            (0x2000, 0x81),
            (0x7000, 0x8001),
            (0x8000, 0x81),
            (0x3000, 0x4010),
            (0x3008, 0x4010),
            (0x4010, 0x3000),
            (0x4018, 0x3000),
            (0x4030, 42),
            (0x4040, 0x7000),
            (0x4050, 123456),
        ] {
            bytes[pa..pa + 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes[0xaffc..0xb004].copy_from_slice(b"CAPTURE!");
        fs::write(&input, bytes).unwrap();
        let options = CaptureOptions {
            input,
            format: CaptureFormat::Raw { physical_base: 0 },
            kernel: directory.join("kernel.exe"),
            pdb: directory.join("kernel.pdb"),
            config: PagingConfig::new(48, true, true).unwrap(),
            request: ProcessRequest {
                kernel_root_pa: 0x1000,
                list_head_va: 0x3000,
                pid: 42,
                max_nodes: 1,
            },
            va: 0xaffc,
            length: 8,
            output: Some(output),
        };
        let profile = ProcessProfile::new(ProcessLayoutEvidence {
            eprocess_bytes: 0x100,
            active_links_offset: 0x010,
            pid_offset: 0x030,
            create_time_offset: Some(0x050),
            directory_root_offset: 0x040,
            dtb_low_bits_mask: 0,
        })
        .unwrap();
        Self { directory, options, profile }
    }

    fn output(&self) -> &Path {
        self.options.output.as_deref().unwrap()
    }

    fn use_full_dump(&mut self, include_last_page: bool) {
        let bytes = fs::read(&self.options.input).unwrap();
        // Reverse physical order exercises the distinction between run order and file offset.
        let mut runs = vec![(0x7000, &bytes[0x7000..0xb000]), (0, &bytes[..0x7000])];
        if include_last_page {
            runs.push((0xb000, &bytes[0xb000..]));
        }
        let dump = full_dump_fixture(&runs, 0x1000, 0x3000);
        fs::write(&self.options.input, dump).unwrap();
        self.options.format = CaptureFormat::FullDump;
    }

    fn use_bitmap_dump(&mut self, include_last_page: bool) {
        let bytes = fs::read(&self.options.input).unwrap();
        let count = if include_last_page { 12 } else { 11 };
        let pages = bytes
            .chunks_exact(0x1000)
            .take(count)
            .enumerate()
            .map(|(index, page)| (index as u64 * 0x1000, page))
            .collect::<Vec<_>>();
        fs::write(&self.options.input, bitmap_dump_fixture(&pages, 12, 0x1000, 0x3000)).unwrap();
        self.options.format = CaptureFormat::BitmapKernel;
    }
}

impl Drop for CommandFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn arguments() -> Vec<String> {
    [
        "--input",
        "image.raw",
        "--format",
        "raw",
        "--physical-base",
        "0",
        "--kernel",
        "kernel.exe",
        "--pdb",
        "kernel.pdb",
        "--kernel-root",
        "0x1000",
        "--list-head",
        "0x3000",
        "--physical-bits",
        "48",
        "--nxe",
        "true",
        "--page-1g",
        "true",
        "--max-nodes",
        "1",
        "--pid",
        "42",
        "--address",
        "0xaffc",
        "--length",
        "8",
        "--output",
        "result.bin",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

#[test]
fn synthetic_file_discovery_and_target_read_write_exact_bytes() {
    let fixture = CommandFixture::new();
    let original = fs::read(&fixture.options.input).unwrap();
    assert_eq!(execute(&fixture.options, fixture.profile), Ok(0));
    assert_eq!(fs::read(fixture.output()).unwrap(), b"CAPTURE!");
    assert_eq!(fs::read(&fixture.options.input).unwrap(), original);
}

#[test]
fn bitmap_dump_discovery_and_read_use_present_pages() {
    let mut fixture = CommandFixture::new();
    fixture.use_bitmap_dump(true);
    let original = fs::read(&fixture.options.input).unwrap();
    assert_eq!(execute(&fixture.options, fixture.profile), Ok(0));
    assert_eq!(fs::read(fixture.output()).unwrap(), b"CAPTURE!");
    assert_eq!(fs::read(&fixture.options.input).unwrap(), original);
}

#[test]
fn bitmap_dump_omitted_page_returns_partial_without_zero_fill() {
    let mut fixture = CommandFixture::new();
    fixture.use_bitmap_dump(false);
    assert_eq!(execute(&fixture.options, fixture.profile), Ok(4));
    assert_eq!(fs::read(fixture.output()).unwrap(), b"CAPT");
}

#[test]
fn dump_format_selection_is_never_silently_reinterpreted() {
    let mut fixture = CommandFixture::new();
    fixture.use_bitmap_dump(true);
    fixture.options.format = CaptureFormat::FullDump;
    assert!(execute(&fixture.options, fixture.profile).is_err());
    assert!(!fixture.output().exists());
    let mut fixture = CommandFixture::new();
    fixture.use_full_dump(true);
    fixture.options.format = CaptureFormat::BitmapKernel;
    assert!(execute(&fixture.options, fixture.profile).is_err());
    assert!(!fixture.output().exists());
}

#[test]
fn full_dump_discovery_and_read_preserve_original_run_file_order() {
    let mut fixture = CommandFixture::new();
    fixture.use_full_dump(true);
    let original = fs::read(&fixture.options.input).unwrap();
    assert_eq!(execute(&fixture.options, fixture.profile), Ok(0));
    assert_eq!(fs::read(fixture.output()).unwrap(), b"CAPTURE!");
    assert_eq!(fs::read(&fixture.options.input).unwrap(), original);
}

#[test]
fn full_dump_missing_physical_page_outputs_only_completed_prefix() {
    let mut fixture = CommandFixture::new();
    fixture.use_full_dump(false);
    assert_eq!(execute(&fixture.options, fixture.profile), Ok(4));
    assert_eq!(fs::read(fixture.output()).unwrap(), b"CAPT");
}

#[test]
fn full_dump_high_run_is_checked_against_declared_physical_width() {
    let mut fixture = CommandFixture::new();
    let bytes = fs::read(&fixture.options.input).unwrap();
    let dump = full_dump_fixture(&[(0, &bytes), (1 << 48, &[0; 0x1000])], 0x1000, 0x3000);
    fs::write(&fixture.options.input, dump).unwrap();
    fixture.options.format = CaptureFormat::FullDump;
    assert_eq!(
        execute(&fixture.options, fixture.profile),
        Err("capture physical range exceeds declared physical width".into()),
    );
    assert!(!fixture.output().exists());
}

#[test]
fn malformed_full_dump_is_rejected_without_output() {
    let mut fixture = CommandFixture::new();
    fixture.use_full_dump(true);
    let length = fs::metadata(&fixture.options.input).unwrap().len();
    OpenOptions::new()
        .write(true)
        .open(&fixture.options.input)
        .unwrap()
        .set_len(length - 1)
        .unwrap();
    assert!(execute(&fixture.options, fixture.profile).is_err());
    assert!(!fixture.output().exists());
}

#[test]
fn full_dump_metadata_never_replaces_explicit_lookup_context() {
    let mut fixture = CommandFixture::new();
    fixture.use_full_dump(true);
    fixture.options.request.kernel_root_pa = 0x6000;
    assert!(execute(&fixture.options, fixture.profile).is_err());
    assert!(!fixture.output().exists());
}

#[test]
fn truncated_data_writes_only_completed_prefix_and_returns_partial_status() {
    let fixture = CommandFixture::new();
    OpenOptions::new().write(true).open(&fixture.options.input).unwrap().set_len(0xb000).unwrap();
    assert_eq!(execute(&fixture.options, fixture.profile), Ok(4));
    assert_eq!(fs::read(fixture.output()).unwrap(), b"CAPT");
}

#[test]
fn absent_pid_creates_no_output() {
    let mut fixture = CommandFixture::new();
    fixture.options.request.pid = 99;
    assert_eq!(execute(&fixture.options, fixture.profile), Ok(3));
    assert!(!fixture.output().exists());
}

#[test]
fn existing_output_and_input_aliases_are_never_overwritten() {
    let mut fixture = CommandFixture::new();
    fs::write(fixture.output(), b"preserved").unwrap();
    assert!(execute(&fixture.options, fixture.profile).is_err());
    assert_eq!(fs::read(fixture.output()).unwrap(), b"preserved");
    fixture.options.output = Some(fixture.options.input.clone());
    let original = fs::read(&fixture.options.input).unwrap();
    assert!(execute(&fixture.options, fixture.profile).is_err());
    assert_eq!(fs::read(&fixture.options.input).unwrap(), original);
}

#[test]
fn hard_link_output_alias_is_rejected() {
    let fixture = CommandFixture::new();
    fs::hard_link(&fixture.options.input, fixture.output()).unwrap();
    let original = fs::read(&fixture.options.input).unwrap();
    assert!(execute(&fixture.options, fixture.profile).is_err());
    assert_eq!(fs::read(&fixture.options.input).unwrap(), original);
}

#[test]
fn parser_requires_every_runtime_context_field_and_rejects_ambiguous_options() {
    let valid = arguments();
    assert!(CaptureOptions::parse(&valid).is_ok());
    for index in (0..valid.len()).step_by(2) {
        let mut missing = valid.clone();
        missing.drain(index..index + 2);
        assert!(CaptureOptions::parse(&missing).is_err(), "accepted missing {}", valid[index]);
    }
    for extra in [vec!["--pid", "99"], vec!["--hex"], vec!["--unknown", "1"]] {
        let mut duplicate = valid.clone();
        duplicate.extend(extra.into_iter().map(String::from));
        assert!(CaptureOptions::parse(&duplicate).is_err());
    }
}

#[test]
fn full_dump_requires_explicit_context_and_forbids_raw_physical_base() {
    let mut args = arguments();
    let format = args.iter().position(|arg| arg == "--format").unwrap();
    args[format + 1] = "full-dump".into();
    assert!(CaptureOptions::parse(&args).unwrap_err().contains("forbidden"));
    let base = args.iter().position(|arg| arg == "--physical-base").unwrap();
    args.drain(base..base + 2);
    assert!(matches!(CaptureOptions::parse(&args).unwrap().format, CaptureFormat::FullDump));
    for flag in ["--kernel-root", "--list-head", "--physical-bits", "--nxe", "--page-1g"] {
        let mut missing = args.clone();
        let index = missing.iter().position(|arg| arg == flag).unwrap();
        missing.drain(index..index + 2);
        assert!(CaptureOptions::parse(&missing).is_err(), "accepted missing {flag}");
    }
}

#[test]
fn bitmap_dump_requires_explicit_context_and_forbids_raw_physical_base() {
    let mut args = arguments();
    let format = args.iter().position(|arg| arg == "--format").unwrap();
    args[format + 1] = "bitmap-kernel".into();
    assert!(CaptureOptions::parse(&args).unwrap_err().contains("forbidden"));
    let base = args.iter().position(|arg| arg == "--physical-base").unwrap();
    args.drain(base..base + 2);
    assert!(matches!(CaptureOptions::parse(&args).unwrap().format, CaptureFormat::BitmapKernel));
    for flag in ["--kernel-root", "--list-head", "--physical-bits", "--nxe", "--page-1g"] {
        let mut missing = args.clone();
        let index = missing.iter().position(|arg| arg == flag).unwrap();
        missing.drain(index..index + 2);
        assert!(CaptureOptions::parse(&missing).is_err(), "accepted missing {flag}");
    }
}

#[test]
fn parser_rejects_overflow_bounds_and_noncanonical_context() {
    for (flag, value) in [
        ("--length", "65537"),
        ("--length", "0"),
        ("--max-nodes", "4097"),
        ("--max-nodes", "0"),
        ("--physical-bits", "53"),
        ("--kernel-root", "0x1001"),
        ("--kernel-root", "0x1000000000000"),
        ("--list-head", "0"),
        ("--address", "0x800000000000"),
        ("--address", "0xffffffffffffffff"),
        ("--pid", "18446744073709551616"),
        ("--pid", "-1"),
        ("--pid", "+1"),
        ("--pid", "0x"),
        ("--nxe", "yes"),
        ("--format", "dump"),
    ] {
        let mut malformed = arguments();
        let index = malformed.iter().position(|arg| arg == flag).unwrap();
        malformed[index + 1] = value.into();
        assert!(CaptureOptions::parse(&malformed).is_err(), "accepted {flag}={value}");
    }
}

#[test]
fn hex_output_is_exclusive_and_bounded() {
    let mut args = arguments();
    args.truncate(args.len() - 2);
    args.push("--hex".into());
    assert!(CaptureOptions::parse(&args).is_ok());
    let length = args.iter().position(|arg| arg == "--length").unwrap();
    args[length + 1] = "257".into();
    assert!(CaptureOptions::parse(&args).is_err());
    args[length + 1] = "256".into();
    assert!(CaptureOptions::parse(&args).is_ok());
    args.push("--hex".into());
    assert!(CaptureOptions::parse(&args).is_err());
}

#[test]
fn shipping_command_rejects_wrong_kernel_identity_before_creating_output() {
    let fixture = CommandFixture::new();
    fs::write(&fixture.options.kernel, b"not the pinned kernel").unwrap();
    fs::write(&fixture.options.pdb, b"not the pinned PDB").unwrap();
    let mut args = arguments();
    for (flag, path) in [
        ("--input", &fixture.options.input),
        ("--kernel", &fixture.options.kernel),
        ("--pdb", &fixture.options.pdb),
        ("--output", fixture.options.output.as_ref().unwrap()),
    ] {
        let index = args.iter().position(|arg| arg == flag).unwrap();
        args[index + 1] = path.to_str().unwrap().into();
    }
    assert_eq!(command(&args), ExitCode::FAILURE);
    assert!(!fixture.output().exists());
}
