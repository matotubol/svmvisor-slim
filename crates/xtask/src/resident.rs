//! Build a raw resident payload, audit its complete linked code, then its DXE
//! shim. No firmware execution. Output directories are fresh and retain
//! failure logs.

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use sha2::{Digest, Sha256};

use crate::{audit, json::Value, relocations};

/// Files and directories whose exact bytes define a resident build.
const SOURCE_FILES: [&str; 4] =
    ["Cargo.toml", "Cargo.lock", ".cargo/config.toml", "rust-toolchain.toml"];
const SKIPPED_DIRECTORIES: [&str; 2] = ["target", "__pycache__"];
const PRODUCER: PayloadProducer = PayloadProducer {
    manifest: "crates/hypervisor/Cargo.toml",
    archive: "libsvmvisor_hypervisor.a",
    linker_script: "crates/hypervisor/payload.ld",
    assembly_directory: "crates/hypervisor/src/firmware/native/resident",
    assembly_units: &["runtime", "nmi", "fault"],
    source_directories: &["crates/card-abi", "crates/hypervisor", "crates/xtask"],
    driver: "driver.efi",
};

/// Reviewed inputs to the raw payload producer, separate from DXE delivery.
/// The producer retains the actual interrupt/startup backend and its mandatory audits.
struct PayloadProducer {
    manifest: &'static str,
    archive: &'static str,
    linker_script: &'static str,
    assembly_directory: &'static str,
    assembly_units: &'static [&'static str],
    source_directories: &'static [&'static str],
    driver: &'static str,
}

struct Build {
    root: PathBuf,
    out: PathBuf,
}

impl Build {
    /// Run one tool from the repository root; `<name>.log` keeps its merged
    /// stdout and stderr whether or not it succeeds.
    fn command(
        &self,
        args: &[&OsStr],
        name: &str,
        env: &[(&str, &OsStr)],
    ) -> Result<String, String> {
        let tool = args[0].to_string_lossy();
        let executable = which(&tool).ok_or(format!("missing tool {tool}"))?;
        let log = self.out.join(format!("{name}.log"));
        let sink = io(fs::File::create(&log), "create", &log)?;
        let temporary = process_temp(&self.root, name)?;
        let status = Command::new(&executable)
            .args(&args[1..])
            .current_dir(&self.root)
            .envs(env.iter().copied())
            .env("TEMP", &temporary)
            .env("TMP", &temporary)
            .stdin(Stdio::null())
            .stdout(io(sink.try_clone(), "create", &log)?)
            .stderr(sink)
            .status()
            .map_err(|error| format!("{name}: cannot run {}: {error}", executable.display()))?;
        let output =
            String::from_utf8_lossy(&io(fs::read(&log), "read", &log)?).replace("\r\n", "\n");
        if !status.success() {
            let tail: String = {
                let characters: Vec<char> = output.chars().collect();
                characters[characters.len().saturating_sub(6000)..].iter().collect()
            };
            let code = status.code().map_or("unknown".to_string(), |code| code.to_string());
            return Err(format!("{name} exit {code}\n{tail}"));
        }
        Ok(output)
    }
}

/// Each build/verification invocation owns fresh scratch space under target.
/// Retain it with the evidence instead of sharing the user's global TEMP.
pub(crate) fn process_temp(root: &Path, label: &str) -> Result<PathBuf, String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = root.join("target").join("process-temporary");
    io(fs::create_dir_all(&parent), "create", &parent)?;
    let label: String = label.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
    for _ in 0..128 {
        let suffix = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("{label}-{}-{suffix}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("create {}: {error}", path.display())),
        }
    }
    Err("could not allocate fresh process temporary directory".into())
}

/// Build the one supported native profile: SMP guest startup behind the
/// successful-EBS interposer, with the shared allocation/bootstrap DXE and
/// runtime audits and the platform-specific below-1GiB runtime allocation.
/// Reader and entry-trial admission remain disabled until a protected service exists.
pub fn build(out: &Path) -> Result<(), String> {
    let producer = &PRODUCER;
    let root = root();
    let out = io(std::path::absolute(out), "resolve", out)?;
    if let Some(parent) = out.parent() {
        io(fs::create_dir_all(parent), "create", parent)?;
    }
    // Fresh output only: an existing directory is an error, never reused.
    io(fs::create_dir(&out), "create fresh output directory", &out)?;
    let manifest = producer_sources(&root, producer)?;
    let manifest_path = out.join("source-manifest.json");
    io(fs::write(&manifest_path, manifest_json(&manifest)), "write", &manifest_path)?;
    for (name, hash) in &manifest {
        let destination = out.join("source").join(name);
        let parent = destination.parent().unwrap();
        io(fs::create_dir_all(parent), "create", parent)?;
        copy(&root.join(name), &destination)?;
        if &sha(&destination)? != hash {
            return Err(format!("source changed during snapshot: {name}"));
        }
    }
    let build = Build { root: root.clone(), out: out.clone() };
    let path = |relative: &str| root.join(relative).into_os_string();
    let artifact = |name: &str| out.join(name).into_os_string();
    let target = out.join("cargo-payload");
    let resident = "crates/hypervisor/src/firmware/native/resident";

    let payload_manifest = path(producer.manifest);
    let mut payload_args: Vec<&OsStr> = vec![
        "cargo".as_ref(),
        "rustc".as_ref(),
        "--manifest-path".as_ref(),
        &payload_manifest,
        "--locked".as_ref(),
        "--no-default-features".as_ref(),
        "--lib".as_ref(),
        "--crate-type".as_ref(),
        "staticlib".as_ref(),
        "--features".as_ref(),
        "resident-runtime".as_ref(),
        "--target".as_ref(),
        "x86_64-unknown-none".as_ref(),
        "--target-dir".as_ref(),
        target.as_os_str(),
        "--release".as_ref(),
    ];
    payload_args.extend([
        OsStr::new("--"),
        OsStr::new("-C"),
        OsStr::new("opt-level=2"),
        OsStr::new("-C"),
        OsStr::new("codegen-units=1"),
        OsStr::new("-C"),
        OsStr::new("relocation-model=static"),
        OsStr::new("-C"),
        OsStr::new("code-model=small"),
    ]);
    build.command(&payload_args, "payload-cargo", &[])?;
    copy(
        &target.join("x86_64-unknown-none/release").join(producer.archive),
        &out.join("payload.a"),
    )?;
    let mut objects = Vec::new();
    for name in producer.assembly_units {
        let source = path(&format!("{}/{name}.S", producer.assembly_directory));
        let object = artifact(&format!("{name}.o"));
        build.command(
            &[
                "clang".as_ref(),
                "--target=x86_64-unknown-none".as_ref(),
                "-c".as_ref(),
                &source,
                "-o".as_ref(),
                &object,
            ],
            &format!("{name}-compile"),
            &[],
        )?;
        objects.push(object);
    }
    let (script, elf, image, package) = (
        path(producer.linker_script),
        artifact("payload.elf"),
        artifact("payload.bin"),
        out.join("payload.reloc"),
    );
    let mut link_args: Vec<&OsStr> = vec![
        "ld.lld".as_ref(),
        "-m".as_ref(),
        "elf_x86_64".as_ref(),
        "--gc-sections".as_ref(),
        "--emit-relocs".as_ref(),
        "-T".as_ref(),
        &script,
    ];
    link_args.extend(objects.iter().map(OsString::as_os_str));
    let archive = artifact("payload.a");
    link_args.extend([archive.as_os_str(), "-o".as_ref(), elf.as_os_str()]);
    build.command(&link_args, "payload-link", &[])?;
    build.command(
        &["llvm-objcopy".as_ref(), "-O".as_ref(), "binary".as_ref(), &elf, &image],
        "payload-flat",
        &[],
    )?;

    let relocation_log = out.join("payload-relocations.log");
    let packaged = relocations::package(
        &io(fs::read(&elf), "read", Path::new(&elf))?,
        &io(fs::read(&image), "read", Path::new(&image))?,
    );
    let message = match &packaged {
        Ok(bytes) => format!(
            "Packaged {} runtime relocations: {}\n",
            relocations::relocation_count(bytes),
            package.display()
        ),
        Err(error) => format!("{error}\n"),
    };
    io(fs::write(&relocation_log, &message), "write", &relocation_log)?;
    let packaged = packaged.map_err(|error| format!("payload-relocations: {error}"))?;
    io(fs::write(&package, packaged), "write", &package)?;

    let undefined = build.command(
        &["llvm-nm".as_ref(), "--undefined-only".as_ref(), &elf],
        "undefined",
        &[],
    )?;
    if !undefined.trim().is_empty() {
        return Err("resident payload has external symbol dependencies".into());
    }
    let symbols = build.command(
        &["llvm-nm".as_ref(), "--defined-only".as_ref(), "--demangle".as_ref(), &elf],
        "symbols",
        &[],
    )?;
    audit_minimal_symbols(&symbols)?;
    audit_retired_services(&symbols)?;
    let text = build.command(
        &["llvm-objdump".as_ref(), "-d".as_ref(), "--no-show-raw-insn".as_ref(), &elf],
        "disassembly",
        &[],
    )?;
    let debug_reset_audit = audit::audit_debug_reset(&text)?;
    let entry_capture_audit = audit::audit_entry_capture(&text)?;
    let tsc_ratio_audit = audit::audit_tsc_ratio_init(&text)?;
    let msr_capture_audit = audit::audit_msr_capture(&text)?;
    let host_fault_audit = audit::audit_host_fault(&text)?;
    let count = audit::audit_extended_state(&text)?;

    let target = out.join("cargo-dxe");
    build.command(
        &[
            "cargo".as_ref(),
            "build".as_ref(),
            "--locked".as_ref(),
            "--no-default-features".as_ref(),
            "-p".as_ref(),
            "svmvisor-hypervisor".as_ref(),
            "--bin".as_ref(),
            "svmvisor-hypervisor".as_ref(),
            "--target".as_ref(),
            "x86_64-unknown-uefi".as_ref(),
            "--target-dir".as_ref(),
            target.as_os_str(),
            "--release".as_ref(),
        ],
        "dxe-cargo",
        &[("SVMVISOR_RESIDENT_PAYLOAD", package.as_os_str())],
    )?;
    let driver = out.join(producer.driver);
    copy(&target.join("x86_64-unknown-uefi/release/svmvisor-hypervisor.efi"), &driver)?;
    audit::audit_runtime_driver(&io(fs::read(&driver), "read", &driver)?)?;

    let object = out.join("physical-audit.obj");
    build.command(
        &[
            "clang".as_ref(),
            "--target=x86_64-pc-windows-msvc".as_ref(),
            "-c".as_ref(),
            &path(&format!("{resident}/physical.S")),
            "-o".as_ref(),
            object.as_os_str(),
        ],
        "physical-audit-compile",
        &[],
    )?;
    let listing = build.command(
        &["llvm-objdump".as_ref(), "-t".as_ref(), "-r".as_ref(), object.as_os_str()],
        "physical-audit-relocations",
        &[],
    )?;
    let bootstrap_audit =
        audit::audit_copied_ap_wait(&io(fs::read(&object), "read", &object)?, &listing)?;
    let boot_object = artifact("boot-audit.obj");
    build.command(
        &[
            "clang".as_ref(),
            "--target=x86_64-pc-windows-msvc".as_ref(),
            "-c".as_ref(),
            &path(&format!("{resident}/boot.S")),
            "-o".as_ref(),
            &boot_object,
        ],
        "boot-audit-compile",
        &[],
    )?;
    build.command(
        &["llvm-objdump".as_ref(), "-d".as_ref(), "-r".as_ref(), &boot_object],
        "boot-audit-disassembly",
        &[],
    )?;

    if producer_sources(&root, producer)? != manifest {
        return Err("source changed during build; retry from a stable snapshot".into());
    }
    let mut artifacts = BTreeMap::new();
    for entry in io(fs::read_dir(&out), "list", &out)? {
        let entry = io(entry, "list", &out)?;
        if io(fs::metadata(entry.path()), "inspect", &entry.path())?.is_file() {
            artifacts.insert(
                entry.file_name().to_string_lossy().into_owned(),
                Value::Str(sha(&entry.path())?),
            );
        }
    }
    // verify-resident-build.py requires these fixed profile fields.
    let mut result = vec![
        ("entry_trial".to_string(), Value::Bool(false)),
        ("reader_enabled".to_string(), Value::Bool(false)),
        ("authenticated_reader".to_string(), Value::Bool(false)),
        ("payload_features".to_string(), Value::str("resident-runtime")),
        ("test_output".to_string(), Value::Bool(false)),
        ("payload_only".into(), Value::Bool(false)),
        ("boot".into(), Value::Bool(true)),
        ("low_runtime".into(), Value::Bool(true)),
        ("diagnostic_read".into(), Value::Bool(false)),
        ("native_iommu_bootstrap".into(), Value::str("enabled-translated-no-ats-v1")),
        ("guest_release_enabled".into(), Value::Bool(false)),
        ("windows_boot_candidate".into(), Value::Bool(false)),
        ("linked_instruction_count".into(), Value::Int(count as i64)),
        ("bootstrap_audit".into(), bootstrap_audit),
        ("debug_reset_audit".into(), debug_reset_audit),
        ("entry_capture_audit".into(), entry_capture_audit),
        ("tsc_ratio_audit".into(), tsc_ratio_audit),
        ("msr_capture_audit".into(), msr_capture_audit),
        ("host_fault_audit".into(), host_fault_audit),
        ("no_fp_simd_xstate_instructions".into(), Value::Bool(true)),
        ("undefined_symbols".into(), Value::Int(0)),
    ];
    let report = Value::Map(result.clone()).dump();
    result.push(("artifacts".into(), Value::Map(artifacts.into_iter().collect())));
    let summary = out.join("summary.json");
    io(fs::write(&summary, Value::Map(result).dump()), "write", &summary)?;
    println!("{report}");
    Ok(())
}

/// The repository root: this crate lives at `crates/xtask`.
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/xtask lives two levels below the root")
        .to_path_buf()
}

/// Root-relative '/' paths to SHA-256, ordered like sorted `pathlib` paths:
/// component-wise, case-insensitively on Windows.
pub fn sources(root: &Path) -> Result<Vec<(String, String)>, String> {
    producer_sources(root, &PRODUCER)
}

pub fn sha(path: &Path) -> Result<String, String> {
    let digest = Sha256::digest(io(fs::read(path), "read", path)?);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub fn manifest_json(manifest: &[(String, String)]) -> String {
    Value::Map(manifest.iter().map(|(name, hash)| (name.clone(), Value::str(hash))).collect())
        .dump()
}

/// PATH lookup with the platform's executable extensions.
pub(crate) fn which(tool: &str) -> Option<PathBuf> {
    let extensions: Vec<OsString> = if cfg!(windows) {
        let listed = std::env::var_os("PATHEXT").unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into());
        std::iter::once(OsString::new())
            .chain(std::env::split_paths(&listed).map(PathBuf::into_os_string))
            .collect()
    } else {
        vec![OsString::new()]
    };
    std::env::split_paths(&std::env::var_os("PATH")?).find_map(|directory| {
        extensions.iter().find_map(|extension| {
            let mut name = OsString::from(tool);
            name.push(extension);
            let candidate = directory.join(name);
            candidate.is_file().then_some(candidate)
        })
    })
}

fn audit_retired_services(symbols: &str) -> Result<(), String> {
    // Verify the linked artifact independently of Cargo features and metadata.
    // Prefix checks also reject future adapters under either retired interface.
    if let Some(symbol) =
        symbols.lines().filter_map(|line| line.split_whitespace().last()).find(|symbol| {
            symbol.starts_with("svmvisor_entry_trial_")
                || symbol.starts_with("svmvisor_local_read_")
        })
    {
        return Err(format!(
            "retired guest service linked into reader-disabled resident: {symbol}"
        ));
    }
    Ok(())
}

fn audit_minimal_symbols(symbols: &str) -> Result<(), String> {
    for required in ["entry_uefi", "svmvisor_minimal_prepare", "svmvisor_resident_enter"] {
        if !symbols.lines().any(|line| line.split_whitespace().last() == Some(required)) {
            return Err(format!("minimal continuation lacks linked symbol {required}"));
        }
    }
    for forbidden in ["svmvisor_minimal_enter", "svmvisor_minimal_stop", "svmvisor_minimal_halt"] {
        if symbols.lines().any(|line| line.split_whitespace().last() == Some(forbidden)) {
            return Err(format!(
                "terminal experiment linked into minimal continuation: {forbidden}"
            ));
        }
    }
    Ok(())
}

fn producer_sources(
    root: &Path,
    producer: &PayloadProducer,
) -> Result<Vec<(String, String)>, String> {
    let mut names: Vec<String> = SOURCE_FILES.iter().map(|name| name.to_string()).collect();
    for directory in producer.source_directories {
        walk(&root.join(directory), directory, &mut names)?;
    }
    let key = |name: &String| -> Vec<String> {
        name.split('/')
            .map(|part| if cfg!(windows) { part.to_lowercase() } else { part.to_string() })
            .collect()
    };
    names.sort_by_key(key);
    names.dedup();
    names.into_iter().map(|name| Ok((name.clone(), sha(&root.join(&name))?))).collect()
}

fn walk(directory: &Path, relative: &str, found: &mut Vec<String>) -> Result<(), String> {
    for entry in io(fs::read_dir(directory), "list", directory)? {
        let entry = io(entry, "list", directory)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|name| format!("non-Unicode source name {name:?}"))?;
        let path = entry.path();
        let child = format!("{relative}/{name}");
        // Follows links like the original's Path.is_file()/rglob.
        let kind = io(fs::metadata(&path), "inspect", &path)?;
        if kind.is_dir() {
            if !SKIPPED_DIRECTORIES.contains(&name.as_str()) {
                walk(&path, &child, found)?;
            }
        } else if kind.is_file() && !SKIPPED_DIRECTORIES.contains(&name.as_str()) {
            found.push(child);
        }
    }
    Ok(())
}

fn io<T>(result: std::io::Result<T>, what: &str, path: &Path) -> Result<T, String> {
    result.map_err(|error| format!("{what} {}: {error}", path.display()))
}

fn copy(from: &Path, to: &Path) -> Result<(), String> {
    fs::copy(from, to)
        .map(drop)
        .map_err(|error| format!("copy {} to {}: {error}", from.display(), to.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_disabled_resident_rejects_every_retired_service_export() {
        assert!(audit_retired_services("").is_ok());
        assert!(audit_retired_services("100000 T svmvisor_resident_enter\n").is_ok());
        for symbol in [
            "svmvisor_entry_trial_request",
            "svmvisor_entry_trial_final",
            "svmvisor_entry_trial_complete",
            "svmvisor_entry_trial_future_adapter",
            "svmvisor_local_read_service",
            "svmvisor_local_read_future_adapter",
        ] {
            let error = audit_retired_services(&format!("100000 T {symbol}\n")).unwrap_err();
            assert!(error.contains(symbol));
        }
    }

    #[test]
    fn minimal_link_audit_rejects_terminal_component_and_missing_producer() {
        let symbols = "100000 T entry_uefi\n100020 T svmvisor_minimal_prepare\n100040 T svmvisor_resident_enter\n";
        assert!(audit_minimal_symbols(symbols).is_ok());
        assert!(
            audit_minimal_symbols(&symbols.replace("svmvisor_minimal_prepare", "other")).is_err()
        );
        assert!(
            audit_minimal_symbols(&symbols.replace("svmvisor_resident_enter", "other")).is_err()
        );
        assert!(
            audit_minimal_symbols(&format!("{symbols}100060 T svmvisor_minimal_stop\n")).is_err()
        );
    }
}
