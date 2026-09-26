fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("uefi") {
        return;
    }
    embed_resident_payload();
    for name in ["resident_callback", "resident_boot", "resident_physical"] {
        assemble_native(name);
    }
    println!("cargo:rerun-if-changed=src/firmware/native/admission/boundary.S");
    for flag in
        ["/subsystem:efi_runtime_driver", "/merge:.rdata=.text", "/debug:none", "/timestamp:0"]
    {
        println!("cargo:rustc-link-arg-bin=svmvisor-hypervisor={flag}");
    }
}

// Source locations follow crate responsibilities; output object names stay
// stable for the linker, stack audit and retained assembly provenance.
fn assemble_native(name: &str) {
    let source = match name {
        "resident_callback" => "src/firmware/native/resident/bridge.S",
        "resident_boot" => "src/firmware/native/resident/boot.S",
        "resident_physical" => "src/firmware/native/resident/physical.S",
        _ => panic!("unknown native assembly unit: {name}"),
    };
    println!("cargo:rerun-if-changed={source}");
    let out =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join(format!("{name}.obj"));
    let mut command = std::process::Command::new("clang");
    let status = command
        .args(["--target=x86_64-pc-windows-msvc", "-c", source, "-o"])
        .arg(&out)
        .status()
        .expect("native assembly requires clang");
    assert!(status.success(), "native assembly failed: {name}");
    println!("cargo:rustc-link-arg-bin=svmvisor-hypervisor={}", out.display());
}

fn embed_resident_payload() {
    use std::{env, fs, path::PathBuf};
    println!("cargo:rerun-if-env-changed=SVMVISOR_RESIDENT_PAYLOAD");
    let path = fs::canonicalize(
        env::var_os("SVMVISOR_RESIDENT_PAYLOAD")
            .expect("native resident requires its audited raw payload"),
    )
    .unwrap();
    let bytes = fs::read(&path).unwrap();
    assert!(bytes.len() >= 64 && &bytes[..8] == b"SVMRELO1");
    let entry = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
    assert!(entry < u64::from_le_bytes(bytes[24..32].try_into().unwrap()));
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(out.join("resident-payload.bin"), bytes).unwrap();
    fs::write(
        out.join("resident-entry.rs"),
        format!("const RESIDENT_ENTRY_OFFSET: usize = {entry};\n"),
    )
    .unwrap();
    println!("cargo:rerun-if-changed={}", path.display());
}
