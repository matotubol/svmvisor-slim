//! The connection to the svmvisor runtime, made with the kernel files this build found.

use std::path::PathBuf;

use svmvisor_live_reader::{Config, Result, Svm};

/// Settings for the running kernel: `target/kernel-analysis/ntoskrnl.exe` and its PDB, under the
/// first ancestor of this executable or the working directory that has them.
pub fn config() -> Config {
    let root = std::env::current_exe()
        .ok()
        .into_iter()
        .chain(std::env::current_dir().ok())
        .flat_map(|path| path.ancestors().map(PathBuf::from).collect::<Vec<_>>())
        .find(|path| path.join("target/kernel-analysis").is_dir())
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".."));
    let files = root.join("target/kernel-analysis");
    Config::new(files.join("ntoskrnl.exe"), files.join("ntkrnlmp.pdb"))
}

/// Connects this thread to the runtime. The kernel files are checked first, so a missing or
/// mismatched file fails with `ErrorKind::Profile` before anything reaches the runtime.
pub fn connect(config: Config) -> Result<Svm> {
    // SAFETY: the client runs only on a boot with the svmvisor runtime active. Running it is the
    // operator's statement of that, because the runtime cannot be detected (see `Svm::connect`).
    unsafe { Svm::connect(config) }
}

#[cfg(test)]
mod tests {
    use svmvisor_live_reader::ErrorKind;

    use super::*;

    #[test]
    fn connecting_without_kernel_files_never_reaches_the_runtime() {
        let config = Config::new("missing/ntoskrnl.exe", "missing/ntkrnlmp.pdb");
        let error = connect(config).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::Profile);
    }
}
