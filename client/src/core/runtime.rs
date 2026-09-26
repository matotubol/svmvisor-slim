//! Retained client configuration and explicit unavailable connection state.

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

/// Returns `ErrorKind::ReaderDisabled` before profile checks or runtime access.
/// The legacy guest interface is retired; the authenticated replacement is not available yet.
pub fn connect(config: Config) -> Result<Svm> {
    Svm::connect(config)
}

#[cfg(test)]
mod tests {
    use svmvisor_live_reader::ErrorKind;

    use super::*;

    #[test]
    fn connecting_reports_disabled_before_kernel_profile_errors() {
        let config = Config::new("missing/ntoskrnl.exe", "missing/ntkrnlmp.pdb");
        let error = connect(config).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::ReaderDisabled);
        assert!(error.message().contains("authenticated reader is not available"));
    }
}
