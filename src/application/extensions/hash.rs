use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use super::PluginExecutionError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PluginFileIdentity {
    size: u64,
    modified_ns: Option<u128>,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    sha256: [u8; 32],
}

impl PluginFileIdentity {
    pub(super) fn from_metadata(meta: &Metadata, sha256: [u8; 32]) -> Self {
        let modified_ns = meta
            .modified()
            .ok()
            .and_then(|ts| ts.duration_since(UNIX_EPOCH).ok())
            .map(|dur| dur.as_nanos());

        Self {
            size: meta.len(),
            modified_ns,
            #[cfg(unix)]
            dev: meta.dev(),
            #[cfg(unix)]
            ino: meta.ino(),
            sha256,
        }
    }
}

pub(super) fn capture_identity(path: &Path) -> Result<PluginFileIdentity, PluginExecutionError> {
    let mut file = File::open(path).map_err(|source| PluginExecutionError::BinaryIo {
        path: path.display().to_string(),
        source,
    })?;
    let metadata = file
        .metadata()
        .map_err(|source| PluginExecutionError::BinaryIo {
            path: path.display().to_string(),
            source,
        })?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| PluginExecutionError::BinaryIo {
                path: path.display().to_string(),
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let sha256: [u8; 32] = hasher.finalize().into();
    Ok(PluginFileIdentity::from_metadata(&metadata, sha256))
}

pub(super) fn enforce_file_identity(
    path: &Path,
    expected: &PluginFileIdentity,
) -> Result<(), PluginExecutionError> {
    let current = capture_identity(path)?;
    if &current != expected {
        return Err(PluginExecutionError::Validation {
            path: path.display().to_string(),
            message: "le binaire a changé après validation (taille/mtime/inode/sha256)".into(),
        });
    }
    Ok(())
}

pub(super) fn verify_child_identity(
    child: &std::process::Child,
    path: &Path,
    expected: &PluginFileIdentity,
) -> Result<(), PluginExecutionError> {
    #[cfg(target_os = "linux")]
    {
        let exe_path = PathBuf::from(format!("/proc/{}/exe", child.id()));
        if let Ok(()) = enforce_file_identity(&exe_path, expected) {
            return Ok(());
        }
    }
    enforce_file_identity(path, expected)
}

pub(super) fn verify_plugin_signature(
    path: &Path,
    expected_hex: &str,
    baseline: &PluginFileIdentity,
) -> Result<PluginFileIdentity, PluginExecutionError> {
    let expected = expected_hex.trim();
    if expected.is_empty() {
        return Err(PluginExecutionError::Validation {
            path: path.display().to_string(),
            message: "empreinte SHA-256 manquante".into(),
        });
    }
    let expected_norm = expected.to_ascii_lowercase();
    let identity = capture_identity(path)?;
    if &identity != baseline {
        return Err(PluginExecutionError::Validation {
            path: path.display().to_string(),
            message: "le binaire a changé pendant la vérification (taille/mtime/inode/sha256)"
                .into(),
        });
    }

    let actual = hex::encode(identity.sha256);
    if actual != expected_norm {
        return Err(PluginExecutionError::ValidationFailed {
            expected: expected_norm,
            actual,
        });
    }

    Ok(identity)
}
