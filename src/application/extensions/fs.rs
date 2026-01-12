use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::{PluginExecutionError, PluginPolicy};

pub(super) fn ensure_plugin_path_allowed(
    path: &Path,
    policy: &PluginPolicy,
) -> Result<PathBuf, PluginExecutionError> {
    let path_str = path.display().to_string();
    if !path.is_absolute() {
        return Err(PluginExecutionError::Validation {
            path: path_str,
            message: "le chemin doit être absolu".into(),
        });
    }

    if path
        .components()
        .any(|comp| matches!(comp, Component::ParentDir))
    {
        return Err(PluginExecutionError::Validation {
            path: path_str,
            message: "composant .. interdit dans le chemin plugin".into(),
        });
    }

    let canonical = path
        .canonicalize()
        .map_err(|source| PluginExecutionError::Validation {
            path: path_str.clone(),
            message: format!("résolution canonique impossible: {source}"),
        })?;

    let root = policy.root();
    if !root.is_absolute() {
        return Err(PluginExecutionError::Validation {
            path: root.display().to_string(),
            message: "le répertoire racine des plugins doit être absolu".into(),
        });
    }
    let root_canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    if !canonical.starts_with(&root_canon) {
        return Err(PluginExecutionError::Validation {
            path: path_str,
            message: format!("le chemin doit rester sous {}", root_canon.display()),
        });
    }

    Ok(canonical)
}

pub(super) fn ensure_plugin_file_allowed(
    path: &Path,
    policy: &PluginPolicy,
) -> Result<std::fs::Metadata, PluginExecutionError> {
    let path_str = path.display().to_string();
    let metadata = std::fs::metadata(path).map_err(|source| PluginExecutionError::BinaryIo {
        path: path_str.clone(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(PluginExecutionError::Validation {
            path: path_str,
            message: "le binaire doit être un fichier régulier".into(),
        });
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode();
        if policy.require_exec && mode & 0o111 == 0 {
            return Err(PluginExecutionError::Validation {
                path: path_str,
                message: "permis d'exécution manquants".into(),
            });
        }
        if mode & 0o022 != 0 {
            return Err(PluginExecutionError::Validation {
                path: path_str,
                message: format!(
                    "permissions trop ouvertes (mode {}), retirer l'écriture groupe/monde",
                    format_mode(mode)
                ),
            });
        }
    }
    Ok(metadata)
}

#[cfg(unix)]
fn format_mode(mode: u32) -> String {
    format!("{mode:04o}")
}
