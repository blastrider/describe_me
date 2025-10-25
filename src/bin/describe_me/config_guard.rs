use crate::cli_opts::Opts;
use anyhow::{bail, Context, Result};
use std::env;
use std::path::{Path, PathBuf};

const CONFIG_MAX_BYTES: u64 = 1_048_576; // 1 MiB

pub(crate) fn load_config(opts: &Opts) -> Result<Option<describe_me::DescribeConfig>> {
    if let Some(path) = &opts.config {
        let canon =
            validate_config_path(path, opts.config_allow_symlink, opts.config_allow_outside)?;
        let cfg = describe_me::load_config_from_path(&canon).context("chargement config TOML")?;
        Ok(Some(cfg))
    } else {
        Ok(None)
    }
}

fn validate_config_path(p: &Path, allow_symlink: bool, allow_outside: bool) -> Result<PathBuf> {
    use std::fs;

    // (A) Refus explicite des `..`
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        bail!("--config: chemins relatifs contenant `..` refusés.");
    }

    // 1) Expansion minimale ~/
    let p = expand_home_if_needed(p.to_path_buf());

    // 2) Lstat pour détecter symlink sans suivre
    let lmd =
        fs::symlink_metadata(&p).with_context(|| format!("read metadata: {}", p.display()))?;
    if lmd.file_type().is_symlink() && !allow_symlink {
        bail!("--config ne doit pas être un lien symbolique (utilisez --config-allow-symlink si vous assumez).");
    }

    // 3) Canonicalise (résout .. et symlinks) pour les contrôles suivants
    let canon = p
        .canonicalize()
        .with_context(|| format!("canonicalize: {}", p.display()))?;

    // 4) Fichier régulier + taille + permissions
    let md = fs::metadata(&canon)?;
    if !md.is_file() {
        bail!("--config doit pointer vers un fichier régulier.");
    }
    if md.len() > CONFIG_MAX_BYTES {
        bail!("fichier --config trop volumineux (> 1 MiB).");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = md.mode() & 0o777;
        // exiger 0600 (rw-------)
        if (mode & 0o077) != 0 || (mode & 0o600) != 0o600 {
            bail!("permissions faibles sur --config (exigez chmod 600).");
        }
    }

    // 5) Répertoire parent: refuser monde-écrivable sans sticky
    if let Some(parent) = canon.parent() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(pmd) = fs::metadata(parent) {
                let m = pmd.mode();
                let world_w = (m & 0o002) != 0;
                let sticky = (m & 0o1000) != 0;
                if world_w && !sticky {
                    bail!("répertoire parent du --config monde-écrivable sans sticky: refusé.");
                }
            }
        }
    }

    // 6) Répertoires approuvés (protection anti-traversal/chemins inattendus)
    if !allow_outside {
        let roots = approved_config_roots();
        let inside = roots.iter().any(|r| path_is_inside(r, &canon));
        if !inside {
            bail!("--config en dehors des répertoires approuvés ({}) — utilisez --config-allow-outside si vous assumez.",
                  roots.iter().map(|r| r.display().to_string()).collect::<Vec<_>>().join(", "));
        }
    }

    Ok(canon)
}

#[cfg(unix)]
fn is_world_writable(md: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    (md.mode() & 0o022) != 0 // writable par groupe/autres
}

fn expand_home_if_needed(p: PathBuf) -> PathBuf {
    if let Some(s) = p.to_str() {
        if let Some(rest) = s.strip_prefix("~/") {
            if let Ok(home) = env::var("HOME") {
                return Path::new(&home).join(rest);
            }
        }
    }
    p
}

fn approved_config_roots() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        v.push(cwd);
        v.push(Path::new(".").join("config")); // ./config
    }
    if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
        v.push(Path::new(&xdg).join("describe_me"));
    } else if let Ok(home) = env::var("HOME") {
        v.push(Path::new(&home).join(".config/describe_me"));
    }
    v.push(Path::new("/etc/describe_me").to_path_buf());
    v
}

fn path_is_inside(root: &Path, target: &Path) -> bool {
    if let (Ok(r), Ok(t)) = (root.canonicalize(), target.canonicalize()) {
        t.starts_with(r)
    } else {
        false
    }
}
