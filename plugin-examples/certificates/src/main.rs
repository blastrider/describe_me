use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use describe_me_plugin_sdk::{describe_me_plugin_main, Plugin, PluginError, PluginOutput};
use serde_json::json;

const DEFAULT_PROBES: &[&str] = &["/etc/ssl/certs", "/etc/describe_me/certs"];
const CERTS_ENV: &str = "DESCRIBE_ME_CERTS_DIR";

#[derive(Clone)]
struct CertificatesPlugin {
    probes: Vec<PathBuf>,
}

impl CertificatesPlugin {
    fn new() -> Result<Self, PluginError> {
        let args = Self::parse_args(env::args_os().skip(1))?;
        let probes = if !args.is_empty() {
            args
        } else if let Ok(value) = env::var(CERTS_ENV) {
            vec![PathBuf::from(value)]
        } else {
            DEFAULT_PROBES.iter().map(PathBuf::from).collect()
        };
        Ok(Self { probes })
    }

    fn parse_args<I>(mut args: I) -> Result<Vec<PathBuf>, PluginError>
    where
        I: Iterator<Item = OsString>,
    {
        let mut probes = Vec::new();
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("--probe") => {
                    let value = args.next().ok_or_else(|| {
                        PluginError::msg("--probe nécessite un chemin juste après")
                    })?;
                    probes.push(PathBuf::from(value));
                }
                Some("--help") => {
                    println!("Usage: certificates-plugin [--probe <PATH>]...");
                    println!(
                        "Par défaut, les dossiers suivants sont inspectés: {:?}",
                        DEFAULT_PROBES
                    );
                    std::process::exit(0);
                }
                Some(other) => {
                    return Err(PluginError::msg(format!(
                        "argument inconnu '{other}', utilisez --probe <PATH>"
                    )));
                }
                None => {
                    return Err(PluginError::msg(
                        "argument non UTF-8, impossible de continuer",
                    ));
                }
            }
        }
        Ok(probes)
    }

    fn scan_directory(path: &Path) -> Result<(u64, u64, String), PluginError> {
        let mut entries = 0_u64;
        let mut pem_count = 0_u64;
        match std::fs::read_dir(path) {
            Ok(read_dir) => {
                for entry in read_dir {
                    let entry = entry?;
                    entries += 1;
                    if entry
                        .path()
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .map(|ext| ext.eq_ignore_ascii_case("pem"))
                        .unwrap_or(false)
                    {
                        pem_count += 1;
                    }
                }
                Ok((entries, pem_count, String::from("ok")))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok((
                0,
                0,
                String::from("directory-not-found"),
            )),
            Err(err) => Err(err.into()),
        }
    }
}

impl Default for CertificatesPlugin {
    fn default() -> Self {
        match CertificatesPlugin::new() {
            Ok(plugin) => plugin,
            Err(err) => {
                eprintln!("certificate plugin init error: {err}");
                std::process::exit(1);
            }
        }
    }
}

impl Plugin for CertificatesPlugin {
    fn name(&self) -> &'static str {
        "certificates-demo"
    }

    fn collect(&self) -> Result<PluginOutput, PluginError> {
        let mut output = PluginOutput::new();
        output.insert(
            "directories",
            self.probes
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
        );

        let mut total_entries = 0_u64;
        let mut total_pem = 0_u64;
        let mut details = Vec::with_capacity(self.probes.len());

        for dir in &self.probes {
            match Self::scan_directory(dir) {
                Ok((entries, pem_files, status)) => {
                    total_entries += entries;
                    total_pem += pem_files;
                    details.push(json!({
                        "path": dir.display().to_string(),
                        "files_total": entries,
                        "pem_files": pem_files,
                        "status": status,
                    }));
                }
                Err(err) => {
                    details.push(json!({
                        "path": dir.display().to_string(),
                        "files_total": 0,
                        "pem_files": 0,
                        "status": err.to_string(),
                    }));
                }
            }
        }

        output.insert("files_total", total_entries);
        output.insert("pem_files", total_pem);
        if !details.is_empty() {
            output.insert("details", details);
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_supports_multiple_probes() {
        let args = vec![
            OsString::from("bin"),
            OsString::from("--probe"),
            OsString::from("/tmp/a"),
            OsString::from("--probe"),
            OsString::from("/tmp/b"),
        ];
        let parsed = CertificatesPlugin::parse_args(args.into_iter().skip(1)).unwrap();
        assert_eq!(parsed, vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")]);
    }
}

describe_me_plugin_main!(CertificatesPlugin);
