use std::env;
use std::path::PathBuf;

use describe_me_plugin_sdk::{describe_me_plugin_main, Plugin, PluginError, PluginOutput};

const DEFAULT_CERTS_DIR: &str = "/etc/describe_me/certs";
const CERTS_ENV: &str = "DESCRIBE_ME_CERTS_DIR";

#[derive(Default)]
struct CertificatesPlugin;

impl CertificatesPlugin {
    fn certs_dir() -> PathBuf {
        env::var(CERTS_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_CERTS_DIR))
    }
}

impl Plugin for CertificatesPlugin {
    fn name(&self) -> &'static str {
        "certificates-demo"
    }

    fn collect(&self) -> Result<PluginOutput, PluginError> {
        let folder = Self::certs_dir();
        let mut entries = 0_u64;
        let mut pem_count = 0_u64;

        let mut output = PluginOutput::new();
        output.insert("directory", folder.display().to_string());

        match std::fs::read_dir(&folder) {
            Ok(read_dir) => {
                for entry_result in read_dir {
                    let entry = entry_result?;
                    entries += 1;
                    let is_pem = entry
                        .path()
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .map(|ext| ext.eq_ignore_ascii_case("pem"))
                        .unwrap_or(false);
                    if is_pem {
                        pem_count += 1;
                    }
                }
                output.insert("files_total", entries);
                output.insert("pem_files", pem_count);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                output.insert("files_total", 0);
                output.insert("pem_files", 0);
                output.insert("status", "directory-not-found");
            }
            Err(err) => return Err(err.into()),
        }

        Ok(output)
    }
}

describe_me_plugin_main!(CertificatesPlugin);
