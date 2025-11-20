use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeZone, Utc};
use describe_me_plugin_sdk::{describe_me_plugin_main, Plugin, PluginError, PluginOutput};
use rustls_pemfile::certs;
use serde_json::{json, Value};
use x509_parser::{certificate::X509Certificate, parse_x509_certificate, time::ASN1Time};

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

    fn asn1_to_utc(time: &ASN1Time) -> Option<DateTime<Utc>> {
        let dt = time.to_datetime();
        let secs = dt.unix_timestamp();
        let nanos = dt.nanosecond();
        Utc.timestamp_opt(secs, nanos).single()
    }

    fn format_datetime(time: &ASN1Time) -> String {
        if let Some(dt) = Self::asn1_to_utc(time) {
            dt.to_rfc3339()
        } else {
            time.to_string()
        }
    }

    fn certificate_value(path: &Path, cert: &X509Certificate<'_>) -> Value {
        let validity = cert.validity();
        let not_before_dt = Self::asn1_to_utc(&validity.not_before);
        let not_after_dt = Self::asn1_to_utc(&validity.not_after);

        let validity_days = match (not_before_dt.as_ref(), not_after_dt.as_ref()) {
            (Some(start), Some(end)) => Some((*end - *start).num_days()),
            _ => None,
        };
        let days_until_expiry = not_after_dt
            .as_ref()
            .map(|end| (*end - Utc::now()).num_days());

        let mut obj = serde_json::Map::new();
        obj.insert("path".into(), json!(path.display().to_string()));
        obj.insert("status".into(), json!("ok"));
        obj.insert(
            "not_before".into(),
            json!(Self::format_datetime(&validity.not_before)),
        );
        obj.insert(
            "not_after".into(),
            json!(Self::format_datetime(&validity.not_after)),
        );
        if let Some(days) = validity_days {
            obj.insert("validity_days".into(), json!(days));
        }
        if let Some(days) = days_until_expiry {
            obj.insert("days_until_expiry".into(), json!(days));
        }

        Value::Object(obj)
    }

    fn parse_certificate_file(path: &Path) -> Result<Vec<Value>, PluginError> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let pem_certs = certs(&mut reader)
            .map_err(|err| PluginError::msg(format!("ERREUR PEM: {err}")))?;
        if pem_certs.is_empty() {
            return Err(PluginError::msg(
                "aucun bloc CERTIFICATE trouvé dans le fichier",
            ));
        }

        let mut entries = Vec::new();
        for der in pem_certs {
            match parse_x509_certificate(der.as_ref()) {
                Ok((_, cert)) => entries.push(Self::certificate_value(path, &cert)),
                Err(err) => entries.push(json!({
                    "path": path.display().to_string(),
                    "status": format!("invalid-cert: {err}"),
                })),
            }
        }
        Ok(entries)
    }

    fn collect_certificates(&self) -> Vec<Value> {
        let mut certificates = Vec::new();
        for dir in &self.probes {
            match std::fs::read_dir(dir) {
                Ok(read_dir) => {
                    for entry in read_dir.flatten() {
                        let path = entry.path();
                        let is_file = entry
                            .file_type()
                            .map(|ft| ft.is_file())
                            .unwrap_or(false);
                        let name_lower = path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .map(|s| s.to_ascii_lowercase());
                        if let Some(name) = name_lower.as_deref() {
                            if name.contains("key") {
                                continue;
                            }
                        }
                        let is_pem = path
                            .extension()
                            .and_then(|ext| ext.to_str())
                            .map(|ext| ext.eq_ignore_ascii_case("pem"))
                            .unwrap_or(false);
                        if !is_file || !is_pem {
                            continue;
                        }
                        match Self::parse_certificate_file(&path) {
                            Ok(mut list) => certificates.append(&mut list),
                            Err(err) => certificates.push(json!({
                                "path": path.display().to_string(),
                                "status": err.to_string(),
                            })),
                        }
                    }
                }
                Err(err) => certificates.push(json!({
                    "path": dir.display().to_string(),
                    "status": err.to_string(),
                })),
            }
        }
        certificates
    }

    fn summarize_certificates(entries: &[Value]) -> Vec<String> {
        let mut lines = Vec::new();
        for entry in entries {
            let obj = match entry.as_object() {
                Some(obj) => obj,
                None => continue,
            };
            let path = obj
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("certificat");
            let status = obj
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            if status != "ok" {
                lines.push(format!("{path}: {status}"));
                continue;
            }
            let not_after = obj
                .get("not_after")
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            let days = obj
                .get("days_until_expiry")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let lifespan = obj
                .get("validity_days")
                .and_then(|v| v.as_i64())
                .map(|v| format!("validité totale {v}j"))
                .unwrap_or_else(|| "validité inconnue".to_string());

            let label = if days >= 0 {
                format!("{path}: expire dans {days}j ({lifespan}), jusqu'au {not_after}")
            } else {
                format!(
                    "{path}: expiré depuis {}j ({lifespan}), jusqu'au {not_after}",
                    days.abs()
                )
            };
            lines.push(label);
        }
        lines
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

        let certificates = self.collect_certificates();
        let certificates_ok = certificates
            .iter()
            .filter(|entry| {
                entry
                    .as_object()
                    .and_then(|obj| obj.get("status"))
                    .and_then(|v| v.as_str())
                    .map(|status| status == "ok")
                    .unwrap_or(false)
            })
            .count() as u64;
        let certificates_summary = Self::summarize_certificates(&certificates);

        output.insert("files_total", total_entries);
        output.insert("pem_files", total_pem);
        output.insert("certificates_found", certificates_ok);
        if !details.is_empty() {
            output.insert("details", details);
        }
        if !certificates.is_empty() {
            output.insert("certificates", certificates);
        }
        if !certificates_summary.is_empty() {
            output.insert("certificates_summary", certificates_summary);
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
