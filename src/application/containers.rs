use crate::domain::{ContainerInfo, ContainersSnapshot, ContainersSummary};
use crate::SharedSlice;
use describe_me_plugin_sdk::PluginOutput;
use std::net::IpAddr;
use std::time::Duration;
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::Deserialize;

/// Version du contrat JSON attendu depuis `describe-me-plugin-containers`.
pub const CONTAINERS_CONTRACT_VERSION: u16 = 1;

/// Timeout par défaut appliqué au binaire plugin (collecte rapide, sans blocage).
pub const CONTAINERS_PLUGIN_TIMEOUT: Duration = Duration::from_secs(4);

/// Codes de sortie normalisés pour le plugin conteneurs.
///
/// - `Success` (0) : collecte OK, JSON valide.
/// - `NoRuntime` (10) : aucun runtime détecté (Docker/Podman/containerd absent), échec non fatal.
/// - `PermissionDenied` (11) : socket ou CLI inaccessible sans privilèges supplémentaires.
/// - `RuntimeUnavailable` (12) : runtime présent mais injoignable (daemon down, socket refusé).
/// - `InvalidPayload` (20) : bug de sérialisation/validation côté plugin.
/// - `Unexpected` (30) : toute autre erreur interne.
///
/// Les dépassements de temps sont gérés côté core via `CONTAINERS_PLUGIN_TIMEOUT` plutôt
/// que par un code de sortie dédié.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ContainersPluginExitCode {
    Success = 0,
    NoRuntime = 10,
    PermissionDenied = 11,
    RuntimeUnavailable = 12,
    InvalidPayload = 20,
    Unexpected = 30,
}

impl ContainersPluginExitCode {
    /// Conversion sécurisée d’un code brut (valeur inconnue → `Unexpected`).
    pub fn from_i32(code: i32) -> Self {
        match code {
            0 => Self::Success,
            10 => Self::NoRuntime,
            11 => Self::PermissionDenied,
            12 => Self::RuntimeUnavailable,
            20 => Self::InvalidPayload,
            _ => Self::Unexpected,
        }
    }

    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Indique si l’échec ne doit pas être traité comme critique (ex: pas de runtime).
    pub fn is_soft_failure(self) -> bool {
        matches!(
            self,
            Self::NoRuntime | Self::PermissionDenied | Self::RuntimeUnavailable
        )
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Success => "collecte réussie",
            Self::NoRuntime => "aucun runtime conteneur détecté",
            Self::PermissionDenied => "accès refusé au runtime conteneur",
            Self::RuntimeUnavailable => "runtime conteneur injoignable",
            Self::InvalidPayload => "payload JSON invalide",
            Self::Unexpected => "erreur interne du plugin",
        }
    }
}

#[cfg(feature = "serde")]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContainersContractError {
    #[error("contrat conteneurs v{found} non supporté (attendu v{expected})")]
    UnsupportedVersion { found: u16, expected: u16 },
    #[error("payload JSON invalide: {0}")]
    InvalidJson(String),
    #[error("section summary manquante dans la sortie du plugin")]
    MissingSummary,
    #[error("summary invalide: {0}")]
    InvalidSummary(String),
    #[error("container #{index}: {reason}")]
    InvalidContainer { index: usize, reason: String },
}

#[cfg(feature = "serde")]
#[derive(Debug, Deserialize)]
struct ContainersPayload {
    #[serde(default = "default_contract_version")]
    version: u16,
    summary: Option<ContainersSummaryWire>,
    #[serde(default)]
    containers: Vec<ContainerInfoWire>,
}

#[cfg(feature = "serde")]
#[derive(Debug, Deserialize)]
struct ContainersSummaryWire {
    total: usize,
    running: usize,
}

#[cfg(feature = "serde")]
#[derive(Debug, Deserialize)]
struct ContainerInfoWire {
    name: String,
    runtime: String,
    #[serde(default)]
    ip: Option<String>,
    state: String,
    #[serde(default)]
    image: Option<String>,
}

#[cfg(feature = "serde")]
const fn default_contract_version() -> u16 {
    CONTAINERS_CONTRACT_VERSION
}

/// Parse et normalise la sortie JSON du plugin conteneurs.
#[cfg(feature = "serde")]
pub fn parse_plugin_output(
    output: &PluginOutput,
) -> Result<ContainersSnapshot, ContainersContractError> {
    let payload: ContainersPayload = serde_json::from_value(
        serde_json::to_value(output.as_map())
            .map_err(|err| ContainersContractError::InvalidJson(err.to_string()))?,
    )
    .map_err(|err| ContainersContractError::InvalidJson(err.to_string()))?;

    if payload.version != CONTAINERS_CONTRACT_VERSION {
        return Err(ContainersContractError::UnsupportedVersion {
            found: payload.version,
            expected: CONTAINERS_CONTRACT_VERSION,
        });
    }

    let summary_wire = payload
        .summary
        .ok_or(ContainersContractError::MissingSummary)?;
    let summary = validate_summary(&summary_wire)?;

    let mut containers = Vec::with_capacity(payload.containers.len());
    for (idx, raw) in payload.containers.into_iter().enumerate() {
        let normalized = normalize_container(raw)
            .map_err(|reason| ContainersContractError::InvalidContainer { index: idx, reason })?;
        containers.push(normalized);
    }

    if summary.total < containers.len() {
        return Err(ContainersContractError::InvalidSummary(format!(
            "summary.total={} < containers.len()={}",
            summary.total,
            containers.len()
        )));
    }

    Ok(ContainersSnapshot {
        summary: Some(summary),
        containers: (!containers.is_empty()).then(|| SharedSlice::from_vec(containers)),
    })
}

#[cfg(feature = "serde")]
fn validate_summary(
    wire: &ContainersSummaryWire,
) -> Result<ContainersSummary, ContainersContractError> {
    if wire.running > wire.total {
        return Err(ContainersContractError::InvalidSummary(format!(
            "running ({}) > total ({})",
            wire.running, wire.total
        )));
    }
    Ok(ContainersSummary {
        total: wire.total,
        running: wire.running,
    })
}

#[cfg(feature = "serde")]
fn normalize_container(raw: ContainerInfoWire) -> Result<ContainerInfo, String> {
    const NAME_MAX: usize = 128;
    const RUNTIME_MAX: usize = 32;
    const STATE_MAX: usize = 32;
    const IMAGE_MAX: usize = 256;

    let name = normalize_token(&raw.name, "name", NAME_MAX)?;
    let runtime = normalize_token(&raw.runtime, "runtime", RUNTIME_MAX)?.to_ascii_lowercase();
    let state = normalize_token(&raw.state, "state", STATE_MAX)?.to_ascii_lowercase();
    let ip = normalize_ip(raw.ip)?;
    let image = normalize_optional_token(raw.image, "image", IMAGE_MAX)?;

    Ok(ContainerInfo {
        name,
        runtime,
        ip,
        state,
        image,
    })
}

#[cfg(feature = "serde")]
fn normalize_ip(raw: Option<String>) -> Result<Option<String>, String> {
    let Some(value) = raw else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let parsed: IpAddr = trimmed
        .parse()
        .map_err(|_| format!("ip invalide '{trimmed}'"))?;
    Ok(Some(parsed.to_string()))
}

#[cfg(feature = "serde")]
fn normalize_optional_token(
    raw: Option<String>,
    field: &'static str,
    max_len: usize,
) -> Result<Option<String>, String> {
    match raw {
        None => Ok(None),
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            normalize_token(trimmed, field, max_len).map(Some)
        }
    }
}

#[cfg(feature = "serde")]
fn normalize_token(raw: &str, field: &'static str, max_len: usize) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} manquant"));
    }
    if trimmed.len() > max_len {
        return Err(format!("{field} trop long (>{max_len} caractères)"));
    }
    if !trimmed.is_ascii() {
        return Err(format!("{field} doit être ASCII"));
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(format!(
            "{field} contient des espaces ou caractères de contrôle"
        ));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "serde")]
    #[test]
    fn parses_and_normalizes_valid_payload() {
        let mut output = PluginOutput::new();
        output.insert("version", CONTAINERS_CONTRACT_VERSION);
        output.insert("summary", serde_json::json!({"total": 2, "running": 1}));
        output.insert(
            "containers",
            serde_json::json!([
                {
                    "name": "web",
                    "runtime": "Docker",
                    "ip": "10.0.0.2",
                    "state": "RUNNING",
                    "image": "nginx:latest"
                },
                {
                    "name": "db",
                    "runtime": "podman",
                    "ip": null,
                    "state": "exited",
                    "image": null
                }
            ]),
        );

        let snapshot = parse_plugin_output(&output).expect("valid payload");
        let summary = snapshot.summary.expect("summary");
        assert_eq!(summary.total, 2);
        assert_eq!(summary.running, 1);

        let containers = snapshot.containers.expect("containers");
        assert_eq!(containers.len(), 2);
        assert_eq!(containers[0].runtime, "docker");
        assert_eq!(containers[0].state, "running");
        assert_eq!(containers[0].ip.as_deref(), Some("10.0.0.2"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn rejects_invalid_ip() {
        let mut output = PluginOutput::new();
        output.insert("version", CONTAINERS_CONTRACT_VERSION);
        output.insert("summary", serde_json::json!({"total": 1, "running": 0}));
        output.insert(
            "containers",
            serde_json::json!([{"name":"bad","runtime":"docker","ip":"abc","state":"exited"}]),
        );

        let err = parse_plugin_output(&output).unwrap_err();
        assert!(matches!(
            err,
            ContainersContractError::InvalidContainer { .. }
        ));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn rejects_version_mismatch() {
        let mut output = PluginOutput::new();
        output.insert("version", CONTAINERS_CONTRACT_VERSION + 1);
        output.insert("summary", serde_json::json!({"total": 0, "running": 0}));
        output.insert("containers", serde_json::json!([]));

        let err = parse_plugin_output(&output).unwrap_err();
        assert!(matches!(
            err,
            ContainersContractError::UnsupportedVersion { .. }
        ));
    }
}
