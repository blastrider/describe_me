#[cfg(feature = "serde")]
use serde::Deserialize;

use super::{ExposureConfig, WebSecurityConfig};

/// Contrôles d'accès pour le mode web (--web).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct WebAccessConfig {
    /// Empreinte du jeton requis (Hash Argon2id/bcrypt pour Authorization: Bearer ou l'en-tête `x-describe-me-token`).
    pub token: Option<String>,
    /// IP ou réseaux autorisés (ex: "192.0.2.5", "10.0.0.0/16", "::1").
    pub allow_ips: Vec<String>,
    /// Origins autorisés (ex: "<https://admin.example.com>") pour CORS strict.
    pub allow_origins: Vec<String>,
    /// Proxys de confiance dont on accepte X-Forwarded-For.
    pub trusted_proxies: Vec<String>,
    /// Chemin absolu vers un logo SVG personnalisé (statique).
    pub logo_path: Option<String>,
    /// Exposition des champs sensibles côté web (--web).
    pub exposure: Option<ExposureConfig>,
    /// Paramétrage des limites de sécurité (rate limiting, anti-bruteforce).
    pub security: Option<WebSecurityConfig>,
    /// Intervalle de rafraîchissement (en secondes) pour le cache des mises à jour.
    pub updates_refresh_seconds: Option<u64>,
    /// Paramètres TLS optionnels (activent HTTPS natif).
    pub tls: Option<WebTlsOptions>,
    /// Mode développement HTTP: autorise un cookie describe_me_session sans attribut Secure.
    pub dev_insecure_session_cookie: bool,
}

/// Paramètres TLS (certificat/clé) pour HTTPS natif.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct WebTlsOptions {
    /// Chemin vers le certificat serveur (PEM).
    pub cert_path: String,
    /// Chemin vers la clé privée correspondante (PEM).
    pub key_path: String,
}
