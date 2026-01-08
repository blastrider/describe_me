use super::error::DescribeError;
use super::history_profile::HistoryProfile;
use super::plugin::validate_plugin_name;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

/// Configuration haut-niveau.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct DescribeConfig {
    /// Sélection des services à afficher (si `with_services = true`).
    pub services: Option<ServiceSelection>,
    /// Contrôles d'accès pour le mode web (--web).
    pub web: Option<WebAccessConfig>,
    /// Exposition des champs sensibles pour la sortie JSON.
    pub exposure: Option<ExposureConfig>,
    /// Paramètres runtime (logging, valeurs par défaut CLI).
    pub runtime: Option<RuntimeConfig>,
    /// Plugins/collecteurs additionnels à exécuter sur chaque snapshot.
    pub extensions: Option<ExtensionsConfig>,
    /// Paramétrage de l'historique local (mini time-series).
    pub history: Option<HistoryConfig>,
}

/// Sélection des services (liste blanche simple).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct ServiceSelection {
    /// Noms exacts systemd à inclure (ex: "sshd.service").
    pub include: Vec<String>,
}

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

/// Paramètres runtime supplémentaires (logging, CLI).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct RuntimeConfig {
    /// Valeur à appliquer pour la variable d'environnement RUST_LOG.
    pub rust_log: Option<String>,
    /// Valeurs par défaut pour la CLI.
    pub cli: Option<CliDefaults>,
    /// Autorise l'application des drapeaux `expose-*`/`web-expose-*` depuis la configuration.
    /// Priorité: CLI > runtime.allow_config_exposure > ENV DESCRIBE_ME_ALLOW_CONFIG_EXPOSURE.
    pub allow_config_exposure: bool,
    /// Répertoire personnalisé pour les données persistées (metadata.redb).
    pub state_dir: Option<String>,
}

/// Valeurs par défaut pour la CLI.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct CliDefaults {
    /// Valeur par défaut pour --web (ADDR:PORT).
    pub web: Option<String>,
    /// Active --with-services si true.
    pub with_services: Option<bool>,
    /// Active --with-containers si true.
    pub with_containers: Option<bool>,
    /// Active --web-expose-all si true.
    pub web_expose_all: Option<bool>,
    /// Valeurs par défaut pour --web-allow-ip.
    pub web_allow_ip: Vec<String>,
    /// Valeurs par défaut pour --web-allow-origin.
    pub web_allow_origin: Vec<String>,
    /// Valeurs par défaut pour --web-trusted-proxy.
    pub web_trusted_proxy: Vec<String>,
}

/// Configuration des collecteurs externes.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct ExtensionsConfig {
    /// Liste des plugins exécutés à chaque snapshot.
    pub plugins: Vec<PluginDefinition>,
}

/// Configuration de l'historique persistant (mini time-series).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct HistoryConfig {
    /// Active l'enregistrement des snapshots dans l'historique.
    pub enabled: bool,
    /// Profil préconfiguré (default, ops, paranoid).
    pub profile: Option<HistoryProfile>,
    /// Nombre maximal de points conservés par serveur.
    pub retention_points: Option<u32>,
    /// Fenêtre maximale autorisée par requête (secondes).
    pub max_window_seconds: Option<u32>,
    /// Arrondi appliqué aux timestamps pour les tendances (secondes).
    pub rounding_seconds: Option<u64>,
    /// Force un stockage purement mémoire (pas d'écriture disque).
    pub in_memory_only: bool,
    /// Applique les garde-fous paranoïaques (quotas réduits, pas d'exposition UI).
    pub paranoid: bool,
}

/// Plugin externe lancé durant les captures.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[non_exhaustive]
pub struct PluginDefinition {
    /// Nom stable affiché côté UI/JSON (namespacing).
    pub name: String,
    /// Chemin absolu vers le binaire autorisé.
    pub path: String,
    /// Arguments optionnels transmis au binaire.
    #[cfg_attr(feature = "serde", serde(default))]
    pub args: Vec<String>,
    /// Timeout (secondes) avant de tuer le processus.
    #[cfg_attr(feature = "serde", serde(default))]
    pub timeout_secs: Option<u64>,
    /// Empreinte SHA-256 hexadécimale attendue pour le binaire.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "deserialize_sha256"))]
    pub sha256: String,
    /// Allowlist d'ENV transmis au plugin (vide => allowlist par défaut).
    #[cfg_attr(feature = "serde", serde(default))]
    pub allowed_env: Vec<String>,
    /// ENV additionnels injectés (override explicite).
    #[cfg_attr(feature = "serde", serde(default))]
    pub extra_env: BTreeMap<String, String>,
}

impl PluginDefinition {
    pub fn new(
        name: impl Into<String>,
        path: impl Into<String>,
        sha256: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            sha256: sha256.into(),
            ..Self::default()
        }
    }
}

impl DescribeConfig {
    pub fn validate_plugin_names(&self) -> Result<(), DescribeError> {
        let Some(extensions) = self.extensions.as_ref() else {
            return Ok(());
        };
        let mut seen: HashMap<String, usize> = HashMap::new();
        for (idx, plugin) in extensions.plugins.iter().enumerate() {
            validate_plugin_name(plugin.name.as_str()).map_err(|err| {
                DescribeError::Config(format!("extensions.plugins[{idx}].name: {err}"))
            })?;
            if let Some(previous) = seen.insert(plugin.name.clone(), idx) {
                return Err(DescribeError::Config(format!(
                    "extensions.plugins[{idx}].name: nom dupliqué \"{}\" (déjà présent à l'index {previous})",
                    plugin.name
                )));
            }
        }
        Ok(())
    }

    pub fn validate_runtime(&self) -> Result<(), DescribeError> {
        if let Some(runtime) = self.runtime.as_ref() {
            if let Some(state_dir) = runtime.state_dir.as_deref() {
                if state_dir.is_empty() {
                    return Err(DescribeError::Config(
                        "runtime.state_dir ne peut pas être vide".into(),
                    ));
                }
                let path = Path::new(state_dir);
                if !path.is_absolute() {
                    return Err(DescribeError::Config(
                        "runtime.state_dir doit être un chemin absolu".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Contrôle fin des champs JSON sensibles.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct ExposureConfig {
    /// Autoriser l'exposition du hostname exact.
    pub expose_hostname: bool,
    /// Autoriser l'exposition des informations d'OS.
    pub expose_os: bool,
    /// Autoriser l'exposition de la version complète du noyau.
    pub expose_kernel: bool,
    /// Autoriser la liste détaillée des services systemd.
    pub expose_services: bool,
    /// Autoriser le détail des partitions disque (points de montage, fs, ...).
    pub expose_disk_partitions: bool,
    /// Autoriser la liste des sockets en écoute.
    pub expose_listening_sockets: bool,
    /// Autoriser l'exposition du trafic réseau par interface.
    pub expose_network_traffic: bool,
    /// Autoriser le résumé des conteneurs (totaux).
    pub expose_containers_summary: bool,
    /// Autoriser le détail des conteneurs (nom, IP, image).
    pub expose_containers_details: bool,
    /// Autoriser l'exposition des informations de mises à jour.
    pub expose_updates: bool,
    /// Autoriser l'exposition des extensions/plugins.
    pub expose_extensions: bool,
    /// Fournir des valeurs masquées (versions tronquées) lorsque l'exposition complète est désactivée.
    /// Safe by default; mettre à `false` expose davantage d'informations potentiellement sensibles.
    #[cfg_attr(feature = "serde", serde(default = "ExposureConfig::default_redacted"))]
    pub redacted: bool,
}

impl ExposureConfig {
    const fn default_redacted() -> bool {
        true
    }
}

impl Default for ExposureConfig {
    fn default() -> Self {
        Self {
            expose_hostname: false,
            expose_os: false,
            expose_kernel: false,
            expose_services: false,
            expose_disk_partitions: false,
            expose_listening_sockets: false,
            expose_network_traffic: false,
            expose_containers_summary: false,
            expose_containers_details: false,
            expose_updates: false,
            expose_extensions: false,
            redacted: true,
        }
    }
}

#[cfg(feature = "serde")]
fn deserialize_sha256<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    let value = Option::<String>::deserialize(deserializer)?;
    let Some(v) = value else {
        return Err(serde::de::Error::missing_field("sha256"));
    };

    let trimmed = v.trim();
    if trimmed.is_empty() {
        return Err(serde::de::Error::custom("sha256 ne peut pas être vide"));
    }

    let normalized = trimmed.to_ascii_lowercase();
    if normalized.len() != 64 {
        return Err(serde::de::Error::custom(
            "sha256 doit contenir 64 caractères hexadécimaux",
        ));
    }
    if !normalized
        .chars()
        .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
    {
        return Err(serde::de::Error::custom(
            "sha256 doit être une valeur hexadécimale (0-9, a-f)",
        ));
    }

    Ok(normalized)
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn expose_updates_defaults_to_false() {
        let cfg: ExposureConfig = toml::from_str("").expect("deserialize default exposure");
        assert!(!cfg.expose_updates);
    }

    #[test]
    fn expose_updates_can_be_enabled() {
        let cfg: ExposureConfig =
            toml::from_str("expose_updates = true").expect("deserialize exposure");
        assert!(cfg.expose_updates);
    }

    #[test]
    fn expose_extensions_defaults_to_false() {
        let cfg: ExposureConfig = toml::from_str("").expect("deserialize default exposure");
        assert!(!cfg.expose_extensions);
    }

    #[test]
    fn expose_extensions_can_be_enabled() {
        let cfg: ExposureConfig =
            toml::from_str("expose_extensions = true").expect("deserialize exposure");
        assert!(cfg.expose_extensions);
    }

    #[test]
    fn validate_plugin_names_rejects_duplicates() {
        let cfg: DescribeConfig = toml::from_str(
            r#"
[extensions]
[[extensions.plugins]]
name = "demo"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo"
sha256 = "7f51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e"

[[extensions.plugins]]
name = "demo"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo2"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#,
        )
        .expect("deserialize config");

        let err = cfg.validate_plugin_names().expect_err("duplicate name");
        assert!(matches!(err, DescribeError::Config(msg) if msg.contains("nom dupliqué")));
    }

    #[test]
    fn validate_plugin_names_accepts_unique() {
        let cfg: DescribeConfig = toml::from_str(
            r#"
[extensions]
[[extensions.plugins]]
name = "demo"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo"
sha256 = "7f51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e"

[[extensions.plugins]]
name = "demo2"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo2"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#,
        )
        .expect("deserialize config");

        cfg.validate_plugin_names().expect("valid plugin names");
    }

    #[test]
    fn plugin_sha256_rejects_invalid_length() {
        let err: Result<DescribeConfig, _> = toml::from_str(
            r#"
[extensions]
[[extensions.plugins]]
name = "demo"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo"
sha256 = "abc"
"#,
        );
        let err = err.expect_err("sha256 length rejected");
        assert!(err.to_string().contains("sha256"));
    }

    #[test]
    fn plugin_sha256_rejects_non_hex_chars() {
        let err: Result<DescribeConfig, _> = toml::from_str(
            r#"
[extensions]
[[extensions.plugins]]
name = "demo"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo"
sha256 = "zz51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e"
"#,
        );
        let err = err.expect_err("sha256 hex rejected");
        assert!(err.to_string().contains("sha256"));
    }

    #[test]
    fn plugin_sha256_is_normalized_to_lowercase() {
        let cfg: DescribeConfig = toml::from_str(
            r#"
[extensions]
[[extensions.plugins]]
name = "demo"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo"
sha256 = "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"
"#,
        )
        .expect("deserialize config");

        assert_eq!(
            cfg.extensions.unwrap().plugins[0].sha256,
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        );
    }

    #[test]
    fn validate_plugin_names_rejects_invalid_chars() {
        let cfg: DescribeConfig = toml::from_str(
            r#"
[extensions]
[[extensions.plugins]]
name = "demo bad"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-demo"
sha256 = "7f51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e7f51e83f0f1b8b1e"
"#,
        )
        .expect("deserialize config");

        let err = cfg.validate_plugin_names().expect_err("invalid name");
        assert!(
            matches!(err, DescribeError::Config(msg) if msg.contains("extensions.plugins[0].name"))
        );
    }
}

/// Paramétrage SameSite des cookies de session web.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum SessionCookieSameSite {
    #[default]
    Lax,
    Strict,
    None,
}

/// Paramétrage global des limites de sécurité côté web.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct WebSecurityConfig {
    /// Limites applicables à la route "/" (HTML).
    pub html: RouteLimitConfig,
    /// Limites applicables à la route "/sse".
    pub sse: SseLimitConfig,
    /// Limites applicables à la route "/api/history".
    pub history: RouteLimitConfig,
    /// Limites applicables aux endpoints de logs (/api/logs, /logs).
    pub logs: RouteLimitConfig,
    /// Multiplicateur des plafonds pour les IP explicitement autorisées.
    pub allowlist_multiplier: u32,
    /// Nombre maximal d'IP distinctes autorisées par token dans la fenêtre.
    pub token_ip_affinity_limit: u32,
    /// Politique anti-bruteforce (authentification, tokens).
    pub brute_force: BruteForceConfig,
    /// Durée de vie maximale (en secondes) des cookies de session émis par le serveur web.
    /// La valeur est bornée à [60s, WEB_SESSION_SECONDS] et un warning est émis si elle sort
    /// des bornes (la valeur effective clampée est utilisée).
    pub session_ttl_seconds: Option<u64>,
    /// Attribut SameSite des cookies de session (lax/strict/none).
    /// None => valeur par défaut (Lax). SameSite=None nécessite Secure, sinon fallback Lax.
    pub session_cookie_same_site: Option<SessionCookieSameSite>,
}

impl Default for WebSecurityConfig {
    fn default() -> Self {
        Self {
            html: RouteLimitConfig::html_default(),
            sse: SseLimitConfig::sse_default(),
            history: RouteLimitConfig::history_default(),
            logs: RouteLimitConfig::logs_default(),
            allowlist_multiplier: 2,
            token_ip_affinity_limit: 2,
            brute_force: BruteForceConfig::default(),
            session_ttl_seconds: None,
            session_cookie_same_site: None,
        }
    }
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

/// Limites génériques pour un endpoint.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct RouteLimitConfig {
    /// Fenêtre glissante (secondes) pour compter les requêtes.
    pub window_seconds: u64,
    /// Nombre de requêtes autorisées par IP dans la fenêtre.
    pub per_ip: u32,
    /// Nombre de requêtes autorisées par token dans la fenêtre.
    pub per_token: u32,
    /// Limite globale de concurrence (toutes IP confondues) pour la route.
    /// Ce n'est pas un quota par fenêtre; `window_seconds` ne s'applique qu'à `per_ip`/`per_token`.
    pub global: u32,
}

impl RouteLimitConfig {
    const fn html_default() -> Self {
        Self {
            window_seconds: 60,
            per_ip: 30,
            per_token: 10,
            global: 120,
        }
    }
}

impl Default for RouteLimitConfig {
    fn default() -> Self {
        Self::html_default()
    }
}

impl RouteLimitConfig {
    pub const fn history_default() -> Self {
        Self {
            window_seconds: 60,
            per_ip: 24,
            per_token: 16,
            global: 120,
        }
    }

    pub const fn logs_default() -> Self {
        Self {
            window_seconds: 60,
            per_ip: 6,
            per_token: 4,
            global: 40,
        }
    }
}

/// Limites spécifiques au flux SSE.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct SseLimitConfig {
    /// Fenêtre glissante (secondes) pour les requêtes de connexion SSE.
    pub window_seconds: u64,
    /// Nombre de connexions SSE autorisées par IP dans la fenêtre.
    pub per_ip: u32,
    /// Nombre de connexions SSE autorisées par token dans la fenêtre.
    pub per_token: u32,
    /// Limite globale de concurrence des connexions SSE.
    /// Un slot est conservé pendant toute la durée de la connexion SSE (pas par fenêtre).
    pub global: u32,
    /// Nombre maximal de connexions SSE actives simultanément par IP.
    pub max_active_per_ip: u32,
    /// Nombre maximal de connexions SSE actives simultanément par token.
    pub max_active_per_token: u32,
    /// Durée maximale d'un flux SSE (en secondes).
    pub max_stream_seconds: u64,
    /// Intervalle minimal entre deux évènements SSE (en millisecondes).
    pub min_event_interval_ms: u64,
    /// Taille maximale d'un payload SSE (en octets).
    pub max_payload_bytes: u32,
    /// Taille cumulée maximale d'un flux SSE (en octets).
    pub max_stream_bytes: u32,
}

impl SseLimitConfig {
    const fn sse_default() -> Self {
        Self {
            window_seconds: 60,
            per_ip: 10,
            per_token: 6,
            global: 40,
            max_active_per_ip: 1,
            max_active_per_token: 1,
            max_stream_seconds: 10 * 60,
            min_event_interval_ms: 1000,
            max_payload_bytes: 48 * 1024,
            max_stream_bytes: 4 * 1024 * 1024,
        }
    }
}

impl Default for SseLimitConfig {
    fn default() -> Self {
        Self::sse_default()
    }
}

/// Paramètres anti-bruteforce (échecs auth).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct BruteForceConfig {
    /// Fenêtre d'observation des échecs (secondes).
    pub window_seconds: u64,
    /// Nombre d'échecs autorisés avant backoff.
    pub threshold: u32,
    /// Durée initiale du backoff (secondes).
    pub initial_backoff_seconds: u64,
    /// Multiplicateur du backoff exponentiel (x2 par défaut).
    pub backoff_multiplier: f32,
    /// Durée maximale du backoff (secondes).
    pub backoff_ceiling_seconds: u64,
    /// Durée de quarantaine après trop d'échecs (secondes).
    pub quarantine_seconds: u64,
    /// Nombre d'échecs déclenchant le verrouillage doux du token.
    pub token_failure_threshold: u32,
    /// Nombre minimal d'IP distinctes pour verrouiller le token.
    /// Valeur bornée à [1..=32] (au-delà, clampée à 32).
    pub token_ip_spread: u32,
    /// Délai minimal conseillé entre deux tentatives SSE échouées (secondes).
    pub sse_min_retry_seconds: u64,
    /// TTL (secondes) des entrées de suivi de spread token.
    pub token_spread_ttl_seconds: u64,
    /// Intervalle de nettoyage des entrées de spread token (secondes).
    pub token_spread_cleanup_seconds: u64,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            window_seconds: 300,
            threshold: 3,
            initial_backoff_seconds: 15,
            backoff_multiplier: 3.0,
            backoff_ceiling_seconds: 5 * 60,
            quarantine_seconds: 45 * 60,
            token_failure_threshold: 6,
            token_ip_spread: 2,
            sse_min_retry_seconds: 2,
            token_spread_ttl_seconds: 45 * 60,
            token_spread_cleanup_seconds: 60,
        }
    }
}

#[cfg(all(test, feature = "config"))]
mod security_tests {
    use super::*;

    #[test]
    fn hardened_web_security_defaults() {
        let cfg = WebSecurityConfig::default();
        assert_eq!(cfg.allowlist_multiplier, 2);
        assert_eq!(cfg.token_ip_affinity_limit, 2);

        assert_eq!(cfg.html.per_ip, 30);
        assert_eq!(cfg.html.per_token, 10);

        assert_eq!(cfg.sse.per_ip, 10);
        assert_eq!(cfg.sse.per_token, 6);
        assert_eq!(cfg.sse.max_active_per_ip, 1);
        assert_eq!(cfg.sse.max_active_per_token, 1);
        assert_eq!(cfg.sse.max_stream_seconds, 10 * 60);
    }
}
