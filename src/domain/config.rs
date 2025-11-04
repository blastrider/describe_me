#[cfg(feature = "serde")]
use serde::Deserialize;

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
    /// Exposition des champs sensibles côté web (--web).
    pub exposure: Option<ExposureConfig>,
    /// Paramétrage des limites de sécurité (rate limiting, anti-bruteforce).
    pub security: Option<WebSecurityConfig>,
    /// Intervalle de rafraîchissement (en secondes) pour le cache des mises à jour.
    pub updates_refresh_seconds: Option<u64>,
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
    /// Active --web-expose-all si true.
    pub web_expose_all: Option<bool>,
    /// Valeurs par défaut pour --web-allow-ip.
    pub web_allow_ip: Vec<String>,
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
    /// Autoriser l'exposition des informations de mises à jour.
    pub expose_updates: bool,
    /// Fournir des valeurs masquées (versions tronquées) lorsque l'exposition complète est désactivée.
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
            expose_updates: false,
            redacted: true,
        }
    }
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
    /// Multiplicateur des plafonds pour les IP explicitement autorisées.
    pub allowlist_multiplier: u32,
    /// Nombre maximal d'IP distinctes autorisées par token dans la fenêtre.
    pub token_ip_affinity_limit: u32,
    /// Politique anti-bruteforce (authentification, tokens).
    pub brute_force: BruteForceConfig,
}

impl Default for WebSecurityConfig {
    fn default() -> Self {
        Self {
            html: RouteLimitConfig::html_default(),
            sse: SseLimitConfig::sse_default(),
            allowlist_multiplier: 2,
            token_ip_affinity_limit: 2,
            brute_force: BruteForceConfig::default(),
        }
    }
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
}

impl RouteLimitConfig {
    const fn html_default() -> Self {
        Self {
            window_seconds: 60,
            per_ip: 30,
            per_token: 10,
        }
    }
}

impl Default for RouteLimitConfig {
    fn default() -> Self {
        Self::html_default()
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
}

impl SseLimitConfig {
    const fn sse_default() -> Self {
        Self {
            window_seconds: 60,
            per_ip: 10,
            per_token: 6,
            max_active_per_ip: 1,
            max_active_per_token: 1,
            max_stream_seconds: 10 * 60,
            min_event_interval_ms: 1000,
            max_payload_bytes: 48 * 1024,
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
    pub token_ip_spread: u32,
    /// Délai minimal conseillé entre deux tentatives SSE échouées (secondes).
    pub sse_min_retry_seconds: u64,
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
