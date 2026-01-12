#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

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
