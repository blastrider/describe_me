use super::security::WebSecurity;
use super::updates_cache::UpdatesCache;
use crate::application::context::AppContext;
use crate::application::exposure::{Exposure, SnapshotView};
use crate::application::sync::lock_expect;
use crate::domain::DescribeError;
use axum::body::{Body, Bytes};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

#[cfg(feature = "config")]
use crate::domain::DescribeConfig;

#[derive(Clone)]
pub(crate) struct CachedSnapshot {
    pub view: SnapshotView,
    pub captured_at: Instant,
}

/// Ressource statique (ou personnalisée) représentant le logo exposé par l'UI.
#[derive(Clone)]
pub struct LogoAsset {
    pub(crate) bytes: Bytes,
}

impl LogoAsset {
    pub fn default() -> Self {
        Self {
            bytes: Bytes::from_static(super::assets::LOGO_SVG),
        }
    }

    pub fn response(&self) -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("image/svg+xml"),
            )
            .body(Body::from(self.bytes.clone()))
            .expect("logo response")
    }

    #[cfg(feature = "config")]
    pub fn from_optional_path(path: Option<&str>) -> Result<Self, DescribeError> {
        match path {
            Some(raw) => Self::from_path(raw),
            None => Ok(Self::default()),
        }
    }

    #[cfg(feature = "config")]
    pub fn from_path(raw: &str) -> Result<Self, DescribeError> {
        use std::fs;
        use std::path::Path;

        let path = Path::new(raw);
        if !path.is_absolute() {
            return Err(DescribeError::Config(format!(
                "web.logo_path \"{}\" doit être un chemin absolu",
                path.display()
            )));
        }

        let canonical = fs::canonicalize(path).map_err(|err| {
            DescribeError::Config(format!("web.logo_path \"{}\": {err}", path.display()))
        })?;
        let metadata = fs::metadata(&canonical).map_err(|err| {
            DescribeError::Config(format!("web.logo_path \"{}\": {err}", canonical.display()))
        })?;
        if !metadata.is_file() {
            return Err(DescribeError::Config(format!(
                "web.logo_path \"{}\" n'est pas un fichier",
                canonical.display()
            )));
        }
        if metadata.len() > super::LOGO_MAX_BYTES {
            return Err(DescribeError::Config(format!(
                "web.logo_path \"{}\" dépasse la limite de {} octets",
                canonical.display(),
                super::LOGO_MAX_BYTES
            )));
        }

        let data = fs::read(&canonical).map_err(|err| {
            DescribeError::Config(format!("web.logo_path \"{}\": {err}", canonical.display()))
        })?;

        validate_logo_bytes(&data).map_err(|reason| {
            DescribeError::Config(format!(
                "web.logo_path \"{}\" invalide: {reason}",
                canonical.display()
            ))
        })?;

        Ok(Self {
            bytes: Bytes::from(data),
        })
    }
}

#[cfg(feature = "config")]
fn validate_logo_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("le fichier est vide".into());
    }
    if (bytes.len() as u64) > super::LOGO_MAX_BYTES {
        return Err(format!(
            "le fichier dépasse la limite de {} octets",
            super::LOGO_MAX_BYTES
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "le logo doit être un SVG encodé en UTF-8".to_string())?;
    let lower = text.to_ascii_lowercase();
    if !lower.contains("<svg") {
        return Err("balise <svg> introuvable".into());
    }
    if lower.contains("<script") {
        return Err("les balises <script> sont interdites".into());
    }
    for attr in ["onload", "onerror", "onclick", "onfocus", "onmouseover"] {
        if lower.contains(&format!("{attr}=")) {
            return Err(format!("l'attribut {attr}= est interdit"));
        }
    }
    if lower.contains("javascript:") {
        return Err("les URLs javascript: sont interdites".into());
    }
    Ok(())
}

#[derive(Clone)]
pub struct StaticWebConfig {
    pub interval: Duration,
    #[cfg(feature = "config")]
    pub config: Option<DescribeConfig>,
    pub web_debug: bool,
    pub(crate) security: Arc<WebSecurity>,
    pub exposure: Exposure,
    pub logo: LogoAsset,
    pub session_cookie_secure: bool,
    pub session_ttl: Duration,
    pub updates_refresh_ttl: Duration,
    pub tls_enabled: bool,
}

#[derive(Clone)]
pub(crate) struct RuntimeState {
    pub shutdown: Arc<Notify>,
    pub updates_cache: UpdatesCache,
    pub snapshot_cache: Arc<RwLock<Option<CachedSnapshot>>>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub ctx: Arc<AppContext>,
    pub static_cfg: Arc<StaticWebConfig>,
    pub runtime: RuntimeState,
}

impl AppState {
    pub fn new(ctx: Arc<AppContext>, static_cfg: StaticWebConfig, runtime: RuntimeState) -> Self {
        Self {
            ctx,
            static_cfg: Arc::new(static_cfg),
            runtime,
        }
    }

    pub fn cache_snapshot(&self, view: SnapshotView) {
        let mut guard = lock_expect(
            self.runtime.snapshot_cache.write(),
            "AppState.snapshot_cache",
        );
        *guard = Some(CachedSnapshot {
            view,
            captured_at: Instant::now(),
        });
    }

    pub fn latest_snapshot(&self) -> Option<CachedSnapshot> {
        let guard = lock_expect(
            self.runtime.snapshot_cache.read(),
            "AppState.snapshot_cache",
        );
        guard.clone()
    }

    pub fn ctx(&self) -> Arc<AppContext> {
        Arc::clone(&self.ctx)
    }

    pub fn exposure(&self) -> Exposure {
        self.static_cfg.exposure
    }

    pub(super) fn security(&self) -> Arc<WebSecurity> {
        Arc::clone(&self.static_cfg.security)
    }

    pub fn logo(&self) -> &LogoAsset {
        &self.static_cfg.logo
    }

    pub fn web_debug(&self) -> bool {
        self.static_cfg.web_debug
    }

    pub fn session_cookie_secure(&self) -> bool {
        self.static_cfg.session_cookie_secure
    }

    pub fn session_ttl(&self) -> Duration {
        self.static_cfg.session_ttl
    }

    pub fn interval(&self) -> Duration {
        self.static_cfg.interval
    }

    #[cfg(feature = "config")]
    pub fn config(&self) -> Option<DescribeConfig> {
        self.static_cfg.config.clone()
    }

    pub fn updates_cache(&self) -> &UpdatesCache {
        &self.runtime.updates_cache
    }

    pub fn shutdown(&self) -> Arc<Notify> {
        self.runtime.shutdown.clone()
    }
}
