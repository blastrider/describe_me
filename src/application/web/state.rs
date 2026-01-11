use super::security::WebSecurity;
use super::updates_cache::UpdatesCache;
use crate::application::capture_snapshot_with_view;
use crate::application::context::AppContext;
use crate::application::exposure::{Exposure, SnapshotView};
use crate::application::logging::LogEvent;
use crate::domain::{CaptureOptions, DescribeError, SessionCookieSameSite};
use axum::body::{Body, Bytes};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify, RwLock};

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
    let doc = roxmltree::Document::parse(text).map_err(|err| format!("SVG invalide: {err}"))?;
    let root = doc.root_element();
    if root.tag_name().name() != "svg" {
        return Err("balise <svg> racine requise".into());
    }

    for node in doc.descendants().filter(|node| node.is_element()) {
        let tag = node.tag_name().name();
        if !is_allowed_svg_tag(tag) {
            return Err(format!("balise <{tag}> interdite"));
        }
        if tag == "style" {
            let style_text = collect_text(node);
            validate_style_text(&style_text)?;
        }
        for attr in node.attributes() {
            validate_svg_attribute(tag, attr)?;
        }
    }

    Ok(())
}

#[cfg(feature = "config")]
fn is_allowed_svg_tag(tag: &str) -> bool {
    matches!(
        tag,
        "svg"
            | "g"
            | "path"
            | "rect"
            | "circle"
            | "ellipse"
            | "line"
            | "polyline"
            | "polygon"
            | "title"
            | "desc"
            | "style"
            | "defs"
            | "linearGradient"
            | "radialGradient"
            | "stop"
            | "clipPath"
            | "mask"
            | "pattern"
            | "symbol"
            | "use"
            | "text"
            | "tspan"
    )
}

#[cfg(feature = "config")]
fn validate_svg_attribute(tag: &str, attr: roxmltree::Attribute<'_, '_>) -> Result<(), String> {
    let namespace = attr.namespace();
    let name = attr.name();
    if namespace == Some(roxmltree::NS_XMLNS_URI) {
        return Ok(());
    }
    if namespace == Some(roxmltree::NS_XML_URI) && name.eq_ignore_ascii_case("space") {
        return Ok(());
    }

    let full_name = display_attr_name(namespace, name);
    let name_lower = full_name.to_ascii_lowercase();
    if name_lower.starts_with("on") {
        return Err(format!("attribut {full_name} interdit"));
    }
    if name_lower == "href" && (namespace.is_none() || namespace == Some(XLINK_NAMESPACE_URI)) {
        return validate_fragment_reference(tag, &full_name, attr.value());
    }
    if namespace.is_some() {
        return Err(format!("attribut {full_name} interdit"));
    }
    if !is_allowed_svg_attribute(&name_lower) {
        return Err(format!("attribut {full_name} interdit"));
    }

    let value = attr.value();
    if name_lower == "style" {
        validate_style_text(value)?;
    } else {
        validate_attribute_value(&full_name, value)?;
    }

    Ok(())
}

#[cfg(feature = "config")]
fn is_allowed_svg_attribute(name: &str) -> bool {
    matches!(
        name,
        "id" | "class"
            | "d"
            | "fill"
            | "fill-opacity"
            | "fill-rule"
            | "stroke"
            | "stroke-width"
            | "stroke-linecap"
            | "stroke-linejoin"
            | "stroke-miterlimit"
            | "stroke-dasharray"
            | "stroke-dashoffset"
            | "stroke-opacity"
            | "opacity"
            | "transform"
            | "viewbox"
            | "preserveaspectratio"
            | "width"
            | "height"
            | "x"
            | "y"
            | "x1"
            | "x2"
            | "y1"
            | "y2"
            | "cx"
            | "cy"
            | "r"
            | "rx"
            | "ry"
            | "points"
            | "role"
            | "aria-label"
            | "aria-labelledby"
            | "aria-hidden"
            | "focusable"
            | "style"
            | "type"
            | "clip-path"
            | "clip-rule"
            | "mask"
            | "filter"
            | "gradientunits"
            | "gradienttransform"
            | "offset"
            | "stop-color"
            | "stop-opacity"
            | "vector-effect"
            | "display"
            | "font-family"
            | "font-size"
            | "font-weight"
            | "font-style"
            | "letter-spacing"
            | "word-spacing"
            | "text-anchor"
            | "dominant-baseline"
    ) || name.starts_with("aria-")
        || name.starts_with("data-")
}

#[cfg(feature = "config")]
const XLINK_NAMESPACE_URI: &str = "http://www.w3.org/1999/xlink";

#[cfg(feature = "config")]
fn display_attr_name(namespace: Option<&str>, local_name: &str) -> String {
    match namespace {
        Some(roxmltree::NS_XML_URI) => format!("xml:{local_name}"),
        Some(roxmltree::NS_XMLNS_URI) => {
            if local_name.eq_ignore_ascii_case("xmlns") {
                "xmlns".to_string()
            } else {
                format!("xmlns:{local_name}")
            }
        }
        Some(XLINK_NAMESPACE_URI) => format!("xlink:{local_name}"),
        Some(_) => local_name.to_string(),
        None => local_name.to_string(),
    }
}

#[cfg(feature = "config")]
fn validate_fragment_reference(tag: &str, name: &str, value: &str) -> Result<(), String> {
    let trimmed = value.trim().trim_matches('"').trim_matches('\'');
    if trimmed.len() < 2 || !trimmed.starts_with('#') {
        return Err(format!(
            "attribut {name} invalide sur <{tag}> (fragment interne requis)"
        ));
    }
    Ok(())
}

#[cfg(feature = "config")]
fn validate_style_text(value: &str) -> Result<(), String> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("@import") {
        return Err("les @import CSS sont interdits".into());
    }
    if lower.contains("javascript:") || lower.contains("data:") {
        return Err("les URLs javascript/data sont interdites".into());
    }
    if contains_unsafe_url(value) {
        return Err("les URLs externes dans url() sont interdites".into());
    }
    Ok(())
}

#[cfg(feature = "config")]
fn validate_attribute_value(name: &str, value: &str) -> Result<(), String> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("javascript:") || lower.contains("data:") {
        return Err(format!("attribut {name} contient une URL interdite"));
    }
    if contains_unsafe_url(value) {
        return Err(format!("attribut {name} contient une URL externe"));
    }
    Ok(())
}

#[cfg(feature = "config")]
fn contains_unsafe_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some(pos) = rest.find("url(") {
        rest = &rest[pos + 4..];
        let Some(end) = rest.find(')') else {
            return true;
        };
        let inside = rest[..end].trim().trim_matches('"').trim_matches('\'');
        if inside.is_empty()
            || inside.starts_with("javascript:")
            || inside.starts_with("data:")
            || !inside.starts_with('#')
        {
            return true;
        }
        rest = &rest[end + 1..];
    }
    false
}

#[cfg(feature = "config")]
fn collect_text(node: roxmltree::Node<'_, '_>) -> String {
    let mut text = String::new();
    for chunk in node.descendants().filter_map(|child| child.text()) {
        text.push_str(chunk);
    }
    text
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
    pub session_cookie_same_site: SessionCookieSameSite,
    pub session_ttl: Duration,
    pub updates_refresh_ttl: Duration,
    pub tls_enabled: bool,
}

#[derive(Clone)]
pub(crate) struct RuntimeState {
    pub shutdown: Arc<Notify>,
    pub updates_cache: UpdatesCache,
    pub snapshot_cache: Arc<RwLock<Option<Arc<CachedSnapshot>>>>,
    pub snapshot_refresh: Arc<Mutex<()>>,
    pub extension_metrics: Arc<crate::application::metrics::ExtensionMetricsState>,
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

    pub async fn cache_snapshot(&self, view: SnapshotView) {
        let mut guard = self.runtime.snapshot_cache.write().await;
        *guard = Some(Arc::new(CachedSnapshot {
            view,
            captured_at: Instant::now(),
        }));
    }

    pub async fn latest_snapshot(&self) -> Option<Arc<CachedSnapshot>> {
        let guard = self.runtime.snapshot_cache.read().await;
        guard.as_ref().map(Arc::clone)
    }

    pub async fn ensure_snapshot_fresh(&self) -> Option<Arc<CachedSnapshot>> {
        let stale_after = self.interval();
        if let Some(cached) = self.latest_snapshot().await {
            if !snapshot_is_stale(&cached, stale_after) {
                return Some(cached);
            }
        }

        let _guard = self.runtime.snapshot_refresh.lock().await;
        if let Some(cached) = self.latest_snapshot().await {
            if !snapshot_is_stale(&cached, stale_after) {
                return Some(cached);
            }
        }

        let exposure = self.exposure();
        let ctx = self.ctx();
        #[cfg(feature = "config")]
        let config = self.config_ref().cloned();
        let capture_opts = CaptureOptions {
            with_services: should_capture_services(),
            with_disk_usage: true,
            with_listening_sockets: exposure.listening_sockets(),
            resolve_socket_processes: false,
            with_network_traffic: exposure.network_traffic(),
            with_updates: false,
            with_containers: exposure.containers_summary() || exposure.containers_details(),
        };

        let captured = tokio::task::spawn_blocking({
            let ctx = ctx.clone();
            move || {
                #[cfg(feature = "config")]
                {
                    capture_snapshot_with_view(capture_opts, exposure, config.as_ref(), &ctx)
                }
                #[cfg(not(feature = "config"))]
                {
                    capture_snapshot_with_view(capture_opts, exposure, &ctx)
                }
            }
        })
        .await;

        let captured = match captured {
            Ok(result) => result,
            Err(err) => {
                LogEvent::SystemError {
                    location: Cow::Borrowed("snapshot_capture_on_demand"),
                    error: Cow::Owned(err.to_string()),
                }
                .emit();
                return None;
            }
        };

        match captured {
            Ok((_snapshot, mut view)) => {
                if exposure.updates() {
                    if let Some(info) = self.updates_cache().peek().await {
                        view.updates = Some(info);
                    }
                }
                self.cache_snapshot(view).await;
                self.latest_snapshot().await
            }
            Err(err) => {
                LogEvent::SystemError {
                    location: Cow::Borrowed("snapshot_capture_on_demand"),
                    error: Cow::Owned(err.to_string()),
                }
                .emit();
                None
            }
        }
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

    pub fn session_cookie_same_site(&self) -> SessionCookieSameSite {
        self.static_cfg.session_cookie_same_site
    }

    pub fn session_ttl(&self) -> Duration {
        self.static_cfg.session_ttl
    }

    pub fn interval(&self) -> Duration {
        self.static_cfg.interval
    }

    #[cfg(feature = "config")]
    pub(crate) fn config_ref(&self) -> Option<&DescribeConfig> {
        self.static_cfg.config.as_ref()
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

fn snapshot_is_stale(snapshot: &CachedSnapshot, stale_after: Duration) -> bool {
    snapshot.captured_at.elapsed() > stale_after
}

fn should_capture_services() -> bool {
    #[cfg(feature = "systemd")]
    {
        let container = std::env::var("DESCRIBE_ME_CONTAINER")
            .ok()
            .map(|v| v.trim().eq_ignore_ascii_case("1") || v.trim().eq_ignore_ascii_case("true"));
        !matches!(container, Some(true))
    }
    #[cfg(not(feature = "systemd"))]
    {
        false
    }
}
