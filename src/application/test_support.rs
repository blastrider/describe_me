//! Helpers de support communs pour les tests applicatifs (snapshots, AppState).
//! Ce module est compilé uniquement en configuration test.

use crate::domain::SystemSnapshot;
#[cfg(feature = "systemd")]
use crate::SharedSlice;
#[cfg(feature = "web")]
use std::sync::Arc;
#[cfg(feature = "web")]
use std::time::Duration;

#[cfg(feature = "web")]
use crate::application::context::AppContext;
#[cfg(feature = "web")]
use crate::application::exposure::Exposure;
#[cfg(feature = "web")]
use crate::application::web::{
    state::AppState, state::StaticWebConfig, updates_cache::UpdatesCache, LogoAsset, RuntimeState,
    WebAccess, WebSecurity,
};

/// Snapshot minimal cohérent pour les tests.
pub fn dummy_snapshot() -> SystemSnapshot {
    SystemSnapshot {
        hostname: "localhost".into(),
        os: Some("TestOS".into()),
        kernel: Some("5.0.0-test".into()),
        uptime_seconds: 0,
        cpu_count: 1,
        load_average: (0.0, 0.0, 0.0),
        total_memory_bytes: 1024,
        used_memory_bytes: 512,
        total_swap_bytes: 0,
        used_swap_bytes: 0,
        disk_usage: None,
        #[cfg(feature = "systemd")]
        services_running: SharedSlice::from_vec(Vec::new()),
        #[cfg(feature = "net")]
        listening_sockets: None,
        #[cfg(feature = "net")]
        network_traffic: None,
        containers: None,
        updates: None,
        extensions: None,
    }
}

/// AppState sans authentification forte (tests UI).
#[cfg(feature = "web")]
pub fn make_test_app_state(exposure: Exposure) -> AppState {
    let security = WebSecurity::build(
        WebAccess::default(),
        #[cfg(feature = "config")]
        None,
    )
    .unwrap();
    build_app_state(exposure, security, true)
}

/// AppState avec jeton obligatoire.
#[cfg(feature = "web")]
pub fn make_secured_app_state(exposure: Exposure) -> AppState {
    let access = WebAccess {
        token: Some(bcrypt::hash("secret", bcrypt::DEFAULT_COST).expect("hash token")),
        session_cookie_secure: false,
        ..WebAccess::default()
    };
    let security = WebSecurity::build(
        access,
        #[cfg(feature = "config")]
        None,
    )
    .unwrap();
    build_app_state(exposure, security, false)
}

#[cfg(feature = "web")]
fn build_app_state(
    exposure: Exposure,
    security: WebSecurity,
    session_cookie_secure: bool,
) -> AppState {
    make_app_state_with_ctx(
        exposure,
        security,
        session_cookie_secure,
        AppContext::in_memory(),
    )
}

/// Construit un AppState en injectant un AppContext custom (ex: historique configuré).
#[cfg(feature = "web")]
pub fn make_app_state_with_ctx(
    exposure: Exposure,
    security: WebSecurity,
    session_cookie_secure: bool,
    ctx: AppContext,
) -> AppState {
    let session_ttl = security.session_ttl();
    let static_cfg = StaticWebConfig {
        interval: Duration::from_secs(1),
        #[cfg(feature = "config")]
        config: None,
        web_debug: false,
        security: Arc::new(security),
        exposure,
        logo: LogoAsset::default(),
        session_cookie_secure,
        session_ttl,
        updates_refresh_ttl: Duration::from_secs(1),
        tls_enabled: false,
    };
    let runtime = RuntimeState {
        shutdown: Arc::new(tokio::sync::Notify::new()),
        updates_cache: UpdatesCache::new(Duration::from_secs(1), Duration::from_secs(1)),
        snapshot_cache: Arc::new(std::sync::RwLock::new(None)),
        extension_metrics: Arc::new(crate::application::metrics::ExtensionMetricsState::new()),
    };
    AppState::new(Arc::new(ctx), static_cfg, runtime)
}
