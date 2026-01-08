#[cfg(feature = "web")]
use std::sync::Arc;
#[cfg(feature = "web")]
use std::time::Duration;

#[cfg(feature = "web")]
use crate::application::context::AppContext;
use crate::application::exposure::Exposure;
use crate::application::history::{HistoryMode, HistorySettings};
#[cfg(feature = "web")]
use crate::application::web::{
    effective_session_cookie_secure, LogoAsset, StaticWebConfig, WebAccess, WebSecurity,
};
use crate::domain::HistoryProfile;
#[cfg(feature = "web")]
use crate::domain::{DescribeConfig, DescribeError, SessionCookieSameSite, WebAccessConfig};
use crate::domain::{ExposureConfig, HistoryConfig};

#[cfg(feature = "web")]
pub trait WebAccessConfigExt {
    fn to_runtime(
        &self,
        ctx: &AppContext,
        web_access: &WebAccess,
        exposure: Exposure,
        interval: Duration,
        config: Option<DescribeConfig>,
        web_debug: bool,
    ) -> Result<(StaticWebConfig, Arc<WebSecurity>, LogoAsset), DescribeError>;
}

#[cfg(feature = "web")]
impl WebAccessConfigExt for WebAccessConfig {
    fn to_runtime(
        &self,
        ctx: &AppContext,
        web_access: &WebAccess,
        exposure: Exposure,
        interval: Duration,
        config: Option<DescribeConfig>,
        web_debug: bool,
    ) -> Result<(StaticWebConfig, Arc<WebSecurity>, LogoAsset), DescribeError> {
        let _ = ctx;
        let security = WebSecurity::build(web_access.clone(), self.security.clone())?;
        let session_cookie_secure =
            effective_session_cookie_secure(web_access, self.dev_insecure_session_cookie);
        let session_cookie_same_site = self
            .security
            .as_ref()
            .and_then(|cfg| cfg.session_cookie_same_site)
            .unwrap_or(SessionCookieSameSite::Lax);
        let session_cookie_same_site =
            if matches!(session_cookie_same_site, SessionCookieSameSite::None)
                && !session_cookie_secure
            {
                tracing::warn!("SameSite=None nécessite Secure; fallback vers SameSite=Lax");
                SessionCookieSameSite::Lax
            } else {
                session_cookie_same_site
            };
        let session_ttl = security.session_ttl();
        let logo = LogoAsset::from_optional_path(self.logo_path.as_deref())?;
        let updates_refresh_ttl = self
            .updates_refresh_seconds
            .map(|secs| Duration::from_secs(secs.max(1)))
            .unwrap_or(crate::application::web::UPDATES_CACHE_SUCCESS_TTL);
        let tls_enabled = web_access.tls.is_some();

        let security_arc = Arc::new(security);

        let static_cfg = StaticWebConfig {
            interval,
            #[cfg(feature = "config")]
            config,
            web_debug,
            security: security_arc.clone(),
            exposure,
            logo: logo.clone(),
            session_cookie_secure,
            session_cookie_same_site,
            session_ttl,
            updates_refresh_ttl,
            tls_enabled,
        };
        Ok((static_cfg, security_arc, logo))
    }
}

pub trait HistoryConfigExt {
    fn to_settings(&self) -> HistorySettings;
}

impl HistoryConfigExt for HistoryConfig {
    fn to_settings(&self) -> HistorySettings {
        if !self.enabled {
            return HistorySettings::disabled();
        }
        let mut settings = match self.profile.unwrap_or(HistoryProfile::Default) {
            HistoryProfile::Default => HistorySettings::for_profile(HistoryProfile::Default),
            HistoryProfile::Ops => HistorySettings::for_profile(HistoryProfile::Ops),
            HistoryProfile::Paranoid => HistorySettings::for_profile(HistoryProfile::Paranoid),
        };
        if let Some(retention) = self.retention_points {
            settings.set_retention_points(retention);
        }
        if let Some(max_window) = self.max_window_seconds {
            settings.max_window_seconds = max_window;
        }
        if let Some(rounding) = self.rounding_seconds {
            settings.rounding_seconds = rounding;
        }
        if self.in_memory_only {
            settings.set_mode(HistoryMode::InMemory);
        }
        if self.paranoid {
            tracing::warn!(
                "history.paranoid activé: les réglages retention/max_window/rounding/in_memory_only sont réinitialisés au profil paranoïaque"
            );
            settings = HistorySettings::for_profile(HistoryProfile::Paranoid);
        }
        settings
    }
}

pub trait ExposureConfigExt {
    fn to_settings(&self) -> Exposure;
    fn default_settings() -> Exposure;
}

impl ExposureConfigExt for ExposureConfig {
    fn to_settings(&self) -> Exposure {
        crate::application::exposure::ExposureBuilder::from_config(self).build()
    }

    fn default_settings() -> Exposure {
        crate::application::exposure::ExposureBuilder::new().build()
    }
}

#[cfg(all(test, feature = "web", feature = "config"))]
mod tests {
    use super::*;
    use crate::application::context::AppContext;
    use crate::application::web::WebAccess;
    use crate::domain::{SessionCookieSameSite, WebSecurityConfig};
    use std::time::Duration;

    #[test]
    fn to_runtime_sets_secure_cookie_with_trusted_proxy() {
        let ctx = AppContext::in_memory();
        let access = WebAccess {
            session_cookie_secure: true,
            trusted_proxies: vec!["10.0.0.1".into()],
            ..WebAccess::default()
        };
        let cfg = WebAccessConfig::default();
        let (static_cfg, _security, _logo) = cfg
            .to_runtime(
                &ctx,
                &access,
                Exposure::all(),
                Duration::from_secs(1),
                None,
                false,
            )
            .expect("runtime config");
        assert!(static_cfg.session_cookie_secure);
    }

    #[test]
    fn to_runtime_disables_secure_cookie_without_tls_or_proxy() {
        let ctx = AppContext::in_memory();
        let access = WebAccess {
            session_cookie_secure: true,
            ..WebAccess::default()
        };
        let cfg = WebAccessConfig::default();
        let (static_cfg, _security, _logo) = cfg
            .to_runtime(
                &ctx,
                &access,
                Exposure::all(),
                Duration::from_secs(1),
                None,
                false,
            )
            .expect("runtime config");
        assert!(!static_cfg.session_cookie_secure);
    }

    #[test]
    fn to_runtime_respects_dev_insecure_override() {
        let ctx = AppContext::in_memory();
        let access = WebAccess {
            session_cookie_secure: true,
            trusted_proxies: vec!["10.0.0.1".into()],
            ..WebAccess::default()
        };
        let cfg = WebAccessConfig {
            dev_insecure_session_cookie: true,
            ..WebAccessConfig::default()
        };
        let (static_cfg, _security, _logo) = cfg
            .to_runtime(
                &ctx,
                &access,
                Exposure::all(),
                Duration::from_secs(1),
                None,
                false,
            )
            .expect("runtime config");
        assert!(!static_cfg.session_cookie_secure);
    }

    #[test]
    fn to_runtime_falls_back_to_lax_when_same_site_none_without_secure() {
        let ctx = AppContext::in_memory();
        let access = WebAccess {
            session_cookie_secure: true,
            ..WebAccess::default()
        };
        let cfg = WebAccessConfig {
            security: Some(WebSecurityConfig {
                session_cookie_same_site: Some(SessionCookieSameSite::None),
                ..WebSecurityConfig::default()
            }),
            ..WebAccessConfig::default()
        };
        let (static_cfg, _security, _logo) = cfg
            .to_runtime(
                &ctx,
                &access,
                Exposure::all(),
                Duration::from_secs(1),
                None,
                false,
            )
            .expect("runtime config");
        assert_eq!(
            static_cfg.session_cookie_same_site,
            SessionCookieSameSite::Lax
        );
    }

    #[test]
    fn to_runtime_allows_same_site_none_with_secure_cookie() {
        let ctx = AppContext::in_memory();
        let access = WebAccess {
            session_cookie_secure: true,
            trusted_proxies: vec!["10.0.0.1".into()],
            ..WebAccess::default()
        };
        let cfg = WebAccessConfig {
            security: Some(WebSecurityConfig {
                session_cookie_same_site: Some(SessionCookieSameSite::None),
                ..WebSecurityConfig::default()
            }),
            ..WebAccessConfig::default()
        };
        let (static_cfg, _security, _logo) = cfg
            .to_runtime(
                &ctx,
                &access,
                Exposure::all(),
                Duration::from_secs(1),
                None,
                false,
            )
            .expect("runtime config");
        assert_eq!(
            static_cfg.session_cookie_same_site,
            SessionCookieSameSite::None
        );
    }
}
