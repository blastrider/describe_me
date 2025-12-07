use std::sync::Arc;
use std::time::Duration;

use crate::application::context::AppContext;
use crate::application::exposure::Exposure;
use crate::application::history::{HistoryMode, HistorySettings};
use crate::application::web::{LogoAsset, StaticWebConfig, WebAccess, WebSecurity};
use crate::domain::HistoryProfile;
use crate::domain::{
    DescribeConfig, DescribeError, ExposureConfig, HistoryConfig, WebAccessConfig,
};

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
        let session_cookie_secure = if self.dev_insecure_session_cookie {
            false
        } else {
            web_access.session_cookie_secure && web_access.tls.is_some()
        };
        let session_ttl = security.session_ttl();
        let logo = LogoAsset::from_optional_path(self.logo_path.as_deref())?;
        let updates_refresh_ttl = self
            .updates_refresh_seconds
            .map(|secs| Duration::from_secs(secs.max(1)))
            .unwrap_or(crate::application::web::UPDATES_CACHE_SUCCESS_TTL);

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
            session_ttl,
            updates_refresh_ttl,
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
