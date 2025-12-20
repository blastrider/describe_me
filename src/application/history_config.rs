use crate::application::context::AppContext;
use crate::application::history::HistorySettings;
use crate::application::logging::LogEvent;
use crate::domain::DescribeError;

#[cfg(feature = "config")]
use crate::application::config::runtime::HistoryConfigExt;
#[cfg(feature = "config")]
use crate::domain::DescribeConfig;

/// Configure le service d'historique et journalise le mode retenu.
pub fn apply_history_settings(
    ctx: &AppContext,
    settings: HistorySettings,
) -> Result<HistorySettings, DescribeError> {
    ctx.history().configure(settings.clone())?;
    LogEvent::HistoryConfig {
        enabled: settings.enabled,
        profile: settings.profile,
        mode: settings.mode,
        retention_points: settings.retention_points,
        max_window_seconds: settings.max_window_seconds,
        rounding_seconds: settings.rounding_seconds,
        paranoid: settings.paranoid_mode,
    }
    .emit();
    Ok(settings)
}

#[cfg(feature = "config")]
pub fn history_settings_from_config(cfg: &DescribeConfig) -> Option<HistorySettings> {
    cfg.history
        .as_ref()
        .map(|history_cfg| history_cfg.to_settings())
}
