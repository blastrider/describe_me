//! Exposition des champs sensibles/optionnels pour la CLI, le web et l'API.
//!
//! - `Exposure` porte l'etat courant (flags + `redacted` safe-by-default) utilise pour
//!   filtrer les snapshots (`SnapshotView`).
//! - `ExposureBuilder` agregre les sources : config TOML (`ExposureConfig`), overrides
//!   explicites (CLI `ExposureOpts`, web), et contexte de capture (sockets, trafic, conteneurs).
//! - `ExposureOverrides`/`ExposureCaptureContext` rendent explicite ce qui force l'exposition
//!   (ex: `--net-listen` active les sockets, `--no-redacted` leve les masques).
//! - Semantique `redacted` : masquage par defaut des indices sensibles (hostname, kernel, OS);
//!   desactivation volontaire via config/CLI/web expose davantage de details.

mod flags;
#[cfg(feature = "serde")]
mod sanitize;
pub(crate) mod view;

pub use flags::{
    Exposure, ExposureBuilder, ExposureCaptureContext, ExposureFlagSource, ExposureOverrides,
};

#[cfg(feature = "serde")]
pub use view::SnapshotView;
