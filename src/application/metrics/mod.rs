//! Conversion d'un `SnapshotView` en exposition texte Prometheus.
//!
//! Le rendu repose uniquement sur le dernier snapshot mis en cache (aucune
//! recapture) et couvre les familles de métriques stables du projet. Un point
//! d'extension (`write_extension_metrics`) est prévu pour exposer à terme des
//! valeurs numériques issues des plugins SDK sans exploser la cardinalité.

mod encode;
mod extensions;
mod snapshot;

pub use encode::render_prometheus_metrics_with_state;
pub use extensions::ExtensionMetricsState;
