#[cfg(feature = "serde")]
use serde::Deserialize;

/// Profils d'historique prédéfinis (utilisés par la config et la CLI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum HistoryProfile {
    Default,
    Ops,
    Paranoid,
}
