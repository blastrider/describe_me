use thiserror::Error;

/// Erreurs possibles de la bibliothèque.
#[derive(Debug, Error)]
pub enum DescribeError {
    /// Erreur liée au système (sysinfo ou I/O).
    #[error("system error: {0}")]
    System(String),

    /// Appel externe (ex: systemctl) a échoué.
    #[error("external command failed: {0}")]
    External(String),

    /// Erreur de parsing (par ex. sortie de `systemctl`).
    #[error("parse error: {0}")]
    Parse(String),

    /// Erreur de config.
    #[error("config error: {0}")] // <— NEW
    Config(String),

    /// Fonctionnalité non supportée pour cette plateforme.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}

/// Helper standardisé pour signaler une fonctionnalité absente sur l'OS courant.
#[macro_export]
macro_rules! unsupported_feature {
    ($feature:literal) => {
        $crate::domain::DescribeError::Unsupported(concat!(
            "feature ",
            $feature,
            " is not supported on this platform"
        ))
    };
}
