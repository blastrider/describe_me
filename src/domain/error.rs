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
}
