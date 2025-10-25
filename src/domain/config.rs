#[cfg(feature = "serde")]
use serde::Deserialize;

use crate::domain::DescribeError;

/// Configuration haut-niveau.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct DescribeConfig {
    /// Sélection des services à afficher (si `with_services = true`).
    pub services: Option<ServiceSelection>,
}

/// Sélection des services (liste blanche simple).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct ServiceSelection {
    /// Noms exacts systemd à inclure (ex: "sshd.service").
    pub include: Vec<String>,
}

impl DescribeConfig {
    /// Validation stricte du contenu (volumétrie + charset).
    pub fn validate(&self) -> Result<(), DescribeError> {
        if let Some(sel) = &self.services {
            if sel.include.len() > 256 {
                return Err(DescribeError::Config(
                    "services.include dépasse 256 éléments".into(),
                ));
            }
            for n in &sel.include {
                if n.len() > 128 {
                    return Err(DescribeError::Config(format!(
                        "nom de service trop long: {}",
                        n
                    )));
                }
                if !n
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
                {
                    return Err(DescribeError::Config(format!(
                        "nom de service invalide (caractères non autorisés): {}",
                        n
                    )));
                }
            }
        }
        Ok(())
    }
}
