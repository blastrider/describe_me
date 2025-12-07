//! Assemblage centralisé du JavaScript frontal.
//! L'ordre de concaténation est important (dépendances internes) et pourra
//! être remplacé ultérieurement par un bundle généré via `build.rs`.

use super::MAIN_JS;

/// Retourne le bundle JS principal (concaténation des segments statiques).
pub fn main_js() -> &'static str {
    // Les segments sont déjà concaténés dans `MAIN_JS`, cette fonction expose
    // un point d'entrée unique pour le template.
    MAIN_JS
}
