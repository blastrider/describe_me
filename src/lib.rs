//! describe_me — bibliothèque pour décrire rapidement un serveur.
//!
//! # API
//! - Utilisation recommandée : `use describe_me::api::*;`.
//! - Le reste de l’arbre de modules est sujet à changement sans préavis.
//!
//! # Examples
//! ```rust
//! use describe_me::api::{AppContext, CaptureOptions, SystemSnapshot};
//! let ctx = AppContext::in_memory();
//! let snap = SystemSnapshot::capture_with(CaptureOptions::default(), &ctx).expect("snapshot");
//! assert!(snap.cpu_count >= 1);
//! ```

#![forbid(unsafe_code)]

mod application;
pub mod domain;
mod infrastructure;
pub mod security;
mod shared;

pub mod api;

#[doc(hidden)]
// Maintenu pour compatibilité : le réexport global disparaîtra lors d'une prochaine version
// majeure. Préférez dès maintenant importer via les modules explicites
// (`describe_me::api::history::*`, `describe_me::api::web::*`, etc.).
pub use crate::api::*;

// Outils de test/fuzz internes
#[cfg(any(test, feature = "internals"))]
pub mod internals {
    //! Helpers de parsing réservés aux tests/fuzz. Non stable, non supportés en production.
    #[cfg(all(feature = "net", target_os = "linux"))]
    pub use crate::infrastructure::net::linux::{
        parse_table_from_str, table_parse_opts_tcp, table_parse_opts_udp, AddressKind,
        TableParseOpts,
    };
    pub use crate::infrastructure::sysinfo::parse_mountinfo_for_tests;
    #[cfg(all(feature = "systemd", target_os = "linux"))]
    pub use crate::infrastructure::systemd::__parse_systemctl_line_for_tests;
    #[cfg(target_os = "linux")]
    pub use crate::infrastructure::updates::{
        count_apk_updates_for_tests, count_dnf_updates_for_tests,
        parse_apt_upgradable_line_for_tests,
    };
}
