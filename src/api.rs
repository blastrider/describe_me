//! Façade officielle de l’API publique du crate, organisée par capacités stables.
//! Import recommandé : `use describe_me::api::history::*;` puis les modules nécessaires.
//! Les autres modules peuvent évoluer sans préavis.

pub mod system {
    //! Capture système de base et contexte runtime.
    pub use crate::application::{disk_usage, AppContext};
    pub use crate::domain::{
        CaptureOptions, DescribeError, DiskPartition, DiskUsage, ServiceInfo, SystemSnapshot,
        UpdatePackage, UpdatesInfo,
    };
    pub use crate::shared::SharedSlice;
}

pub mod metadata {
    //! Métadonnées persistées (description et tags du serveur).
    pub use crate::application::metadata::{
        add_server_tags_with, clear_server_description_with, clear_server_tags_with,
        load_server_description_with, load_server_tags_with, override_state_directory,
        remove_server_tags_with, set_server_description_with, set_server_tags_with,
    };
    pub use crate::domain::{MetadataValidationError, ServerDescription, ServerTag, TagsBatch};
}

pub mod history {
    //! Historique local des mesures et requêtes associées.
    pub use crate::application::history::{
        HistoryMode, HistoryPoint, HistoryQueryError, HistorySeries, HistoryService,
        HistorySettings, MetricAggregate,
    };
    pub use crate::domain::HistoryProfile;
}

pub mod exposure {
    //! Contrôle de l'exposition des snapshots et vues redacted.
    #[cfg(feature = "serde")]
    pub use crate::application::capture_snapshot_with_view;
    #[cfg(feature = "serde")]
    pub use crate::application::exposure::SnapshotView;
    pub use crate::application::exposure::{
        Exposure, ExposureBuilder, ExposureCaptureContext, ExposureFlagSource, ExposureOverrides,
    };
}

pub mod errors {
    //! Structures d'erreur JSON communes (HTTP, plugins, SSE).
    pub use crate::application::error::{serialize_error_body, ErrorBody};
}

pub mod health {
    //! Parsing et évaluation des checks de santé.
    pub use crate::application::health::{eval_checks, parse_check, Severity};
}

pub mod logs {
    //! Lecture des journaux systèmes.
    pub use crate::application::logs::{
        tail_host_logs, HOST_LOGS_DEFAULT_LINES, HOST_LOGS_MAX_LINES,
    };
    pub use crate::domain::{HostLogEntry, HostLogsPage};
}

pub mod net {
    //! Collecte réseau (sockets et trafic).
    #[cfg(feature = "net")]
    pub use crate::application::{net_listen, network_traffic};
    #[cfg(feature = "net")]
    pub use crate::domain::ListeningSocket;
    pub use crate::domain::NetworkInterfaceTraffic;
}

pub mod web {
    //! Serveur web SSE.
    #[cfg(feature = "web")]
    pub use crate::application::web::{serve_http, WebAccess, WebTlsConfig};
}

pub mod containers {
    //! Contrats et helpers liés au collecteur conteneurs.
    #[cfg(feature = "serde")]
    pub use crate::application::containers::{parse_plugin_output, ContainersContractError};
    pub use crate::application::containers::{
        ContainersPluginExitCode, CONTAINERS_CONTRACT_VERSION, CONTAINERS_PLUGIN_TIMEOUT,
    };
    pub use crate::domain::{ContainerInfo, ContainersSnapshot, ContainersSummary};
}

pub mod plugins {
    //! Extensions/plug-ins ad hoc.
    pub use crate::application::extensions::{
        run_ad_hoc_plugin, run_ad_hoc_plugin_with_policy, PluginExecutionError, PluginPolicy,
    };
    pub use describe_me_plugin_sdk::PluginOutput;
}

pub mod pagination {
    //! Utilitaires de pagination pour les collections.
    pub use crate::application::pagination::{paginate_slice, Page, PageRequest};
}

pub mod logging {
    //! Initialisation et événements de logging.
    pub use crate::application::logging::{init_logging, LogEvent};
}

pub mod config {
    //! Chargement et filtrage de la configuration.
    #[cfg(feature = "config")]
    pub use crate::application::{filter_services, load_config_from_path};
    #[cfg(feature = "config")]
    pub use crate::domain::{DescribeConfig, ServiceSelection};
    pub mod runtime {
        pub use crate::application::config::runtime::{
            ExposureConfigExt, HistoryConfigExt, WebAccessConfigExt,
        };
    }
}

#[doc(hidden)]
// TODO: retirer ces réexports plats à la prochaine version majeure ; préférez les sous-modules.
pub use config::*;
pub use containers::*;
pub use errors::*;
pub use exposure::*;
pub use health::*;
pub use history::*;
pub use logging::*;
pub use logs::*;
pub use metadata::*;
pub use net::*;
pub use pagination::*;
pub use plugins::*;
pub use system::*;
pub use web::*;
