use crate::application::collectors::log_system_error;
use crate::application::context::AppContext;
#[cfg(feature = "systemd")]
use crate::domain::ServiceInfo;
use crate::domain::{CaptureOptions, DescribeError, SystemSnapshot};
use crate::infrastructure::system;
#[cfg(feature = "systemd")]
use crate::SharedSlice;

/// Collecteur de base chargé d'initialiser un [`SystemSnapshot`] cohérent.
///
/// Ce collecteur est responsable de la création initiale du snapshot avec des valeurs par défaut
/// (champs `None` ou `SharedSlice` vides lorsque l'information est absente). Les collecteurs
/// suivants complètent ces champs sans réinitialiser ceux qu'ils ne gèrent pas.
pub struct CoreCollector;

impl CoreCollector {
    pub fn capture_base(
        &self,
        opts: &CaptureOptions,
        ctx: &AppContext,
    ) -> Result<SystemSnapshot, DescribeError> {
        let base = system::collect_system_metrics(ctx).inspect_err(|err| {
            log_system_error("gather", err);
        })?;

        let disk_usage = if opts.with_disk_usage {
            Some(
                system::collect_disks(ctx)
                    .inspect_err(|err| log_system_error("gather_disks", err))?,
            )
        } else {
            None
        };

        Ok(SystemSnapshot {
            hostname: base.hostname,
            os: base.os,
            kernel: base.kernel,
            uptime_seconds: base.uptime_seconds,
            cpu_count: base.cpu_count,
            load_average: base.load_average,
            total_memory_bytes: base.total_memory_bytes,
            used_memory_bytes: base.used_memory_bytes,
            total_swap_bytes: base.total_swap_bytes,
            used_swap_bytes: base.used_swap_bytes,
            disk_usage,
            #[cfg(feature = "systemd")]
            services_running: SharedSlice::from_vec(Vec::<ServiceInfo>::new()),
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            containers: None,
            updates: None,
            extensions: None,
        })
    }
}
