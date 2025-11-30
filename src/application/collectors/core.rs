use std::borrow::Cow;

use crate::application::logging::LogEvent;
#[cfg(feature = "systemd")]
use crate::domain::ServiceInfo;
use crate::domain::{CaptureOptions, DescribeError, SystemSnapshot};
use crate::infrastructure::sysinfo;
#[cfg(feature = "systemd")]
use crate::SharedSlice;

pub struct CoreCollector;

impl CoreCollector {
    pub fn capture_base(&self, opts: &CaptureOptions) -> Result<SystemSnapshot, DescribeError> {
        let base = sysinfo::gather().inspect_err(|err| {
            LogEvent::SystemError {
                location: Cow::Borrowed("gather"),
                error: Cow::Owned(err.to_string()),
            }
            .emit();
        })?;

        let disk_usage = if opts.with_disk_usage {
            Some(sysinfo::gather_disks().inspect_err(|err| {
                LogEvent::SystemError {
                    location: Cow::Borrowed("gather_disks"),
                    error: Cow::Owned(err.to_string()),
                }
                .emit();
            })?)
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
