use crate::application::collectors::{log_system_error, SnapshotCollector};
use crate::application::context::AppContext;
use crate::application::services::{default_service_backend, ServiceBackend};
use crate::domain::{CaptureOptions, DescribeError, SystemSnapshot};
use crate::SharedSlice;

pub struct ServicesCollector;

impl SnapshotCollector for ServicesCollector {
    fn collect(
        &self,
        snapshot: &mut SystemSnapshot,
        opts: &CaptureOptions,
        ctx: &AppContext,
    ) -> Result<(), DescribeError> {
        if !opts.with_services {
            snapshot.services_running = SharedSlice::from_vec(Vec::new());
            return Ok(());
        }

        let Some(backend) = default_service_backend() else {
            snapshot.services_running = SharedSlice::from_vec(Vec::new());
            return Err(DescribeError::Unsupported(
                "service backend not available on this platform",
            ));
        };

        let list = backend.list_services(ctx).inspect_err(|err| {
            log_system_error("systemctl", err);
        })?;

        snapshot.services_running = SharedSlice::from_vec(list);
        Ok(())
    }
}
