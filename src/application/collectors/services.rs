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

        let backend = default_service_backend();
        let list = backend
            .collect_services(ctx)
            .inspect_err(|err| log_system_error("services_collect", err))?;

        snapshot.services_running = SharedSlice::from_vec(list);
        Ok(())
    }
}
