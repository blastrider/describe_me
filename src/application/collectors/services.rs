use crate::application::collectors::{log_system_error, SnapshotCollector};
use crate::domain::{CaptureOptions, DescribeError, SystemSnapshot};
use crate::SharedSlice;

pub struct ServicesCollector;

impl SnapshotCollector for ServicesCollector {
    fn collect(
        &self,
        snapshot: &mut SystemSnapshot,
        opts: &CaptureOptions,
    ) -> Result<(), DescribeError> {
        if !opts.with_services {
            snapshot.services_running = SharedSlice::from_vec(Vec::new());
            return Ok(());
        }

        let list = crate::infrastructure::systemd::list_systemd_services().inspect_err(|err| {
            log_system_error("systemctl", err);
        })?;

        snapshot.services_running = SharedSlice::from_vec(list);
        Ok(())
    }
}
