use crate::application::collectors::{log_system_error, SnapshotCollector};
use crate::application::context::AppContext;
use crate::domain::{CaptureOptions, DescribeError, SystemSnapshot};

pub struct ContainersCollector;

impl SnapshotCollector for ContainersCollector {
    fn collect(
        &self,
        snapshot: &mut SystemSnapshot,
        opts: &CaptureOptions,
        ctx: &AppContext,
    ) -> Result<(), DescribeError> {
        if !opts.with_containers {
            snapshot.containers = None;
            return Ok(());
        }

        match ctx.containers_cache().capture() {
            Ok(data) => {
                snapshot.containers = Some(data);
            }
            Err(err) => {
                log_system_error("capture_containers", &err);
                snapshot.containers = None;
            }
        }
        Ok(())
    }
}
