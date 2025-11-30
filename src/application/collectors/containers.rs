use crate::application::collectors::SnapshotCollector;
use crate::application::context::AppContext;
use crate::domain::{CaptureOptions, DescribeError, SystemSnapshot};
use tracing::warn;

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
                warn!(error = %err, "capture_containers_failed");
                snapshot.containers = None;
            }
        }
        Ok(())
    }
}
