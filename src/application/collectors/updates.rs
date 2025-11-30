use crate::application::collectors::SnapshotCollector;
use crate::application::context::AppContext;
use crate::domain::{CaptureOptions, DescribeError, SystemSnapshot};

pub struct UpdatesCollector;

impl SnapshotCollector for UpdatesCollector {
    fn collect(
        &self,
        snapshot: &mut SystemSnapshot,
        opts: &CaptureOptions,
        _ctx: &AppContext,
    ) -> Result<(), DescribeError> {
        if opts.with_updates {
            snapshot.updates = crate::infrastructure::updates::gather_updates();
        } else {
            snapshot.updates = None;
        }
        Ok(())
    }
}
