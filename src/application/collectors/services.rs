use crate::application::collectors::{log_system_error, SnapshotCollector};
use crate::application::context::AppContext;
use crate::application::services::{default_service_backend, ServiceBackend};
use crate::domain::{CaptureOptions, DescribeError, SystemSnapshot};
use crate::SharedSlice;
use tracing::warn;

pub struct ServicesCollector;

impl SnapshotCollector for ServicesCollector {
    fn collect(
        &self,
        snapshot: &mut SystemSnapshot,
        opts: &CaptureOptions,
        ctx: &AppContext,
    ) -> Result<(), DescribeError> {
        collect_services_with(snapshot, opts, ctx, |ctx| {
            default_service_backend().collect_services(ctx)
        })
    }
}

fn collect_services_with<F>(
    snapshot: &mut SystemSnapshot,
    opts: &CaptureOptions,
    ctx: &AppContext,
    collect: F,
) -> Result<(), DescribeError>
where
    F: FnOnce(&AppContext) -> Result<Vec<crate::domain::ServiceInfo>, DescribeError>,
{
    if !opts.with_services {
        snapshot.services_running = SharedSlice::from_vec(Vec::new());
        return Ok(());
    }

    match collect(ctx) {
        Ok(list) => {
            snapshot.services_running = SharedSlice::from_vec(list);
        }
        Err(err) => {
            log_system_error("services_collect", &err);
            warn!(error = %err, "services_collect_failed");
            snapshot.services_running = SharedSlice::from_vec(Vec::new());
        }
    }

    Ok(())
}

#[cfg(all(test, feature = "systemd"))]
mod tests {
    use super::*;
    use crate::application::collectors::tests_common::{record_field_eq, RecordingLayer};
    use crate::application::collectors::CoreCollector;

    #[test]
    fn services_collector_is_best_effort_on_error() {
        let ctx = AppContext::in_memory();
        let opts = CaptureOptions {
            with_services: true,
            ..CaptureOptions::default()
        };
        let mut snapshot = CoreCollector
            .capture_base(&opts, &ctx)
            .expect("base snapshot");

        let result = collect_services_with(&mut snapshot, &opts, &ctx, |_ctx| {
            Err(DescribeError::System("boom".into()))
        });

        assert!(result.is_ok());
        assert!(snapshot.services_running.is_empty());
    }

    #[test]
    fn services_collector_emits_system_error_event() {
        let layer = RecordingLayer::new();
        let _guard = layer.clone().install();
        log_system_error("probe", &"boom");
        assert!(
            layer
                .records()
                .iter()
                .any(|record| record_field_eq(record, "where", "probe")),
            "recording layer inactive before test"
        );
        layer.clear();

        let ctx = AppContext::in_memory();
        let opts = CaptureOptions {
            with_services: true,
            ..CaptureOptions::default()
        };
        let mut snapshot = CoreCollector
            .capture_base(&opts, &ctx)
            .expect("base snapshot");

        let _ = collect_services_with(&mut snapshot, &opts, &ctx, |_ctx| {
            Err(DescribeError::System("boom".into()))
        });

        let records = layer.records();
        assert!(
            records
                .iter()
                .any(|record| record_field_eq(record, "where", "services_collect")),
            "missing system_error for services_collect"
        );
    }
}
