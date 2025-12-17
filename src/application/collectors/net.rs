use crate::application::collectors::{log_system_error, SnapshotCollector};
use crate::application::context::AppContext;
use crate::application::net::{
    net_listen_with_context, network_traffic_with_context, NetCollectionParams,
};
use crate::domain::{
    CaptureOptions, DescribeError, ListeningSocket, NetworkInterfaceTraffic, SystemSnapshot,
};
use crate::SharedSlice;
use tracing::warn;

pub struct NetCollector;

impl SnapshotCollector for NetCollector {
    fn collect(
        &self,
        snapshot: &mut SystemSnapshot,
        opts: &CaptureOptions,
        ctx: &AppContext,
    ) -> Result<(), DescribeError> {
        collect_net_with(
            snapshot,
            opts,
            ctx,
            net_listen_with_context,
            network_traffic_with_context,
        )
    }
}

fn collect_net_with<F, G>(
    snapshot: &mut SystemSnapshot,
    opts: &CaptureOptions,
    ctx: &AppContext,
    net_listen: F,
    net_traffic: G,
) -> Result<(), DescribeError>
where
    F: FnOnce(&AppContext, NetCollectionParams) -> Result<Vec<ListeningSocket>, DescribeError>,
    G: FnOnce(&AppContext) -> Result<Vec<NetworkInterfaceTraffic>, DescribeError>,
{
    if opts.with_listening_sockets {
        match net_listen(
            ctx,
            NetCollectionParams {
                resolve_processes: opts.resolve_socket_processes,
            },
        ) {
            Ok(sockets) => {
                snapshot.listening_sockets = Some(SharedSlice::from_vec(sockets));
            }
            Err(err) => {
                log_system_error("net_listen", &err);
                warn!(error = %err, "net_listen_failed");
                snapshot.listening_sockets = None;
            }
        }
    } else {
        snapshot.listening_sockets = None;
    }

    if opts.with_network_traffic {
        match net_traffic(ctx) {
            Ok(traffic) => {
                snapshot.network_traffic = Some(SharedSlice::from_vec(traffic));
            }
            Err(err) => {
                log_system_error("net_traffic", &err);
                warn!(error = %err, "net_traffic_failed");
                snapshot.network_traffic = None;
            }
        }
    } else {
        snapshot.network_traffic = None;
    }

    Ok(())
}

#[cfg(all(test, feature = "net"))]
mod tests {
    use super::*;
    use crate::application::collectors::tests_common::{record_field_eq, RecordingLayer};
    use crate::application::collectors::CoreCollector;

    #[test]
    fn net_collector_is_best_effort_on_error() {
        let ctx = AppContext::in_memory();
        let opts = CaptureOptions {
            with_listening_sockets: true,
            with_network_traffic: true,
            ..CaptureOptions::default()
        };
        let mut snapshot = CoreCollector
            .capture_base(&opts, &ctx)
            .expect("base snapshot");

        let result = collect_net_with(
            &mut snapshot,
            &opts,
            &ctx,
            |_ctx, _params| Err(DescribeError::System("boom".into())),
            |_ctx| Err(DescribeError::System("boom".into())),
        );

        assert!(result.is_ok());
        assert!(snapshot.listening_sockets.is_none());
        assert!(snapshot.network_traffic.is_none());
    }

    #[test]
    fn net_collector_emits_system_error_events() {
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
            with_listening_sockets: true,
            with_network_traffic: true,
            ..CaptureOptions::default()
        };
        let mut snapshot = CoreCollector
            .capture_base(&opts, &ctx)
            .expect("base snapshot");

        let _ = collect_net_with(
            &mut snapshot,
            &opts,
            &ctx,
            |_ctx, _params| Err(DescribeError::System("boom".into())),
            |_ctx| Err(DescribeError::System("boom".into())),
        );

        let records = layer.records();
        assert!(
            records
                .iter()
                .any(|record| record_field_eq(record, "where", "net_listen")),
            "missing system_error for net_listen"
        );
        assert!(
            records
                .iter()
                .any(|record| record_field_eq(record, "where", "net_traffic")),
            "missing system_error for net_traffic"
        );
    }
}
