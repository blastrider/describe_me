use crate::application::collectors::{log_system_error, SnapshotCollector};
use crate::application::context::AppContext;
use crate::application::net::{
    net_listen_with_context, network_traffic_with_context, NetCollectionParams,
};
use crate::domain::{CaptureOptions, DescribeError, SystemSnapshot};
use crate::SharedSlice;

pub struct NetCollector;

impl SnapshotCollector for NetCollector {
    fn collect(
        &self,
        snapshot: &mut SystemSnapshot,
        opts: &CaptureOptions,
        ctx: &AppContext,
    ) -> Result<(), DescribeError> {
        if opts.with_listening_sockets {
            let sockets = net_listen_with_context(
                ctx,
                NetCollectionParams {
                    resolve_processes: opts.resolve_socket_processes,
                },
            )
            .inspect_err(|err| log_system_error("net_listen", err))?;
            snapshot.listening_sockets = Some(SharedSlice::from_vec(sockets));
        } else {
            snapshot.listening_sockets = None;
        }

        if opts.with_network_traffic {
            let traffic = network_traffic_with_context(ctx)
                .inspect_err(|err| log_system_error("net_traffic", err))?;
            snapshot.network_traffic = Some(SharedSlice::from_vec(traffic));
        } else {
            snapshot.network_traffic = None;
        }

        Ok(())
    }
}
