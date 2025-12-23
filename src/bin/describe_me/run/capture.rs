use anyhow::Result;
use describe_me_lib::{AppContext, CaptureOptions, DescribeConfig, DescribeError};

use crate::describe_me::args::CliConfig;

pub fn build_capture_opts(
    cli: &CliConfig,
    exposure: describe_me_lib::Exposure,
    with_containers_effective: bool,
) -> CaptureOptions {
    CaptureOptions {
        with_services: cli.capture.with_services,
        with_disk_usage: true,
        with_listening_sockets: cli.capture.net_listen || exposure.listening_sockets(),
        resolve_socket_processes: cli.capture.net_listen || exposure.listening_sockets(),
        with_network_traffic: cli.capture.net_traffic || exposure.network_traffic(),
        with_updates: true,
        with_containers: with_containers_effective,
    }
}

pub fn execute_capture(
    capture_opts: CaptureOptions,
    exposure: describe_me_lib::Exposure,
    cfg: Option<&DescribeConfig>,
    ctx: &AppContext,
) -> Result<
    (
        describe_me_lib::SystemSnapshot,
        describe_me_lib::SnapshotView,
    ),
    DescribeError,
> {
    #[cfg(feature = "config")]
    {
        describe_me_lib::capture_snapshot_with_view(capture_opts, exposure, cfg, ctx)
    }
    #[cfg(not(feature = "config"))]
    {
        let _ = cfg;
        describe_me_lib::capture_snapshot_with_view(capture_opts, exposure, ctx)
    }
}

pub fn validate_feature_flags(_cli: &CliConfig) -> Result<()> {
    #[cfg(not(feature = "systemd"))]
    if _cli.capture.with_services {
        anyhow::bail!(
            "--with-services nécessite la feature `systemd` (cargo run --features \"cli systemd\")."
        );
    }

    #[cfg(not(feature = "net"))]
    if _cli.capture.net_listen {
        anyhow::bail!(
            "--net-listen nécessite la feature `net` (cargo run --features \"cli net\")."
        );
    }

    #[cfg(not(feature = "net"))]
    if _cli.capture.net_traffic {
        anyhow::bail!(
            "--net-traffic nécessite la feature `net` (cargo run --features \"cli net\")."
        );
    }
    Ok(())
}

#[cfg(all(test, any(not(feature = "net"), not(feature = "systemd"))))]
mod tests {
    use super::*;
    use crate::describe_me::args;
    use clap::Parser;

    #[cfg(any(not(feature = "net"), not(feature = "systemd")))]
    fn base_cli() -> CliConfig {
        args::Opts::parse_from(["describe-me"]).into()
    }

    #[cfg(not(feature = "net"))]
    #[test]
    fn validate_feature_flags_rejects_net_requests() {
        let mut cli = base_cli();
        cli.capture.net_listen = true;
        let err = validate_feature_flags(&cli).expect_err("expected error");
        assert!(err.to_string().contains("feature `net`"));
    }

    #[cfg(not(feature = "systemd"))]
    #[test]
    fn validate_feature_flags_rejects_systemd_requests() {
        let mut cli = base_cli();
        cli.capture.with_services = true;
        let err = validate_feature_flags(&cli).expect_err("expected error");
        assert!(err.to_string().contains("feature `systemd`"));
    }
}
