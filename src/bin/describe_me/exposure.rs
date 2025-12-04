use crate::args::{CaptureOpts, CliConfig, ExposureOpts, WebExposureOpts};

#[cfg(feature = "config")]
pub fn apply_cli_exposure_flags(
    exposure: &mut describe_me::Exposure,
    cli: &CliConfig,
    cfg: Option<&describe_me::DescribeConfig>,
    allow_config_exposure: bool,
) {
    let mut builder = describe_me::ExposureBuilder::from_exposure(std::mem::take(exposure));

    if allow_config_exposure {
        if let Some(cfg) = cfg {
            if let Some(cfg_exp) = cfg.exposure.as_ref() {
                builder.apply_config(cfg_exp);
            }
        }
    }

    builder.apply_overrides(&overrides_from_cli(&cli.exposure));
    builder.apply_capture(capture_context(&cli.capture));
    *exposure = builder.build();
}

#[cfg(not(feature = "config"))]
pub fn apply_cli_exposure_flags(
    exposure: &mut describe_me::Exposure,
    cli: &CliConfig,
    _allow_config_exposure: bool,
) {
    let mut builder = describe_me::ExposureBuilder::from_exposure(std::mem::take(exposure));
    builder.apply_overrides(&overrides_from_cli(&cli.exposure));
    builder.apply_capture(capture_context(&cli.capture));
    *exposure = builder.build();
}

#[cfg(all(feature = "web", feature = "config"))]
pub fn apply_web_exposure_flags(
    exposure: describe_me::Exposure,
    cli: &CliConfig,
    cfg: Option<&describe_me::DescribeConfig>,
    allow_config_exposure: bool,
) -> describe_me::Exposure {
    let mut builder = describe_me::ExposureBuilder::from_exposure(exposure);

    if allow_config_exposure {
        if let Some(cfg) = cfg {
            if let Some(web_cfg) = cfg.web.as_ref() {
                if let Some(web_exp) = web_cfg.exposure.as_ref() {
                    builder.apply_config(web_exp);
                }
            }
        }
    }

    builder.apply_overrides(&overrides_from_web(
        &cli.web_exposure,
        cli.exposure.no_redacted,
    ));
    builder.build()
}

#[cfg(all(feature = "web", not(feature = "config")))]
pub fn apply_web_exposure_flags(
    exposure: describe_me::Exposure,
    cli: &CliConfig,
    _allow_config_exposure: bool,
) -> describe_me::Exposure {
    let mut builder = describe_me::ExposureBuilder::from_exposure(exposure);
    builder.apply_overrides(&overrides_from_web(
        &cli.web_exposure,
        cli.exposure.no_redacted,
    ));
    builder.build()
}

fn overrides_from_cli(opts: &ExposureOpts) -> describe_me::ExposureOverrides {
    describe_me::ExposureOverrides {
        expose_hostname: opts.expose_hostname,
        expose_os: opts.expose_os,
        expose_kernel: opts.expose_kernel,
        expose_services: opts.expose_services,
        expose_disk_partitions: opts.expose_disk_partitions,
        expose_network_traffic: opts.expose_network_traffic,
        expose_containers_summary: opts.expose_containers_summary,
        expose_containers_details: opts.expose_containers_details,
        expose_updates: opts.expose_updates,
        expose_extensions: opts.expose_extensions,
        expose_all: opts.expose_all,
        no_redacted: opts.no_redacted,
        expose_listening_sockets: false,
    }
}

fn overrides_from_web(opts: &WebExposureOpts, no_redacted: bool) -> describe_me::ExposureOverrides {
    describe_me::ExposureOverrides {
        expose_hostname: opts.expose_hostname,
        expose_os: opts.expose_os,
        expose_kernel: opts.expose_kernel,
        expose_services: opts.expose_services,
        expose_disk_partitions: opts.expose_disk_partitions,
        expose_network_traffic: opts.expose_network_traffic,
        expose_containers_summary: opts.expose_containers_summary,
        expose_containers_details: opts.expose_containers_details,
        expose_updates: opts.expose_updates,
        expose_extensions: opts.expose_extensions,
        expose_all: opts.expose_all,
        no_redacted,
        expose_listening_sockets: false,
    }
}

fn capture_context(capture: &CaptureOpts) -> describe_me::ExposureCaptureContext {
    describe_me::ExposureCaptureContext {
        net_listen: capture.net_listen,
        net_traffic: capture.net_traffic,
        containers: capture.containers,
    }
}
