use crate::args::{CaptureOpts, CliConfig, ExposureOpts, WebExposureOpts};

#[cfg(feature = "config")]
pub fn apply_cli_exposure_flags(
    exposure: &mut describe_me::Exposure,
    cli: &CliConfig,
    cfg: Option<&describe_me::DescribeConfig>,
    allow_config_exposure: bool,
) {
    if allow_config_exposure {
        if let Some(cfg) = cfg {
            if let Some(cfg_exp) = cfg.exposure.as_ref() {
                exposure.merge(describe_me::Exposure::from(cfg_exp));
            }
        }
    }
    apply_cli_flags(exposure, &cli.exposure, &cli.capture);
}

#[cfg(not(feature = "config"))]
pub fn apply_cli_exposure_flags(
    exposure: &mut describe_me::Exposure,
    cli: &CliConfig,
    _allow_config_exposure: bool,
) {
    apply_cli_flags(exposure, &cli.exposure, &cli.capture);
}

#[cfg(all(feature = "web", feature = "config"))]
pub fn apply_web_exposure_flags(
    exposure: describe_me::Exposure,
    cli: &CliConfig,
    cfg: Option<&describe_me::DescribeConfig>,
    allow_config_exposure: bool,
) -> describe_me::Exposure {
    let mut web_exposure = exposure;

    if allow_config_exposure {
        if let Some(cfg) = cfg {
            if let Some(web_cfg) = cfg.web.as_ref() {
                if let Some(web_exp) = web_cfg.exposure.as_ref() {
                    web_exposure.merge(describe_me::Exposure::from(web_exp));
                }
            }
        }
    }

    apply_web_flags(
        &mut web_exposure,
        &cli.web_exposure,
        cli.exposure.no_redacted,
    );
    web_exposure
}

#[cfg(all(feature = "web", not(feature = "config")))]
pub fn apply_web_exposure_flags(
    exposure: describe_me::Exposure,
    cli: &CliConfig,
    _allow_config_exposure: bool,
) -> describe_me::Exposure {
    let mut web_exposure = exposure;
    apply_web_flags(
        &mut web_exposure,
        &cli.web_exposure,
        cli.exposure.no_redacted,
    );
    web_exposure
}

fn apply_cli_flags(
    exposure: &mut describe_me::Exposure,
    opts: &ExposureOpts,
    capture: &CaptureOpts,
) {
    if opts.expose_all {
        *exposure = describe_me::Exposure::all();
    } else {
        if opts.expose_hostname {
            exposure.set_hostname(true);
        }
        if opts.expose_os {
            exposure.set_os(true);
        }
        if opts.expose_kernel {
            exposure.set_kernel(true);
        }
        if opts.expose_services {
            exposure.set_services(true);
        }
        if opts.expose_disk_partitions {
            exposure.set_disk_partitions(true);
        }
        if opts.expose_network_traffic {
            exposure.set_network_traffic(true);
        }
        if opts.expose_containers_summary {
            exposure.set_containers_summary(true);
        }
        if opts.expose_containers_details {
            exposure.set_containers_details(true);
        }
        if opts.expose_updates {
            exposure.set_updates(true);
        }
        if opts.expose_extensions {
            exposure.set_extensions(true);
        }
    }

    if opts.no_redacted {
        exposure.redacted = false;
    }

    if capture.net_listen {
        exposure.set_listening_sockets(true);
    }
    if capture.net_traffic {
        exposure.set_network_traffic(true);
    }
    if capture.containers {
        exposure.set_containers_details(true);
    }
}

#[cfg(feature = "web")]
fn apply_web_flags(
    exposure: &mut describe_me::Exposure,
    opts: &WebExposureOpts,
    no_redacted: bool,
) {
    if opts.expose_all {
        *exposure = describe_me::Exposure::all();
    } else {
        if opts.expose_hostname {
            exposure.set_hostname(true);
        }
        if opts.expose_os {
            exposure.set_os(true);
        }
        if opts.expose_kernel {
            exposure.set_kernel(true);
        }
        if opts.expose_services {
            exposure.set_services(true);
        }
        if opts.expose_disk_partitions {
            exposure.set_disk_partitions(true);
        }
        if opts.expose_network_traffic {
            exposure.set_network_traffic(true);
        }
        if opts.expose_containers_summary {
            exposure.set_containers_summary(true);
        }
        if opts.expose_containers_details {
            exposure.set_containers_details(true);
        }
        if opts.expose_updates {
            exposure.set_updates(true);
        }
        if opts.expose_extensions {
            exposure.set_extensions(true);
        }
    }

    if no_redacted {
        exposure.redacted = false;
    }
}
