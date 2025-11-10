use crate::args::Opts;

#[cfg(feature = "config")]
pub fn apply_cli_exposure_flags(
    exposure: &mut describe_me::Exposure,
    opts: &Opts,
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
    apply_cli_flags(exposure, opts);
}

#[cfg(not(feature = "config"))]
pub fn apply_cli_exposure_flags(
    exposure: &mut describe_me::Exposure,
    opts: &Opts,
    _allow_config_exposure: bool,
) {
    apply_cli_flags(exposure, opts);
}

#[cfg(all(feature = "web", feature = "config"))]
pub fn apply_web_exposure_flags(
    exposure: describe_me::Exposure,
    opts: &Opts,
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

    apply_web_flags(&mut web_exposure, opts);
    web_exposure
}

#[cfg(all(feature = "web", not(feature = "config")))]
pub fn apply_web_exposure_flags(
    exposure: describe_me::Exposure,
    opts: &Opts,
    _allow_config_exposure: bool,
) -> describe_me::Exposure {
    let mut web_exposure = exposure;
    apply_web_flags(&mut web_exposure, opts);
    web_exposure
}

fn apply_cli_flags(exposure: &mut describe_me::Exposure, opts: &Opts) {
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
        if opts.expose_updates {
            exposure.set_updates(true);
        }
    }

    if opts.no_redacted {
        exposure.redacted = false;
    }

    if opts.net_listen {
        exposure.set_listening_sockets(true);
    }
    if opts.net_traffic {
        exposure.set_network_traffic(true);
    }
}

#[cfg(feature = "web")]
fn apply_web_flags(exposure: &mut describe_me::Exposure, opts: &Opts) {
    if opts.web_expose_all {
        *exposure = describe_me::Exposure::all();
    } else {
        if opts.web_expose_hostname {
            exposure.set_hostname(true);
        }
        if opts.web_expose_os {
            exposure.set_os(true);
        }
        if opts.web_expose_kernel {
            exposure.set_kernel(true);
        }
        if opts.web_expose_services {
            exposure.set_services(true);
        }
        if opts.web_expose_disk_partitions {
            exposure.set_disk_partitions(true);
        }
        if opts.web_expose_network_traffic {
            exposure.set_network_traffic(true);
        }
        if opts.web_expose_updates {
            exposure.set_updates(true);
        }
    }

    if opts.no_redacted {
        exposure.redacted = false;
    }
}
