use super::args::{CaptureOpts, CliConfig, ExposureOpts, WebExposureOpts};
use describe_me_lib::ExposureFlagSource;

#[cfg(feature = "config")]
pub fn apply_cli_exposure_flags(
    exposure: &mut describe_me_lib::Exposure,
    cli: &CliConfig,
    cfg: Option<&describe_me_lib::DescribeConfig>,
    allow_config_exposure: bool,
) {
    let mut builder = describe_me_lib::ExposureBuilder::from_exposure(std::mem::take(exposure));

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
    exposure: &mut describe_me_lib::Exposure,
    cli: &CliConfig,
    _allow_config_exposure: bool,
) {
    let mut builder = describe_me_lib::ExposureBuilder::from_exposure(std::mem::take(exposure));
    builder.apply_overrides(&overrides_from_cli(&cli.exposure));
    builder.apply_capture(capture_context(&cli.capture));
    *exposure = builder.build();
}

#[cfg(all(feature = "web", feature = "config"))]
pub fn apply_web_exposure_flags(
    exposure: describe_me_lib::Exposure,
    cli: &CliConfig,
    cfg: Option<&describe_me_lib::DescribeConfig>,
    allow_config_exposure: bool,
) -> describe_me_lib::Exposure {
    let mut builder = describe_me_lib::ExposureBuilder::from_exposure(exposure);

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
    exposure: describe_me_lib::Exposure,
    cli: &CliConfig,
    _allow_config_exposure: bool,
) -> describe_me_lib::Exposure {
    let mut builder = describe_me_lib::ExposureBuilder::from_exposure(exposure);
    builder.apply_overrides(&overrides_from_web(
        &cli.web_exposure,
        cli.exposure.no_redacted,
    ));
    builder.build()
}

fn overrides_from_cli(opts: &ExposureOpts) -> describe_me_lib::ExposureOverrides {
    describe_me_lib::ExposureOverrides::from_flags(opts)
}

fn overrides_from_web(
    opts: &WebExposureOpts,
    no_redacted: bool,
) -> describe_me_lib::ExposureOverrides {
    let flags = WebExposureWithRedaction { opts, no_redacted };
    describe_me_lib::ExposureOverrides::from_flags(&flags)
}

fn capture_context(capture: &CaptureOpts) -> describe_me_lib::ExposureCaptureContext {
    describe_me_lib::ExposureCaptureContext {
        net_listen: capture.net_listen,
        net_traffic: capture.net_traffic,
        containers: capture.containers,
    }
}

impl ExposureFlagSource for ExposureOpts {
    fn expose_hostname(&self) -> bool {
        self.expose_hostname
    }

    fn expose_os(&self) -> bool {
        self.expose_os
    }

    fn expose_kernel(&self) -> bool {
        self.expose_kernel
    }

    fn expose_services(&self) -> bool {
        self.expose_services
    }

    fn expose_disk_partitions(&self) -> bool {
        self.expose_disk_partitions
    }

    fn expose_network_traffic(&self) -> bool {
        self.expose_network_traffic
    }

    fn expose_containers_summary(&self) -> bool {
        self.expose_containers_summary
    }

    fn expose_containers_details(&self) -> bool {
        self.expose_containers_details
    }

    fn expose_updates(&self) -> bool {
        self.expose_updates
    }

    fn expose_extensions(&self) -> bool {
        self.expose_extensions
    }

    fn expose_all(&self) -> bool {
        self.expose_all
    }

    fn no_redacted(&self) -> bool {
        self.no_redacted
    }
}

struct WebExposureWithRedaction<'a> {
    opts: &'a WebExposureOpts,
    no_redacted: bool,
}

impl ExposureFlagSource for WebExposureWithRedaction<'_> {
    fn expose_hostname(&self) -> bool {
        self.opts.expose_hostname
    }

    fn expose_os(&self) -> bool {
        self.opts.expose_os
    }

    fn expose_kernel(&self) -> bool {
        self.opts.expose_kernel
    }

    fn expose_services(&self) -> bool {
        self.opts.expose_services
    }

    fn expose_disk_partitions(&self) -> bool {
        self.opts.expose_disk_partitions
    }

    fn expose_network_traffic(&self) -> bool {
        self.opts.expose_network_traffic
    }

    fn expose_containers_summary(&self) -> bool {
        self.opts.expose_containers_summary
    }

    fn expose_containers_details(&self) -> bool {
        self.opts.expose_containers_details
    }

    fn expose_updates(&self) -> bool {
        self.opts.expose_updates
    }

    fn expose_extensions(&self) -> bool {
        self.opts.expose_extensions
    }

    fn expose_all(&self) -> bool {
        self.opts.expose_all
    }

    fn no_redacted(&self) -> bool {
        self.no_redacted
    }
}
