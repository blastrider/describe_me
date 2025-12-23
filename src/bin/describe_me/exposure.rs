use super::args::{CaptureOpts, CliConfig, ExposureOpts, WebExposureOpts};

fn apply_exposure_common<F>(
    base: describe_me_lib::Exposure,
    overrides: describe_me_lib::ExposureOverrides,
    capture_ctx: Option<describe_me_lib::ExposureCaptureContext>,
    apply_config: F,
) -> describe_me_lib::Exposure
where
    F: FnOnce(&mut describe_me_lib::ExposureBuilder),
{
    let mut builder = describe_me_lib::ExposureBuilder::from_exposure(base);
    apply_config(&mut builder);
    builder.apply_overrides(&overrides);
    if let Some(ctx) = capture_ctx {
        builder.apply_capture(ctx);
    }
    builder.build()
}

#[cfg(feature = "config")]
pub fn apply_cli_exposure_flags(
    exposure: &mut describe_me_lib::Exposure,
    cli: &CliConfig,
    cfg: Option<&describe_me_lib::DescribeConfig>,
    allow_config_exposure: bool,
) {
    let config_exposure = if allow_config_exposure {
        cfg.and_then(|cfg| cfg.exposure.as_ref())
    } else {
        None
    };
    let overrides = overrides_from_cli(&cli.exposure);
    let capture_ctx = Some(capture_context(&cli.capture));

    *exposure = apply_exposure_common(
        std::mem::take(exposure),
        overrides,
        capture_ctx,
        |builder| {
            if let Some(cfg_exp) = config_exposure {
                builder.apply_config(cfg_exp);
            }
        },
    );
}

#[cfg(not(feature = "config"))]
pub fn apply_cli_exposure_flags(
    exposure: &mut describe_me_lib::Exposure,
    cli: &CliConfig,
    _allow_config_exposure: bool,
) {
    let overrides = overrides_from_cli(&cli.exposure);
    let capture_ctx = Some(capture_context(&cli.capture));
    *exposure = apply_exposure_common(std::mem::take(exposure), overrides, capture_ctx, |_| {});
}

#[cfg(all(feature = "web", feature = "config"))]
pub fn apply_web_exposure_flags(
    exposure: describe_me_lib::Exposure,
    cli: &CliConfig,
    cfg: Option<&describe_me_lib::DescribeConfig>,
    allow_config_exposure: bool,
) -> describe_me_lib::Exposure {
    let config_exposure = if allow_config_exposure {
        cfg.and_then(|cfg| cfg.web.as_ref())
            .and_then(|web_cfg| web_cfg.exposure.as_ref())
    } else {
        None
    };
    let overrides = overrides_from_web(&cli.web_exposure, cli.exposure.no_redacted);

    apply_exposure_common(exposure, overrides, None, |builder| {
        if let Some(web_exp) = config_exposure {
            builder.apply_config(web_exp);
        }
    })
}

#[cfg(all(feature = "web", not(feature = "config")))]
pub fn apply_web_exposure_flags(
    exposure: describe_me_lib::Exposure,
    cli: &CliConfig,
    _allow_config_exposure: bool,
) -> describe_me_lib::Exposure {
    let overrides = overrides_from_web(&cli.web_exposure, cli.exposure.no_redacted);
    apply_exposure_common(exposure, overrides, None, |_| {})
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

describe_me_lib::impl_exposure_flag_source!(
    ExposureOpts,
    base: this,
    expose_all: { this_field(expose_all) },
    no_redacted: { this_field(no_redacted) },
    expose_listening_sockets: { const(false) },
);

struct WebExposureWithRedaction<'a> {
    opts: &'a WebExposureOpts,
    no_redacted: bool,
}

describe_me_lib::impl_exposure_flag_source!(
    WebExposureWithRedaction<'_>,
    base: field(opts),
    expose_all: { base_field(expose_all) },
    no_redacted: { this_field(no_redacted) },
    expose_listening_sockets: { const(false) },
);

#[cfg(test)]
mod tests {
    use super::*;

    fn exposure_opts_fixture() -> ExposureOpts {
        ExposureOpts {
            expose_hostname: true,
            expose_os: false,
            expose_kernel: true,
            expose_services: false,
            expose_disk_partitions: true,
            expose_network_traffic: false,
            expose_containers_summary: true,
            expose_containers_details: false,
            expose_updates: true,
            expose_extensions: false,
            no_redacted: true,
            expose_all: false,
        }
    }

    fn web_exposure_opts_fixture() -> WebExposureOpts {
        WebExposureOpts {
            expose_hostname: false,
            expose_os: true,
            expose_kernel: false,
            expose_services: true,
            expose_disk_partitions: false,
            expose_network_traffic: true,
            expose_containers_summary: false,
            expose_containers_details: true,
            expose_updates: false,
            expose_extensions: true,
            expose_all: true,
        }
    }

    fn assert_cli_overrides(overrides: &describe_me_lib::ExposureOverrides, opts: &ExposureOpts) {
        assert_eq!(overrides.expose_hostname, opts.expose_hostname);
        assert_eq!(overrides.expose_os, opts.expose_os);
        assert_eq!(overrides.expose_kernel, opts.expose_kernel);
        assert_eq!(overrides.expose_services, opts.expose_services);
        assert_eq!(
            overrides.expose_disk_partitions,
            opts.expose_disk_partitions
        );
        assert_eq!(
            overrides.expose_network_traffic,
            opts.expose_network_traffic
        );
        assert_eq!(
            overrides.expose_containers_summary,
            opts.expose_containers_summary
        );
        assert_eq!(
            overrides.expose_containers_details,
            opts.expose_containers_details
        );
        assert_eq!(overrides.expose_updates, opts.expose_updates);
        assert_eq!(overrides.expose_extensions, opts.expose_extensions);
        assert_eq!(overrides.expose_all, opts.expose_all);
        assert_eq!(overrides.no_redacted, opts.no_redacted);
        assert!(!overrides.expose_listening_sockets);
    }

    fn assert_web_overrides(
        overrides: &describe_me_lib::ExposureOverrides,
        opts: &WebExposureOpts,
    ) {
        assert_eq!(overrides.expose_hostname, opts.expose_hostname);
        assert_eq!(overrides.expose_os, opts.expose_os);
        assert_eq!(overrides.expose_kernel, opts.expose_kernel);
        assert_eq!(overrides.expose_services, opts.expose_services);
        assert_eq!(
            overrides.expose_disk_partitions,
            opts.expose_disk_partitions
        );
        assert_eq!(
            overrides.expose_network_traffic,
            opts.expose_network_traffic
        );
        assert_eq!(
            overrides.expose_containers_summary,
            opts.expose_containers_summary
        );
        assert_eq!(
            overrides.expose_containers_details,
            opts.expose_containers_details
        );
        assert_eq!(overrides.expose_updates, opts.expose_updates);
        assert_eq!(overrides.expose_extensions, opts.expose_extensions);
        assert_eq!(overrides.expose_all, opts.expose_all);
        assert!(!overrides.expose_listening_sockets);
    }

    #[test]
    fn exposure_flag_sources_map_flags_and_redaction() {
        let opts = exposure_opts_fixture();
        let overrides = describe_me_lib::ExposureOverrides::from_flags(&opts);
        assert_cli_overrides(&overrides, &opts);

        let web_opts = web_exposure_opts_fixture();
        let wrapper = WebExposureWithRedaction {
            opts: &web_opts,
            no_redacted: false,
        };
        let overrides = describe_me_lib::ExposureOverrides::from_flags(&wrapper);
        assert_web_overrides(&overrides, &web_opts);
        assert!(!overrides.no_redacted);

        let wrapper = WebExposureWithRedaction {
            opts: &web_opts,
            no_redacted: true,
        };
        let overrides = describe_me_lib::ExposureOverrides::from_flags(&wrapper);
        assert_web_overrides(&overrides, &web_opts);
        assert!(overrides.no_redacted);
    }
}
